use super::*;

pub(super) fn run_sys_03(context: &SystemContext, deadline: Instant) -> CheckResult {
    super::run_check("SYS-03", sys_03_body, context, deadline)
}

/// Wildcard listeners attributed to their declared fleet owners. `ss -p`
/// cannot resolve pids for root-owned sockets (k3s, sshd, harmonia), so those
/// entries carry no process name and a socket on their port with a visible
/// pid is someone else's. User-owned entries name the comms `ss` may show
/// (`git daemon` runs as `git`). Any other wildcard flags.
const ATTRIBUTED_WILDCARD_LISTENERS: &[(u16, Option<&[&str]>, &str)] = &[
    (
        2586,
        Some(&["ntfy"]),
        "ntfy.service (--listen-http 0.0.0.0:2586, modules/tools/killswitch.nix)",
    ),
    (
        6443,
        None,
        "k3s.service (services.k3s server role, modules/features/odin-foundations.nix)",
    ),
    (
        10250,
        None,
        "k3s.service embedded kubelet (modules/features/odin-foundations.nix)",
    ),
    (
        22,
        None,
        "sshd.service (services.openssh, modules/features/tailnet.nix)",
    ),
    (
        5000,
        None,
        "harmonia.service (services.harmonia, modules/features/binary-cache.nix)",
    ),
    (
        9418,
        Some(&["git", "git-daemon"]),
        "git-mirror-daemon.service (modules/features/git-mirror.nix)",
    ),
    (
        22000,
        Some(&["syncthing"]),
        "syncthing sync protocol (modules/home/vault-sync.nix)",
    ),
];

/// The listener policy over one inventory: every declared port is observed
/// and confined to its declared (or loopback) address; a wildcard on an
/// attributed port is held by its declared owner; any other wildcard flags.
fn listener_verdict(
    declared: &BTreeMap<u16, String>,
    inventory: &[SocketObservation],
    mut evidence: Vec<String>,
) -> Outcome {
    let mut violations = Vec::new();
    let mut unattributed_wildcards = Vec::new();
    let mut observed_ports = BTreeSet::new();
    for socket in inventory {
        let endpoint = format!("{}:{}", socket.address, socket.port);
        if let Some(required) = declared.get(&socket.port) {
            observed_ports.insert(socket.port);
            if !host_allowed(required, &socket.address) {
                violations.push(format!("{endpoint} (declared {required})"));
            }
            continue;
        }
        if !is_wildcard_host(&socket.address) {
            continue;
        }
        let Some((_, process, owner)) = ATTRIBUTED_WILDCARD_LISTENERS
            .iter()
            .find(|(port, _, _)| *port == socket.port)
        else {
            unattributed_wildcards.push(match (&socket.owner_name, socket.owner_pid) {
                (Some(name), Some(pid)) => format!("{endpoint} ({name} pid={pid})"),
                _ => endpoint,
            });
            continue;
        };
        let held_by_owner = match (process, socket.owner_pid) {
            (None, None) => true,
            (None, Some(_)) => false,
            (Some(processes), _) => socket
                .owner_name
                .as_deref()
                .is_some_and(|name| processes.contains(&name)),
        };
        if !held_by_owner {
            violations.push(format!(
                "{endpoint} held by {:?} pid={:?}, declared owner {owner}",
                socket.owner_name, socket.owner_pid
            ));
            continue;
        }
        note_evidence(
            &mut evidence,
            format!("attributed-wildcard={endpoint} ({owner})"),
        );
    }
    if !violations.is_empty() {
        return Err(CheckFailure::fail(
            "listener-bind-violation",
            format!(
                "listener port(s) bound outside their declared address or owner: {}",
                violations.join(", ")
            ),
        ));
    }
    let absent = declared
        .iter()
        .filter(|(port, _)| !observed_ports.contains(*port))
        .map(|(port, host)| format!("{host}:{port}"))
        .collect::<Vec<_>>();
    if !absent.is_empty() {
        return Err(CheckFailure::fail(
            "declared-listener-absent",
            format!("declared listener(s) not bound: {}", absent.join(", ")),
        ));
    }
    if !unattributed_wildcards.is_empty() {
        return Ok(CheckOutcome {
            status: CheckStatus::Flag,
            summary: format!(
                "declared listeners are private, but {} wildcard listener(s) have no declared owner: {}",
                unattributed_wildcards.len(),
                unattributed_wildcards.join(", ")
            ),
            reason: Some("unattributed-wildcard-listener".to_owned()),
            evidence,
        });
    }
    CheckOutcome::pass(
        format!(
            "all {} declared listener(s) bound and confined to loopback or their declared address",
            declared.len()
        ),
        evidence,
    )
}

fn sys_03_body(context: &SystemContext, deadline: Instant) -> Outcome {
    let mut evidence = Vec::new();
    let (runtime, config) = require_config(context)?;
    verify_manifest_executable(&runtime, "odind")?;
    let ss = require_tool("ss", Some(&runtime))?;
    let scratch = command_scratch(context, "SYS-03")?;

    // Declared listeners, each from its real configured owner. The
    // declared host facts (or the tracked zellij-web unit declaration)
    // decide the zellij web port, and only while it is declared on.
    let facts = load_host_facts()?;
    let control = config.listener.address;
    let zellij = zellij_declared_endpoint(
        &context.dotfiles_root,
        facts.as_ref().map(|facts| &facts.zellij_web),
    )?;
    let (model_host, model_port) = model_endpoint(&config)?;
    let mut declared: BTreeMap<u16, String> = BTreeMap::new();
    declared.insert(control.port(), control.ip().to_string());
    declared.insert(model_port, model_host);
    if zellij.enabled {
        let (debug_host, debug_port) = &zellij.endpoint;
        if !is_loopback_host(debug_host) {
            return Err(CheckFailure::fail(
                "debug-listener-not-private",
                format!(
                    "the tracked zellij web declaration binds {debug_host}:{debug_port}, which is not loopback"
                ),
            ));
        }
        declared.insert(*debug_port, debug_host.clone());
    }
    note_evidence(
        &mut evidence,
        format!(
            "declared-ports={}",
            declared
                .iter()
                .map(|(port, host)| format!("{port}@{host}"))
                .collect::<Vec<_>>()
                .join(",")
        ),
    );

    let inventory = listener_inventory(&ss, &scratch, &context.odin_root, deadline)?;

    // Check discovery and disappearance using a loopback listener created by this process.
    let fixture =
        TcpListener::bind(SocketAddr::new(IpAddr::from([127, 0, 0, 1]), 0)).map_err(|error| {
            CheckFailure::fail(
                "listener-fixture-bind-failed",
                format!("owned loopback fixture bind failed: {error}"),
            )
        })?;
    let fixture_port = fixture
        .local_addr()
        .map_err(|error| {
            CheckFailure::fail(
                "listener-fixture-bind-failed",
                format!("owned fixture address unavailable: {error}"),
            )
        })?
        .port();
    let observed = listener_inventory(&ss, &scratch, &context.odin_root, deadline)?;
    let fixture_resolved = observed
        .iter()
        .any(|socket| socket.port == fixture_port && socket.owner_pid == Some(std::process::id()));
    drop(fixture);
    let after = listener_inventory(&ss, &scratch, &context.odin_root, deadline)?;
    let fixture_absent = !after.iter().any(|socket| socket.port == fixture_port);
    if !fixture_resolved || !fixture_absent {
        return Err(CheckFailure::fail(
            "listener-inventory-unreliable",
            "the owned loopback fixture was not resolved and cleaned in the real inventory",
        ));
    }
    note_evidence(&mut evidence, "listener-fixture=resolved-and-cleaned");

    listener_verdict(&declared, &inventory, evidence)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socket(address: &str, port: u16, owner: Option<(&str, u32)>) -> SocketObservation {
        SocketObservation {
            address: address.to_owned(),
            port,
            owner_pid: owner.map(|(_, pid)| pid),
            owner_name: owner.map(|(name, _)| name.to_owned()),
        }
    }

    fn declared() -> BTreeMap<u16, String> {
        BTreeMap::from([
            (18420, "127.0.0.1".to_owned()),
            (4000, "127.0.0.1".to_owned()),
        ])
    }

    fn healthy() -> Vec<SocketObservation> {
        vec![
            socket("127.0.0.1", 18420, Some(("odind", 10))),
            socket("127.0.0.1", 4000, Some((".litellm-wrappe", 11))),
            socket("0.0.0.0", 22, None),
            socket("*", 2586, Some(("ntfy", 12))),
            socket("0.0.0.0", 9418, Some(("git", 13))),
        ]
    }

    #[test]
    fn declared_private_listeners_and_owned_wildcards_pass() {
        let outcome = listener_verdict(&declared(), &healthy(), Vec::new()).expect("healthy");
        assert_eq!(outcome.status, CheckStatus::Pass, "{}", outcome.summary);
    }

    #[test]
    fn an_absent_declared_listener_fails() {
        let mut inventory = healthy();
        inventory.retain(|socket| socket.port != 18420);
        let failure = listener_verdict(&declared(), &inventory, Vec::new())
            .expect_err("odind's control listener is down");
        assert_eq!(failure.reason, "declared-listener-absent");
        assert!(
            failure.summary.contains("127.0.0.1:18420"),
            "{}",
            failure.summary
        );
    }

    #[test]
    fn a_wildcard_with_a_visible_pid_and_no_declared_owner_flags() {
        let mut inventory = healthy();
        inventory.push(socket("0.0.0.0", 7777, Some(("python3", 99))));
        let outcome =
            listener_verdict(&declared(), &inventory, Vec::new()).expect("a flag, not a fail");
        assert_eq!(outcome.status, CheckStatus::Flag);
        assert!(
            outcome.summary.contains("python3 pid=99"),
            "{}",
            outcome.summary
        );
    }

    #[test]
    fn an_attributed_port_held_by_another_process_fails() {
        let mut inventory = healthy();
        inventory.push(socket("0.0.0.0", 5000, Some(("python3", 99))));
        let failure = listener_verdict(&declared(), &inventory, Vec::new())
            .expect_err("a user process on harmonia's port is not harmonia");
        assert_eq!(failure.reason, "listener-bind-violation");
        let mut inventory = healthy();
        inventory.push(socket("*", 2586, Some(("nc", 98))));
        let failure = listener_verdict(&declared(), &inventory, Vec::new())
            .expect_err("ntfy's port is held by another process");
        assert_eq!(failure.reason, "listener-bind-violation");
    }

    #[test]
    fn a_declared_port_on_a_wildcard_fails() {
        let mut inventory = healthy();
        inventory.push(socket("0.0.0.0", 4000, None));
        let failure = listener_verdict(&declared(), &inventory, Vec::new())
            .expect_err("the gateway port is exposed");
        assert_eq!(failure.reason, "listener-bind-violation");
    }
}
