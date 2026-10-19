use super::*;

pub(super) fn run_sys_07(context: &SystemContext, deadline: Instant) -> CheckResult {
    super::run_check("SYS-07", sys_07_body, context, deadline)
}

/// Baseline user units required independently of the Discord surface.
const REQUIRED_USER_UNITS: [&str; 1] = ["ntfy.service"];
const OPTIONAL_HUB_UNIT: &str = "hub-llm.service";

fn sys_07_body(context: &SystemContext, deadline: Instant) -> Outcome {
    let mut evidence = Vec::new();
    let (runtime, config) = require_config(context)?;
    verify_manifest_executable(&runtime, "odind")?;
    let ss = require_tool("ss", Some(&runtime))?;
    let scratch = command_scratch(context, "SYS-07")?;

    // The configured model endpoint must be LiteLLM answering its liveness
    // route; any other service on the port fails.
    let (model_host, model_port) = model_endpoint(&config)?;
    let address = SocketAddr::new(
        model_host.parse::<IpAddr>().map_err(|_| {
            CheckFailure::fail(
                "model-endpoint-not-addressable",
                format!("model endpoint host {model_host:?} is not a literal IP address"),
            )
        })?,
        model_port,
    );
    if !gateway_answers_as_litellm(address, deadline) {
        return Err(CheckFailure::fail(
            "model-endpoint-unhealthy",
            format!(
                "the configured model endpoint {address} does not answer LiteLLM's liveness route"
            ),
        ));
    }
    note_evidence(
        &mut evidence,
        format!("model-endpoint=litellm-live {address}"),
    );

    // User units must not fall back to the system manager; unreadable state must fail the check.
    let mut units = UnitStateReader::for_host(ManagerScope::UserOnly)?;
    for unit in REQUIRED_USER_UNITS {
        let note = require_user_unit_active(&mut units, unit)?;
        note_evidence(&mut evidence, note);
    }

    // A deployed Discord surface requires odind to hold the gateway; no declared surface is not a failure.
    if odin_discord_declared(&config) {
        note_evidence(
            &mut evidence,
            "discord-surface=declared ([hermes].discord in the deployed composition)",
        );
        let odind = units.unit("odind.service")?;
        note_evidence(&mut evidence, gateway_owner_running(&odind)?);
    } else {
        note_evidence(
            &mut evidence,
            "discord-surface=undeclared (the deployed composition declares no [hermes].discord)",
        );
    }

    // The declared zellij web listener: when the host declares the
    // zellij-web unit on (host facts or the tracked unit declaration) it
    // must be present and loopback-confined; when it is declared off, any
    // listener on the port is drift.
    let facts = load_host_facts()?;
    let zellij = zellij_declared_endpoint(
        &context.dotfiles_root,
        facts.as_ref().map(|facts| &facts.zellij_web),
    )?;
    let inventory = listener_inventory(&ss, &scratch, &context.odin_root, deadline)?;
    let (debug_host, debug_port) = &zellij.endpoint;
    let zellij_bound = inventory.iter().any(|socket| socket.port == *debug_port);
    if !zellij.enabled {
        if zellij_bound {
            return Err(CheckFailure::fail(
                "zellij-listener-drift",
                format!(
                    "the candidate declares the zellij web server off, but port {debug_port} is bound"
                ),
            ));
        }
        note_evidence(
            &mut evidence,
            format!("zellij-web=declared-off; port {debug_port} unbound"),
        );
    } else {
        let zellij_addresses = inventory
            .iter()
            .filter(|socket| socket.port == *debug_port)
            .map(|socket| socket.address.clone())
            .collect::<BTreeSet<_>>();
        if zellij_addresses.is_empty() {
            return Err(CheckFailure::fail(
                "zellij-listener-unhealthy",
                format!("the declared zellij web listener on port {debug_port} is absent"),
            ));
        }
        if zellij_addresses
            .iter()
            .any(|address| !host_allowed(debug_host, address))
        {
            return Err(CheckFailure::fail(
                "zellij-listener-unhealthy",
                format!(
                    "the declared zellij web listener is exposed beyond {debug_host}: {:?}",
                    zellij_addresses
                ),
            ));
        }
        note_evidence(
            &mut evidence,
            format!("zellij-listener={debug_host}:{debug_port}"),
        );
    }

    // The optional local model hub is advisory: absent, down, or
    // model-intentionally-absent states flag rather than fail. It is a user
    // unit, so it is likewise resolved against the user manager only.
    let hub = units.unit(OPTIONAL_HUB_UNIT);
    let (status, summary, reason) = match hub {
        Err(failure) => (
            CheckStatus::Flag,
            format!(
                "required services and listeners are healthy; the optional {OPTIONAL_HUB_UNIT} state is unavailable"
            ),
            Some(format!("optional-hub-query-error: {}", failure.reason)),
        ),
        Ok(properties) => {
            let loaded = properties.get("LoadState").map(String::as_str) == Some("loaded");
            let active = unit_active(&properties);
            let model_absent =
                properties.get("ConditionResult").map(String::as_str) == Some("no");
            if active {
                (
                    CheckStatus::Pass,
                    "all required services, the model endpoint, and the optional hub are healthy"
                        .to_owned(),
                    None,
                )
            } else if loaded && model_absent {
                (
                    CheckStatus::Pass,
                    "required services and listeners are healthy; the hub model is intentionally absent"
                        .to_owned(),
                    None,
                )
            } else {
                (
                    CheckStatus::Flag,
                    "required services and listeners are healthy; the optional hub is down"
                        .to_owned(),
                    Some("optional-hub-down".to_owned()),
                )
            }
        }
    };
    Ok(CheckOutcome {
        status,
        summary,
        reason,
        evidence,
    })
}

fn require_user_unit_active(
    units: &mut UnitStateReader,
    unit: &str,
) -> Result<String, CheckFailure> {
    let properties = units.unit(unit)?;
    if !unit_active(&properties) {
        return Err(CheckFailure::fail(
            "required-service-unhealthy",
            format!(
                "required user service {unit} is not active (LoadState={:?}, ActiveState={:?}, SubState={:?})",
                properties.get("LoadState"),
                properties.get("ActiveState"),
                properties.get("SubState")
            ),
        ));
    }
    Ok(format!("{unit}=active"))
}

/// The declared gateway owner is the authority's odind: it must be loaded,
/// active, and running. A failed or restarting odind holds no gateway.
fn gateway_owner_running(properties: &BTreeMap<String, String>) -> Result<String, CheckFailure> {
    let state = |key: &str| properties.get(key).map(String::as_str);
    if state("LoadState") != Some("loaded")
        || state("ActiveState") != Some("active")
        || state("SubState") != Some("running")
    {
        return Err(CheckFailure::fail(
            "gateway-owner-not-running",
            format!(
                "the declared gateway owner odind.service is not running in the user manager (LoadState={:?}, ActiveState={:?}, SubState={:?})",
                state("LoadState"),
                state("ActiveState"),
                state("SubState")
            ),
        ));
    }
    Ok("odind=active (running)".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use odin_process::test_support::RegisteredWorkerFixture;

    /// Separate D-Bus fixture managers count queries to detect access to the wrong manager.
    struct ManagerFixture {
        user: RegisteredWorkerFixture,
        system: RegisteredWorkerFixture,
    }

    impl ManagerFixture {
        fn new() -> Self {
            Self {
                user: RegisteredWorkerFixture::new().expect("user manager fixture"),
                system: RegisteredWorkerFixture::new().expect("system manager fixture"),
            }
        }

        fn reader(&self, scope: ManagerScope) -> UnitStateReader {
            UnitStateReader::at(scope, self.user.bus().clone(), self.system.bus().clone())
        }
    }

    #[test]
    fn a_loaded_active_user_unit_is_healthy_through_the_user_manager_only() {
        let managers = ManagerFixture::new();
        managers
            .user
            .plant_unit("ntfy.service", "loaded", "active", "running", &[]);
        managers
            .system
            .plant_unit("ntfy.service", "loaded", "active", "running", &[]);
        let mut units = managers.reader(ManagerScope::UserOnly);
        let note =
            require_user_unit_active(&mut units, "ntfy.service").expect("the unit is active");
        assert_eq!(note, "ntfy.service=active");
        assert_eq!(
            managers.system.queries(),
            0,
            "a declared user unit never consults the system manager"
        );
    }

    #[test]
    fn a_unit_present_only_in_the_system_manager_stays_unhealthy_without_system_fallback() {
        let managers = ManagerFixture::new();
        managers
            .system
            .plant_unit("example.service", "loaded", "active", "running", &[]);
        let mut units = managers.reader(ManagerScope::UserOnly);
        let failure = require_user_unit_active(&mut units, "example.service")
            .expect_err("a user unit is not satisfied by the system manager");
        assert_eq!(failure.status, CheckStatus::Fail);
        assert_eq!(
            failure.reason, "required-service-unhealthy",
            "{}",
            failure.summary
        );
        assert!(
            failure.summary.contains(r#"LoadState=Some("not-found")"#),
            "the honest unit answer must be reported: {}",
            failure.summary
        );
        assert_eq!(
            managers.system.queries(),
            0,
            "no system-manager fallback may rescue a user unit"
        );
    }

    /// The user manager cannot be consulted at all — every call refused —
    /// and the unit is system-managed: the `UserThenSystem` lookup still
    /// resolves it through the system manager. The refusal must never
    /// turn into a failed check.
    #[test]
    fn a_system_managed_unit_still_resolves_when_the_user_manager_is_unreachable() {
        let managers = ManagerFixture::new();
        managers.user.refuse_queries(true);
        managers
            .system
            .plant_unit("example.service", "loaded", "active", "running", &[]);
        let mut units = managers.reader(ManagerScope::UserThenSystem);
        let properties = units
            .unit("example.service")
            .expect("a refused user manager falls back to the system manager");
        assert_eq!(
            properties.get("LoadState").map(String::as_str),
            Some("loaded")
        );
        assert_eq!(
            properties.get("ActiveState").map(String::as_str),
            Some("active")
        );
        assert!(
            managers.user.queries() > 0,
            "the user manager was consulted and refused first"
        );
        assert!(
            managers.system.queries() > 0,
            "the system manager answered the fallback"
        );
    }

    #[test]
    fn a_refused_user_manager_is_a_typed_unreadable_failure() {
        let managers = ManagerFixture::new();
        managers.user.refuse_queries(true);
        let mut units = managers.reader(ManagerScope::UserOnly);
        let failure = require_user_unit_active(&mut units, "ntfy.service")
            .expect_err("a refused manager cannot pronounce a unit inactive");
        assert_eq!(failure.status, CheckStatus::Fail);
        assert_eq!(
            failure.reason, "unit-unreadable",
            "the refused read is typed; there is no shell fallback: {}",
            failure.summary
        );
        assert!(
            failure
                .summary
                .contains("user manager could not be consulted"),
            "the manager scope must be named: {}",
            failure.summary
        );
    }

    /// A unit the manager cannot find is an honest not-found answer, not an
    /// unreadable manager — the failure names the unit state, and the optional
    /// hub path can still flag advisory instead of failing the sweep.
    #[test]
    fn a_missing_unit_is_an_honest_not_found_answer() {
        let managers = ManagerFixture::new();
        let mut units = managers.reader(ManagerScope::UserOnly);
        let properties = units
            .unit("hub-llm.service")
            .expect("an absent unit is an answer, not a refused manager");
        assert_eq!(
            properties.get("LoadState").map(String::as_str),
            Some("not-found")
        );
        let failure = require_user_unit_active(&mut units, "hub-llm.service")
            .expect_err("an absent required unit is unhealthy");
        assert_eq!(failure.reason, "required-service-unhealthy");
        assert!(
            failure.summary.contains(r#"LoadState=Some("not-found")"#),
            "{}",
            failure.summary
        );
    }

    /// `SubState=auto-restart` is a crash loop between restarts: it must
    /// never ride an active-shaped sample into a Pass.
    #[test]
    fn an_auto_restarting_unit_is_not_active() {
        let managers = ManagerFixture::new();
        managers
            .user
            .plant_unit("ntfy.service", "loaded", "activating", "auto-restart", &[]);
        let mut units = managers.reader(ManagerScope::UserOnly);
        let failure = require_user_unit_active(&mut units, "ntfy.service")
            .expect_err("a crash loop is not a healthy required service");
        assert_eq!(failure.reason, "required-service-unhealthy");
        assert!(
            failure.summary.contains(r#"SubState=Some("auto-restart")"#),
            "{}",
            failure.summary
        );
        let active_shaped = BTreeMap::from([
            ("LoadState".to_owned(), "loaded".to_owned()),
            ("ActiveState".to_owned(), "active".to_owned()),
            ("SubState".to_owned(), "auto-restart".to_owned()),
        ]);
        assert!(
            !unit_active(&active_shaped),
            "even an active sample with SubState=auto-restart is a crash loop"
        );
    }

    #[test]
    fn the_gateway_owner_must_be_running() {
        let properties = |load: &str, active: &str, sub: &str| {
            BTreeMap::from([
                ("LoadState".to_owned(), load.to_owned()),
                ("ActiveState".to_owned(), active.to_owned()),
                ("SubState".to_owned(), sub.to_owned()),
            ])
        };
        gateway_owner_running(&properties("loaded", "active", "running"))
            .expect("a running odind holds the gateway");
        for (load, active, sub) in [
            ("loaded", "failed", "failed"),
            ("loaded", "activating", "auto-restart"),
            ("loaded", "inactive", "dead"),
            ("not-found", "inactive", "dead"),
        ] {
            let failure = gateway_owner_running(&properties(load, active, sub))
                .expect_err("an odind that is not running holds no gateway");
            assert_eq!(failure.status, CheckStatus::Fail);
            assert_eq!(failure.reason, "gateway-owner-not-running");
        }
    }

    #[test]
    fn an_auth_wall_on_the_model_port_is_not_the_gateway() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut request = [0_u8; 512];
                let _ = stream.read(&mut request);
                let _ = stream.write_all(b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\n\r\n");
            }
        });
        assert!(!gateway_answers_as_litellm(
            addr,
            Instant::now() + Duration::from_secs(10)
        ));
    }

    /// Writes one zellij.nix fixture body and parses the declared
    /// endpoint from it.
    fn parse_fixture(body: &str) -> Result<ZellijWebDeclaration, CheckFailure> {
        let root = tempfile::tempdir().expect("dotfiles fixture is creatable");
        let module = root.path().join("modules/home");
        fs::create_dir_all(&module).expect("module dir is creatable");
        fs::write(module.join("zellij.nix"), body).expect("zellij fixture is writable");
        zellij_declared_endpoint(root.path(), None)
    }

    #[test]
    fn the_parser_reads_the_declared_service_not_the_settings_block() {
        // The real declaration shape: a webPort let-binding, the
        // zellij-web user unit with its ExecStart, and a settings block
        // that turns the built-in server off and names an identifier.
        let declaration = parse_fixture(
            r#"_: {
  webPort = 8093; # loopback
  systemd.user.services.zellij-web = {
    Service.ExecStart = "${pkgs.zellij}/bin/zellij web --start --ip 127.0.0.1 --port ${toString webPort}";
  };
  programs.zellij.settings = {
    web_server = false;
    web_server_ip = "127.0.0.1";
    web_server_port = webPort;
  };
}
"#,
        )
        .expect("the declared service parses");
        assert!(
            declaration.enabled,
            "the zellij-web unit declares the server on"
        );
        assert_eq!(declaration.endpoint, ("127.0.0.1".to_owned(), 8093));
    }

    #[test]
    fn the_old_settings_identifier_form_is_rejected() {
        // No let-binding and no unit: the identifier `webPort` behind
        // web_server_port must never be mistaken for a port.
        let failure = parse_fixture(
            r#"_: {
  programs.zellij.settings = {
    web_server = true;
    web_server_ip = "127.0.0.1";
    web_server_port = webPort;
  };
}
"#,
        )
        .expect_err("the old settings-identifier form must fail");
        assert_eq!(failure.reason, "zellij-declaration-invalid");
        assert!(failure.summary.contains("webPort"));
    }

    #[test]
    fn a_unit_without_an_execstart_declares_the_server_off() {
        let declaration = parse_fixture(
            r#"_: {
  webPort = 8093;
  systemd.user.services.zellij-web = {
    Unit.Description = "reserved";
  };
  programs.zellij.settings = {
    web_server_ip = "127.0.0.1";
  };
}
"#,
        )
        .expect("the declaration parses");
        assert!(!declaration.enabled, "no ExecStart, no declared server");
        assert_eq!(declaration.endpoint, ("127.0.0.1".to_owned(), 8093));
    }

    #[test]
    fn the_declared_host_facts_win_over_the_textual_scan() {
        let facts = ZellijWebFacts {
            enabled: false,
            ip: "127.0.0.1".to_owned(),
            port: 9093,
        };
        let declaration = zellij_declared_endpoint(Path::new("/nonexistent"), Some(&facts))
            .expect("declared facts decide without touching the checkout");
        assert!(!declaration.enabled);
        assert_eq!(declaration.endpoint, ("127.0.0.1".to_owned(), 9093));
    }
}
