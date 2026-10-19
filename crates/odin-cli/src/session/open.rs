//! The operator's open and attach orchestration: the selected launch is
//! proven a declared option and the command identity derives from the strict
//! configuration, bounded authority is ensured before the daemon opens
//! anything, the open is always idle, and the interactive surface runs over
//! either the fresh composition or a verified existing bridge run.

use odin_cli::authority_provision::{
    self, LaunchSelection, SessionComposition, DEFAULT_TOKEN_TTL_SECONDS,
};
use odin_cli::operator_prompt::{self, OperatorPlanReceipt};
use odin_domain::huginn as live;
use odin_domain::NodeId;
use odin_huginn::client::{ColinRemoteClient, EndpointTransport, FileCredentialStore};
use odin_huginn::DeviceCredentialStore as _;
use odin_huginn::OdindConfig;
use odin_ledger::lane_run;
use odin_ledger::Ledger;
use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::interactive;
use super::plan::{deliver_first_prompt, prompt_text_from_file};
use super::transport::{
    endpoint_for, find_live_session, generated_command_id, zellij_session_name,
};

pub(crate) struct SessionRequest {
    pub config: PathBuf,
    /// Seat to open; `None` resolves the declared chat-seat default.
    pub seat: Option<String>,
    /// Project to open; `None` uses only the exact declared chat-seat binding.
    pub project: Option<String>,
    /// The declared launch to open with, required on every open and absent
    /// only on attach, which composes nothing.
    pub provider: Option<String>,
    /// The declared launch model to open with, required on every open and
    /// absent only on attach, which composes nothing.
    pub model: Option<String>,
    pub command_id: Option<String>,
    pub prompt_file: Option<PathBuf>,
    pub headless: bool,
    pub interactive: bool,
    pub json: bool,
    /// Attach the interactive client to an EXISTING live session instead of
    /// opening one; quitting detaches and the session keeps running.
    pub attach: Option<String>,
}

/// The machine-readable session open report. Paths and identifiers only.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionOpenReport {
    endpoint: String,
    command_id: String,
    session_id: String,
    epoch: u64,
    state: String,
    seat: String,
    project: String,
    lane: String,
    slice: String,
    provider: String,
    model: String,
    node: String,
    open_tab: bool,
    prompt_sent: bool,
    /// Present exactly when the operator prompt was durably accepted first.
    plan: Option<OperatorPlanReceipt>,
    token_path: PathBuf,
    token_id: String,
    token_ttl_seconds: u64,
    token_renewed: bool,
    token_reused: bool,
}

pub(crate) fn start(request: SessionRequest, output: &mut dyn Write) -> Result<(), String> {
    let config = OdindConfig::load(&request.config).map_err(|error| {
        format!(
            "could not load the controller configuration {}: {error}",
            request.config.display()
        )
    })?;
    // Attaching never opens, composes, or mints: the interactive client
    // rides the EXISTING governed session, and quitting only detaches.
    if let Some(raw) = &request.attach {
        return attach_session(raw, &config, output);
    }
    let (seat, project) =
        declared_defaults(&config, request.seat.as_deref(), request.project.as_deref())?;
    let (provider, model) = required_launch_selection(request.provider, request.model)?;
    let command_id = match request.command_id.as_deref() {
        Some(raw) => authority_provision::parse_command_uuid(raw)?,
        None => generated_command_id()?,
    };
    let composition = authority_provision::compose(
        &config,
        &seat,
        &project,
        &command_id,
        LaunchSelection::new(&provider, &model),
    )?;
    let prompt_text = match &request.prompt_file {
        Some(path) => Some(prompt_text_from_file(path)?),
        None => None,
    };
    let endpoint = endpoint_for(&config)?;
    let node = NodeId::parse(&config.identity.node).map_err(|error| {
        format!(
            "invalid controller node id {:?}: {error}",
            config.identity.node
        )
    })?;
    let open_request = open_session_request(&composition, node, !request.headless);
    let limits = odin_huginn::protocol::CodecLimits::default();
    let transport = EndpointTransport::new(endpoint.clone()).map_err(|error| error.to_string())?;
    let credential_root = config.paths.state_root.join("huginn");
    let credentials =
        FileCredentialStore::open(&credential_root).map_err(|error| error.to_string())?;
    let credential = credentials
        .load()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| {
            format!(
                "session {} (command {}) cannot open because no enrolled device credential exists at {}; no token was minted. Pair this loopback workstation first with `odin huginn --state-root {} devices pair --label LABEL --node UUID`",
                composition.live_session,
                composition.command_id,
                credential_root.join("device.credential").display(),
                config.paths.state_root.display()
            )
        })?;
    let client = ColinRemoteClient::with_limits(transport, credentials, limits);
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|error| format!("could not start the session client runtime: {error}"))?;

    // The token must exist before the daemon opens anything: the production
    // bridge verifies it during session listing, before the worker launches.
    // Reentry may reuse valid tokens; replacement requires explicit `--renew`.
    let mint = authority_provision::ensure_session_token(
        &config,
        &composition,
        DEFAULT_TOKEN_TTL_SECONDS,
        authority_provision::TokenRenewalPolicy::OperatorOnly,
    )
    .map_err(|error| {
        format!(
            "session {} (command {}) has no usable authority: {error}",
            composition.live_session, composition.command_id
        )
    })?;
    let opened = runtime.block_on(async {
        match client
            .request(live::HuginnRequest::OpenSession(open_request))
            .await
        {
            Ok(live::HuginnResponse::SessionOpened(summary)) => Ok(summary),
            Ok(other) => Err(format!(
                "the controller answered the session open with {other:?}"
            )),
            Err(error) => Err(error.to_string()),
        }
    });
    let summary = opened.map_err(|error| {
        format!(
            "session {} (command {}) failed to open: {error}; bounded token remains at {}",
            composition.live_session,
            composition.command_id,
            mint.token_path.display()
        )
    })?;
    if summary.session_id != composition.live_session {
        return Err(format!(
            "the controller returned session {}, but command {} provisioned {}",
            summary.session_id, composition.command_id, composition.live_session
        ));
    }

    // The gated first prompt: the session is open and idle, and no model
    // prompt exists yet. The shared acceptance owner proves the paired
    // operator device, verifies the supervisor's real bridge run, and
    // durably accepts the exact prompt — only then does the existing
    // Huginn Prompt command exist, bound to the opened epoch.
    let accepted = deliver_first_prompt(
        &runtime,
        &client,
        &config,
        &composition,
        &summary,
        &credential,
        prompt_text,
    )?;

    if request.interactive {
        let device = credential.device_id().map_err(|error| error.to_string())?;
        let identity = operator_prompt::operator_identity(&config.paths.state_root, device)?;
        let session = interactive::InteractiveSession {
            runtime: &runtime,
            client: &client,
            config: &config,
            gate: interactive::PlanGate::Opened(&composition),
            summary: &summary,
            identity: &identity,
            attach: false,
            zellij_session: zellij_session_name()?,
        };
        return interactive::run(&session, accepted.is_some(), output);
    }

    let report = SessionOpenReport {
        endpoint: endpoint.to_string(),
        command_id: composition.command_id.to_string(),
        session_id: summary.session_id.to_string(),
        epoch: summary.epoch.get(),
        state: format!("{:?}", summary.state),
        seat: composition.seat.to_string(),
        project: composition.project.to_string(),
        lane: composition.lane.to_string(),
        slice: composition.slice.to_string(),
        provider: composition.provider.to_string(),
        model: composition.model.to_string(),
        node: config.identity.node.clone(),
        open_tab: !request.headless,
        prompt_sent: accepted.is_some(),
        plan: accepted,
        token_path: mint.token_path,
        token_id: mint.token_id,
        token_ttl_seconds: mint.ttl_seconds,
        token_renewed: mint.renewed,
        token_reused: mint.reused_existing,
    };
    if request.json {
        let rendered = serde_json::to_string_pretty(&report)
            .map_err(|error| format!("could not serialize the open report: {error}"))?;
        writeln!(output, "{rendered}")
            .map_err(|error| format!("could not write report: {error}"))?;
        return Ok(());
    }
    let hints = control_hints(&report, &config.paths.state_root);
    writeln!(
        output,
        "session {} opened ({}): seat {} project {} lane {} slice {}",
        report.session_id, report.state, report.seat, report.project, report.lane, report.slice,
    )
    .map_err(|error| format!("could not write report: {error}"))?;
    writeln!(
        output,
        "model {}/{} node {} epoch {} command {}",
        report.provider, report.model, report.node, report.epoch, report.command_id
    )
    .map_err(|error| format!("could not write report: {error}"))?;
    if let Some(plan) = &report.plan {
        writeln!(
            output,
            "plan: accepted revision {} for run {} as {} (device label \"{}\")",
            plan.revision, plan.run, plan.actor, plan.label
        )
        .map_err(|error| format!("could not write report: {error}"))?;
        writeln!(
            output,
            "gated prompt: sent as command {} after the acceptance was verified",
            plan.prompt_command_id
        )
        .map_err(|error| format!("could not write report: {error}"))?;
    }
    writeln!(
        output,
        "authority: {} bounded token {} ({} s) at {}",
        if report.token_reused {
            "reused"
        } else {
            "minted"
        },
        report.token_id,
        report.token_ttl_seconds,
        report.token_path.display()
    )
    .map_err(|error| format!("could not write report: {error}"))?;
    if report.open_tab {
        writeln!(
            output,
            "surface: the controller opens the persistent zellij tab"
        )
    } else {
        writeln!(output, "surface: headless; attach when needed")
    }
    .map_err(|error| format!("could not write report: {error}"))?;
    writeln!(output, "follow-up controls:")
        .map_err(|error| format!("could not write report: {error}"))?;
    for hint in hints {
        writeln!(output, "  {hint}").map_err(|error| format!("could not write report: {error}"))?;
    }
    Ok(())
}

/// Attaches the interactive client to an EXISTING governed live session:
/// no composition, no token mint, no open. The session is located through
/// the controller's real session list, its durable bridge run is verified,
/// and the SAME plan-gated interactive surface runs over it — history
/// backfill, prompts, follow-ups, approvals. Quitting DETACHES: the
/// session keeps running.
fn attach_session(raw: &str, config: &OdindConfig, output: &mut dyn Write) -> Result<(), String> {
    let session_id = live::LiveSessionId::parse(raw)
        .map_err(|error| format!("invalid session id {raw:?}: {error}"))?;
    let endpoint = endpoint_for(config)?;
    let limits = odin_huginn::protocol::CodecLimits::default();
    let transport = EndpointTransport::new(endpoint).map_err(|error| error.to_string())?;
    let credential_root = config.paths.state_root.join("huginn");
    let credentials =
        FileCredentialStore::open(&credential_root).map_err(|error| error.to_string())?;
    let credential = credentials
        .load()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| {
            format!(
                "session {session_id} cannot attach because no enrolled device credential \
                 exists at {}; pair this loopback workstation first with `odin huginn \
                 --state-root {} devices pair --label LABEL --node UUID`",
                credential_root.join("device.credential").display(),
                config.paths.state_root.display()
            )
        })?;
    let client = ColinRemoteClient::with_limits(transport, credentials, limits);
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|error| format!("could not start the session client runtime: {error}"))?;
    let summary = find_live_session(&runtime, &client, session_id)?;
    // The durable bridge run must exist: attach rides the real run, and
    // the displayed lane is read FROM the record.
    let ledger = Ledger::open(config.paths.state_root.join("ledger.sqlite3"))
        .map_err(|error| format!("could not open the session state ledger: {error}"))?;
    let run_id = operator_prompt::session_run_id(&summary.session_id)?;
    let record = lane_run::read_run(ledger.connection(), &run_id)
        .map_err(|error| format!("could not read the session run {run_id}: {error}"))?
        .ok_or_else(|| {
            format!(
                "session {} has no durable bridge run {run_id}; the controller did not \
                 complete the session launch",
                summary.session_id
            )
        })?;
    let device = credential.device_id().map_err(|error| error.to_string())?;
    let identity = operator_prompt::operator_identity(&config.paths.state_root, device)?;
    let session = interactive::InteractiveSession {
        runtime: &runtime,
        client: &client,
        config,
        gate: interactive::PlanGate::Attached {
            seat: summary.seat_id.as_str().to_owned(),
            lane: record.lane_id.clone(),
        },
        summary: &summary,
        identity: &identity,
        attach: true,
        zellij_session: zellij_session_name()?,
    };
    interactive::run(&session, false, output)
}

/// Builds the real Huginn open request from the derived composition alone.
/// The open is always idle: the first prompt is only ever sent after its plan
/// is durably accepted.
fn open_session_request(
    composition: &SessionComposition,
    target_node: NodeId,
    open_tab: bool,
) -> live::OpenSessionRequest {
    live::OpenSessionRequest {
        command_id: composition.command_id.clone(),
        seat_id: composition.seat.clone(),
        project_id: composition.project.clone(),
        slice_id: composition.slice.clone(),
        provider: composition.provider.clone(),
        model: composition.model.clone(),
        title: None,
        target_node,
        open_tab,
        initial_prompt: None,
        workload: None,
        served_revision: Some(composition.snapshot_revision),
    }
}

/// Resolves the exact declared defaults for an unpinned `odin session` open:
/// both the seat and the project come from the ONE exact transport binding
/// (`[hermes.discord]`'s `seat` + `project`). No default is ever inferred
/// from `[[lane_bindings]]` order: an explicit `--seat` that differs from
/// the transport seat must name its `--project` explicitly, and an explicit
/// `--project` is always honored. Both defaults derive from the SAME strict
/// configuration the daemon serves — there are no compiled seat or project
/// literals, and no first-lane, first-entry, or map-order selection.
fn declared_defaults(
    config: &OdindConfig,
    seat: Option<&str>,
    project: Option<&str>,
) -> Result<(String, String), String> {
    let discord = config
        .hermes
        .as_ref()
        .and_then(|hermes| hermes.discord.as_ref());
    let transport_seat = discord.map(|discord| discord.seat.as_str());
    let transport_project = discord.map(|discord| discord.project.as_str());
    let seat = match seat {
        Some(explicit) => explicit.to_owned(),
        None => transport_seat
            .ok_or_else(|| {
                "no --seat was given and the configuration declares no [hermes.discord] chat \
                 seat; pass --seat explicitly"
                    .to_owned()
            })?
            .to_owned(),
    };
    let project = match project {
        Some(explicit) => explicit.to_owned(),
        // The exact transport project applies only to the transport's own
        // seat; every other seat must name its project explicitly.
        None if transport_seat == Some(seat.as_str()) => transport_project
            .ok_or_else(|| {
                "no --project was given and [hermes.discord] declares no project; pass \
                 --project explicitly"
                    .to_owned()
            })?
            .to_owned(),
        None => {
            return Err(format!(
                "no --project was given and seat {seat} is not the declared [hermes.discord] \
                 chat seat; pass --project explicitly"
            ));
        }
    };
    Ok((seat, project))
}

/// Open requires a launch selection; attach omits it because it does not compose.
fn required_launch_selection(
    provider: Option<String>,
    model: Option<String>,
) -> Result<(String, String), String> {
    match (provider, model) {
        (Some(provider), Some(model)) => Ok((provider, model)),
        _ => Err(
            "opening a session requires an explicit --provider and --model: the launch is a \
             declared selection, never a default inferred from declaration order"
                .to_owned(),
        ),
    }
}

/// The existing follow-up controls, rendered from real subcommands only.
fn control_hints(report: &SessionOpenReport, state_root: &Path) -> Vec<String> {
    let prefix = format!(
        "odin huginn --endpoint {} --state-root {}",
        report.endpoint,
        state_root.display()
    );
    vec![
        format!("{prefix} sessions"),
        format!(
            "{prefix} session prompt --command-id <new-command-uuid> --session {} --expected-epoch {} \"text\"",
            report.session_id, report.epoch
        ),
        format!("{prefix} terminal attach --session {} --expected-epoch {}", report.session_id, report.epoch),
        format!("{prefix} watch --kind agent-events --stream <stream-id>"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use odin_domain::CommandId;

    fn composition() -> SessionComposition {
        let policy = odin_omp::host_tools::operations::seat_operation_policy(
            odin_omp::host_tools::operations::SeatOperationPolicyInputs {
                seat_id: odin_domain::SeatId::new("architect").unwrap(),
                slice_id: odin_domain::SliceId::new("architect-core").unwrap(),
                lane_id: odin_domain::LaneId::new("architect-odin").unwrap(),
                seat_revision: odin_domain::Digest::hash(b"seat"),
                slice_revision: odin_domain::Digest::hash(b"slice"),
                admission: odin_domain::Digest::hash(b"admission"),
                seat_tool_refs: Default::default(),
                slice_capabilities: Default::default(),
                project_capabilities: Default::default(),
                lane_capabilities: Default::default(),
                denied_capabilities: Default::default(),
                denied_tools: Default::default(),
                resource_constraints: Default::default(),
                seat_categories: Default::default(),
            },
        );
        SessionComposition {
            command_id: CommandId::new("00000000-0000-4000-8000-000000000042").unwrap(),
            live_session: live::LiveSessionId::parse("00000000-0000-4000-8000-000000000001")
                .unwrap(),
            session: odin_domain::SessionId::parse("00000000-0000-4000-8000-000000000001").unwrap(),
            seat: odin_domain::SeatId::new("architect").unwrap(),
            project: odin_domain::ProjectId::new("odin").unwrap(),
            slice: odin_domain::SliceId::new("architect-core").unwrap(),
            lane: odin_domain::LaneId::new("architect-odin").unwrap(),
            provider: live::ProviderName::parse("openai-codex").unwrap(),
            model: live::ModelName::parse("gpt-6-astra").unwrap(),
            project_root: PathBuf::from("/tmp/odin"),
            snapshot_revision: 1,
            admission_digest: odin_domain::Digest::hash(b"admission"),
            policy,
        }
    }

    #[test]
    fn open_request_is_composed_entirely_from_the_derived_tuple() {
        let composition = composition();
        let node = NodeId::parse("laptop").unwrap();
        let request = open_session_request(&composition, node.clone(), true);
        assert_eq!(request.command_id, composition.command_id);
        assert_eq!(request.seat_id, composition.seat);
        assert_eq!(request.project_id, composition.project);
        assert_eq!(request.slice_id, composition.slice);
        assert_eq!(request.provider, composition.provider);
        assert_eq!(request.model, composition.model);
        assert_eq!(request.target_node, node);
        assert!(request.open_tab);
        assert!(request.title.is_none());
        // The open is always idle, even when a prompt file is supplied: the
        // prompt only travels after its plan is durably accepted.
        assert!(request.initial_prompt.is_none());

        let headless = open_session_request(&composition, node, false);
        assert!(!headless.open_tab);
        assert!(headless.initial_prompt.is_none());
    }

    /// One minimal strict configuration plus declared lane bindings and the
    /// exact Discord transport binding, parsed through the real strict
    /// parser.
    fn transport_config(lane_bindings: &str) -> OdindConfig {
        let mut text = String::from(
            "schema = 'odin.odind-config.v1'\nrevision = 1\nworker_bus = 'unix:/tmp/bus.sock'\n[identity]\nnode = 'laptop'\n[paths]\nregistry_root = '/'\nstate_root = '/'\nregistry_snapshot = '/'\nauthority_token_root = '/'\nauthority_verification_key_file = '/'\n[listener]\naddress = '127.0.0.1:18420'\n[executables]\nomp_bin = '/omp'\nomp_revision = '",
        );
        text.push_str(&"a".repeat(40));
        text.push_str(
            "'\nextension = '/ext.ts'\nzellij_bin = '/zellij'\nzellij_session = 'odin'\n[catalogs.gateway_projection]\npath = '/p.json'\ndigest = 'blake3:",
        );
        text.push_str(&"c".repeat(64));
        text.push_str(
            "'\n[publish]\nrender_session = '00000000-0000-4000-8000-0000000000aa'\nfile_lane = 'f'\nrender_lane = 'r'\n",
        );
        text.push_str(lane_bindings);
        text.push_str(
            "\n[hermes]\nstate_dir = '/var/lib/odin/hermes'\n[hermes.discord]\nseat = 'sinmara'\nproject = 'odin'\nowner_user_id = 'owner'\nnotify_channel_id = 'paired-channel'\ncapability = 'discord.intake'\negress_capacity = 8\ngateway_intents = 1\nbot_token_handle = 'cred:discord.bot'\nttl_seconds = 300\n[capacity]\n",
        );
        OdindConfig::parse(&text).expect("transport config parses")
    }

    #[test]
    fn session_defaults_bind_the_exact_transport_seat_and_project() {
        let first = transport_config(
            "\n[[lane_bindings]]\nseat = 'architect'\nproject = 'odin'\nlane = 'architect-odin'\n[[lane_bindings]]\nseat = 'architect'\nproject = 'dotfiles'\nlane = 'architect-dotfiles'\n[[lane_bindings]]\nseat = 'sinmara'\nproject = 'dotfiles'\nlane = 'sinmara-dotfiles'\n",
        );

        // No explicit flags: the exact transport binding is the default.
        let (seat, project) = declared_defaults(&first, None, None).expect("transport defaults");
        assert_eq!((seat.as_str(), project.as_str()), ("sinmara", "odin"));

        // Explicit seat and explicit project are honored verbatim.
        let (seat, project) =
            declared_defaults(&first, Some("architect"), Some("dotfiles")).expect("explicit pair");
        assert_eq!((seat.as_str(), project.as_str()), ("architect", "dotfiles"));

        // An explicit seat EQUAL to the transport seat still gets the exact
        // transport project.
        let (seat, project) =
            declared_defaults(&first, Some("sinmara"), None).expect("transport seat");
        assert_eq!((seat.as_str(), project.as_str()), ("sinmara", "odin"));

        // An explicit seat that differs from the transport seat NEVER
        // inherits a project from lane order — first entry or otherwise.
        let error = declared_defaults(&first, Some("architect"), None)
            .expect_err("no lane-order inference");
        assert!(
            error.contains("pass --project explicitly"),
            "unexpected error: {error}"
        );

        // Order independence: permuting the lane bindings cannot change any
        // resolution.
        let permuted = transport_config(
            "\n[[lane_bindings]]\nseat = 'sinmara'\nproject = 'dotfiles'\nlane = 'sinmara-dotfiles'\n[[lane_bindings]]\nseat = 'architect'\nproject = 'dotfiles'\nlane = 'architect-dotfiles'\n[[lane_bindings]]\nseat = 'architect'\nproject = 'odin'\nlane = 'architect-odin'\n",
        );
        let (seat, project) = declared_defaults(&permuted, None, None).expect("permuted defaults");
        assert_eq!((seat.as_str(), project.as_str()), ("sinmara", "odin"));
        assert!(declared_defaults(&permuted, Some("architect"), None).is_err());

        // Without a declared transport there is no default seat at all, and
        // an explicit seat still names its project explicitly.
        let mut bare = transport_config("");
        bare.hermes = None;
        let error = declared_defaults(&bare, None, None).expect_err("no default seat");
        assert!(error.contains("no --seat"), "unexpected error: {error}");
        let (seat, project) = declared_defaults(&bare, Some("architect"), Some("odin"))
            .expect("explicit pair without a transport");
        assert_eq!((seat.as_str(), project.as_str()), ("architect", "odin"));
        let error = declared_defaults(&bare, Some("architect"), None)
            .expect_err("explicit seat still needs a project");
        assert!(
            error.contains("pass --project explicitly"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn control_hints_render_real_subcommands_only() {
        let composition = composition();
        let report = SessionOpenReport {
            endpoint: "http://127.0.0.1:18420/".to_owned(),
            command_id: composition.command_id.to_string(),
            session_id: composition.session.to_string(),
            epoch: 1,
            state: "Idle".to_owned(),
            seat: composition.seat.to_string(),
            project: composition.project.to_string(),
            lane: composition.lane.to_string(),
            slice: composition.slice.to_string(),
            provider: composition.provider.to_string(),
            model: composition.model.to_string(),
            node: "laptop".to_owned(),
            open_tab: true,
            prompt_sent: false,
            plan: None,
            token_path: PathBuf::from("/tokens/x.json"),
            token_id: "seat-token:1:x".to_owned(),
            token_ttl_seconds: 86_400,
            token_renewed: false,
            token_reused: false,
        };
        let hints = control_hints(&report, Path::new("/state"));
        assert!(hints[0].contains(
            "odin huginn --endpoint http://127.0.0.1:18420/ --state-root /state sessions"
        ));
        assert!(hints[1].contains("session prompt --command-id <new-command-uuid>"));
        assert!(hints[2].contains("terminal attach --session"));
        assert!(hints[3].contains("watch --kind agent-events"));
    }
}
