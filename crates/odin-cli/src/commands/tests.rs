use std::fs;
use std::path::PathBuf;

use crate::commands::authority::{AuthorityArgs, AuthorityCommand};
use crate::commands::huginn::HuginnPlan;
use crate::{run, Cli, Command, RunStatus};
use clap::Parser;
use odin_cli::authority_provision;
use odin_domain::huginn as live;
use odin_domain::{ApprovalId, ApprovalStatus, CapabilityId, Digest, LaneId, LeaseId, ProviderId};
use odin_kernel::{
    ApprovalGate, ApprovalScope, NewApproval, ProviderHealth, ProviderQuotaSnapshot,
};
use odin_ledger::provider_lease::{NewProviderLease, ProviderLeaseBoundary, ProviderLeaseEnd};
use odin_ledger::Ledger;
use odin_registry::RegistryKind;
use tempfile::TempDir;
use time::{Duration, OffsetDateTime};

use crate::commands::approval::{ApproveArgs, DecisionTarget, RejectArgs};
use crate::commands::atlas::{providers, ProvidersArgs};
use crate::commands::session::SessionInvocation;
use crate::session;

/// The wrapper environment default is process-global: tests that exercise
/// `ODIN_CONFIG` resolution serialize on this lock.
static CONFIG_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn request_approval(state_root: &TempDir, raw_id: &str) -> ApprovalId {
    let approval_id = write_requested(state_root, raw_id);
    publish_admitted(state_root, "system.activate");
    approval_id
}

fn write_requested(state_root: &TempDir, raw_id: &str) -> ApprovalId {
    fs::create_dir_all(state_root.path()).unwrap();
    let approval_id = ApprovalId::new(raw_id).unwrap();
    let now = OffsetDateTime::now_utc();
    let mut ledger = Ledger::open(state_root.path().join("ledger.sqlite3")).unwrap();
    ApprovalGate::new(&mut ledger)
        .request(NewApproval {
            approval_id: approval_id.clone(),
            issuer: "seat:operator".to_owned(),
            scope: ApprovalScope {
                target_kind: "host".to_owned(),
                target_id: "laptop".to_owned(),
                capability_id: CapabilityId::new("system.activate").unwrap(),
                arguments_digest: Digest::hash(b"fixture"),
            },
            requested_at: now,
            expires_at: now + Duration::hours(1),
        })
        .unwrap();
    approval_id
}

fn target(state_root: &TempDir, approval: &ApprovalId, revision: i64) -> DecisionTarget {
    DecisionTarget {
        state_root: state_root.path().to_path_buf(),
        approval: approval.to_string(),
        expected_revision: revision,
        decider: "human:operator".to_owned(),
        json: true,
    }
}

fn stored_approval(state_root: &TempDir, approval_id: &ApprovalId) -> odin_kernel::Approval {
    Ledger::open(state_root.path().join("ledger.sqlite3"))
        .unwrap()
        .approval(approval_id)
        .unwrap()
        .unwrap()
}

fn publish_admitted(state_root: &TempDir, capability: &str) {
    let worktree = state_root.path().join("authoring");
    fs::create_dir_all(&worktree).unwrap();
    git(&worktree, &["-c", "init.defaultBranch=main", "init"]);
    let registry = worktree.join("registry");
    for kind in RegistryKind::ALL {
        let directory = registry.join(kind.directory());
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join(".gitkeep"), b"").unwrap();
    }
    for (path, contents) in [
        (
            "nodes/authority/node.toml",
            r#"schema = "odin.registry.v1"
kind = "node"
enabled = true
description = "Approval fixture authority"
host = "authority-host"
role = "control"
capabilities = []
allow_workloads = false
authoritative_state = true
"#,
        ),
        (
            "hosts/authority-host/host.toml",
            r#"schema = "odin.registry.v1"
kind = "host"
enabled = true
description = "Approval fixture host"
hardware = "fixture"
role = "control"
tailscale = "authority-host"
enrolled = true
"#,
        ),
    ] {
        let path = registry.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
    let object = registry.join("capabilities").join(capability);
    fs::create_dir_all(&object).unwrap();
    fs::write(object.join("capability.toml"), capability_toml(capability)).unwrap();
    fs::create_dir_all(worktree.join("schemas/capability")).unwrap();
    fs::write(worktree.join("schemas/.gitkeep"), b"").unwrap();
    let schema = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}"#;
    fs::write(
        worktree.join(format!("schemas/capability/{capability}.input.json")),
        schema,
    )
    .unwrap();
    fs::write(
        worktree.join(format!("schemas/capability/{capability}.output.json")),
        schema,
    )
    .unwrap();
    let commit = commit_all(&worktree, "admit capability");
    let candidate = odin_registry::ValidatedSnapshotCandidate::from_committed_worktree(
        &worktree,
        &commit,
        [admitted_binding(capability)],
    )
    .expect("committed capability candidate");
    odin_registry::SnapshotStore::new(state_root.path().join("registry/snapshot.json"))
        .publish_committed(&candidate, 1)
        .expect("publish admitted snapshot");
}

fn capability_toml(capability: &str) -> String {
    format!(
        "schema = \"odin.registry.v1\"\n\
         kind = \"capability\"\n\
         enabled = true\n\
         implementation = \"builtin\"\n\
         version = 1\n\
         description = \"Fixture capability.\"\n\
         handler = {{ id = \"fixture_handler\" }}\n\
         input_schema = \"schemas/capability/{capability}.input.json\"\n\
         output_schema = \"schemas/capability/{capability}.output.json\"\n\
         effect_class = \"R1\"\n\
         seat_tags = [\"*\"]\n\
         timeout_seconds = 30\n\
         idempotency = \"required\"\n\
         retry = {{ max_attempts = 0 }}\n\
         approval_policy = \"none\"\n\
         evidence_extractor = {{ id = \"fixture_evidence\" }}\n"
    )
}

fn admitted_binding(capability: &str) -> odin_registry::AdmittedBinding {
    use odin_registry::schema::{BuiltinHandlerToml, HandlerBindingToml};
    odin_registry::AdmittedBinding {
        version: 1,
        input_schema: format!("schemas/capability/{capability}.input.json"),
        output_schema: format!("schemas/capability/{capability}.output.json"),
        handler: HandlerBindingToml::Builtin(BuiltinHandlerToml {
            id: "fixture_handler".to_owned(),
        }),
        evidence_extractor: HandlerBindingToml::Builtin(BuiltinHandlerToml {
            id: "fixture_evidence".to_owned(),
        }),
    }
}

fn git(worktree: &std::path::Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("spawn git");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("git output is UTF-8")
        .trim_end()
        .to_owned()
}

fn commit_all(worktree: &std::path::Path, message: &str) -> String {
    git(worktree, &["add", "-A"]);
    git(
        worktree,
        &[
            "-c",
            "user.name=Odin Test",
            "-c",
            "user.email=odin-test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            message,
        ],
    );
    git(worktree, &["rev-parse", "HEAD"])
}

#[test]
fn approve_persists_exact_revision_decision() {
    let state_root = TempDir::new().unwrap();
    let approval_id = request_approval(&state_root, "approval:approve");
    let cli = Cli {
        command: Some(Command::Approve(ApproveArgs {
            target: target(&state_root, &approval_id, 1),
            evidence: Some("artifact:review".to_owned()),
        })),
    };
    let mut output = Vec::new();

    assert_eq!(run(cli, &mut output).unwrap(), RunStatus::Success);
    let approval = stored_approval(&state_root, &approval_id);
    assert_eq!(approval.status, ApprovalStatus::Approved);
    assert_eq!(approval.revision, 2);
    assert_eq!(approval.decided_by.as_deref(), Some("human:operator"));
    assert_eq!(
        approval.decision_evidence_ref.as_deref(),
        Some("artifact:review")
    );
    let report: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["schema"], "odin.approval-decision.v1");
    assert_eq!(report["approval"], "approval:approve");
    assert_eq!(report["status"], "approved");
    assert_eq!(report["revision"], 2);
    assert_eq!(report["decider"], "human:operator");
    assert_eq!(report["evidence"], "artifact:review");
    assert!(report.get("redirect").is_none());
}

#[test]
fn reject_persists_denial_evidence() {
    let state_root = TempDir::new().unwrap();
    let approval_id = request_approval(&state_root, "approval:reject");
    let cli = Cli {
        command: Some(Command::Reject(RejectArgs {
            target: target(&state_root, &approval_id, 1),
            evidence: "artifact:denial".to_owned(),
        })),
    };
    let mut output = Vec::new();

    assert_eq!(run(cli, &mut output).unwrap(), RunStatus::Success);
    let approval = stored_approval(&state_root, &approval_id);
    assert_eq!(approval.status, ApprovalStatus::Denied);
    assert_eq!(approval.revision, 2);
    assert_eq!(
        approval.decision_evidence_ref.as_deref(),
        Some("artifact:denial")
    );
    let report: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["status"], "denied");
    assert_eq!(report["evidence"], "artifact:denial");
}

#[test]
fn reject_requires_nonempty_evidence_without_writing() {
    let state_root = TempDir::new().unwrap();
    let approval_id = request_approval(&state_root, "approval:no-evidence");
    let parse_error = Cli::try_parse_from([
        "odin",
        "reject",
        "--state-root",
        state_root.path().to_str().unwrap(),
        "--approval",
        approval_id.as_str(),
        "--expected-revision",
        "1",
        "--decider",
        "human:operator",
    ])
    .unwrap_err();
    assert_eq!(
        parse_error.kind(),
        clap::error::ErrorKind::MissingRequiredArgument
    );

    let whitespace = Cli {
        command: Some(Command::Reject(RejectArgs {
            target: target(&state_root, &approval_id, 1),
            evidence: "  ".to_owned(),
        })),
    };
    assert!(run(whitespace, &mut Vec::new()).is_err());
    let approval = stored_approval(&state_root, &approval_id);
    assert_eq!(approval.status, ApprovalStatus::Requested);
    assert_eq!(approval.revision, 1);
}

#[test]
fn unresolved_capability_refuses_without_writing() {
    let state_root = TempDir::new().unwrap();
    let approval_id = write_requested(&state_root, "approval:unresolved");
    publish_admitted(&state_root, "other.capability");
    let cli = Cli {
        command: Some(Command::Approve(ApproveArgs {
            target: target(&state_root, &approval_id, 1),
            evidence: None,
        })),
    };

    let _error = run(cli, &mut Vec::new()).unwrap_err();
    let approval = stored_approval(&state_root, &approval_id);
    assert_eq!(approval.status, ApprovalStatus::Requested);
    assert_eq!(approval.revision, 1);
}

#[test]
fn stale_revision_redirects_without_writing() {
    let state_root = TempDir::new().unwrap();
    let approval_id = request_approval(&state_root, "approval:stale");
    let cli = Cli {
        command: Some(Command::Approve(ApproveArgs {
            target: target(&state_root, &approval_id, 0),
            evidence: None,
        })),
    };
    let mut output = Vec::new();

    assert_eq!(run(cli, &mut output).unwrap(), RunStatus::Redirect);
    let approval = stored_approval(&state_root, &approval_id);
    assert_eq!(approval.status, ApprovalStatus::Requested);
    assert_eq!(approval.revision, 1);
    let report: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["schema"], "odin.approval-decision.v1");
    assert_eq!(report["approval"], "approval:stale");
    assert!(report["status"].is_null());
    assert_eq!(report["revision"], 1);
    assert!(report["decider"].is_null());
    assert!(report["evidence"].is_null());
    assert_eq!(report["redirect"]["kind"], "staleRevision");
    assert_eq!(report["redirect"]["expectedRevision"], 0);
    assert_eq!(report["redirect"]["actualRevision"], 1);
}

#[test]
fn no_arguments_selects_the_seat_menu_path() {
    let cli = Cli::try_parse_from(["odin"]).unwrap();
    assert!(cli.command.is_none());
}

#[test]
fn session_subcommand_parses_the_production_orchestrator_flags() {
    let cli = Cli::try_parse_from([
        "odin",
        "session",
        "--config",
        "/etc/odin/odind.toml",
        "--seat",
        "architect",
        "--project",
        "odin",
        "--provider",
        "gateway",
        "--model",
        "deepseek-chat",
        "--command-id",
        "00000000-0000-4000-8000-000000000042",
        "--prompt-file",
        "/tmp/prompt.txt",
        "--headless",
        "--json",
    ])
    .unwrap();
    let Some(Command::Session(arguments)) = cli.command else {
        panic!("expected the session subcommand");
    };
    assert_eq!(
        arguments.config.as_deref(),
        Some(std::path::Path::new("/etc/odin/odind.toml"))
    );
    assert_eq!(arguments.seat.as_deref(), Some("architect"));
    assert_eq!(arguments.project.as_deref(), Some("odin"));
    assert_eq!(arguments.provider.as_deref(), Some("gateway"));
    assert_eq!(arguments.model.as_deref(), Some("deepseek-chat"));
    assert_eq!(
        arguments.command_id.as_deref(),
        Some("00000000-0000-4000-8000-000000000042")
    );
    assert_eq!(
        arguments.prompt_file.as_deref(),
        Some(std::path::Path::new("/tmp/prompt.txt"))
    );
    assert!(arguments.headless);
    assert!(arguments.json);
}

#[test]
fn session_open_requires_an_explicit_declared_launch_pair() {
    // Both flags are REQUIRED on the open path: the launch is a selection,
    // and there is no default, alias, or positional fallback.
    for flags in [
        vec!["odin", "session", "--interactive"],
        vec!["odin", "session", "--interactive", "--provider", "gateway"],
        vec![
            "odin",
            "session",
            "--interactive",
            "--model",
            "deepseek-chat",
        ],
    ] {
        let error = Cli::try_parse_from(flags.clone()).unwrap_err();
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument,
            "expected a required-launch refusal for {flags:?}"
        );
    }
    // A complete open resolves both into the request.
    let cli = Cli::try_parse_from([
        "odin",
        "session",
        "--config",
        "/etc/odin/odind.toml",
        "--provider",
        "gateway",
        "--model",
        "deepseek-chat",
    ])
    .unwrap();
    let Some(Command::Session(arguments)) = cli.command else {
        panic!("expected the session subcommand");
    };
    match arguments.into_invocation().unwrap() {
        SessionInvocation::Open(request) => {
            assert_eq!(request.provider.as_deref(), Some("gateway"));
            assert_eq!(request.model.as_deref(), Some("deepseek-chat"));
        }
        SessionInvocation::Terminal(_) => panic!("expected the open invocation"),
    }
    // Attaching composes nothing, so it neither requires nor accepts a
    // launch selection.
    let attached = Cli::try_parse_from([
        "odin",
        "session",
        "--config",
        "/etc/odin/odind.toml",
        "--attach",
        "00000000-0000-4000-8000-000000000007",
    ])
    .unwrap();
    let Some(Command::Session(arguments)) = attached.command else {
        panic!("expected the session subcommand");
    };
    match arguments.into_invocation().unwrap() {
        SessionInvocation::Open(request) => {
            assert_eq!(request.provider, None);
            assert_eq!(request.model, None);
        }
        SessionInvocation::Terminal(_) => panic!("expected the open invocation"),
    }
    let error = Cli::try_parse_from([
        "odin",
        "session",
        "--attach",
        "00000000-0000-4000-8000-000000000007",
        "--provider",
        "gateway",
        "--model",
        "deepseek-chat",
    ])
    .unwrap_err();
    assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    // The terminal-administration modes open nothing either: they parse with
    // no launch selection at all.
    for mode in ["status", "unbind"] {
        let cli = Cli::try_parse_from(["odin", "session", mode]).unwrap();
        let Some(Command::Session(arguments)) = cli.command else {
            panic!("expected the session subcommand");
        };
        assert_eq!(arguments.provider, None);
        assert_eq!(arguments.model, None);
    }
}

#[test]
fn plan_accept_parses_the_local_session_acceptance_flags() {
    let cli = Cli::try_parse_from([
        "odin",
        "plan",
        "--config",
        "/etc/odin/odind.toml",
        "accept",
        "--session",
        "00000000-0000-4000-8000-000000000001",
        "--expected-revision",
        "3",
    ])
    .unwrap();
    let Some(Command::Plan(arguments)) = cli.command else {
        panic!("expected the plan subcommand");
    };
    assert_eq!(
        arguments.config.as_path(),
        std::path::Path::new("/etc/odin/odind.toml")
    );
    let request = arguments.into_accept_request();
    assert_eq!(request.session, "00000000-0000-4000-8000-000000000001");
    assert_eq!(request.expected_revision, Some(3));

    let cli = Cli::try_parse_from([
        "odin",
        "plan",
        "--config",
        "/etc/odin/odind.toml",
        "accept",
        "--session",
        "00000000-0000-4000-8000-000000000001",
    ])
    .unwrap();
    let Some(Command::Plan(arguments)) = cli.command else {
        panic!("expected the plan subcommand");
    };
    assert_eq!(arguments.into_accept_request().expected_revision, None);
}

#[test]
fn plan_accept_requires_config_and_session() {
    let error = Cli::try_parse_from(["odin", "plan", "accept"]).unwrap_err();
    assert_eq!(
        error.kind(),
        clap::error::ErrorKind::MissingRequiredArgument
    );
}

#[test]
fn session_subcommand_resolves_config_from_flag_environment_or_typed_error() {
    let _environment = CONFIG_ENV_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    // The explicit flag wins over the environment default.
    std::env::set_var("ODIN_CONFIG", "/env/odind.toml");
    let flagged = Cli::try_parse_from([
        "odin",
        "session",
        "--config",
        "/flag/odind.toml",
        "--provider",
        "gateway",
        "--model",
        "deepseek-chat",
        "--interactive",
    ])
    .unwrap();
    let Some(Command::Session(arguments)) = flagged.command else {
        panic!("expected the session subcommand");
    };
    match arguments.into_invocation().unwrap() {
        SessionInvocation::Open(request) => {
            assert_eq!(request.config, PathBuf::from("/flag/odind.toml"))
        }
        SessionInvocation::Terminal(_) => panic!("expected the open invocation"),
    }

    // Without the flag the wrapper-provided environment default is read.
    let bare = Cli::try_parse_from([
        "odin",
        "session",
        "--provider",
        "gateway",
        "--model",
        "deepseek-chat",
        "--interactive",
    ])
    .unwrap();
    let Some(Command::Session(arguments)) = bare.command else {
        panic!("expected the session subcommand");
    };
    match arguments.into_invocation().unwrap() {
        SessionInvocation::Open(request) => {
            assert_eq!(request.config, PathBuf::from("/env/odind.toml"));
            assert!(request.interactive);
        }
        SessionInvocation::Terminal(_) => panic!("expected the open invocation"),
    }

    // With neither declaration the typed error names both remedies.
    std::env::remove_var("ODIN_CONFIG");
    let undeclared = Cli::try_parse_from([
        "odin",
        "session",
        "--provider",
        "gateway",
        "--model",
        "deepseek-chat",
        "--interactive",
    ])
    .unwrap();
    let Some(Command::Session(arguments)) = undeclared.command else {
        panic!("expected the session subcommand");
    };
    let error = match arguments.into_invocation() {
        Err(error) => error,
        Ok(_) => panic!("expected the typed missing-configuration error"),
    };
    assert!(error.contains("--config"), "{error}");
    assert!(error.contains("ODIN_CONFIG"), "{error}");

    // An empty environment default counts as undeclared.
    std::env::set_var("ODIN_CONFIG", "   ");
    let empty = Cli::try_parse_from([
        "odin",
        "session",
        "--provider",
        "gateway",
        "--model",
        "deepseek-chat",
        "--interactive",
    ])
    .unwrap();
    let Some(Command::Session(arguments)) = empty.command else {
        panic!("expected the session subcommand");
    };
    let error = match arguments.into_invocation() {
        Err(error) => error,
        Ok(_) => panic!("expected the typed empty-environment error"),
    };
    assert!(error.contains("ODIN_CONFIG"), "{error}");
    std::env::remove_var("ODIN_CONFIG");

    // The strict composition still rejects obsolete flags verbatim.
    let old = Cli::try_parse_from([
        "odin",
        "session",
        "--config",
        "/etc/odin/odind.toml",
        "--seat",
        "architect",
        "--project",
        "odin",
        "--provider",
        "gateway",
        "--model",
        "deepseek-chat",
        "--lane",
        "obsolete",
    ])
    .unwrap_err();
    assert_eq!(old.kind(), clap::error::ErrorKind::UnknownArgument);
}

#[test]
fn session_attach_and_terminal_surfaces_resolve_config_the_same_way() {
    let _environment = CONFIG_ENV_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    std::env::set_var("ODIN_CONFIG", "/env/odind.toml");

    // Attach rides the same open surface and resolution; semantics unchanged.
    let attached = Cli::try_parse_from([
        "odin",
        "session",
        "--attach",
        "00000000-0000-4000-8000-000000000007",
    ])
    .unwrap();
    let Some(Command::Session(arguments)) = attached.command else {
        panic!("expected the session subcommand");
    };
    match arguments.into_invocation().unwrap() {
        SessionInvocation::Open(request) => {
            assert_eq!(request.config, PathBuf::from("/env/odind.toml"));
            assert_eq!(
                request.attach.as_deref(),
                Some("00000000-0000-4000-8000-000000000007")
            );
            assert!(request.interactive);
        }
        SessionInvocation::Terminal(_) => panic!("expected the open invocation"),
    }

    // The terminal administration surface resolves identically.
    let bound = Cli::try_parse_from([
        "odin",
        "session",
        "bind",
        "--config",
        "/flag/odind.toml",
        "sinmara-tab",
    ])
    .unwrap();
    let Some(Command::Session(arguments)) = bound.command else {
        panic!("expected the session subcommand");
    };
    match arguments.into_invocation().unwrap() {
        SessionInvocation::Terminal(request) => {
            assert_eq!(request.config, PathBuf::from("/flag/odind.toml"));
            match request.command {
                session::TerminalCommand::Bind(name) => assert_eq!(name, "sinmara-tab"),
                _ => panic!("expected the bind command"),
            }
        }
        SessionInvocation::Open(_) => panic!("expected the terminal invocation"),
    }

    let status = Cli::try_parse_from(["odin", "session", "status"]).unwrap();
    let Some(Command::Session(arguments)) = status.command else {
        panic!("expected the session subcommand");
    };
    match arguments.into_invocation().unwrap() {
        SessionInvocation::Terminal(request) => {
            assert_eq!(request.config, PathBuf::from("/env/odind.toml"));
            match request.command {
                session::TerminalCommand::Status => {}
                _ => panic!("expected the status command"),
            }
        }
        SessionInvocation::Open(_) => panic!("expected the terminal invocation"),
    }

    // Without any declaration even the terminal surface fails honestly.
    std::env::remove_var("ODIN_CONFIG");
    let unbound = Cli::try_parse_from(["odin", "session", "unbind"]).unwrap();
    let Some(Command::Session(arguments)) = unbound.command else {
        panic!("expected the session subcommand");
    };
    let error = match arguments.into_invocation() {
        Err(error) => error,
        Ok(_) => panic!("expected the typed missing-configuration error"),
    };
    assert!(error.contains("--config"), "{error}");
    assert!(error.contains("ODIN_CONFIG"), "{error}");
}

#[test]
fn authority_subcommands_parse_explicit_init_mint_and_renewal() {
    let init = Cli::try_parse_from([
        "odin",
        "authority",
        "init",
        "--config",
        "/etc/odin/odind.toml",
    ])
    .unwrap();
    assert!(matches!(
        init.command,
        Some(Command::Authority(AuthorityArgs {
            command: AuthorityCommand::Init(_)
        }))
    ));

    let mint = Cli::try_parse_from([
        "odin",
        "authority",
        "mint",
        "--config",
        "/etc/odin/odind.toml",
        "--command-id",
        "00000000-0000-4000-8000-000000000042",
        "--seat",
        "architect",
        "--project",
        "odin",
        "--provider",
        "gateway",
        "--model",
        "deepseek-chat",
    ])
    .unwrap();
    let Some(Command::Authority(AuthorityArgs {
        command: AuthorityCommand::Mint(defaults),
    })) = mint.command
    else {
        panic!("expected authority mint");
    };
    assert_eq!(
        defaults.ttl_seconds,
        authority_provision::DEFAULT_TOKEN_TTL_SECONDS
    );
    assert!(!defaults.renew);

    let renewed = Cli::try_parse_from([
        "odin",
        "authority",
        "mint",
        "--config",
        "/etc/odin/odind.toml",
        "--command-id",
        "00000000-0000-4000-8000-000000000042",
        "--seat",
        "architect",
        "--project",
        "odin",
        "--provider",
        "gateway",
        "--model",
        "deepseek-chat",
        "--ttl-seconds",
        "60",
        "--renew",
    ])
    .unwrap();
    let Some(Command::Authority(AuthorityArgs {
        command: AuthorityCommand::Mint(explicit),
    })) = renewed.command
    else {
        panic!("expected explicit authority renewal");
    };
    assert_eq!(explicit.ttl_seconds, 60);
    assert!(explicit.renew);
}

const GATEWAY_PROVIDER_TOML: &str = concat!(
    "schema = \"odin.registry.v1\"\n",
    "kind = \"provider\"\n",
    "enabled = true\n",
    "description = \"The deployed LiteLLM loopback gateway with hard budgets; lanes resolve through it.\"\n",
    "adapter = \"litellm-gateway\"\n",
    "policy = { routes = [{ gateway_lane_id = \"zai-glm\", gateway_model_id = \"openai/glm-5.3\" }] }\n",
    "budget = { usd_micros = 30_000_000, window = { duration_seconds = 2_592_000 } }\n",
    "recovery = { allowed_rungs = [\"retry\", \"restart_worker\", \"checkpoint\", \"rehome\", \"escalate\"], blocked_missing_decision = \"operator decision required\", max_attempts = { retry = 2, restart_worker = 1, checkpoint = 1, rehome = 1, escalate = 1 }, cooldown_seconds = { retry = 30, restart_worker = 30, checkpoint = 30, rehome = 60, escalate = 0 } }\n"
);

fn provider_registry_root(root: &std::path::Path) -> PathBuf {
    let registry = root.join("registry");
    for kind in RegistryKind::ALL {
        fs::create_dir_all(registry.join(kind.directory())).unwrap();
    }
    let provider = registry.join("providers/gateway");
    fs::create_dir_all(&provider).unwrap();
    fs::write(provider.join("provider.toml"), GATEWAY_PROVIDER_TOML).unwrap();
    registry
}

fn seed_provider_lane(ledger: &Ledger, lane: &LaneId) {
    ledger
        .connection()
        .execute(
            "INSERT INTO lanes (
                 lane_id, seat_id, template_id, backend, status, created_by, created_at, updated_at
             ) VALUES (?1, 'seat-a', 'template-a', 'local_omp', 'ready', 'test', ?2, ?2)",
            rusqlite::params![lane.to_string(), "2026-08-31T00:00:00Z"],
        )
        .unwrap();
}

fn provider_lease(id: &str, lane: LaneId, account: &str, started_at: i64) -> NewProviderLease {
    NewProviderLease {
        lease_id: LeaseId::new(id).unwrap(),
        lane_id: lane,
        provider_id: ProviderId::new("gateway").unwrap(),
        account_handle: account.to_owned(),
        model: "kimi-k3".to_owned(),
        role: "primary".to_owned(),
        affinity_key: "skuld".to_owned(),
        quota_snapshot: ProviderQuotaSnapshot {
            health: ProviderHealth::Available,
            remaining: Some(1),
            updated_at: OffsetDateTime::from_unix_timestamp(started_at).unwrap(),
        }
        .to_value()
        .unwrap(),
        selection_reason: format!(
            "boundary lane-start selected provider gateway account {account} model kimi-k3 by priority 0"
        ),
        started_at: OffsetDateTime::from_unix_timestamp(started_at).unwrap(),
        expires_at: None,
    }
}

#[test]
fn providers_subcommand_parses_state_lane_and_json() {
    let cli = Cli::try_parse_from([
        "odin",
        "providers",
        "--state-root",
        "/var/lib/odin/state",
        "--lane",
        "skuld-kernel",
        "--json",
    ])
    .unwrap();
    let Some(Command::Providers(arguments)) = cli.command else {
        panic!("expected providers command");
    };
    assert_eq!(arguments.state_root, PathBuf::from("/var/lib/odin/state"));
    assert_eq!(arguments.lane.as_deref(), Some("skuld-kernel"));
    assert!(arguments.json);
}

#[test]
fn providers_report_uses_one_credential_free_status_model() {
    let root = TempDir::new().unwrap();
    let state_root = TempDir::new().unwrap();
    let registry_root = provider_registry_root(root.path());
    let lane = LaneId::new("lane-a").unwrap();
    let mut ledger = Ledger::open(state_root.path().join("ledger.sqlite3")).unwrap();
    seed_provider_lane(&ledger, &lane);
    let first = ledger
        .start_provider_lease(provider_lease(
            "lease-a",
            lane.clone(),
            "gateway-primary",
            10,
        ))
        .unwrap();
    let successor = ledger
        .rotate_provider_lease_at_boundary(
            &first.lease_id,
            first.revision,
            OffsetDateTime::from_unix_timestamp(20).unwrap(),
            ProviderLeaseEnd {
                boundary: ProviderLeaseBoundary::Quota,
                reason: "quota storm".to_owned(),
            },
            provider_lease("lease-b", lane, "gateway-storm", 20),
        )
        .unwrap();
    drop(ledger);

    let mut json_output = Vec::new();
    assert_eq!(
        providers(
            ProvidersArgs {
                state_root: state_root.path().to_path_buf(),
                lane: None,
                json: true,
            },
            &registry_root,
            &mut json_output,
        )
        .unwrap(),
        RunStatus::Success
    );
    let report: serde_json::Value = serde_json::from_slice(&json_output).unwrap();
    assert_eq!(report["schema"], "odin.providers.status.v1");
    assert_eq!(report["providers"][0], "gateway");
    assert_eq!(report["lanes"][0]["lane"], "lane-a");
    assert_eq!(
        report["lanes"][0]["active"]["lease_id"],
        successor.lease_id.to_string()
    );
    assert_eq!(
        report["lanes"][0]["active"]["account_handle"],
        "gateway-storm"
    );
    assert_eq!(report["lanes"][0]["active"]["model"], "kimi-k3");
    assert_eq!(report["lanes"][0]["active"]["health"]["state"], "available");
    assert_eq!(report["lanes"][0]["lineage"].as_array().unwrap().len(), 2);
    assert_eq!(report["lanes"][0]["lineage"][0]["end"]["boundary"], "quota");

    let json_text = String::from_utf8(json_output).unwrap();
    for secret in ["LITELLM_MASTER_KEY", "base_url", "127.0.0.1", "\"auth\""] {
        assert!(!json_text.contains(secret));
    }

    let mut text_output = Vec::new();
    providers(
        ProvidersArgs {
            state_root: state_root.path().to_path_buf(),
            lane: None,
            json: false,
        },
        &registry_root,
        &mut text_output,
    )
    .unwrap();
    let text = String::from_utf8(text_output).unwrap();
    assert!(text.contains("providers gateway"));
    assert!(text.contains("lane lane-a"));
    assert!(text.contains("account gateway-storm model kimi-k3"));
    assert!(text.contains("health available eligible true enabled true"));
    assert!(text.contains("quota storm"));
    for secret in ["LITELLM_MASTER_KEY", "base_url", "127.0.0.1", "\"auth\""] {
        assert!(!text.contains(secret));
    }
}

#[test]
fn providers_reject_unknown_lane_before_opening_ledger() {
    let root = TempDir::new().unwrap();
    let state_root = TempDir::new().unwrap();
    let registry_root = provider_registry_root(root.path());
    let error = providers(
        ProvidersArgs {
            state_root: state_root.path().to_path_buf(),
            lane: Some("missing-lane".to_owned()),
            json: false,
        },
        &registry_root,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(error, "unknown lane \"missing-lane\" in the registry");
}

fn parsed_huginn_plan(arguments: &[&str]) -> Result<HuginnPlan, String> {
    let cli = Cli::try_parse_from(arguments).map_err(|error| error.to_string())?;
    match cli.command {
        Some(Command::Huginn(arguments)) => arguments.command.into_plan(),
        _ => Err("fixture did not parse as a Huginn command".to_owned()),
    }
}

#[test]
fn huginn_session_prompt_is_the_shared_protocol_request() {
    let plan = parsed_huginn_plan(&[
        "odin",
        "huginn",
        "session",
        "prompt",
        "--command-id",
        "command:prompt-1",
        "--session",
        "00000000-0000-4000-8000-000000000001",
        "--expected-epoch",
        "7",
        "--expected-event-head",
        "11",
        "continue safely",
    ])
    .unwrap();

    let HuginnPlan::Request(request) = plan else {
        panic!("prompt did not map to a request");
    };
    let encoded = serde_json::to_vec(&request).unwrap();
    let shared: live::HuginnRequest = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(shared, request);
    let live::HuginnRequest::SessionCommand(command) = shared else {
        panic!("prompt did not map to SessionCommand");
    };
    assert_eq!(command.command_id.to_string(), "command:prompt-1");
    assert_eq!(command.expected_epoch.get(), 7);
    assert_eq!(command.expected_event_head.unwrap().get(), 11);
    assert!(matches!(
        command.body,
        live::LiveCommandBody::Prompt {
            message: live::LiveMessage { .. }
        }
    ));
}

/// the lane command has a CLI caller.
#[test]
fn huginn_lane_verb_is_the_shared_lane_command() {
    let plan = parsed_huginn_plan(&[
        "odin",
        "huginn",
        "lane",
        "surtr-review",
        "--expected-revision",
        "3",
        "--command-id",
        "command:lane-1",
        "rehome",
        "--node",
        "pc",
    ])
    .unwrap();
    let HuginnPlan::Request(request) = plan else {
        panic!("lane did not map to a request");
    };
    let encoded = serde_json::to_vec(&request).unwrap();
    let shared: live::HuginnRequest = serde_json::from_slice(&encoded).unwrap();
    let live::HuginnRequest::LaneCommand(command) = shared else {
        panic!("lane did not map to LaneCommand");
    };
    assert_eq!(command.lane_id.to_string(), "surtr-review");
    assert_eq!(command.expected_revision, 3);
    assert_eq!(command.command_id.to_string(), "command:lane-1");
    assert_eq!(
        command.body,
        live::LaneCommandBody::Rehome("pc".parse().unwrap())
    );
    let HuginnPlan::Request(live::HuginnRequest::LaneCommand(pause)) = parsed_huginn_plan(&[
        "odin",
        "huginn",
        "lane",
        "surtr-review",
        "--expected-revision",
        "3",
        "pause",
    ])
    .unwrap() else {
        panic!("pause did not map to LaneCommand");
    };
    assert_eq!(pause.body, live::LaneCommandBody::Pause);
    assert!(pause.command_id.to_string().starts_with("cli:lane:"));
}

/// KubeCommand has a CLI caller.
#[test]
fn huginn_kube_command_is_the_shared_kube_command() {
    let json = serde_json::json!({
        "suspendWorkload": {
            "commandId": "command:kube-1",
            "runId": "run:live:probe",
            "expectedRevision": 2,
            "argumentsDigest": format!("blake3:{}", "0".repeat(64)),
        }
    })
    .to_string();
    let plan =
        parsed_huginn_plan(&["odin", "huginn", "kube-command", "--request-json", &json]).unwrap();
    let HuginnPlan::Request(live::HuginnRequest::KubeCommand(command)) = plan else {
        panic!("kube-command did not map to KubeCommand");
    };
    assert!(matches!(
        command,
        live::KubeCommand::SuspendWorkload {
            expected_revision: 2,
            ..
        }
    ));
}

#[test]
fn huginn_watch_builds_one_bounded_shared_subscription() {
    let plan = parsed_huginn_plan(&[
        "odin",
        "huginn",
        "watch",
        "--kind",
        "agent-events",
        "--stream",
        "00000000-0000-4000-8000-000000000002",
        "--after",
        "19",
        "--credit-items",
        "3",
        "--credit-bytes",
        "4096",
    ])
    .unwrap();
    let HuginnPlan::Stream(set) = plan else {
        panic!("watch did not map to a subscription");
    };
    assert!(set.is_valid());
    assert_eq!(set.subscriptions.len(), 1);
    assert_eq!(set.subscriptions[0].credit.items.get(), 3);
    assert_eq!(set.subscriptions[0].credit.bytes.get(), 4096);
    assert!(matches!(
        set.subscriptions[0].cursor,
        live::StreamCursor::Durable {
            after: Some(sequence),
            ..
        } if sequence.get() == 19
    ));
}

#[test]
fn huginn_file_commands_use_complete_shared_client_paths() {
    let upload = parsed_huginn_plan(&[
        "odin",
        "huginn",
        "files",
        "upload",
        "/tmp/input.bin",
        "--session",
        "00000000-0000-4000-8000-000000000003",
        "--media-type",
        "application/octet-stream",
    ])
    .unwrap();
    assert!(matches!(upload, HuginnPlan::Upload { .. }));

    let cancel = parsed_huginn_plan(&[
        "odin",
        "huginn",
        "files",
        "cancel-upload",
        "/tmp/input.bin",
        "--session",
        "00000000-0000-4000-8000-000000000003",
        "--media-type",
        "application/octet-stream",
    ])
    .unwrap();
    assert!(matches!(cancel, HuginnPlan::CancelUpload { .. }));

    let fetch = parsed_huginn_plan(&[
        "odin",
        "huginn",
        "files",
        "fetch",
        "artifact:fixture",
        "--output",
        "/tmp/out.bin",
    ])
    .unwrap();
    assert!(matches!(
        fetch,
        HuginnPlan::Download {
            source: live::ContentSource::Artifact(_),
            ..
        }
    ));

    let read = parsed_huginn_plan(&[
        "odin",
        "huginn",
        "files",
        "read",
        "--root",
        "fixture",
        "nested/input.bin",
    ])
    .unwrap();
    assert!(matches!(read, HuginnPlan::FileRead(_)));

    let download = parsed_huginn_plan(&[
        "odin",
        "huginn",
        "files",
        "download",
        "--root",
        "fixture",
        "nested/input.bin",
        "--output",
        "/tmp/output.bin",
    ])
    .unwrap();
    assert!(matches!(download, HuginnPlan::Download { .. }));
}

#[test]
fn huginn_specialized_watches_reject_mismatched_stream_kinds() {
    let error = parsed_huginn_plan(&[
        "odin",
        "huginn",
        "browser",
        "watch",
        "--kind",
        "logs",
        "--stream",
        "00000000-0000-4000-8000-000000000004",
    ])
    .unwrap_err();
    assert_eq!(error, "browser watch requires --kind browser-frames");
}

#[test]
fn huginn_command_tree_is_discoverable_at_every_required_group() {
    for arguments in [
        vec!["odin", "huginn", "status"],
        vec!["odin", "huginn", "snapshot"],
        vec!["odin", "huginn", "search", "needle"],
        vec!["odin", "huginn", "seats"],
        vec!["odin", "huginn", "agents"],
        vec!["odin", "huginn", "lanes"],
        vec!["odin", "huginn", "sessions"],
        vec!["odin", "huginn", "nodes"],
        vec!["odin", "huginn", "kube"],
        vec!["odin", "huginn", "containers"],
        vec!["odin", "huginn", "approvals", "list"],
        vec!["odin", "huginn", "files", "roots"],
        vec!["odin", "huginn", "render", "status", "render-1"],
        vec!["odin", "huginn", "browser", "list"],
        vec!["odin", "huginn", "simulation", "list"],
        vec!["odin", "huginn", "terminal", "list"],
        vec!["odin", "huginn", "devices", "list"],
    ] {
        assert!(
            Cli::try_parse_from(arguments.clone()).is_ok(),
            "required command failed to parse: {arguments:?}"
        );
    }
}

#[test]
fn huginn_local_pairing_and_unsupported_operations_are_explicit() {
    let pair = parsed_huginn_plan(&[
        "odin",
        "huginn",
        "devices",
        "pair",
        "--label",
        "laptop-console",
        "--node",
        "00000000-0000-4000-8000-000000000009",
        "--force",
    ])
    .unwrap();
    assert!(matches!(
        pair,
        HuginnPlan::PairDevice {
            label,
            node,
            force: true,
            out: None,
        } if label == "laptop-console"
            && node == "00000000-0000-4000-8000-000000000009"
    ));

    let enroll = parsed_huginn_plan(&[
        "odin",
        "huginn",
        "devices",
        "pair",
        "--label",
        "phone",
        "--node",
        "00000000-0000-4000-8000-000000000009",
        "--out",
        "phones/phone.credential",
    ])
    .unwrap();
    assert!(matches!(
        enroll,
        HuginnPlan::PairDevice {
            label,
            node,
            force: false,
            out: Some(_),
        } if label == "phone"
            && node == "00000000-0000-4000-8000-000000000009"
    ));

    let conflict = Cli::try_parse_from([
        "odin",
        "huginn",
        "devices",
        "pair",
        "--label",
        "phone",
        "--node",
        "00000000-0000-4000-8000-000000000009",
        "--out",
        "phones/phone.credential",
        "--force",
    ])
    .unwrap();
    // The typed rejection is the contract, not the prose: with an ambient
    // ODIN_HUGINN_ENDPOINT the loopback-local guard reports before the
    // --out/--force check.
    let _ = run(conflict, &mut Vec::new()).expect_err("--out and --force cannot combine");

    let remote = Cli::try_parse_from([
        "odin",
        "huginn",
        "--endpoint",
        "https://controller.example.invalid",
        "devices",
        "pair",
        "--label",
        "laptop-console",
        "--node",
        "00000000-0000-4000-8000-000000000009",
    ])
    .unwrap();
    let error = run(remote, &mut Vec::new()).expect_err("remote pairing is rejected");
    assert!(
        error.contains("remote pairing is unsupported"),
        "unexpected error: {error}"
    );

    let revoke = parsed_huginn_plan(&[
        "odin",
        "huginn",
        "devices",
        "revoke",
        "00000000-0000-4000-8000-0000000000a1",
    ])
    .unwrap();
    assert!(matches!(revoke, HuginnPlan::RevokeDevice(_)));

    let open = parsed_huginn_plan(&[
        "odin",
        "huginn",
        "render",
        "open",
        "--command-id",
        "open-render-1",
        "00000000-0000-4000-8000-000000000005",
    ])
    .unwrap();
    assert!(matches!(
        open,
        HuginnPlan::Request(live::HuginnRequest::IssueContentTicket(_))
    ));

    let stat = parsed_huginn_plan(&[
        "odin",
        "huginn",
        "files",
        "stat",
        "--root",
        "fixture",
        "input.bin",
    ])
    .unwrap();
    assert!(
        matches!(&stat, HuginnPlan::FileStat { root, path } if root.as_str() == "fixture" && path.as_str() == "input.bin"),
        "{stat:?}"
    );
}
