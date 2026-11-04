use std::fs;
use std::path::PathBuf;

use crate::{run, Cli, Command, RunStatus};
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
use crate::test_support::{commit_all, git};

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
            evidence: Some("artifact:denial".to_owned()),
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

const GATEWAY_PROVIDER_TOML: &str = concat!(
    "schema = \"odin.registry.v1\"\n",
    "kind = \"provider\"\n",
    "enabled = true\n",
    "description = \"The deployed LiteLLM loopback gateway with hard budgets; lanes resolve through it.\"\n",
    "adapter = \"litellm-gateway\"\n",
    "policy = { routes = [] }\n",
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
        affinity_key: "project-a".to_owned(),
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
