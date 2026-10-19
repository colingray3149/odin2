//! First-prompt acceptance shared by the CLI and ACP frontend.
//!
//! The prompt must be persisted as the session's plan objective and accepted
//! by a paired, unrevoked device before a command can be constructed.
//! Reports contain identifiers and digests, not private prompt text;
//! authorization is checked against the ledger, not the report.

use std::path::Path;

use crate::authority_provision::{self, SessionComposition, MAX_PROMPT_FILE_BYTES};
use odin_domain::huginn as live;
use odin_domain::{CommandId, RunId};
use odin_huginn::OdindConfig;
use odin_ledger::lane_run;
use odin_ledger::Ledger;
use rusqlite::OptionalExtension;
use serde::Serialize;
use time::OffsetDateTime;

/// Accepts the prompt for the declared lane's existing bridge run before
/// constructing a command for `epoch` and a metadata-only report.
pub fn prepare(
    config: &OdindConfig,
    composition: &SessionComposition,
    device: live::DeviceId,
    prompt: &str,
    epoch: live::SessionEpoch,
) -> Result<PreparedOperatorPrompt, String> {
    let identity = operator_identity(&config.paths.state_root, device)?;
    let mut ledger = open_ledger(config)?;
    let proof = accept_prompt_plan(
        &mut ledger,
        composition,
        prompt,
        &identity,
        OffsetDateTime::now_utc(),
    )?;
    Ok(PreparedOperatorPrompt {
        command: prompt_command(composition.live_session, epoch, &proof),
        receipt: proof.receipt(),
    })
}

/// Checks acceptance without replacing the objective or todos.
/// Requires an existing bridge run in the declared lane, even without a plan.
pub fn has_accepted_plan(
    config: &OdindConfig,
    composition: &SessionComposition,
) -> Result<bool, String> {
    let ledger = open_ledger(config)?;
    let run_id = session_run_id(&composition.live_session)?;
    require_session_run(&ledger, &run_id, composition)?;
    ledger
        .plan_is_accepted(&run_id)
        .map_err(|error| format!("could not verify plan acceptance of {run_id}: {error}"))
}

/// Accepts an attached session's first prompt using its existing bridge run.
/// Attach has no locally derived composition to cross-check against the lane.
pub fn prepare_existing(
    config: &OdindConfig,
    session: &live::LiveSessionId,
    device: live::DeviceId,
    prompt: &str,
    epoch: live::SessionEpoch,
) -> Result<PreparedOperatorPrompt, String> {
    let identity = operator_identity(&config.paths.state_root, device)?;
    let mut ledger = open_ledger(config)?;
    let proof = accept_attached_prompt_plan(
        &mut ledger,
        session,
        prompt,
        &identity,
        OffsetDateTime::now_utc(),
    )?;
    Ok(PreparedOperatorPrompt {
        command: prompt_command(*session, epoch, &proof),
        receipt: proof.receipt(),
    })
}

/// Private fields prevent construction without passing the acceptance checks.
pub struct PreparedOperatorPrompt {
    command: live::LiveCommand,
    receipt: OperatorPlanReceipt,
}

impl PreparedOperatorPrompt {
    pub fn into_parts(self) -> (live::LiveCommand, OperatorPlanReceipt) {
        (self.command, self.receipt)
    }
}

/// Report metadata excludes private objective text and does not authorize prompts.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperatorPlanReceipt {
    pub run: String,
    pub revision: i64,
    pub fingerprint: String,
    pub actor: String,
    pub label: String,
    pub prompt_command_id: String,
}

/// A paired, unrevoked device from the controller's device trust store.
pub struct OperatorIdentity {
    pub device_id: live::DeviceId,
    pub label: String,
}

impl OperatorIdentity {
    /// The actor string recorded with the durable acceptance.
    pub fn actor(&self) -> String {
        format!("device:{}", self.device_id)
    }
}

/// Requires a paired, unrevoked device in the controller's trust store.
/// No credentials or secrets are read into the result.
pub fn operator_identity(
    state_root: &Path,
    device: live::DeviceId,
) -> Result<OperatorIdentity, String> {
    let store_path = state_root.join("huginn").join("devices.sqlite3");
    let connection = rusqlite::Connection::open_with_flags(
        &store_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| {
        format!(
            "could not open the device trust store {}: {error}",
            store_path.display()
        )
    })?;
    let row: Option<(String, Option<i64>)> = connection
        .query_row(
            "SELECT label, revoked_at FROM trusted_devices WHERE device_id = ?1",
            [device.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| {
            format!(
                "could not read the device trust store {}: {error}",
                store_path.display()
            )
        })?;
    let Some((label, revoked_at)) = row else {
        return Err(format!(
            "device {device} is not a paired operator device in {}; pair this workstation first with `odin huginn devices pair`",
            store_path.display()
        ));
    };
    if revoked_at.is_some() {
        return Err(format!(
            "device {device} is revoked; acceptance requires an active paired operator device"
        ));
    }
    Ok(OperatorIdentity {
        device_id: device,
        label,
    })
}

fn open_ledger(config: &OdindConfig) -> Result<Ledger, String> {
    Ledger::open(config.paths.state_root.join("ledger.sqlite3"))
        .map_err(|error| format!("could not open the session state ledger: {error}"))
}

fn generated_command_id() -> Result<CommandId, String> {
    authority_provision::random_command_uuid()
}

/// Uses the bridge runtime's derivation so the operator and model read the same plan.
pub fn session_run_id(session: &live::LiveSessionId) -> Result<RunId, String> {
    RunId::new(format!("run:live:{session}"))
        .map_err(|error| format!("the live session cannot be mapped to a run identity: {error}"))
}

/// Requires the bridge run created by the supervisor before returning an open summary.
fn require_session_run(
    ledger: &Ledger,
    run_id: &RunId,
    composition: &SessionComposition,
) -> Result<lane_run::RunRecord, String> {
    let record = lane_run::read_run(ledger.connection(), run_id)
        .map_err(|error| format!("could not read the session run {run_id}: {error}"))?
        .ok_or_else(|| {
            format!(
                "session {session} has no durable bridge run {run_id}; the controller did not complete the session launch, so no plan can be persisted",
                session = composition.live_session
            )
        })?;
    if record.lane_id != composition.lane {
        return Err(format!(
            "bridge run {run_id} is bound to lane {}, not the declared lane {}",
            record.lane_id, composition.lane
        ));
    }
    Ok(record)
}

/// Validates the prompt before ledger writes without trimming or rewriting it.
fn require_prompt(prompt: &str) -> Result<(), String> {
    if prompt.trim().is_empty() {
        return Err("the operator prompt is empty".to_owned());
    }
    if u64::try_from(prompt.len()).unwrap_or(u64::MAX) > MAX_PROMPT_FILE_BYTES {
        return Err(format!(
            "the operator prompt holds {} bytes, above the {} byte bound",
            prompt.len(),
            MAX_PROMPT_FILE_BYTES
        ));
    }
    Ok(())
}

/// Only constructed after the prompt's persisted plan passes acceptance checks.
struct AcceptedPrompt {
    run_id: RunId,
    plan_revision: i64,
    fingerprint: String,
    actor: String,
    label: String,
    prompt_command_id: CommandId,
    message: live::LiveMessage,
}

impl AcceptedPrompt {
    fn receipt(&self) -> OperatorPlanReceipt {
        OperatorPlanReceipt {
            run: self.run_id.to_string(),
            revision: self.plan_revision,
            fingerprint: self.fingerprint.clone(),
            actor: self.actor.clone(),
            label: self.label.clone(),
            prompt_command_id: self.prompt_command_id.to_string(),
        }
    }
}

fn accept_prompt_plan(
    ledger: &mut Ledger,
    composition: &SessionComposition,
    prompt: &str,
    identity: &OperatorIdentity,
    now: OffsetDateTime,
) -> Result<AcceptedPrompt, String> {
    let run_id = session_run_id(&composition.live_session)?;
    require_session_run(ledger, &run_id, composition)?;
    persist_accepted_plan(ledger, &run_id, prompt, identity, now)
}

/// Both opened and attached sessions persist, accept, and recheck the plan here.
fn persist_accepted_plan(
    ledger: &mut Ledger,
    run_id: &RunId,
    prompt: &str,
    identity: &OperatorIdentity,
    now: OffsetDateTime,
) -> Result<AcceptedPrompt, String> {
    require_prompt(prompt)?;
    let observed_revision = ledger
        .plan(run_id)
        .map_err(|error| format!("could not read the current session plan: {error}"))?
        .map(|plan| plan.revision)
        .unwrap_or(0);
    let plan = ledger
        .replace_plan(run_id, prompt, &[], observed_revision, now)
        .map_err(|error| {
            format!("could not persist the operator prompt as the plan of run {run_id}: {error}")
        })?;
    ledger
        .accept_plan(run_id, plan.revision, &identity.actor(), now)
        .map_err(|error| {
            format!(
                "could not record operator acceptance of plan {run_id} revision {}: {error}",
                plan.revision
            )
        })?;
    let gate = ledger
        .plan_is_accepted(run_id)
        .map_err(|error| format!("could not verify plan acceptance of {run_id}: {error}"))?;
    if !gate {
        return Err(format!(
            "plan {run_id} revision {} was recorded but does not verify as accepted; refusing to prompt",
            plan.revision
        ));
    }
    let record = ledger
        .plan_acceptance(run_id)
        .map_err(|error| format!("could not re-read the acceptance record of {run_id}: {error}"))?
        .ok_or_else(|| {
            format!("the acceptance record of {run_id} disappeared after verification")
        })?;
    Ok(AcceptedPrompt {
        run_id: run_id.clone(),
        plan_revision: plan.revision,
        fingerprint: record.fingerprint,
        actor: record.actor,
        label: identity.label.clone(),
        prompt_command_id: generated_command_id()?,
        message: live::LiveMessage::new(vec![live::LiveContentBlock::Text(prompt.to_owned())])
            .map_err(|error| format!("the operator prompt is not a valid message: {error}"))?,
    })
}

/// Attach uses the existing bridge run because it has no local composition to check.
fn accept_attached_prompt_plan(
    ledger: &mut Ledger,
    session: &live::LiveSessionId,
    prompt: &str,
    identity: &OperatorIdentity,
    now: OffsetDateTime,
) -> Result<AcceptedPrompt, String> {
    let run_id = session_run_id(session)?;
    lane_run::read_run(ledger.connection(), &run_id)
        .map_err(|error| format!("could not read the session run {run_id}: {error}"))?
        .ok_or_else(|| {
            format!(
                "session {session} has no durable bridge run {run_id}; the controller did not \
                 complete the session launch, so no plan can be persisted"
            )
        })?;
    persist_accepted_plan(ledger, &run_id, prompt, identity, now)
}

fn prompt_command(
    session_id: live::LiveSessionId,
    epoch: live::SessionEpoch,
    proof: &AcceptedPrompt,
) -> live::LiveCommand {
    live::LiveCommand {
        command_id: proof.prompt_command_id.clone(),
        session_id,
        expected_epoch: epoch,
        expected_event_head: None,
        body: live::LiveCommandBody::Prompt {
            message: proof.message.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::*;

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

    fn identity() -> OperatorIdentity {
        OperatorIdentity {
            device_id: live::DeviceId::parse("00000000-0000-4000-8000-000000000002").unwrap(),
            label: "test laptop".to_owned(),
        }
    }

    fn seeded_ledger() -> Ledger {
        let ledger = Ledger::open_in_memory().unwrap();
        ledger
            .connection()
            .execute_batch(
                "INSERT INTO lanes(
                     lane_id, seat_id, template_id, backend, status, created_by,
                     created_at, updated_at
                 ) VALUES (
                     'architect-odin', 'architect', 'template:test', 'local_omp',
                     'desired', 'test', '1970-01-01T00:00:00Z', '1970-01-01T00:00:00Z'
                 );",
            )
            .unwrap();
        ledger
    }

    // Mirrors the bridge run the supervisor creates before returning a session.
    fn seed_bridge_run(
        ledger: &mut Ledger,
        live_session: &live::LiveSessionId,
        lane: &odin_domain::LaneId,
    ) {
        let run_id = session_run_id(live_session).unwrap();
        // The plan/run foreign keys are enforced: the lane row exists
        // before the run row, in memory or in a fresh file ledger.
        ledger
            .connection()
            .execute_batch(
                "INSERT OR IGNORE INTO lanes(
                     lane_id, seat_id, template_id, backend, status, created_by,
                     created_at, updated_at
                 ) VALUES (
                     'architect-odin', 'architect', 'template:test', 'local_omp',
                     'desired', 'test', '1970-01-01T00:00:00Z', '1970-01-01T00:00:00Z'
                 );",
            )
            .unwrap();
        odin_ledger::lane_run::create_run(
            ledger.connection(),
            &odin_ledger::lane_run::NewRun {
                run_id: run_id.clone(),
                lane_id: lane.clone(),
                attempt_number: 1,
                workflow_id: Some(format!("live:{lane}")),
                workflow_version: Some(1),
                input_hash: odin_domain::Digest::hash(b"manifest").to_string(),
                accepted_capability_revision: None,
                lease_id: None,
                absolute_deadline: None,
                retry_budget: 0,
                created_at: AT,
            },
        )
        .unwrap();
    }

    const AT: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;

    fn state_config(state_root: &Path) -> OdindConfig {
        let mut text = String::from(
            "schema = 'odin.odind-config.v1'\nrevision = 1\nworker_bus = 'unix:/tmp/bus.sock'\n[identity]\nnode = 'laptop'\n[paths]\nregistry_root = '/'\nstate_root = '",
        );
        text.push_str(state_root.to_str().expect("utf-8 state root"));
        text.push_str(
            "'\nregistry_snapshot = '/'\nauthority_verification_key_file = '/'\nauthority_token_root = '",
        );
        text.push_str(
            state_root
                .join("authority/tokens")
                .to_str()
                .expect("utf-8 token root"),
        );
        text.push_str(
            "'\n[listener]\naddress = '127.0.0.1:18420'\n[executables]\nomp_bin = '/omp'\nomp_revision = '",
        );
        text.push_str(&"a".repeat(40));
        text.push_str(
            "'\nextension = '/ext.ts'\nzellij_bin = '/zellij'\nzellij_session = 'odin'\n[catalogs.gateway_projection]\npath = '/p.json'\ndigest = 'blake3:",
        );
        text.push_str(&"c".repeat(64));
        text.push_str(
            "'\n[publish]\nrender_session = 'live'\nfile_lane = 'f'\nrender_lane = 'r'\n[capacity]\n",
        );
        OdindConfig::parse(&text).expect("minimal config parses")
    }

    fn seed_paired_device(state_root: &Path, device: live::DeviceId, label: &str) {
        let store_path = state_root.join("huginn").join("devices.sqlite3");
        fs::create_dir_all(store_path.parent().unwrap()).unwrap();
        let connection = rusqlite::Connection::open(&store_path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE trusted_devices (
                    device_id TEXT PRIMARY KEY NOT NULL,
                    tailnet_node_id TEXT NOT NULL,
                    label TEXT NOT NULL,
                    credential_digest BLOB NOT NULL CHECK(length(credential_digest) = 32),
                    created_at INTEGER NOT NULL,
                    last_seen_at INTEGER,
                    revoked_at INTEGER
                ) STRICT;",
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO trusted_devices(
                     device_id, tailnet_node_id, label, credential_digest,
                     created_at, last_seen_at, revoked_at
                 ) VALUES (?1, 'tailnet:node', ?2, zeroblob(32), 0, NULL, NULL)",
                rusqlite::params![device.to_string(), label],
            )
            .unwrap();
    }

    /// A well-formed enrolled credential without touching any secret store.
    fn test_credential() -> odin_huginn::client::DeviceCredential {
        let mut bytes = vec![0_u8; 48];
        bytes[6] = 0x40; // UUID version 4 nibble
        bytes[8] = 0x80; // RFC 4122 variant
        bytes[15] = 0x02; // distinguishable device
        odin_huginn::client::DeviceCredential::new(bytes).unwrap()
    }

    #[test]
    fn session_runs_are_derived_exactly_like_the_bridge() {
        let composition = composition();
        let run_id = session_run_id(&composition.live_session).unwrap();
        assert_eq!(
            run_id.as_str(),
            "run:live:00000000-0000-4000-8000-000000000001"
        );
        let other = live::LiveSessionId::parse("00000000-0000-4000-8000-000000000002").unwrap();
        assert_ne!(run_id, session_run_id(&other).unwrap());
    }

    #[test]
    fn gated_handoff_requires_the_server_created_bridge_run() {
        let composition = composition();
        let mut ledger = seeded_ledger();
        let identity = identity();

        // A missing bridge run must not be created by the prompt handoff.
        let error = accept_prompt_plan(&mut ledger, &composition, "first prompt", &identity, AT)
            .err()
            .expect("a missing bridge run must reject the prompt");
        assert!(
            error.contains("no durable bridge run"),
            "unexpected error: {error}"
        );
        assert!(ledger
            .plan(&session_run_id(&composition.live_session).unwrap())
            .unwrap()
            .is_none());

        seed_bridge_run(&mut ledger, &composition.live_session, &composition.lane);
        let proof =
            accept_prompt_plan(&mut ledger, &composition, "first prompt", &identity, AT).unwrap();
        let run = odin_ledger::lane_run::read_run(ledger.connection(), &proof.run_id)
            .unwrap()
            .unwrap();
        assert_eq!(run.lane_id, composition.lane);
        assert!(ledger.plan_is_accepted(&proof.run_id).unwrap());
    }

    #[test]
    fn gated_handoff_persists_accepts_and_survives_structure_changes() {
        let composition = composition();
        let mut ledger = seeded_ledger();
        seed_bridge_run(&mut ledger, &composition.live_session, &composition.lane);
        let identity = identity();

        let proof =
            accept_prompt_plan(&mut ledger, &composition, "first prompt", &identity, AT).unwrap();
        let expected_run = session_run_id(&composition.live_session).unwrap();
        assert_eq!(proof.run_id, expected_run);
        assert_eq!(proof.actor, format!("device:{}", identity.device_id));
        assert_eq!(proof.label, "test laptop");
        assert!(ledger.plan_is_accepted(&proof.run_id).unwrap());
        let plan = ledger.plan(&proof.run_id).unwrap().unwrap();
        assert_eq!(plan.objective, "first prompt");
        assert_eq!(plan.revision, 1);
        assert_eq!(proof.plan_revision, plan.revision);
        let record = ledger.plan_acceptance(&proof.run_id).unwrap().unwrap();
        assert_eq!(record.fingerprint, proof.fingerprint);
        assert!(record.parent.is_none());

        // Structural plan changes invalidate acceptance.
        let changed = ledger
            .replace_plan(&proof.run_id, "second prompt", &[], plan.revision, AT)
            .unwrap();
        assert!(!ledger.plan_is_accepted(&proof.run_id).unwrap());

        let proof2 =
            accept_prompt_plan(&mut ledger, &composition, "second prompt", &identity, AT).unwrap();
        // The handoff replaces revision 2 with revision 3 before accepting it.
        assert_eq!(changed.revision, 2);
        assert_eq!(proof2.plan_revision, changed.revision + 1);
        assert!(ledger.plan_is_accepted(&proof2.run_id).unwrap());
        assert_ne!(proof.prompt_command_id, proof2.prompt_command_id);

        // Rewriting the identical approved structure keeps the gate open.
        let rewritten = ledger
            .replace_plan(
                &proof.run_id,
                "second prompt",
                &[],
                proof2.plan_revision,
                AT,
            )
            .unwrap();
        assert!(rewritten.revision > proof2.plan_revision);
        assert!(ledger.plan_is_accepted(&proof.run_id).unwrap());
    }

    #[test]
    fn attachment_reproves_acceptance_without_replacing_the_plan() {
        let temporary = tempfile::TempDir::new().unwrap();
        let config = state_config(temporary.path());
        let mut composition = composition();
        assert!(has_accepted_plan(&config, &composition).is_err());
        let mut ledger = open_ledger(&config).unwrap();
        seed_bridge_run(&mut ledger, &composition.live_session, &composition.lane);
        assert!(!has_accepted_plan(&config, &composition).unwrap());
        let proof = accept_prompt_plan(
            &mut ledger,
            &composition,
            "retain the original objective",
            &identity(),
            AT,
        )
        .unwrap();
        let before = ledger.plan(&proof.run_id).unwrap();
        let acceptance = ledger.plan_acceptance(&proof.run_id).unwrap();
        assert!(has_accepted_plan(&config, &composition).unwrap());
        assert_eq!(ledger.plan(&proof.run_id).unwrap(), before);
        assert_eq!(ledger.plan_acceptance(&proof.run_id).unwrap(), acceptance);
        composition.lane = odin_domain::LaneId::new("another-project-lane").unwrap();
        assert!(has_accepted_plan(&config, &composition).is_err());
        assert_eq!(ledger.plan(&proof.run_id).unwrap(), before);
    }

    #[test]
    fn operator_identity_requires_an_active_paired_device() {
        let temporary = tempfile::TempDir::new().unwrap();
        let state_root = temporary.path().to_path_buf();
        let store_path = state_root.join("huginn").join("devices.sqlite3");
        fs::create_dir_all(store_path.parent().unwrap()).unwrap();
        let credential = test_credential();
        let device = credential.device_id().unwrap();

        // No store: fail closed.
        let error = operator_identity(&state_root, device)
            .err()
            .expect("a missing device store must reject the operator");
        assert!(error.contains("device trust store"), "unexpected: {error}");

        let connection = rusqlite::Connection::open(&store_path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE trusted_devices (
                    device_id TEXT PRIMARY KEY NOT NULL,
                    tailnet_node_id TEXT NOT NULL,
                    label TEXT NOT NULL,
                    credential_digest BLOB NOT NULL CHECK(length(credential_digest) = 32),
                    created_at INTEGER NOT NULL,
                    last_seen_at INTEGER,
                    revoked_at INTEGER
                ) STRICT;",
            )
            .unwrap();

        // Unknown device: fail closed.
        let error = operator_identity(&state_root, device)
            .err()
            .expect("an unknown device must reject the operator");
        assert!(
            error.contains("not a paired operator device"),
            "unexpected: {error}"
        );

        // Active paired device: the real identity with its label.
        connection
            .execute(
                "INSERT INTO trusted_devices(
                     device_id, tailnet_node_id, label, credential_digest,
                     created_at, last_seen_at, revoked_at
                 ) VALUES (?1, 'tailnet:node', 'operator laptop', zeroblob(32), 0, NULL, NULL)",
                rusqlite::params![device.to_string()],
            )
            .unwrap();
        let found = operator_identity(&state_root, device).unwrap();
        assert_eq!(found.label, "operator laptop");
        assert_eq!(found.actor(), format!("device:{device}"));

        // Revoked device: fail closed.
        connection
            .execute(
                "UPDATE trusted_devices SET revoked_at = 1 WHERE device_id = ?1",
                rusqlite::params![device.to_string()],
            )
            .unwrap();
        let error = operator_identity(&state_root, device)
            .err()
            .expect("a revoked device must reject the operator");
        assert!(error.contains("revoked"), "unexpected: {error}");
    }

    #[test]
    fn prepare_refuses_a_missing_bridge_run_and_then_binds_the_real_one() {
        let temporary = tempfile::TempDir::new().unwrap();
        let state_root = temporary.path().to_path_buf();
        let config = state_config(&state_root);
        let composition = composition();
        let device = identity().device_id;
        seed_paired_device(&state_root, device, "operator laptop");

        assert!(prepare(
            &config,
            &composition,
            device,
            "first prompt",
            live::SessionEpoch::new(7),
        )
        .is_err());

        let mut ledger = Ledger::open(state_root.join("ledger.sqlite3")).unwrap();
        let run_id = session_run_id(&composition.live_session).unwrap();
        assert!(lane_run::read_run(ledger.connection(), &run_id)
            .unwrap()
            .is_none());
        assert!(ledger.plan(&run_id).unwrap().is_none());
        seed_bridge_run(&mut ledger, &composition.live_session, &composition.lane);
        drop(ledger);
        let (command, receipt) = prepare(
            &config,
            &composition,
            device,
            "first prompt",
            live::SessionEpoch::new(7),
        )
        .unwrap()
        .into_parts();
        assert_eq!(command.session_id, composition.live_session);
        assert_eq!(command.expected_epoch.get(), 7);
        let live::LiveCommandBody::Prompt { message } = command.body else {
            panic!("the prepared first prompt is a Prompt command");
        };
        assert_eq!(
            message.content.first(),
            Some(&live::LiveContentBlock::Text("first prompt".to_owned()))
        );

        // Reports identify accepted state without exposing the prompt.
        let run_id = session_run_id(&composition.live_session).unwrap();
        assert_eq!(receipt.run, run_id.to_string());
        assert_eq!(receipt.revision, 1);
        assert_eq!(receipt.actor, format!("device:{device}"));
        let ledger = Ledger::open(state_root.join("ledger.sqlite3")).unwrap();
        assert!(ledger.plan_is_accepted(&run_id).unwrap());
        let record = ledger.plan_acceptance(&run_id).unwrap().unwrap();
        assert_eq!(receipt.fingerprint, record.fingerprint);
        assert!(!serde_json::to_string(&receipt)
            .unwrap()
            .contains("first prompt"));
    }

    #[test]
    fn prepare_existing_gates_the_attached_prompt_on_the_recorded_run() {
        let temporary = tempfile::TempDir::new().unwrap();
        let state_root = temporary.path().to_path_buf();
        let config = state_config(&state_root);
        let device = identity().device_id;
        seed_paired_device(&state_root, device, "operator laptop");
        let session = live::LiveSessionId::parse("00000000-0000-4000-8000-000000000001").unwrap();
        let lane = odin_domain::LaneId::new("architect-odin").unwrap();

        // Attach requires an existing run without a local composition to check.
        let error = prepare_existing(
            &config,
            &session,
            device,
            "attached prompt",
            live::SessionEpoch::new(2),
        )
        .err()
        .expect("a missing recorded run must reject the attached prompt");
        assert!(
            error.contains("no durable bridge run"),
            "unexpected error: {error}"
        );

        let mut ledger = Ledger::open(state_root.join("ledger.sqlite3")).unwrap();
        seed_bridge_run(&mut ledger, &session, &lane);
        drop(ledger);
        let run_id = session_run_id(&session).unwrap();
        let (command, receipt) = prepare_existing(
            &config,
            &session,
            device,
            "attached prompt",
            live::SessionEpoch::new(2),
        )
        .unwrap()
        .into_parts();
        assert_eq!(command.session_id, session);
        assert_eq!(command.expected_epoch.get(), 2);
        assert_eq!(receipt.run, run_id.to_string());
        assert_eq!(receipt.revision, 1);
        assert_eq!(receipt.actor, format!("device:{device}"));
        let ledger = Ledger::open(state_root.join("ledger.sqlite3")).unwrap();
        assert!(ledger.plan_is_accepted(&run_id).unwrap());
        let plan = ledger.plan(&run_id).unwrap().unwrap();
        assert_eq!(plan.objective, "attached prompt");
    }

    // Rejected prompts must leave no plan behind.
    #[test]
    fn prepare_enforces_the_bounded_nonempty_prompt() {
        let temporary = tempfile::TempDir::new().unwrap();
        let state_root = temporary.path().to_path_buf();
        let config = state_config(&state_root);
        let composition = composition();
        let device = identity().device_id;
        seed_paired_device(&state_root, device, "operator laptop");
        let mut ledger = Ledger::open(state_root.join("ledger.sqlite3")).unwrap();
        seed_bridge_run(&mut ledger, &composition.live_session, &composition.lane);
        drop(ledger);

        let error = prepare(
            &config,
            &composition,
            device,
            "   \n",
            live::SessionEpoch::new(1),
        )
        .err()
        .expect("an empty prompt must be refused");
        assert!(error.contains("empty"), "unexpected error: {error}");
        let oversized = "x".repeat(usize::try_from(MAX_PROMPT_FILE_BYTES).unwrap() + 1);
        let error = prepare(
            &config,
            &composition,
            device,
            &oversized,
            live::SessionEpoch::new(1),
        )
        .err()
        .expect("an oversized prompt must be refused");
        assert!(error.contains("bound"), "unexpected error: {error}");

        let run_id = session_run_id(&composition.live_session).unwrap();
        let ledger = Ledger::open(state_root.join("ledger.sqlite3")).unwrap();
        assert!(
            ledger.plan(&run_id).unwrap().is_none(),
            "a refused prompt never persists a plan"
        );
    }
}
