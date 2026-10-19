//! Case 16 machinery: the four durable command crash windows, the
//! once-only checkpoint artifact effect, and the singular session lease,
//! exercised against the production bridge and the probe ledger.

use std::io::Write;

use async_trait::async_trait;
use odin_domain::{CheckpointId, CommandId, Digest, EventId};
use odin_ledger::artifact::{ArtifactRegistration, RetentionClass};
use odin_ledger::checkpoint::CheckpointSpec;
use odin_ledger::live::{
    AppendLiveCommand, CompleteLiveCommand, LiveCommand, NewLiveCommand, NewLiveEvent,
};
use odin_ledger::{Ledger, LedgerError};
use serde_json::{json, Value};
use time::OffsetDateTime;

use crate::bridge::{
    BridgeError, BridgeStatus, LiveSessionDescriptor, OmpBridge, CHECKPOINT_COMPATIBILITY_KEY,
    LEASE_OBJECT_KIND,
};
use crate::probe::{
    CaseContext, CaseEvidence, CaseFailure, CaseOutcome, CleanupOutcome, CleanupReceipt,
    ConformanceCase, ConformanceCaseId, FIXTURE_MODEL_A, FIXTURE_PROVIDER,
};

use super::*;

const EFFECT_BYTES: &[u8] =
    br#"{"case":16,"effect":"checkpoint-artifact","invocations":1,"schema":"odin.probe.effect.v1"}"#;

pub(super) struct ProcessKillRecovery;

#[async_trait]
impl ConformanceCase for ProcessKillRecovery {
    fn id(&self) -> ConformanceCaseId {
        PROCESS_KILL_RECOVERY
    }

    fn name(&self) -> &'static str {
        "process_kill_recovery"
    }

    fn deadline(&self) -> Duration {
        CASE_DEADLINE
    }

    async fn run(&self, context: &CaseContext) -> CaseOutcome {
        run_process_kill_recovery(context).await
    }
}

struct CrashRecoveryEvidence {
    crash_windows: Value,
    journal: Value,
    artifact: Value,
    lease: Value,
    bridge_frames: Vec<u8>,
}

struct EffectRecord {
    artifact_id: String,
    checkpoint_id: String,
    digest: String,
    storage_path: String,
}

async fn run_process_kill_recovery(context: &CaseContext) -> CaseOutcome {
    let mut cleanup = CleanupReceipt::default();
    let mut failures = Vec::new();
    let mut evidence = Vec::new();
    match exercise_crash_recovery(context, &mut cleanup).await {
        Ok(record) => {
            evidence.push(json_evidence(
                "crash_windows",
                "kill-recovery.json",
                &record.crash_windows,
            ));
            evidence.push(json_evidence(
                "journal",
                "command-history.json",
                &record.journal,
            ));
            evidence.push(json_evidence(
                "artifact",
                "once-only-effect.json",
                &record.artifact,
            ));
            evidence.push(json_evidence("lease", "singular-lease.json", &record.lease));
            evidence.push(CaseEvidence {
                kind: "bridge_frames",
                label: "recovery-frames.jsonl".to_owned(),
                bytes: record.bridge_frames,
            });
        }
        Err(detail) => {
            failures.push(CaseFailure {
                check: ("crash_recovery").to_owned(),
                detail: detail.clone(),
            });
            if cleanup.steps.is_empty() || cleanup.is_clean() {
                cleanup.push(
                    "case_cleanup",
                    context.ids().session.to_string(),
                    CleanupOutcome::Failed {
                        reason: format!(
                            "crash recovery aborted before a proven clean stop: {detail}"
                        ),
                    },
                );
            }
        }
    }
    finish_outcome(
        "all command crash windows recovered without duplicate effects under one lease",
        failures,
        evidence,
        cleanup,
    )
}

async fn exercise_crash_recovery(
    context: &CaseContext,
    cleanup: &mut CleanupReceipt,
) -> Result<CrashRecoveryEvidence, String> {
    let session = context.session_descriptor();
    let before_send = command_id("before-send")?;
    let after_send = command_id("after-send")?;
    let after_effect = command_id("after-effect")?;
    let before_completion = command_id("before-completion")?;
    let commands = [
        before_send.clone(),
        after_send.clone(),
        after_effect.clone(),
        before_completion.clone(),
    ];
    let mut frames = Vec::new();
    let mut epochs = Vec::new();
    let mut kills = Vec::new();
    let mut bridge = start_bridge(context, &session).await?;
    let initial_binding = bridge.binding().map_err(|error| error.to_string())?;
    let lease_id = initial_binding
        .lease_id
        .ok_or_else(|| "started bridge did not expose its durable lease id".to_owned())?;
    record_epoch(&mut epochs, "initial", &bridge)?;

    append_command_row(context, initial_binding.epoch, &before_send, "set_model")?;
    bridge = crash_and_restart(bridge, "before-send", &mut kills, cleanup).await?;
    require_same_lease(&bridge, &lease_id, "before-send")?;
    require_ready(&bridge, "before-send")?;
    record_epoch(&mut epochs, "before-send-recovered", &bridge)?;
    let before_send_row = live_command(context, &before_send)?;
    if before_send_row.completed_at.is_none()
        || before_send_row
            .outcome
            .as_ref()
            .and_then(|outcome| outcome.get("kind"))
            .and_then(Value::as_str)
            != Some("not_dispatched_before_crash")
    {
        return Err(format!(
            "before-send row was not reconciled as a proven non-effect: {:?}",
            before_send_row.outcome
        ));
    }

    let epoch = bridge.binding().map_err(|error| error.to_string())?.epoch;
    append_command_row(context, epoch, &after_send, "set_model")?;
    append_command_issued(
        context,
        epoch,
        &after_send,
        "set_model",
        "after-send-issued",
    )?;
    bridge = crash_and_restart(bridge, "after-send", &mut kills, cleanup).await?;
    require_same_lease(&bridge, &lease_id, "after-send")?;
    require_blocked_exact(&bridge, &after_send, "after-send")?;
    record_epoch(&mut epochs, "after-send-blocked", &bridge)?;
    match bridge.set_model(FIXTURE_PROVIDER, FIXTURE_MODEL_A).await {
        Err(BridgeError::BlockedIncomplete { commands })
            if commands.len() == 1 && commands[0] == after_send => {}
        Err(error) => {
            return Err(format!(
                "after-send ambiguity returned the wrong mutation failure: {error}"
            ));
        }
        Ok(_) => return Err("after-send ambiguity allowed a mutating command".to_owned()),
    }
    append_command_response(
        context,
        bridge.binding().map_err(|error| error.to_string())?.epoch,
        &after_send,
        "set_model",
        "after-send-response",
        json!({"operator_resolution": "wire effect did not occur"}),
    )?;
    let previous_epoch = bridge.binding().map_err(|error| error.to_string())?.epoch;
    let recovered = bridge.recover().await.map_err(|error| {
        format!("after-send response evidence could not unblock recovery: {error}")
    })?;
    if recovered.epoch != previous_epoch + 1
        || recovered.epoch != bridge.binding().map_err(|error| error.to_string())?.epoch
    {
        return Err("after-send recovery did not advance exactly one epoch".to_owned());
    }
    if !recovered.blocked.is_empty() || !recovered.reconciled.contains(&after_send) {
        return Err(format!(
            "after-send recovery mismatch: reconciled={:?}, blocked={:?}",
            recovered.reconciled, recovered.blocked
        ));
    }
    let after_send_outcome = require_response_outcome(context, &after_send, "set_model")?;
    if after_send_outcome.get("data")
        != Some(&json!({"operator_resolution": "wire effect did not occur"}))
    {
        return Err("after-send recovery accepted the wrong stored response".to_owned());
    }
    require_ready(&bridge, "after-send resolved")?;
    require_same_lease(&bridge, &lease_id, "after-send resolved")?;
    record_epoch(&mut epochs, "after-send-resolved", &bridge)?;

    let epoch = bridge.binding().map_err(|error| error.to_string())?.epoch;
    append_command_row(context, epoch, &after_effect, "checkpoint")?;
    append_command_issued(
        context,
        epoch,
        &after_effect,
        "checkpoint",
        "after-effect-issued",
    )?;
    let effect = create_effect_once(context)?;
    require_object_counts(context, 1, 1, "after-effect creation")?;
    bridge = crash_and_restart(bridge, "after-effect", &mut kills, cleanup).await?;
    require_same_lease(&bridge, &lease_id, "after-effect")?;
    require_blocked_exact(&bridge, &after_effect, "after-effect")?;
    require_object_counts(context, 1, 1, "after-effect blocked recovery")?;
    record_epoch(&mut epochs, "after-effect-blocked", &bridge)?;
    append_command_response(
        context,
        bridge.binding().map_err(|error| error.to_string())?.epoch,
        &after_effect,
        "checkpoint",
        "after-effect-response",
        json!({
            "artifact_id": effect.artifact_id.clone(),
            "checkpoint_id": effect.checkpoint_id.clone(),
            "digest": effect.digest.clone(),
        }),
    )?;
    let previous_epoch = bridge.binding().map_err(|error| error.to_string())?.epoch;
    let recovered = bridge
        .recover()
        .await
        .map_err(|error| format!("after-effect evidence could not unblock recovery: {error}"))?;
    if recovered.epoch != previous_epoch + 1
        || recovered.epoch != bridge.binding().map_err(|error| error.to_string())?.epoch
    {
        return Err("after-effect recovery did not advance exactly one epoch".to_owned());
    }
    if !recovered.blocked.is_empty() || !recovered.reconciled.contains(&after_effect) {
        return Err(format!(
            "after-effect recovery mismatch: reconciled={:?}, blocked={:?}",
            recovered.reconciled, recovered.blocked
        ));
    }
    let after_effect_outcome = require_response_outcome(context, &after_effect, "checkpoint")?;
    if after_effect_outcome.get("data")
        != Some(&json!({
            "artifact_id": effect.artifact_id.clone(),
            "checkpoint_id": effect.checkpoint_id.clone(),
            "digest": effect.digest.clone(),
        }))
    {
        return Err("after-effect recovery accepted the wrong stored response".to_owned());
    }
    require_ready(&bridge, "after-effect resolved")?;
    require_same_lease(&bridge, &lease_id, "after-effect resolved")?;
    require_effect_is_once(context, &effect)?;
    record_epoch(&mut epochs, "after-effect-resolved", &bridge)?;

    let epoch = bridge.binding().map_err(|error| error.to_string())?.epoch;
    append_command_row(context, epoch, &before_completion, "set_model")?;
    append_command_issued(
        context,
        epoch,
        &before_completion,
        "set_model",
        "before-completion-issued",
    )?;
    append_command_response(
        context,
        epoch,
        &before_completion,
        "set_model",
        "before-completion-response",
        json!({"provider": FIXTURE_PROVIDER, "model": FIXTURE_MODEL_A}),
    )?;
    if live_command(context, &before_completion)?
        .completed_at
        .is_some()
    {
        return Err("before-completion command was completed before the injected crash".to_owned());
    }
    bridge = crash_and_restart(bridge, "before-completion", &mut kills, cleanup).await?;
    require_same_lease(&bridge, &lease_id, "before-completion")?;
    require_ready(&bridge, "before-completion")?;
    record_epoch(&mut epochs, "before-completion-recovered", &bridge)?;
    let original_outcome = require_response_outcome(context, &before_completion, "set_model")?;
    if original_outcome.get("data")
        != Some(&json!({"provider": FIXTURE_PROVIDER, "model": FIXTURE_MODEL_A}))
    {
        return Err("before-completion recovery accepted the wrong stored response".to_owned());
    }
    match complete_command(
        context,
        &before_completion,
        json!({"kind": "incorrect-duplicate-completion"}),
    )? {
        CompleteLiveCommand::Existing(existing) if existing.outcome == Some(original_outcome) => {}
        CompleteLiveCommand::Existing(_) => {
            return Err("duplicate completion changed the durable command outcome".to_owned());
        }
        CompleteLiveCommand::Completed(_) => {
            return Err("recovery left the before-completion command incomplete".to_owned());
        }
    }
    require_effect_is_once(context, &effect)?;

    let mut contender = context
        .bridge_config(session)
        .map_err(|error| format!("contender bridge config failed: {error}"))?;
    contender.binding.owner_id = format!("{}-contender", context.ids().owner);
    match OmpBridge::start(contender).await {
        Err(BridgeError::LeaseConflict { .. }) => {}
        Err(error) => return Err(format!("contender returned a non-lease error: {error}")),
        Ok(unexpected) => {
            let _ = unexpected.stop().await;
            return Err("a second lease owner started the same durable session".to_owned());
        }
    }
    let (active_leases, distinct_owners, total_leases) = lease_counts(context)?;
    if (active_leases, distinct_owners, total_leases) != (1, 1, 1) {
        return Err(format!(
            "session lease was not singular: active={active_leases}, owners={distinct_owners}, total={total_leases}"
        ));
    }
    bridge
        .set_model(FIXTURE_PROVIDER, FIXTURE_MODEL_A)
        .await
        .map_err(|error| format!("final recovered bridge rejected mutation: {error}"))?;

    // The in-process evidence window is gone. Frames already broadcast are
    // in the durable journal; a late subscribe cannot replay them, so nothing
    // is counted as elided.
    let final_binding = bridge.binding().map_err(|error| error.to_string())?;
    let stop = bridge.stop().await.map_err(|error| {
        cleanup.push(
            "child_stop",
            context.ids().session.to_string(),
            CleanupOutcome::Failed {
                reason: error.to_string(),
            },
        );
        error.to_string()
    })?;
    for frame in &stop.drained {
        append_raw(&mut frames, &frame.raw());
    }
    cleanup.push(
        "child_stop",
        context.ids().session.to_string(),
        if stop.exit.is_some() {
            CleanupOutcome::Clean
        } else {
            CleanupOutcome::Failed {
                reason: "healthy replacement stopped without observable child exit".to_owned(),
            }
        },
    );
    cleanup.push(
        "lease_release",
        lease_id.to_string(),
        if stop.lease_released {
            CleanupOutcome::Clean
        } else {
            CleanupOutcome::Failed {
                reason: "final bridge stop did not release its session lease".to_owned(),
            }
        },
    );
    if !stop.incomplete.is_empty() {
        return Err(format!(
            "final stop retained incomplete issued commands: {:?}",
            stop.incomplete
        ));
    }
    let (active_after_stop, _, total_after_stop) = lease_counts(context)?;
    if active_after_stop != 0 || total_after_stop != 1 {
        return Err(format!(
            "lease cleanup mismatch after stop: active={active_after_stop}, total={total_after_stop}"
        ));
    }

    let (journal, issued_counts, response_counts) = journal_snapshot(context, &commands)?;
    if issued_counts != [0, 1, 1, 1] {
        return Err(format!(
            "crash-window issued cardinality changed: {issued_counts:?}"
        ));
    }
    if response_counts != [0, 1, 1, 1] {
        return Err(format!(
            "crash-window response cardinality changed: {response_counts:?}"
        ));
    }
    for command in &commands {
        if live_command(context, command)?.completed_at.is_none() {
            return Err(format!("resolved command {command} remained incomplete"));
        }
    }

    let crash_windows = json!({
        "schema": "odin.omp.probe.crash-windows.v1",
        "session_id": context.ids().session.to_string(),
        "owner_id": context.ids().owner,
        "lease_id": lease_id.to_string(),
        "epochs": epochs,
        "kills": kills,
        "windows": [
            {"name":"before-send","command_id":before_send.to_string(),"issued_events":issued_counts[0],"response_events":response_counts[0],"resolution":"durable row proved unsent; no effect"},
            {"name":"after-send","command_id":after_send.to_string(),"issued_events":issued_counts[1],"response_events":response_counts[1],"resolution":"ambiguous command blocked until response evidence"},
            {"name":"after-effect","command_id":after_effect.to_string(),"issued_events":issued_counts[2],"response_events":response_counts[2],"resolution":"durable effect blocked until response evidence; artifact not recreated"},
            {"name":"before-completion","command_id":before_completion.to_string(),"issued_events":issued_counts[3],"response_events":response_counts[3],"resolution":"completed once from durable response history"},
        ],
        "final_epoch": final_binding.epoch,
        "bridge_evidence_elided": 0,
        "effect_cardinality": 1,
        "cleanup_clean": cleanup.is_clean(),
    });
    let artifact = json!({
        "schema": "odin.omp.probe.once-only-effect.v1",
        "artifact_id": effect.artifact_id,
        "checkpoint_id": effect.checkpoint_id,
        "digest": effect.digest,
        "storage_path": effect.storage_path,
        "artifact_rows": 1,
        "checkpoint_rows": 1,
        "bytes": EFFECT_BYTES.len(),
    });
    let lease = json!({
        "schema": "odin.omp.probe.singular-lease.v1",
        "lease_id": lease_id.to_string(),
        "owner_id": context.ids().owner,
        "active_during_recovery": active_leases,
        "distinct_owners_during_recovery": distinct_owners,
        "total_rows": total_after_stop,
        "active_after_stop": active_after_stop,
        "contender_rejected": true,
        "released": stop.lease_released,
    });
    Ok(CrashRecoveryEvidence {
        crash_windows,
        journal,
        artifact,
        lease,
        bridge_frames: frames,
    })
}

async fn start_bridge(
    context: &CaseContext,
    session: &LiveSessionDescriptor,
) -> Result<OmpBridge, String> {
    let config = context
        .bridge_config(session.clone())
        .map_err(|error| format!("bridge configuration failed: {error}"))?;
    OmpBridge::start(config)
        .await
        .map_err(|error| format!("bridge start failed: {error}"))
}

async fn crash_and_restart(
    bridge: OmpBridge,
    window: &'static str,
    kills: &mut Vec<Value>,
    cleanup: &mut CleanupReceipt,
) -> Result<OmpBridge, String> {
    let binding = bridge.binding().map_err(|error| error.to_string())?;
    let subject = format!("{window}:{}", binding.session_id);
    match bridge.kill_child_for_probe().await {
        Ok(Some(exit)) => {
            let status = exit.status().map(|status| status.to_string());
            // The production kill returns Ok only after StopAuthority proves
            // Stopped. The manager may reap the leader without an observable
            // OS exit status; retain that absence rather than inventing one.
            if exit.success() {
                let detail = format!("forced crash returned a non-killed exit: {exit}");
                cleanup.push(
                    "child_crash",
                    subject,
                    CleanupOutcome::Failed {
                        reason: detail.clone(),
                    },
                );
                return Err(format!("{window}: {detail}"));
            }
            kills.push(json!({
                "window": window,
                "status": status,
                "code": exit.code(),
                "success": exit.success(),
                "stderr_bytes": exit.stderr_tail().len(),
                "stderr_blake3": blake3::hash(exit.stderr_tail()).to_hex().to_string(),
                "unfinished": exit
                    .unfinished_sequence()
                    .map(|error| error.kind().to_string()),
            }));
            cleanup.push("child_crash", subject, CleanupOutcome::Clean);
        }
        Ok(None) => {
            let detail = "production bridge reported no child at the injected crash boundary";
            cleanup.push(
                "child_crash",
                subject,
                CleanupOutcome::Failed {
                    reason: detail.to_owned(),
                },
            );
            return Err(format!("{window}: {detail}"));
        }
        Err(error) => {
            cleanup.push(
                "child_crash",
                subject,
                CleanupOutcome::Failed {
                    reason: error.to_string(),
                },
            );
            return Err(format!("{window}: production child kill failed: {error}"));
        }
    }
    let previous_epoch = bridge.binding().map_err(|error| error.to_string())?.epoch;
    let recovered = bridge
        .recover()
        .await
        .map_err(|error| format!("{window}: production bridge recovery failed: {error}"))?;
    if recovered.epoch != previous_epoch + 1
        || recovered.epoch != bridge.binding().map_err(|error| error.to_string())?.epoch
    {
        return Err(format!(
            "{window}: recovery did not advance exactly one epoch: previous={previous_epoch}, report={}, binding={}",
            recovered.epoch,
            bridge.binding().map_err(|error| error.to_string())?.epoch
        ));
    }
    Ok(bridge)
}

fn append_command_row(
    context: &CaseContext,
    epoch: i64,
    command_id: &CommandId,
    command: &str,
) -> Result<(), String> {
    let command_id = command_id.clone();
    let session_id = context.ids().session.clone();
    let frame = json!({"id":command_id.to_string(),"type":command,"probeCrashWindow":true});
    ledger_op(context, move |ledger| {
        let head = ledger.reconnect_head(&session_id)?;
        let row = NewLiveCommand {
            command_id,
            session_id,
            expected_epoch: epoch,
            expected_event_head: Some(head),
            body: frame,
            issued_at: OffsetDateTime::now_utc(),
        };
        match ledger.append_live_command(&row)? {
            AppendLiveCommand::Inserted(_) => Ok(()),
            AppendLiveCommand::Existing(existing) => Err(LedgerError::Conflict(format!(
                "probe crash-window command {} already existed",
                existing.command_id
            ))),
        }
    })
}

fn append_command_issued(
    context: &CaseContext,
    epoch: i64,
    command_id: &CommandId,
    command: &'static str,
    event_label: &'static str,
) -> Result<(), String> {
    let event_id = event_id(event_label)?;
    let command_id = command_id.clone();
    let session_id = context.ids().session.clone();
    ledger_op(context, move |ledger| {
        ledger.append_live_event_after_blobs(&NewLiveEvent {
            event_id,
            session_id,
            expected_epoch: epoch,
            occurred_at: OffsetDateTime::now_utc(),
            body: json!({
                "kind":"command_issued","command":command,"command_id":command_id.to_string(),
                "frame":{"id":command_id.to_string(),"type":command,"probeCrashWindow":true},
            }),
            blob_refs: json!([]),
        })?;
        Ok(())
    })
}

fn append_command_response(
    context: &CaseContext,
    epoch: i64,
    command_id: &CommandId,
    command: &'static str,
    event_label: &'static str,
    data: Value,
) -> Result<(), String> {
    let event_id = event_id(event_label)?;
    let command_id = command_id.clone();
    let session_id = context.ids().session.clone();
    ledger_op(context, move |ledger| {
        ledger.append_live_event_after_blobs(&NewLiveEvent {
            event_id,
            session_id,
            expected_epoch: epoch,
            occurred_at: OffsetDateTime::now_utc(),
            body: json!({
                "kind":"command_response","command":command,"command_id":command_id.to_string(),
                "success":true,"data":data,
            }),
            blob_refs: json!([]),
        })?;
        Ok(())
    })
}

fn create_effect_once(context: &CaseContext) -> Result<EffectRecord, String> {
    let digest = Digest::hash(EFFECT_BYTES);
    let hex = digest_hex(&digest);
    let storage_path = format!("{}/{}", &hex[..2], hex);
    let path = context.artifact_root().join(&storage_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("effect artifact directory creation failed: {error}"))?;
    }
    match std::fs::read(&path) {
        Ok(existing) if existing.as_slice() == EFFECT_BYTES => {}
        Ok(_) => {
            return Err(format!(
                "effect path {} held different bytes",
                path.display()
            ))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|error| format!("effect artifact create failed: {error}"))?;
            file.write_all(EFFECT_BYTES)
                .map_err(|error| format!("effect artifact write failed: {error}"))?;
            file.sync_all()
                .map_err(|error| format!("effect artifact sync failed: {error}"))?;
            if let Some(parent) = path.parent() {
                std::fs::File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|error| format!("effect artifact directory sync failed: {error}"))?;
            }
        }
        Err(error) => return Err(format!("effect artifact read failed: {error}")),
    }
    let checkpoint_id = CheckpointId::from_parts("odin-probe-c16-checkpoint", 16, "after-effect")
        .map_err(|error| error.to_string())?;
    let run_id = context.ids().run.clone();
    let storage_for_ledger = storage_path.clone();
    let (artifact, checkpoint) = ledger_op(context, move |ledger| {
        let artifact = ledger.register_artifact(ArtifactRegistration {
            bytes: EFFECT_BYTES,
            media_type: "application/json",
            storage_path: &storage_for_ledger,
            retention: RetentionClass::Pinned,
            created_at: OffsetDateTime::now_utc(),
        })?;
        let created = ledger.create_checkpoint(&CheckpointSpec {
            id: checkpoint_id,
            run_id,
            command_id: None,
            compatibility_key: CHECKPOINT_COMPATIBILITY_KEY.to_owned(),
            artifact_ref: artifact.artifact_id.clone(),
            artifact_digest: artifact.digest,
            state_digest: digest,
            created_at: OffsetDateTime::now_utc(),
        })?;
        let committed =
            ledger.commit_checkpoint(&created.id, created.revision, OffsetDateTime::now_utc())?;
        Ok((artifact, committed))
    })?;
    if !checkpoint.is_committed() {
        return Err("after-effect checkpoint was not committed".to_owned());
    }
    Ok(EffectRecord {
        artifact_id: artifact.artifact_id.to_string(),
        checkpoint_id: checkpoint.id.to_string(),
        digest: artifact.digest.to_string(),
        storage_path,
    })
}

fn require_effect_is_once(context: &CaseContext, effect: &EffectRecord) -> Result<(), String> {
    require_object_counts(context, 1, 1, "effect reconciliation")?;
    let digest = Digest::parse(&effect.digest).map_err(|error| error.to_string())?;
    let expected_id = effect.artifact_id.clone();
    let existing = ledger_op(context, move |ledger| {
        let original =
            ledger
                .artifact_by_digest(&digest)?
                .ok_or_else(|| LedgerError::NotFound {
                    kind: "artifact",
                    id: expected_id,
                })?;
        let repeated = ledger.register_artifact(ArtifactRegistration {
            bytes: EFFECT_BYTES,
            media_type: "application/json",
            storage_path: "must-not-replace-original",
            retention: RetentionClass::Scratch,
            created_at: OffsetDateTime::now_utc(),
        })?;
        Ok((original, repeated))
    })?;
    if existing.0 != existing.1 || existing.0.artifact_id.to_string() != effect.artifact_id {
        return Err("content-addressed retry created or replaced the durable artifact".to_owned());
    }
    require_object_counts(context, 1, 1, "effect idempotency retry")
}

fn require_object_counts(
    context: &CaseContext,
    expected_artifacts: i64,
    expected_checkpoints: i64,
    phase: &str,
) -> Result<(), String> {
    let (artifacts, checkpoints) = ledger_op(context, |ledger| {
        let artifacts =
            ledger
                .connection()
                .query_row("SELECT COUNT(*) FROM artifacts", [], |row| {
                    row.get::<_, i64>(0)
                })?;
        let checkpoints =
            ledger
                .connection()
                .query_row("SELECT COUNT(*) FROM checkpoints", [], |row| {
                    row.get::<_, i64>(0)
                })?;
        Ok((artifacts, checkpoints))
    })?;
    if (artifacts, checkpoints) != (expected_artifacts, expected_checkpoints) {
        return Err(format!(
            "{phase} changed effect cardinality: artifacts={artifacts}, checkpoints={checkpoints}"
        ));
    }
    Ok(())
}

fn lease_counts(context: &CaseContext) -> Result<(i64, i64, i64), String> {
    let session_id = context.ids().session.to_string();
    ledger_op(context, move |ledger| {
        let active = ledger.connection().query_row(
            "SELECT COUNT(*) FROM leases WHERE object_kind=?1 AND object_id=?2 AND released_at IS NULL",
            [LEASE_OBJECT_KIND, session_id.as_str()],
            |row| row.get::<_, i64>(0),
        )?;
        let owners = ledger.connection().query_row(
            "SELECT COUNT(DISTINCT owner_id) FROM leases WHERE object_kind=?1 AND object_id=?2",
            [LEASE_OBJECT_KIND, session_id.as_str()],
            |row| row.get::<_, i64>(0),
        )?;
        let total = ledger.connection().query_row(
            "SELECT COUNT(*) FROM leases WHERE object_kind=?1 AND object_id=?2",
            [LEASE_OBJECT_KIND, session_id.as_str()],
            |row| row.get::<_, i64>(0),
        )?;
        Ok((active, owners, total))
    })
}

fn journal_snapshot(
    context: &CaseContext,
    commands: &[CommandId; 4],
) -> Result<(Value, [usize; 4], [usize; 4]), String> {
    let session_id = context.ids().session.clone();
    let command_ids = (*commands).clone();
    ledger_op(context, move |ledger| {
        let head = ledger.reconnect_head(&session_id)?;
        let history = ledger.live_event_history(&session_id, 0, head)?;
        let mut issued = [0_usize; 4];
        let mut responses = [0_usize; 4];
        for event in &history {
            let kind = event.body.get("kind").and_then(Value::as_str);
            let id = event.body.get("command_id").and_then(Value::as_str);
            for (index, command_id) in command_ids.iter().enumerate() {
                if id == Some(command_id.as_str()) {
                    if kind == Some("command_issued") {
                        issued[index] += 1;
                    }
                    if matches!(kind, Some("command_response" | "response_mismatch")) {
                        responses[index] += 1;
                    }
                }
            }
        }
        let command_rows = command_ids
            .iter()
            .map(|id| ledger.live_command(id).map(|row| live_command_json(&row)))
            .collect::<Result<Vec<_>, _>>()?;
        let event_rows = history
            .iter()
            .map(|event| {
                json!({
                    "event_id":event.event_id.to_string(),"epoch":event.epoch,
                    "sequence":event.sequence,"body":event.body.clone(),
                    "blob_refs":event.blob_refs.clone(),
                })
            })
            .collect::<Vec<_>>();
        Ok((
            json!({
                "schema":"odin.omp.probe.command-journal.v1",
                "session_id":session_id.to_string(),"captured_head":head,
                "commands":command_rows,"history":event_rows,
            }),
            issued,
            responses,
        ))
    })
}

fn live_command_json(command: &LiveCommand) -> Value {
    json!({
        "command_id":command.command_id.to_string(),"session_id":command.session_id.to_string(),
        "expected_epoch":command.expected_epoch,"expected_event_head":command.expected_event_head,
        "body":command.body.clone(),"issued_at":command.issued_at,
        "completed_at":command.completed_at,"outcome":command.outcome.clone(),
    })
}

fn live_command(context: &CaseContext, command_id: &CommandId) -> Result<LiveCommand, String> {
    let command_id = command_id.clone();
    ledger_op(context, move |ledger| ledger.live_command(&command_id))
}

fn require_response_outcome(
    context: &CaseContext,
    command_id: &CommandId,
    command: &str,
) -> Result<Value, String> {
    let row = live_command(context, command_id)?;
    let outcome = row
        .outcome
        .ok_or_else(|| format!("reconciled command {command_id} had no outcome"))?;
    if row.completed_at.is_none()
        || outcome.get("kind").and_then(Value::as_str) != Some("command_response")
        || outcome.get("command_id").and_then(Value::as_str) != Some(command_id.as_str())
        || outcome.get("command").and_then(Value::as_str) != Some(command)
        || outcome.get("success").and_then(Value::as_bool) != Some(true)
    {
        return Err(format!(
            "reconciled command {command_id} accepted an invalid stored outcome: {outcome}"
        ));
    }
    Ok(outcome)
}

fn complete_command(
    context: &CaseContext,
    command_id: &CommandId,
    outcome: Value,
) -> Result<CompleteLiveCommand, String> {
    let command_id = command_id.clone();
    ledger_op(context, move |ledger| {
        ledger.complete_live_command_once(&command_id, &outcome, OffsetDateTime::now_utc())
    })
}

fn ledger_op<T>(
    context: &CaseContext,
    operation: impl FnOnce(&mut Ledger) -> Result<T, LedgerError>,
) -> Result<T, String> {
    let ledger = context.ledger();
    let mut guard = ledger
        .lock()
        .map_err(|_| "probe ledger mutex was poisoned".to_owned())?;
    operation(&mut guard).map_err(|error| error.to_string())
}

fn require_same_lease(
    bridge: &OmpBridge,
    expected: &odin_domain::LeaseId,
    phase: &str,
) -> Result<(), String> {
    match bridge
        .binding()
        .map_err(|error| error.to_string())?
        .lease_id
    {
        Some(actual) if &actual == expected => Ok(()),
        actual => Err(format!(
            "{phase} recovery changed the singular lease: expected {expected}, observed {actual:?}"
        )),
    }
}

fn require_ready(bridge: &OmpBridge, phase: &str) -> Result<(), String> {
    match bridge.status().map_err(|error| error.to_string())? {
        BridgeStatus::Ready => Ok(()),
        status => Err(format!("{phase} recovery was not ready: {status:?}")),
    }
}

fn require_blocked_exact(
    bridge: &OmpBridge,
    expected: &CommandId,
    phase: &str,
) -> Result<(), String> {
    match bridge.status().map_err(|error| error.to_string())? {
        BridgeStatus::Blocked { commands } if commands.len() == 1 && commands[0] == *expected => {
            Ok(())
        }
        status => Err(format!(
            "{phase} recovery did not block only {expected}: {status:?}"
        )),
    }
}

fn record_epoch(
    entries: &mut Vec<Value>,
    phase: &'static str,
    bridge: &OmpBridge,
) -> Result<(), String> {
    let binding = bridge.binding().map_err(|error| error.to_string())?;
    let status = bridge.status().map_err(|error| error.to_string())?;
    entries.push(json!({
        "phase":phase,"epoch":binding.epoch,
        "lease_id":binding.lease_id.map(|id| id.to_string()),
        "status":format!("{status:?}"),
    }));
    Ok(())
}

fn command_id(label: &'static str) -> Result<CommandId, String> {
    CommandId::from_parts("odin-probe-c16-command", 16, label).map_err(|error| error.to_string())
}

fn event_id(label: &'static str) -> Result<EventId, String> {
    EventId::from_parts("odin-probe-c16-event", 16, label).map_err(|error| error.to_string())
}

fn digest_hex(digest: &Digest) -> String {
    digest
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
