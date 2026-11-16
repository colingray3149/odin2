//! Durable root-plan decision continuations, independent of the conversation vehicle.
use odin_domain::huginn::{
    CommandReceipt, LiveCommand, LiveCommandBody, LiveContentBlock, LiveMessage, LiveSessionId,
    LiveSessionState, OmpLivePlane, SessionEpoch,
};
use odin_domain::{ApprovalId, CommandId, Digest};
use odin_ledger::plan_acceptance::{RootPlanConsent, RootPlanContinuation};
use odin_ledger::Ledger;
use odin_omp::live::service::OmpLiveService;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use time::OffsetDateTime;
use tokio::task::JoinSet;

#[async_trait::async_trait]
trait WakePlane: Send + Sync {
    async fn state(&self, session: LiveSessionId) -> Result<(LiveSessionState, u64), String>;
    async fn admitted(&self, command: &LiveCommand) -> Result<bool, String>;
    async fn send(&self, command: LiveCommand) -> Result<CommandReceipt, String>;
}

#[async_trait::async_trait]
impl WakePlane for OmpLiveService {
    async fn state(&self, session: LiveSessionId) -> Result<(LiveSessionState, u64), String> {
        let summary = self
            .supervisor()
            .durable_summary(session)
            .await
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("root session {session} is missing"))?;
        Ok((summary.state, summary.epoch.get()))
    }
    async fn admitted(&self, command: &LiveCommand) -> Result<bool, String> {
        Ok(self
            .command_entry(command)
            .await
            .map_err(|error| error.to_string())?
            .is_some())
    }
    async fn send(&self, command: LiveCommand) -> Result<CommandReceipt, String> {
        self.command(command)
            .await
            .map_err(|error| error.to_string())
    }
}

fn command(
    id: &ApprovalId,
    consent: &RootPlanConsent,
    approved: bool,
    epoch: u64,
) -> Result<LiveCommand, String> {
    let session_id =
        LiveSessionId::parse(consent.session.as_str()).map_err(|error| error.to_string())?;
    let identity = format!("{}:{epoch}", id.as_str());
    let command_id = CommandId::new(format!(
        "command:root-consent-wake:{}",
        Digest::hash(identity.as_bytes())
    ))
    .map_err(|error| error.to_string())?;
    let text = if approved {
        "[host] The owner accepted the reviewed root plan. Continue the plan; the blocked operation has not been run by the host."
    } else {
        "[host] The owner declined the reviewed root plan. It is not accepted; do not proceed under it."
    };
    let message = LiveMessage::new(vec![LiveContentBlock::Text(text.to_owned())])
        .map_err(|error| error.to_string())?;
    Ok(LiveCommand {
        command_id,
        session_id,
        expected_epoch: SessionEpoch::new(epoch),
        expected_event_head: None,
        body: LiveCommandBody::Prompt {
            message,
            owner_text: None,
            wake: false,
        },
    })
}

async fn deliver(
    ledger: &Mutex<Ledger>,
    plane: &impl WakePlane,
    id: &ApprovalId,
    consent: &RootPlanConsent,
    continuation: &RootPlanContinuation,
) -> Result<(), String> {
    let session =
        LiveSessionId::parse(consent.session.as_str()).map_err(|error| error.to_string())?;
    let (state, current_epoch) = plane.state(session).await?;
    // Reconstruct an earlier attempt before checking current state, so a lost receipt
    // is recovered even if the admitted prompt is now running.
    let epoch = if let Some(epoch) = continuation.epoch {
        epoch
    } else {
        if state != LiveSessionState::Idle {
            return Ok(());
        }
        ledger
            .lock()
            .map_err(|error| error.to_string())?
            .claim_root_plan_continuation(id, current_epoch, OffsetDateTime::now_utc())
            .map_err(|error| error.to_string())?
    };
    let command = command(id, consent, continuation.approved, epoch)?;
    if plane.admitted(&command).await? {
        ledger
            .lock()
            .map_err(|error| error.to_string())?
            .mark_root_plan_continuation_admitted(id, epoch, OffsetDateTime::now_utc())
            .map_err(|error| error.to_string())?;
        return Ok(());
    }
    if current_epoch != epoch {
        // The old identity was never admitted; a new epoch gets a new identity.
        ledger
            .lock()
            .map_err(|error| error.to_string())?
            .reset_root_plan_continuation_claim(id, epoch, OffsetDateTime::now_utc())
            .map_err(|error| error.to_string())?;
        return Ok(());
    }
    if state != LiveSessionState::Idle {
        return Ok(());
    }
    match plane.send(command).await? {
        CommandReceipt::Accepted { .. } | CommandReceipt::Duplicate { .. } => {
            ledger
                .lock()
                .map_err(|error| error.to_string())?
                .mark_root_plan_continuation_admitted(id, epoch, OffsetDateTime::now_utc())
                .map_err(|error| error.to_string())?;
        }
        CommandReceipt::Rejected { reason, .. } => {
            tracing::warn!(approval = %id, %reason, "root plan continuation deferred");
        }
    }
    Ok(())
}

pub(super) fn arm(
    pumps: &mut JoinSet<Result<(), String>>,
    ledger: Arc<Mutex<Ledger>>,
    omp: Arc<OmpLiveService>,
    registry: Arc<odin_registry::SnapshotHandle>,
) {
    pumps.spawn(async move {
        loop {
            let snapshot = registry.current();
            let seconds = snapshot.objects.iter().find_map(|object| match &object.config {
                odin_registry::ObjectConfig::Node(node) if node.enabled && node.authoritative_state => node.root_plan_wake_seconds,
                _ => None,
            }).map_or(5, |seconds| seconds.get());
            tokio::time::sleep(Duration::from_secs(u64::from(seconds))).await;
            let pending = match ledger.lock() {
                Ok(ledger) => ledger.pending_root_plan_continuations().map_err(|error| error.to_string()),
                Err(error) => Err(error.to_string()),
            };
            match pending {
                Ok(pending) => for (id, consent, continuation) in pending {
                    if let Err(error) = deliver(&ledger, omp.as_ref(), &id, &consent, &continuation).await {
                        tracing::warn!(approval = %id, %error, "root plan continuation deferred");
                    }
                },
                Err(error) => tracing::error!(%error, "root plan continuation queue unavailable"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use odin_domain::{Actor, EventId, Redaction, RunId, SessionId};
    use odin_ledger::approval::{ApprovalDecision, DecisionIntake};
    use odin_ledger::audit::{NewAuditEvent, RedactedPayload};
    use std::collections::BTreeMap;

    struct FakePlane {
        state: Mutex<(LiveSessionState, u64)>,
        commands: Mutex<BTreeMap<String, LiveCommand>>,
        lose_receipt: Mutex<bool>,
    }
    #[async_trait::async_trait]
    impl WakePlane for FakePlane {
        async fn state(&self, _: LiveSessionId) -> Result<(LiveSessionState, u64), String> {
            Ok(*self.state.lock().unwrap())
        }
        async fn admitted(&self, command: &LiveCommand) -> Result<bool, String> {
            Ok(self
                .commands
                .lock()
                .unwrap()
                .get(command.command_id.as_str())
                == Some(command))
        }
        async fn send(&self, command: LiveCommand) -> Result<CommandReceipt, String> {
            let id = command.command_id.clone();
            self.commands
                .lock()
                .unwrap()
                .insert(id.to_string(), command);
            if std::mem::take(&mut *self.lose_receipt.lock().unwrap()) {
                return Err("receipt lost".into());
            }
            Ok(CommandReceipt::Accepted { command_id: id })
        }
    }

    fn decided(path: &std::path::Path, session: &str, approved: bool) -> ApprovalId {
        let mut ledger = Ledger::open(path).unwrap();
        let now = OffsetDateTime::now_utc();
        let run = RunId::new(format!("run:live:{session}")).unwrap();
        ledger.connection().execute_batch(&format!("INSERT INTO lanes(lane_id, seat_id, template_id, backend, status, created_by, created_at, updated_at) VALUES ('lane:wake', 'seat:test', 'template:test', 'local_omp', 'desired', 'test', '1970-01-01T00:00:00Z', '1970-01-01T00:00:00Z'); INSERT INTO runs(run_id, lane_id, attempt_number, status, input_hash, created_at, updated_at) VALUES ('{run}', 'lane:wake', 1, 'pending', 'hash', '1970-01-01T00:00:00Z', '1970-01-01T00:00:00Z');")).unwrap();
        let plan = ledger
            .replace_plan(&run, "review the incident", &[], 0, now)
            .unwrap();
        let id = ledger
            .request_root_plan_consent(
                &run,
                &SessionId::new(session).unwrap(),
                "seat:test",
                plan.revision,
                &plan.objective,
                now,
            )
            .unwrap();
        let row = ledger.approval(&id).unwrap().unwrap();
        let event = EventId::new("event:wake-preview").unwrap();
        let payload = serde_json::json!({"approvalId": id.as_str(), "revision": row.revision,
            "capabilityId": "plan.root-consent", "session": row.scope.target_id,
            "argumentsDigest": row.scope.arguments_digest.to_string(), "completeSnapshot": true});
        ledger
            .append_audit_event(NewAuditEvent {
                event_id: event.clone(),
                kind: odin_ledger::approval::OWNER_PREVIEW_DELIVERY_KIND.to_owned(),
                actor: Actor::System {
                    name: "odin-hermes.runtime".into(),
                },
                scope: Default::default(),
                evidence: Vec::new(),
                payload: RedactedPayload::new(payload, Redaction::None).unwrap(),
                occurred_at: now,
            })
            .unwrap();
        let decision = if approved {
            ApprovalDecision::Approve {
                evidence_ref: Some(format!("delivery:{event}")),
            }
        } else {
            ApprovalDecision::Deny {
                evidence_ref: "owner:no".into(),
            }
        };
        ledger
            .decide_approval_consuming_intake(
                &id,
                decision,
                "owner:test",
                now,
                row.revision,
                &DecisionIntake {
                    consumer_id: "owner:test".into(),
                    message_id: "message:test".into(),
                    owner_preview: true,
                },
            )
            .unwrap()
            .unwrap();
        id
    }

    #[tokio::test]
    async fn continuation_recovers_lost_receipt_for_both_session_kinds_and_decisions() {
        for (session, approved) in [
            ("00000000-0000-4000-8000-0000000000a1", true),
            ("00000000-0000-4000-8000-0000000000b2", false),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("authority.sqlite3");
            let id = decided(&path, session, approved);
            let plane = FakePlane {
                state: Mutex::new((LiveSessionState::Idle, 1)),
                commands: Mutex::new(BTreeMap::new()),
                lose_receipt: Mutex::new(true),
            };
            let ledger = Mutex::new(Ledger::open(&path).unwrap());
            let (queued, consent, intent) = ledger
                .lock()
                .unwrap()
                .pending_root_plan_continuations()
                .unwrap()
                .pop()
                .unwrap();
            assert_eq!(id, queued);
            assert!(deliver(&ledger, &plane, &id, &consent, &intent)
                .await
                .is_err());
            drop(ledger);
            *plane.state.lock().unwrap() = (LiveSessionState::Running, 1);
            let reopened = Mutex::new(Ledger::open(&path).unwrap());
            let (_, consent, intent) = reopened
                .lock()
                .unwrap()
                .pending_root_plan_continuations()
                .unwrap()
                .pop()
                .unwrap();
            deliver(&reopened, &plane, &id, &consent, &intent)
                .await
                .unwrap();
            assert!(reopened
                .lock()
                .unwrap()
                .pending_root_plan_continuations()
                .unwrap()
                .is_empty());
            let sent = plane.commands.lock().unwrap();
            assert_eq!(sent.len(), 1);
            let command = sent.values().next().unwrap();
            assert_eq!(command.session_id.to_string(), session);
            let LiveCommandBody::Prompt { message, .. } = &command.body else {
                panic!("expected prompt")
            };
            let LiveContentBlock::Text(text) = &message.content[0] else {
                panic!("expected text")
            };
            assert!(text.contains(if approved { "accepted" } else { "declined" }));
            assert!(!text.contains("host made the call"));
        }
    }

    #[tokio::test]
    async fn waits_for_idle_and_reclaims_an_unadmitted_stale_epoch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authority.sqlite3");
        let id = decided(&path, "00000000-0000-4000-8000-0000000000c3", true);
        let ledger = Mutex::new(Ledger::open(&path).unwrap());
        let plane = FakePlane {
            state: Mutex::new((LiveSessionState::Running, 1)),
            commands: Mutex::new(BTreeMap::new()),
            lose_receipt: Mutex::new(false),
        };
        let (_, consent, intent) = ledger
            .lock()
            .unwrap()
            .pending_root_plan_continuations()
            .unwrap()
            .pop()
            .unwrap();
        deliver(&ledger, &plane, &id, &consent, &intent)
            .await
            .unwrap();
        assert!(plane.commands.lock().unwrap().is_empty());
        ledger
            .lock()
            .unwrap()
            .claim_root_plan_continuation(&id, 1, OffsetDateTime::now_utc())
            .unwrap();
        *plane.state.lock().unwrap() = (LiveSessionState::Idle, 2);
        let (_, consent, intent) = ledger
            .lock()
            .unwrap()
            .pending_root_plan_continuations()
            .unwrap()
            .pop()
            .unwrap();
        deliver(&ledger, &plane, &id, &consent, &intent)
            .await
            .unwrap();
        let (_, consent, intent) = ledger
            .lock()
            .unwrap()
            .pending_root_plan_continuations()
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(intent.epoch, None);
        deliver(&ledger, &plane, &id, &consent, &intent)
            .await
            .unwrap();
        assert!(ledger
            .lock()
            .unwrap()
            .pending_root_plan_continuations()
            .unwrap()
            .is_empty());
        let sent = plane.commands.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent.values().next().unwrap().expected_epoch.get(), 2);
    }
}
