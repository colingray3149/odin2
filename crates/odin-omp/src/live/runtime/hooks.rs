use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use odin_domain::huginn::{ApprovalDecision, LiveError};
use odin_domain::{ApprovalId, ApprovalStatus, NodeId, RunId};
use odin_ledger::approval::{ApprovalDecision as LedgerApprovalDecision, DecideApproval};
use odin_ledger::Ledger;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::live::control::LiveControlHooks;

use super::errors::{conflict, invalid, io_error, unavailable};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct HookState {
    paused: bool,
    target_node: NodeId,
}

pub struct FsControlHooks {
    path: PathBuf,
    run_id: RunId,
    allowed_nodes: BTreeSet<NodeId>,
    bridge_ledger: Arc<Mutex<Ledger>>,
    decided_by: String,
    owner_preview: BTreeSet<String>,
    state: Mutex<HookState>,
}

impl FsControlHooks {
    pub fn open(
        root: impl AsRef<Path>,
        session_id: odin_domain::huginn::LiveSessionId,
        target_node: NodeId,
        allowed_nodes: BTreeSet<NodeId>,
        bridge_ledger: Arc<Mutex<Ledger>>,
        decided_by: String,
    ) -> Result<Self, LiveError> {
        if allowed_nodes.is_empty() || !allowed_nodes.contains(&target_node) {
            return Err(invalid("control hooks require the current allowed node"));
        }
        fs::create_dir_all(root.as_ref()).map_err(io_error)?;
        let path = root.as_ref().join(format!("{session_id}.cbor"));
        let state = if path.try_exists().map_err(io_error)? {
            crate::live::ledger::decode_cbor(&fs::read(&path).map_err(io_error)?)
                .map_err(|_| unavailable("control_hook_state"))?
        } else {
            HookState {
                paused: false,
                target_node,
            }
        };
        if !allowed_nodes.contains(&state.target_node) {
            return Err(invalid("durable control hook targets a disabled node"));
        }
        Ok(Self {
            path,
            run_id: RunId::new(format!("run:live:{session_id}"))
                .map_err(|_| invalid("live session could not be mapped to run identity"))?,
            allowed_nodes,
            bridge_ledger,
            decided_by,
            owner_preview: BTreeSet::new(),
            state: Mutex::new(state),
        })
    }

    pub fn with_owner_preview(mut self, ids: BTreeSet<String>) -> Self {
        self.owner_preview = ids;
        self
    }

    fn update(
        &self,
        change: impl FnOnce(&mut HookState) -> Result<(), LiveError>,
    ) -> Result<(), LiveError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| unavailable("control_hook_lock"))?;
        let mut candidate = state.clone();
        change(&mut candidate)?;
        store_hook_state(&self.path, &candidate)?;
        *state = candidate;
        Ok(())
    }
}

#[async_trait]
impl LiveControlHooks for FsControlHooks {
    async fn pause(&self) -> Result<(), LiveError> {
        self.update(|state| {
            state.paused = true;
            Ok(())
        })
    }

    async fn resume(&self) -> Result<(), LiveError> {
        self.update(|state| {
            state.paused = false;
            Ok(())
        })
    }

    async fn rehome(&self, target_node: &NodeId) -> Result<(), LiveError> {
        if !self.allowed_nodes.contains(target_node) {
            return Err(LiveError::Unauthorized);
        }
        self.update(|state| {
            state.target_node = target_node.clone();
            Ok(())
        })
    }

    async fn decide_approval(
        &self,
        approval_id: &ApprovalId,
        expected_revision: u64,
        decision: ApprovalDecision,
    ) -> Result<(), LiveError> {
        let expected = i64::try_from(expected_revision)
            .map_err(|_| invalid("approval revision does not fit the durable ledger"))?;
        let mut ledger = self
            .bridge_ledger
            .lock()
            .map_err(|_| unavailable("bridge_ledger_lock"))?;
        let current = ledger
            .approval(approval_id)
            .map_err(|_| unavailable("approval_ledger"))?
            .ok_or_else(|| LiveError::NotFound {
                object_kind: "approval".to_owned(),
                object_id: approval_id.to_string(),
            })?;
        if current.scope.target_kind != "run" || current.scope.target_id != self.run_id.as_str() {
            return Err(LiveError::Unauthorized);
        }
        let now = OffsetDateTime::now_utc();
        if current.revision != expected || current.status != ApprovalStatus::Requested {
            return Err(conflict("approval revision or state changed"));
        }
        if current.expires_at <= now {
            return Err(conflict("approval has expired"));
        }
        let evidence = format!(
            "huginn:{}:{}:{}",
            self.decided_by, approval_id, expected_revision
        );
        let ledger_decision = match decision {
            ApprovalDecision::Approve => LedgerApprovalDecision::Approve {
                evidence_ref: Some(evidence.clone()),
            },
            ApprovalDecision::Reject => LedgerApprovalDecision::Deny {
                evidence_ref: evidence.clone(),
            },
        };
        let owner_preview = self
            .owner_preview
            .contains(current.scope.capability_id.as_str());
        if odin_ledger::approval::requires_owner_preview(&current.scope, owner_preview) {
            // Live control shows no exact effect preview: consent binds the
            // complete question the owner's conversation already delivered.
            let intake = odin_ledger::approval::DecisionIntake {
                consumer_id: "live-control".to_owned(),
                message_id: format!(
                    "decision-{}",
                    odin_domain::Digest::hash(evidence.as_bytes())
                ),
            };
            return match odin_kernel::ApprovalGate::new(&mut ledger)
                .decide_owner(
                    approval_id,
                    expected,
                    ledger_decision,
                    &self.decided_by,
                    now,
                    &intake,
                    owner_preview,
                )
                .map_err(|_| unavailable("approval_ledger"))?
            {
                Some(
                    odin_kernel::DecisionOutcome::Approved(_)
                    | odin_kernel::DecisionOutcome::Denied(_),
                ) => Ok(()),
                Some(odin_kernel::DecisionOutcome::Redirect(
                    odin_kernel::ApprovalRedirect::PreviewRequired { .. },
                )) => Err(conflict(
                    "approval needs its complete question delivered to the owner first",
                )),
                Some(odin_kernel::DecisionOutcome::Redirect(_)) | None => {
                    Err(conflict("approval is no longer awaiting a decision"))
                }
            };
        }
        match ledger
            .decide_approval(
                approval_id,
                ledger_decision,
                &self.decided_by,
                now,
                expected,
            )
            .map_err(|_| unavailable("approval_ledger"))?
        {
            DecideApproval::Decided(_) => {}
            DecideApproval::NotFound => {
                return Err(LiveError::NotFound {
                    object_kind: "approval".to_owned(),
                    object_id: approval_id.to_string(),
                });
            }
            DecideApproval::NotRequested(_) | DecideApproval::PreviewRequired(_) => {
                return Err(conflict("approval is no longer awaiting a decision"));
            }
        }
        Ok(())
    }
}

fn store_hook_state(path: &Path, state: &HookState) -> Result<(), LiveError> {
    let encoded =
        crate::live::ledger::encode_cbor(state).map_err(|_| unavailable("control_hook_state"))?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("control hook path has no parent"))?;
    let temporary = parent.join(format!(".{}.tmp", Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).map_err(io_error)?;
    file.write_all(&encoded).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    fs::rename(&temporary, path).map_err(io_error)?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(io_error)
}

#[cfg(test)]
mod control_hook_tests {
    use super::*;
    use odin_ledger::approval::{ApprovalScope, NewApproval};

    fn request(
        ledger: &mut Ledger,
        target: &str,
        now: OffsetDateTime,
    ) -> odin_ledger::approval::Approval {
        ledger
            .request_approval(NewApproval {
                approval_id: ApprovalId::new("approval:control-scope").unwrap(),
                issuer: "test".to_owned(),
                scope: ApprovalScope {
                    target_kind: "run".to_owned(),
                    target_id: target.to_owned(),
                    capability_id: odin_domain::CapabilityId::new("test.effect").unwrap(),
                    arguments_digest: odin_domain::Digest::hash(b"bounded effect"),
                },
                requested_at: now,
                expires_at: now + time::Duration::hours(1),
            })
            .unwrap()
    }

    fn hooks(root: &Path, ledger: Arc<Mutex<Ledger>>) -> FsControlHooks {
        let session =
            odin_domain::huginn::LiveSessionId::parse("00000000-0000-4000-8000-000000000001")
                .unwrap();
        let node = NodeId::new("node.test").unwrap();
        FsControlHooks::open(
            root,
            session,
            node.clone(),
            BTreeSet::from([node]),
            ledger,
            "device:test".to_owned(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn another_sessions_approval_cannot_be_decided() {
        let root = tempfile::tempdir().unwrap();
        let ledger = Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()));
        let approval = request(
            &mut ledger.lock().unwrap(),
            "run:live:00000000-0000-4000-8000-000000000002",
            OffsetDateTime::now_utc(),
        );
        let control = hooks(root.path(), ledger.clone());
        assert!(matches!(
            control
                .decide_approval(&approval.approval_id, 1, ApprovalDecision::Approve)
                .await,
            Err(LiveError::Unauthorized)
        ));
        assert_eq!(
            ledger
                .lock()
                .unwrap()
                .approval(&approval.approval_id)
                .unwrap(),
            Some(approval)
        );
    }

    #[tokio::test]
    async fn reopened_control_reproves_terminal_approval() {
        let root = tempfile::tempdir().unwrap();
        let ledger = Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()));
        let approval = request(
            &mut ledger.lock().unwrap(),
            "run:live:00000000-0000-4000-8000-000000000001",
            OffsetDateTime::now_utc(),
        );
        let control = hooks(root.path(), ledger.clone());
        control
            .decide_approval(&approval.approval_id, 1, ApprovalDecision::Approve)
            .await
            .unwrap();
        // A new command cannot reuse an already-settled request to trigger
        // another continuation. Actual command retries are journal-deduped.
        assert!(control
            .decide_approval(&approval.approval_id, 1, ApprovalDecision::Approve)
            .await
            .is_err());
        control.pause().await.unwrap();
        ledger
            .lock()
            .unwrap()
            .expire_approval(
                &approval.approval_id,
                approval.expires_at,
                approval.revision + 1,
            )
            .unwrap();
        drop(control);
        let reopened = hooks(root.path(), ledger.clone());
        assert!(reopened
            .decide_approval(&approval.approval_id, 1, ApprovalDecision::Approve)
            .await
            .is_err());
        assert_eq!(
            ledger
                .lock()
                .unwrap()
                .approval(&approval.approval_id)
                .unwrap()
                .unwrap()
                .status,
            ApprovalStatus::Expired
        );
    }

    #[tokio::test]
    async fn requested_but_expired_approval_cannot_start_a_continuation() {
        let root = tempfile::tempdir().unwrap();
        let ledger = Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()));
        let approval = request(
            &mut ledger.lock().unwrap(),
            "run:live:00000000-0000-4000-8000-000000000001",
            OffsetDateTime::UNIX_EPOCH,
        );
        let control = hooks(root.path(), ledger.clone());
        assert!(control
            .decide_approval(&approval.approval_id, 1, ApprovalDecision::Approve)
            .await
            .is_err());
        assert_eq!(
            ledger
                .lock()
                .unwrap()
                .approval(&approval.approval_id)
                .unwrap(),
            Some(approval)
        );
    }
}
