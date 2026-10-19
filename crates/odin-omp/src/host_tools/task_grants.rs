//! Exact consequential-effect batches authorized by one durable owner decision.
//! Prose and legacy capability lists never confer authority. Every coverage
//! rechecks the consumed approval and reserves one exact batch entry.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use odin_domain::{ApprovalId, ApprovalStatus, CapabilityId, CommandId, SessionId};
use odin_kernel::{arguments_digest, CapabilityContract, ToolInvocation};
use odin_ledger::Ledger;
use odin_registry::schema::BatchLimitsToml;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::delegation::ParentSessionLink;

/// One exact effect, excluding the dispatch-owned approval selector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedEffect {
    pub capability: CapabilityId,
    pub arguments: Value,
}

/// The capability whose owner approval mints a grant.
pub const TASK_GRANT_CAPABILITY: &str = "task.grant";

/// The caller's admitted grant-batch policy: exactly one positive `batch`
/// declaration, and every capability marked `batchable`.
pub fn admitted_batch_policy(
    contracts: &BTreeMap<CapabilityId, CapabilityContract>,
) -> Result<(BatchLimitsToml, BTreeSet<CapabilityId>), String> {
    let mut declared = contracts.values().filter_map(|contract| contract.batch);
    let Some(limits) = declared.next() else {
        return Err(format!(
            "{TASK_GRANT_CAPABILITY}: no capability declares grant batch limits"
        ));
    };
    if declared.next().is_some() {
        return Err(format!(
            "{TASK_GRANT_CAPABILITY}: more than one capability declares grant batch limits"
        ));
    }
    if limits.max_effects == 0 || limits.max_minutes == 0 || limits.max_uses == 0 {
        return Err(format!(
            "{TASK_GRANT_CAPABILITY}: grant batch limits must be positive"
        ));
    }
    let batchable = contracts
        .iter()
        .filter(|(_, contract)| contract.batchable)
        .map(|(id, _)| id.clone())
        .collect();
    Ok((limits, batchable))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TaskGrant {
    /// The consumed owner approval that minted the grant.
    pub id: String,
    /// The plan in the owner's terms, as he approved it.
    pub task: String,
    /// The session that asked for the grant; it and its delegated children
    /// are covered.
    pub session: SessionId,
    pub capabilities: BTreeSet<CapabilityId>,
    pub expires_at_ms: u64,
    pub max_uses: u32,
    pub used: u32,
    #[serde(default)]
    pub revoked: bool,
    /// Exact consumed request; absent on historical, unproven rows.
    #[serde(default)]
    pub request: Option<Value>,
    /// Each batch entry is reserved once; identical commands may retry.
    #[serde(default)]
    pub reservations: Vec<Option<CommandId>>,
}

impl TaskGrant {
    /// Reconstructs authority from a consumed owner decision that still
    /// honors the caller's admitted batch policy. A consumed grant that
    /// violates that policy is `Ok(None)`, not a derivation failure.
    pub fn from_approval(
        ledger: &Ledger,
        id: &ApprovalId,
        session: SessionId,
        limits: BatchLimitsToml,
        batchable: &BTreeSet<CapabilityId>,
    ) -> Result<Option<Self>, String> {
        let Some(approval) = ledger.approval(id).map_err(|error| error.to_string())? else {
            return Ok(None);
        };
        if approval.status != ApprovalStatus::Consumed
            || approval.scope.capability_id.as_str() != TASK_GRANT_CAPABILITY
            || !ledger
                .approval_has_owner_decision(&approval, true)
                .map_err(|error| error.to_string())?
        {
            return Ok(None);
        }
        let Some(command_id) = &approval.consumed_by_command_id else {
            return Ok(None);
        };
        let Some(command) = ledger
            .command(command_id)
            .map_err(|error| error.to_string())?
        else {
            return Ok(None);
        };
        if command.capability_id != approval.scope.capability_id
            || command.target_kind != approval.scope.target_kind
            || command.target_id != approval.scope.target_id
            || command.approval_id.as_ref() != Some(id)
            || command.arguments.get("approvalId").and_then(Value::as_str) != Some(id.as_str())
            || arguments_digest(&command.arguments) != approval.scope.arguments_digest
        {
            return Ok(None);
        }
        let request = command.arguments;
        let effects: Vec<PlannedEffect> = serde_json::from_value(request["effects"].clone())
            .map_err(|error| error.to_string())?;
        let max_minutes = u64::from(limits.max_minutes);
        let max_uses_limit = u64::from(limits.max_uses);
        let Some(minutes) = request["minutes"]
            .as_u64()
            .filter(|value| (1..=max_minutes).contains(value))
        else {
            return Ok(None);
        };
        let Some(max_uses) = request["max_uses"]
            .as_u64()
            .filter(|value| (1..=max_uses_limit).contains(value))
        else {
            return Ok(None);
        };
        let Some(decided_at) = approval.decided_at else {
            return Ok(None);
        };
        let decided_ms = u64::try_from(decided_at.unix_timestamp_nanos() / 1_000_000)
            .map_err(|error| error.to_string())?;
        if effects.is_empty()
            || effects.len() > usize::from(limits.max_effects)
            || effects.iter().any(|effect| {
                !batchable.contains(&effect.capability)
                    || !effect.arguments.is_object()
                    || effect.arguments.get("approvalId").is_some()
            })
        {
            return Ok(None);
        }
        Ok(Some(Self {
            id: id.to_string(),
            task: request["task"].as_str().unwrap_or_default().to_owned(),
            session,
            capabilities: effects
                .iter()
                .map(|effect| effect.capability.clone())
                .collect(),
            expires_at_ms: decided_ms.saturating_add(minutes * 60_000),
            max_uses: u32::try_from(max_uses).map_err(|error| error.to_string())?,
            used: 0,
            revoked: false,
            reservations: vec![None; effects.len()],
            request: Some(request),
        }))
    }

    fn live(&self, now_ms: u64) -> bool {
        !self.revoked && now_ms < self.expires_at_ms && self.used < self.max_uses
    }
}

/// File-backed durable grant ledger (atomic replace under one lock).
pub struct TaskGrantStore {
    path: PathBuf,
    lock: Mutex<()>,
}

impl TaskGrantStore {
    pub fn open(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Mutex::new(()),
        }
    }

    fn load(&self) -> Result<Vec<TaskGrant>, String> {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| format!("task grant ledger is unreadable: {error}")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(error) => Err(format!("task grant ledger is unreadable: {error}")),
        }
    }

    fn update<T>(
        &self,
        now_ms: u64,
        change: impl FnOnce(&mut Vec<TaskGrant>) -> Result<T, String>,
    ) -> Result<T, String> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| "task grant ledger lock poisoned".to_owned())?;
        let mut grants = self.load()?;
        let value = change(&mut grants)?;
        // Dead grants are kept a day for audit, then dropped.
        grants.retain(|grant| now_ms < grant.expires_at_ms.saturating_add(86_400_000));
        let bytes = serde_json::to_vec_pretty(&grants).map_err(|error| error.to_string())?;
        let temporary = self.path.with_extension("json.tmp");
        let write = || -> std::io::Result<()> {
            use std::io::Write as _;
            let parent = self
                .path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            std::fs::create_dir_all(parent)?;
            let directory = std::fs::File::open(parent)?;
            let mut file = std::fs::File::create(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(&temporary, &self.path)?;
            // The replacement name is authority too; file sync alone does
            // not make the rename durable. A failed sync grants no success.
            directory.sync_all()
        };
        write().map_err(|error| format!("task grant ledger write failed: {error}"))?;
        Ok(value)
    }

    /// Records the grant minted by one consumed owner approval. Recording
    /// the same approval twice keeps the first row.
    pub fn record(&self, grant: TaskGrant, now_ms: u64) -> Result<TaskGrant, String> {
        self.update(now_ms, |grants| {
            if let Some(existing) = grants.iter().find(|row| row.id == grant.id) {
                return Ok(existing.clone());
            }
            grants.push(grant.clone());
            Ok(grant)
        })
    }

    /// Reserves an exact effect for this command, checking durable owner consent
    /// even when revalidating an already-minted grant-derived approval.
    #[allow(clippy::too_many_arguments)]
    pub fn cover(
        &self,
        invocation: &ToolInvocation,
        session: &SessionId,
        parent: Option<&ParentSessionLink>,
        ledger: &Ledger,
        now_ms: u64,
        limits: BatchLimitsToml,
        batchable: &BTreeSet<CapabilityId>,
    ) -> Result<Option<String>, String> {
        // A cancelled selector is still part of this command's immutable
        // journal identity. Re-reserving it would mint a different selector,
        // conflict at journaling, and strand the otherwise reusable entry.
        let cancelled = ledger
            .command(&invocation.command_id)
            .map_err(|error| error.to_string())?
            .and_then(|command| command.approval_id)
            .map(|approval_id| ledger.approval(&approval_id))
            .transpose()
            .map_err(|error| error.to_string())?
            .flatten()
            .is_some_and(|approval| approval.status == ApprovalStatus::Cancelled);
        if cancelled {
            return Err(
                "this command's approval was cancelled before execution; use a fresh request"
                    .to_owned(),
            );
        }
        let mut arguments = invocation.arguments.clone();
        if let Some(object) = arguments.as_object_mut() {
            object.remove("approvalId");
        }
        let selected = invocation
            .approval_id
            .as_ref()
            .map(|id| ledger.approval(id))
            .transpose()
            .map_err(|error| error.to_string())?
            .flatten()
            .and_then(|approval| approval.decided_by)
            .and_then(|actor| actor.strip_prefix("grant:").map(str::to_owned));
        self.update(now_ms, |grants| {
            for grant in grants {
                if grant.revoked || grant.request.is_none() {
                    continue;
                }
                if selected.as_deref().is_some_and(|id| id != grant.id) {
                    continue;
                }
                let id = ApprovalId::new(grant.id.clone()).map_err(|error| error.to_string())?;
                let Some(proven) = TaskGrant::from_approval(
                    ledger,
                    &id,
                    grant.session.clone(),
                    limits,
                    batchable,
                )?
                else {
                    continue;
                };
                if grant.request != proven.request || now_ms >= proven.expires_at_ms {
                    continue;
                }
                let approval = ledger
                    .approval(&id)
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| "grant approval disappeared".to_owned())?;
                let direct = &grant.session == session
                    && approval.scope.target_kind == invocation.target.kind
                    && approval.scope.target_id == invocation.target.id;
                let delegated = parent.is_some_and(|link| {
                    link.session == grant.session
                        && approval.scope.target_kind == "run"
                        && approval.scope.target_id == link.run.as_str()
                });
                if !direct && !delegated {
                    continue;
                }
                let effects: Vec<PlannedEffect> = serde_json::from_value(
                    proven.request.as_ref().expect("proven request")["effects"].clone(),
                )
                .map_err(|error| error.to_string())?;
                if grant.reservations.len() != effects.len() {
                    continue;
                }
                let matching = |index: usize| {
                    effects[index].capability == invocation.capability_id
                        && effects[index].arguments == arguments
                };
                if grant
                    .reservations
                    .iter()
                    .enumerate()
                    .any(|(index, command)| {
                        command.as_ref() == Some(&invocation.command_id) && matching(index)
                    })
                {
                    return Ok(Some(grant.id.clone()));
                }
                if grant.reservations.iter().flatten().count() >= proven.max_uses as usize {
                    continue;
                }
                if let Some(index) = grant
                    .reservations
                    .iter()
                    .enumerate()
                    .position(|(index, command)| command.is_none() && matching(index))
                {
                    grant.reservations[index] = Some(invocation.command_id.clone());
                    grant.used = u32::try_from(grant.reservations.iter().flatten().count())
                        .map_err(|error| error.to_string())?;
                    return Ok(Some(grant.id.clone()));
                }
            }
            Ok(None)
        })
    }

    /// Returns a known-unspent entry only after invalidating its old approval.
    /// Callers hold the authority ledger before this store's lock, as for
    /// coverage. A failed reservation write never leaves stale authority usable.
    pub fn release(
        &self,
        invocation: &ToolInvocation,
        ledger: &mut Ledger,
        now_ms: u64,
    ) -> Result<bool, String> {
        let Some(id) = &invocation.approval_id else {
            return Ok(false);
        };
        let Some(approval) = ledger.approval(id).map_err(|error| error.to_string())? else {
            return Ok(false);
        };
        let Some(grant_id) = approval
            .decided_by
            .as_deref()
            .and_then(|actor| actor.strip_prefix("grant:"))
        else {
            return Ok(false);
        };
        if approval.status != ApprovalStatus::Approved
            || approval.consumed_by_command_id.is_some()
            || invocation.expected_revision != Some(approval.revision)
            || approval.scope.target_kind != invocation.target.kind
            || approval.scope.target_id != invocation.target.id
            || approval.scope.capability_id != invocation.capability_id
            || approval.scope.arguments_digest != invocation.arguments_digest
        {
            return Ok(false);
        }
        self.update(now_ms, |grants| {
            let Some(grant) = grants.iter_mut().find(|grant| grant.id == grant_id) else {
                return Ok(false);
            };
            let Some(slot) = grant
                .reservations
                .iter_mut()
                .find(|reserved| reserved.as_ref() == Some(&invocation.command_id))
            else {
                return Ok(false);
            };
            let now =
                time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(now_ms) * 1_000_000)
                    .map_err(|error| error.to_string())?;
            if !ledger
                .cancel_unconsumed_approval(id, now, approval.revision)
                .map_err(|error| error.to_string())?
            {
                return Ok(false);
            }
            *slot = None;
            grant.used = u32::try_from(grant.reservations.iter().flatten().count())
                .map_err(|error| error.to_string())?;
            Ok(true)
        })
    }

    /// Every grant still live for `session`.
    pub fn live_for(&self, session: &SessionId, now_ms: u64) -> Result<Vec<TaskGrant>, String> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| "task grant ledger lock poisoned".to_owned())?;
        Ok(self
            .load()?
            .into_iter()
            .filter(|grant| grant.live(now_ms) && &grant.session == session)
            .collect())
    }

    pub fn revoke(&self, id: &str, now_ms: u64) -> Result<bool, String> {
        self.update(now_ms, |grants| {
            Ok(grants
                .iter_mut()
                .find(|grant| grant.id == id && !grant.revoked)
                .map(|grant| grant.revoked = true)
                .is_some())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capability(id: &str) -> CapabilityId {
        CapabilityId::new(id).expect("capability")
    }

    fn session(id: &str) -> SessionId {
        SessionId::new(id).expect("session")
    }

    fn invocation(command: &str, arguments: Value) -> ToolInvocation {
        ToolInvocation {
            command_id: CommandId::new(command).unwrap(),
            capability_id: capability("email.send"),
            capability_version: 1,
            listing_digest: odin_domain::knowledge::CapabilityListingDigest::new(
                odin_domain::Digest::hash(b"listing"),
            ),
            arguments_digest: arguments_digest(&arguments),
            arguments,
            target: odin_kernel::InvocationTarget {
                kind: "run".to_owned(),
                id: "run:root".to_owned(),
            },
            executor_binding: None,
            expected_revision: None,
            plan_id: None,
            approval_id: None,
            resource: None,
        }
    }

    fn admitted() -> (BatchLimitsToml, BTreeSet<CapabilityId>) {
        (
            BatchLimitsToml {
                max_effects: 16,
                max_minutes: 1440,
                max_uses: 500,
            },
            BTreeSet::from([capability("email.send")]),
        )
    }

    fn cover_admitted(
        store: &TaskGrantStore,
        invocation: &ToolInvocation,
        session: &SessionId,
        ledger: &Ledger,
        now_ms: u64,
    ) -> Result<Option<String>, String> {
        let (limits, batchable) = admitted();
        store.cover(
            invocation, session, None, ledger, now_ms, limits, &batchable,
        )
    }

    fn approved_grant(ledger: &mut Ledger, max_uses: u32) -> TaskGrant {
        use odin_ledger::approval::{ApprovalDecision, ApprovalScope, DecisionIntake, NewApproval};
        let now = time::OffsetDateTime::UNIX_EPOCH;
        let id = ApprovalId::new("approval:batch").unwrap();
        let arguments = serde_json::json!({
            "task": "Send exact updates", "minutes": 1, "max_uses": max_uses,
            "effects": [
                {"capability": "email.send", "arguments": {"account": "test", "draft_id": "one"}},
                {"capability": "email.send", "arguments": {"account": "test", "draft_id": "two"}}
            ], "approvalId": id.to_string()
        });
        let scope = ApprovalScope {
            target_kind: "run".to_owned(),
            target_id: "run:root".to_owned(),
            capability_id: capability(TASK_GRANT_CAPABILITY),
            arguments_digest: arguments_digest(&arguments),
        };
        ledger
            .request_approval(NewApproval {
                approval_id: id.clone(),
                issuer: "coordinator".to_owned(),
                scope: scope.clone(),
                requested_at: now,
                expires_at: now + time::Duration::hours(1),
            })
            .unwrap();
        // The complete batch question as Hermes records its delivery.
        let payload = serde_json::json!({
            "approvalId": id.as_str(), "revision": 1, "capabilityId": TASK_GRANT_CAPABILITY,
            "argumentsDigest": scope.arguments_digest.to_string(), "session": scope.target_id,
            "completeSnapshot": true,
        });
        ledger
            .append_audit_event(odin_ledger::audit::NewAuditEvent {
                event_id: odin_domain::EventId::new("event:batch-delivery").unwrap(),
                kind: odin_ledger::approval::OWNER_PREVIEW_DELIVERY_KIND.to_owned(),
                actor: odin_domain::Actor::System {
                    name: "odin-hermes.runtime".to_owned(),
                },
                scope: odin_domain::Scope::default(),
                evidence: Vec::new(),
                payload: odin_ledger::audit::RedactedPayload::new(
                    payload,
                    odin_domain::Redaction::None,
                )
                .unwrap(),
                occurred_at: now,
            })
            .unwrap();
        ledger
            .decide_approval_consuming_intake(
                &id,
                ApprovalDecision::Approve {
                    evidence_ref: Some("delivery:event:batch-delivery".to_owned()),
                },
                "discord-owner:fixture",
                now,
                1,
                &DecisionIntake {
                    consumer_id: "discord-owner:fixture".to_owned(),
                    message_id: "message:owner".to_owned(),
                },
                true,
            )
            .unwrap();
        let command_id = CommandId::new("command:batch").unwrap();
        ledger
            .record_command(&odin_ledger::command::CommandSpec {
                id: command_id.clone(),
                idempotency_key: "batch".to_owned(),
                correlation_id: "batch".to_owned(),
                causation_id: None,
                issuer: "coordinator".to_owned(),
                approval_id: Some(id.clone()),
                target_kind: scope.target_kind.clone(),
                target_id: scope.target_id.clone(),
                capability_id: scope.capability_id.clone(),
                capability_version: 1,
                arguments_hash: scope.arguments_digest,
                arguments,
                expected_desired_revision: None,
                issued_at: now,
                expires_at: now + time::Duration::hours(1),
            })
            .unwrap();
        ledger
            .consume_approval(&id, &scope, &command_id, now, 2)
            .unwrap();
        let (limits, batchable) = admitted();
        TaskGrant::from_approval(ledger, &id, session("root"), limits, &batchable)
            .unwrap()
            .expect("owner batch")
    }

    #[test]
    fn owner_batch_reservations_survive_reopen_and_enforce_exact_effects_and_limits() {
        let dir = tempfile::tempdir().unwrap();
        let mut ledger = Ledger::open(dir.path().join("authority.sqlite3")).unwrap();
        let store = TaskGrantStore::open(dir.path().join("grants.json"));
        store.record(approved_grant(&mut ledger, 2), 0).unwrap();
        let root = session("root");
        let first = invocation(
            "send:one",
            serde_json::json!({"account": "test", "draft_id": "one"}),
        );
        let changed = invocation(
            "send:changed",
            serde_json::json!({"account": "other", "draft_id": "one"}),
        );
        assert_eq!(
            cover_admitted(&store, &changed, &root, &ledger, 10).unwrap(),
            None
        );
        assert_eq!(
            cover_admitted(&store, &first, &session("other"), &ledger, 10).unwrap(),
            None
        );
        assert!(cover_admitted(&store, &first, &root, &ledger, 10)
            .unwrap()
            .is_some());
        let reopened = TaskGrantStore::open(dir.path().join("grants.json"));
        let ledger = Ledger::open(dir.path().join("authority.sqlite3")).unwrap();
        assert!(cover_admitted(&reopened, &first, &root, &ledger, 20)
            .unwrap()
            .is_some());
        let duplicate = invocation("send:duplicate", first.arguments.clone());
        assert_eq!(
            cover_admitted(&reopened, &duplicate, &root, &ledger, 20).unwrap(),
            None
        );
        let second = invocation(
            "send:two",
            serde_json::json!({"account": "test", "draft_id": "two"}),
        );
        assert!(cover_admitted(&reopened, &second, &root, &ledger, 20)
            .unwrap()
            .is_some());
        assert_eq!(reopened.live_for(&root, 20).unwrap().len(), 0);
        assert_eq!(
            cover_admitted(&reopened, &first, &root, &ledger, 60_000).unwrap(),
            None
        );
        assert!(reopened.revoke("approval:batch", 20).unwrap());
        assert_eq!(
            cover_admitted(&reopened, &first, &root, &ledger, 20).unwrap(),
            None
        );
    }

    #[test]
    fn total_batch_cap_can_be_smaller_than_the_effect_count() {
        let dir = tempfile::tempdir().unwrap();
        let mut ledger = Ledger::open_in_memory().unwrap();
        let store = TaskGrantStore::open(dir.path().join("grants.json"));
        store.record(approved_grant(&mut ledger, 1), 0).unwrap();
        let first = invocation(
            "send:one",
            serde_json::json!({"account": "test", "draft_id": "one"}),
        );
        let second = invocation(
            "send:two",
            serde_json::json!({"account": "test", "draft_id": "two"}),
        );
        assert!(
            cover_admitted(&store, &first, &session("root"), &ledger, 10)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            cover_admitted(&store, &second, &session("root"), &ledger, 10).unwrap(),
            None
        );
    }

    #[test]
    fn persisted_unproven_grant_cannot_decide_a_consequential_call() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("grants.json");
        let root = session("root");
        let send = capability("email.send");
        TaskGrantStore::open(&path)
            .record(
                TaskGrant {
                    id: "approval:declaration-plan".to_owned(),
                    task: "Send the planned update".to_owned(),
                    session: root.clone(),
                    capabilities: [send.clone()].into(),
                    expires_at_ms: 1_000,
                    max_uses: 2,
                    used: 0,
                    revoked: false,
                    request: None,
                    reservations: Vec::new(),
                },
                0,
            )
            .expect("retain the legacy unproven grant");
        let reopened = TaskGrantStore::open(path);
        let ledger = Ledger::open_in_memory().unwrap();
        let call = invocation(
            "send:unproven",
            serde_json::json!({"account": "test", "draft_id": "draft"}),
        );
        assert_eq!(
            cover_admitted(&reopened, &call, &root, &ledger, 10).unwrap(),
            None
        );
    }

    #[test]
    fn replay_honors_the_callers_admitted_batch_policy() {
        let dir = tempfile::tempdir().unwrap();
        let mut ledger = Ledger::open(dir.path().join("authority.sqlite3")).unwrap();
        let grant = approved_grant(&mut ledger, 2);
        let id = ApprovalId::new("approval:batch").unwrap();
        let (limits, batchable) = admitted();
        assert!(
            TaskGrant::from_approval(&ledger, &id, session("root"), limits, &batchable)
                .unwrap()
                .is_some()
        );

        let over_effects = BatchLimitsToml {
            max_effects: 1,
            ..limits
        };
        assert!(
            TaskGrant::from_approval(&ledger, &id, session("root"), over_effects, &batchable)
                .unwrap()
                .is_none()
        );
        let under_uses = BatchLimitsToml {
            max_uses: 1,
            ..limits
        };
        assert!(
            TaskGrant::from_approval(&ledger, &id, session("root"), under_uses, &batchable)
                .unwrap()
                .is_none()
        );
        let foreign = BTreeSet::from([capability("browser.consequential")]);
        assert!(
            TaskGrant::from_approval(&ledger, &id, session("root"), limits, &foreign)
                .unwrap()
                .is_none()
        );

        let store = TaskGrantStore::open(dir.path().join("grants.json"));
        store.record(grant, 0).unwrap();
        let first = invocation(
            "send:policy",
            serde_json::json!({"account": "test", "draft_id": "one"}),
        );
        assert_eq!(
            store
                .cover(
                    &first,
                    &session("root"),
                    None,
                    &ledger,
                    10,
                    over_effects,
                    &batchable,
                )
                .unwrap(),
            None
        );
        assert!(store
            .cover(
                &first,
                &session("root"),
                None,
                &ledger,
                10,
                limits,
                &batchable,
            )
            .unwrap()
            .is_some());
    }
}
