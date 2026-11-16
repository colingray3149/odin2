//! Durable operator plan acceptance bound to the exact structural plan.
//!
//! Projection rebuilds preserve the `plan_acceptance` extension kind because acceptance has no other source table.
//!
//! A record binds the accepted run to the structural fingerprint of its plan
//! (objective plus ordered todo definitions; never mutable progress state)
//! and to the authenticated local operator that approved it. [`Ledger::plan_is_accepted`]
//! therefore answers a question about the present: a plan that merely exists
//! is never accepted, and any structural change silently voids the record
//! until a real operator re-approves. Inherited acceptance additionally pins
//! the parent's approval instance (its actor and acceptance time), so a child
//! stays valid only while the parent still holds that same approval; the
//! parent's to-do progress never voids it. Records written before the pin
//! existed fall back to the approved parent structure. Lineage is bounded and
//! cycle-free by construction.

use std::collections::BTreeSet;

use odin_domain::RunId;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Deserializer, Serialize};
use time::OffsetDateTime;

use crate::plan::{load_plan, plan_structure_fingerprint, stale_plan};
use crate::{decode_utc, encode_utc, Ledger, LedgerError, LedgerResult};

pub const PLAN_ACCEPTANCE_SCHEMA_VERSION: u16 = 1;

/// The `materialized_status` object kind that owns acceptance records.
pub const PLAN_ACCEPTANCE_OBJECT_KIND: &str = "plan_acceptance";

/// The maximum number of acceptance records in one lineage. Deeper or cyclic
/// lineages are rejected at write time and never validate at read time.
pub const MAX_LINEAGE_DEPTH: usize = 64;

const ACTOR_MAX_BYTES: usize = 128;
pub(crate) fn apply_root_plan_consent_in_tx(
    tx: &rusqlite::Transaction<'_>,
    approval: &crate::approval::Approval,
    actor: &str,
    now: OffsetDateTime,
) -> LedgerResult<()> {
    validate_actor(actor)?;
    let id = &approval.approval_id;
    let body: String = tx.query_row(
        "SELECT status_json FROM materialized_status WHERE object_kind = ?1 AND object_id = ?2",
        params![ROOT_CONSENT_KIND, id.to_string()],
        |row| row.get(0),
    )?;
    let mut record: RootPlanConsent = serde_json::from_str(&body)?;
    let mut bound = record.clone();
    bound.applied = false;
    let digest = odin_domain::Digest::hash(serde_json::to_string(&bound)?.as_bytes());
    if approval.scope.capability_id.as_str() != "plan.root-consent"
        || approval.scope.target_kind != "run"
        || approval.scope.target_id != record.run.as_str()
        || approval.scope.arguments_digest != digest
        || approval.issuer != record.seat
        || record.run.as_str() != format!("run:live:{}", record.session)
    {
        return Err(LedgerError::invalid_data(
            "root consent binding does not match its approval".to_owned(),
        ));
    }
    if record.applied {
        return Ok(());
    }
    let plan = load_plan(tx, &record.run)?
        .ok_or_else(|| LedgerError::invalid_data("reviewed root plan disappeared".to_owned()))?;
    if plan.revision != record.revision || plan.objective != record.objective {
        return Err(LedgerError::invalid_data(
            "the reviewed plan changed".to_owned(),
        ));
    }
    if acceptance_holds(tx, &record.run)? {
        return Err(LedgerError::invalid_data(
            "the root plan is already accepted".to_owned(),
        ));
    }
    write_acceptance(
        tx,
        &PlanAcceptance {
            run_id: record.run.clone(),
            plan_revision: plan.revision,
            fingerprint: plan_structure_fingerprint(&plan),
            actor: actor.to_owned(),
            accepted_at: now,
            parent: None,
        },
    )?;
    record.applied = true;
    tx.execute("UPDATE materialized_status SET status_json = ?1, revision = revision + 1, updated_at = ?2 WHERE object_kind = ?3 AND object_id = ?4", params![serde_json::to_string(&record)?, encode_utc(now)?, ROOT_CONSENT_KIND, id.to_string()])?;
    Ok(())
}

const ROOT_CONSENT_KIND: &str = "root_plan_consent";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RootPlanConsent {
    pub run: RunId,
    pub session: odin_domain::SessionId,
    pub seat: String,
    pub revision: i64,
    pub objective: String,
    pub applied: bool,
}

const ROOT_CONTINUATION_KIND: &str = "root_plan_continuation";

/// A decision's durable continuation intent, independent of approval expiry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RootPlanContinuation {
    pub approved: bool,
    pub epoch: Option<u64>,
    pub admitted: bool,
}

pub(crate) fn queue_root_plan_continuation_in_tx(
    tx: &rusqlite::Transaction<'_>,
    approval: &crate::approval::Approval,
    now: OffsetDateTime,
) -> LedgerResult<()> {
    let approved = match approval.status {
        odin_domain::ApprovalStatus::Approved => true,
        odin_domain::ApprovalStatus::Denied => false,
        _ => {
            return Err(LedgerError::invalid_data(
                "root consent has no settled decision".into(),
            ))
        }
    };
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM materialized_status WHERE object_kind = ?1 AND object_id = ?2)",
        params![ROOT_CONSENT_KIND, approval.approval_id.as_str()], |row| row.get(0),
    )?;
    if !exists {
        return Err(LedgerError::invalid_data(
            "root consent record is missing".into(),
        ));
    }
    let continuation = RootPlanContinuation {
        approved,
        epoch: None,
        admitted: false,
    };
    tx.execute(
        "INSERT INTO materialized_status (object_kind, object_id, revision, status_json, source_event_id, updated_at) VALUES (?1, ?2, 1, ?3, ?4, ?5)",
        params![ROOT_CONTINUATION_KIND, approval.approval_id.as_str(), serde_json::to_string(&continuation)?, format!("source:root-continuation:{}", approval.approval_id), encode_utc(now)?],
    )?;
    Ok(())
}

fn read_root_continuation(
    connection: &Connection,
    id: &odin_domain::ApprovalId,
) -> LedgerResult<RootPlanContinuation> {
    let body: String = connection.query_row(
        "SELECT status_json FROM materialized_status WHERE object_kind = ?1 AND object_id = ?2",
        params![ROOT_CONTINUATION_KIND, id.as_str()],
        |row| row.get(0),
    )?;
    Ok(serde_json::from_str(&body)?)
}

fn write_root_continuation(
    connection: &Connection,
    id: &odin_domain::ApprovalId,
    state: &RootPlanContinuation,
    now: OffsetDateTime,
) -> LedgerResult<()> {
    connection.execute(
        "UPDATE materialized_status SET status_json = ?1, revision = revision + 1, updated_at = ?2 WHERE object_kind = ?3 AND object_id = ?4",
        params![serde_json::to_string(state)?, encode_utc(now)?, ROOT_CONTINUATION_KIND, id.as_str()],
    )?;
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanAcceptance {
    pub run_id: RunId,
    /// The plan revision observed when the operator approved; informational,
    /// because progress advances the revision without changing the structure.
    pub plan_revision: i64,
    pub fingerprint: String,
    /// The authenticated local operator identity, e.g. `device:<uuid>` or
    /// `inherit:<parent run>`.
    pub actor: String,
    pub accepted_at: OffsetDateTime,
    pub parent: Option<InheritedParent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InheritedParent {
    pub run_id: RunId,
    pub fingerprint: String,
    /// The parent's approval instance; `None` on records that predate it.
    pub approval: Option<ParentApproval>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParentApproval {
    pub actor: String,
    pub accepted_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanAcceptanceWire {
    pub schema_version: u16,
    pub run_id: RunId,
    pub plan_revision: i64,
    pub fingerprint: String,
    pub actor: String,
    pub accepted_at: String,
    pub parent: Option<ParentWire>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParentWire {
    pub run_id: RunId,
    pub fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_at: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlanAcceptanceWireParts {
    schema_version: u16,
    run_id: RunId,
    plan_revision: i64,
    fingerprint: String,
    actor: String,
    accepted_at: String,
    parent: Option<ParentWire>,
}

impl<'de> Deserialize<'de> for PlanAcceptanceWire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let parts = PlanAcceptanceWireParts::deserialize(deserializer)?;
        if parts.schema_version != PLAN_ACCEPTANCE_SCHEMA_VERSION {
            return Err(serde::de::Error::custom(format!(
                "unsupported plan acceptance schema version {}",
                parts.schema_version
            )));
        }
        validate_plan_revision(parts.plan_revision).map_err(serde::de::Error::custom)?;
        validate_fingerprint(&parts.fingerprint).map_err(serde::de::Error::custom)?;
        validate_actor(&parts.actor).map_err(serde::de::Error::custom)?;
        decode_utc(&parts.accepted_at).map_err(serde::de::Error::custom)?;
        if let Some(parent) = &parts.parent {
            validate_parent(parent).map_err(serde::de::Error::custom)?;
        }
        Ok(Self {
            schema_version: parts.schema_version,
            run_id: parts.run_id,
            plan_revision: parts.plan_revision,
            fingerprint: parts.fingerprint,
            actor: parts.actor,
            accepted_at: parts.accepted_at,
            parent: parts.parent,
        })
    }
}

impl TryFrom<&PlanAcceptance> for PlanAcceptanceWire {
    type Error = LedgerError;

    fn try_from(record: &PlanAcceptance) -> LedgerResult<Self> {
        validate_plan_revision(record.plan_revision)?;
        validate_fingerprint(&record.fingerprint)?;
        validate_actor(&record.actor)?;
        if let Some(parent) = &record.parent {
            validate_fingerprint(&parent.fingerprint)?;
        }
        Ok(Self {
            schema_version: PLAN_ACCEPTANCE_SCHEMA_VERSION,
            run_id: record.run_id.clone(),
            plan_revision: record.plan_revision,
            fingerprint: record.fingerprint.clone(),
            actor: record.actor.clone(),
            accepted_at: encode_utc(record.accepted_at)?,
            parent: record
                .parent
                .as_ref()
                .map(|parent| -> LedgerResult<ParentWire> {
                    let (actor, accepted_at) = match &parent.approval {
                        Some(approval) => {
                            validate_actor(&approval.actor)?;
                            (
                                Some(approval.actor.clone()),
                                Some(encode_utc(approval.accepted_at)?),
                            )
                        }
                        None => (None, None),
                    };
                    Ok(ParentWire {
                        run_id: parent.run_id.clone(),
                        fingerprint: parent.fingerprint.clone(),
                        actor,
                        accepted_at,
                    })
                })
                .transpose()?,
        })
    }
}

impl PlanAcceptanceWire {
    pub fn into_acceptance(self) -> LedgerResult<PlanAcceptance> {
        if self.schema_version != PLAN_ACCEPTANCE_SCHEMA_VERSION {
            return Err(LedgerError::invalid_data(format!(
                "unsupported plan acceptance schema version {}",
                self.schema_version
            )));
        }
        validate_plan_revision(self.plan_revision)?;
        validate_fingerprint(&self.fingerprint)?;
        validate_actor(&self.actor)?;
        if let Some(parent) = &self.parent {
            validate_parent(parent)?;
        }
        Ok(PlanAcceptance {
            run_id: self.run_id,
            plan_revision: self.plan_revision,
            fingerprint: self.fingerprint,
            actor: self.actor,
            accepted_at: decode_utc(&self.accepted_at)?,
            parent: self
                .parent
                .map(|parent| -> LedgerResult<InheritedParent> {
                    let approval = match (parent.actor, parent.accepted_at) {
                        (Some(actor), Some(accepted_at)) => Some(ParentApproval {
                            actor,
                            accepted_at: decode_utc(&accepted_at)?,
                        }),
                        _ => None,
                    };
                    Ok(InheritedParent {
                        run_id: parent.run_id,
                        fingerprint: parent.fingerprint,
                        approval,
                    })
                })
                .transpose()?,
        })
    }
}

fn validate_parent(parent: &ParentWire) -> LedgerResult<()> {
    validate_fingerprint(&parent.fingerprint)?;
    match (&parent.actor, &parent.accepted_at) {
        (Some(actor), Some(accepted_at)) => {
            validate_actor(actor)?;
            decode_utc(accepted_at)?;
            Ok(())
        }
        (None, None) => Ok(()),
        _ => Err(LedgerError::invalid_data(
            "an inherited parent pin names both its approval actor and time, or neither".into(),
        )),
    }
}

fn validate_fingerprint(value: &str) -> LedgerResult<()> {
    odin_domain::Digest::parse(value).map_err(|error| {
        LedgerError::invalid_data_caused_by(
            format!("acceptance fingerprint {value:?} is not a canonical BLAKE3 digest"),
            error,
        )
    })?;
    Ok(())
}

fn validate_actor(actor: &str) -> LedgerResult<()> {
    let bytes = actor.as_bytes();
    let well_formed = !bytes.is_empty()
        && bytes.len() <= ACTOR_MAX_BYTES
        && bytes
            .iter()
            .copied()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'));
    if !well_formed {
        return Err(LedgerError::invalid_data(
            "acceptance actor must be a bounded identifier-like operator identity".into(),
        ));
    }
    Ok(())
}

fn validate_plan_revision(revision: i64) -> LedgerResult<()> {
    if revision < 1 {
        return Err(LedgerError::invalid_data(
            "acceptance plan revision must be positive".into(),
        ));
    }
    Ok(())
}

impl Ledger {
    /// Journals a root plan question and its exact immutable contents together.
    pub fn request_root_plan_consent(
        &mut self,
        run: &RunId,
        session: &odin_domain::SessionId,
        seat: &str,
        revision: i64,
        objective: &str,
        now: OffsetDateTime,
    ) -> LedgerResult<odin_domain::ApprovalId> {
        let record = RootPlanConsent {
            run: run.clone(),
            session: session.clone(),
            seat: seat.to_owned(),
            revision,
            objective: objective.to_owned(),
            applied: false,
        };
        if run.as_str() != format!("run:live:{session}") {
            return Err(LedgerError::invalid_data(
                "root consent run does not match session".to_owned(),
            ));
        }
        let body = serde_json::to_string(&record)?;
        let digest = odin_domain::Digest::hash(body.as_bytes());
        let base_id = format!("approval:root-plan:{digest}");
        self.with_tx(|tx| {
            let plan = load_plan(tx, run)?.ok_or_else(|| LedgerError::NotFound { kind: "plan", id: run.to_string() })?;
            if plan.revision != revision || plan.objective != objective {
                return Err(LedgerError::invalid_data("the root plan changed before consent was requested".to_owned()));
            }
            if acceptance_holds(tx, run)? {
                return Err(LedgerError::invalid_data("the root plan is already accepted".to_owned()));
            }
            // Preserve settled requests and their delivery evidence. A fresh
            // question gets a distinct identity while concurrent/repeated
            // requests for an open question deduplicate under this transaction.
            let mut sequence = 0_u64;
            let id = loop {
                let value = if sequence == 0 { base_id.clone() } else { format!("{base_id}:{sequence}") };
                let candidate = odin_domain::ApprovalId::new(value)
                    .map_err(|error| LedgerError::invalid_data(error.to_string()))?;
                let Some(existing) = crate::approval::load_approval(tx, &candidate)? else { break candidate; };
                if existing.scope.target_kind != "run"
                    || existing.scope.target_id != run.as_str()
                    || existing.scope.capability_id.as_str() != "plan.root-consent"
                    || existing.scope.arguments_digest != digest
                    || existing.issuer != seat
                {
                    return Err(LedgerError::invalid_data("root consent identity collision".to_owned()));
                }
                if existing.status == odin_domain::ApprovalStatus::Requested && now < existing.expires_at {
                    return Ok(candidate);
                }
                if existing.status == odin_domain::ApprovalStatus::Requested {
                    tx.execute("UPDATE approvals SET status = 'expired', revision = revision + 1 WHERE approval_id = ?1 AND status = 'requested'", [candidate.as_str()])?;
                    let expired = crate::approval::load_approval(tx, &candidate)?.ok_or_else(|| LedgerError::invalid_data("expired root consent disappeared".to_owned()))?;
                    crate::approval_feed::journal_approval_change(tx, &expired, now)?;
                }
                sequence = sequence.checked_add(1).ok_or_else(|| LedgerError::invalid_data("root consent request sequence exhausted".to_owned()))?;
            };
            let request = crate::approval::NewApproval {
                approval_id: id.clone(), issuer: seat.to_owned(),
                scope: crate::approval::ApprovalScope {
                    target_kind: "run".to_owned(), target_id: run.to_string(),
                    capability_id: odin_domain::CapabilityId::new("plan.root-consent").map_err(|error| LedgerError::invalid_data(error.to_string()))?,
                    arguments_digest: digest,
                }, requested_at: now, expires_at: now + time::Duration::hours(1),
            };
            crate::approval::insert_requested(tx, &request)?;
            tx.execute("INSERT INTO materialized_status (object_kind, object_id, revision, status_json, source_event_id, updated_at) VALUES (?1, ?2, 1, ?3, ?4, ?5)",
                params![ROOT_CONSENT_KIND, id.to_string(), body, format!("source:{id}"), encode_utc(now)?])?;
            Ok(id.clone())
        })
    }

    pub fn root_plan_consent(
        &self,
        id: &odin_domain::ApprovalId,
    ) -> LedgerResult<Option<RootPlanConsent>> {
        let body: Option<String> = self.connection().query_row(
            "SELECT status_json FROM materialized_status WHERE object_kind = ?1 AND object_id = ?2",
            params![ROOT_CONSENT_KIND, id.to_string()], |row| row.get(0),
        ).optional()?;
        body.map(|body| serde_json::from_str(&body).map_err(Into::into))
            .transpose()
    }

    pub fn root_plan_consents(
        &self,
    ) -> LedgerResult<Vec<(odin_domain::ApprovalId, RootPlanConsent)>> {
        let mut statement = self.connection().prepare("SELECT object_id, status_json FROM materialized_status WHERE object_kind = ?1 ORDER BY object_id")?;
        let mut rows = statement.query([ROOT_CONSENT_KIND])?;
        let mut result = Vec::new();
        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            let body: String = row.get(1)?;
            let id = odin_domain::ApprovalId::new(id)
                .map_err(|error| LedgerError::invalid_data(error.to_string()))?;
            result.push((id, serde_json::from_str(&body)?));
        }
        Ok(result)
    }

    pub fn pending_root_plan_consents(&self) -> LedgerResult<Vec<odin_domain::ApprovalId>> {
        let mut pending = Vec::new();
        for (id, _) in self.root_plan_consents()? {
            if self
                .approval(&id)?
                .is_some_and(|row| row.status == odin_domain::ApprovalStatus::Requested)
            {
                pending.push(id);
            }
        }
        Ok(pending)
    }

    /// Settled root decisions whose continuation has not been admitted.
    pub fn pending_root_plan_continuations(
        &self,
    ) -> LedgerResult<
        Vec<(
            odin_domain::ApprovalId,
            RootPlanConsent,
            RootPlanContinuation,
        )>,
    > {
        let mut statement = self.connection().prepare(
            "SELECT c.object_id, c.status_json, r.status_json FROM materialized_status c JOIN materialized_status r ON r.object_kind = ?1 AND r.object_id = c.object_id WHERE c.object_kind = ?2 ORDER BY c.object_id"
        )?;
        let mut rows = statement.query(params![ROOT_CONSENT_KIND, ROOT_CONTINUATION_KIND])?;
        let mut pending = Vec::new();
        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            let continuation: RootPlanContinuation =
                serde_json::from_str(&row.get::<_, String>(1)?)?;
            if !continuation.admitted {
                let consent = serde_json::from_str(&row.get::<_, String>(2)?)?;
                let id = odin_domain::ApprovalId::new(id)
                    .map_err(|error| LedgerError::invalid_data(error.to_string()))?;
                pending.push((id, consent, continuation));
            }
        }
        Ok(pending)
    }

    /// Freeze the session epoch used for a deterministic continuation command.
    pub fn claim_root_plan_continuation(
        &mut self,
        id: &odin_domain::ApprovalId,
        epoch: u64,
        now: OffsetDateTime,
    ) -> LedgerResult<u64> {
        self.with_tx(|tx| {
            let mut state = read_root_continuation(tx, id)?;
            if state.admitted {
                return Err(LedgerError::invalid_data(
                    "root continuation already admitted".into(),
                ));
            }
            if let Some(existing) = state.epoch {
                return Ok(existing);
            }
            state.epoch = Some(epoch);
            write_root_continuation(tx, id, &state, now)?;
            Ok(epoch)
        })
    }

    /// Mark a frozen command as admitted; repeated admission is idempotent.
    pub fn mark_root_plan_continuation_admitted(
        &mut self,
        id: &odin_domain::ApprovalId,
        epoch: u64,
        now: OffsetDateTime,
    ) -> LedgerResult<()> {
        self.with_tx(|tx| {
            let mut state = read_root_continuation(tx, id)?;
            if state.epoch != Some(epoch) {
                return Err(LedgerError::invalid_data(
                    "root continuation epoch mismatch".into(),
                ));
            }
            if !state.admitted {
                state.admitted = true;
                write_root_continuation(tx, id, &state, now)?;
            }
            Ok(())
        })
    }

    /// Clear a claim only after the caller proves its command was not admitted.
    pub fn reset_root_plan_continuation_claim(
        &mut self,
        id: &odin_domain::ApprovalId,
        epoch: u64,
        now: OffsetDateTime,
    ) -> LedgerResult<()> {
        self.with_tx(|tx| {
            let mut state = read_root_continuation(tx, id)?;
            if state.admitted || state.epoch != Some(epoch) {
                return Err(LedgerError::invalid_data(
                    "root continuation claim changed".into(),
                ));
            }
            state.epoch = None;
            write_root_continuation(tx, id, &state, now)
        })
    }

    /// Applies witnessed consent at most once, atomically checking the reviewed plan.
    pub fn apply_root_plan_consent(
        &mut self,
        id: &odin_domain::ApprovalId,
        actor: &str,
        now: OffsetDateTime,
    ) -> LedgerResult<()> {
        validate_actor(actor)?;
        let approval = self.approval(id)?.ok_or_else(|| {
            LedgerError::invalid_data("root consent approval is missing".to_owned())
        })?;
        if approval.status != odin_domain::ApprovalStatus::Approved
            || approval.decided_by.as_deref() != Some(actor)
            || !self.approval_has_owner_decision(&approval, true)?
        {
            return Err(LedgerError::invalid_data(
                "root consent lacks a witnessed owner approval".to_owned(),
            ));
        }
        self.with_tx(|tx| {
            let current = crate::approval::load_approval(tx, id)?.ok_or_else(|| {
                LedgerError::invalid_data("root consent approval is missing".to_owned())
            })?;
            if current != approval {
                return Err(LedgerError::invalid_data(
                    "root consent approval changed".to_owned(),
                ));
            }
            apply_root_plan_consent_in_tx(tx, &current, actor, now)
        })
    }

    /// Reads the acceptance record of one run's plan, if any. The record is a
    /// fact about the past; only [`Ledger::plan_is_accepted`] decides whether
    /// it still holds for the current plan structure.
    pub fn plan_acceptance(&self, run_id: &RunId) -> LedgerResult<Option<PlanAcceptance>> {
        read_acceptance_row(self.connection(), run_id)
    }

    /// Whether the run's plan is genuinely accepted right now: a durable
    /// acceptance record must exist and match the plan's current structural
    /// fingerprint and — for inherited acceptance — its approved parent
    /// structure must be unchanged and the parent's own acceptance must still
    /// hold. A plan that merely exists is never accepted.
    pub fn plan_is_accepted(&self, run_id: &RunId) -> LedgerResult<bool> {
        acceptance_holds(self.connection(), run_id)
    }

    /// A seat's own to-do list rewritten under the objective the operator accepted: the plan is
    /// replaced and, when its acceptance held and the objective is unchanged, the acceptance moves to
    /// the new list in the same transaction. A changed objective still needs real acceptance, except
    /// on an inherited record: a delegated child's objective was never reviewed, its authority is the
    /// parent's approval, so the record carries over with its parent pin intact.
    pub fn replace_own_todos(
        &mut self,
        run_id: &RunId,
        objective: &str,
        todos: &[crate::plan::TodoSpec],
        expected_revision: i64,
        now: OffsetDateTime,
    ) -> LedgerResult<crate::plan::Plan> {
        crate::plan::validate_replace_inputs(expected_revision, objective, todos)?;
        let timestamp = encode_utc(now)?;
        self.with_tx(|tx| {
            let carried = match (read_acceptance_row(tx, run_id)?, load_plan(tx, run_id)?) {
                (Some(record), Some(plan))
                    if (plan.objective == objective || record.parent.is_some())
                        && acceptance_holds(tx, run_id)? =>
                {
                    Some(record)
                }
                _ => None,
            };
            let plan = crate::plan::replace_aggregate(
                tx,
                run_id,
                objective,
                todos,
                expected_revision,
                &timestamp,
            )?;
            if let Some(record) = carried {
                write_acceptance(
                    tx,
                    &PlanAcceptance {
                        plan_revision: plan.revision,
                        fingerprint: plan_structure_fingerprint(&plan),
                        ..record
                    },
                )?;
            }
            Ok(plan)
        })
    }

    /// Records real operator acceptance of the exact current plan structure.
    ///
    /// `expected_revision` names the plan revision the operator reviewed; a
    /// mismatch is rejected exactly like a stale aggregate replacement.
    /// `actor` is the authenticated local operator identity. A previous
    /// record for the run is replaced: accepting again is a new approval of
    /// the then-current structure.
    pub fn accept_plan(
        &mut self,
        run_id: &RunId,
        expected_revision: i64,
        actor: &str,
        now: OffsetDateTime,
    ) -> LedgerResult<()> {
        validate_actor(actor)?;
        self.with_tx(|tx| {
            let plan = load_plan(tx, run_id)?.ok_or_else(|| LedgerError::NotFound {
                kind: "plan",
                id: run_id.to_string(),
            })?;
            if plan.revision != expected_revision {
                return Err(stale_plan(tx, run_id, expected_revision)?);
            }
            write_acceptance(
                tx,
                &PlanAcceptance {
                    run_id: run_id.clone(),
                    plan_revision: plan.revision,
                    fingerprint: plan_structure_fingerprint(&plan),
                    actor: actor.to_owned(),
                    accepted_at: now,
                    parent: None,
                },
            )
        })
    }

    /// Accepts only the exact objective and revision shown to the owner.
    pub fn accept_plan_exact(
        &mut self,
        run_id: &RunId,
        expected_revision: i64,
        expected_objective: &str,
        actor: &str,
        now: OffsetDateTime,
    ) -> LedgerResult<()> {
        validate_actor(actor)?;
        self.with_tx(|tx| {
            let plan = load_plan(tx, run_id)?.ok_or_else(|| LedgerError::NotFound {
                kind: "plan",
                id: run_id.to_string(),
            })?;
            if plan.revision != expected_revision || plan.objective != expected_objective {
                return Err(LedgerError::invalid_data(
                    "the reviewed plan changed".to_owned(),
                ));
            }
            write_acceptance(
                tx,
                &PlanAcceptance {
                    run_id: run_id.clone(),
                    plan_revision: plan.revision,
                    fingerprint: plan_structure_fingerprint(&plan),
                    actor: actor.to_owned(),
                    accepted_at: now,
                    parent: None,
                },
            )
        })
    }

    /// Inherits operator acceptance for a child plan from an already-accepted
    /// parent plan.
    ///
    /// The parent must currently hold a valid acceptance (its whole lineage
    /// included), and the child record pins the parent's approval instance,
    /// so a new parent approval (or a parent objective change) voids the
    /// child while the parent's to-do edits do not. Lineage that would close a cycle or exceed the bounded depth is
    /// rejected.
    pub fn inherit_plan_acceptance(
        &mut self,
        parent_run: &RunId,
        child_run: &RunId,
        now: OffsetDateTime,
    ) -> LedgerResult<()> {
        if parent_run == child_run {
            return Err(LedgerError::invalid_data(
                "plan acceptance lineage cannot be self-referential".to_owned(),
            ));
        }
        self.with_tx(|tx| {
            let child_plan = load_plan(tx, child_run)?.ok_or_else(|| LedgerError::NotFound {
                kind: "plan",
                id: child_run.to_string(),
            })?;
            let parent_plan = load_plan(tx, parent_run)?.ok_or_else(|| LedgerError::NotFound {
                kind: "plan",
                id: parent_run.to_string(),
            })?;
            verify_accepted_lineage(tx, parent_run, child_run)?;
            let parent_record =
                read_acceptance_row(tx, parent_run)?.ok_or_else(|| LedgerError::NotFound {
                    kind: "plan acceptance",
                    id: parent_run.to_string(),
                })?;
            write_acceptance(
                tx,
                &PlanAcceptance {
                    run_id: child_run.clone(),
                    plan_revision: child_plan.revision,
                    fingerprint: plan_structure_fingerprint(&child_plan),
                    actor: format!("inherit:{parent_run}"),
                    accepted_at: now,
                    parent: Some(InheritedParent {
                        run_id: parent_run.clone(),
                        fingerprint: plan_structure_fingerprint(&parent_plan),
                        approval: Some(ParentApproval {
                            actor: parent_record.actor,
                            accepted_at: parent_record.accepted_at,
                        }),
                    }),
                },
            )
        })
    }
}

/// Reads and decodes one acceptance row, cross-checking the denormalized
/// columns against the canonical JSON record.
fn read_acceptance_row(
    connection: &Connection,
    run_id: &RunId,
) -> LedgerResult<Option<PlanAcceptance>> {
    let row = connection
        .query_row(
            "SELECT revision, status_json FROM materialized_status
             WHERE object_kind = ?1 AND object_id = ?2",
            params![PLAN_ACCEPTANCE_OBJECT_KIND, run_id.to_string()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((plan_revision, status_json)) = row else {
        return Ok(None);
    };
    let wire: PlanAcceptanceWire = serde_json::from_str(&status_json)?;
    if wire.run_id != *run_id {
        return Err(LedgerError::invalid_data(format!(
            "acceptance record {} names run {}",
            run_id, wire.run_id
        )));
    }
    if wire.plan_revision != plan_revision {
        return Err(LedgerError::invalid_data(format!(
            "acceptance record {run_id} revision {plan_revision} disagrees with its JSON revision {}",
            wire.plan_revision
        )));
    }
    wire.into_acceptance().map(Some)
}

fn write_acceptance(connection: &Connection, record: &PlanAcceptance) -> LedgerResult<()> {
    let wire = PlanAcceptanceWire::try_from(record)?;
    let status_json = serde_json::to_string(&wire)?;
    let accepted_at = encode_utc(record.accepted_at)?;
    let source = format!(
        "source:plan_acceptance:{}:revision:{}",
        record.run_id, record.plan_revision
    );
    connection.execute(
        "INSERT INTO materialized_status (
             object_kind, object_id, revision, status_json,
             source_event_id, updated_at, stale_after
         )
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)
         ON CONFLICT(object_kind, object_id) DO UPDATE SET
             revision = excluded.revision,
             status_json = excluded.status_json,
             source_event_id = excluded.source_event_id,
             updated_at = excluded.updated_at,
             stale_after = NULL",
        params![
            PLAN_ACCEPTANCE_OBJECT_KIND,
            record.run_id.to_string(),
            record.plan_revision,
            status_json,
            source,
            accepted_at,
        ],
    )?;
    Ok(())
}

/// Walks the acceptance lineage from `start` upward. Every record must match
/// its plan's current structure, every pinned parent approval must still be
/// the parent's record (a legacy pin: its structure unchanged), and the
/// lineage must stay within the bounded depth. Returns
/// `Ok(false)` for every doubt: missing records, changed structures, cyclic
/// or over-deep lineages never validate.
fn acceptance_holds(connection: &Connection, start: &RunId) -> LedgerResult<bool> {
    let mut visited: BTreeSet<RunId> = BTreeSet::new();
    visited.insert(start.clone());
    let mut current = start.clone();
    for _ in 0..MAX_LINEAGE_DEPTH {
        let Some(record) = read_acceptance_row(connection, &current)? else {
            return Ok(false);
        };
        let Some(plan) = load_plan(connection, &current)? else {
            return Ok(false);
        };
        if plan_structure_fingerprint(&plan) != record.fingerprint {
            return Ok(false);
        }
        let Some(parent) = record.parent else {
            return Ok(true);
        };
        if !visited.insert(parent.run_id.clone()) {
            return Ok(false);
        }
        let pin_holds = match &parent.approval {
            Some(approval) => {
                read_acceptance_row(connection, &parent.run_id)?.is_some_and(|parent_record| {
                    parent_record.actor == approval.actor
                        && parent_record.accepted_at == approval.accepted_at
                })
            }
            None => load_plan(connection, &parent.run_id)?.is_some_and(|parent_plan| {
                plan_structure_fingerprint(&parent_plan) == parent.fingerprint
            }),
        };
        if !pin_holds {
            return Ok(false);
        }
        current = parent.run_id;
    }
    Ok(false)
}

/// Verifies, inside the caller's transaction, that `parent` roots a currently
/// valid acceptance lineage that never reaches `child` and leaves room for
/// the child record within the bounded depth.
fn verify_accepted_lineage(
    connection: &Connection,
    parent: &RunId,
    child: &RunId,
) -> LedgerResult<()> {
    if !acceptance_holds(connection, parent)? {
        return Err(LedgerError::Conflict(format!(
            "parent plan {parent} does not have a current accepted lineage"
        )));
    }
    let mut visited: BTreeSet<RunId> = BTreeSet::new();
    visited.insert(parent.clone());
    let mut current = parent.clone();
    let mut depth = 0_usize;
    loop {
        if depth == MAX_LINEAGE_DEPTH {
            return Err(LedgerError::Conflict(format!(
                "plan acceptance lineage above {parent} exceeds the {MAX_LINEAGE_DEPTH}-record bound"
            )));
        }
        if current == *child {
            return Err(LedgerError::Conflict(format!(
                "plan acceptance lineage would close a cycle at {child}"
            )));
        }
        let Some(record) = read_acceptance_row(connection, &current)? else {
            return Err(LedgerError::Conflict(format!(
                "parent plan {current} is not accepted: no acceptance record exists"
            )));
        };
        let Some(plan) = load_plan(connection, &current)? else {
            return Err(LedgerError::Conflict(format!(
                "parent plan {current} disappeared from the ledger"
            )));
        };
        if plan_structure_fingerprint(&plan) != record.fingerprint {
            return Err(LedgerError::Conflict(format!(
                "parent plan {current} changed after its acceptance was recorded"
            )));
        }
        depth += 1;
        let Some(inherited) = record.parent else {
            break;
        };
        if !visited.insert(inherited.run_id.clone()) {
            return Err(LedgerError::Conflict(format!(
                "plan acceptance lineage above {parent} is cyclic"
            )));
        }
        current = inherited.run_id;
    }
    if depth + 1 > MAX_LINEAGE_DEPTH {
        return Err(LedgerError::Conflict(format!(
            "plan acceptance lineage would exceed the {MAX_LINEAGE_DEPTH}-record bound at {child}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use odin_domain::RunId;
    use time::OffsetDateTime;

    use super::{Ledger, LedgerError};
    use crate::plan::Plan;

    fn scratch_db() -> (tempfile::TempDir, std::path::PathBuf) {
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("plan-acceptance.sqlite3");
        (scratch, path)
    }

    const AT: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;

    fn run(name: &str) -> RunId {
        RunId::new(format!("run:{name}")).unwrap()
    }

    /// Seeds the lane and run rows the plan foreign keys require. Attempt
    /// numbers are unique per lane, so every run names its own.
    fn seed_run_at(ledger: &Ledger, run_id: &RunId, attempt: i64) {
        ledger
            .connection()
            .execute_batch(&format!(
                "INSERT OR IGNORE INTO lanes(
                     lane_id, seat_id, template_id, backend, status, created_by,
                     created_at, updated_at
                 ) VALUES (
                     'lane:accept-test', 'seat:test', 'template:test', 'local_omp',
                     'desired', 'test', '1970-01-01T00:00:00Z', '1970-01-01T00:00:00Z'
                 );
                 INSERT INTO runs(
                     run_id, lane_id, attempt_number, status, input_hash,
                     created_at, updated_at
                 ) VALUES (
                     '{run_id}', 'lane:accept-test', {attempt}, 'pending', 'hash',
                     '1970-01-01T00:00:00Z', '1970-01-01T00:00:00Z'
                 );"
            ))
            .unwrap();
    }

    fn seed_run(ledger: &Ledger, run_id: &RunId) {
        seed_run_at(ledger, run_id, 1);
    }

    fn draft_plan(ledger: &mut Ledger, run_id: &RunId, objective: &str) -> Plan {
        ledger.replace_plan(run_id, objective, &[], 0, AT).unwrap()
    }

    #[test]
    fn exact_acceptance_rejects_changed_revision_and_objective() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let run_id = run("exact-card");
        seed_run(&ledger, &run_id);
        let plan = draft_plan(&mut ledger, &run_id, "reviewed objective");
        assert!(ledger
            .accept_plan_exact(&run_id, plan.revision, "different", "owner", AT)
            .is_err());
        assert!(ledger
            .accept_plan_exact(&run_id, plan.revision + 1, &plan.objective, "owner", AT)
            .is_err());
        assert!(!ledger.plan_is_accepted(&run_id).unwrap());
        ledger
            .accept_plan_exact(&run_id, plan.revision, &plan.objective, "owner", AT)
            .unwrap();
        assert!(ledger.plan_is_accepted(&run_id).unwrap());
    }

    #[test]
    fn root_consent_request_is_exact_durable_and_deduplicated() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let session = odin_domain::SessionId::new("00000000-0000-4000-8000-000000000001").unwrap();
        let run_id = RunId::new(format!("run:live:{session}")).unwrap();
        seed_run(&ledger, &run_id);
        let plan = draft_plan(&mut ledger, &run_id, "review this");
        let request = |ledger: &mut Ledger| {
            ledger
                .request_root_plan_consent(
                    &run_id,
                    &session,
                    "seat:test",
                    plan.revision,
                    &plan.objective,
                    AT,
                )
                .unwrap()
        };
        let id = request(&mut ledger);
        assert_eq!(request(&mut ledger), id);
        let stored = ledger.root_plan_consent(&id).unwrap().unwrap();
        assert_eq!(stored.objective, plan.objective);
        assert_eq!(stored.revision, plan.revision);
        assert_eq!(
            ledger.pending_root_plan_consents().unwrap(),
            vec![id.clone()]
        );
        assert!(ledger.apply_root_plan_consent(&id, "owner", AT).is_err());
        assert!(!ledger.plan_is_accepted(&run_id).unwrap());
    }

    #[test]
    fn root_consent_renews_settled_questions_and_survives_rebuild() {
        use crate::approval::{ApprovalDecision, DecisionIntake};
        use odin_domain::ApprovalStatus;

        let (_scratch, path) = scratch_db();
        let session = odin_domain::SessionId::new("renewal").unwrap();
        let run_id = RunId::new(format!("run:live:{session}")).unwrap();
        let mut ledger = Ledger::open(&path).unwrap();
        seed_run(&ledger, &run_id);
        let plan = draft_plan(&mut ledger, &run_id, "review this");
        let request = |ledger: &mut Ledger, now| {
            ledger
                .request_root_plan_consent(
                    &run_id,
                    &session,
                    "seat:test",
                    plan.revision,
                    &plan.objective,
                    now,
                )
                .unwrap()
        };
        let first = request(&mut ledger, AT);
        assert!(ledger
            .decide_approval(
                &first,
                ApprovalDecision::Approve { evidence_ref: None },
                "owner",
                AT,
                1
            )
            .is_err());
        ledger
            .decide_approval_consuming_intake(
                &first,
                ApprovalDecision::Deny {
                    evidence_ref: "owner-denied".into(),
                },
                "owner",
                AT,
                1,
                &DecisionIntake {
                    consumer_id: "owner".into(),
                    message_id: "denial".into(),
                    owner_preview: true,
                },
            )
            .unwrap();
        let second = request(&mut ledger, AT);
        assert_ne!(first, second);
        assert_eq!(request(&mut ledger, AT), second);
        let later = AT + time::Duration::hours(2);
        let third = request(&mut ledger, later);
        assert_ne!(second, third);
        assert_eq!(
            ledger.approval(&second).unwrap().unwrap().status,
            ApprovalStatus::Expired
        );
        let pending = ledger.pending_root_plan_continuations().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, first);
        assert!(!pending[0].2.approved);
        assert_eq!(
            ledger
                .claim_root_plan_continuation(&first, 2, later)
                .unwrap(),
            2
        );
        assert_eq!(
            ledger
                .claim_root_plan_continuation(&first, 3, later)
                .unwrap(),
            2
        );
        assert!(ledger
            .reset_root_plan_continuation_claim(&first, 3, later)
            .is_err());
        ledger
            .reset_root_plan_continuation_claim(&first, 2, later)
            .unwrap();
        assert_eq!(
            ledger
                .claim_root_plan_continuation(&first, 3, later)
                .unwrap(),
            3
        );
        ledger.rebuild_materialized_status().unwrap();
        drop(ledger);
        let mut reopened = Ledger::open(&path).unwrap();
        assert_eq!(
            reopened.pending_root_plan_consents().unwrap(),
            vec![third.clone()]
        );
        assert_eq!(
            reopened.root_plan_consent(&first).unwrap(),
            reopened.root_plan_consent(&third).unwrap()
        );
        assert_eq!(
            reopened.pending_root_plan_continuations().unwrap()[0]
                .2
                .epoch,
            Some(3)
        );
        assert!(reopened
            .mark_root_plan_continuation_admitted(&first, 2, later)
            .is_err());
        reopened
            .mark_root_plan_continuation_admitted(&first, 3, later)
            .unwrap();
        reopened
            .mark_root_plan_continuation_admitted(&first, 3, later)
            .unwrap();
        assert!(reopened
            .pending_root_plan_continuations()
            .unwrap()
            .is_empty());
        assert!(reopened
            .reset_root_plan_continuation_claim(&first, 3, later)
            .is_err());
        assert!(!reopened.plan_is_accepted(&run_id).unwrap());
    }

    /// A seat keeps its own to-do list without losing the objective the operator accepted; a new
    /// objective is a new plan and needs acceptance again.
    #[test]
    fn rewriting_ones_own_todos_keeps_acceptance_and_a_new_objective_does_not() {
        use crate::plan::{TodoSpec, TodoStatus};
        let mut ledger = Ledger::open_in_memory().unwrap();
        let run_id = run("own-todos");
        seed_run(&ledger, &run_id);
        let plan = draft_plan(&mut ledger, &run_id, "answer the owner");
        ledger
            .accept_plan(&run_id, plan.revision, "operator:console", AT)
            .unwrap();
        let todos = [TodoSpec {
            id: "look".parse().unwrap(),
            title: "look it up".into(),
            status: TodoStatus::Active,
        }];
        let plan = ledger
            .replace_own_todos(&run_id, "answer the owner", &todos, plan.revision, AT)
            .unwrap();
        assert!(ledger.plan_is_accepted(&run_id).unwrap());
        assert_eq!(
            ledger.plan_acceptance(&run_id).unwrap().unwrap().actor,
            "operator:console"
        );
        ledger
            .replace_own_todos(&run_id, "something else", &todos, plan.revision, AT)
            .unwrap();
        assert!(!ledger.plan_is_accepted(&run_id).unwrap());
    }

    #[test]
    fn a_plan_that_merely_exists_is_never_accepted() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let run_id = run("draft-only");
        seed_run(&ledger, &run_id);
        draft_plan(&mut ledger, &run_id, "unapproved objective");

        assert!(!ledger.plan_is_accepted(&run_id).unwrap());
        assert!(ledger.plan_acceptance(&run_id).unwrap().is_none());

        // A stale expected revision is rejected exactly like a stale
        // aggregate replacement, and nothing gets recorded.
        let error = ledger
            .accept_plan(
                &run_id,
                2,
                "device:00000000-0000-4000-8000-000000000001",
                AT,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            LedgerError::StaleActor {
                expected_revision: 2,
                actual_revision: 1,
                ..
            }
        ));
    }

    #[test]
    fn acceptance_persists_and_survives_reopen() {
        let (_scratch, path) = scratch_db();
        let run_id = run("durable-accept");
        {
            let mut ledger = Ledger::open(&path).unwrap();
            seed_run(&ledger, &run_id);
            let plan = draft_plan(&mut ledger, &run_id, "durable objective");
            ledger
                .accept_plan(
                    &run_id,
                    plan.revision,
                    "device:00000000-0000-4000-8000-000000000001",
                    AT,
                )
                .unwrap();
            assert!(ledger.plan_is_accepted(&run_id).unwrap());
        }

        let reopened = Ledger::open(&path).unwrap();
        assert!(reopened.plan_is_accepted(&run_id).unwrap());
        let record = reopened.plan_acceptance(&run_id).unwrap().unwrap();
        assert_eq!(record.actor, "device:00000000-0000-4000-8000-000000000001");
        assert_eq!(record.plan_revision, 1);
        assert!(record.parent.is_none());
        drop(reopened);
    }

    #[test]
    fn a_structural_change_voids_acceptance_until_reapproved() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let run_id = run("structural");
        seed_run(&ledger, &run_id);
        let plan = draft_plan(&mut ledger, &run_id, "approved objective");
        ledger
            .accept_plan(&run_id, plan.revision, "operator:console", AT)
            .unwrap();
        assert!(ledger.plan_is_accepted(&run_id).unwrap());

        // A replacement that changes the objective changes the structure.
        let changed = ledger
            .replace_plan(&run_id, "rewritten objective", &[], plan.revision, AT)
            .unwrap();
        assert!(!ledger.plan_is_accepted(&run_id).unwrap());
        // The record still exists; it no longer holds for the new structure.
        assert!(ledger.plan_acceptance(&run_id).unwrap().is_some());

        // Re-approval of the current structure is a new genuine acceptance.
        ledger
            .accept_plan(&run_id, changed.revision, "operator:console", AT)
            .unwrap();
        assert!(ledger.plan_is_accepted(&run_id).unwrap());

        // Re-writing the identical structure does not change the approved
        // intent, so the earlier acceptance keeps holding.
        let rewritten = ledger
            .replace_plan(&run_id, "rewritten objective", &[], changed.revision, AT)
            .unwrap();
        assert_ne!(rewritten.revision, changed.revision);
        assert!(ledger.plan_is_accepted(&run_id).unwrap());
    }

    #[test]
    fn inherited_acceptance_follows_a_currently_accepted_parent() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let parent_id = run("inherit-parent");
        let child_id = run("inherit-child");
        seed_run_at(&ledger, &parent_id, 1);
        seed_run_at(&ledger, &child_id, 2);

        // Without an accepted parent there is nothing to inherit.
        let parent = draft_plan(&mut ledger, &parent_id, "parent objective");
        let child = draft_plan(&mut ledger, &child_id, "child objective");
        let error = ledger
            .inherit_plan_acceptance(&parent_id, &child_id, AT)
            .unwrap_err();
        assert!(matches!(error, LedgerError::Conflict(_)));

        ledger
            .accept_plan(&parent_id, parent.revision, "operator:console", AT)
            .unwrap();
        ledger
            .inherit_plan_acceptance(&parent_id, &child_id, AT)
            .unwrap();
        assert!(ledger.plan_is_accepted(&child_id).unwrap());
        let record = ledger.plan_acceptance(&child_id).unwrap().unwrap();
        let inherited = record.parent.as_ref().unwrap();
        assert_eq!(inherited.run_id, parent_id);
        assert_eq!(record.actor, format!("inherit:{parent_id}"));

        // Changing the approved parent structure voids the child. While the
        // parent itself is not yet re-approved, even its own gate is shut.
        let changed_parent = ledger
            .replace_plan(&parent_id, "parent objective v2", &[], parent.revision, AT)
            .unwrap();
        assert!(!ledger.plan_is_accepted(&parent_id).unwrap());
        assert!(!ledger.plan_is_accepted(&child_id).unwrap());

        // Re-approving the parent reopens the parent gate — but that is a new
        // approval instance, and the child pins the old one, so it stays void.
        ledger
            .accept_plan(
                &parent_id,
                changed_parent.revision,
                "operator:console",
                AT + time::Duration::SECOND,
            )
            .unwrap();
        assert!(ledger.plan_is_accepted(&parent_id).unwrap());
        assert!(!ledger.plan_is_accepted(&child_id).unwrap());

        // Re-inheritance pins the new parent structure and reopens the child.
        ledger
            .inherit_plan_acceptance(&parent_id, &child_id, AT)
            .unwrap();
        assert!(ledger.plan_is_accepted(&child_id).unwrap());
        drop(child);
    }

    fn todo(id: &str) -> crate::plan::TodoSpec {
        crate::plan::TodoSpec {
            id: id.parse().unwrap(),
            title: format!("do {id}"),
            status: crate::plan::TodoStatus::Pending,
        }
    }

    /// Accepted parent plus a child that inherited from it.
    fn inherited_pair(ledger: &mut Ledger, name: &str) -> (RunId, RunId, Plan, Plan) {
        let parent_id = run(&format!("{name}-parent"));
        let child_id = run(&format!("{name}-child"));
        seed_run_at(ledger, &parent_id, 1);
        seed_run_at(ledger, &child_id, 2);
        let parent = draft_plan(ledger, &parent_id, "answer the owner");
        let child = draft_plan(
            ledger,
            &child_id,
            "Execute the delegated implementation task",
        );
        ledger
            .accept_plan(&parent_id, parent.revision, "discord-owner:1", AT)
            .unwrap();
        ledger
            .inherit_plan_acceptance(&parent_id, &child_id, AT)
            .unwrap();
        (parent_id, child_id, parent, child)
    }

    #[test]
    fn an_inherited_acceptance_survives_a_new_child_objective() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let (_, child_id, _, child) = inherited_pair(&mut ledger, "child-objective");
        ledger
            .replace_own_todos(
                &child_id,
                "Raise research memory to 3Gi",
                &[todo("edit")],
                child.revision,
                AT,
            )
            .unwrap();
        assert!(ledger.plan_is_accepted(&child_id).unwrap());
    }

    #[test]
    fn a_parents_todo_rewrite_keeps_its_children() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let (parent_id, child_id, parent, _) = inherited_pair(&mut ledger, "parent-todos");
        ledger
            .replace_own_todos(
                &parent_id,
                "answer the owner",
                &[todo("ask")],
                parent.revision,
                AT,
            )
            .unwrap();
        assert!(ledger.plan_is_accepted(&parent_id).unwrap());
        assert!(ledger.plan_is_accepted(&child_id).unwrap());
    }

    #[test]
    fn voided_parent_cannot_pass_on_acceptance() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let (root, parent, root_plan, _) = inherited_pair(&mut ledger, "voided-lineage");
        let child = run("voided-lineage-grandchild");
        seed_run_at(&ledger, &child, 3);
        draft_plan(&mut ledger, &child, "grandchild objective");
        ledger
            .accept_plan(
                &root,
                root_plan.revision,
                "discord-owner:1",
                AT + time::Duration::SECOND,
            )
            .unwrap();
        assert!(!ledger.plan_is_accepted(&parent).unwrap());
        assert!(ledger.inherit_plan_acceptance(&parent, &child, AT).is_err());
        assert!(ledger.plan_acceptance(&child).unwrap().is_none());
    }

    #[test]
    fn a_legacy_parent_pin_falls_back_to_structure() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let (parent_id, child_id, parent, _) = inherited_pair(&mut ledger, "legacy");
        let mut record = ledger.plan_acceptance(&child_id).unwrap().unwrap();
        record.parent.as_mut().unwrap().approval = None;
        super::write_acceptance(ledger.connection(), &record).unwrap();
        assert!(ledger.plan_is_accepted(&child_id).unwrap());
        ledger
            .replace_own_todos(
                &parent_id,
                "answer the owner",
                &[todo("ask")],
                parent.revision,
                AT,
            )
            .unwrap();
        assert!(!ledger.plan_is_accepted(&child_id).unwrap());
    }
}
