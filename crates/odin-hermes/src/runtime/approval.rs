//! Approval questions must be delivered before conversation replies can decide them.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use odin_domain::{Actor, ApprovalId, ApprovalStatus, EventId, Redaction};
use odin_ledger::audit::{NewAuditEvent, RedactedPayload};
use odin_ledger::Ledger;
use serde_json::json;
use time::OffsetDateTime;

use super::authority::{durable_question_detail, durable_retry_arguments, latest_deliveries};
use super::{
    now_utc, ApprovalDelivery, AuthenticatedOwnerMessage, DecisionRefusal, DeliveredApproval,
    DeliveryError, HermesRuntime, APPROVAL_DELIVERY_AUDIT_KIND, RUNTIME_ISSUER,
};
use crate::discord::{transport_message_order, MAX_MESSAGE_CODEPOINTS};
use crate::egress::{
    split_reply, DeliveryCheckpoint, DeliveryOperation, DeliveryPlan, DeliveryReservation,
    EgressError, OutboundMessage, ReplyChunks,
};

/// Reuse the same canonical schema and full kernel validator as dispatch;
/// preview does not invent another action grammar or require a live browser.
static BROWSER_EFFECT_SCHEMA: std::sync::LazyLock<odin_domain::knowledge::ToolSchema> =
    std::sync::LazyLock::new(|| {
        let value = serde_json::from_str(include_str!(
            "../../../../schemas/capability/browser.consequential.input.json"
        ))
        .expect("the canonical browser schema is JSON");
        odin_domain::knowledge::ToolSchema::from_value(value)
            .expect("the canonical browser schema has a stable digest")
    });

/// Validate the schema and native identifiers before showing browser arguments.
fn browser_effect_preview(arguments: &serde_json::Value) -> Result<String, DeliveryError> {
    let missing = || {
        DeliveryError::SnapshotUnavailable(
            "the exact effect snapshot is missing or incomplete".into(),
        )
    };
    odin_kernel::operation::validate_input_arguments(&BROWSER_EFFECT_SCHEMA, arguments)
        .map_err(|_| missing())?;
    // Schema validation alone does not validate native session and digest representations.
    let _: odin_domain::huginn::BrowserSessionId =
        serde_json::from_value(arguments["sessionId"].clone()).map_err(|_| missing())?;
    for key in ["argumentsDigest", "policyDigest"] {
        let _: odin_domain::Digest =
            serde_json::from_value(arguments[key].clone()).map_err(|_| missing())?;
    }
    Ok(format!(
        "This binds the typed action, session revision and policy below; \
         it does not freeze arbitrary page scripts or form state.\n{}",
        serde_json::to_string_pretty(arguments).map_err(|_| missing())?,
    ))
}

struct MirroredCheckpoint {
    inner: Arc<dyn DeliveryCheckpoint>,
    log: Arc<super::channel_log::ChannelLog>,
    pending: Mutex<Option<(u64, DeliveryOperation)>>,
}

impl DeliveryCheckpoint for MirroredCheckpoint {
    fn prepare(&self, message: &OutboundMessage) -> Result<DeliveryPlan, EgressError> {
        self.inner.prepare(message)
    }

    fn reserve(&self, operation: &DeliveryOperation) -> Result<DeliveryReservation, EgressError> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| EgressError::DeliveryState("mirror checkpoint poisoned".into()))?;
        let reservation = self.inner.reserve(operation)?;
        *pending = Some((reservation.sequence, operation.clone()));
        Ok(reservation)
    }

    fn acknowledge(
        &self,
        reservation: &DeliveryReservation,
        reference: Option<&crate::discord::DiscordMessageRef>,
    ) -> Result<(), EgressError> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| EgressError::DeliveryState("mirror checkpoint poisoned".into()))?;
        let Some((sequence, operation)) = pending.as_ref() else {
            return Err(EgressError::DeliveryState(
                "mirror acknowledgement lacks reservation".into(),
            ));
        };
        if *sequence != reservation.sequence {
            return Err(EgressError::DeliveryState(
                "mirror acknowledgement is stale".into(),
            ));
        }
        self.inner.acknowledge(reservation, reference)?;
        match operation {
            DeliveryOperation::Post { content, .. } => {
                if let Some(reference) = reference {
                    self.log.record(odin_domain::huginn::ConversationLine {
                        id: reference.message_id.clone(),
                        from_owner: false,
                        text: content.clone(),
                        files: Vec::new(),
                    });
                }
            }
            DeliveryOperation::Patch {
                reference, content, ..
            } => {
                self.log.edit(&reference.message_id, content);
            }
            DeliveryOperation::Delete { reference } => self.log.delete(&reference.message_id),
        }
        *pending = None;
        Ok(())
    }

    fn failed(
        &self,
        reservation: &DeliveryReservation,
        error: &crate::discord::DiscordSendError,
    ) -> Result<(), EgressError> {
        self.inner.failed(reservation, error)
    }

    fn complete(&self) -> Result<(), EgressError> {
        self.inner.complete()
    }
}

impl HermesRuntime {
    /// Projects only the digest-selected request and authoritative draft
    /// receipts. Task prose is deliberately not an authorization preview.
    fn exact_question_detail(
        &self,
        capability: &str,
        request: &serde_json::Value,
    ) -> Result<String, DeliveryError> {
        let missing = || {
            DeliveryError::SnapshotUnavailable(
                "the exact effect snapshot is missing or incomplete".into(),
            )
        };
        let kind = self.preview_kind(capability).ok_or_else(missing)?;
        match kind {
            odin_registry::schema::PreviewKindToml::Browser => {
                let mut effect = request.clone();
                if let Some(object) = effect.as_object_mut() {
                    object.remove("approvalId");
                }
                browser_effect_preview(&effect)
            }
            odin_registry::schema::PreviewKindToml::Email => {
                let account = request["account"].as_str().ok_or_else(missing)?;
                let draft_id = request["draft_id"].as_str().ok_or_else(missing)?;
                let draft_digest = request["draft_digest"].as_str().ok_or_else(missing)?;
                let draft = self
                    .email
                    .as_ref()
                    .ok_or_else(missing)?
                    .approved_draft(account, draft_id, draft_digest)
                    .map_err(|_| missing())?;
                Ok(format!(
                    "Approved draft content:\n{}",
                    serde_json::to_string_pretty(&draft).map_err(|_| missing())?,
                ))
            }
            odin_registry::schema::PreviewKindToml::Batch => {
                self.batch_question_detail(request, missing)
            }
        }
    }

    fn preview_kind(&self, capability: &str) -> Option<odin_registry::schema::PreviewKindToml> {
        let id = odin_domain::CapabilityId::new(capability).ok()?;
        self.contracts
            .get(&id)
            .and_then(|contract| contract.preview)
    }

    fn declares_owner_preview(&self, capability: &odin_domain::CapabilityId) -> bool {
        self.contracts
            .get(capability)
            .is_some_and(|contract| contract.preview.is_some())
    }

    fn batch_question_detail(
        &self,
        request: &serde_json::Value,
        missing: impl Fn() -> DeliveryError,
    ) -> Result<String, DeliveryError> {
        let limits = self.batch_limits().map_err(|_| missing())?;
        let effects: Vec<odin_omp::host_tools::task_grants::PlannedEffect> =
            serde_json::from_value(request["effects"].clone()).map_err(|_| missing())?;
        let max_minutes = u64::from(limits.max_minutes);
        let max_uses_limit = u64::from(limits.max_uses);
        let minutes = request["minutes"]
            .as_u64()
            .filter(|value| (1..=max_minutes).contains(value))
            .ok_or_else(&missing)?;
        let max_uses = request["max_uses"]
            .as_u64()
            .filter(|value| (1..=max_uses_limit).contains(value))
            .ok_or_else(&missing)?;
        if effects.is_empty() || effects.len() > usize::from(limits.max_effects) {
            return Err(missing());
        }
        let mut detail = format!(
            "Authorize these exact effects for {minutes} minutes from your decision, \
             at most {max_uses} total uses across the batch. Each listed entry may execute once; \
             changed content, recipients or browser actions require a new decision."
        );
        for (index, effect) in effects.iter().enumerate() {
            let Some(contract) = self.contracts.get(&effect.capability) else {
                return Err(missing());
            };
            if !contract.batchable
                || !effect.arguments.is_object()
                || effect.arguments.get("approvalId").is_some()
            {
                return Err(missing());
            }
            let preview =
                self.exact_question_detail(effect.capability.as_str(), &effect.arguments)?;
            use std::fmt::Write as _;
            write!(
                detail,
                "\n\nEffect {} — {}\n{preview}",
                index + 1,
                effect.capability
            )
            .expect("writing to a String cannot fail");
        }
        Ok(detail)
    }

    pub(crate) fn deliver_checkpointed(
        &self,
        content: &str,
        checkpoint: Arc<dyn DeliveryCheckpoint>,
    ) -> Result<ReplyChunks, EgressError> {
        let content = crate::egress::scrub_sensitive(content, &self.scrub_tokens());
        self.deliver_scrubbed_checkpointed(content, checkpoint)
    }

    fn deliver_scrubbed_checkpointed(
        &self,
        content: String,
        checkpoint: Arc<dyn DeliveryCheckpoint>,
    ) -> Result<ReplyChunks, EgressError> {
        let bridge = self
            .notify
            .as_ref()
            .ok_or(EgressError::RoutingUnavailable)?;
        let checkpoint = Arc::new(MirroredCheckpoint {
            inner: checkpoint,
            log: Arc::clone(&self.channel_log),
            pending: Mutex::new(None),
        });
        bridge
            .notify(super::notify::NotifyAction::Deliver {
                content,
                checkpoint,
            })
            .map_err(EgressError::from)
    }

    /// The delivery binding and channel of one kind of owner reply.
    fn owner_reply_binding(&self, kind: &str) -> Result<(String, String), EgressError> {
        let discord = self
            .settings
            .discord
            .as_ref()
            .ok_or(EgressError::RoutingUnavailable)?;
        let binding = serde_json::to_string(&(
            kind,
            &discord.notify_channel_id,
            &discord.owner_user_id,
            discord.seat.as_str(),
            discord.project.as_str(),
        ))
        .map_err(|error| EgressError::DeliveryState(error.to_string()))?;
        Ok((binding, discord.notify_channel_id.clone()))
    }

    pub(super) fn notify_reply(
        &self,
        kind: &str,
        key: &str,
        content: &str,
    ) -> Result<ReplyChunks, EgressError> {
        let (binding, channel) = self.owner_reply_binding(kind)?;
        let path = self.store.ledger_path().ok_or_else(|| {
            EgressError::DeliveryState("owner reply requires a durable ledger".into())
        })?;
        let content = crate::egress::scrub_sensitive(content, &self.scrub_tokens());
        let checkpoint = crate::conversation::delivery::ReplyDelivery::open(
            &path,
            &binding,
            &channel,
            key,
            Some(&content),
            None,
        )?;
        self.deliver_scrubbed_checkpointed(content, checkpoint)
    }

    /// Delivers one scheduled notification occurrence to the owner exactly
    /// as the first attempt froze it. `key` names the occurrence. The first
    /// attempt renders and scrubs the text and the delivery ledger freezes
    /// those bytes; any later attempt (a retry, a replay after a crash)
    /// sends the frozen bytes and never calls `render` again.
    ///
    /// The stored fate decides before the notify worker is consulted: a
    /// committed delivery returns its receipt without admission or a send,
    /// and an operation of unknown outcome stays unknown. Only a resumable
    /// delivery is dispatched, so a refusal at that point (the bridge is
    /// closed or the job was withdrawn) proves nothing was handed over:
    /// [`EgressError::may_have_posted`] is false.
    pub(super) fn notify_scheduled(
        &self,
        key: &str,
        render: impl FnOnce() -> String,
    ) -> Result<ReplyChunks, EgressError> {
        use crate::conversation::delivery::{ReplyDelivery, ScheduledReply};
        let (binding, channel) = self.owner_reply_binding("schedule-notify")?;
        let path = self.store.ledger_path().ok_or(EgressError::InvalidState(
            "scheduled delivery requires a durable ledger",
        ))?;
        let reply = ReplyDelivery::open_scheduled(&path, &binding, &channel, key, || {
            crate::egress::scrub_sensitive(&render(), &self.scrub_tokens())
        })?;
        match reply {
            ScheduledReply::Delivered(receipt) => Ok(receipt),
            ScheduledReply::Unknown => Err(EgressError::DeliveryState(
                "scheduled delivery outcome unknown; explicit reconciliation required".into(),
            )),
            ScheduledReply::Resumable {
                content,
                checkpoint,
            } => self.deliver_scrubbed_checkpointed(content, checkpoint),
        }
    }

    /// Seals a scheduled send whose worker stopped before the outcome was known.
    pub(super) fn seal_scheduled(
        &self,
        key: &str,
    ) -> Result<crate::conversation::delivery::ScheduledSeal, EgressError> {
        let (binding, channel) = self.owner_reply_binding("schedule-notify")?;
        let path = self.store.ledger_path().ok_or(EgressError::InvalidState(
            "scheduled delivery requires a durable ledger",
        ))?;
        crate::conversation::delivery::ReplyDelivery::seal_unobserved(
            &path, &binding, &channel, key,
        )
    }

    /// Scrubs and sends to the paired channel, returning posted message identities.
    /// Partial sends mirror acknowledged chunks into the channel log before failing.
    pub(crate) fn notify_deliverable(&self, content: &str) -> Result<ReplyChunks, EgressError> {
        let bridge = self
            .notify
            .as_ref()
            .ok_or(EgressError::RoutingUnavailable)?;
        let content = crate::egress::scrub_sensitive(content, &self.scrub_tokens());
        let chunks = split_reply(&content, MAX_MESSAGE_CODEPOINTS);
        let sent = bridge
            .notify(super::notify::NotifyAction::Send(content.clone()))
            .map_err(EgressError::from);
        match &sent {
            Ok(posted) => self.mirror_chunks(posted, &chunks, chunks.len()),
            Err(EgressError::Partial {
                ownership, applied, ..
            }) => self.mirror_chunks(ownership.as_ref(), &chunks, *applied),
            Err(_) => {}
        }
        sent
    }

    /// Mirrors the chunks acknowledged by a non-conversation notification.
    fn mirror_chunks(&self, owned: &ReplyChunks, chunks: &[String], landed: usize) {
        for (index, text) in chunks.iter().take(landed).enumerate() {
            let Some(reference) = owned.refs().nth(index) else {
                break;
            };
            self.channel_log
                .record(odin_domain::huginn::ConversationLine {
                    id: reference.message_id.clone(),
                    from_owner: false,
                    text: text.clone(),
                    files: Vec::new(),
                });
        }
    }

    /// Shows the owner that a reply is being written.
    pub(crate) fn typing(&self) -> Result<(), String> {
        let bridge = self
            .notify
            .as_ref()
            .ok_or_else(|| "the discord surface is not configured".to_owned())?;
        bridge
            .notify(super::notify::NotifyAction::Typing)
            .map(drop)
            .map_err(|error| error.to_string())
    }

    /// Commits up to `max` status events without sending lifecycle receipts to the owner.
    /// Failed commits redeliver on the next tick; approval questions use
    /// [`HermesRuntime::deliver_approval_question`] instead.
    pub fn pump_status_egress(&self, max: usize) -> Result<usize, String> {
        // Typed before any drain: a Discord-less runtime never pretends the
        // pump ran, even with nothing to send.
        if self.notify.is_none() {
            return Err("the discord surface is not configured".to_owned());
        }
        let batch = self.bus.drain_batch(crate::egress::EGRESS_SUBJECTS, max);
        if batch.is_empty() {
            return Ok(0);
        }
        let committed = batch.len();
        self.bus
            .commit_batch(&batch)
            .map_err(|error| error.to_string())?;
        Ok(committed)
    }

    /// Records the exact request and recipient only after the question is delivered.
    /// Delivery evidence must use the same `ledger` as the approval row.
    pub fn deliver_approval_question(
        &self,
        ledger: &Arc<parking_lot::Mutex<Ledger>>,
        approval_id: &ApprovalId,
        channel_id: &str,
        owner_user_id: &str,
        now: OffsetDateTime,
        via: Option<&str>,
    ) -> Result<ApprovalDelivery, DeliveryError> {
        // The notify sink sends only to the configured owner and channel.
        let discord = self
            .settings
            .discord
            .as_ref()
            .ok_or(DeliveryError::NotConfigured)?;
        if channel_id != discord.notify_channel_id || owner_user_id != discord.owner_user_id {
            return Err(DeliveryError::NotPaired);
        }
        // The wording is composed from durable facts before the send: the
        // ADMITTED contract's declared description (never a phrase table)
        // and the exact journaled command body. A capability the pinned
        // snapshot does not admit with a usable declared description
        // refuses — no invented generic consent.
        let (
            description,
            detail,
            exact_request,
            approval_id,
            revision,
            session,
            capability,
            surface_seat,
            surface_project,
            ledger_path,
        ) = {
            let guard = ledger.lock();
            let approval = guard
                .approval(approval_id)
                .map_err(|error| DeliveryError::Evidence(error.to_string()))?
                .ok_or_else(|| DeliveryError::NotFound(approval_id.clone()))?;
            if approval.status != ApprovalStatus::Requested {
                return Err(DeliveryError::NotRequested(approval_id.clone()));
            }
            if approval.expires_at <= now {
                return Err(DeliveryError::Expired(approval_id.clone()));
            }
            let capability = approval.scope.capability_id.clone();
            let contract = self
                .contracts
                .get(&capability)
                .ok_or_else(|| DeliveryError::Undeclared(capability.clone()))?;
            if crate::natural::declared_action_phrase(&contract.description).is_empty() {
                return Err(DeliveryError::Undeclared(capability.clone()));
            }
            // Require a live requester for this seat/project so reassigned channels
            // cannot reuse an earlier delivery record.
            if !Self::requester_bound(&guard, &approval, via, discord) {
                return Err(DeliveryError::TargetUnbound);
            }
            let (detail, exact_request) = if odin_ledger::approval::requires_owner_preview(
                &approval.scope,
                self.declares_owner_preview(&approval.scope.capability_id),
            ) {
                (
                    None,
                    Some(durable_retry_arguments(&guard, &approval).map(|(_, retry)| retry)),
                )
            } else {
                (durable_question_detail(&guard, &approval), None)
            };
            (
                contract.description.clone(),
                detail,
                exact_request,
                approval.approval_id.clone(),
                approval.revision,
                approval.scope.target_id.clone(),
                capability.clone(),
                discord.seat.clone(),
                discord.project.clone(),
                guard
                    .connection()
                    .path()
                    .filter(|path| !path.is_empty() && *path != ":memory:")
                    .map(std::path::PathBuf::from)
                    .ok_or_else(|| {
                        DeliveryError::Evidence(
                            "approval delivery requires a durable ledger".into(),
                        )
                    })?,
            )
        };
        // The email adapter may share this authority ledger. Resolve its
        // authoritative snapshot only after releasing the journal read lock.
        let exact = exact_request.is_some();
        let detail = match exact_request {
            Some(request) => Some(self.exact_question_detail(
                capability.as_str(),
                &request.ok_or_else(|| {
                    DeliveryError::SnapshotUnavailable("the digest-bound request is missing".into())
                })?,
            )?),
            None => detail,
        };
        let rendered = crate::natural::approval_question(&description, detail.as_deref());
        let question = crate::egress::scrub_sensitive(&rendered, &self.scrub_tokens());
        if exact && question != rendered {
            return Err(DeliveryError::SnapshotUnavailable(
                "the exact preview contains protected material and cannot be delivered".into(),
            ));
        }

        let binding = serde_json::to_string(&(
            "kernel-approval",
            channel_id,
            owner_user_id,
            surface_seat.as_str(),
            surface_project.as_str(),
        ))
        .map_err(|error| DeliveryError::Evidence(error.to_string()))?;
        let key = serde_json::to_string(&(approval_id.as_str(), revision))
            .map_err(|error| DeliveryError::Evidence(error.to_string()))?;
        let checkpoint = crate::conversation::delivery::ReplyDelivery::open(
            &ledger_path,
            &binding,
            channel_id,
            &key,
            Some(&question),
            None,
        )
        .map_err(|error| DeliveryError::SendFailed(error.to_string()))?;
        let posted = self
            .deliver_scrubbed_checkpointed(question, checkpoint)
            .map_err(|error| DeliveryError::SendFailed(error.to_string()))?;
        let delivered_at = now_utc();
        let completion = posted
            .refs()
            .last()
            .expect("a delivered reply has an anchor");
        if posted
            .refs()
            .any(|reference| reference.channel_id != channel_id)
        {
            return Err(DeliveryError::NotPaired);
        }
        let delivery_identity = serde_json::to_vec(&(
            approval_id.as_str(),
            completion.channel_id.as_str(),
            completion.message_id.as_str(),
        ))
        .map_err(|error| DeliveryError::Evidence(error.to_string()))?;
        let evidence_event_id = EventId::new(format!(
            "event:hermes-delivery:{}",
            odin_domain::Digest::hash(&delivery_identity),
        ))
        .map_err(|error| DeliveryError::Evidence(error.to_string()))?;
        let mut delivery = ApprovalDelivery {
            approval_id,
            revision,
            session,
            seat: surface_seat,
            project: surface_project,
            capability_id: capability,
            channel_id: channel_id.to_owned(),
            owner_user_id: owner_user_id.to_owned(),
            evidence_event_id,
            sent_message_id: completion.message_id.clone(),
            delivered_at,
        };
        // Recheck under the recording lock: the approval may have changed during the send.
        let guard = ledger.lock();
        let approval = guard
            .approval(&delivery.approval_id)
            .map_err(|error| DeliveryError::Evidence(error.to_string()))?
            .ok_or_else(|| DeliveryError::NotFound(delivery.approval_id.clone()))?;
        if approval.status != ApprovalStatus::Requested || approval.revision != delivery.revision {
            return Err(DeliveryError::NotRequested(delivery.approval_id.clone()));
        }
        let event = NewAuditEvent {
            event_id: delivery.evidence_event_id.clone(),
            kind: APPROVAL_DELIVERY_AUDIT_KIND.to_owned(),
            actor: Actor::System {
                name: RUNTIME_ISSUER.to_owned(),
            },
            scope: odin_domain::Scope::default(),
            evidence: Vec::new(),
            payload: RedactedPayload::new(
                json!({
                    "approvalId": delivery.approval_id.to_string(),
                    "revision": delivery.revision,
                    "capabilityId": delivery.capability_id.to_string(),
                    "session": delivery.session.clone(),
                    "seat": delivery.seat.to_string(),
                    "project": delivery.project.to_string(),
                    "channelId": delivery.channel_id.clone(),
                    "ownerUserId": delivery.owner_user_id.clone(),
                    "evidenceEventId": delivery.evidence_event_id.to_string(),
                    "sentMessageId": delivery.sent_message_id,
                    // The exact content shown: owner consent binds this digest.
                    "argumentsDigest": approval.scope.arguments_digest.to_string(),
                    "completeSnapshot": exact,
                    "via": via,
                }),
                Redaction::None,
            )
            .map_err(|error| DeliveryError::Evidence(error.to_string()))?,
            occurred_at: delivery.delivered_at,
        };
        let recorded = match guard.append_audit_event(event.clone()) {
            Ok(recorded) => recorded,
            Err(error) => guard
                .audit_event(&event.event_id)
                .map_err(|read_error| DeliveryError::Evidence(read_error.to_string()))?
                .ok_or_else(|| DeliveryError::Evidence(error.to_string()))?,
        };
        if recorded.kind != event.kind
            || recorded.actor != event.actor
            || recorded.scope != event.scope
            || recorded.evidence != event.evidence
            || recorded.payload != *event.payload.value()
            || recorded.redaction != *event.payload.redaction()
        {
            return Err(DeliveryError::Evidence(
                "approval delivery evidence identity conflicts".into(),
            ));
        }
        delivery.delivered_at = recorded.occurred_at;
        Ok(delivery)
    }

    /// Includes every question posted here, even if re-posted at a successor session's revision.
    pub fn ever_delivered_approvals(
        &self,
        ledger: &Arc<parking_lot::Mutex<Ledger>>,
        channel_id: &str,
        owner_user_id: &str,
    ) -> Result<BTreeSet<String>, DecisionRefusal> {
        let guard = ledger.lock();
        Ok(latest_deliveries(&guard, channel_id, owner_user_id, |id| {
            self.preview_kind(id).is_some()
        })?
        .into_iter()
        .map(|(payload, _)| payload.approval_id)
        .collect())
    }

    pub fn delivered_pending_approvals(
        &self,
        ledger: &Arc<parking_lot::Mutex<Ledger>>,
        channel_id: &str,
        owner_user_id: &str,
        now: OffsetDateTime,
    ) -> Result<Vec<DeliveredApproval>, DecisionRefusal> {
        let discord = self
            .settings
            .discord
            .as_ref()
            .ok_or(DecisionRefusal::NotAuthenticated)?;
        if channel_id != discord.notify_channel_id || owner_user_id != discord.owner_user_id {
            return Err(DecisionRefusal::NotAuthenticated);
        }
        let guard = ledger.lock();
        let deliveries = latest_deliveries(&guard, channel_id, owner_user_id, |id| {
            self.preview_kind(id).is_some()
        })?;
        let mut pending = Vec::new();
        let mut listed = BTreeSet::new();
        for (payload, occurred_at) in deliveries {
            // A re-asked question is listed once, using its newest delivery.
            if !listed.insert(payload.approval_id.clone()) {
                continue;
            }
            let Ok(approval_id) = ApprovalId::new(&payload.approval_id) else {
                continue;
            };
            let approval = match guard.approval(&approval_id) {
                Ok(Some(approval)) => approval,
                Ok(None) => continue,
                // A "yes" would bind nothing: say why once.
                Err(error) => {
                    tracing::warn!(
                        approval = %approval_id,
                        error = %error,
                        "odin-hermes: pending approval unreadable approval={approval_id}: {error}"
                    );
                    continue;
                }
            };
            if approval.status != ApprovalStatus::Requested
                || approval.expires_at <= now
                || approval.revision != payload.revision
            {
                continue;
            }
            if !Self::requester_bound(&guard, &approval, payload.via.as_deref(), discord) {
                continue;
            }
            let Some(contract) = self.contracts.get(&approval.scope.capability_id) else {
                continue;
            };
            let _ = occurred_at;
            let (detail, exact_request) = if odin_ledger::approval::requires_owner_preview(
                &approval.scope,
                self.declares_owner_preview(&approval.scope.capability_id),
            ) {
                (
                    None,
                    Some(durable_retry_arguments(&guard, &approval).map(|(_, retry)| retry)),
                )
            } else {
                (durable_question_detail(&guard, &approval), None)
            };
            pending.push((
                DeliveredApproval {
                    approval_id: approval.approval_id,
                    revision: approval.revision,
                    capability_id: approval.scope.capability_id,
                    session: payload.session,
                    label: crate::natural::approval_label(&contract.description),
                    detail,
                },
                exact_request,
            ));
        }
        drop(guard);
        Ok(pending
            .into_iter()
            .filter_map(|(mut delivered, exact_request)| {
                if let Some(request) = exact_request {
                    delivered.detail = Some(
                        self.exact_question_detail(delivered.capability_id.as_str(), &request?)
                            .ok()?,
                    );
                }
                Some(delivered)
            })
            .collect())
    }

    /// Decides only a live, unexpired request at its delivered revision. The authenticated
    /// reply must follow the question in transport order; the transaction consumes the
    /// reply identity once, so replayed replies cannot authorize replacement requests.
    pub fn decide_delivered_approval(
        &self,
        ledger: &Arc<parking_lot::Mutex<Ledger>>,
        message: &AuthenticatedOwnerMessage,
        approval_id: &ApprovalId,
        expected_revision: i64,
        decision: crate::natural::OwnerDecision,
        now: OffsetDateTime,
    ) -> Result<odin_kernel::DecisionOutcome, DecisionRefusal> {
        // (1) Authentication against the configured surface binding.
        let discord = self
            .settings
            .discord
            .as_ref()
            .ok_or(DecisionRefusal::NotAuthenticated)?;
        let authenticated = message.owner_user_id == discord.owner_user_id
            && message.channel_id == discord.notify_channel_id
            && message.seat == discord.seat
            && message.project == discord.project;
        if !authenticated {
            return Err(DecisionRefusal::NotAuthenticated);
        }
        let mut guard = ledger.lock();
        // (2) The actual delivery proofs for this exact conversation and
        // approval: the newest copy carries the binding fields; the
        // EARLIEST completed copy anchors the causal check, so a reply to
        // any complete copy stays valid across re-asks.
        let mut copies =
            latest_deliveries(&guard, &message.channel_id, &message.owner_user_id, |id| {
                self.preview_kind(id).is_some()
            })?
            .into_iter()
            .filter(|(payload, _)| payload.approval_id == approval_id.as_str());
        let (payload, _) = copies
            .next()
            .ok_or_else(|| DecisionRefusal::Undelivered(approval_id.clone()))?;
        let earliest_sent = copies
            .map(|(copy, _)| copy.sent_message_id)
            .chain(std::iter::once(payload.sent_message_id.clone()))
            .min_by(|a, b| transport_message_order(a, b).unwrap_or(std::cmp::Ordering::Greater))
            .expect("the newest copy's id is always present");
        // (3) Causal identity order: the reply was written after the
        // question reached this conversation. An unorderable transport
        // identity refuses fail-closed.
        match transport_message_order(&message.message_id, &earliest_sent) {
            Some(std::cmp::Ordering::Greater) => {}
            _ => return Err(DecisionRefusal::PredatesDelivery(approval_id.clone())),
        }
        // (4) Exact request + revision: the delivered question and the
        // row must both be the reply's binding.
        if payload.revision != expected_revision {
            return Err(DecisionRefusal::Superseded {
                shown: payload.revision,
                claimed: expected_revision,
            });
        }
        let approval = guard
            .approval(approval_id)
            .map_err(|error| DecisionRefusal::Evidence(error.to_string()))?
            .ok_or_else(|| DecisionRefusal::NotOpen(approval_id.clone()))?;
        if approval.scope.target_id != payload.session {
            return Err(DecisionRefusal::Undelivered(approval_id.clone()));
        }
        // (4b) The proof's recorded seat/project binding must be the reply's
        // binding too: a Discord channel rebound to another seat/project can
        // never spend a question delivered under the old binding.
        if payload.seat != message.seat.as_str() || payload.project != message.project.as_str() {
            return Err(DecisionRefusal::Undelivered(approval_id.clone()));
        }
        // (5) Still open, fresh, and the requester session is STILL a live
        // vehicle durably bound to this surface's seat and project. Unknown
        // target kinds have no durable vehicle and are never implicitly
        // alive for a conversation decision.
        if approval.status != ApprovalStatus::Requested {
            return Err(DecisionRefusal::NotOpen(approval_id.clone()));
        }
        if approval.expires_at <= now {
            return Err(DecisionRefusal::Expired(approval_id.clone()));
        }
        if approval.scope.target_kind != "run" {
            return Err(DecisionRefusal::Undelivered(approval_id.clone()));
        }
        if !Self::requester_bound(&guard, &approval, payload.via.as_deref(), discord) {
            return Err(DecisionRefusal::SessionRetired);
        }
        // (6) The kernel decides at the delivered revision, consuming this
        // exact inbound message identity once in the settlement's own
        // transaction; the evidence reference names the durable delivery
        // proof.
        let evidence_ref = format!("delivery:{}", payload.evidence_event_id);
        let ledger_decision = match decision {
            crate::natural::OwnerDecision::AllowOnce => {
                odin_ledger::approval::ApprovalDecision::Approve {
                    evidence_ref: Some(evidence_ref),
                }
            }
            crate::natural::OwnerDecision::Deny => {
                odin_ledger::approval::ApprovalDecision::Deny { evidence_ref }
            }
        };
        let intake = odin_ledger::approval::DecisionIntake {
            consumer_id: format!("discord-owner:{}", message.owner_user_id),
            message_id: message.message_id.clone(),
        };
        let owner_preview = self.declares_owner_preview(&approval.scope.capability_id);
        match odin_kernel::ApprovalGate::new(&mut guard).decide_consuming_intake(
            approval_id,
            expected_revision,
            ledger_decision,
            &format!("discord-owner:{}", message.owner_user_id),
            now,
            &intake,
            owner_preview,
        ) {
            Ok(Some(outcome)) => Ok(outcome),
            Ok(None) => Err(DecisionRefusal::IntakeConsumed(approval_id.clone())),
            Err(error) => Err(DecisionRefusal::Ledger(error.to_string())),
        }
    }

    /// Requires this surface's live vehicle or a live delegated worker delivered via it;
    /// failed, ended, retired and non-run targets cannot authorize conversation decisions.
    fn requester_bound(
        ledger: &Ledger,
        approval: &odin_ledger::approval::Approval,
        via: Option<&str>,
        discord: &crate::config::DiscordSettings,
    ) -> bool {
        if approval.scope.target_kind != "run" {
            return false;
        }
        let surface = |binding: Option<(String, String)>| {
            binding.is_some_and(|(seat, project)| {
                seat == discord.seat.as_str() && project == discord.project.as_str()
            })
        };
        match via {
            None => {
                approval.issuer == discord.seat.as_str()
                    && surface(Self::approval_target_binding(
                        ledger,
                        &approval.scope.target_id,
                    ))
            }
            Some(vehicle) => {
                Self::approval_target_binding(ledger, &approval.scope.target_id).is_some()
                    && surface(Self::approval_target_binding(ledger, vehicle))
            }
        }
    }

    fn approval_target_binding(ledger: &Ledger, target_id: &str) -> Option<(String, String)> {
        let session_id = target_id.strip_prefix("run:live:")?;
        ledger
            .connection()
            .query_row(
                "SELECT seat_id, project_id FROM live_sessions \
                 WHERE session_id = ?1 AND state NOT IN ('failed', 'ended') \
                 AND retired_at IS NULL LIMIT 1",
                [&session_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .ok()
    }
}
