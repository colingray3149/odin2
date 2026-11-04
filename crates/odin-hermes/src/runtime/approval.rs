//! Approval questions must be delivered before conversation replies can decide them.

use super::tools::NO_DISCORD;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use odin_domain::{Actor, ApprovalId, ApprovalStatus, EventId, Redaction};
use odin_ledger::audit::{NewAuditEvent, RedactedPayload};
use odin_ledger::Ledger;
use serde_json::json;
use time::OffsetDateTime;

use super::authority::{durable_retry_arguments, latest_deliveries};
use super::notify::{NotifyAction, STATUS_WAIT};
use super::{
    ApprovalDelivery, AuthenticatedOwnerMessage, DecisionRefusal, DeliveredApproval, DeliveryError,
    HermesRuntime, APPROVAL_DELIVERY_AUDIT_KIND, RUNTIME_ISSUER,
};
use crate::conversation::StatusPostError;
use crate::discord::{transport_message_order, DiscordMessageRef, MAX_MESSAGE_CODEPOINTS};
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

/// The call's own arguments, which the owner approves word for word when no better preview exists.
fn exact_arguments(request: &serde_json::Value) -> String {
    let mut arguments = request.clone();
    if let Some(object) = arguments.as_object_mut() {
        object.remove("approvalId");
    }
    serde_json::to_string_pretty(&arguments).unwrap_or_else(|_| arguments.to_string())
}

fn incomplete_snapshot(cause: impl std::fmt::Display) -> DeliveryError {
    DeliveryError::SnapshotUnavailable(format!(
        "the exact effect snapshot is missing or incomplete: {cause}"
    ))
}

/// Validate the schema and native identifiers before showing browser arguments.
fn browser_effect_preview(arguments: &serde_json::Value) -> Result<String, DeliveryError> {
    odin_kernel::operation::validate_input_arguments(&BROWSER_EFFECT_SCHEMA, arguments)
        .map_err(incomplete_snapshot)?;
    // Schema validation alone does not validate native session and digest representations.
    let _: odin_domain::huginn::BrowserSessionId =
        serde_json::from_value(arguments["sessionId"].clone()).map_err(incomplete_snapshot)?;
    for key in ["argumentsDigest", "policyDigest"] {
        let _: odin_domain::Digest =
            serde_json::from_value(arguments[key].clone()).map_err(incomplete_snapshot)?;
    }
    Ok(format!(
        "This binds the typed action, session revision and policy below; \
         it does not freeze arbitrary page scripts or form state.\n{}",
        serde_json::to_string_pretty(arguments).map_err(incomplete_snapshot)?,
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
            .map_err(|error| EgressError::DeliveryState(format!("mirror checkpoint: {error}")))?;
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
            .map_err(|error| EgressError::DeliveryState(format!("mirror checkpoint: {error}")))?;
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
            odin_registry::schema::PreviewKindToml::Batch => {
                self.batch_question_detail(request, missing)
            }
            odin_registry::schema::PreviewKindToml::Deploy => {
                super::coding::deploy::question_detail(self, request)
                    .map_err(DeliveryError::SnapshotUnavailable)
            }
            odin_registry::schema::PreviewKindToml::Plan => self
                .workflow_plan(capability, request)
                .map_err(DeliveryError::SnapshotUnavailable),
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
        let (limits, _) = self.batch_policy().map_err(incomplete_snapshot)?;
        let effects: Vec<odin_omp::host_tools::task_grants::PlannedEffect> =
            serde_json::from_value(request["effects"].clone()).map_err(incomplete_snapshot)?;
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
        let bridge = self.notify.as_ref().ok_or_else(|| NO_DISCORD.to_owned())?;
        bridge
            .notify(super::notify::NotifyAction::Typing)
            .map(drop)
            .map_err(|error| error.to_string())
    }

    /// Posts a turn's status message to the paired channel. It is a passing
    /// display, so it is neither durable nor mirrored into the channel log,
    /// and a busy sink costs it [`STATUS_WAIT`], not the turn.
    /// It posts silently: each one would otherwise ping the owner's phone and
    /// then vanish.
    pub(crate) fn status_post(&self, content: &str) -> Result<DiscordMessageRef, StatusPostError> {
        let content = crate::egress::scrub_sensitive(content, &self.scrub_tokens());
        let bridge = self
            .notify
            .as_ref()
            .ok_or_else(|| StatusPostError::refused("the discord surface is not configured"))?;
        bridge
            .notify_within(NotifyAction::Silent(content), STATUS_WAIT)
            .map(|posted| posted.anchor)
            .map_err(|error| StatusPostError {
                cause: error.to_string(),
                may_have_posted: error.may_have_posted(),
            })
    }

    pub(crate) fn status_edit(
        &self,
        message: &DiscordMessageRef,
        content: &str,
    ) -> Result<(), String> {
        let content = crate::egress::scrub_sensitive(content, &self.scrub_tokens());
        self.notify_status(NotifyAction::Edit {
            message: message.clone(),
            content,
        })
        .map(drop)
    }

    pub(crate) fn status_delete(&self, message: &DiscordMessageRef) -> Result<(), String> {
        self.notify_status(NotifyAction::Delete(message.clone()))
            .map(drop)
    }

    fn notify_status(&self, action: NotifyAction) -> Result<ReplyChunks, String> {
        self.notify
            .as_ref()
            .ok_or_else(|| "the discord surface is not configured".to_owned())?
            .notify_within(action, STATUS_WAIT)
            .map_err(|error| error.to_string())
    }

    /// Commits up to `max` status events without sending lifecycle receipts to the owner.
    /// Failed commits redeliver on the next tick; approval questions use
    /// [`HermesRuntime::deliver_approval_question`] instead.
    pub fn pump_status_egress(&self, max: usize) -> Result<usize, String> {
        // Typed before any drain: a Discord-less runtime never pretends the
        // pump ran, even with nothing to send.
        if self.notify.is_none() {
            return Err(NO_DISCORD.to_owned());
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
        let (description, journaled, approval_id, revision, session, capability) = {
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
            let journaled = durable_retry_arguments(&guard, &approval);
            // A previewed question shows the call itself, so it cannot be asked without it.
            if journaled.is_none() && self.declares_owner_preview(&capability) {
                return Err(DeliveryError::SnapshotUnavailable(
                    "the journaled call this approval covers is missing".into(),
                ));
            }
            if journaled.is_none() {
                tracing::warn!(
                    "odin-hermes: no journaled call matches approval {approval_id}; its question names {capability} only"
                );
            }
            (
                contract.description.clone(),
                journaled,
                approval.approval_id.clone(),
                approval.revision,
                approval.scope.target_id.clone(),
                capability,
            )
        };
        let ledger_path = ledger
            .lock()
            .connection()
            .path()
            .filter(|path| !path.is_empty() && *path != ":memory:")
            .map(std::path::PathBuf::from)
            .ok_or_else(|| {
                DeliveryError::Evidence("approval delivery requires a durable ledger".into())
            })?;
        let surface_seat = discord.seat.clone();
        let surface_project = discord.project.clone();
        // The email adapter may share this authority ledger. Resolve its
        // authoritative snapshot only after releasing the journal read lock.
        let exact = self.declares_owner_preview(&capability);
        let detail = match journaled {
            // A preview that cannot run leaves the owner the exact arguments and the cause;
            // the question is asked either way.
            Some((_, request)) if exact => Some(
                match self.exact_question_detail(capability.as_str(), &request) {
                    Ok(detail) => detail,
                    Err(cause) => format!("(no preview: {cause})\n{}", exact_arguments(&request)),
                },
            ),
            Some((arguments_json, request)) => Some(
                crate::natural::detail_from_request_json(&arguments_json)
                    .unwrap_or_else(|| exact_arguments(&request)),
            ),
            None => None,
        };
        let question = crate::egress::scrub_sensitive(
            &crate::natural::approval_question(&description, detail.as_deref()),
            &self.scrub_tokens(),
        );

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
        let delivered_at = OffsetDateTime::now_utc();
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

    /// A question that could not be asked is withdrawn, so no request waits on an answer nobody
    /// can give, and the owner hears why in one line. The seat's retry is told the same: the
    /// request was cancelled.
    pub fn withdraw_unasked_question(
        &self,
        ledger: &Arc<parking_lot::Mutex<Ledger>>,
        approval_id: &ApprovalId,
        cause: &DeliveryError,
    ) {
        // A request that already moved on is not a failure to tell anyone about.
        if matches!(
            cause,
            DeliveryError::NotFound(_) | DeliveryError::NotRequested(_) | DeliveryError::Expired(_)
        ) {
            return;
        }
        let label = {
            let mut guard = ledger.lock();
            let Ok(Some(approval)) = guard.approval(approval_id) else {
                return;
            };
            if let Err(error) = guard.withdraw_requested_approval(
                approval_id,
                OffsetDateTime::now_utc(),
                approval.revision,
            ) {
                tracing::error!(
                    "odin-hermes: approval {approval_id} could not be withdrawn: {error}"
                );
            }
            self.contracts
                .get(&approval.scope.capability_id)
                .map_or_else(
                    || approval.scope.capability_id.to_string(),
                    |contract| crate::natural::approval_label(&contract.description),
                )
        };
        self.approved_calls.release(approval_id);
        tracing::error!("odin-hermes: question {approval_id} could not be delivered: {cause}");
        let line =
            format!("I could not ask you about \u{201c}{label}\u{201d}: {cause}. Nothing ran.");
        if let Err(error) = self.notify_deliverable(&line) {
            tracing::error!(
                "odin-hermes: the owner could not be told about {approval_id}: {error}"
            );
        }
    }

    /// Every open question this owner was asked, newest first. The row is the list: nothing
    /// is recomputed, so a question once asked stays decidable until it lapses.
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
        for (payload, _) in deliveries {
            // A re-asked question is listed once, at its newest delivery.
            if !listed.insert(payload.approval_id.clone()) {
                continue;
            }
            let Ok(approval_id) = ApprovalId::new(&payload.approval_id) else {
                continue;
            };
            let approval = match guard.approval(&approval_id) {
                Ok(Some(approval)) => approval,
                Ok(None) => continue,
                Err(error) => return Err(DecisionRefusal::Evidence(error.to_string())),
            };
            if approval.status != ApprovalStatus::Requested || approval.expires_at <= now {
                continue;
            }
            let Some(contract) = self.contracts.get(&approval.scope.capability_id) else {
                continue;
            };
            pending.push(DeliveredApproval {
                approval_id: approval.approval_id,
                revision: approval.revision,
                capability_id: approval.scope.capability_id,
                session: approval.scope.target_id,
                label: crate::natural::approval_label(&contract.description),
            });
        }
        Ok(pending)
    }

    /// The owner's most recent question that lapsed unanswered or already settled, as one plain
    /// sentence, so a late or repeated yes is answered instead of read as chat. `None` when
    /// nothing lapsed within `window`.
    pub fn lapsed_approval_sentence(
        &self,
        ledger: &Arc<parking_lot::Mutex<Ledger>>,
        channel_id: &str,
        owner_user_id: &str,
        now: OffsetDateTime,
        window: time::Duration,
    ) -> Result<Option<String>, DecisionRefusal> {
        let guard = ledger.lock();
        let deliveries = latest_deliveries(&guard, channel_id, owner_user_id, |id| {
            self.preview_kind(id).is_some()
        })?;
        for (payload, asked_at) in deliveries {
            let Ok(approval_id) = ApprovalId::new(&payload.approval_id) else {
                continue;
            };
            let Ok(Some(approval)) = guard.approval(&approval_id) else {
                continue;
            };
            let Some(contract) = self.contracts.get(&approval.scope.capability_id) else {
                continue;
            };
            let label = crate::natural::approval_label(&contract.description);
            let (at, sentence) = match approval.status {
                ApprovalStatus::Requested if approval.expires_at <= now => (
                    approval.expires_at,
                    format!("That question ({label}) expired before your answer, so nothing ran. Ask again if you still want it."),
                ),
                ApprovalStatus::Expired => (
                    approval.expires_at,
                    format!("That question ({label}) expired before your answer, so nothing ran. Ask again if you still want it."),
                ),
                ApprovalStatus::Denied => (
                    approval.decided_at.unwrap_or(asked_at),
                    format!("You already said no to that ({label}), so nothing ran."),
                ),
                ApprovalStatus::Approved | ApprovalStatus::Consumed => (
                    approval.decided_at.unwrap_or(asked_at),
                    format!("You already said yes to that ({label}); it is not waiting on you any more."),
                ),
                ApprovalStatus::Cancelled => (
                    asked_at,
                    format!("That question ({label}) was withdrawn, so nothing ran."),
                ),
                ApprovalStatus::Requested => continue,
            };
            // The newest delivery that is not open decides; older ones are history.
            return Ok((now - at <= window).then_some(sentence));
        }
        Ok(None)
    }

    /// Decides one open request, citing the delivery that showed it. The reply is consumed once,
    /// so a replayed message cannot decide a later request.
    pub fn decide_delivered_approval(
        &self,
        ledger: &Arc<parking_lot::Mutex<Ledger>>,
        message: &AuthenticatedOwnerMessage,
        approval_id: &ApprovalId,
        expected_revision: i64,
        decision: crate::natural::OwnerDecision,
        now: OffsetDateTime,
    ) -> Result<odin_kernel::DecisionOutcome, DecisionRefusal> {
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
        let mut copies =
            latest_deliveries(&guard, &message.channel_id, &message.owner_user_id, |id| {
                self.preview_kind(id).is_some()
            })?
            .into_iter()
            .filter(|(payload, _)| payload.approval_id == approval_id.as_str());
        let (payload, _) = copies
            .next()
            .ok_or_else(|| DecisionRefusal::Undelivered(approval_id.clone()))?;
        // A reply sent before the question arrived (queued while the owner was away) decides
        // nothing; a reply to any complete copy of it does.
        let earliest_sent = copies
            .map(|(copy, _)| copy.sent_message_id)
            .chain(std::iter::once(payload.sent_message_id.clone()))
            .min_by(|a, b| transport_message_order(a, b).unwrap_or(std::cmp::Ordering::Greater))
            .expect("the newest copy's id is always present");
        if transport_message_order(&message.message_id, &earliest_sent)
            != Some(std::cmp::Ordering::Greater)
        {
            return Err(DecisionRefusal::PredatesDelivery(approval_id.clone()));
        }
        let approval = guard
            .approval(approval_id)
            .map_err(|error| DecisionRefusal::Evidence(error.to_string()))?
            .ok_or_else(|| DecisionRefusal::NotOpen(approval_id.clone()))?;
        if approval.status != ApprovalStatus::Requested {
            return Err(DecisionRefusal::NotOpen(approval_id.clone()));
        }
        if approval.expires_at <= now {
            return Err(DecisionRefusal::Expired(approval_id.clone()));
        }
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
            owner_preview: self.declares_owner_preview(&approval.scope.capability_id),
        };
        match odin_kernel::ApprovalGate::new(&mut guard).decide_consuming_intake(
            approval_id,
            expected_revision,
            ledger_decision,
            &format!("discord-owner:{}", message.owner_user_id),
            now,
            &intake,
        ) {
            Ok(Some(outcome)) => Ok(outcome),
            Ok(None) => Err(DecisionRefusal::IntakeConsumed(approval_id.clone())),
            Err(error) => Err(DecisionRefusal::Ledger(error.to_string())),
        }
    }
}
