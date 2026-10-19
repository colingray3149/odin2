//! Authorization-bound controls on the serialized session handle.
//!
//! Every method locks the session state for the operation's duration, so
//! calls from any number of tasks are strictly ordered. This layer performs
//! the mechanical revalidation that gates dispatch: policy and control
//! binding currency, exact approval evidence against the active rule and
//! the prepared request's canonical digest, and outbound payload inspection
//! through the session safety gate. It never mints approvals or policy.

use std::sync::Arc;

use odin_domain::huginn::artifact::{ArtifactKind, ArtifactRef};
use odin_domain::huginn::browser::{
    BrowserDownloadView, BrowserSessionView, BrowserTakeoverCommand, BrowserTakeoverView,
};
use odin_domain::huginn::ids::{BrowserSessionId, DeviceId};
use odin_domain::huginn::RenderKind;
use time::OffsetDateTime;

use crate::capability::{
    ActionArguments, ActionRequest, ActivationStructure, ArtifactPublication, ArtifactPublisher,
    PublicationKind, ReadRequest, SanitizedUrl, TypedRead,
};
use crate::download::QuarantineRecord;
use crate::policy::{ActionRule, BrowserPolicySnapshot, BrowserPolicyUpdate, StructuralAction};
use crate::safety::{BrowserSafetyGate, OutboundBlockReason, OutboundFragment, OutboundVerdict};
use crate::stream::FrameStream;
use crate::takeover::LocalReclaim;

use super::actions::{self, ActionDispatch, ActionDispatchLimits};
use super::reads;
use super::state::remote_takeover_holder;
use super::{
    AbandonedAction, ActionId, BrowserControlSnapshot, BrowserHandle, ConsumedApproval,
    ExecutedAction, PendingAction, PolicyUpdateReport, PreparedActionView, SessionError,
    SessionPhase, TakeoverLeaseExpiry,
};

const SCREENSHOT_MEDIA_TYPE: &str = "image/png";

impl BrowserHandle {
    pub fn session_id(&self) -> BrowserSessionId {
        self.session_id
    }

    /// Bounded frame stream for frame readers (latest record, counters).
    pub fn frames(&self) -> Arc<FrameStream> {
        self.frames.clone()
    }

    /// Latest retained session view, whether or not it has been reported
    /// through [`super::BrowserSession::next_event`]. `None` before the first view
    /// build.
    pub async fn latest_view(&self) -> Option<BrowserSessionView> {
        self.state.lock().await.view.clone()
    }

    pub async fn phase(&self) -> SessionPhase {
        self.state.lock().await.phase
    }

    pub async fn control_revision(&self) -> u64 {
        self.state.lock().await.control_revision
    }

    /// Atomic controller/revision/holder observation for durable restart and
    /// lease-expiry reconciliation.
    pub async fn control_snapshot(&self) -> BrowserControlSnapshot {
        let state = self.state.lock().await;
        BrowserControlSnapshot {
            control_revision: state.control_revision,
            takeover: state.takeover.view(),
            remote_holder: remote_takeover_holder(state.takeover.status()),
            lease_token: state.takeover_lease_token,
            lease_deadline: state.takeover.lease_deadline(),
            pending_action: state.pending.as_ref().map(|pending| pending.id),
        }
    }

    pub async fn policy(&self) -> BrowserPolicySnapshot {
        self.state.lock().await.policy.clone()
    }

    pub async fn takeover_view(&self) -> BrowserTakeoverView {
        self.state.lock().await.takeover.view()
    }

    /// Bounded retained download views, including terminal failures.
    pub async fn download_views(&self) -> Vec<BrowserDownloadView> {
        self.state.lock().await.downloads.views()
    }

    /// Bounded scanner-confirmed quarantine evidence.
    pub async fn quarantine_records(&self) -> Vec<QuarantineRecord> {
        self.state.lock().await.downloads.quarantine_records()
    }

    /// Compare-and-swap policy replacement. A pending action bound to the
    /// superseded (revision, digest) pair is abandoned in the same critical
    /// section and reported, so a stale action can never reach dispatch.
    pub async fn update_policy(
        &self,
        update: BrowserPolicyUpdate,
    ) -> Result<PolicyUpdateReport, SessionError> {
        let mut state = self.state.lock().await;
        state.require_live()?;
        state
            .expire_takeover_lease(OffsetDateTime::now_utc(), true)
            .await?;
        let outcome = state.policy.apply(&update)?;
        let abandoned = if state
            .pending
            .as_ref()
            .is_some_and(|pending| !outcome.snapshot.binding_is_current(&pending.policy))
        {
            let pending = state.pending.as_ref().expect("pending action was present");
            let abandoned_id = pending.id;
            state.release_action_binding(&pending.preflight).await?;
            state.pending = None;
            Some(abandoned_id)
        } else {
            None
        };
        // Commit the new control generation before installing or projecting
        // the policy update; stale hosts fail the durable CAS.
        state.bump_control_revision(OffsetDateTime::now_utc())?;
        state.policy = outcome.snapshot.clone();
        state.observe_view();
        Ok(PolicyUpdateReport {
            snapshot: outcome.snapshot,
            invalidation: outcome.invalidation,
            abandoned,
            control_revision: state.control_revision,
        })
    }

    /// One bounded, always-untrusted typed read against the live page.
    pub async fn read(&self, request: ReadRequest) -> Result<TypedRead, SessionError> {
        let mut state = self.state.lock().await;
        state.require_live()?;
        let deadline = state.limits.read;
        let runtime = state.runtime_mut()?;
        reads::execute_read(runtime.client(), request, deadline).await
    }
    /// Checks only browser-bound payload text against the session's configured
    /// protected values. Selectors and non-payload controls are not content.
    pub async fn validate_outbound(&self, request: &ActionRequest) -> Result<(), SessionError> {
        let state = self.state.lock().await;
        validate_outbound(state.gate.as_ref(), request)
    }

    /// Read-only preparation of one structural action: observational
    /// preflight (document binding, unique target resolution, structural
    /// facts) retained beside the current policy and control bindings. At most
    /// one action may be pending.
    pub async fn prepare_action(
        &self,
        request: ActionRequest,
    ) -> Result<PreparedActionView, SessionError> {
        let mut state = self.state.lock().await;
        state.require_live()?;
        // Control admission: a due lease is retired before the holder's
        // next action can bind, so post-expiry work binds to the advanced
        // control revision, never to the retired lease's generation.
        state
            .expire_takeover_lease(OffsetDateTime::now_utc(), true)
            .await?;
        state.require_durable_admission().await?;
        validate_outbound(state.gate.as_ref(), &request)?;
        admit_navigation_target(state.navigate_hosts.as_ref(), &request)?;
        if let Some(held) = state.pending.as_ref() {
            return Err(SessionError::PendingActionExists { held: held.id });
        }
        let preflight_deadline = state.limits.preflight;
        let runtime = state.runtime_mut()?;
        let preflight =
            actions::preflight_action(runtime.client(), &request, preflight_deadline).await?;
        let policy_action = if request.action == StructuralAction::Activate
            && preflight.descriptor.activation == ActivationStructure::FormSubmission
        {
            StructuralAction::SubmitForm
        } else {
            request.action
        };
        let rule = match state.policy.rule(&policy_action).cloned() {
            Some(rule) => rule,
            None => {
                let _ = state.release_action_binding(&preflight).await;
                return Err(SessionError::PolicyUnmapped {
                    action: policy_action,
                });
            }
        };
        let policy_binding = state.current_policy_binding();
        let control_revision = state.control_revision;

        let action_id = ActionId(state.next_action_id);
        state.next_action_id = state.next_action_id.saturating_add(1);
        let view = PreparedActionView {
            action_id,
            request: request.clone(),
            policy_action,
            descriptor: preflight.descriptor.clone(),
            dom_binding: preflight.dom_binding,
            policy_binding,
            control_revision,
            arguments_digest: request.canonical_arguments_digest(),
            rule,
            prepared_at: OffsetDateTime::now_utc(),
        };
        state.pending = Some(PendingAction {
            id: action_id,
            request,
            policy_action,
            preflight,
            policy: policy_binding,
            control_revision,
        });
        Ok(view)
    }

    /// Executes the pending action after authorization. The caller must
    /// already hold the higher authority's decision (and, where the active
    /// rule demands it, a durably consumed approval). The facade revalidates
    /// policy and control bindings, verifies exact approval evidence, and then
    /// lets the dispatch helper revalidate the DOM binding before mutation.
    /// The pending slot is consumed on every attempted execute. Approval
    /// required/mismatch paths return before dispatch.
    pub async fn execute_action(
        &self,
        action_id: ActionId,
        approval: Option<ConsumedApproval>,
    ) -> Result<ExecutedAction, SessionError> {
        let mut state = self.state.lock().await;
        state.require_live()?;
        // Control admission: a due lease is retired first. A prepared action
        // from the retired generation then meets either the cancelled slot or
        // a stale control binding, never dispatch.
        state
            .expire_takeover_lease(OffsetDateTime::now_utc(), true)
            .await?;
        state.require_durable_admission().await?;
        let pending = match state.pending.take() {
            Some(pending) if pending.id == action_id => pending,
            other => {
                state.pending = other;
                return Err(SessionError::UnknownAction { action_id });
            }
        };
        let authorization =
            (|| {
                if !state.policy.binding_is_current(&pending.policy) {
                    return Err(SessionError::StalePolicyBinding { action_id });
                }
                if pending.control_revision != state.control_revision {
                    return Err(SessionError::StaleControlBinding { action_id });
                }
                let rule = state.policy.rule(&pending.policy_action).ok_or(
                    SessionError::PolicyUnmapped {
                        action: pending.policy_action,
                    },
                )?;
                verify_approval(action_id, rule, &pending.request, approval.as_ref())
            })();
        if let Err(error) = authorization {
            let _ = state.release_action_binding(&pending.preflight).await;
            return Err(error);
        }

        let limits = ActionDispatchLimits {
            deadline: state.limits.dispatch,
            max_screenshot_bytes: state.limits.max_screenshot_bytes,
        };
        let dispatch = {
            let runtime = state.runtime.as_ref().ok_or(SessionError::Stopped)?;
            actions::dispatch_action(
                runtime.client(),
                &pending.request,
                &pending.preflight,
                limits,
            )
            .await
        };
        let dispatch = match dispatch {
            Ok(dispatch) => dispatch,
            Err(error) => {
                let _ = state.release_action_binding(&pending.preflight).await;
                if matches!(error, SessionError::InputUncertain) {
                    state.phase = SessionPhase::InputUncertain;
                    state.observe_view();
                }
                return Err(error);
            }
        };
        let ActionDispatch {
            navigation,
            screenshot,
            target_closed,
        } = dispatch;
        let screenshot = match screenshot {
            Some(bytes) => Some(publish_screenshot(
                state.publisher.as_ref(),
                state.policy.session_id(),
                action_id,
                bytes,
            )?),
            None => None,
        };
        let navigated = navigation.is_some();
        if target_closed {
            state.phase = SessionPhase::TargetClosed;
            state.observe_view();
        } else if navigated || pending.request.action == StructuralAction::Fill {
            // Navigation and text entry both change what the page reports
            // as its location and title; refresh the bounded page facts so
            // the public view follows the observed document.
            state.refresh_page_view().await;
        }
        Ok(ExecutedAction {
            action_id,
            request: pending.request,
            policy_binding: pending.policy,
            control_revision: state.control_revision,
            navigation,
            screenshot,
        })
    }

    /// Retires the pending action without dispatch; available in every
    /// non-stopped phase, since terminalizing a prepared action never needs a
    /// live page.
    pub async fn abandon_action(
        &self,
        action_id: ActionId,
    ) -> Result<AbandonedAction, SessionError> {
        let mut state = self.state.lock().await;
        state.require_active()?;
        let Some(pending) = state.pending.as_ref() else {
            return Err(SessionError::UnknownAction { action_id });
        };
        if pending.id != action_id {
            return Err(SessionError::UnknownAction { action_id });
        }
        state.release_action_binding(&pending.preflight).await?;
        state.pending = None;
        Ok(AbandonedAction { action_id })
    }

    /// Applies an authenticated remote takeover acquire/release command: a
    /// device may act only as itself, and a transition changes controller
    /// truth only — never capability, policy, or approval state.
    pub async fn takeover(
        &self,
        actor: DeviceId,
        command: &BrowserTakeoverCommand,
    ) -> Result<BrowserTakeoverView, SessionError> {
        let mut state = self.state.lock().await;
        state.require_active()?;
        // Control admission: a due lease is retired first, so an acquire or
        // release command is judged against post-expiry truth and a retired
        // holder's replay is rejected instead of honored.
        state
            .expire_takeover_lease(OffsetDateTime::now_utc(), true)
            .await?;
        if matches!(command, BrowserTakeoverCommand::Acquire { .. })
            && state.lease_expiry_unreported.is_some()
        {
            return Err(SessionError::TakeoverExpiryUnobserved);
        }
        let now = OffsetDateTime::now_utc();
        let mut proposed_takeover = state.takeover.clone();
        let view = proposed_takeover.apply_authenticated(actor, command, now)?;
        let next_control_revision = state.next_control_revision()?;
        let lease_token = match command {
            BrowserTakeoverCommand::Acquire { .. } => Some(next_control_revision),
            BrowserTakeoverCommand::Release { .. } => None,
        };
        state.commit_takeover_transition(
            proposed_takeover,
            lease_token,
            next_control_revision,
            now,
        )?;
        state.observe_view();
        Ok(view)
    }

    /// Locally reclaims a held remote controller. Sealed to the local
    /// supervisor; no remotely decoded command can mint this transition.
    pub async fn reclaim_takeover_locally(&self) -> Result<BrowserTakeoverView, SessionError> {
        let mut state = self.state.lock().await;
        state.require_active()?;
        state
            .expire_takeover_lease(OffsetDateTime::now_utc(), true)
            .await?;
        let now = OffsetDateTime::now_utc();
        let mut proposed_takeover = state.takeover.clone();
        proposed_takeover.reclaim_locally(LocalReclaim::local(), now)?;
        let next_control_revision = state.next_control_revision()?;
        state.commit_takeover_transition(proposed_takeover, None, next_control_revision, now)?;
        state.observe_view();
        Ok(state.takeover.view())
    }

    /// Returns a locally reclaimed controller to the available state. Also
    /// sealed against remote commands.
    pub async fn release_takeover_locally(&self) -> Result<BrowserTakeoverView, SessionError> {
        let mut state = self.state.lock().await;
        state.require_active()?;
        state
            .expire_takeover_lease(OffsetDateTime::now_utc(), true)
            .await?;
        let now = OffsetDateTime::now_utc();
        let mut proposed_takeover = state.takeover.clone();
        proposed_takeover.make_available_locally(LocalReclaim::local(), now)?;
        let next_control_revision = state.next_control_revision()?;
        state.commit_takeover_transition(proposed_takeover, None, next_control_revision, now)?;
        state.observe_view();
        Ok(state.takeover.view())
    }

    /// Runs the production takeover-lease expiry path now, as local
    /// supervision: a held lease is retired exactly as the production timer
    /// retires a due one — the in-flight owner action is cancelled, the
    /// holder and its token stop surviving, the takeover revision advances
    /// into the available state, and the control revision advances so
    /// every token bound below it is stale. Returns the exact retirement
    /// facts, or `None` when no lease is held. Sealed against remote
    /// commands, like every local takeover transition.
    pub async fn expire_takeover_lease(&self) -> Result<Option<TakeoverLeaseExpiry>, SessionError> {
        let mut state = self.state.lock().await;
        state.require_active()?;
        state
            .expire_takeover_lease(OffsetDateTime::now_utc(), false)
            .await
    }

    /// Takes the sole lossless expiry observation not already delivered by
    /// [`super::BrowserSession::next_event`]. Exactly one consumer wins; a new lease
    /// is not admitted until this cancellation fact has been consumed.
    pub async fn take_expiry_observation(&self) -> Option<TakeoverLeaseExpiry> {
        self.state.lock().await.lease_expiry_unreported.take()
    }

    /// Deadline at which the currently held takeover control lease expires.
    /// `None` while no lease is held. The production session pump retires the
    /// lease itself once this deadline passes.
    pub async fn takeover_lease_deadline(&self) -> Option<OffsetDateTime> {
        self.state.lock().await.takeover.lease_deadline()
    }
}
/// Composed host scopes require exact equality and cannot be widened by page content.
/// Unscoped sessions admit all navigation. Redirects rely on carrier egress enforcement
/// because the protocol cannot intercept them before navigation.
fn admit_navigation_target(
    navigate_hosts: Option<&std::collections::BTreeSet<String>>,
    request: &ActionRequest,
) -> Result<(), SessionError> {
    let Some(hosts) = navigate_hosts else {
        return Ok(());
    };
    if request.action != StructuralAction::Navigate {
        return Ok(());
    }
    let ActionArguments::Url { url, .. } = &request.arguments else {
        return Ok(());
    };
    // Admission resolves the target through its standards-derived origin; a
    // URL that cannot be sanitized resolves to no declared host and is denied.
    let Ok(sanitized) = SanitizedUrl::parse(url) else {
        return Err(SessionError::NavigateHostDenied);
    };
    let Some(host) = declared_host_of(sanitized.origin()) else {
        return Err(SessionError::NavigateHostDenied);
    };
    if hosts.contains(host) {
        Ok(())
    } else {
        Err(SessionError::NavigateHostDenied)
    }
}

/// The DNS host of a standards origin, lowercased for declaration
/// comparison. Bracketed IPv6 literals are never declared hosts.
fn declared_host_of(origin: &str) -> Option<&str> {
    let rest = origin.split_once("://").map_or(origin, |(_, rest)| rest);
    let authority = rest.split('/').next().unwrap_or(rest);
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if authority.starts_with('[') {
        return None;
    }
    let host = authority.split(':').next().unwrap_or(authority);
    (!host.is_empty()).then_some(host)
}

fn validate_outbound(
    gate: &BrowserSafetyGate,
    request: &ActionRequest,
) -> Result<(), SessionError> {
    let fragment = match &request.arguments {
        ActionArguments::Url { url } => OutboundFragment {
            field: "url",
            text: url,
        },
        ActionArguments::Fill { text, .. } => OutboundFragment {
            field: "text",
            text,
        },
        ActionArguments::Key { key } => OutboundFragment {
            field: "key",
            text: key,
        },
        ActionArguments::None
        | ActionArguments::Selector { .. }
        | ActionArguments::Scroll { .. } => return Ok(()),
    };
    match gate.inspect_outbound(std::slice::from_ref(&fragment)) {
        OutboundVerdict::Allowed => Ok(()),
        OutboundVerdict::Blocked(block) => {
            let (protected_label, code) = match block.reason {
                OutboundBlockReason::ProtectedValue { label } => (Some(label), "protected_value"),
                OutboundBlockReason::Uninspectable { .. } => (None, "uninspectable"),
            };
            Err(SessionError::OutboundBlocked {
                field: block.field,
                protected_label,
                code,
            })
        }
    }
}

/// Verifies approval evidence against the active rule and prepared request.
/// Missing required approval and mismatched approval evidence both return
/// before the dispatch helper receives control.
fn verify_approval(
    action_id: ActionId,
    rule: &ActionRule,
    request: &ActionRequest,
    approval: Option<&ConsumedApproval>,
) -> Result<(), SessionError> {
    match approval {
        None if rule.approval_required => Err(SessionError::ApprovalRequired {
            action: request.action,
        }),
        None => Ok(()),
        Some(approval) => {
            if approval.capability_id != rule.capability_id
                || approval.arguments_digest != request.canonical_arguments_digest()
            {
                Err(SessionError::ApprovalMismatch { action_id })
            } else {
                Ok(())
            }
        }
    }
}

fn publish_screenshot(
    publisher: &dyn ArtifactPublisher,
    session_id: BrowserSessionId,
    action_id: ActionId,
    bytes: Vec<u8>,
) -> Result<ArtifactRef, SessionError> {
    let publication = ArtifactPublication::new(
        session_id,
        // On-demand screenshots are durable publications, distinct from the
        // transient latest-frame projection.
        PublicationKind::Screenshot,
        format!("action-{action_id}-screenshot"),
        SCREENSHOT_MEDIA_TYPE.to_owned(),
        bytes,
    )?;
    let byte_len = publication.byte_len();
    let digest = publication.content_digest;
    let artifact = publisher.publish(publication)?;
    let binding_matches = matches!(artifact.kind, ArtifactKind::Render(RenderKind::RasterImage))
        && artifact.media_type == SCREENSHOT_MEDIA_TYPE
        && artifact.byte_len == byte_len
        && artifact.content_digest == digest;
    if binding_matches {
        Ok(artifact)
    } else {
        Err(SessionError::Transport(
            "published screenshot artifact does not match the captured PNG bytes".to_owned(),
        ))
    }
}

#[cfg(test)]
mod navigation_admission_tests {
    use super::*;

    fn navigate(url: &str) -> ActionRequest {
        ActionRequest {
            action: StructuralAction::Navigate,
            arguments: ActionArguments::Url {
                url: url.to_owned(),
            },
        }
    }

    #[test]
    fn a_declared_pod_browser_navigates_only_to_its_declared_hosts() {
        let hosts = std::collections::BTreeSet::from(["example.com".to_owned()]);
        for allowed in ["https://example.com/", "https://EXAMPLE.com/path?q=1"] {
            assert!(
                admit_navigation_target(Some(&hosts), &navigate(allowed)).is_ok(),
                "{allowed}"
            );
        }
        for denied in [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:18430/",
            "http://10.77.0.11/",
            "https://example.com.evil.test/",
            "https://example.com@evil.test/",
            "http://[::1]/",
            "file:///etc/passwd",
            "not a url",
        ] {
            assert!(
                matches!(
                    admit_navigation_target(Some(&hosts), &navigate(denied)),
                    Err(SessionError::NavigateHostDenied)
                ),
                "{denied} must be refused"
            );
        }
        // No declared scope (the local path) admits navigation as before.
        assert!(admit_navigation_target(None, &navigate("http://10.77.0.11/")).is_ok());
    }
}
