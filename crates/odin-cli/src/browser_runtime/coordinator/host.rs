use odin_browser::{ActionRequest, ReadKind, ReadRequest, StructuralAction};
use odin_domain::huginn as live;
use odin_domain::{ApprovalId, CapabilityId, CommandId, Digest, Scope, SeatId};
use odin_ledger::approval::Approval;
use odin_omp::host_tools::{
    BrowserCapabilityBinding, BrowserCapabilityOwner, ConsumedHostCommand, HostInvocation,
    HostToolError,
};
use serde::Deserialize;
use serde_json::Value;

use super::protocol::{invalid_request, unavailable};
use super::BrowserCommandCoordinator;
use crate::browser_runtime::dispatch::{
    browser_action_output, browser_arguments, browser_runtime, extract_action_evidence,
    extract_observe_evidence, host_action_request, require_browser_seat_scope,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BrowserObserveInvocation {
    session_id: live::BrowserSessionId,
    kind: ReadKind,
    max_bytes: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BrowserActionInvocation {
    session_id: live::BrowserSessionId,
    expected_revision: Option<u64>,
    action: StructuralAction,
    arguments: Value,
    arguments_digest: Option<Digest>,
    policy_revision: Option<u64>,
    policy_digest: Option<Digest>,
    approval_id: Option<ApprovalId>,
}

/// How one action invocation is bound to the live session.
/// `Explicit` is the caller-supplied binding, verified exactly as
/// before. `Host` is an ordinary interaction that names none of the four
/// binding fields: the host binds the session's current revision, policy
/// and the typed action's own digest — a model cannot compute a blake3
/// digest, and an ordinary interaction spends no human decision on it. A
/// partial binding, or a consequential action without one, is refused.
#[derive(Debug, PartialEq, Eq)]
enum ActionBinding {
    Explicit {
        expected_revision: u64,
        arguments_digest: Digest,
        policy_revision: u64,
        policy_digest: Digest,
    },
    Host,
}

fn action_binding(
    expected_capability: &str,
    input: &BrowserActionInvocation,
) -> Result<ActionBinding, &'static str> {
    match (
        input.expected_revision,
        input.arguments_digest,
        input.policy_revision,
        input.policy_digest,
    ) {
        (
            Some(expected_revision),
            Some(arguments_digest),
            Some(policy_revision),
            Some(policy_digest),
        ) => Ok(ActionBinding::Explicit {
            expected_revision,
            arguments_digest,
            policy_revision,
            policy_digest,
        }),
        (None, None, None, None) if expected_capability == "browser.interact" => {
            Ok(ActionBinding::Host)
        }
        (None, None, None, None) => {
            Err("a consequential browser action must name its full session binding")
        }
        _ => Err(
            "action input names part of its session binding: give expectedRevision, \
             argumentsDigest, policyRevision and policyDigest together, or none of them",
        ),
    }
}

/// One resolved action: the issuer, the typed request, the command digest
/// the host command id derives from, and the exact binding it executes
/// under.
struct ResolvedAction {
    issuer: String,
    request: ActionRequest,
    command_digest: Digest,
    expected_revision: u64,
    arguments_digest: Digest,
}

impl BrowserCommandCoordinator {
    async fn invoke_host_capability(
        &self,
        binding: BrowserCapabilityBinding,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        match binding {
            BrowserCapabilityBinding::Observe => {
                self.invoke_host_observe(binding.id(), invocation).await
            }
            BrowserCapabilityBinding::Interact => {
                self.invoke_host_action(binding.id(), "browser.interact", invocation, None)
                    .await
            }
            BrowserCapabilityBinding::Consequential => {
                self.invoke_host_action(binding.id(), "browser.consequential", invocation, None)
                    .await
            }
            BrowserCapabilityBinding::ObserveEvidence => {
                extract_observe_evidence(binding.id(), invocation.arguments)
            }
            BrowserCapabilityBinding::InteractEvidence
            | BrowserCapabilityBinding::ConsequentialEvidence => {
                extract_action_evidence(binding.id(), invocation.arguments)
            }
        }
    }

    /// Shared preflight/execution validation without touching the browser.
    async fn resolve_host_observe(
        &self,
        tool: &'static str,
        invocation: &HostInvocation,
    ) -> Result<ReadRequest, HostToolError> {
        require_browser_seat_scope(tool, invocation)?;
        let input: BrowserObserveInvocation = serde_json::from_value(invocation.arguments.clone())
            .map_err(|error| browser_arguments(tool, format!("invalid observe input: {error}")))?;
        if input.session_id != self.projection.browser().session_id() {
            return Err(browser_arguments(
                tool,
                "observe input targets a different browser session",
            ));
        }
        ReadRequest::new(input.kind, input.max_bytes)
            .map_err(|error| browser_arguments(tool, error.to_string()))
    }

    async fn invoke_host_observe(
        &self,
        tool: &'static str,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        let request = self.resolve_host_observe(tool, &invocation).await?;
        let read = self
            .projection
            .browser()
            .read(request)
            .await
            .map_err(|error| browser_runtime(tool, error.to_string()))?;
        read.validate()
            .map_err(|error| browser_runtime(tool, error.to_string()))?;
        serde_json::to_value(read)
            .map_err(|error| browser_runtime(tool, format!("cannot serialize read: {error}")))
    }

    pub(super) async fn observe_authenticated(
        &self,
        device: live::DeviceId,
        request: live::BrowserObserveRequest,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        request
            .validate()
            .map_err(|error| invalid_request("browserObserveBound", error))?;
        let session_id = request.session_id;
        let kind = request.kind;
        let read_kind = match kind {
            live::BrowserObserveKind::Text => ReadKind::Text,
            live::BrowserObserveKind::Links => ReadKind::Links,
            live::BrowserObserveKind::Tables => ReadKind::Tables,
            live::BrowserObserveKind::Accessibility => ReadKind::Accessibility,
            live::BrowserObserveKind::SanitizedDom => ReadKind::SanitizedDom,
        };
        let device_seat = device.to_string();
        let seat = SeatId::new(&device_seat).map_err(|_| {
            invalid_request(
                "browserObserver",
                "authenticated device identity cannot bind a browser observer seat",
            )
        })?;
        let payload = self
            .invoke_host_observe(
                "browser_observe",
                HostInvocation {
                    scope: Scope {
                        seat: Some(seat),
                        ..Scope::default()
                    },
                    arguments: serde_json::json!({
                        "sessionId": session_id.clone(),
                        "kind": read_kind,
                        "maxBytes": u64::from(request.max_bytes.get()),
                    }),
                },
            )
            .await
            .map_err(|_| unavailable("browserObserve"))?;
        let encoded = serde_json::to_vec(&payload).map_err(|_| unavailable("browserObserve"))?;
        Ok(live::HuginnResponse::BrowserObservation(
            live::BrowserObservation {
                session_id,
                kind,
                payload,
                payload_digest: Digest::hash(&encoded),
            },
        ))
    }

    /// Resolves scope, approval, policy, and action digest without browser effects.
    /// Execution repeats this check at the permit to reject intervening policy changes.
    async fn resolve_host_action(
        &self,
        tool: &'static str,
        expected_capability: &'static str,
        invocation: &HostInvocation,
    ) -> Result<ResolvedAction, HostToolError> {
        let issuer = require_browser_seat_scope(tool, invocation)?;
        let canonical = serde_json::to_vec(&invocation.arguments)
            .map_err(|error| browser_arguments(tool, format!("invalid action input: {error}")))?;
        let input: BrowserActionInvocation = serde_json::from_value(invocation.arguments.clone())
            .map_err(|error| {
            browser_arguments(tool, format!("invalid action input: {error}"))
        })?;
        if expected_capability == "browser.interact" && input.approval_id.is_some() {
            return Err(browser_arguments(
                tool,
                "ordinary browser interaction does not accept approval authority",
            ));
        }
        if input.session_id != self.projection.browser().session_id() {
            return Err(browser_arguments(
                tool,
                "action input targets a different browser session",
            ));
        }
        let binding = action_binding(expected_capability, &input)
            .map_err(|detail| browser_arguments(tool, detail))?;
        let policy = self.projection.browser().policy().await;
        let request = host_action_request(tool, input.action, input.arguments)?;
        let typed_digest = request.canonical_arguments_digest();
        match binding {
            ActionBinding::Explicit {
                expected_revision,
                arguments_digest,
                policy_revision,
                policy_digest,
            } => {
                if policy.revision() != policy_revision || policy.digest() != policy_digest {
                    return Err(browser_arguments(
                        tool,
                        "action input carries a stale browser policy binding",
                    ));
                }
                if typed_digest != arguments_digest {
                    return Err(browser_arguments(
                        tool,
                        "action arguments digest does not match the typed action",
                    ));
                }
                Ok(ResolvedAction {
                    issuer,
                    request,
                    command_digest: Digest::hash(&canonical),
                    expected_revision,
                    arguments_digest,
                })
            }
            ActionBinding::Host => {
                let expected_revision = self.projection.browser().control_revision().await;
                // A host-bound command is a fresh command each time: its id
                // carries the bound revision, policy and a per-call nonce, so
                // a repeated identical interaction is never answered from an
                // earlier command's journal row.
                let mut bound = canonical;
                bound.extend_from_slice(
                    format!(
                        "|{expected_revision}|{}|{}|{}",
                        policy.revision(),
                        policy.digest(),
                        uuid::Uuid::new_v4()
                    )
                    .as_bytes(),
                );
                Ok(ResolvedAction {
                    issuer,
                    request,
                    command_digest: Digest::hash(&bound),
                    expected_revision,
                    arguments_digest: typed_digest,
                })
            }
        }
    }

    /// `consumed` is the approval the kernel authority already consumed for
    /// exactly this host command, re-verified durably; the action spends it
    /// instead of consuming a decision of its own.
    async fn invoke_host_action(
        &self,
        tool: &'static str,
        expected_capability: &'static str,
        invocation: HostInvocation,
        consumed: Option<Approval>,
    ) -> Result<Value, HostToolError> {
        let ResolvedAction {
            issuer,
            request,
            command_digest,
            expected_revision,
            arguments_digest,
        } = self
            .resolve_host_action(tool, expected_capability, &invocation)
            .await?;
        let input: BrowserActionInvocation = serde_json::from_value(invocation.arguments)
            .map_err(|error| browser_arguments(tool, format!("invalid action input: {error}")))?;
        if let Some(approval) = &consumed {
            if input.approval_id.as_ref() != Some(&approval.approval_id) {
                return Err(browser_arguments(
                    tool,
                    "action input names a different approval than the consumed permit",
                ));
            }
        }
        let command_id = CommandId::new(format!("browser.host:{command_digest}"))
            .map_err(|error| browser_arguments(tool, error.to_string()))?;
        let capability_id = CapabilityId::new(expected_capability)
            .map_err(|error| browser_runtime(tool, error.to_string()))?;
        let context = live::BrowserCommandContext {
            command_id,
            session_id: input.session_id,
            expected_revision,
            arguments_digest,
            approval_id: input.approval_id,
        };
        let response = self
            .execute_action_request(issuer, context, request, Some((capability_id, 1)), consumed)
            .await
            .map_err(|error| browser_runtime(tool, error.to_string()))?;
        browser_action_output(tool, response)
    }

    /// Checks the journaled command, consumed approval, and admitted operation.
    /// Model-supplied approval IDs or decider labels cannot substitute for them.
    fn verify_host_consumed(
        &self,
        tool: &'static str,
        consumed: &ConsumedHostCommand,
        invocation: &HostInvocation,
    ) -> Result<Approval, HostToolError> {
        // Every refusal here precedes preparation: provably nothing ran.
        let refuse = |detail: &str| HostToolError::Unavailable {
            tool,
            reason: detail.to_owned(),
        };
        let target = consumed.target();
        if consumed.capability_id().as_str() != "browser.consequential"
            || consumed.arguments() != &invocation.arguments
            || target.kind != "run"
            || invocation.scope.run.as_ref().map(|run| run.as_str()) != Some(target.id.as_str())
        {
            return Err(refuse(
                "the consumed permit does not bind this browser action",
            ));
        }
        let ledger = self
            .ledger
            .lock()
            .map_err(|_| refuse("the browser ledger is unavailable"))?;
        let unreadable = |_| refuse("the consumed permit records are unreadable");
        let command = ledger
            .command(consumed.command_id())
            .map_err(unreadable)?
            .ok_or_else(|| refuse("the consumed host command is not journaled"))?;
        let approval = match &command.approval_id {
            Some(approval_id) => ledger.approval(approval_id).map_err(unreadable)?,
            None => None,
        }
        .ok_or_else(|| refuse("the consumed host command names no approval"))?;
        let operation = odin_ledger::operation::operation_row_by_id(
            ledger.connection(),
            consumed.operation_id().as_str(),
        )
        .map_err(unreadable)?
        .ok_or_else(|| refuse("the consumed operation is not admitted"))?;
        if command.capability_id != *consumed.capability_id()
            || command.arguments_hash != consumed.arguments_digest()
            || approval.status != odin_domain::ApprovalStatus::Consumed
            || approval.consumed_by_command_id.as_ref() != Some(consumed.command_id())
            || approval.scope != consumed.approval_scope()
            || operation.correlation_id != consumed.correlation_id().as_str()
            || operation.capsule_id != consumed.capsule_id().as_str()
            || operation.capability != consumed.capability_id().as_str()
            || operation.effect_state != odin_domain::operation::EffectState::EffectStarted
        {
            return Err(refuse(
                "the consumed approval or operation does not match this permit",
            ));
        }
        Ok(approval)
    }
}

impl BrowserCapabilityOwner for BrowserCommandCoordinator {
    fn invoke_browser_capability(
        &self,
        binding: BrowserCapabilityBinding,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        let runtime = self.runtime.clone();
        let coordinator = self.clone();
        runtime.block_on(coordinator.invoke_host_capability(binding, invocation))
    }

    fn invoke_consumed(
        &self,
        binding: BrowserCapabilityBinding,
        invocation: HostInvocation,
        consumed: &ConsumedHostCommand,
    ) -> Result<Value, HostToolError> {
        if binding != BrowserCapabilityBinding::Consequential {
            return self.invoke_browser_capability(binding, invocation);
        }
        let approval = self.verify_host_consumed(binding.id(), consumed, &invocation)?;
        let runtime = self.runtime.clone();
        let coordinator = self.clone();
        runtime.block_on(coordinator.invoke_host_action(
            binding.id(),
            "browser.consequential",
            invocation,
            Some(approval),
        ))
    }

    fn preflight_browser_capability(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        binding: BrowserCapabilityBinding,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        // Declared-admissibility gate through the SAME resolution the
        // executed handler runs first — observed before anything is
        // journaled, minted, requested, or consumed. Evidence bindings
        // consume the handler's post-effect output, which does not exist
        // at dispatch time, so their gate is the explicit documented
        // no-op. Execution re-runs the resolution at the permit.
        if binding.is_evidence_extractor() {
            return Ok(());
        }
        let invocation = HostInvocation {
            scope: scope.clone(),
            arguments: arguments.clone(),
        };
        let coordinator = self.clone();
        self.runtime.block_on(async move {
            match binding {
                BrowserCapabilityBinding::Observe => {
                    coordinator
                        .resolve_host_observe(binding.id(), &invocation)
                        .await?;
                }
                BrowserCapabilityBinding::Interact => {
                    coordinator
                        .resolve_host_action(binding.id(), "browser.interact", &invocation)
                        .await?;
                }
                BrowserCapabilityBinding::Consequential => {
                    coordinator
                        .resolve_host_action(binding.id(), "browser.consequential", &invocation)
                        .await?;
                }
                BrowserCapabilityBinding::ObserveEvidence
                | BrowserCapabilityBinding::InteractEvidence
                | BrowserCapabilityBinding::ConsequentialEvidence => {
                    unreachable!("evidence bindings returned the explicit no-gate above")
                }
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invocation(fields: Value) -> BrowserActionInvocation {
        let mut input = serde_json::json!({
            "sessionId": "00000000-0000-4000-8000-000000000008",
            "action": "navigate",
            "arguments": {"url": "https://example.com/"},
        });
        for (key, value) in fields.as_object().unwrap() {
            input[key] = value.clone();
        }
        serde_json::from_value(input).expect("action input decodes")
    }

    #[test]
    fn an_ordinary_interaction_without_a_binding_is_bound_by_the_host() {
        let digest = Digest::hash(b"x").to_string();
        let full = invocation(serde_json::json!({
            "expectedRevision": 3, "argumentsDigest": digest,
            "policyRevision": 1, "policyDigest": digest,
        }));
        assert!(matches!(
            action_binding("browser.interact", &full),
            Ok(ActionBinding::Explicit {
                expected_revision: 3,
                ..
            })
        ));
        let bare = invocation(serde_json::json!({}));
        assert_eq!(
            action_binding("browser.interact", &bare),
            Ok(ActionBinding::Host)
        );
        // A consequential action spends a human decision on an exact
        // binding: the host never fills it.
        assert!(action_binding("browser.consequential", &bare).is_err());
        let partial = invocation(serde_json::json!({"expectedRevision": 3}));
        assert!(action_binding("browser.interact", &partial).is_err());
    }
}
