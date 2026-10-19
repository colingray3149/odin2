//! Typed Playwright-worker action preparation and dispatch.
//!
//! This layer is deliberately mechanical. Rust validates requests and retains
//! the worker's opaque preflight binding, while policy, approval, capability,
//! journaling, and publication stay with the session actor. Every mutating
//! operation is a closed [`WorkerAction`] and can be dispatched only with the
//! binding returned by a completed read-only preflight.

use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use odin_domain::Digest;
use time::OffsetDateTime;

use crate::capability::{
    classify_activation, ActionArguments, ActionRequest, ActivationStructure, CapabilityError,
    DomBinding, ElementStructure, NavigationObservation, StructuralDescriptor,
};
use crate::policy::StructuralAction;
use crate::worker::{
    Ack, DispatchParams, DispatchResult, PreflightParams, PreflightResult, ReleaseBindingParams,
    WorkerAction, WorkerCaller, WorkerElementStructure, WorkerError, WorkerErrorCode, WorkerMethod,
    WorkerNavigation,
};

use super::SessionError;

const MAX_BINDING_ID_BYTES: usize = 256;
const MAX_STRUCTURAL_TOKEN_BYTES: usize = 64;
const SHA256_TOKEN_BYTES: usize = 64;
const ERROR_RELEASE_DEADLINE: Duration = Duration::from_secs(2);
const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

/// Read-only facts retained for one prepared dispatch.
///
/// The binding id is an opaque worker-issued reference to the one retained
/// preflight handle. It is never interpreted or promoted into authority by
/// Rust. The document token and request digest are retained independently so
/// both sides can reject a stale or substituted dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ActionPreflight {
    pub(super) descriptor: StructuralDescriptor,
    pub(super) dom_binding: DomBinding,
    binding_id: String,
    document_token: String,
    request_digest: Digest,
}

/// Mechanical limits needed while dispatching one authorized action.
#[derive(Clone, Copy, Debug)]
pub(super) struct ActionDispatchLimits {
    pub(super) deadline: Duration,
    pub(super) max_screenshot_bytes: usize,
}

/// Raw mechanism result. Screenshot bytes are published and bound to an
/// artifact by the session owner; this layer never fabricates an artifact.
#[derive(Debug)]
pub(super) struct ActionDispatch {
    pub(super) navigation: Option<NavigationObservation>,
    pub(super) screenshot: Option<Vec<u8>>,
    pub(super) target_closed: bool,
}

/// Resolve a unique selector, inspect its structure, and retain an opaque
/// worker binding without performing any page mutation.
pub(super) async fn preflight_action(
    worker: &WorkerCaller,
    request: &ActionRequest,
    deadline: Duration,
) -> Result<ActionPreflight, SessionError> {
    request.validate()?;
    let request_digest = request.canonical_arguments_digest();
    let params = PreflightParams {
        request_digest: request_digest.to_string(),
        selector: action_selector(request).map(str::to_owned),
    };
    let result: PreflightResult = worker
        .call(WorkerMethod::Preflight, &params, deadline)
        .await
        .map_err(|error| worker_failure(error, "browser action preflight"))?;

    let release_id = result.binding_id.clone();
    match validate_preflight(request, request_digest, result) {
        Ok(preflight) => Ok(preflight),
        Err(error) => {
            if !release_id.is_empty() {
                let _ = release_binding_id(worker, &release_id, ERROR_RELEASE_DEADLINE).await;
            }
            Err(error)
        }
    }
}

fn validate_preflight(
    request: &ActionRequest,
    request_digest: Digest,
    result: PreflightResult,
) -> Result<ActionPreflight, SessionError> {
    validate_binding_id(&result.binding_id)?;
    let document_digest = digest_worker_token(&result.document_token, "preflight document token")?;
    let target = result.target.map(validate_element_structure).transpose()?;
    if target.is_some() != action_selector(request).is_some() {
        return Err(stale(
            "worker preflight target did not match the request selector",
        ));
    }
    if request.action == StructuralAction::SubmitForm
        && classify_activation(target.as_ref()) != ActivationStructure::FormSubmission
    {
        return Err(CapabilityError::InvalidRequest {
            reason: "submitForm selector is not a form-submitting control".to_owned(),
        }
        .into());
    }

    let descriptor = StructuralDescriptor::new(request.action, target)?;
    descriptor.validate()?;
    Ok(ActionPreflight {
        descriptor,
        dom_binding: DomBinding {
            document_digest,
            observed_at: OffsetDateTime::now_utc(),
        },
        binding_id: result.binding_id,
        document_token: result.document_token,
        request_digest,
    })
}

/// Dispatch one already-authorized action through the closed worker protocol.
///
/// Local binding validation happens before constructing the mutation request.
/// The worker then consumes the binding and rechecks its retained handle,
/// request digest, document token, and structural facts immediately before the
/// closed action. No policy, approval, capability, or protected value is sent.
pub(super) async fn dispatch_action(
    worker: &WorkerCaller,
    request: &ActionRequest,
    expected: &ActionPreflight,
    limits: ActionDispatchLimits,
) -> Result<ActionDispatch, SessionError> {
    let result = dispatch_checked(worker, request, expected, limits).await;
    if result.is_err() {
        // Dispatch consumes bindings, but release is intentionally idempotent:
        // it also covers validation failures before the worker call and
        // responses lost after consumption without masking the primary error.
        let _ = release_action_binding(worker, expected, ERROR_RELEASE_DEADLINE).await;
    }
    result
}

async fn dispatch_checked(
    worker: &WorkerCaller,
    request: &ActionRequest,
    expected: &ActionPreflight,
    limits: ActionDispatchLimits,
) -> Result<ActionDispatch, SessionError> {
    request.validate()?;
    if limits.max_screenshot_bytes == 0 {
        return Err(CapabilityError::InvalidRequest {
            reason: "screenshot byte bound must be non-zero".to_owned(),
        }
        .into());
    }
    validate_retained_binding(request, expected)?;

    let max_screenshot_bytes = u64::try_from(limits.max_screenshot_bytes).map_err(|_| {
        CapabilityError::InvalidRequest {
            reason: "screenshot byte bound cannot be represented on the worker wire".to_owned(),
        }
    })?;
    let params = DispatchParams {
        binding_id: expected.binding_id.clone(),
        request_digest: expected.request_digest.to_string(),
        document_token: expected.document_token.clone(),
        expected_target: expected
            .descriptor
            .target
            .as_ref()
            .map(worker_element_structure),
        action: worker_action(request)?,
        max_screenshot_bytes,
    };
    let result: DispatchResult = worker
        .call(WorkerMethod::Dispatch, &params, limits.deadline)
        .await
        .map_err(|error| worker_failure(error, "authorized browser action dispatch"))?;
    validate_dispatch_result(request.action, result, limits.max_screenshot_bytes)
}

/// Idempotently release the worker handle retained for an abandoned or
/// invalidated action. Unknown and already-consumed ids are acknowledged by
/// the worker, so callers may safely use this on every cleanup path.
pub(super) async fn release_action_binding(
    worker: &WorkerCaller,
    preflight: &ActionPreflight,
    deadline: Duration,
) -> Result<(), SessionError> {
    release_binding_id(worker, &preflight.binding_id, deadline).await
}

async fn release_binding_id(
    worker: &WorkerCaller,
    binding_id: &str,
    deadline: Duration,
) -> Result<(), SessionError> {
    let params = ReleaseBindingParams {
        binding_id: binding_id.to_owned(),
    };
    let ack: Ack = worker
        .call(WorkerMethod::ReleaseBinding, &params, deadline)
        .await
        .map_err(|error| worker_failure(error, "browser action binding release"))?;
    if !ack.acknowledged {
        return Err(SessionError::Transport(
            "playwright worker did not acknowledge action binding release".to_owned(),
        ));
    }
    Ok(())
}

fn validate_retained_binding(
    request: &ActionRequest,
    expected: &ActionPreflight,
) -> Result<(), SessionError> {
    validate_binding_id(&expected.binding_id)?;
    let computed_document =
        digest_worker_token(&expected.document_token, "retained document token")?;
    if computed_document != expected.dom_binding.document_digest {
        return Err(stale(
            "retained document token does not match the DOM binding",
        ));
    }
    if expected.request_digest != request.canonical_arguments_digest() {
        return Err(stale("action arguments changed after preflight"));
    }
    if expected.descriptor.action != request.action {
        return Err(stale("structural action changed after preflight"));
    }
    expected.descriptor.validate()?;
    if expected.descriptor.target.is_some() != action_selector(request).is_some() {
        return Err(stale("retained target does not match the request selector"));
    }
    if let Some(target) = expected.descriptor.target.as_ref() {
        validate_element_structure(worker_element_structure(target))?;
    }
    Ok(())
}

fn validate_dispatch_result(
    action: StructuralAction,
    mut result: DispatchResult,
    max_screenshot_bytes: usize,
) -> Result<ActionDispatch, SessionError> {
    let expects_navigation = matches!(
        action,
        StructuralAction::Navigate
            | StructuralAction::Back
            | StructuralAction::Forward
            | StructuralAction::Reload
    );
    let expects_screenshot = action == StructuralAction::Screenshot;
    let expects_close = action == StructuralAction::Close;
    if result.navigation.is_some() != expects_navigation
        || result.screenshot_base64.is_some() != expects_screenshot
        || result.target_closed != expects_close
    {
        return Err(SessionError::Transport(
            "playwright worker returned a result for a different action shape".to_owned(),
        ));
    }

    let navigation = result
        .navigation
        .take()
        .map(navigation_observation)
        .transpose()?;
    let screenshot = result
        .screenshot_base64
        .take()
        .map(|encoded| decode_screenshot(&encoded, max_screenshot_bytes))
        .transpose()?;
    Ok(ActionDispatch {
        navigation,
        screenshot,
        target_closed: result.target_closed,
    })
}

fn navigation_observation(
    navigation: WorkerNavigation,
) -> Result<NavigationObservation, SessionError> {
    let exact_url_digest = digest_worker_token(&navigation.url_token, "navigation URL token")?;
    let document_digest =
        digest_worker_token(&navigation.document_token, "navigation document token")?;
    NavigationObservation::from_sanitized_parts(
        navigation.display_url,
        navigation.origin,
        exact_url_digest,
        Some(document_digest),
    )
    .map_err(Into::into)
}

fn decode_screenshot(encoded: &str, limit: usize) -> Result<Vec<u8>, SessionError> {
    let max_encoded = limit.saturating_add(2).saturating_div(3).saturating_mul(4);
    if encoded.len() > max_encoded {
        let minimum_decoded = encoded
            .len()
            .saturating_div(4)
            .saturating_mul(3)
            .saturating_sub(2);
        return Err(CapabilityError::BoundExceeded {
            limit: limit as u64,
            requested: minimum_decoded as u64,
        }
        .into());
    }
    let bytes = STANDARD.decode(encoded.as_bytes()).map_err(|_| {
        SessionError::Transport(
            "playwright worker returned an invalid screenshot encoding".to_owned(),
        )
    })?;
    if bytes.len() > limit {
        return Err(CapabilityError::BoundExceeded {
            limit: limit as u64,
            requested: bytes.len() as u64,
        }
        .into());
    }
    if !bytes.starts_with(PNG_SIGNATURE) {
        return Err(SessionError::Transport(
            "playwright worker returned a screenshot that is not PNG".to_owned(),
        ));
    }
    Ok(bytes)
}

fn worker_action(request: &ActionRequest) -> Result<WorkerAction, SessionError> {
    let action = match (&request.action, &request.arguments) {
        (StructuralAction::Navigate, ActionArguments::Url { url }) => {
            WorkerAction::Navigate { url: url.clone() }
        }
        (StructuralAction::Back, ActionArguments::None) => WorkerAction::Back,
        (StructuralAction::Forward, ActionArguments::None) => WorkerAction::Forward,
        (StructuralAction::Reload, ActionArguments::None) => WorkerAction::Reload,
        (StructuralAction::Fill, ActionArguments::Fill { selector, text }) => WorkerAction::Fill {
            selector: selector.selector.clone(),
            text: text.clone(),
        },
        (StructuralAction::Activate, ActionArguments::Selector { selector }) => {
            WorkerAction::Activate {
                selector: selector.selector.clone(),
            }
        }
        (StructuralAction::SubmitForm, ActionArguments::Selector { selector }) => {
            WorkerAction::SubmitForm {
                selector: selector.selector.clone(),
            }
        }
        (StructuralAction::PressKey, ActionArguments::Key { key }) => {
            WorkerAction::PressKey { key: key.clone() }
        }
        (StructuralAction::Scroll, ActionArguments::Scroll { delta_x, delta_y }) => {
            WorkerAction::Scroll {
                delta_x: *delta_x,
                delta_y: *delta_y,
            }
        }
        (StructuralAction::Screenshot, ActionArguments::None) => WorkerAction::Screenshot,
        (StructuralAction::Close, ActionArguments::None) => WorkerAction::Close,
        _ => {
            return Err(CapabilityError::InvalidRequest {
                reason: "action arguments changed after validation".to_owned(),
            }
            .into());
        }
    };
    Ok(action)
}

fn action_selector(request: &ActionRequest) -> Option<&str> {
    match &request.arguments {
        ActionArguments::Selector { selector } | ActionArguments::Fill { selector, .. } => {
            Some(selector.selector.as_str())
        }
        _ => None,
    }
}

fn worker_element_structure(target: &ElementStructure) -> WorkerElementStructure {
    WorkerElementStructure {
        tag: target.tag.clone(),
        input_type: target.input_type.clone(),
        in_form: target.in_form,
    }
}

fn validate_element_structure(
    target: WorkerElementStructure,
) -> Result<ElementStructure, SessionError> {
    validate_structural_token(&target.tag, "target tag")?;
    if target.tag != target.tag.to_ascii_lowercase() {
        return Err(SessionError::Transport(
            "playwright worker returned a non-canonical target tag".to_owned(),
        ));
    }
    if let Some(input_type) = target.input_type.as_deref() {
        validate_structural_token(input_type, "target input type")?;
        if input_type != input_type.to_ascii_lowercase() {
            return Err(SessionError::Transport(
                "playwright worker returned a non-canonical input type".to_owned(),
            ));
        }
    }

    let valid_shape = match target.tag.as_str() {
        "input" => target
            .input_type
            .as_deref()
            .is_some_and(|kind| INPUT_TYPES.contains(&kind)),
        "button" => matches!(
            target.input_type.as_deref(),
            Some("submit" | "reset" | "button")
        ),
        _ => target.input_type.is_none() && !target.in_form,
    };
    if !valid_shape {
        return Err(SessionError::Transport(
            "playwright worker returned inconsistent target structure".to_owned(),
        ));
    }

    Ok(ElementStructure {
        tag: target.tag,
        input_type: target.input_type,
        in_form: target.in_form,
    })
}

fn validate_structural_token(value: &str, field: &'static str) -> Result<(), SessionError> {
    if value.is_empty() {
        return Err(SessionError::Transport(format!(
            "playwright worker returned an empty {field}"
        )));
    }
    if value.len() > MAX_STRUCTURAL_TOKEN_BYTES {
        return Err(CapabilityError::BoundExceeded {
            limit: MAX_STRUCTURAL_TOKEN_BYTES as u64,
            requested: value.len() as u64,
        }
        .into());
    }
    if value
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(SessionError::Transport(format!(
            "playwright worker returned an invalid {field}"
        )));
    }
    Ok(())
}

fn validate_binding_id(binding_id: &str) -> Result<(), SessionError> {
    if !binding_id_is_valid(binding_id) {
        return Err(SessionError::Transport(
            "playwright worker returned an invalid action binding id".to_owned(),
        ));
    }
    Ok(())
}

fn binding_id_is_valid(binding_id: &str) -> bool {
    !binding_id.is_empty()
        && binding_id.len() <= MAX_BINDING_ID_BYTES
        && !binding_id.chars().any(char::is_control)
}

fn digest_worker_token(token: &str, field: &'static str) -> Result<Digest, SessionError> {
    if token.len() != SHA256_TOKEN_BYTES
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(SessionError::Transport(format!(
            "playwright worker returned an invalid {field}"
        )));
    }
    Ok(Digest::hash(token.as_bytes()))
}

fn worker_failure(error: WorkerError, operation: &'static str) -> SessionError {
    match error {
        WorkerError::UncertainMutation { .. }
        | WorkerError::Remote {
            code: WorkerErrorCode::InputStateUncertain | WorkerErrorCode::OutcomeUncertain,
            ..
        } => SessionError::InputUncertain,
        WorkerError::DeadlineExceeded
        | WorkerError::Remote {
            code: WorkerErrorCode::DeadlineExceeded,
            ..
        } => SessionError::Timeout { operation },
        WorkerError::Remote {
            code: WorkerErrorCode::DocumentChanged,
            ..
        } => stale("document changed after action preparation"),
        WorkerError::Remote {
            code:
                WorkerErrorCode::StaleBinding
                | WorkerErrorCode::BindingMissing
                | WorkerErrorCode::BindingIdMismatch
                | WorkerErrorCode::TargetDisconnected,
            ..
        } => stale("selector resolved to a different DOM node"),
        WorkerError::Remote {
            code: WorkerErrorCode::TargetStructureChanged,
            ..
        } => stale("target structure changed after action preparation"),
        WorkerError::Remote {
            code: WorkerErrorCode::ExpectedTargetMismatch,
            ..
        } => stale("prepared target evidence changed after action preparation"),
        WorkerError::Remote {
            code: WorkerErrorCode::RequestDigestMismatch,
            ..
        } => stale("action arguments changed after action preparation"),
        WorkerError::Remote {
            code: WorkerErrorCode::AmbiguousSelector | WorkerErrorCode::MissingTarget,
            ..
        } => CapabilityError::InvalidRequest {
            reason: "selector must resolve to exactly one element".to_owned(),
        }
        .into(),
        WorkerError::Remote {
            code: WorkerErrorCode::BrowserClosed,
            ..
        } => SessionError::TargetClosed,
        _ => SessionError::Transport(format!("{operation} failed: {error}")),
    }
}

fn stale(reason: &str) -> SessionError {
    CapabilityError::StaleBinding {
        reason: reason.to_owned(),
    }
    .into()
}

/// Valid reflected `input.type` keywords. The worker canonicalizes missing or
/// invalid content attributes to the corresponding IDL default before return.
const INPUT_TYPES: &[&str] = &[
    "hidden",
    "text",
    "search",
    "tel",
    "url",
    "email",
    "password",
    "date",
    "month",
    "week",
    "time",
    "datetime-local",
    "number",
    "range",
    "color",
    "checkbox",
    "radio",
    "file",
    "submit",
    "image",
    "reset",
    "button",
];
