//! Registry model-card field validation.

use super::super::model::{
    ModelCardToml, CHAT_CAPABILITY, CLAUDE_ROUTE, EMBEDDING_CAPABILITY, GATEWAY_ROUTE,
    LOCAL_ACCOUNT, MODEL_ROUTES, MODEL_TIERS,
};
use super::super::object::RegistryObject;
use super::{fail, require_nonempty, validate_common};
use crate::RegistryFinding;

pub(super) fn validate_model_card(
    object: &RegistryObject,
    value: &ModelCardToml,
    findings: &mut Vec<RegistryFinding>,
) {
    validate_common(
        object,
        &value.schema,
        value.kind,
        &value.description,
        findings,
    );
    require_nonempty(object, "strengths", &value.strengths, findings);
    fn card_segment(
        object: &RegistryObject,
        findings: &mut Vec<RegistryFinding>,
        field: &str,
        id: &str,
    ) -> Option<String> {
        let Some((provider, model)) = id.split_once('/') else {
            findings.push(fail(
                object,
                "model-card-id",
                format!("{field} {id:?} must be provider/model"),
            ));
            return None;
        };
        if provider.is_empty()
            || !provider
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            findings.push(fail(
                object,
                "model-card-id",
                format!("{field} {id:?} provider must be lowercase letters, digits or dashes"),
            ));
            return None;
        }
        if model.is_empty()
            || model.len() > 256
            || !model
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'))
        {
            findings.push(fail(
                object,
                "model-card-id",
                format!("{field} {id:?} model must be 1..256 ASCII letters/digits or . _ : -"),
            ));
            return None;
        }
        Some(model.to_owned())
    }
    if let Some(model) = card_segment(object, findings, "id", &value.id) {
        if object.id != model {
            findings.push(fail(
                object,
                "model-card-folder",
                format!(
                    "model card folder must be named {model:?} to match id {:?}",
                    value.id
                ),
            ));
        }
    }
    if !MODEL_ROUTES.contains(&value.route.as_str()) {
        findings.push(fail(
            object,
            "model-card-route",
            format!(
                "route must be one of {:?}, found {:?}",
                MODEL_ROUTES, value.route
            ),
        ));
    }
    match value.capability.as_str() {
        CHAT_CAPABILITY => match value.tier.as_deref() {
            Some(tier) if !MODEL_TIERS.contains(&tier) => findings.push(fail(
                object,
                "model-card-tier",
                format!("tier must be one of {MODEL_TIERS:?}, found {tier:?}"),
            )),
            None => findings.push(fail(
                object,
                "model-card-tier",
                "chat cards must declare tier frontier, everyday or fast-cheap",
            )),
            _ => {}
        },
        EMBEDDING_CAPABILITY => {
            if value.tier.is_some() {
                findings.push(fail(
                    object,
                    "model-card-tier",
                    "embedding cards declare no tier",
                ));
            }
            if value.order.is_some() {
                findings.push(fail(
                    object,
                    "model-card-order",
                    "embedding cards declare no class order",
                ));
            }
        }
        other => findings.push(fail(
            object,
            "model-card-capability",
            format!(
                "capability must be {CHAT_CAPABILITY:?} or {EMBEDDING_CAPABILITY:?}, found {other:?}"
            ),
        )),
    }
    let is_local = value.account.as_deref() == Some(LOCAL_ACCOUNT);
    if value.family && !is_local {
        findings.push(fail(
            object,
            "model-card-family",
            format!(
                "family cards must use account {LOCAL_ACCOUNT:?}, found {:?}",
                value.account
            ),
        ));
    }
    if value.route == GATEWAY_ROUTE && !is_local && value.served.is_none() {
        findings.push(fail(
            object,
            "model-card-served",
            "gateway cards must declare the upstream served provider/model; \
             only local accounts may omit it",
        ));
    }
    if value.seats
        && value.route == CLAUDE_ROUTE
        && value
            .served
            .as_deref()
            .is_none_or(|served| !served.contains('/'))
    {
        findings.push(fail(
            object,
            "model-card-served",
            "a seat-open claude-code card declares served as provider/model, the model the harness passes to claude --model",
        ));
    }
    if value.route != GATEWAY_ROUTE && value.order.is_some() {
        findings.push(fail(
            object,
            "model-card-order",
            "only gateway class lanes carry a class order",
        ));
    }
    for fallback in &value.fallbacks {
        if Some(fallback.as_str()) == value.lane() {
            findings.push(fail(
                object,
                "model-card-fallback",
                format!("card {:?} cannot name itself as a fallback", value.id),
            ));
        }
    }
    if let Some(window) = &value.window {
        if window.context_tokens.is_none() && window.max_output_tokens.is_none() {
            findings.push(fail(
                object,
                "model-card-window",
                "window must declare context_tokens or max_output_tokens",
            ));
        }
        if window.context_tokens == Some(0) || window.max_output_tokens == Some(0) {
            findings.push(fail(
                object,
                "model-card-window",
                "window tokens must be positive",
            ));
        }
    }
    if let Some(thinking) = &value.thinking {
        if thinking.default.is_none()
            && thinking.levels.is_empty()
            && thinking.temperature.is_none()
        {
            findings.push(fail(
                object,
                "model-card-thinking",
                "thinking must declare default, levels or temperature",
            ));
        }
        if let Some(default) = thinking.default.as_deref() {
            if !thinking.levels.is_empty() && !thinking.levels.iter().any(|level| level == default)
            {
                findings.push(fail(
                    object,
                    "model-card-thinking",
                    format!("thinking default {default:?} must be one of the declared levels"),
                ));
            }
        }
        if thinking
            .temperature
            .is_some_and(|temperature| !(0.0..=2.0).contains(&temperature))
        {
            findings.push(fail(
                object,
                "model-card-thinking",
                "thinking temperature must be within 0..=2",
            ));
        }
    }
    if let Some(wire) = value.wire.as_deref() {
        if wire.is_empty() || !wire.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            findings.push(fail(
                object,
                "model-card-wire",
                "wire must be a non-empty API name like responses or chat-completions",
            ));
        }
    }
}
