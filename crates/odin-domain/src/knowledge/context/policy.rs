use std::collections::BTreeSet;
use std::num::NonZeroU32;

use serde::{Deserialize, Serialize};

use super::tools::ToolName;
use crate::knowledge::retrieval::ModelDescriptor;
use crate::{Digest, DomainError};

const MAX_HTTP_REDIRECT_HOPS: u8 = 3;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SliceContextPolicy {
    pub max_bundle_tokens: NonZeroU32,
    pub reserve_output_tokens: NonZeroU32,
    pub control_tokens: NonZeroU32,
    pub history_tokens: NonZeroU32,
    pub core_tokens: NonZeroU32,
    pub prefetch_tokens: NonZeroU32,
    pub tool_result_tokens: NonZeroU32,
    pub tool_schema_tokens: NonZeroU32,
    pub max_item_tokens: NonZeroU32,
}

impl SliceContextPolicy {
    pub fn validate(&self) -> Result<(), DomainError> {
        let component_tokens = [
            self.control_tokens,
            self.history_tokens,
            self.core_tokens,
            self.prefetch_tokens,
            self.tool_result_tokens,
            self.tool_schema_tokens,
        ]
        .into_iter()
        .map(|tokens| u64::from(tokens.get()))
        .sum::<u64>();
        if component_tokens > u64::from(self.max_bundle_tokens.get()) {
            return Err(invalid_context_policy(
                "component token ceilings exceed max bundle",
            ));
        }
        if self.max_item_tokens > self.max_bundle_tokens {
            return Err(invalid_context_policy("max item tokens exceed max bundle"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SeatContextPolicy {
    pub max_bundle_tokens: NonZeroU32,
    pub core_tokens: NonZeroU32,
    pub prefetch_tokens: NonZeroU32,
    /// The per-turn brain tail; 0 injects only at session start and after
    /// compaction.
    pub per_turn_tokens: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveContextPolicy {
    pub max_bundle_tokens: NonZeroU32,
    pub reserve_output_tokens: NonZeroU32,
    pub control_tokens: NonZeroU32,
    pub history_tokens: NonZeroU32,
    pub core_tokens: NonZeroU32,
    pub prefetch_tokens: NonZeroU32,
    pub tool_result_tokens: NonZeroU32,
    pub tool_schema_tokens: NonZeroU32,
    pub max_item_tokens: NonZeroU32,
    pub effective_model_input_tokens: NonZeroU32,
    pub per_turn_tokens: u32,
}

impl EffectiveContextPolicy {
    pub fn resolve(
        slice: &SliceContextPolicy,
        seat: &SeatContextPolicy,
        model: &ModelDescriptor,
    ) -> Result<Self, DomainError> {
        resolve_context_policy(slice, seat, model)
    }
}

pub fn resolve_context_policy(
    slice: &SliceContextPolicy,
    seat: &SeatContextPolicy,
    model: &ModelDescriptor,
) -> Result<EffectiveContextPolicy, DomainError> {
    slice.validate()?;
    let window = u64::from(model.context_window_tokens.get());
    let max_bundle = slice.max_bundle_tokens.min(seat.max_bundle_tokens);
    let reserve = u64::from(slice.reserve_output_tokens.get());
    // The authored lane is the declared bundle beside the declared
    // reserve. When it fits the window, the reserve is honored verbatim.
    // When it does not, the effective reserve keeps the authored reserve's
    // share of the authored lane, applied proportionally to the window and
    // floored at one token — output is never silently unreserved — and the
    // bundle is capped to the window remainder. The authored input:output
    // ratio is the only scaling authority; no per-seat constant exists.
    let authored_input = u64::from(max_bundle.get()) + reserve;
    let effective_reserve = if authored_input <= window {
        reserve
    } else {
        (window.saturating_mul(reserve) / authored_input).max(1)
    };
    let effective_reserve = u32::try_from(effective_reserve)
        .ok()
        .and_then(NonZeroU32::new)
        .ok_or_else(|| invalid_context_policy("effective output reserve is zero"))?;
    let bundle_budget = window.saturating_sub(u64::from(effective_reserve.get()));
    let effective_bundle = u64::from(max_bundle.get()).min(bundle_budget);
    let effective_bundle = u32::try_from(effective_bundle)
        .ok()
        .and_then(NonZeroU32::new)
        .ok_or_else(|| {
            invalid_context_policy(
                "declared window cannot carry any bundle beside the effective output reserve",
            )
        })?;
    let effective_input = u64::from(effective_bundle.get()) + u64::from(effective_reserve.get());
    let effective_model_input_tokens = u32::try_from(effective_input)
        .ok()
        .and_then(NonZeroU32::new)
        .ok_or_else(|| invalid_context_policy("effective model input is zero or out of range"))?;
    Ok(EffectiveContextPolicy {
        max_bundle_tokens: effective_bundle,
        reserve_output_tokens: effective_reserve,
        control_tokens: slice.control_tokens.min(effective_bundle),
        history_tokens: slice.history_tokens.min(effective_bundle),
        core_tokens: slice
            .core_tokens
            .min(seat.core_tokens)
            .min(effective_bundle),
        prefetch_tokens: slice
            .prefetch_tokens
            .min(seat.prefetch_tokens)
            .min(effective_bundle),
        tool_result_tokens: slice.tool_result_tokens.min(effective_bundle),
        tool_schema_tokens: slice.tool_schema_tokens.min(effective_bundle),
        max_item_tokens: slice.max_item_tokens.min(effective_bundle),
        effective_model_input_tokens,
        per_turn_tokens: seat
            .per_turn_tokens
            .min(slice.prefetch_tokens.get())
            .min(seat.prefetch_tokens.get()),
    })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedirectPolicy {
    pub max_http_hops: u8,
    pub allow_cross_origin: bool,
    pub allow_https_downgrade: bool,
    pub disabled_aliases: BTreeSet<ToolName>,
}

impl RedirectPolicy {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.max_http_hops > MAX_HTTP_REDIRECT_HOPS {
            return Err(invalid_tool_policy("max HTTP hops exceeds three"));
        }
        if self.allow_https_downgrade {
            return Err(invalid_tool_policy("HTTPS downgrade must remain disabled"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AliasRedirectPolicy {
    pub from: ToolName,
    pub to: ToolName,
    pub schema_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SliceToolPolicy {
    pub allow: BTreeSet<ToolName>,
    pub deny: BTreeSet<ToolName>,
    pub redirects: RedirectPolicy,
    pub alias_redirects: BTreeSet<AliasRedirectPolicy>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SeatToolPolicy {
    pub deny: BTreeSet<ToolName>,
    pub redirects: RedirectPolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveToolPolicy {
    pub allow: BTreeSet<ToolName>,
    pub deny: BTreeSet<ToolName>,
    pub redirects: RedirectPolicy,
    pub alias_redirects: BTreeSet<AliasRedirectPolicy>,
}

impl EffectiveToolPolicy {
    pub fn resolve(slice: &SliceToolPolicy, seat: &SeatToolPolicy) -> Result<Self, DomainError> {
        resolve_tool_policy(slice, seat)
    }
}

pub fn resolve_tool_policy(
    slice: &SliceToolPolicy,
    seat: &SeatToolPolicy,
) -> Result<EffectiveToolPolicy, DomainError> {
    slice.redirects.validate()?;
    seat.redirects.validate()?;
    validate_aliases(&slice.alias_redirects)?;
    let deny = slice
        .deny
        .union(&seat.deny)
        .cloned()
        .collect::<BTreeSet<_>>();
    let allow = slice
        .allow
        .difference(&deny)
        .cloned()
        .collect::<BTreeSet<_>>();
    let disabled_aliases = slice
        .redirects
        .disabled_aliases
        .union(&seat.redirects.disabled_aliases)
        .cloned()
        .collect::<BTreeSet<_>>();
    let redirects = RedirectPolicy {
        max_http_hops: slice
            .redirects
            .max_http_hops
            .min(seat.redirects.max_http_hops),
        allow_cross_origin: slice.redirects.allow_cross_origin && seat.redirects.allow_cross_origin,
        allow_https_downgrade: slice.redirects.allow_https_downgrade
            && seat.redirects.allow_https_downgrade,
        disabled_aliases,
    };
    let alias_redirects = slice
        .alias_redirects
        .iter()
        .filter(|alias| {
            !deny.contains(&alias.from)
                && allow.contains(&alias.to)
                && !redirects.disabled_aliases.contains(&alias.from)
        })
        .cloned()
        .collect();
    Ok(EffectiveToolPolicy {
        allow,
        deny,
        redirects,
        alias_redirects,
    })
}

fn validate_aliases(aliases: &BTreeSet<AliasRedirectPolicy>) -> Result<(), DomainError> {
    let sources = aliases
        .iter()
        .map(|alias| &alias.from)
        .collect::<BTreeSet<_>>();
    if aliases
        .iter()
        .any(|alias| alias.from == alias.to || sources.contains(&alias.to))
    {
        return Err(invalid_tool_policy(
            "alias self-redirects, chains, and cycles are forbidden",
        ));
    }
    if sources.len() != aliases.len() {
        return Err(invalid_tool_policy("alias sources must be unique"));
    }
    Ok(())
}

fn invalid_context_policy(reason: impl Into<String>) -> DomainError {
    DomainError::InvalidScope(format!("context policy: {}", reason.into()))
}

fn invalid_tool_policy(reason: impl Into<String>) -> DomainError {
    DomainError::InvalidScope(format!("tool policy: {}", reason.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::huginn::ids::ModelName;
    use crate::knowledge::ids::TokenizerId;

    fn nz(value: u32) -> NonZeroU32 {
        NonZeroU32::new(value).unwrap()
    }
    fn redirects(hops: u8, cross_origin: bool) -> RedirectPolicy {
        RedirectPolicy {
            max_http_hops: hops,
            allow_cross_origin: cross_origin,
            allow_https_downgrade: false,
            disabled_aliases: BTreeSet::new(),
        }
    }

    #[test]
    fn context_resolution_narrows_budgets() {
        let slice = slice_with(100, 20);
        let seat = SeatContextPolicy {
            max_bundle_tokens: nz(70),
            core_tokens: nz(10),
            prefetch_tokens: nz(10),
            per_turn_tokens: 0,
        };
        let model = model_with_window(80);
        let effective = resolve_context_policy(&slice, &seat, &model).unwrap();
        // Authored lane 70 + 20 = 90 exceeds the 80-token window, so the
        // reserve scales proportionally: floor(80 * 20 / 90) = 17, the
        // bundle is capped to the 63-token window remainder, and the
        // effective model input is the full window.
        assert_eq!(effective.max_bundle_tokens, nz(63));
        assert_eq!(effective.reserve_output_tokens, nz(17));
        assert_eq!(effective.prefetch_tokens, nz(10));
        assert_eq!(effective.effective_model_input_tokens, nz(80));
    }

    #[test]
    fn reserve_is_verbatim_when_the_authored_lane_fits_the_window() {
        let slice = slice_with(90, 10);
        let seat = SeatContextPolicy {
            max_bundle_tokens: nz(90),
            core_tokens: nz(10),
            prefetch_tokens: nz(10),
            per_turn_tokens: 0,
        };
        let model = model_with_window(100);
        // Authored lane 90 + 10 = 100 exactly equals the window: the
        // declared reserve is honored without any scaling.
        let effective = resolve_context_policy(&slice, &seat, &model).unwrap();
        assert_eq!(effective.max_bundle_tokens, nz(90));
        assert_eq!(effective.reserve_output_tokens, nz(10));
        assert_eq!(effective.effective_model_input_tokens, nz(100));
    }

    #[test]
    fn reserve_scales_proportionally_preserving_the_authored_ratio() {
        // window 100, bundle 90, reserve 20: floor(100 * 20 / 110) = 18;
        // the bundle caps to the 82-token remainder and keeps the authored
        // input:output shape (82:18 of 100 against 90:20 of 110).
        let slice = slice_with(90, 20);
        let seat = SeatContextPolicy {
            max_bundle_tokens: nz(90),
            core_tokens: nz(10),
            prefetch_tokens: nz(10),
            per_turn_tokens: 0,
        };
        let effective = resolve_context_policy(&slice, &seat, &model_with_window(100)).unwrap();
        assert_eq!(effective.reserve_output_tokens, nz(18));
        assert_eq!(effective.max_bundle_tokens, nz(82));
        assert_eq!(effective.effective_model_input_tokens, nz(100));
    }

    #[test]
    fn scaled_reserve_never_floors_below_one_token() {
        // window 10 against a 1000:1 authored lane: the proportional floor
        // would be zero, so the reserve floors at one token and the bundle
        // takes the remaining nine.
        let slice = slice_with(1000, 1);
        let seat = SeatContextPolicy {
            max_bundle_tokens: nz(1000),
            core_tokens: nz(10),
            prefetch_tokens: nz(10),
            per_turn_tokens: 0,
        };
        let effective = resolve_context_policy(&slice, &seat, &model_with_window(10)).unwrap();
        assert_eq!(effective.reserve_output_tokens, nz(1));
        assert_eq!(effective.max_bundle_tokens, nz(9));
        assert_eq!(effective.effective_model_input_tokens, nz(10));
    }

    fn slice_with(max_bundle: u32, reserve: u32) -> SliceContextPolicy {
        SliceContextPolicy {
            max_bundle_tokens: nz(max_bundle),
            reserve_output_tokens: nz(reserve),
            control_tokens: nz(20),
            history_tokens: nz(20),
            core_tokens: nz(10),
            prefetch_tokens: nz(20),
            tool_result_tokens: nz(10),
            tool_schema_tokens: nz(10),
            max_item_tokens: nz(15),
        }
    }

    fn model_with_window(window: u32) -> ModelDescriptor {
        ModelDescriptor {
            name: ModelName::new("model").unwrap(),
            tokenizer: TokenizerId::new("tokenizer").unwrap(),
            context_window_tokens: nz(window),
        }
    }

    #[test]
    fn deny_wins_over_allow() {
        let read = ToolName::new("Read").unwrap();
        let edit = ToolName::new("Edit").unwrap();
        let bash = ToolName::new("Bash").unwrap();
        let slice = SliceToolPolicy {
            allow: BTreeSet::from([read.clone(), edit.clone(), bash.clone()]),
            deny: BTreeSet::from([edit.clone()]),
            redirects: redirects(2, true),
            alias_redirects: BTreeSet::new(),
        };
        let seat = SeatToolPolicy {
            deny: BTreeSet::from([bash.clone()]),
            redirects: redirects(1, false),
        };
        let effective = resolve_tool_policy(&slice, &seat).unwrap();
        assert_eq!(effective.allow, BTreeSet::from([read]));
        assert_eq!(effective.deny, BTreeSet::from([edit, bash]));
        assert_eq!(effective.redirects.max_http_hops, 1);
        assert!(!effective.redirects.allow_cross_origin);
    }
}
