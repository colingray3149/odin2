//! Sole domain vocabulary for durable capability and operation authority.
//!
//! Shared capability grants, budgets, and effect-state transitions; identifiers come from [`odin_types`].

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use odin_types::{CorrelationId, OperationId};

/// Coarse grant class an admitted capability executes under.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityClass {
    Read,
    Write,
    Execute,
    Network,
}

impl CapabilityClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Execute => "execute",
            Self::Network => "network",
        }
    }
}

impl fmt::Display for CapabilityClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Grant {
    capabilities: BTreeSet<CapabilityClass>,
    stop_budget: u64,
    spend_budget: u64,
}

impl Grant {
    pub fn new(
        capabilities: impl IntoIterator<Item = CapabilityClass>,
        stop_budget: u64,
        spend_budget: u64,
    ) -> Self {
        Self {
            capabilities: capabilities.into_iter().collect(),
            stop_budget,
            spend_budget,
        }
    }

    pub fn capabilities(&self) -> &BTreeSet<CapabilityClass> {
        &self.capabilities
    }

    pub fn stop_budget(&self) -> u64 {
        self.stop_budget
    }

    pub fn spend_budget(&self) -> u64 {
        self.spend_budget
    }

    pub fn allows(&self, class: CapabilityClass) -> bool {
        self.capabilities.contains(&class)
    }
}

/// One declared capability class plus its per-operation budget claim.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RequestCost {
    pub requests: u64,
    pub stops: u64,
    pub spend: u64,
}

/// Authority ceilings over cumulative usage.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Limits {
    pub requests: u64,
    pub stops: u64,
    pub spend: u64,
}

impl Limits {
    pub const fn new(requests: u64, stops: u64, spend: u64) -> Self {
        Self {
            requests,
            stops,
            spend,
        }
    }

    /// Applies one operation cost to cumulative usage and enforces the ceiling.
    pub fn apply(self, usage: Usage, cost: RequestCost) -> Result<Usage, OperationError> {
        let next = Usage {
            requests: add(usage.requests, cost.requests, LimitKind::Requests)?,
            stops: add(usage.stops, cost.stops, LimitKind::Stops)?,
            spend: add(usage.spend, cost.spend, LimitKind::Spend)?,
        };
        require_at_most(next.requests, self.requests, LimitKind::Requests)?;
        require_at_most(next.stops, self.stops, LimitKind::Stops)?;
        require_at_most(next.spend, self.spend, LimitKind::Spend)?;
        Ok(next)
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Usage {
    pub requests: u64,
    pub stops: u64,
    pub spend: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitKind {
    Requests,
    Stops,
    Spend,
}

impl LimitKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requests => "requests",
            Self::Stops => "stops",
            Self::Spend => "spend",
        }
    }
}

/// Durable effect states. The canonical strings are the wire spellings.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectState {
    Prepared,
    EffectStarted,
    Committed,
    Aborted,
    InDoubt,
}

impl EffectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::EffectStarted => "effect_started",
            Self::Committed => "committed",
            Self::Aborted => "aborted",
            Self::InDoubt => "in_doubt",
        }
    }

    /// Parses the canonical state spelling; unknown strings are rejected.
    pub fn parse(raw: &str) -> Result<Self, OperationError> {
        match raw {
            "prepared" => Ok(Self::Prepared),
            "effect_started" => Ok(Self::EffectStarted),
            "committed" => Ok(Self::Committed),
            "aborted" => Ok(Self::Aborted),
            "in_doubt" => Ok(Self::InDoubt),
            _ => Err(OperationError::Invalid(format!(
                "effect state {raw:?} is not a canonical operation state"
            ))),
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Committed | Self::Aborted)
    }

    pub const fn is_nonterminal(self) -> bool {
        !self.is_terminal()
    }
}

impl fmt::Display for EffectState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Allowed effect-state transitions; terminal states cannot transition.
pub fn can_transition(from: EffectState, to: EffectState) -> bool {
    matches!(
        (from, to),
        (EffectState::Prepared, EffectState::EffectStarted)
            | (EffectState::Prepared, EffectState::Aborted)
            | (EffectState::EffectStarted, EffectState::Committed)
            | (EffectState::EffectStarted, EffectState::Aborted)
            | (EffectState::EffectStarted, EffectState::InDoubt)
            | (EffectState::InDoubt, EffectState::Committed)
            | (EffectState::InDoubt, EffectState::Aborted)
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationError {
    LimitExceeded {
        kind: LimitKind,
        limit: u64,
        attempted: u64,
    },
    ArithmeticOverflow(LimitKind),
    UnknownOperation {
        correlation_id: CorrelationId,
    },
    OperationMismatch {
        correlation_id: CorrelationId,
        operation_id: OperationId,
    },
    InvalidTransition {
        state: &'static str,
        action: &'static str,
    },
    Invalid(String),
}

impl fmt::Display for OperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitExceeded {
                kind,
                limit,
                attempted,
            } => write!(
                formatter,
                "{} limit {limit} is below attempted usage {attempted}",
                kind.as_str()
            ),
            Self::ArithmeticOverflow(kind) => {
                write!(formatter, "{} usage arithmetic overflowed", kind.as_str())
            }
            Self::UnknownOperation { correlation_id } => {
                write!(formatter, "correlation {correlation_id} was not prepared")
            }
            Self::OperationMismatch {
                correlation_id,
                operation_id,
            } => write!(
                formatter,
                "correlation {correlation_id} does not belong to operation {operation_id}"
            ),
            Self::InvalidTransition { state, action } => {
                write!(formatter, "cannot {action} an operation in {state} state")
            }
            Self::Invalid(detail) => formatter.write_str(detail),
        }
    }
}

impl std::error::Error for OperationError {}

fn add(left: u64, right: u64, kind: LimitKind) -> Result<u64, OperationError> {
    left.checked_add(right)
        .ok_or(OperationError::ArithmeticOverflow(kind))
}

fn require_at_most(value: u64, limit: u64, kind: LimitKind) -> Result<(), OperationError> {
    if value <= limit {
        Ok(())
    } else {
        Err(OperationError::LimitExceeded {
            kind,
            limit,
            attempted: value,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transition_table_is_total_and_terminal_states_never_move() {
        let states = [
            EffectState::Prepared,
            EffectState::EffectStarted,
            EffectState::Committed,
            EffectState::Aborted,
            EffectState::InDoubt,
        ];
        for from in states {
            for to in states {
                let allowed = can_transition(from, to);
                if from.is_terminal() {
                    assert!(
                        !allowed,
                        "terminal state {from} must never transition to {to}"
                    );
                }
                if allowed {
                    assert!(
                        from.is_nonterminal(),
                        "only nonterminal states may transition: {from} -> {to}"
                    );
                }
            }
        }
        assert!(can_transition(
            EffectState::Prepared,
            EffectState::EffectStarted
        ));
        assert!(can_transition(EffectState::Prepared, EffectState::Aborted));
        assert!(!can_transition(
            EffectState::Prepared,
            EffectState::Committed
        ));
        assert!(can_transition(
            EffectState::EffectStarted,
            EffectState::Committed
        ));
        assert!(can_transition(
            EffectState::EffectStarted,
            EffectState::InDoubt
        ));
        assert!(can_transition(EffectState::InDoubt, EffectState::Committed));
        assert!(can_transition(EffectState::InDoubt, EffectState::Aborted));
    }

    #[test]
    fn limits_apply_costs_and_enforce_ceilings() {
        let limits = Limits::new(2, 0, 1_000);
        let usage = limits
            .apply(
                Usage::default(),
                RequestCost {
                    requests: 1,
                    stops: 0,
                    spend: 400,
                },
            )
            .expect("first operation fits");
        let usage = limits
            .apply(
                usage,
                RequestCost {
                    requests: 1,
                    stops: 0,
                    spend: 400,
                },
            )
            .expect("second operation reaches request ceiling");
        assert!(matches!(
            limits.apply(
                usage,
                RequestCost {
                    requests: 1,
                    stops: 0,
                    spend: 400
                }
            ),
            Err(OperationError::LimitExceeded {
                kind: LimitKind::Requests,
                ..
            })
        ));
    }
}
