//! Case module `subagents_tools` — subagent observation and tool dispatch.
//!
//! Owns cases 11, 12, and 13 of the OMP host-contract conformance suite. The
//! `odin-mock:subagent`, `odin-mock:read`,
//! and `odin-mock:host-tool` fixture directives drive the model side; host
//! tools and URI schemes are dispatched by the bridge assembled through
//! [`crate::probe::CaseContext::bridge_config`].
//!
//! Directive responses are contract-checked for success only: the `data`
//! payload is optional, and only an explicit `agentInvoked: false` rejects a
//! model-visible directive. Invocation is proven by the agent, tool, and
//! side-channel lifecycle frames each case requires, never by response
//! metadata.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use odin_domain::{LaneId, LaneStatus, RunStatus};
use odin_ledger::lane_run;
use odin_ledger::revision;
use serde_json::{json, Value};
use time::OffsetDateTime;
use tokio::sync::broadcast;

use crate::bridge::{
    FrameClass, ObservedFrame, OmpBridge, OmpBridgeConfig, Prompt, SideChannelKind,
    SideChannelOutcome, SideChannelStatus,
};
use crate::frames::DecodedRpcFrame;
use crate::host_tools::lane_status::LaneStatusTool;
use crate::host_tools::operations::{HostToolOperationError, SessionOperationContext};
use crate::probe::{
    CaseContext, CaseEvidence, CaseFailure, CaseOutcome, CleanupOutcome, CleanupReceipt,
    ConformanceCase, ConformanceCaseId, RawRpcDriver, DEFAULT_MODEL_SELECTOR,
};
use crate::uri::{ScopedUriRouter, UriBody, UriContext};

/// Case 11 — subscribe to subagent progress/events, start a subagent, page its
/// messages, and observe roster/state.
pub const SUBAGENT_SUBSCRIPTION: ConformanceCaseId = ConformanceCaseId::new(11);

/// Case 12 — execute a harmless read tool and record tool events.
pub const READ_TOOL_EVENTS: ConformanceCaseId = ConformanceCaseId::new(12);

/// Case 13 — exercise one host-provided tool or URI.
pub const HOST_TOOL_AND_URI: ConformanceCaseId = ConformanceCaseId::new(13);

mod bridge;
mod host_tool;
mod read_tool;
mod shared;
mod subscription;

/// The module's three fixed registration slots.
pub fn cases() -> Vec<Arc<dyn ConformanceCase>> {
    vec![
        Arc::new(subscription::SubagentSubscriptionCase),
        Arc::new(read_tool::ReadToolEventsCase),
        Arc::new(host_tool::HostToolAndUriCase),
    ]
}
