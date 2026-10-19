//! The OMP bridge: one journaled, scope-bound command surface over one
//! supervised pinned-OMP child.
//!
//! [`OmpBridge`] owns the durable side of the pinned RPC protocol (omp @
//! `eab72e8`): every command is caller-IDed with a deterministic id, checked
//! against the live session's ownership epoch and event head, journaled
//! through [`odin_ledger::live`] **before** it is written to the child, and
//! completed exactly once from the child's response. The wire request id is
//! the journaled [`CommandId`], so crash recovery reconciles effects from the
//! journal and never resends a command blindly.
//!
//! One dedicated pump task owns the [`OmpProcess`] value and interleaves
//! outbound writes with [`OmpProcess::next_frame`] through `tokio::select!`.
//! No other code touches the child. Every frame the child emits — including
//! unknown futures, duplicates, late responses, and malformed lines — is
//! classified into a [`FrameClass`] and published as an [`ObservedFrame`] that
//! retains the exact bytes: unmatched and malformed evidence is never
//! discarded, and lifecycle frames are durably appended as normalized live
//! events before they are broadcast to subscribers.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fs::{self, OpenOptions};
use std::future::Future;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use base64::Engine as _;
use odin_domain::{
    CheckpointId, CommandId, Digest, EventId, LaneId, LeaseId, RunId, Scope, SessionId,
};
use odin_ledger::artifact::{ArtifactMetadata, ArtifactRegistration, RetentionClass};
use odin_ledger::checkpoint::{Checkpoint, CheckpointSpec};
use odin_ledger::lease::{self, LeaseRecord, NewHeartbeat, NewLease};
use odin_ledger::live::{
    CompleteLiveCommand, LiveCommand, LiveEvent, LiveSession, LiveSessionExit, NewLiveCommand,
    NewLiveEvent, NewLiveSession,
};
use odin_ledger::{Ledger, LedgerError};
use serde_json::{json, Value};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::Notify;
use tokio::sync::{
    broadcast, mpsc, oneshot, watch, Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore,
};
use tokio::task::JoinSet;

use crate::process::{
    OmpExitRecord, OmpProcess, OmpProcessError, OmpProcessSpec, OmpWorkerLaunch,
    RemoteHarnessFactory, DRAIN_BYTE_CAP, DRAIN_FRAME_CAP,
};

use crate::frames::{DecodedRpcFrame, RpcFrameError};
use crate::host_tools::delegation::{ChildStopCoordinator, ChildStopRecord};
use crate::host_tools::operations::{
    context_policy_digest, session_capsule_id, HostToolOperationError, HostToolOperations,
    SessionOperationBinding, SessionOperationContext,
};
use crate::host_tools::RpcHostToolDefinition;
use crate::uri::{ExecutionBinding, ScopedUriRouter, UriBody, UriContext, UriError, UriResult};

mod api;
mod checkpoint;
mod config;
mod confirmation;
mod contracts;
mod correlation;
mod dispatch;
mod evidence;
mod lifecycle;
mod model_text;
mod observations;
mod pump;
mod recovery;
mod rollover;
mod shared;
mod side_channel;
mod trace;
pub(crate) use model_text::{model_error_text, model_tool_text};
#[cfg(test)]
mod tests;

pub use self::api::{resumable_transcript, set_resume_arg, OmpBridge};
pub use self::checkpoint::CHECKPOINT_COMPATIBILITY_KEY;
pub use self::config::{BridgeBinding, LiveSessionDescriptor, OmpBridgeConfig};
pub use self::contracts::{
    BridgeError, BridgeObserver, BridgeStatus, CheckpointRecord, CommandReceipt, ObserverToken,
    Prompt, RecoveryReport, SideChannelKind, SideChannelOutcome, SideChannelStatus, StopReport,
    StreamingBehavior, OBSERVATION_CHANNEL_CAP,
};
pub use self::lifecycle::LEASE_OBJECT_KIND;
pub use self::observations::{classify_frame, FrameClass, ObservedFrame, TypedFrameFailure};
pub use self::side_channel::{
    DISPATCH_PERMITS, SIDE_CHANNEL_ACTIVE_BYTE_BUDGET, SIDE_CHANNEL_HISTORY_CAP,
};

use self::checkpoint::*;
use self::config::*;
use self::confirmation::*;
use self::contracts::*;
use self::correlation::*;
use self::lifecycle::*;
use self::observations::{ephemeral_token_update, journaled_frame};
use self::pump::*;
use self::recovery::*;
use self::rollover::*;
use self::shared::*;
use self::side_channel::*;
