//! Launch and stop the configured effector through StopAuthority rather than raw process handles.

mod bindings;
mod broker;
mod executor;
mod roundtrip;
mod stop;

pub use bindings::{EffectorSandboxBinding, InterpreterBinding};

use odin_kernel::stop::WorkerChannel;
use odin_kernel::{ExecutorFault, StopAuthority};
use odin_sidecar_protocol::{CapsuleBinding, EffectBehavior};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::authority::store::EffectReceiptStore;
use crate::authority::Clock;
use crate::{SidecarError, SidecarErrorCode};

const EFFECT_POLL: Duration = Duration::from_millis(50);
const EFFECTOR_TX_ID: &str = "sidecar";
const EFFECTOR_WP_ID: &str = "effector";
pub(super) const EVAL_TERM_GRACE_MS: u64 = 1_000;
/// Keep the runtime path short enough for a Unix socket.
const BROKER_RUNTIME_ROOT_PREFIX: &str = "odin-sidecar-broker";
const ROUNDTRIP_BROKER_SHUTDOWN: Duration = Duration::from_secs(10);

pub struct EffectorExecutor {
    program: PathBuf,
    binding_digest: String,
    pub(super) capsule: CapsuleBinding,
    request_ceiling: usize,
    response_ceiling: usize,
    clock: Clock,
    /// Nested sidecars use the parent's StopAuthority instead of a local worker channel.
    channel: Option<WorkerChannel>,
    /// Retain nested worker ledgers beyond each broker's lifetime for recovery.
    scope_store_root: OnceLock<PathBuf>,
    interpreters: Option<InterpreterBinding>,
    sandbox: Option<EffectorSandboxBinding>,
    receipts: OnceLock<Arc<EffectReceiptStore>>,
    stop: OnceLock<Arc<StopAuthority>>,
    post_effect_uncertainty_once: AtomicBool,
}

/// Derive builtin behavior from compiled handlers so callers cannot select executables.
pub(super) fn builtin_behavior(name: &str) -> Option<EffectBehavior> {
    match name {
        "odin_eval.run" => Some(EffectBehavior::Eval),
        "odin_file.edit" => Some(EffectBehavior::Write),
        _ => None,
    }
}

impl EffectorExecutor {
    pub(super) fn arm_post_effect_uncertainty_once(&self) {
        self.post_effect_uncertainty_once
            .store(true, Ordering::SeqCst);
    }

    pub(super) fn worker_channel(&self) -> Option<&WorkerChannel> {
        self.channel.as_ref()
    }

    pub(super) fn bind_receipt_store(
        &self,
        store: Arc<EffectReceiptStore>,
    ) -> Result<(), SidecarError> {
        self.receipts.set(store).map_err(|_| {
            SidecarError::new(
                SidecarErrorCode::Authority,
                "effect receipt store is already bound",
            )
        })
    }

    fn stop_authority(&self) -> Result<&Arc<StopAuthority>, ExecutorFault> {
        self.stop.get().ok_or_else(|| ExecutorFault::Rejected {
            detail: "effector StopAuthority is not bound".to_owned(),
        })
    }

    /// Configure once before use; nested executors have no local broker storage root.
    pub(super) fn bind_stop_authority(
        &self,
        stop: Arc<StopAuthority>,
        scope_store_root: Option<PathBuf>,
    ) -> Result<(), SidecarError> {
        if self.stop.get().is_some() || self.scope_store_root.get().is_some() {
            return Err(SidecarError::new(
                SidecarErrorCode::Authority,
                "effector StopAuthority is already bound",
            ));
        }
        if let Some(root) = scope_store_root {
            self.scope_store_root.set(root).map_err(|_| {
                SidecarError::new(
                    SidecarErrorCode::Authority,
                    "scope store root is already bound",
                )
            })?;
        }
        self.stop.set(stop).map_err(|_| {
            SidecarError::new(
                SidecarErrorCode::Authority,
                "effector StopAuthority is already bound",
            )
        })
    }

    fn scope_store_root(&self) -> Result<&Path, ExecutorFault> {
        self.scope_store_root
            .get()
            .map(PathBuf::as_path)
            .ok_or_else(|| ExecutorFault::Rejected {
                detail: "root scope store root is not bound".to_owned(),
            })
    }
}

fn strict_field<'a>(
    value: &'a odin_strict_json::Value,
    field: &str,
) -> Result<&'a odin_strict_json::Value, ExecutorFault> {
    let odin_strict_json::Value::Object(entries) = value else {
        return Err(ExecutorFault::Rejected {
            detail: format!("builtin arguments must be an object, got {}", value.kind()),
        });
    };
    entries
        .iter()
        .find(|entry| entry.key == field)
        .map(|entry| &entry.value)
        .ok_or_else(|| ExecutorFault::Rejected {
            detail: format!("builtin arguments omit required field {field:?}"),
        })
}

fn require_string(value: &odin_strict_json::Value, field: &str) -> Result<String, ExecutorFault> {
    match strict_field(value, field)? {
        odin_strict_json::Value::String(value) => Ok(value.clone()),
        other => Err(ExecutorFault::Rejected {
            detail: format!(
                "builtin argument {field:?} must be a string, got {}",
                other.kind()
            ),
        }),
    }
}

fn optional_string(
    value: &odin_strict_json::Value,
    field: &str,
) -> Result<Option<String>, ExecutorFault> {
    match strict_field(value, field)? {
        odin_strict_json::Value::Null => Ok(None),
        odin_strict_json::Value::String(value) => Ok(Some(value.clone())),
        other => Err(ExecutorFault::Rejected {
            detail: format!(
                "builtin argument {field:?} must be a string or null, got {}",
                other.kind()
            ),
        }),
    }
}

fn require_u64(value: &odin_strict_json::Value, field: &str) -> Result<u64, ExecutorFault> {
    match strict_field(value, field)? {
        odin_strict_json::Value::UInt(value) => Ok(*value),
        odin_strict_json::Value::Int(value) if *value >= 0 => Ok(*value as u64),
        other => Err(ExecutorFault::Rejected {
            detail: format!(
                "builtin argument {field:?} must be a nonnegative integer, got {}",
                other.kind()
            ),
        }),
    }
}
