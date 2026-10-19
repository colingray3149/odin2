//! Recheck kernel authorization for each request; caller identifiers provide idempotency, not permission.

mod admission;
mod dispatch;
mod host;
mod projection;
mod provisioning;
mod sandbox;
mod store;

pub use dispatch::{authorization_code, rejection_code, rejection_response, TransportRejection};
pub use host::{AuthorityConfig, AuthoritySnapshot};
pub use projection::TransportProjection;
pub use provisioning::{PeerCredentials, Provisioning};
pub use sandbox::{EffectorExecutor, EffectorSandboxBinding, InterpreterBinding};
pub use store::{effect_receipt_at, EffectReceipt, ReceiptEvent, ReceiptFileChange};

use odin_domain::SeatToken;
use odin_kernel::OperationAuthority;
use odin_ledger::{Ledger, LedgerError};
use odin_strict_json::canonicalize;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;

use crate::lifecycle::LifecycleLock;
use crate::{SidecarError, SidecarErrorCode};

const PROJECTION_SCHEMA: &str = "OdinTransportProjection/v1";
const LEGACY_STATE_FILE: &str = "authority-state.json";
const LEGACY_ARCHIVE_SUFFIX: &str = ".archived";
const LEDGER_FILE: &str = "authority-ledger.db";

/// Use host time rather than caller-supplied timestamps for authorization.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

pub fn system_clock() -> Clock {
    Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis() as u64)
            .unwrap_or(0)
    })
}

fn now_utc(now_ms: u64) -> Result<OffsetDateTime, LedgerError> {
    let nanos = i128::from(now_ms) * 1_000_000;
    OffsetDateTime::from_unix_timestamp_nanos(nanos).map_err(|error| {
        LedgerError::invalid_data_caused_by(
            format!("clock reading {now_ms} ms is out of range"),
            error,
        )
    })
}

fn strict_to_serde(value: &odin_strict_json::Value) -> Result<serde_json::Value, SidecarError> {
    let bytes = canonicalize(value)
        .map_err(|error| SidecarError::new(SidecarErrorCode::Protocol, error.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|error| {
        SidecarError::new(
            SidecarErrorCode::Protocol,
            format!("payload arguments are not representable: {error}"),
        )
    })
}

pub struct Sidecar {
    authority: OperationAuthority,
    executor: Arc<EffectorExecutor>,
    ledger: Arc<Mutex<Ledger>>,
    signing_key: Vec<u8>,
    token: SeatToken,
    projection: Arc<TransportProjection>,
    clock: Clock,
    _lifecycle: Arc<LifecycleLock>,
}

#[cfg(test)]
#[path = "authority/tests.rs"]
mod transport_only;
