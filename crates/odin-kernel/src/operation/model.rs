//! Persist execution inputs so reconciliation cannot substitute a newer contract or handler.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use odin_domain::knowledge::ToolSchema;
use odin_domain::operation::{EffectState, Grant, RequestCost};
use odin_domain::Digest;
use odin_ledger::operation as store;
use odin_ledger::{Ledger, LedgerError};
use odin_types::{CapsuleId, CapsuleLeaseId, CorrelationId, OperationId};
use serde::Serialize;
use time::OffsetDateTime;

use crate::capability::CapabilityContract;

#[derive(Clone, Debug)]
pub struct Payload {
    pub arguments: serde_json::Value,
    pub digest: Digest,
}

impl Payload {
    pub fn from_arguments(arguments: &serde_json::Value) -> Self {
        let bytes =
            serde_json::to_vec(arguments).expect("serde_json::Value serialization is infallible");
        Self {
            arguments: arguments.clone(),
            digest: Digest::hash(&bytes),
        }
    }
}

/// Effect-free observation of the world an effect will land in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreWorld {
    Absent,
    Digest(Digest),
}

impl PreWorld {
    pub fn encode(self) -> Option<String> {
        match self {
            Self::Absent => None,
            Self::Digest(digest) => Some(digest.to_string()),
        }
    }

    pub fn decode(raw: Option<&str>) -> Self {
        match raw.and_then(|value| Digest::parse(value).ok()) {
            Some(digest) => Self::Digest(digest),
            None => Self::Absent,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reconciliation {
    pub pre_world: PreWorld,
    pub expected_post_world: Option<Digest>,
}

impl Reconciliation {
    pub fn encode(self) -> String {
        serde_json::json!({
            "pre_world": self.pre_world.encode(),
            "expected_post_world":
                self.expected_post_world.map(|digest| digest.to_string()),
        })
        .to_string()
    }

    pub fn decode(raw: &str) -> Self {
        let parsed: serde_json::Value =
            serde_json::from_str(raw).unwrap_or(serde_json::Value::Null);
        let pre_world =
            PreWorld::decode(parsed.get("pre_world").and_then(serde_json::Value::as_str));
        let expected_post_world = parsed
            .get("expected_post_world")
            .and_then(serde_json::Value::as_str)
            .and_then(|value| Digest::parse(value).ok());
        Self {
            pre_world,
            expected_post_world,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ProcessIdentity {
    pub pid: i32,
    pub start_time_ticks: u64,
    pub process_group: i32,
}

/// Cancellation is advisory to the executor, not permission to run or stop an effect.
#[derive(Default)]
pub struct StopHandle {
    cancelled: AtomicBool,
    process: Mutex<Option<ProcessIdentity>>,
}

impl StopHandle {
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn register_process(&self, identity: ProcessIdentity) {
        *self
            .process
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(identity);
    }

    pub fn registered_process(&self) -> Option<ProcessIdentity> {
        *self
            .process
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub kind: String,
    pub id: String,
}

pub(crate) struct PreparedEffectFields {
    pub(super) contract: CapabilityContract,
    pub(super) payload: Payload,
    pub(super) target: Target,
    pub(super) executor_binding: Option<serde_json::Value>,
    pub(super) pre_world: PreWorld,
    pub(super) grant: Grant,
    pub(super) resources: Vec<String>,
    pub(super) lease: Option<CapsuleLeaseId>,
    pub(super) expires_at_ms: u64,
    pub(super) reconciliation: Reconciliation,
}

/// Crate-private construction and move-only consumption prevent callers from duplicating permits.
pub struct PreparedEffect {
    correlation_id: CorrelationId,
    operation_id: OperationId,
    capsule_id: CapsuleId,
    contract: CapabilityContract,
    executor_id: &'static str,
    payload: Payload,
    target: Target,
    executor_binding: Option<serde_json::Value>,
    pre_world: PreWorld,
    grant: Grant,
    resources: Vec<String>,
    lease: Option<CapsuleLeaseId>,
    expires_at_ms: u64,
    reconciliation: Reconciliation,
    stop: Arc<StopHandle>,
    // Only live dispatch supplies child authorization; timeout is not identity expiry.
    child_custody_context: Option<(Arc<Mutex<Ledger>>, Clock, u64, Digest)>,
}

/// Executors must refuse permits naming another executor.
impl PreparedEffect {
    pub const OMP_HOST_EXECUTOR: &'static str = "odin.omp.host_tools";
    pub const SIDECAR_EXECUTOR: &'static str = "odin.sidecar.effector";
}

impl fmt::Debug for PreparedEffect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedEffect")
            .field("correlation_id", &self.correlation_id.as_str())
            .field("operation_id", &self.operation_id.as_str())
            .field("capsule_id", &self.capsule_id.as_str())
            .field("capability", &self.contract.id.as_str())
            .field("executor", &self.executor_id)
            .field("payload_digest", &self.payload.digest.to_string())
            .field("target", &self.target)
            .field("has_executor_binding", &self.executor_binding.is_some())
            .field("pre_world", &self.pre_world)
            .field("grant", &self.grant)
            .field("resources", &self.resources)
            .field("lease", &self.lease)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish_non_exhaustive()
    }
}

impl PreparedEffect {
    pub(crate) fn new(
        correlation_id: CorrelationId,
        operation_id: OperationId,
        capsule_id: CapsuleId,
        executor_id: &'static str,
        fields: PreparedEffectFields,
        stop: Arc<StopHandle>,
    ) -> Self {
        Self {
            correlation_id,
            operation_id,
            capsule_id,
            contract: fields.contract,
            executor_id,
            payload: fields.payload,
            target: fields.target,
            executor_binding: fields.executor_binding,
            pre_world: fields.pre_world,
            grant: fields.grant,
            resources: fields.resources,
            lease: fields.lease,
            expires_at_ms: fields.expires_at_ms,
            reconciliation: fields.reconciliation,
            stop,
            child_custody_context: None,
        }
    }

    pub(super) fn with_child_custody_context(
        mut self,
        store: Arc<Mutex<Ledger>>,
        clock: Clock,
        identity_expires_at_ms: u64,
        request_digest: Digest,
    ) -> Self {
        self.child_custody_context = Some((store, clock, identity_expires_at_ms, request_digest));
        self
    }

    /// Use the original dispatch store and clock, never values supplied by an executor.
    pub(crate) fn child_custody_context(&self) -> Option<(Arc<Mutex<Ledger>>, Clock, u64, Digest)> {
        self.child_custody_context
            .as_ref()
            .map(|(store, clock, expiry, request)| {
                (Arc::clone(store), Arc::clone(clock), *expiry, *request)
            })
    }

    pub fn correlation_id(&self) -> &CorrelationId {
        &self.correlation_id
    }

    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    pub fn capsule_id(&self) -> &CapsuleId {
        &self.capsule_id
    }

    pub fn contract(&self) -> &CapabilityContract {
        &self.contract
    }

    pub fn executor_id(&self) -> &'static str {
        self.executor_id
    }

    pub fn payload(&self) -> &Payload {
        &self.payload
    }

    pub fn target(&self) -> &Target {
        &self.target
    }

    /// Executors must validate this opaque context before use.
    pub fn executor_binding(&self) -> Option<&serde_json::Value> {
        self.executor_binding.as_ref()
    }

    pub fn pre_world(&self) -> PreWorld {
        self.pre_world
    }

    pub fn grant(&self) -> &Grant {
        &self.grant
    }

    pub fn resources(&self) -> &[String] {
        &self.resources
    }

    pub fn lease(&self) -> Option<&CapsuleLeaseId> {
        self.lease.as_ref()
    }

    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    pub fn reconciliation(&self) -> Reconciliation {
        self.reconciliation
    }

    pub fn stop_handle(&self) -> Arc<StopHandle> {
        Arc::clone(&self.stop)
    }
}

/// `post_world` is an effect-free observation after execution, when one is available.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectOutcome {
    pub post_world: Option<Digest>,
    pub evidence_digest: Digest,
    pub stop: Option<StopOutcome>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StopOutcome {
    pub stopped: bool,
    pub process: Option<ProcessIdentity>,
    pub survivors: Vec<ProcessIdentity>,
}

/// Rejected effects abort; uncertain effects remain in-doubt, retaining any captured output evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutorFault {
    Rejected {
        detail: String,
    },
    Uncertain {
        detail: String,
    },
    PostEffectUncertain {
        detail: String,
        /// Captured output evidence, never a predicted post-world hash.
        evidence_digest: Digest,
    },
}

impl fmt::Display for ExecutorFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected { detail } => write!(formatter, "effect rejected: {detail}"),
            Self::Uncertain { detail } => write!(formatter, "effect uncertain: {detail}"),
            Self::PostEffectUncertain {
                detail,
                evidence_digest,
            } => write!(
                formatter,
                "effect landed but stayed uncertain: {detail}; captured evidence {evidence_digest}"
            ),
        }
    }
}

impl std::error::Error for ExecutorFault {}

/// Executors must reject permits whose `executor_id` differs from their own.
pub trait OperationExecutor: Send + Sync {
    fn id(&self) -> &'static str;

    fn declared_pre_world(
        &self,
        contract: &CapabilityContract,
        payload: &Payload,
    ) -> Result<Option<PreWorld>, ExecutorFault>;

    fn observe(
        &self,
        contract: &CapabilityContract,
        payload: &Payload,
    ) -> Result<PreWorld, ExecutorFault>;

    fn expected_post_world(
        &self,
        contract: &CapabilityContract,
        payload: &Payload,
    ) -> Result<Option<Digest>, ExecutorFault>;

    fn execute(&self, effect: PreparedEffect) -> Result<EffectOutcome, ExecutorFault>;
}

#[derive(Clone, Debug)]
pub struct InvokeRequest {
    pub capsule_id: CapsuleId,
    pub correlation_id: CorrelationId,
    /// The caller ceiling only restricts the reservation; it is not the amount charged.
    pub requested_ceiling: RequestCost,
}

/// Charge one invocation; spend stays zero because provider accounting does not reserve it here.
pub(super) fn charged_invocation() -> RequestCost {
    RequestCost {
        requests: 1,
        stops: 0,
        spend: 0,
    }
}

pub(super) fn charged_stop() -> RequestCost {
    RequestCost {
        requests: 0,
        stops: 1,
        spend: 0,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationDecision {
    pub correlation_id: CorrelationId,
    pub operation_id: OperationId,
    pub capsule_id: CapsuleId,
    pub state: EffectState,
    pub replay: bool,
}

/// Report the executor observation without letting the transport decide settlement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconcileOutcome {
    pub decision: OperationDecision,
    pub observed: PreWorld,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapsuleOutcome {
    pub capsule_id: CapsuleId,
    pub drained: u64,
    pub replay: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StopIntentOutcome {
    pub correlation_id: CorrelationId,
    pub operation_id: Option<OperationId>,
    pub state: String,
    pub replay: bool,
    pub process: Option<ProcessIdentity>,
}

#[derive(Debug)]
pub enum OperationRejection {
    Unauthorized,
    IdentityExpired {
        expires_at_ms: u64,
    },
    AuthorityMismatch {
        correlation_id: CorrelationId,
    },
    /// Open leases require the same seat and session with a strictly newer token for renewal.
    CapsuleAuthorityMismatch {
        capsule_id: CapsuleId,
    },
    UnknownCapability {
        capability: String,
    },
    NotAdmitted {
        capability: String,
        detail: String,
    },
    BudgetDenied {
        detail: String,
    },
    DuplicateConflict {
        correlation_id: CorrelationId,
    },
    UnknownOperation {
        correlation_id: CorrelationId,
    },
    OperationMismatch {
        correlation_id: CorrelationId,
    },
    CapsuleClosed {
        capsule_id: CapsuleId,
    },
    CapsuleBlocked {
        capsule_id: CapsuleId,
        blocked: u64,
    },
    PreWorldMismatch {
        detail: String,
    },
    PayloadDigestMismatch,
    SchemaInvalid {
        detail: String,
    },
    Durable(LedgerError),
    Executor(ExecutorFault),
}

impl fmt::Display for OperationRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized => {
                formatter.write_str("operation authority requires a fresh verified seat token")
            }
            Self::IdentityExpired { expires_at_ms } => {
                write!(formatter, "authority expired at {expires_at_ms} ms")
            }
            Self::AuthorityMismatch { correlation_id } => write!(
                formatter,
                "authority does not match the recorded authority of {correlation_id}"
            ),
            Self::CapsuleAuthorityMismatch { capsule_id } => write!(
                formatter,
                "capsule {capsule_id} is leased under a different verified authority"
            ),
            Self::UnknownCapability { capability } => {
                write!(formatter, "capability {capability:?} is not admitted")
            }
            Self::NotAdmitted { capability, detail } => {
                write!(
                    formatter,
                    "capability {capability:?} is not admissible: {detail}"
                )
            }
            Self::BudgetDenied { detail } => formatter.write_str(detail),
            Self::DuplicateConflict { correlation_id } => write!(
                formatter,
                "correlation {correlation_id} already names a different request"
            ),
            Self::UnknownOperation { correlation_id } => {
                write!(formatter, "correlation {correlation_id} was not prepared")
            }
            Self::OperationMismatch { correlation_id } => write!(
                formatter,
                "correlation {correlation_id} does not belong to this operation"
            ),
            Self::CapsuleClosed { capsule_id } => {
                write!(formatter, "capsule {capsule_id} is closed")
            }
            Self::CapsuleBlocked {
                capsule_id,
                blocked,
            } => write!(
                formatter,
                "capsule {capsule_id} has {blocked} unresolved operations and stays open"
            ),
            Self::PreWorldMismatch { detail } => formatter.write_str(detail),
            Self::PayloadDigestMismatch => {
                formatter.write_str("authorized argument digest does not match the payload")
            }
            Self::SchemaInvalid { detail } => write!(
                formatter,
                "payload is not valid against the input schema: {detail}"
            ),
            Self::Durable(error) => write!(formatter, "durable authority failure: {error}"),
            Self::Executor(fault) => write!(formatter, "{fault}"),
        }
    }
}

impl From<LedgerError> for OperationRejection {
    fn from(error: LedgerError) -> Self {
        Self::Durable(error)
    }
}

impl std::error::Error for OperationRejection {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Durable(error) => Some(error),
            Self::Executor(fault) => Some(fault),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseMode {
    Drain,
    Abort,
}

impl CloseMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Drain => "drain",
            Self::Abort => "abort",
        }
    }
}

pub(super) type AuthorityResult<T> = Result<T, OperationRejection>;

/// Carry rejections in `Ok` so transaction errors remain distinguishable from refusals.
pub(super) enum Step<T> {
    Done(T),
    Reject(OperationRejection),
}

impl<T> Step<T> {
    pub(super) fn into_result(self) -> AuthorityResult<T> {
        match self {
            Step::Done(value) => Ok(value),
            Step::Reject(rejection) => Err(rejection),
        }
    }
}

/// Authorization uses the configured clock, never caller-supplied timestamps.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Reconcile from the journaled inputs so later policy or handler changes cannot replace them.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedBinding {
    pub contract: CapabilityContract,
    pub executor_id: String,
    pub handler_key: String,
    pub extractor_key: String,
    pub target: Target,
    /// Executor-private host context covered by this record's binding digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executor_binding: Option<serde_json::Value>,
    pub pre_world: PreWorldRecord,
    pub expected_post_world: Option<String>,
    pub lease: Option<String>,
    pub expires_at_ms: u64,
    pub snapshot_revision: i64,
    pub snapshot_digest: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreWorldRecord {
    pub absent: bool,
    pub digest: Option<String>,
}

pub struct RecordedBinding {
    pub contract: CapabilityContract,
    pub executor_id: String,
    pub handler_key: String,
    pub extractor_key: String,
    /// Digest-verified executor context recovered from the durable record.
    pub executor_binding: Option<serde_json::Value>,
    pub reconciliation: Reconciliation,
    pub raw: String,
}

impl RecordedBinding {
    /// Reject altered or unknown fields rather than substituting execution inputs.
    pub fn parse(row: &store::OperationRow) -> Option<Self> {
        if row.binding_digest != Digest::hash(row.prepared_binding.as_bytes()).to_string() {
            return None;
        }
        let binding: PreparedBinding = serde_json::from_str(&row.prepared_binding).ok()?;
        let pre_world = if binding.pre_world.absent {
            PreWorld::Absent
        } else {
            let digest = binding.pre_world.digest.as_deref()?;
            PreWorld::Digest(Digest::parse(digest).ok()?)
        };
        let reconciliation = Reconciliation {
            pre_world,
            expected_post_world: binding
                .expected_post_world
                .as_deref()
                .and_then(|value| Digest::parse(value).ok()),
        };
        Some(Self {
            contract: binding.contract,
            executor_id: binding.executor_id,
            handler_key: binding.handler_key,
            extractor_key: binding.extractor_key,
            executor_binding: binding.executor_binding,
            reconciliation,
            raw: row.prepared_binding.clone(),
        })
    }
}

/// Share validation with approval gates so approval is not spent on an invalid payload.
pub fn validate_input_arguments(
    schema: &ToolSchema,
    arguments: &serde_json::Value,
) -> AuthorityResult<()> {
    validate_input_payload(schema, &Payload::from_arguments(arguments))
}

pub(super) fn validate_input_payload(
    schema: &ToolSchema,
    payload: &Payload,
) -> AuthorityResult<()> {
    let validator = input_validator(schema)?;
    // Return schema violations so callers can correct the rejected payload.
    let violations: Vec<String> = validator
        .iter_errors(&payload.arguments)
        .take(3)
        .map(|error| {
            let at = error.instance_path.to_string();
            if at.is_empty() {
                error.to_string()
            } else {
                format!("{at}: {error}")
            }
        })
        .collect();
    if violations.is_empty() {
        Ok(())
    } else {
        Err(OperationRejection::SchemaInvalid {
            detail: format!(
                "arguments rejected by the capability input schema: {}",
                violations.join("; ")
            ),
        })
    }
}

/// Compiled validators keyed by schema digest; a hit never serves a different schema.
static INPUT_VALIDATORS: LazyLock<Mutex<HashMap<Digest, Arc<jsonschema::Validator>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn input_validator(schema: &ToolSchema) -> AuthorityResult<Arc<jsonschema::Validator>> {
    let digest = schema.digest();
    if let Some(validator) = INPUT_VALIDATORS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&digest)
    {
        return Ok(Arc::clone(validator));
    }
    let validator = Arc::new(
        jsonschema::options()
            .build(schema.canonical_json())
            .map_err(|error| OperationRejection::SchemaInvalid {
                detail: format!("declared input schema is not a valid schema: {error}"),
            })?,
    );
    INPUT_VALIDATORS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(digest, Arc::clone(&validator));
    Ok(validator)
}

pub(super) fn utc(now_ms: u64) -> AuthorityResult<OffsetDateTime> {
    let seconds = i64::try_from(now_ms / 1_000).map_err(|error| {
        OperationRejection::Durable(LedgerError::invalid_data_caused_by(
            "operation timestamp exceeds the representable range",
            error,
        ))
    })?;
    let nanos = u32::try_from((now_ms % 1_000) * 1_000_000).map_err(|error| {
        OperationRejection::Durable(LedgerError::invalid_data_caused_by(
            "operation timestamp exceeds the representable range",
            error,
        ))
    })?;
    OffsetDateTime::from_unix_timestamp(seconds)
        .and_then(|moment| moment.replace_nanosecond(nanos))
        .map_err(|error| {
            OperationRejection::Durable(LedgerError::invalid_data_caused_by(
                "operation timestamp exceeds the representable range",
                error,
            ))
        })
}
