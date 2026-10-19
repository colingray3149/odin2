//! Derive effector arguments from authorized requests and record execution observations.

use odin_domain::Digest;
use odin_kernel::{
    CapabilityContract, EffectOutcome, ExecutorFault, HandlerBinding, OperationExecutor, Payload,
    PreWorld, PreparedEffect, StopHandle,
};
use odin_sidecar_protocol::{
    CapsuleBinding, EffectBehavior, EffectRequest, EffectResponse, EFFECT_MAX_REQUEST_BYTES,
    EFFECT_MAX_RESPONSE_BYTES,
};
use odin_types::{CapsuleId, OperationId};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use crate::authority::store::{EffectReceipt, ReceiptEvent, ReceiptFileChange, RECEIPT_SCHEMA};
use crate::authority::Clock;
use crate::{SidecarError, SidecarErrorCode};

use super::{
    builtin_behavior, optional_string, require_string, require_u64, strict_field, EffectorExecutor,
    EffectorSandboxBinding, InterpreterBinding, EVAL_TERM_GRACE_MS,
};

const OBSERVE_TIMEOUT_MS: u64 = 10_000;
/// Separate eval scratch by operation inside the capsule.
const EVAL_SCRATCH_DIR: &str = ".odin-eval";
const BINDING_DIGEST_LEN: usize = 64;

struct ReceiptTimeline {
    dispatched_at_ms: u64,
    response_received_at_ms: u64,
    recorded_at_ms: u64,
}

fn parse_binding_digest(raw: &str) -> Result<String, SidecarError> {
    let hex = raw.strip_prefix("blake3:").unwrap_or(raw);
    if hex.len() != BINDING_DIGEST_LEN
        || !hex
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(SidecarError::new(
            SidecarErrorCode::Authority,
            "compiled effector binding digest must be 64 lowercase hex characters",
        ));
    }
    Ok(hex.to_owned())
}

impl EffectorExecutor {
    pub fn new(
        program: PathBuf,
        binding_digest: impl Into<String>,
        capsule: CapsuleBinding,
        clock: Clock,
        channel: odin_kernel::stop::WorkerChannel,
    ) -> Result<Self, SidecarError> {
        CapsuleId::new(&capsule.capsule_id).map_err(|error| {
            SidecarError::new(
                SidecarErrorCode::Authority,
                format!("authenticated capsule id rejected: {error}"),
            )
        })?;
        Ok(Self {
            program,
            binding_digest: parse_binding_digest(&binding_digest.into())?,
            capsule,
            request_ceiling: EFFECT_MAX_REQUEST_BYTES,
            response_ceiling: EFFECT_MAX_RESPONSE_BYTES,
            clock,
            channel: Some(channel),
            scope_store_root: OnceLock::new(),
            interpreters: None,
            sandbox: None,
            receipts: OnceLock::new(),
            stop: OnceLock::new(),
            post_effect_uncertainty_once: AtomicBool::new(false),
        })
    }

    /// Nested launch gets StopAuthority from the parent rather than configuring a manager channel.
    pub fn new_nested(
        program: PathBuf,
        binding_digest: impl Into<String>,
        capsule: CapsuleBinding,
        clock: Clock,
    ) -> Result<Self, SidecarError> {
        CapsuleId::new(&capsule.capsule_id).map_err(|error| {
            SidecarError::new(
                SidecarErrorCode::Authority,
                format!("authenticated capsule id rejected: {error}"),
            )
        })?;
        Ok(Self {
            program,
            binding_digest: parse_binding_digest(&binding_digest.into())?,
            capsule,
            request_ceiling: EFFECT_MAX_REQUEST_BYTES,
            response_ceiling: EFFECT_MAX_RESPONSE_BYTES,
            clock,
            channel: None,
            scope_store_root: OnceLock::new(),
            interpreters: None,
            sandbox: None,
            receipts: OnceLock::new(),
            stop: OnceLock::new(),
            post_effect_uncertainty_once: AtomicBool::new(false),
        })
    }

    /// Use configured interpreters instead of resolving programs from the environment.
    pub fn with_interpreters(mut self, interpreters: InterpreterBinding) -> Self {
        self.interpreters = Some(interpreters);
        self
    }

    /// Sandbox paths are host configuration, not request arguments.
    pub fn with_sandbox(mut self, sandbox: EffectorSandboxBinding) -> Self {
        self.sandbox = Some(sandbox);
        self
    }

    /// Inject uncertainty after persisting the receipt to exercise post-effect failure handling.
    pub fn with_post_effect_uncertainty_once(mut self) -> Self {
        self.post_effect_uncertainty_once = AtomicBool::new(true);
        self
    }

    fn behavior(&self, contract: &CapabilityContract) -> Result<EffectBehavior, ExecutorFault> {
        match &contract.handler {
            HandlerBinding::Builtin { name } => {
                builtin_behavior(name).ok_or_else(|| ExecutorFault::Rejected {
                    detail: format!(
                        "capability {} binds builtin {name:?} with no canonical effector behavior",
                        contract.id
                    ),
                })
            }
            HandlerBinding::Exec { executable, argv } => {
                if Path::new(executable) != self.program.as_path() {
                    return Err(ExecutorFault::Rejected {
                        detail: format!(
                            "capability {} names executable {executable:?}; only the exact compiled effector {:?} executes here",
                            contract.id,
                            self.program.display()
                        ),
                    });
                }
                let [verb] = argv.as_slice() else {
                    return Err(ExecutorFault::Rejected {
                        detail: format!(
                            "capability {} handler argv must name exactly one compiled behavior",
                            contract.id
                        ),
                    });
                };
                let behavior = match verb.as_str() {
                    "execute" => EffectBehavior::Execute,
                    "verify" => EffectBehavior::Verify,
                    "preimage" => EffectBehavior::Preimage,
                    "read" => EffectBehavior::Read,
                    "write" => EffectBehavior::Write,
                    "diff" => EffectBehavior::Diff,
                    other => {
                        return Err(ExecutorFault::Rejected {
                            detail: format!(
                                "capability {} handler behavior {other:?} is not compiled",
                                contract.id
                            ),
                        })
                    }
                };
                Ok(behavior)
            }
        }
    }

    fn arguments(&self, payload: &Payload) -> Result<odin_strict_json::Value, ExecutorFault> {
        let bytes =
            serde_json::to_vec(&payload.arguments).map_err(|error| ExecutorFault::Rejected {
                detail: format!("payload arguments are not representable: {error}"),
            })?;
        odin_strict_json::decode(&bytes, self.request_ceiling).map_err(|error| {
            ExecutorFault::Rejected {
                detail: format!("payload arguments are not strict canonical JSON: {error}"),
            }
        })
    }

    /// Translate builtin arguments; Exec arguments already match their configured schema.
    fn effect_arguments(
        &self,
        contract: &CapabilityContract,
        payload: &Payload,
        operation_id: Option<&OperationId>,
    ) -> Result<odin_strict_json::Value, ExecutorFault> {
        let arguments = self.arguments(payload)?;
        match &contract.handler {
            HandlerBinding::Exec { .. } => Ok(arguments),
            HandlerBinding::Builtin { name } => match builtin_behavior(name) {
                Some(EffectBehavior::Write) => Self::file_edit_arguments(&arguments),
                Some(EffectBehavior::Eval) => self.eval_arguments(&arguments, operation_id),
                _ => Err(ExecutorFault::Rejected {
                    detail: format!(
                        "capability {} binds builtin {name:?} with no canonical effector behavior",
                        contract.id
                    ),
                }),
            },
        }
    }

    /// Exact-text edits avoid resending the entire file; whole-file writes remain a separate mode.
    pub(in crate::authority) fn file_edit_arguments(
        arguments: &odin_strict_json::Value,
    ) -> Result<odin_strict_json::Value, ExecutorFault> {
        use odin_strict_json::Value as Json;
        let path = require_string(arguments, "path")?;
        let has = |field: &str| strict_field(arguments, field).is_ok();
        let whole = has("content") || has("preimage_sha256");
        let replace = has("old_text") || has("new_text");
        let mut entries = vec![("path".to_owned(), Json::String(path))];
        match (whole, replace) {
            (false, true) => {
                let old = require_string(arguments, "old_text")?;
                let new = require_string(arguments, "new_text")?;
                if old.is_empty() {
                    return Err(ExecutorFault::Rejected {
                        detail: "old_text is empty; name the exact text to replace".to_owned(),
                    });
                }
                entries.push((
                    "old_hex".to_owned(),
                    Json::String(odin_types::hash::hex_encode(old.as_bytes())),
                ));
                entries.push((
                    "new_hex".to_owned(),
                    Json::String(odin_types::hash::hex_encode(new.as_bytes())),
                ));
            }
            (true, false) => {
                let content = require_string(arguments, "content")?;
                let preimage = optional_string(arguments, "preimage_sha256")?;
                entries.push((
                    "content_hex".to_owned(),
                    Json::String(odin_types::hash::hex_encode(content.as_bytes())),
                ));
                if let Some(preimage) = preimage {
                    entries.push(("preimage_sha256".to_owned(), Json::String(preimage)));
                }
            }
            (true, true) | (false, false) => {
                return Err(ExecutorFault::Rejected {
                    detail: "capsule_file_edit takes old_text and new_text (replace one exact \
                             occurrence) or content and preimage_sha256 (the whole file), \
                             not both or neither"
                        .to_owned(),
                })
            }
        }
        Ok(Json::Object(
            entries
                .into_iter()
                .map(|(key, value)| odin_strict_json::ObjectEntry { key, value })
                .collect(),
        ))
    }

    /// Derive the interpreter and scratch path from host configuration and the operation ID.
    pub(in crate::authority) fn eval_arguments(
        &self,
        arguments: &odin_strict_json::Value,
        operation_id: Option<&OperationId>,
    ) -> Result<odin_strict_json::Value, ExecutorFault> {
        use odin_strict_json::Value as Json;
        let interpreter = require_string(arguments, "interpreter")?;
        let binding = self
            .interpreters
            .as_ref()
            .ok_or_else(|| ExecutorFault::Rejected {
                detail: "eval interpreter binding is absent; the sidecar host must provision "
                    .to_owned()
                    + "--python-bin/--bun-bin before builtin eval effects run",
            })?;
        let program = binding
            .program(&interpreter)
            .ok_or_else(|| ExecutorFault::Rejected {
                detail: format!(
                    "eval interpreter {interpreter:?} is outside the closed python|bun enum"
                ),
            })?;
        let source = require_string(arguments, "source")?;
        let source_sha256 = require_string(arguments, "source_sha256")?;
        let timeout_ms = require_u64(arguments, "timeout_ms")?;
        let max_stdout_bytes = require_u64(arguments, "max_stdout_bytes")?;
        let max_stderr_bytes = require_u64(arguments, "max_stderr_bytes")?;
        let mut entries = vec![
            (
                "interpreter_program".to_owned(),
                Json::String(program.display().to_string()),
            ),
            ("source".to_owned(), Json::String(source)),
            ("source_sha256".to_owned(), Json::String(source_sha256)),
        ];
        if let Some(operation_id) = operation_id {
            entries.push((
                "scratch".to_owned(),
                Json::String(format!("{EVAL_SCRATCH_DIR}/{}", operation_id.as_str())),
            ));
        }
        entries.push(("timeout_ms".to_owned(), Json::UInt(timeout_ms)));
        entries.push(("term_grace_ms".to_owned(), Json::UInt(EVAL_TERM_GRACE_MS)));
        entries.push(("max_stdout_bytes".to_owned(), Json::UInt(max_stdout_bytes)));
        entries.push(("max_stderr_bytes".to_owned(), Json::UInt(max_stderr_bytes)));
        Ok(Json::Object(
            entries
                .into_iter()
                .map(|(key, value)| odin_strict_json::ObjectEntry { key, value })
                .collect(),
        ))
    }

    fn execution_receipt(
        &self,
        effect: &PreparedEffect,
        behavior: EffectBehavior,
        response: &EffectResponse,
        post_world: Option<Digest>,
        timeline: ReceiptTimeline,
    ) -> Result<(EffectReceipt, Digest), ExecutorFault> {
        let handler_entry_ms =
            response
                .handler_entry_ms
                .ok_or_else(|| ExecutorFault::Uncertain {
                    detail: "compiled effector omitted the real handler entry time".to_owned(),
                })?;
        let handler_exit_ms = response
            .handler_exit_ms
            .ok_or_else(|| ExecutorFault::Uncertain {
                detail: "compiled effector omitted the real handler exit time".to_owned(),
            })?;
        if handler_exit_ms < handler_entry_ms {
            return Err(ExecutorFault::Uncertain {
                detail: "compiled effector handler timeline is reversed".to_owned(),
            });
        }
        let outcome = response
            .outcome
            .clone()
            .ok_or_else(|| ExecutorFault::Uncertain {
                detail: "compiled effector omitted its execution outcome".to_owned(),
            })?;
        let stdout_hex = response.stdout_hex.clone().unwrap_or_default();
        let stderr_hex = response.stderr_hex.clone().unwrap_or_default();
        let stdout_retained = odin_types::hash::hex_decode(&stdout_hex)
            .map_err(|error| ExecutorFault::Uncertain {
                detail: format!("compiled effector stdout_hex is malformed: {error}"),
            })?
            .len() as u64;
        let stderr_retained = odin_types::hash::hex_decode(&stderr_hex)
            .map_err(|error| ExecutorFault::Uncertain {
                detail: format!("compiled effector stderr_hex is malformed: {error}"),
            })?
            .len() as u64;
        let stdout_bytes = response.stdout_bytes.unwrap_or(stdout_retained);
        let stderr_bytes = response.stderr_bytes.unwrap_or(stderr_retained);
        let stdout_truncated =
            response.stdout_truncated.unwrap_or(false) || stdout_bytes > stdout_retained;
        let stderr_truncated =
            response.stderr_truncated.unwrap_or(false) || stderr_bytes > stderr_retained;
        let post_world_unchanged = match (effect.reconciliation().expected_post_world, post_world) {
            (Some(expected), Some(observed)) => Some(expected == observed),
            _ => None,
        };
        let operation_id = effect.operation_id().as_str();
        let mut receipt = EffectReceipt {
            schema: RECEIPT_SCHEMA.to_owned(),
            correlation_id: effect.correlation_id().as_str().to_owned(),
            operation_id: operation_id.to_owned(),
            capability: effect.contract().id.as_str().to_owned(),
            capsule_id: effect.capsule_id().as_str().to_owned(),
            evidence_digest: String::new(),
            outcome,
            exit_code: response.exit_code,
            signal: response.signal,
            stdout_hex,
            stdout_bytes,
            stdout_truncated,
            stderr_hex,
            stderr_bytes,
            stderr_truncated,
            events: vec![
                ReceiptEvent {
                    name: "effect_dispatched".to_owned(),
                    at_ms: timeline.dispatched_at_ms,
                    detail: format!(
                        "sidecar dispatched operation {operation_id} through StopAuthority"
                    ),
                },
                ReceiptEvent {
                    name: "handler_entry".to_owned(),
                    at_ms: handler_entry_ms,
                    detail: format!("compiled effector entered the {behavior:?} handler"),
                },
                ReceiptEvent {
                    name: "handler_exit".to_owned(),
                    at_ms: handler_exit_ms,
                    detail: format!("compiled effector exited the {behavior:?} handler"),
                },
                ReceiptEvent {
                    name: "response_received".to_owned(),
                    at_ms: timeline.response_received_at_ms,
                    detail: "sidecar received the compiled effector response".to_owned(),
                },
                ReceiptEvent {
                    name: "receipt_recorded".to_owned(),
                    at_ms: timeline.recorded_at_ms,
                    detail: format!(
                        "sidecar recorded the measured receipt for operation {operation_id}"
                    ),
                },
            ],
            network_connections: Vec::new(),
            filesystem_changes: response
                .filesystem_changes
                .iter()
                .map(|change| ReceiptFileChange {
                    op: change.op.clone(),
                    path: change.path.clone(),
                })
                .collect(),
            post_world: post_world.map(|digest| digest.to_string()),
            worker_stopped: response.worker_stopped.unwrap_or(false)
                && response.survivors.is_empty(),
            residual_workers: response.survivors.len() as u64,
            post_world_unchanged,
        };
        let digest = receipt
            .seal_digest()
            .map_err(|error| ExecutorFault::Uncertain {
                detail: format!("effect receipt digest failed: {}", error.detail()),
            })?;
        receipt
            .validate_bounds()
            .map_err(|error| ExecutorFault::Uncertain {
                detail: format!("effect receipt bounds failed: {}", error.detail()),
            })?;
        Ok((receipt, digest))
    }

    fn observe_world(
        &self,
        contract: &CapabilityContract,
        payload: &Payload,
        stop: Option<&Arc<StopHandle>>,
    ) -> Result<PreWorld, ExecutorFault> {
        let behavior = self.behavior(contract)?;
        let request = EffectRequest::Observe {
            capsule: self.capsule.clone(),
            behavior,
            arguments: self.effect_arguments(contract, payload, None)?,
        };
        let response = self.round_trip(
            request,
            stop,
            (self.clock)().saturating_add(OBSERVE_TIMEOUT_MS),
        )?;
        if !response.ok {
            return Err(ExecutorFault::Rejected {
                detail: response
                    .detail
                    .unwrap_or_else(|| "effector observation failed".to_owned()),
            });
        }
        match response.observed {
            Some(digest) => {
                let digest = Digest::parse(&digest).map_err(|error| ExecutorFault::Rejected {
                    detail: format!("effector observation digest is malformed: {error}"),
                })?;
                Ok(PreWorld::Digest(digest))
            }
            None => Ok(PreWorld::Absent),
        }
    }
}

impl OperationExecutor for EffectorExecutor {
    fn id(&self) -> &'static str {
        PreparedEffect::SIDECAR_EXECUTOR
    }

    fn declared_pre_world(
        &self,
        _contract: &CapabilityContract,
        _payload: &Payload,
    ) -> Result<Option<PreWorld>, ExecutorFault> {
        // The effector checks the preimage during execution; the transport cannot supply that observation.
        Ok(None)
    }

    fn observe(
        &self,
        contract: &CapabilityContract,
        payload: &Payload,
    ) -> Result<PreWorld, ExecutorFault> {
        self.observe_world(contract, payload, None)
    }

    fn expected_post_world(
        &self,
        contract: &CapabilityContract,
        payload: &Payload,
    ) -> Result<Option<Digest>, ExecutorFault> {
        let behavior = self.behavior(contract)?;
        let request = EffectRequest::Declare {
            capsule: self.capsule.clone(),
            behavior,
            arguments: self.effect_arguments(contract, payload, None)?,
        };
        let response = self.round_trip(
            request,
            None,
            (self.clock)().saturating_add(OBSERVE_TIMEOUT_MS),
        )?;
        if !response.ok {
            return Err(ExecutorFault::Rejected {
                detail: response
                    .detail
                    .unwrap_or_else(|| "effector declaration failed".to_owned()),
            });
        }
        response
            .expected_post
            .map(|digest| {
                Digest::parse(&digest).map_err(|error| ExecutorFault::Rejected {
                    detail: format!("effector declared digest is malformed: {error}"),
                })
            })
            .transpose()
    }

    fn execute(&self, effect: PreparedEffect) -> Result<EffectOutcome, ExecutorFault> {
        if effect.executor_id() != self.id() {
            return Err(ExecutorFault::Rejected {
                detail: format!(
                    "permit names executor {:?}; this executor is {:?}",
                    effect.executor_id(),
                    self.id()
                ),
            });
        }
        let behavior = self.behavior(effect.contract())?;
        let stop = effect.stop_handle();
        let request = EffectRequest::Execute {
            capsule: self.capsule.clone(),
            behavior,
            arguments: self.effect_arguments(
                effect.contract(),
                effect.payload(),
                Some(effect.operation_id()),
            )?,
        };
        let dispatched_at_ms = (self.clock)();
        let response = self.round_trip(request, Some(&stop), effect.expires_at_ms())?;
        let response_received_at_ms = (self.clock)();
        let post_effect_uncertain = match response.outcome.as_deref() {
            Some("completed") if response.ok => false,
            Some("completed") => {
                return Err(ExecutorFault::Uncertain {
                    detail: "compiled effector contradicted completed with ok=false".to_owned(),
                })
            }
            Some("rejected") | Some("spawn_failed") => {
                return Err(ExecutorFault::Rejected {
                    detail: response.detail.clone().unwrap_or_else(|| {
                        "compiled effector refused the effect; none landed".to_owned()
                    }),
                })
            }
            Some("uncertain") | Some("timed_out") | Some("cancelled") => true,
            other => {
                return Err(ExecutorFault::Uncertain {
                    detail: format!(
                        "compiled effector reported outcome {other:?}; whether the effect landed is unknown"
                    ),
                })
            }
        };
        let post_world = if post_effect_uncertain {
            None
        } else {
            match self.observe_world(effect.contract(), effect.payload(), Some(&stop))? {
                PreWorld::Digest(digest) => Some(digest),
                PreWorld::Absent => None,
            }
        };
        let recorded_at_ms = (self.clock)();
        let timeline = ReceiptTimeline {
            dispatched_at_ms,
            response_received_at_ms,
            recorded_at_ms,
        };
        let (receipt, evidence_digest) =
            self.execution_receipt(&effect, behavior, &response, post_world, timeline)?;
        let receipt_store = self
            .receipts
            .get()
            .ok_or_else(|| ExecutorFault::Uncertain {
                detail: "effect receipt store is not bound".to_owned(),
            })?;
        receipt_store
            .persist(&receipt, recorded_at_ms)
            .map_err(|error| ExecutorFault::Uncertain {
                detail: format!("effect receipt could not be persisted: {}", error.detail()),
            })?;
        let injected = self
            .post_effect_uncertainty_once
            .swap(false, Ordering::SeqCst);
        if post_effect_uncertain || injected {
            return Err(ExecutorFault::PostEffectUncertain {
                detail: if injected {
                    format!(
                        "failure-storm holdpoint after real effect and receipt {}",
                        receipt.evidence_digest
                    )
                } else {
                    response.detail.clone().unwrap_or_else(|| {
                        format!(
                            "compiled effector reported post-effect outcome {:?}",
                            response.outcome
                        )
                    })
                },
                evidence_digest,
            });
        }
        Ok(EffectOutcome {
            post_world,
            evidence_digest,
            stop: None,
        })
    }
}
