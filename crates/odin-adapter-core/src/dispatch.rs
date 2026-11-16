//! Persist validated receipts before reporting success; failures after dispatch remain uncertain.

use std::sync::Arc;
use std::time::Duration;

use odin_kernel::capability::{HandlerBinding, SchemaCatalog};
use odin_kernel::schema;
use odin_kernel::{
    EffectOutcome, ExecutorFault, OperationExecutor, Payload, PreWorld, PreparedEffect,
};
use serde_json::{json, Value};

use crate::descriptor::{AdapterDescriptor, IdempotencyPolicy, OperationContract};
use crate::evidence::EffectReceiptSink;
use crate::ids::OperationKind;
use crate::operation::{AdapterOperationRecord, IdempotencyKey, OperationRecordState};
use crate::transport::{AdapterTransportFault, JsonRpcOutcome, JsonRpcRequest, RpcMethod};
use crate::{AdapterError, ADAPTER_OPERATION_HANDLER, ADAPTER_RECEIPT_EVIDENCE};
/// A relay failure after persistence leaves durable evidence but no caller-visible result.
pub trait AdapterResultSink: Send + Sync {
    /// Backend errors retain their `{"error":{"code","message"[,"data"]}}` shape.
    fn relay_result(&self, correlation_id: &str, result: Value) -> Result<(), AdapterError>;
}

/// Backend lookup and descriptor failures occur before dispatch.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("adapter {adapter} is unavailable: {detail}")]
pub struct AdapterUnavailable {
    pub adapter: String,
    pub detail: String,
}

/// Host implementations keep process-launch dependencies out of the dispatcher.
pub trait AdapterBackends: Send + Sync {
    /// An error means no operation was dispatched.
    fn descriptor(&self, adapter: &str) -> Result<AdapterDescriptor, AdapterUnavailable>;

    /// Faults must distinguish requests that were not sent from uncertain outcomes.
    fn call(
        &self,
        adapter: &str,
        timeout: Duration,
        request: &JsonRpcRequest,
    ) -> Result<JsonRpcOutcome, AdapterTransportFault>;
}

pub type AdapterClock = Arc<dyn Fn() -> time::OffsetDateTime + Send + Sync>;
/// Validates a bound operation input.
pub type ValueValidator = Arc<dyn Fn(&Value) -> Result<(), String> + Send + Sync>;
/// Validates a bound operation input in its authenticated project.
pub type ProjectValidator = Arc<dyn Fn(&str, &Value) -> Result<(), String> + Send + Sync>;
/// Records a successful operation input and result.
pub type ValueRecorder = Arc<dyn Fn(&Value, &Value) -> Result<(), String> + Send + Sync>;
/// Records a successful operation input and result in its authenticated project.
pub type ProjectRecorder = Arc<dyn Fn(&str, &Value, &Value) -> Result<(), String> + Send + Sync>;

pub struct AdapterExecutor {
    backends: Arc<dyn AdapterBackends>,
    fallback: Arc<dyn OperationExecutor>,
    schemas: Arc<dyn SchemaCatalog + Send + Sync>,
    receipts: Arc<dyn EffectReceiptSink>,
    results: Arc<dyn AdapterResultSink>,
    clock: AdapterClock,
    promotion_verifier: Option<ValueValidator>,
    campaign_validator: Option<ValueValidator>,
    spend_validator: Option<ProjectValidator>,
    campaign_recorder: Option<ValueRecorder>,
    spend_recorder: Option<ProjectRecorder>,
}

fn check_spend_cap(input: &Value) -> Result<(), String> {
    let estimated = input["estimated_usd"]
        .as_f64()
        .ok_or("invalid estimated spend")?;
    let cap = input["cap_usd"].as_f64().ok_or("invalid spend cap")?;
    if estimated > cap {
        return Err("estimated spend exceeds the approved cap".to_owned());
    }
    Ok(())
}

fn marker(name: &str) -> HandlerBinding {
    HandlerBinding::Builtin {
        name: name.to_owned(),
    }
}

impl AdapterExecutor {
    pub fn new(
        backends: Arc<dyn AdapterBackends>,
        fallback: Arc<dyn OperationExecutor>,
        schemas: Arc<dyn SchemaCatalog + Send + Sync>,
        receipts: Arc<dyn EffectReceiptSink>,
        results: Arc<dyn AdapterResultSink>,
        clock: AdapterClock,
    ) -> Self {
        Self {
            backends,
            fallback,
            schemas,
            receipts,
            results,
            clock,
            promotion_verifier: None,
            campaign_validator: None,
            spend_validator: None,
            campaign_recorder: None,
            spend_recorder: None,
        }
    }

    /// Bind the controller's science verdict authority to promotion dispatch.
    pub fn with_promotion_verifier(mut self, verifier: Option<ValueValidator>) -> Self {
        self.promotion_verifier = verifier;
        self
    }

    /// Bind campaign approval validation before dispatch.
    pub fn with_campaign_validator(mut self, validator: Option<ValueValidator>) -> Self {
        self.campaign_validator = validator;
        self
    }

    /// Bind rental approval validation before dispatch.
    pub fn with_spend_validator(mut self, validator: Option<ProjectValidator>) -> Self {
        self.spend_validator = validator;
        self
    }

    /// Bind durable campaign accounting to successful upstream approvals.
    pub fn with_campaign_recorder(mut self, recorder: Option<ValueRecorder>) -> Self {
        self.campaign_recorder = recorder;
        self
    }

    /// Bind durable rental approval accounting to successful upstream approvals.
    pub fn with_spend_recorder(mut self, recorder: Option<ProjectRecorder>) -> Self {
        self.spend_recorder = recorder;
        self
    }

    /// Capability IDs must match an operation declared by the adapter.
    fn operation_for<'d>(
        descriptor: &'d AdapterDescriptor,
        kind: &OperationKind,
    ) -> Result<&'d OperationContract, ExecutorFault> {
        descriptor
            .operations()
            .iter()
            .find(|operation| operation.kind == *kind)
            .ok_or_else(|| ExecutorFault::Rejected {
                detail: format!(
                    "adapter operation {} refused: adapter {} does not declare it",
                    kind.as_str(),
                    descriptor.adapter().adapter_id.as_str()
                ),
            })
    }

    /// Invalid output is uncertain because the effect may already have occurred.
    fn validate_output(
        &self,
        operation: &OperationContract,
        result: &Value,
    ) -> Result<(), ExecutorFault> {
        let uncertain = |detail: String| ExecutorFault::Uncertain {
            detail: format!(
                "adapter effect landed; output schema {} cannot settle: {detail}",
                operation.output_schema.as_str()
            ),
        };
        let tool = self
            .schemas
            .schema(operation.output_schema.as_str())
            .map_err(|error| uncertain(error.to_string()))?;
        let validator = schema::validator(&tool).map_err(uncertain)?;
        match schema::violations(&validator, result) {
            Some(detail) => Err(uncertain(detail)),
            None => Ok(()),
        }
    }

    /// Missing or invalid evidence is uncertain because the effect may already have occurred.
    fn validate_evidence(
        &self,
        operation: &OperationContract,
        evidence: &Value,
    ) -> Result<(), ExecutorFault> {
        for requirement in &operation.evidence {
            if !requirement.required {
                continue;
            }
            let uncertain = |detail: String| ExecutorFault::Uncertain {
                detail: format!(
                    "adapter effect landed; required evidence {} cannot settle: {detail}",
                    requirement.kind.as_str()
                ),
            };
            let tool = self
                .schemas
                .schema(requirement.schema.as_str())
                .map_err(|error| uncertain(error.to_string()))?;
            let validator = schema::validator(&tool).map_err(uncertain)?;
            if let Some(detail) = schema::violations(&validator, evidence) {
                return Err(uncertain(detail));
            }
        }
        Ok(())
    }
    fn settle_receipt(
        &self,
        effect: &PreparedEffect,
        descriptor: &AdapterDescriptor,
        operation: &OperationContract,
        state: OperationRecordState,
        output_digest: Option<crate::ids::Digest>,
        evidence: Option<&Value>,
    ) -> Result<crate::ids::Digest, ExecutorFault> {
        let record = AdapterOperationRecord {
            schema: crate::ADAPTER_OPERATION_SCHEMA_NAME.to_owned(),
            operation_id: crate::ids::AdapterWireId::new(effect.operation_id().as_str()).map_err(
                |error| ExecutorFault::Uncertain {
                    detail: format!("adapter effect landed; receipt operation id refused: {error}"),
                },
            )?,
            adapter: descriptor.adapter().clone(),
            kind: operation.kind.clone(),
            effect_class: operation.effect_class,
            input_schema: operation.input_schema.clone(),
            input_digest: effect.payload().digest,
            credential_handles: operation
                .credential_handle
                .as_ref()
                .map(|handle| vec![handle.clone()])
                .unwrap_or_default(),
            // Reuse the operation identity so replayed preparation produces the same receipt.
            idempotency_key: IdempotencyKey::new(effect.operation_id().as_str()).map_err(
                |error| ExecutorFault::Uncertain {
                    detail: format!(
                        "adapter effect landed; receipt idempotency key refused: {error}"
                    ),
                },
            )?,
            // Receipts cannot reduce the descriptor's initial taint.
            taint: descriptor.initial_taint().join(operation.taint_after),
            state,
            output_schema: operation.output_schema.clone(),
            output_digest,
            // Captured evidence is stored inline rather than as an external reference.
            evidence_refs: Vec::new(),
        };
        record
            .validate()
            .map_err(|error| ExecutorFault::Uncertain {
                detail: format!("adapter effect landed; receipt record is not canonical: {error}"),
            })?;
        self.receipts
            .persist_receipt(effect.correlation_id().as_str(), &record, evidence)
            .map_err(|error| ExecutorFault::Uncertain {
                detail: format!(
                    "adapter effect landed; the receipt could not be durably persisted: {error}"
                ),
            })
    }

    fn relay_settled(
        &self,
        effect: &PreparedEffect,
        evidence_digest: crate::ids::Digest,
        result: Value,
    ) -> Result<EffectOutcome, ExecutorFault> {
        self.results
            .relay_result(effect.correlation_id().as_str(), result)
            .map_err(|error| ExecutorFault::PostEffectUncertain {
                detail: format!(
                    "adapter effect landed and its receipt {evidence_digest} is durable, \
                     but the caller-visible result could not be relayed: {error}"
                ),
                evidence_digest,
            })?;
        Ok(EffectOutcome {
            post_world: None,
            evidence_digest,
            stop: None,
        })
    }

    fn dispatch_adapter(
        &self,
        adapter: &str,
        effect: PreparedEffect,
    ) -> Result<EffectOutcome, ExecutorFault> {
        let contract = effect.contract();
        let rejected = |detail: String| ExecutorFault::Rejected {
            detail: format!("adapter permit for {} refused: {detail}", contract.id),
        };

        if contract.handler != marker(ADAPTER_OPERATION_HANDLER) {
            return Err(rejected(format!(
                "handler {:?} is not the declared-adapter marker {ADAPTER_OPERATION_HANDLER}",
                contract.handler
            )));
        }
        if contract.evidence_extractor != marker(ADAPTER_RECEIPT_EVIDENCE) {
            return Err(rejected(format!(
                "evidence extractor {:?} is not the declared-adapter marker \
                 {ADAPTER_RECEIPT_EVIDENCE}",
                contract.evidence_extractor
            )));
        }
            if effect.executor_binding().is_some() {
                return Err(rejected(
                    "adapter permits carry no executor binding".to_owned(),
                ));
            }
        if effect.stop_handle().is_cancelled() {
            return Err(rejected("stop intent recorded before dispatch".to_owned()));
        }

        // A missing backend or failed handshake is safe to reject before dispatch.
        let descriptor = self
            .backends
            .descriptor(adapter)
            .map_err(|unavailable| rejected(unavailable.to_string()))?;

        let kind = OperationKind::new(contract.id.as_str()).map_err(|error| {
            rejected(format!("capability id is not an operation kind: {error}"))
        })?;
        let operation = Self::operation_for(&descriptor, &kind)?;

        // Descriptor and registry must agree; the dispatcher cannot change approval requirements.
        if contract.effect_class != operation.effect_class {
            return Err(rejected(format!(
                "declared effect class {:?} does not match adapter {adapter}'s descriptor {:?}",
                contract.effect_class, operation.effect_class
            )));
        }
        if contract.idempotency != operation.idempotency {
            return Err(rejected(format!(
                "declared idempotency {:?} does not match adapter {adapter}'s descriptor {:?}",
                contract.idempotency, operation.idempotency
            )));
        }
        for (declared, served, which) in [
            (
                &contract.input_schema_ref,
                &operation.input_schema,
                "input schema",
            ),
            (
                &contract.output_schema_ref,
                &operation.output_schema,
                "output schema",
            ),
        ] {
            if declared != served.as_str() {
                return Err(rejected(format!(
                    "declared {which} {declared} does not match adapter {adapter}'s descriptor \
                     {served}"
                )));
            }
        }

        // Check the descriptor's input schema as well as the registry's schema.
        let input_schema_error = |detail: String| {
            rejected(format!(
                "payload violates the declared input schema {}: {detail}",
                operation.input_schema.as_str()
            ))
        };
        let tool = self
            .schemas
            .schema(operation.input_schema.as_str())
            .map_err(|error| input_schema_error(error.to_string()))?;
        let validator = schema::validator(&tool).map_err(input_schema_error)?;
        if let Some(detail) = schema::violations(&validator, &effect.payload().arguments) {
            return Err(input_schema_error(detail));
        }


        let operation_id = effect.operation_id().as_str();
        let idempotency_key = IdempotencyKey::new(operation_id).map_err(|error| {
            rejected(format!(
                "authority operation id is not an idempotency key: {error}"
            ))
        })?;
        let request = JsonRpcRequest::new(
            effect.correlation_id().as_str(),
            RpcMethod::Operation(kind.clone()),
            json!({
                "operation_id": operation_id,
                "idempotency_key": idempotency_key.as_str(),
                "input": tool_input(&effect.payload().arguments),
            }),
        )
        .map_err(|error| rejected(format!("request frame refused: {error}")))?;

        let timeout = Duration::from_secs(u64::from(contract.timeout_seconds.get()));
        let outcome = match self.backends.call(adapter, timeout, &request) {
            Ok(outcome) => outcome,
            Err(fault) if fault.proved_not_dispatched() => {
                return Err(rejected(format!(
                    "transport proved the frame never left the host: {}",
                    fault.detail()
                )))
            }
            Err(fault) => {
                return Err(ExecutorFault::Uncertain {
                    detail: format!(
                        "adapter {adapter}: transport cannot prove the upstream effect state: {}",
                        fault.detail()
                    ),
                })
            }
        };

        match outcome {
            JsonRpcOutcome::Success { result, .. } => {
                self.validate_output(operation, &result)?;
                let output_digest =
                    canonical_output_digest(&result).map_err(|error| ExecutorFault::Uncertain {
                        detail: format!(
                            "adapter effect landed; its result is not canonicalizable: {error}"
                        ),
                    })?;
                let evidence_document = crate::receipt_evidence(
                    descriptor.adapter(),
                    &kind,
                    descriptor.initial_taint().join(operation.taint_after),
                    &result,
                    (self.clock)(),
                )
                .map_err(|error| ExecutorFault::Uncertain {
                    detail: format!(
                        "adapter effect landed; its receipt evidence cannot be derived: {error}"
                    ),
                })?;
                self.validate_evidence(operation, &evidence_document)?;
                let evidence_digest = self.settle_receipt(
                    &effect,
                    &descriptor,
                    operation,
                    OperationRecordState::Succeeded,
                    Some(output_digest),
                    Some(&evidence_document),
                )?;
                tracing::info!(
                    "{}",
                    settled_line(
                        adapter,
                        kind.as_str(),
                        effect.correlation_id().as_str(),
                        &result
                    )
                );
                self.relay_settled(&effect, evidence_digest, result)
            }
            JsonRpcOutcome::Error {
                code,
                message,
                data,
                ..
            } => {
                let error = crate::transport::error_object(code, &message, data.as_ref());
                match self.settle_receipt(
                    &effect,
                    &descriptor,
                    operation,
                    OperationRecordState::Failed,
                    None,
                    None,
                ) {
                    Ok(evidence_digest) => {
                        let relayed = self
                            .results
                            .relay_result(effect.correlation_id().as_str(), error);
                        // A pure operation has no effect to doubt: its typed failure is final.
                        if operation.idempotency == IdempotencyPolicy::Pure {
                            return Err(ExecutorFault::Rejected {
                                detail: format!(
                                    "adapter {adapter} reported a typed failure: {message}"
                                ),
                            });
                        }
                        Err(ExecutorFault::PostEffectUncertain {
                            detail: format!(
                                "adapter {adapter} reported a typed failure ({message}){}; the \
                                 failed-effect receipt {evidence_digest} is durable and the \
                                 authority reconciles from it",
                                if relayed.is_ok() {
                                    " and the typed reason was relayed"
                                } else {
                                    " but the typed reason could not be relayed"
                                }
                            ),
                            evidence_digest,
                        })
                    }
                    Err(ExecutorFault::Uncertain { detail }) => Err(ExecutorFault::Uncertain {
                        detail: format!(
                            "adapter {adapter} reported a typed failure; the receipt could not \
                             be durably persisted: {detail}"
                        ),
                    }),
                    Err(other) => Err(other),
                }
            }
        }
    }
}

fn canonical_output_digest(result: &Value) -> Result<crate::ids::Digest, AdapterError> {
    let canonical =
        odin_strict_json::canonicalize(result).map_err(|error| AdapterError::Canonical {
            detail: error.to_string(),
        })?;
    Ok(crate::ids::Digest::hash(&canonical))
}

impl OperationExecutor for AdapterExecutor {
    fn id(&self) -> &'static str {
        PreparedEffect::OMP_HOST_EXECUTOR
    }


    fn declared_pre_world(
        &self,
        contract: &odin_kernel::CapabilityContract,
        payload: &Payload,
    ) -> Result<Option<PreWorld>, ExecutorFault> {
        // Reject malformed preWorld values before dispatch, as the host executor does.
        let Some(declared) = payload.arguments.get("preWorld") else {
            return Ok(None);
        };
        let raw = declared.as_str().ok_or_else(|| ExecutorFault::Rejected {
            detail: format!("payload of {} declares a non-string preWorld", contract.id),
        })?;
        let digest = crate::ids::Digest::parse(raw).map_err(|error| ExecutorFault::Rejected {
            detail: format!(
                "payload of {} declares an undecodable preWorld digest: {error}",
                contract.id
            ),
        })?;
        Ok(Some(PreWorld::Digest(digest)))
    }

    fn observe(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        _payload: &Payload,
    ) -> Result<PreWorld, ExecutorFault> {
        // Without an effect-free observation, uncertain outcomes require reconciliation.
        Ok(PreWorld::Absent)
    }

    fn expected_post_world(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        _payload: &Payload,
    ) -> Result<Option<crate::ids::Digest>, ExecutorFault> {
        Ok(None)
    }

    fn execute(&self, effect: PreparedEffect) -> Result<EffectOutcome, ExecutorFault> {
        if effect.executor_id() != <Self as OperationExecutor>::id(self) {
            // Delegation must not bypass the executor identity check.
            return Err(ExecutorFault::Rejected {
                detail: format!(
                    "permit names executor {:?}; this executor is {:?}",
                    effect.executor_id(),
                    <Self as OperationExecutor>::id(self)
                ),
            });
        }
        match effect.contract().adapter.clone() {
            Some(adapter) => {
                let kind = effect.contract().id.to_string();
                let correlation = effect.correlation_id().as_str().to_owned();
                let outcome = self.dispatch_adapter(&adapter, effect);
                if let Some(line) = fault_line(&adapter, &kind, &correlation, &outcome) {
                    tracing::error!("{line}");
                }
                outcome
            }
            None => self.fallback.execute(effect),
        }
    }
}

fn fault_line(
    adapter: &str,
    kind: &str,
    correlation: &str,
    outcome: &Result<EffectOutcome, ExecutorFault>,
) -> Option<String> {
    let (state, detail) = match outcome.as_ref().err()? {
        ExecutorFault::Rejected { detail } => ("failed", detail),
        ExecutorFault::Uncertain { detail } => ("in_doubt", detail),
        ExecutorFault::PostEffectUncertain { detail, .. } => ("in_doubt", detail),
    };
    Some(format!(
        "odind: adapter call id={adapter} kind={kind} correlation={correlation} \
         outcome={state} reason={detail}"
    ))
}

fn settled_line(adapter: &str, kind: &str, correlation: &str, result: &Value) -> String {
    let backend = result
        .get("backend")
        .and_then(Value::as_str)
        .map(|backend| format!(" backend={backend}"))
        .unwrap_or_default();
    format!(
        "odind: adapter call id={adapter} kind={kind} correlation={correlation} \
         outcome=settled{backend}"
    )
}

#[cfg(test)]
mod fault_line_tests {
    use super::*;


    #[test]
    fn spend_cap_checks_the_bound_estimate() {
        assert!(check_spend_cap(&json!({"estimated_usd": 5, "cap_usd": 5})).is_ok());
        assert!(check_spend_cap(&json!({"estimated_usd": 6, "cap_usd": 5})).is_err());
        assert!(check_spend_cap(&json!({"cap_usd": 5})).is_err());
    }

    #[test]
    fn a_failed_call_logs_the_state_its_fault_leaves() {
        let fault_state = |fault: ExecutorFault| {
            let outcome: Result<EffectOutcome, ExecutorFault> = Err(fault);
            fault_line("mcp-time", "time.get_current_time", "c-1", &outcome)
                .expect("a fault is logged")
        };
        let refused = fault_state(ExecutorFault::Rejected {
            detail: "no backend".to_owned(),
        });
        assert!(refused.contains("outcome=failed") && refused.contains("no backend"));
        let uncertain = fault_state(ExecutorFault::Uncertain {
            detail: "no reply frame".to_owned(),
        });
        assert!(uncertain.contains("outcome=in_doubt") && uncertain.contains("no reply frame"));
        assert!(uncertain.contains("id=mcp-time") && uncertain.contains("correlation=c-1"));
    }
}

#[cfg(test)]
mod validator_cache_tests {}
