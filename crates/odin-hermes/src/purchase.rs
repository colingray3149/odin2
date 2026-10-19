//! Approval-gated purchase submission through the kernel dispatch surface.
//!
//! The handler verifies the consumed approval against the shared ledger before dispatch.
//! Canonical request digests identify retries and restrict approval to the exact request.
//! The host command is the durable intent; no second command is recorded for the envelope.
//! Failures before exchange settle the intent; uncertain outcomes remain nonterminal for reconciliation.

use std::sync::Arc;

use odin_adapter_core::{
    descriptor::{AdapterDescriptor, OperationContract},
    ids::{AdapterWireId, OperationKind},
    operation::IdempotencyKey,
    transport::{AdapterErrorCode, JsonRpcRequest, RpcMethod},
};
use odin_kernel::capability::IdempotencyPolicy;

use odin_domain::envelope::CommandEnvelopeInit;
use odin_domain::{
    Actor, CapabilityId, CommandCapability, CommandEnvelope, CommandTarget, Correlation, Digest,
    EffectClass, Producer, Redaction, Scope,
};
use odin_ledger::approval::ApprovalScope;

pub const PURCHASE_CAPABILITY_ID: &str = "purchase.submit";

pub const PURCHASE_COMMAND_KIND: &str = "odin.purchase.submit";

pub const PURCHASE_TARGET_KIND: &str = "purchase";

const MAX_VENDOR_BYTES: usize = 128;
const MAX_ITEM_BYTES: usize = 256;
/// The registry's minor-unit ceiling for one purchase request; the module
/// bound mirrors the wire schema (amount.minor_units) so wrapper and
/// adapter agree exactly.
const MAX_AMOUNT_MINOR_UNITS: i64 = 1_000_000_000;

/// One bounded, secret-free purchase request. Vendor and item names ride in
/// the command envelope by design (an approver must see what they approve);
/// no credential, account, or payment-instrument material is ever part of a
/// purchase request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PurchaseRequest {
    vendor: String,
    item: String,
    amount_cents: i64,
    currency: String,
    /// Included in canonical request bytes only when present.
    checkout: Option<CheckoutPlan>,
}

impl PurchaseRequest {
    pub fn new(
        vendor: impl Into<String>,
        item: impl Into<String>,
        amount_cents: i64,
        currency: impl Into<String>,
    ) -> Result<Self, PurchaseError> {
        let vendor = vendor.into();
        let item = item.into();
        let currency = currency.into();
        if vendor.is_empty() || vendor.len() > MAX_VENDOR_BYTES {
            return Err(PurchaseError::InvalidRequest(
                "vendor must be 1..=128 bytes",
            ));
        }
        if item.is_empty() || item.len() > MAX_ITEM_BYTES {
            return Err(PurchaseError::InvalidRequest("item must be 1..=256 bytes"));
        }
        if amount_cents <= 0 || amount_cents > MAX_AMOUNT_MINOR_UNITS {
            return Err(PurchaseError::InvalidRequest(
                "amount_cents must be a positive minor-unit amount within the registry bound",
            ));
        }
        let currency_bytes = currency.as_bytes();
        if currency.len() != 3 || !currency_bytes.iter().all(u8::is_ascii_uppercase) {
            return Err(PurchaseError::InvalidRequest(
                "currency must be exactly three uppercase ASCII letters",
            ));
        }
        Ok(Self {
            vendor,
            item,
            amount_cents,
            currency,
            checkout: None,
        })
    }

    pub fn with_checkout(mut self, plan: CheckoutPlan) -> Result<Self, PurchaseError> {
        plan.validate()?;
        self.checkout = Some(plan);
        Ok(self)
    }

    pub fn checkout(&self) -> Option<&CheckoutPlan> {
        self.checkout.as_ref()
    }

    pub fn vendor(&self) -> &str {
        &self.vendor
    }

    pub fn item(&self) -> &str {
        &self.item
    }

    pub fn amount_cents(&self) -> i64 {
        self.amount_cents
    }

    pub fn currency(&self) -> &str {
        &self.currency
    }

    /// The canonical request document: the bytes every digest binds. The
    /// field order is fixed, so equal requests always serialize equally.
    pub fn canonical_json(&self) -> String {
        let checkout = self
            .checkout
            .as_ref()
            .map(|plan| format!("\"checkout\":{},", plan.canonical_json()))
            .unwrap_or_default();
        format!(
            "{{\"amount_cents\":{},{checkout}\"currency\":\"{}\",\"item\":\"{}\",\"vendor\":\"{}\"}}",
            self.amount_cents,
            escape_json(&self.currency),
            escape_json(&self.item),
            escape_json(&self.vendor),
        )
    }

    /// The BLAKE3 digest binding approvals, idempotency, and the envelope
    /// args hash to the exact request bytes.
    pub fn args_digest(&self) -> Digest {
        Digest::hash(self.canonical_json().as_bytes())
    }

    /// Short lowercase-hex prefix of the args digest: identity material that
    /// is stable for identical requests and useless for correlation with
    /// anything but this exact request.
    fn identity_hex(&self) -> String {
        let digest = self.args_digest();
        let bytes = digest.as_bytes();
        let mut hex = String::with_capacity(32);
        for byte in bytes.iter().take(8) {
            hex.push_str(&format!("{byte:02x}"));
        }
        hex
    }
}

/// Escapes one string for embedding in [`PurchaseRequest::canonical_json`].
/// Requests are validated, but the canonical form must stay canonical even
/// for hostile vendor strings.
fn escape_json(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            control if (control as u32) < 0x20 => {
                escaped.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => escaped.push(other),
        }
    }
    escaped
}

/// Caller-supplied envelope identity and scope context for [`prepare`].
#[derive(Clone, Debug)]
pub struct PurchasePrepareInit {
    pub command_id: odin_domain::CommandId,
    pub sequence: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub actor: Actor,
    /// The domain scope the purchase executes under (seat, node, ...).
    pub scope: Scope,
    /// The command target the registry capability is bound to.
    pub target: CommandTarget,
    pub producer: Producer,
    /// The real approval id the kernel gate consumed for exactly this
    /// command — resolved and verified from the durable ledger by the
    /// caller, never synthesized here and never taken from a model
    /// selector.
    pub approval_id: odin_domain::ApprovalId,
}

/// Command envelope, approval scope, and canonical-request idempotency key.
#[derive(Clone, Debug)]
pub struct PreparedPurchase {
    pub command: CommandEnvelope,
    pub scope: ApprovalScope,
    pub approval_id: odin_domain::ApprovalId,
    pub idempotency_key: String,
}

/// Prepares a purchase for its already-consumed operator approval.
/// Nothing here talks to a provider.
pub fn prepare(
    request: &PurchaseRequest,
    init: PurchasePrepareInit,
) -> Result<PreparedPurchase, PurchaseError> {
    let identity_hex = request.identity_hex();

    let correlation =
        Correlation::new(format!("purchase:{identity_hex}")).map_err(PurchaseError::Envelope)?;
    let capability = CommandCapability::new(
        CapabilityId::new(PURCHASE_CAPABILITY_ID).map_err(PurchaseError::Envelope)?,
        1,
    )
    .map_err(PurchaseError::Envelope)?;
    let command = CommandEnvelope::new(CommandEnvelopeInit {
        id: init.command_id,
        sequence: init.sequence,
        issued_at_ms: init.issued_at_ms,
        expires_at_ms: init.expires_at_ms,
        kind: PURCHASE_COMMAND_KIND.to_owned(),
        actor: init.actor,
        scope: init.scope,
        correlation,
        payload: serde_json::from_str(&request.canonical_json())
            .map_err(|_| PurchaseError::InvalidRequest("the canonical request is not JSON"))?,
        // Nothing in a purchase request is redacted; there is no secret
        // material in it by construction.
        redaction: Redaction::None,
        producer: init.producer,
        target: init.target,
        capability,
        args_hash: request.args_digest(),
        expected_revision: 0,
    })
    .map_err(PurchaseError::Envelope)?;

    // The caller must resolve the consumed approval from the ledger, not model input.
    let scope = ApprovalScope {
        target_kind: PURCHASE_TARGET_KIND.to_owned(),
        target_id: init.approval_id.to_string(),
        capability_id: CapabilityId::new(PURCHASE_CAPABILITY_ID)
            .map_err(PurchaseError::Envelope)?,
        arguments_digest: request.args_digest(),
    };

    Ok(PreparedPurchase {
        command,
        scope,
        approval_id: init.approval_id,
        idempotency_key: format!("purchase:{identity_hex}"),
    })
}

/// A real provider outcome relayed through the governed submitter port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PurchaseReceipt {
    pub command_id: odin_domain::CommandId,
    pub idempotency_key: String,
    /// The provider's bounded receipt reference, echoed by the submitter.
    pub provider_ref: String,
}

/// Failures before provider exchange are terminal; uncertain outcomes require reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PurchaseFault {
    #[error("the purchase submission was rejected before dispatch")]
    Rejected,
    #[error("the backend refused the purchase before any provider exchange (typed code {0:?})")]
    BackendRefused(AdapterErrorCode),
    #[error("the purchase submission is in doubt and must reconcile")]
    Uncertain,
}

/// Submits approved purchases through the configured adapter backend.
pub trait PurchaseSubmitter: Send {
    fn submit(&self, command: &CommandEnvelope) -> Result<PurchaseReceipt, PurchaseFault>;
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PurchaseError {
    #[error("the purchase request is invalid: {0}")]
    InvalidRequest(&'static str),
    #[error("the purchase envelope is invalid: {0}")]
    Envelope(#[from] odin_domain::DomainError),
    #[error("the purchase backend descriptor is not lawful: {0}")]
    Contract(&'static str),
}

/// Capability, descriptor operation, and JSON-RPC method share this wire id.
pub const PURCHASE_OPERATION_WIRE_ID: &str = "purchase.submit";

/// The backend adapter wire id for the `purchase.submit` capability
/// contract's `adapter` field, the odind `[adapters]` deployment key, and
/// the backend `--config` map key. RegistryLife binds the contract;
/// odind declares the deployment; neither invents a second id.
pub const PURCHASE_BACKEND_ADAPTER_ID: &str = "purchase-submit";

const MAX_PROVIDER_REF_BYTES: usize = 256;

/// Requires an R3 purchase operation with idempotency, credentials, and captured evidence.
#[derive(Clone, Debug)]
pub struct PurchaseAdapterContract {
    descriptor: AdapterDescriptor,
    operation: OperationContract,
}

impl PurchaseAdapterContract {
    pub fn admit(descriptor: AdapterDescriptor) -> Result<Self, PurchaseError> {
        let operation = descriptor
            .operations()
            .iter()
            .find(|operation| operation.kind.as_str() == PURCHASE_OPERATION_WIRE_ID)
            .cloned()
            .ok_or(PurchaseError::Contract(
                "the descriptor does not declare the purchase.submit operation",
            ))?;
        if operation.effect_class != EffectClass::R3 {
            return Err(PurchaseError::Contract(
                "the purchase.submit operation must be effect class R3",
            ));
        }
        if operation.idempotency != IdempotencyPolicy::Required {
            return Err(PurchaseError::Contract(
                "the purchase.submit operation must require idempotency",
            ));
        }
        if operation.credential_handle.is_none() {
            return Err(PurchaseError::Contract(
                "the purchase.submit operation must be credential-bound",
            ));
        }
        if !operation
            .evidence
            .iter()
            .any(|requirement| requirement.required)
        {
            return Err(PurchaseError::Contract(
                "the purchase.submit operation must require captured evidence",
            ));
        }
        Ok(Self {
            descriptor,
            operation,
        })
    }

    pub fn descriptor(&self) -> &AdapterDescriptor {
        &self.descriptor
    }

    pub fn operation(&self) -> &OperationContract {
        &self.operation
    }
}

/// Exchanges one JSON-RPC frame with the supervised backend, which enforces response limits.
/// Endpoint and credential values come from backend configuration, never the request frame.
pub trait PurchaseFrameExchange: Send + Sync {
    fn exchange(&self, request_line: String) -> Result<String, PurchaseFault>;
}

/// Builds backend frames from the approved envelope payload without adding or changing fields.
#[derive(Clone)]
pub struct M10PurchaseSubmitter {
    contract: PurchaseAdapterContract,
    exchange: Arc<dyn PurchaseFrameExchange>,
}

impl M10PurchaseSubmitter {
    pub fn new(
        contract: PurchaseAdapterContract,
        exchange: Arc<dyn PurchaseFrameExchange>,
    ) -> Self {
        Self { contract, exchange }
    }

    pub fn contract(&self) -> &PurchaseAdapterContract {
        &self.contract
    }

    /// Framing failures happen before sending bytes and return [`PurchaseFault::Rejected`].
    fn frame(&self, command: &CommandEnvelope) -> Result<String, PurchaseFault> {
        let refused = PurchaseFault::Rejected;
        let operation_id = AdapterWireId::new(PURCHASE_OPERATION_WIRE_ID).map_err(|_| refused)?;
        let kind = OperationKind::new(PURCHASE_OPERATION_WIRE_ID).map_err(|_| refused)?;
        let idempotency_key = IdempotencyKey::new(command.correlation.idempotency_key.clone())
            .map_err(|_| refused)?;
        let request = JsonRpcRequest::new(
            command.id.to_string(),
            RpcMethod::Operation(kind),
            serde_json::json!({
                "operation_id": operation_id.as_str(),
                "idempotency_key": idempotency_key.as_str(),
                "input": command.payload,
            }),
        )
        .map_err(|_| refused)?;
        serde_json::to_string(&request.to_wire()).map_err(|_| refused)
    }

    /// Relays typed backend refusals; malformed replies, internal errors, and timeouts remain uncertain.
    fn settle(
        &self,
        reply: &str,
        command: &CommandEnvelope,
    ) -> Result<PurchaseReceipt, PurchaseFault> {
        let value: serde_json::Value =
            serde_json::from_str(reply.trim()).map_err(|_| PurchaseFault::Uncertain)?;
        // Require a JSON-RPC response for this command before classifying its outcome.
        if value.get("jsonrpc").and_then(serde_json::Value::as_str) != Some("2.0") {
            return Err(PurchaseFault::Uncertain);
        }
        if value.get("id").and_then(serde_json::Value::as_str) != Some(command.id.as_str()) {
            return Err(PurchaseFault::Uncertain);
        }
        if let Some(error) = value.get("error") {
            let code = error
                .get("code")
                .and_then(serde_json::Value::as_i64)
                .ok_or(PurchaseFault::Uncertain)?;
            let typed =
                AdapterErrorCode::try_from(code as i32).map_err(|_| PurchaseFault::Uncertain)?;
            return match typed {
                AdapterErrorCode::InternalError | AdapterErrorCode::Timeout => {
                    Err(PurchaseFault::Uncertain)
                }
                refused => Err(PurchaseFault::BackendRefused(refused)),
            };
        }
        let result = value.get("result").ok_or(PurchaseFault::Uncertain)?;
        let provider_ref = result
            .get("provider_ref")
            .and_then(serde_json::Value::as_str)
            .ok_or(PurchaseFault::Uncertain)?;
        if provider_ref.is_empty() || provider_ref.len() > MAX_PROVIDER_REF_BYTES {
            return Err(PurchaseFault::Uncertain);
        }
        Ok(PurchaseReceipt {
            command_id: command.id.clone(),
            idempotency_key: command.correlation.idempotency_key.clone(),
            provider_ref: provider_ref.to_owned(),
        })
    }
}

impl PurchaseSubmitter for M10PurchaseSubmitter {
    fn submit(&self, command: &CommandEnvelope) -> Result<PurchaseReceipt, PurchaseFault> {
        let frame = self.frame(command)?;
        let reply = self.exchange.exchange(frame)?;
        self.settle(&reply, command)
    }
}

mod checkout;
pub use checkout::{
    checkout_reply_placed, checkout_reply_refused, checkout_reply_uncertain, page_shows_amount,
    CheckoutFrameError, CheckoutOrder, CheckoutPlan, GOVERNED_BROWSER_CREDENTIAL_HANDLE,
};

#[cfg(test)]
mod tests;
