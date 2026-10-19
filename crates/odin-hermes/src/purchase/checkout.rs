//! Checkout plans and backend frames for purchases through the signed-in browser.
//!
//! Approved canonical requests include the pages and controls; changing either requires new approval.
//! This module validates and encodes plans without performing browser actions.

use odin_adapter_core::descriptor::AdapterDescriptor;
use odin_adapter_core::transport::AdapterErrorCode;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;

use super::{
    escape_json, PurchaseAdapterContract, PurchaseError, PurchaseRequest,
    PURCHASE_BACKEND_ADAPTER_ID, PURCHASE_OPERATION_WIRE_ID,
};

/// The credential handle the governed-browser backend declares: Colin's
/// signed-in browser profile. The profile never leaves the browser
/// runtime; the handle only names which account a purchase spends from.
pub const GOVERNED_BROWSER_CREDENTIAL_HANDLE: &str = "cred:governed-browser-profile";

const MAX_URL_BYTES: usize = 2048;
const MAX_SELECTOR_BYTES: usize = 256;

/// The exact checkout a purchase approval covers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckoutPlan {
    /// The product page the item is added to the cart from.
    pub product_url: String,
    /// The control on the product page that adds the item to the cart.
    pub add_to_cart: String,
    /// The vendor's checkout page, where the order total is shown.
    pub checkout_url: String,
    /// The control on the checkout page that places the order.
    pub place_order: String,
}

impl CheckoutPlan {
    /// Admits one plan: https pages on one vendor site, bounded selectors.
    pub fn validate(&self) -> Result<(), PurchaseError> {
        let product = vendor_page(&self.product_url, "product_url must be an https page")?;
        let checkout = vendor_page(&self.checkout_url, "checkout_url must be an https page")?;
        if !same_site(&product, &checkout) {
            return Err(PurchaseError::InvalidRequest(
                "the product and checkout pages must be on the same vendor site",
            ));
        }
        for selector in [&self.add_to_cart, &self.place_order] {
            if selector.trim().is_empty()
                || selector.len() > MAX_SELECTOR_BYTES
                || selector.chars().any(char::is_control)
            {
                return Err(PurchaseError::InvalidRequest(
                    "checkout selectors must be 1..=256 bytes without control characters",
                ));
            }
        }
        Ok(())
    }

    /// The vendor host the checkout pages live on (`www.` stripped).
    pub fn vendor_host(&self) -> Result<String, PurchaseError> {
        vendor_page(&self.checkout_url, "checkout_url must be an https page")
    }

    /// True when `origin` (a page origin such as `https://www.example.com`)
    /// belongs to this plan's vendor site.
    pub fn covers_origin(&self, origin: &str) -> bool {
        let Ok(host) = self.vendor_host() else {
            return false;
        };
        vendor_page(origin, "")
            .map(|page| same_site(&host, &page))
            .unwrap_or(false)
    }

    /// Canonical, fixed-order form embedded in the request digest.
    pub(super) fn canonical_json(&self) -> String {
        format!(
            "{{\"add_to_cart\":\"{}\",\"checkout_url\":\"{}\",\"place_order\":\"{}\",\"product_url\":\"{}\"}}",
            escape_json(&self.add_to_cart),
            escape_json(&self.checkout_url),
            escape_json(&self.place_order),
            escape_json(&self.product_url),
        )
    }
}

/// Parses one https page and returns its host without a leading `www.`.
fn vendor_page(raw: &str, refusal: &'static str) -> Result<String, PurchaseError> {
    if raw.len() > MAX_URL_BYTES {
        return Err(PurchaseError::InvalidRequest(refusal));
    }
    let url = Url::parse(raw).map_err(|_| PurchaseError::InvalidRequest(refusal))?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return Err(PurchaseError::InvalidRequest(refusal));
    }
    let host = url
        .host_str()
        .ok_or(PurchaseError::InvalidRequest(refusal))?
        .to_ascii_lowercase();
    Ok(host.strip_prefix("www.").unwrap_or(&host).to_owned())
}

/// One vendor site: equal hosts, or one a subdomain of the other
/// (`secure.shop.example` checks out for `shop.example`). Two unrelated
/// sites under one public suffix never match, because neither host is a
/// suffix of the other.
fn same_site(left: &str, right: &str) -> bool {
    left == right || left.ends_with(&format!(".{right}")) || right.ends_with(&format!(".{left}"))
}

impl PurchaseAdapterContract {
    /// Browser-backed purchases require a checkout plan before approval or exchange.
    pub fn requires_checkout_plan(&self) -> bool {
        self.operation
            .credential_handle
            .as_ref()
            .is_some_and(|handle| handle.as_str() == GOVERNED_BROWSER_CREDENTIAL_HANDLE)
    }

    /// Admits the browser backend with the same R3, idempotency, credential, and evidence requirements.
    pub fn governed_browser() -> Result<Self, PurchaseError> {
        let wire = json!({
            "schema": "odin.adapter.descriptor.v1",
            "adapter": {
                "adapter_id": PURCHASE_BACKEND_ADAPTER_ID,
                "version": "1.0.0",
                "binding_digest": odin_domain::Digest::hash(
                    b"odin.purchase.governed-browser.v1"
                ).to_string(),
            },
            "protocol_version": 1,
            "operations": [{
                "kind": PURCHASE_OPERATION_WIRE_ID,
                "input_schema": "schemas/capability/purchase.submit.input.json",
                "output_schema": "schemas/capability/purchase.submit.output.json",
                "effect_class": "R3",
                "idempotency": "required",
                "evidence": [{
                    "kind": "purchase.submit.evidence",
                    "schema": "schemas/capability/purchase.submit.output.json",
                    "required": true,
                }],
                "credential_handle": GOVERNED_BROWSER_CREDENTIAL_HANDLE,
                "taint_after": "credential_tainted",
            }],
            "credential_handles": [GOVERNED_BROWSER_CREDENTIAL_HANDLE],
            "initial_taint": "credential_tainted",
        });
        let descriptor = AdapterDescriptor::from_wire(&wire).map_err(|_| {
            PurchaseError::Contract("the governed-browser purchase descriptor does not parse")
        })?;
        Self::admit(descriptor)
    }
}

/// Decoded approved request and checkout plan received by the backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckoutOrder {
    /// The JSON-RPC id (the approved command id) every reply must echo.
    pub request_id: String,
    pub idempotency_key: String,
    pub request: PurchaseRequest,
    pub plan: CheckoutPlan,
}

/// Why a frame cannot become an order. Every variant is decided before any
/// browser action, so the reply is a typed refusal with zero effect.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CheckoutFrameError {
    #[error("the purchase frame is not a purchase.submit JSON-RPC request")]
    Frame,
    #[error("the approved purchase carries no checkout plan; nothing is bought")]
    NoPlan,
    #[error("the approved purchase is invalid: {0}")]
    Request(PurchaseError),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FrameInput {
    amount_cents: i64,
    checkout: Option<CheckoutPlan>,
    currency: String,
    item: String,
    vendor: String,
}

impl CheckoutOrder {
    /// Decodes one request line. Returns the JSON-RPC id alongside the
    /// error when it is known, so even a refusal answers THIS command.
    pub fn from_frame(line: &str) -> Result<Self, (Option<String>, CheckoutFrameError)> {
        let value: Value =
            serde_json::from_str(line.trim()).map_err(|_| (None, CheckoutFrameError::Frame))?;
        let id = value.get("id").and_then(Value::as_str).map(str::to_owned);
        let fail = |error| (id.clone(), error);
        if value.get("method").and_then(Value::as_str) != Some(PURCHASE_OPERATION_WIRE_ID) {
            return Err(fail(CheckoutFrameError::Frame));
        }
        let request_id = id.clone().ok_or_else(|| fail(CheckoutFrameError::Frame))?;
        let params = value
            .get("params")
            .ok_or_else(|| fail(CheckoutFrameError::Frame))?;
        let idempotency_key = params
            .get("idempotency_key")
            .and_then(Value::as_str)
            .ok_or_else(|| fail(CheckoutFrameError::Frame))?
            .to_owned();
        let input: FrameInput = params
            .get("input")
            .cloned()
            .and_then(|input| serde_json::from_value(input).ok())
            .ok_or_else(|| fail(CheckoutFrameError::Frame))?;
        let plan = input
            .checkout
            .ok_or_else(|| fail(CheckoutFrameError::NoPlan))?;
        let request =
            PurchaseRequest::new(input.vendor, input.item, input.amount_cents, input.currency)
                .and_then(|request| request.with_checkout(plan.clone()))
                .map_err(|error| fail(CheckoutFrameError::Request(error)))?;
        Ok(Self {
            request_id,
            idempotency_key,
            request,
            plan,
        })
    }
}

/// The settled reply for a placed order (`provider_ref` ≤ 256 bytes).
pub fn checkout_reply_placed(request_id: &str, provider_ref: &str) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "result": { "provider_ref": provider_ref },
    })
    .to_string()
}

/// The reply for an order the backend refused BEFORE the place-order
/// control was touched: nothing was bought.
pub fn checkout_reply_refused(request_id: Option<&str>, message: &str) -> String {
    error_reply(request_id, AdapterErrorCode::InvalidParams, message)
}

/// The reply for an order whose place-order step may have landed: the
/// effect is in doubt and must reconcile from the vendor's order history.
pub fn checkout_reply_uncertain(request_id: Option<&str>, message: &str) -> String {
    error_reply(request_id, AdapterErrorCode::InternalError, message)
}

fn error_reply(request_id: Option<&str>, code: AdapterErrorCode, message: &str) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "error": { "code": code.code(), "message": message },
    })
    .to_string()
}

/// True when the checkout page text shows the approved amount: the major
/// and minor units as a decimal (`12.34`, also `1,234.56`), not embedded in
/// a longer number. A page that does not show the approved total is never
/// ordered from.
pub fn page_shows_amount(text: &str, amount_cents: i64) -> bool {
    if amount_cents <= 0 {
        return false;
    }
    let major = amount_cents / 100;
    let minor = amount_cents % 100;
    let plain = format!("{major}.{minor:02}");
    let grouped = format!("{}.{minor:02}", group_thousands(major));
    [plain, grouped]
        .iter()
        .any(|needle| contains_number(text, needle))
}

fn group_thousands(value: i64) -> String {
    let digits = value.to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    grouped
}

fn contains_number(text: &str, needle: &str) -> bool {
    text.match_indices(needle).any(|(start, _)| {
        let before = text[..start].chars().next_back();
        let mut after = text[start + needle.len()..].chars();
        let continues = match after.next() {
            Some(c) if c.is_ascii_digit() => true,
            Some('.' | ',') => after.next().is_some_and(|c| c.is_ascii_digit()),
            _ => false,
        };
        !before.is_some_and(|c| c.is_ascii_digit() || c == ',' || c == '.') && !continues
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> CheckoutPlan {
        CheckoutPlan {
            product_url: "https://www.shop.example/dp/B0CHEAP".to_owned(),
            add_to_cart: "#add-to-cart-button".to_owned(),
            checkout_url: "https://secure.shop.example/checkout".to_owned(),
            place_order: "input[name=placeYourOrder1]".to_owned(),
        }
    }

    #[test]
    fn a_plan_must_stay_on_one_vendor_site_over_https() {
        assert!(plan().validate().is_ok());
        let mut elsewhere = plan();
        elsewhere.checkout_url = "https://evil.example/checkout".to_owned();
        assert!(elsewhere.validate().is_err());
        let mut sibling = plan();
        sibling.checkout_url = "https://other.example/checkout".to_owned();
        assert!(sibling.validate().is_err());
        let mut plain = plan();
        plain.product_url = "http://www.shop.example/dp/B0CHEAP".to_owned();
        assert!(plain.validate().is_err());
        let mut empty = plan();
        empty.place_order = " ".to_owned();
        assert!(empty.validate().is_err());
        assert!(plan().covers_origin("https://www.shop.example"));
        assert!(!plan().covers_origin("https://pay.elsewhere.example"));
    }

    #[test]
    fn the_plan_is_part_of_what_the_approval_binds() {
        let bare = PurchaseRequest::new("Shop", "Cable", 799, "USD").expect("request");
        let with_plan = bare.clone().with_checkout(plan()).expect("plan");
        let mut moved = plan();
        moved.place_order = "#buy-now".to_owned();
        let with_other = bare.clone().with_checkout(moved).expect("plan");
        assert_ne!(bare.args_digest(), with_plan.args_digest());
        assert_ne!(with_plan.args_digest(), with_other.args_digest());
        // An absent checkout plan adds no field to the canonical request.
        assert_eq!(
            bare.canonical_json(),
            "{\"amount_cents\":799,\"currency\":\"USD\",\"item\":\"Cable\",\"vendor\":\"Shop\"}"
        );
    }

    #[test]
    fn the_frame_round_trips_into_the_approved_order() {
        let request = PurchaseRequest::new("Shop", "Cable", 799, "USD")
            .expect("request")
            .with_checkout(plan())
            .expect("plan");
        let input: Value = serde_json::from_str(&request.canonical_json()).expect("json");
        let line = json!({
            "jsonrpc": "2.0",
            "id": "cmd-1",
            "method": PURCHASE_OPERATION_WIRE_ID,
            "params": { "operation_id": PURCHASE_OPERATION_WIRE_ID, "idempotency_key": "purchase:ab", "input": input },
        })
        .to_string();
        let order = CheckoutOrder::from_frame(&line).expect("order");
        assert_eq!(order.request, request);
        assert_eq!(order.request_id, "cmd-1");

        let bare: Value = serde_json::from_str(
            &PurchaseRequest::new("Shop", "Cable", 799, "USD")
                .expect("request")
                .canonical_json(),
        )
        .expect("json");
        let line = json!({
            "jsonrpc": "2.0", "id": "cmd-2", "method": PURCHASE_OPERATION_WIRE_ID,
            "params": { "operation_id": PURCHASE_OPERATION_WIRE_ID, "idempotency_key": "k", "input": bare },
        })
        .to_string();
        assert_eq!(
            CheckoutOrder::from_frame(&line),
            Err((Some("cmd-2".to_owned()), CheckoutFrameError::NoPlan))
        );
    }

    #[test]
    fn the_governed_browser_contract_is_admitted_by_the_purchase_law() {
        let contract = PurchaseAdapterContract::governed_browser().expect("admitted");
        assert_eq!(
            contract.operation().credential_handle,
            Some(
                odin_domain::huginn::OpaqueCredentialHandle::new(
                    GOVERNED_BROWSER_CREDENTIAL_HANDLE
                )
                .expect("handle")
            )
        );
    }

    #[test]
    fn the_checkout_page_must_show_the_approved_total() {
        assert!(page_shows_amount("Order total: $7.99", 799));
        assert!(page_shows_amount("Total 1,234.50 USD", 123_450));
        assert!(page_shows_amount("Total 1234.50", 123_450));
        assert!(!page_shows_amount("Order total: $17.99", 799));
        assert!(!page_shows_amount("Order total: $7.991", 799));
        assert!(!page_shows_amount("Order total: $7.99.5", 799));
        assert!(!page_shows_amount("Order total: $8.99", 799));
        assert!(page_shows_amount("Total: $7.99.", 799));
    }
}
