//! The governed-browser purchase backend.
//!
//! Hermes submits only after the kernel consumes approval for the exact
//! request and [`CheckoutPlan`]. Browser steps share that purchase approval,
//! but still pass policy and outbound-safety checks and enter the command journal.
//!
//! Steps: open the product page, add to cart, open the checkout page, read
//! it, and click place-order only if the page is on the vendor's site and
//! shows the approved amount. Anything that fails before the place-order
//! click is a typed refusal (nothing bought); a failure at or after it is
//! in doubt and reconciles from the vendor's order history.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use odin_browser::capability::{ActionArguments, ActionRequest, ElementRef};
use odin_browser::session::ConsumedApproval;
use odin_browser::{ReadKind, ReadRequest, StructuralAction, TypedRead};
use odin_domain::{CommandId, Digest};
use odin_hermes::purchase::{
    checkout_reply_placed, checkout_reply_refused, checkout_reply_uncertain, page_shows_amount,
    CheckoutOrder, PurchaseFault, PurchaseFrameExchange,
};
use odin_ledger::command::CommandSpec;
use time::OffsetDateTime;

use super::protocol::{durable_revision, prepare_action_failure_code};
use super::{BrowserCommandCoordinator, JournalDisposition, COMMAND_TTL};

const CHECKOUT_ISSUER: &str = "odin-purchase-checkout";
const CHECKOUT_TARGET_KIND: &str = "browser";
const CHECKOUT_READ_BYTES: u64 = 262_144;
const MAX_PROVIDER_REF_BYTES: usize = 256;

/// One step of the approved checkout, in order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CheckoutStep {
    OpenProduct,
    AddToCart,
    OpenCheckout,
    ReadCheckout,
    PlaceOrder,
    ReadConfirmation,
}

impl fmt::Display for CheckoutStep {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::OpenProduct => "open_product",
            Self::AddToCart => "add_to_cart",
            Self::OpenCheckout => "open_checkout",
            Self::ReadCheckout => "read_checkout",
            Self::PlaceOrder => "place_order",
            Self::ReadConfirmation => "read_confirmation",
        })
    }
}

/// How one checkout ended short of a placed order.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum CheckoutError {
    /// Decided before the place-order control was touched: nothing bought.
    #[error("checkout stopped at {step} before ordering: {detail}")]
    Refused { step: CheckoutStep, detail: String },
    /// The place-order step ran (or may have): the order is in doubt.
    #[error("checkout in doubt at {step}: {detail}")]
    InDoubt { step: CheckoutStep, detail: String },
}

/// The page facts the checkout reads: the page origin, its sanitized URL
/// and its text.
pub(crate) struct CheckoutPage {
    pub origin: String,
    pub url: String,
    pub text: String,
}

/// The browser the checkout drives. Production is the governed session
/// (`BrowserCommandCoordinator`); tests script it.
#[async_trait]
pub(crate) trait CheckoutBrowser: Send + Sync {
    async fn act(
        &self,
        order: &CheckoutOrder,
        step: CheckoutStep,
        request: ActionRequest,
    ) -> Result<(), String>;
    async fn read_page(&self) -> Result<CheckoutPage, String>;
}

pub(crate) async fn run_checkout(
    browser: &dyn CheckoutBrowser,
    order: &CheckoutOrder,
) -> Result<String, CheckoutError> {
    let plan = &order.plan;
    let refused = |step, detail: String| CheckoutError::Refused { step, detail };
    let navigate = |url: &str| {
        ActionRequest::new(
            StructuralAction::Navigate,
            ActionArguments::Url {
                url: url.to_owned(),
            },
        )
        .map_err(|error| error.to_string())
    };
    let activate = |selector: &str| {
        ElementRef::new(selector.to_owned())
            .and_then(|selector| {
                ActionRequest::new(
                    StructuralAction::Activate,
                    ActionArguments::Selector { selector },
                )
            })
            .map_err(|error| error.to_string())
    };

    let step = CheckoutStep::OpenProduct;
    let request = navigate(&plan.product_url).map_err(|detail| refused(step, detail))?;
    browser
        .act(order, step, request)
        .await
        .map_err(|detail| refused(step, detail))?;

    let step = CheckoutStep::AddToCart;
    let request = activate(&plan.add_to_cart).map_err(|detail| refused(step, detail))?;
    browser
        .act(order, step, request)
        .await
        .map_err(|detail| refused(step, detail))?;

    let step = CheckoutStep::OpenCheckout;
    let request = navigate(&plan.checkout_url).map_err(|detail| refused(step, detail))?;
    browser
        .act(order, step, request)
        .await
        .map_err(|detail| refused(step, detail))?;

    let step = CheckoutStep::ReadCheckout;
    let page = browser
        .read_page()
        .await
        .map_err(|detail| refused(step, detail))?;
    if !plan.covers_origin(&page.origin) {
        return Err(refused(
            step,
            format!(
                "the checkout page is on {} — not the approved vendor site",
                page.origin
            ),
        ));
    }
    if !page_shows_amount(&page.text, order.request.amount_cents()) {
        return Err(refused(
            step,
            format!(
                "the checkout page does not show the approved total ({} {}.{:02})",
                order.request.currency(),
                order.request.amount_cents() / 100,
                order.request.amount_cents() % 100
            ),
        ));
    }

    let step = CheckoutStep::PlaceOrder;
    let request = activate(&plan.place_order).map_err(|detail| refused(step, detail))?;
    browser
        .act(order, step, request)
        .await
        .map_err(|detail| CheckoutError::InDoubt { step, detail })?;

    let step = CheckoutStep::ReadConfirmation;
    let confirmation = browser
        .read_page()
        .await
        .map_err(|detail| CheckoutError::InDoubt { step, detail })?;
    Ok(provider_ref(&confirmation.url))
}

/// The receipt reference: the confirmation page's sanitized URL, or its
/// digest when the URL is longer than the receipt bound.
fn provider_ref(url: &str) -> String {
    if !url.is_empty() && url.len() <= MAX_PROVIDER_REF_BYTES {
        url.to_owned()
    } else {
        format!("confirmation:{}", Digest::hash(url.as_bytes()))
    }
}

pub(crate) async fn answer_frame(browser: &dyn CheckoutBrowser, request_line: &str) -> String {
    let order = match CheckoutOrder::from_frame(request_line) {
        Ok(order) => order,
        Err((id, error)) => {
            tracing::error!("purchase checkout refused step=frame command={id:?}: {error}");
            return checkout_reply_refused(id.as_deref(), &error.to_string());
        }
    };
    let id = order.request_id.as_str();
    let vendor = order.request.vendor();
    match run_checkout(browser, &order).await {
        Ok(reference) => {
            tracing::info!(
                "purchase checkout placed command={id} vendor={vendor:?} provider_ref={reference:?}"
            );
            checkout_reply_placed(id, &reference)
        }
        Err(error @ CheckoutError::Refused { .. }) => {
            tracing::error!("purchase checkout refused command={id} vendor={vendor:?}: {error}");
            checkout_reply_refused(Some(id), &error.to_string())
        }
        Err(error @ CheckoutError::InDoubt { .. }) => {
            tracing::warn!("purchase checkout in_doubt command={id} vendor={vendor:?}: {error}");
            checkout_reply_uncertain(Some(id), &error.to_string())
        }
    }
}

/// The governed-browser purchase backend bound into the Hermes runtime.
pub struct BrowserCheckoutBackend {
    coordinator: BrowserCommandCoordinator,
}

impl BrowserCheckoutBackend {
    pub fn new(coordinator: BrowserCommandCoordinator) -> Arc<Self> {
        Arc::new(Self { coordinator })
    }
}

impl PurchaseFrameExchange for BrowserCheckoutBackend {
    fn exchange(&self, request_line: String) -> Result<String, PurchaseFault> {
        let coordinator = self.coordinator.clone();
        Ok(self
            .coordinator
            .runtime
            .block_on(async move { answer_frame(&coordinator, &request_line).await }))
    }
}

#[async_trait]
impl CheckoutBrowser for BrowserCommandCoordinator {
    /// Executes one checkout step on the governed session under the
    /// purchase approval: outbound safety, the live policy rule, a journal
    /// row keyed to (approved command, step) — so a replay never clicks
    /// twice — then the session executes it. Where the policy asks for an
    /// approval, the consumed purchase approval is the one presented.
    async fn act(
        &self,
        order: &CheckoutOrder,
        step: CheckoutStep,
        request: ActionRequest,
    ) -> Result<(), String> {
        let browser = self.projection.browser();
        browser
            .validate_outbound(&request)
            .await
            .map_err(|error| format!("outbound safety refused the step: {error}"))?;
        let prepared = browser
            .prepare_action(request)
            .await
            .map_err(|error| prepare_action_failure_code(&error).to_owned())?;
        let action_id = prepared.action_id;
        let abandon = |detail: String| async move {
            // Best effort: an unreleased prepared action expires with the
            // session's own bound; the refusal is what the order records.
            let _ = browser.abandon_action(action_id).await;
            detail
        };
        let policy = browser.policy().await;
        if !policy.binding_is_current(&prepared.policy_binding)
            || policy.rule(&prepared.policy_action) != Some(&prepared.rule)
        {
            return Err(abandon("the browser policy changed during the step".to_owned()).await);
        }
        let revision = match durable_revision(prepared.control_revision) {
            Ok(revision) => revision,
            Err(error) => return Err(abandon(error.to_string()).await),
        };
        let capability_version = match i64::try_from(prepared.rule.capability_version) {
            Ok(version) => version,
            Err(_) => return Err(abandon("capability version out of range".to_owned()).await),
        };
        let key = Digest::hash(
            format!("{}|{}|{step}", order.request_id, order.idempotency_key).as_bytes(),
        );
        let command_id = match CommandId::new(format!("purchase.checkout:{key}")) {
            Ok(id) => id,
            Err(error) => return Err(abandon(error.to_string()).await),
        };
        let causation = Some(order.request_id.clone());
        let arguments =
            serde_json::to_value((&prepared.request.action, &prepared.request.arguments))
                .unwrap_or(serde_json::Value::Null);
        let now = OffsetDateTime::now_utc();
        let spec = CommandSpec {
            id: command_id.clone(),
            idempotency_key: command_id.to_string(),
            correlation_id: order.idempotency_key.clone(),
            causation_id: causation,
            issuer: CHECKOUT_ISSUER.to_owned(),
            approval_id: None,
            target_kind: CHECKOUT_TARGET_KIND.to_owned(),
            target_id: browser.session_id().to_string(),
            capability_id: prepared.rule.capability_id.clone(),
            capability_version,
            arguments_hash: prepared.arguments_digest,
            arguments,
            expected_desired_revision: Some(revision),
            issued_at: now,
            expires_at: now + COMMAND_TTL,
        };
        let accepted = match self.journal(spec) {
            Ok(JournalDisposition::Accepted(accepted)) => accepted,
            Ok(JournalDisposition::Duplicate(_)) => {
                return Err(abandon(
                    "this checkout step already ran for this order; reconcile from the \
                     vendor's order history"
                        .to_owned(),
                )
                .await)
            }
            Err(error) => return Err(abandon(error.to_string()).await),
        };
        let evidence = prepared.rule.approval_required.then(|| ConsumedApproval {
            capability_id: prepared.rule.capability_id.clone(),
            arguments_digest: prepared.arguments_digest,
        });
        self.execute_prepared(&accepted, &prepared, evidence)
            .await
            .map_err(|error| error.to_string())
    }

    async fn read_page(&self) -> Result<CheckoutPage, String> {
        let request = ReadRequest::new(ReadKind::Text, CHECKOUT_READ_BYTES)
            .map_err(|error| error.to_string())?;
        match self.projection.browser().read(request).await {
            Ok(TypedRead::Text(read)) => Ok(CheckoutPage {
                origin: read.metadata.provenance.origin.clone(),
                url: read.metadata.provenance.source_url.display_url().to_owned(),
                text: read.text,
            }),
            Ok(_) => Err("the browser returned a non-text read".to_owned()),
            Err(error) => Err(error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use odin_hermes::purchase::{CheckoutPlan, PurchaseRequest};
    use serde_json::{json, Value};

    use super::*;

    struct ScriptedBrowser {
        steps: Mutex<Vec<CheckoutStep>>,
        pages: Mutex<Vec<CheckoutPage>>,
        fail_at: Option<CheckoutStep>,
    }

    impl ScriptedBrowser {
        fn new(pages: Vec<CheckoutPage>, fail_at: Option<CheckoutStep>) -> Self {
            Self {
                steps: Mutex::new(Vec::new()),
                pages: Mutex::new(pages),
                fail_at,
            }
        }

        fn steps(&self) -> Vec<CheckoutStep> {
            self.steps.lock().expect("steps").clone()
        }
    }

    #[async_trait]
    impl CheckoutBrowser for ScriptedBrowser {
        async fn act(
            &self,
            _order: &CheckoutOrder,
            step: CheckoutStep,
            _request: ActionRequest,
        ) -> Result<(), String> {
            if self.fail_at == Some(step) {
                return Err("scripted failure".to_owned());
            }
            self.steps.lock().expect("steps").push(step);
            Ok(())
        }

        async fn read_page(&self) -> Result<CheckoutPage, String> {
            let mut pages = self.pages.lock().expect("pages");
            if pages.is_empty() {
                return Err("no page".to_owned());
            }
            Ok(pages.remove(0))
        }
    }

    fn page(origin: &str, url: &str, text: &str) -> CheckoutPage {
        CheckoutPage {
            origin: origin.to_owned(),
            url: url.to_owned(),
            text: text.to_owned(),
        }
    }

    fn frame() -> String {
        let request = PurchaseRequest::new("Shop", "USB-C cable", 799, "USD")
            .expect("request")
            .with_checkout(CheckoutPlan {
                product_url: "https://www.shop.example/dp/B0CHEAP".to_owned(),
                add_to_cart: "#add-to-cart-button".to_owned(),
                checkout_url: "https://www.shop.example/checkout".to_owned(),
                place_order: "#place-order".to_owned(),
            })
            .expect("plan");
        let input: Value = serde_json::from_str(&request.canonical_json()).expect("json");
        json!({
            "jsonrpc": "2.0", "id": "cmd-1", "method": "purchase.submit",
            "params": { "operation_id": "purchase.submit", "idempotency_key": "purchase:ab", "input": input },
        })
        .to_string()
    }

    fn reply(line: &str) -> Value {
        serde_json::from_str(line).expect("reply json")
    }

    #[tokio::test]
    async fn an_approved_checkout_places_the_order_and_returns_the_confirmation() {
        let browser = ScriptedBrowser::new(
            vec![
                page(
                    "https://www.shop.example",
                    "https://www.shop.example/checkout",
                    "Order total: $7.99",
                ),
                page(
                    "https://www.shop.example",
                    "https://www.shop.example/thankyou?order=1",
                    "Thanks",
                ),
            ],
            None,
        );
        let answer = reply(&answer_frame(&browser, &frame()).await);
        assert_eq!(answer["id"], "cmd-1");
        assert_eq!(
            answer["result"]["provider_ref"],
            "https://www.shop.example/thankyou?order=1"
        );
        assert_eq!(
            browser.steps(),
            vec![
                CheckoutStep::OpenProduct,
                CheckoutStep::AddToCart,
                CheckoutStep::OpenCheckout,
                CheckoutStep::PlaceOrder
            ]
        );
    }

    #[tokio::test]
    async fn a_checkout_page_without_the_approved_total_is_never_ordered_from() {
        let browser = ScriptedBrowser::new(
            vec![page(
                "https://www.shop.example",
                "https://www.shop.example/checkout",
                "Order total: $17.99",
            )],
            None,
        );
        let answer = reply(&answer_frame(&browser, &frame()).await);
        // A typed refusal (InvalidParams): provably nothing bought.
        assert_eq!(answer["error"]["code"], -32602);
        assert!(!browser.steps().contains(&CheckoutStep::PlaceOrder));
    }

    #[tokio::test]
    async fn a_checkout_redirected_off_the_vendor_site_is_refused() {
        let browser = ScriptedBrowser::new(
            vec![page(
                "https://pay.elsewhere.example",
                "https://pay.elsewhere.example/c",
                "Total $7.99",
            )],
            None,
        );
        let answer = reply(&answer_frame(&browser, &frame()).await);
        assert_eq!(answer["error"]["code"], -32602);
        assert!(!browser.steps().contains(&CheckoutStep::PlaceOrder));
    }

    #[tokio::test]
    async fn a_failed_place_order_click_is_in_doubt_not_refused() {
        let browser = ScriptedBrowser::new(
            vec![page(
                "https://www.shop.example",
                "https://www.shop.example/checkout",
                "Total $7.99",
            )],
            Some(CheckoutStep::PlaceOrder),
        );
        let answer = reply(&answer_frame(&browser, &frame()).await);
        // An uncertain order needs reconciliation, not a refusal inviting a retry.
        assert_eq!(answer["error"]["code"], -32603);
    }

    #[tokio::test]
    async fn a_frame_without_a_checkout_plan_touches_no_browser() {
        let bare: Value = serde_json::from_str(
            &PurchaseRequest::new("Shop", "Cable", 799, "USD")
                .expect("request")
                .canonical_json(),
        )
        .expect("json");
        let line = json!({
            "jsonrpc": "2.0", "id": "cmd-2", "method": "purchase.submit",
            "params": { "operation_id": "purchase.submit", "idempotency_key": "k", "input": bare },
        })
        .to_string();
        let browser = ScriptedBrowser::new(Vec::new(), None);
        let answer = reply(&answer_frame(&browser, &line).await);
        assert_eq!(answer["id"], "cmd-2");
        assert_eq!(answer["error"]["code"], -32602);
        assert!(browser.steps().is_empty());
    }

    #[test]
    fn a_long_confirmation_url_becomes_a_bounded_reference() {
        let long = format!("https://shop.example/{}", "a".repeat(400));
        let reference = provider_ref(&long);
        assert!(reference.starts_with("confirmation:"));
        assert!(reference.len() <= MAX_PROVIDER_REF_BYTES);
    }
}
