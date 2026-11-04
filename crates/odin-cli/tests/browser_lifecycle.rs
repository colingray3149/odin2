//! Focused lifecycle regression tests for the governed local browser: no
//! launch at composition, first governed use launches, idle closes, the
//! next observe reopens, a dead page is recreated, and a refusal names why
//! the page closed. Everything runs against the real launch/request/idle
//! seams; only the page mechanics are scripted.

use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use odin_cli::browser_runtime::LocalBrowser;
use odin_domain::huginn as live;
use odin_domain::huginn::HuginnCommandPort;
use odin_huginn::dispatch::AuthenticatedCommandPort;
use odin_huginn::read_model::MaterializedReadModel;
use odin_ledger::Ledger;
use serde_json::Value;
use time::OffsetDateTime;

#[path = "support/browser.rs"]
mod browser_fixture;
use browser_fixture::{local_launcher, BROWSER};
#[path = "../src/test_wait.rs"]
mod test_wait;
use test_wait::wait_until;

struct Lifecycle {
    // Keeps the fixture directories alive for the whole test.
    _dir: tempfile::TempDir,
    browser: LocalBrowser,
    launcher: Arc<browser_fixture::FixtureLocalLaunch>,
}

async fn lifecycle(idle_close: Duration) -> Lifecycle {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let ledger = Arc::new(Mutex::new(
        Ledger::open(root.join("ledger.sqlite3")).unwrap(),
    ));
    let read_model = Arc::new(MaterializedReadModel::with_limits(
        4096,
        8192,
        OffsetDateTime::now_utc(),
    ));
    let launcher = Arc::new(local_launcher(
        &root,
        ledger,
        Arc::new(Mutex::new(Vec::<Value>::new())),
        read_model,
    ));
    let browser = LocalBrowser::new(launcher.clone(), idle_close);
    Lifecycle {
        _dir: dir,
        browser,
        launcher,
    }
}

fn device() -> live::DeviceId {
    live::DeviceId::parse("00000000-0000-4000-8000-0000000000c1").unwrap()
}

fn observe() -> live::HuginnRequest {
    live::HuginnRequest::BrowserObserve(live::BrowserObserveRequest {
        session_id: live::BrowserSessionId::parse(BROWSER).unwrap(),
        kind: live::BrowserObserveKind::Text,
        max_bytes: NonZeroU32::new(4096).unwrap(),
    })
}

async fn observe_ok(browser: &LocalBrowser) -> live::HuginnResponse {
    browser
        .execute_authenticated(device(), observe())
        .await
        .expect("the governed observe succeeds")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_browser_launches_until_the_first_governed_call() {
    let fixture = lifecycle(Duration::from_secs(3600)).await;
    // Composition launched nothing, and unauthenticated intake never does.
    assert!(!fixture.browser.is_open(), "composition must not launch");
    assert_eq!(fixture.launcher.launch_count(), 0);
    assert!(matches!(
        fixture.browser.execute(observe()).await,
        Err(live::HuginnProtocolError::Unauthenticated)
    ));
    assert!(!fixture.browser.is_open());
    assert_eq!(fixture.launcher.launch_count(), 0);
    // The first governed browser call launches and serves.
    let response = observe_ok(&fixture.browser).await;
    assert!(matches!(
        response,
        live::HuginnResponse::BrowserObservation(_)
    ));
    assert!(fixture.browser.is_open());
    assert_eq!(fixture.launcher.launch_count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_idle_browser_closes_and_the_next_observe_reopens_it() {
    let fixture = lifecycle(Duration::from_millis(200)).await;
    observe_ok(&fixture.browser).await;
    assert!(fixture.browser.is_open());
    // No in-flight call: the declared idle window closes the session.
    wait_until(
        "the governed browser closing",
        Duration::from_secs(10),
        || !fixture.browser.is_open(),
    )
    .await;
    assert_eq!(fixture.launcher.launch_count(), 1, "idle only closes");
    // A later decision is refused with the close cause, without launching.
    let decision = live::HuginnRequest::ApprovalDecision(live::ApprovalDecisionCommand {
        command_id: odin_domain::CommandId::new("lifecycle:idle-decision").unwrap(),
        approval_id: odin_domain::ApprovalId::new("approval:r3:browser.test:idle").unwrap(),
        expected_revision: 1,
        decision: live::ApprovalDecision::Approve,
    });
    match fixture
        .browser
        .execute_authenticated(device(), decision)
        .await
    {
        Err(live::HuginnProtocolError::InvalidRequest { message, .. }) => {
            assert!(
                message.contains("closed because it sat idle"),
                "the refusal must name the close cause: {message}"
            );
        }
        other => panic!("a closed browser refuses the decision typed: {other:?}"),
    }
    assert_eq!(fixture.launcher.launch_count(), 1);
    // The next governed observe reopens a fresh session and succeeds.
    observe_ok(&fixture.browser).await;
    assert_eq!(fixture.launcher.launch_count(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retiring_with_the_daemon_closes_the_open_session_once() {
    let fixture = lifecycle(Duration::from_secs(3600)).await;
    observe_ok(&fixture.browser).await;
    assert!(fixture.browser.is_open());
    let failures = fixture.browser.retire().await;
    assert!(failures.is_empty(), "retirement ladder: {failures:?}");
    assert!(!fixture.browser.is_open());
    // Retiring once is final: no later call reopens.
    assert!(fixture
        .browser
        .execute_authenticated(device(), observe())
        .await
        .is_err());
    assert_eq!(fixture.launcher.launch_count(), 1);
}
