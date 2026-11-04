//! Device-specific token admission and cleanup with a headless launcher.
//! Route startup is bypassed, so fixtures provision the seat binding and token root.
//! Barrier waits race admission completion to expose refusals rather than hang.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use odin_cli::authority_provision::{
    compose, ensure_session_token, LaunchSelection, TokenRenewalPolicy, DEFAULT_TOKEN_TTL_SECONDS,
};
use odin_domain::huginn::{
    LiveError, OpenSessionRequest, SessionEpoch, SessionManifest, TailnetNodeId,
};
use odin_domain::{CommandId, Digest, NodeId};
use odin_huginn::devices::{DeviceTrustStore, NewDeviceRecord, SqliteDeviceTrustStore};
use odin_kernel::{LedgerRevocations, RevocationStore as _};
use odin_ledger::Ledger;
use odin_omp::live::supervisor::{LiveSessionLauncher, SessionRuntime};
use time::OffsetDateTime;

use super::DeviceOpenAuthority;

const LAUNCH_REFUSED: &str = "device open regression: launches toggled off";

/// Records admitted manifests and allows tests to refuse launches.
struct ToggleLaunch {
    open_ok: AtomicBool,
    known_resources: AtomicBool,
    admitted: parking_lot::Mutex<Vec<SessionManifest>>,
    barrier: parking_lot::Mutex<Option<Arc<LaunchBarrier>>>,
    validation: parking_lot::Mutex<Option<Arc<dyn LaunchValidation>>>,
    prompt_barrier: parking_lot::Mutex<Option<Arc<LaunchBarrier>>>,
}

impl ToggleLaunch {
    fn set(open_ok: bool) -> Arc<Self> {
        Arc::new(Self {
            open_ok: AtomicBool::new(open_ok),
            known_resources: AtomicBool::new(true),
            admitted: parking_lot::Mutex::new(Vec::new()),
            barrier: parking_lot::Mutex::new(None),
            validation: parking_lot::Mutex::new(None),
            prompt_barrier: parking_lot::Mutex::new(None),
        })
    }

    fn toggle(&self, open_ok: bool) {
        self.open_ok.store(open_ok, Ordering::SeqCst);
    }

    fn manifests(&self) -> Vec<SessionManifest> {
        self.admitted.lock().clone()
    }
}

#[async_trait::async_trait]
trait LaunchValidation: Send + Sync {
    async fn validate(&self, manifest: &SessionManifest);
}

#[derive(Default)]
struct LaunchBarrier {
    entered: tokio::sync::Notify,
    resume: tokio::sync::Notify,
    terminated: AtomicBool,
}

/// The prompt hook that parks the initial prompt on `barrier` until it is resumed.
fn hold_prompt(barrier: Arc<LaunchBarrier>) -> crate::test_fixture::PromptHook {
    Arc::new(move || {
        let barrier = Arc::clone(&barrier);
        Box::pin(async move {
            let _termination = TerminationWitness(Arc::clone(&barrier));
            barrier.entered.notify_one();
            barrier.resume.notified().await;
        })
    })
}

struct TerminationWitness(Arc<LaunchBarrier>);

impl Drop for TerminationWitness {
    fn drop(&mut self) {
        self.0.terminated.store(true, Ordering::SeqCst);
    }
}
#[async_trait::async_trait]
impl LiveSessionLauncher for ToggleLaunch {
    fn harness_turns(&self) -> Option<std::sync::Arc<odin_omp::live::harness::HarnessTurns>> {
        None
    }

    // This fixture spawns no launch descendants: its blocked future has the
    // Drop witness below and its admitted NullBackend owns no carrier.
    fn cancellation_joins_resources(&self) -> bool {
        self.known_resources.load(Ordering::SeqCst)
    }

    async fn open_owned(
        &self,
        manifest: &SessionManifest,
        epoch: SessionEpoch,
        reclaim: bool,
        effects: odin_omp::live::supervisor::LaunchEffects,
    ) -> Result<SessionRuntime, LiveError> {
        // A refusing fixture has no effects, including while its admission
        // barrier is held. Successful launches mark before that barrier so
        // cancellation exercises the explicit resource-join guarantee.
        if self.open_ok.load(Ordering::SeqCst) {
            effects.mark_started();
        }
        self.open(manifest, epoch, reclaim).await
    }

    async fn open(
        &self,
        manifest: &SessionManifest,
        _epoch: SessionEpoch,
        _reclaim: bool,
    ) -> Result<SessionRuntime, LiveError> {
        let validation = self.validation.lock().clone();
        if let Some(validation) = validation {
            validation.validate(manifest).await;
        }
        let barrier = self.barrier.lock().clone();
        if let Some(barrier) = barrier {
            let _termination = TerminationWitness(Arc::clone(&barrier));
            barrier.entered.notify_one();
            barrier.resume.notified().await;
        }
        if !self.open_ok.load(Ordering::SeqCst) {
            return Err(LiveError::Unsupported {
                operation: LAUNCH_REFUSED.to_owned(),
            });
        }
        self.admitted.lock().push(manifest.clone());
        Ok(SessionRuntime {
            control: Arc::new(crate::test_fixture::NullBackend {
                on_prompt: self.prompt_barrier.lock().clone().map(hold_prompt),
                ..Default::default()
            }),
            terminal: None,
            observations: None,
            failed_notices: None,
        })
    }
}

fn device(id: &str) -> odin_domain::huginn::DeviceId {
    odin_domain::huginn::DeviceId::parse(id).expect("paired device id")
}

async fn paired(store: &SqliteDeviceTrustStore, id: odin_domain::huginn::DeviceId) {
    store
        .insert(NewDeviceRecord {
            device_id: id,
            tailnet_node_id: TailnetNodeId::parse("node.phone").expect("tailnet node"),
            label: "phone".to_owned(),
            credential_digest: Digest::hash(id.to_string().as_bytes()),
            created_at: OffsetDateTime::now_utc(),
        })
        .await
        .expect("paired device inserted");
}

fn open_request(fixture: &crate::live::hermes_routes::tests::GateFixture) -> OpenSessionRequest {
    open_request_for(
        fixture,
        &CommandId::new(format!("device-open-{}", uuid::Uuid::new_v4().simple()))
            .expect("command id"),
    )
}

fn open_request_for(
    fixture: &crate::live::hermes_routes::tests::GateFixture,
    command_id: &CommandId,
) -> OpenSessionRequest {
    let seat = &fixture.config.seats[0];
    let option = &seat.launch_options[0];
    let project = fixture
        .config
        .lane_bindings
        .iter()
        .find(|binding| binding.seat == seat.seat)
        .map(|binding| binding.project.clone())
        .expect("declared seat project");
    OpenSessionRequest {
        command_id: command_id.clone(),
        seat_id: seat.seat.clone(),
        project_id: project,
        slice_id: seat.slice.clone(),
        provider: option.provider.clone(),
        model: option.model.clone(),
        title: None,
        target_node: NodeId::new(&fixture.config.identity.node).expect("node id"),
        open_tab: false,
        initial_prompt: None,
        workload: None,
        // The one lie the authority must overwrite with the mint report.
        served_revision: Some(9_999),
    }
}

fn composition_of(
    fixture: &crate::live::hermes_routes::tests::GateFixture,
    command_id: &CommandId,
) -> odin_cli::authority_provision::SessionComposition {
    let seat = &fixture.config.seats[0];
    let option = &seat.launch_options[0];
    let project = fixture
        .config
        .lane_bindings
        .iter()
        .find(|binding| binding.seat == seat.seat)
        .map(|binding| binding.project.clone())
        .expect("declared seat project");
    compose(
        &fixture.config,
        seat.seat.as_str(),
        project.as_str(),
        command_id,
        LaunchSelection::new(option.provider.as_str(), option.model.as_str()),
    )
    .expect("session composition")
}

fn token_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(root)
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect()
}

fn revoked_token_ids(ledger: &Arc<StdMutex<Ledger>>) -> Vec<String> {
    let guard = ledger.lock().unwrap();
    let mut statement = guard
        .connection()
        .prepare(
            "SELECT object_id FROM materialized_status
             WHERE object_kind = 'seat_token_revocation'",
        )
        .expect("revocation scan prepares");
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .expect("revocation scan queries");
    rows.map(|row| row.expect("revocation row")).collect()
}

struct Fixture {
    /// Holds the fixture root (tempdir) alive for the whole test.
    gate: crate::live::hermes_routes::tests::GateFixture,
    launcher: Arc<ToggleLaunch>,
    devices: Arc<SqliteDeviceTrustStore>,
    ledger: Arc<StdMutex<Ledger>>,
    authority: DeviceOpenAuthority,
}

async fn fixture(open_ok: bool) -> Fixture {
    let launcher = ToggleLaunch::set(open_ok);
    let gate = crate::live::hermes_routes::tests::gate_fixture_with(
        8,
        Arc::clone(&launcher) as Arc<dyn LiveSessionLauncher>,
        false,
    )
    .await;
    // GateFixture leaves binding to Hermes route startup. Device, observer,
    // and workload opens bypass that startup and need the same declared seat
    // installed before supervisor admission can reach the launch barriers.
    let (seat_binding, _) = gate.binding().vehicle.expect("declared live vehicle");
    gate.supervisor
        .bind(seat_binding)
        .await
        .expect("bind device fixture seat");
    // The production reader pins an existing directory, even before the first
    // token is minted. Keep it empty so missing-token opens still prove minting.
    std::fs::create_dir_all(&gate.config.paths.authority_token_root)
        .expect("provision empty token root");
    let devices = Arc::new(SqliteDeviceTrustStore::open_in_memory().expect("device store"));
    let ledger = Arc::new(StdMutex::new(
        Ledger::open(gate.config.paths.state_root.join("ledger.sqlite3")).expect("ledger"),
    ));
    let authority = DeviceOpenAuthority::new(
        gate.config.clone(),
        Arc::clone(&devices),
        Arc::clone(&ledger),
        gate.omp.clone(),
    );
    Fixture {
        gate,
        launcher,
        devices,
        ledger,
        authority,
    }
}

/// A successful device open mints the seat token, claims it for the
/// calling device, overwrites the caller's served_revision with the mint
/// report's, and opens the session.
#[tokio::test]
async fn a_device_open_mints_claims_and_opens_with_the_ensured_revision() {
    let fixture = fixture(true).await;
    let phone = device("00000000-0000-4000-8000-0000000000a1");
    paired(&fixture.devices, phone).await;
    let request = open_request(&fixture.gate);

    let summary = fixture
        .authority
        .open_session_for_device(phone, request)
        .await
        .expect("the device open succeeded");

    assert_eq!(
        token_files(&fixture.gate.config.paths.authority_token_root).len(),
        1
    );
    let grants = fixture.devices.grants(phone).await.expect("grant lookup");
    assert_eq!(grants.len(), 1, "the open claimed exactly one grant");
    assert_eq!(grants[0].device_id, phone);
    assert_eq!(grants[0].revoked_at, None);
    let admitted = fixture.launcher.manifests();
    assert_eq!(admitted.len(), 1, "the supervisor admitted one open");
    let served = admitted[0].served_revision.expect("the mint's generation");
    assert_ne!(served, 9_999, "the caller's revision is never trusted");
    assert_eq!(summary.session_id, admitted[0].session_id);
}

/// A failed open after a fresh mint ledger-revokes the token before
/// releasing the claim, and removes the minted file: no bounded authority
/// survives an open that never happened.
#[tokio::test]
async fn a_failed_fresh_open_revokes_the_token_and_releases_the_grant() {
    let fixture = fixture(false).await;
    let phone = device("00000000-0000-4000-8000-0000000000a1");
    paired(&fixture.devices, phone).await;
    let request = open_request(&fixture.gate);

    let error = fixture
        .authority
        .open_session_for_device(phone, request)
        .await
        .expect_err("the toggled-off open refused");

    assert!(
        matches!(&error, LiveError::Unsupported { operation } if operation == LAUNCH_REFUSED),
        "the supervisor's own refusal surfaced: {error:?}"
    );
    let revoked = revoked_token_ids(&fixture.ledger);
    assert_eq!(revoked.len(), 1, "exactly the fresh token was revoked");
    {
        let guard = fixture.ledger.lock().unwrap();
        assert!(
            LedgerRevocations::new(&guard)
                .is_revoked(&odin_domain::SeatTokenId::parse(&revoked[0]).expect("token id"))
                .expect("revocation lookup"),
            "the minted token is dead in the ledger"
        );
    }
    assert!(
        token_files(&fixture.gate.config.paths.authority_token_root).is_empty(),
        "the minted file is rolled back"
    );
    assert!(
        fixture
            .devices
            .grants(phone)
            .await
            .expect("grants")
            .is_empty(),
        "the claim was released"
    );
}

/// A failed open over a pre-existing (CLI-minted) token preserves it: the
/// file stays, the token stays live, only this call's claim is released.
#[tokio::test]
async fn a_failed_reused_open_preserves_the_preexisting_token() {
    let fixture = fixture(false).await;
    let phone = device("00000000-0000-4000-8000-0000000000a1");
    paired(&fixture.devices, phone).await;
    let command_id = CommandId::new("device-open-reused").expect("command id");
    let composition = composition_of(&fixture.gate, &command_id);
    let pre = ensure_session_token(
        &fixture.gate.config,
        &composition,
        DEFAULT_TOKEN_TTL_SECONDS,
        TokenRenewalPolicy::OperatorOnly,
    )
    .expect("the operator pre-mint");
    assert!(!pre.reused_existing, "the pre-mint is fresh for this test");
    let original_bytes = std::fs::read(&pre.token_path).expect("pre-minted token bytes");

    let error = fixture
        .authority
        .open_session_for_device(phone, open_request_for(&fixture.gate, &command_id))
        .await
        .expect_err("the toggled-off open refused");
    assert!(
        matches!(&error, LiveError::Unsupported { operation } if operation == LAUNCH_REFUSED),
        "the supervisor's own refusal surfaced: {error:?}"
    );

    let token_path = fixture
        .gate
        .config
        .paths
        .authority_token_root
        .join(format!("{}.json", composition.session.as_str()));
    assert!(token_path.exists(), "the pre-existing file survived");
    {
        let guard = fixture.ledger.lock().unwrap();
        assert!(
            !LedgerRevocations::new(&guard)
                .is_revoked(&odin_domain::SeatTokenId::parse(&pre.token_id).expect("token id"))
                .expect("revocation lookup"),
            "a reused token is never revoked by a failed open"
        );
    }
    assert!(
        fixture
            .devices
            .grants(phone)
            .await
            .expect("grants")
            .is_empty(),
        "only this call's claim was released"
    );
    fixture.launcher.toggle(true);
    fixture
        .authority
        .open_session_for_device(phone, open_request_for(&fixture.gate, &command_id))
        .await
        .expect("failed uncommitted claim can be reclaimed, not Foreign");
    let grants = fixture.devices.grants(phone).await.unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].token_id.as_str(), pre.token_id);
    assert_eq!(std::fs::read(&pre.token_path).unwrap(), original_bytes);
    assert!(revoked_token_ids(&fixture.ledger).is_empty());
}

/// After the device is revoked — even with its socket long gone — its
/// session authority refuses: the granted token is dead in the ledger, a
/// re-ensure answers the typed revoked refusal, and a new open claims
/// nothing.
#[tokio::test]
async fn a_revoked_device_cannot_reopen_its_authority() {
    let fixture = fixture(true).await;
    let phone = device("00000000-0000-4000-8000-0000000000a1");
    paired(&fixture.devices, phone).await;
    let request = open_request(&fixture.gate);
    let command_id = request.command_id.clone();
    fixture
        .authority
        .open_session_for_device(phone, request)
        .await
        .expect("the first open succeeded");

    // Revoke after disconnect: ledger-first over the granted tokens, then
    // the store's revoked_at.
    let grants = fixture.devices.grants(phone).await.expect("grants");
    assert_eq!(grants.len(), 1);
    let admin = odin_huginn::devices::DeviceAdmin::new(
        Arc::clone(&fixture.devices),
        odin_huginn::dispatch::ConnectionRegistry::new(),
    );
    admin
        .revoke_ledger_first(
            phone,
            odin_cli::authority_provision::ledger_revoke_pass(Arc::clone(&fixture.ledger)),
        )
        .await
        .expect("ledger-first device revoke");

    let composition = composition_of(&fixture.gate, &command_id);
    let revoked = fixture
        .devices
        .grant_snapshot(&grants[0].token_id)
        .await
        .unwrap()
        .expect("revoked grant remains a tombstone");
    assert!(revoked.revoked_at.is_some());
    assert!(
        !fixture
            .devices
            .relinquish_grant_sync(&grants[0].token_id, phone, &composition.session,)
            .unwrap(),
        "relinquish never deletes an actually revoked grant"
    );
    assert_eq!(
        fixture
            .devices
            .grant_snapshot(&grants[0].token_id)
            .await
            .unwrap(),
        Some(revoked)
    );
    let error = ensure_session_token(
        &fixture.gate.config,
        &composition,
        DEFAULT_TOKEN_TTL_SECONDS,
        TokenRenewalPolicy::OperatorOnly,
    )
    .expect_err("revoked authority refuses ensure");
    assert!(
        matches!(&error, odin_cli::authority_provision::EnsureSessionTokenError::Revoked { token_id }
            if token_id == &grants[0].token_id.as_str().to_owned()),
        "the typed revoked refusal names the granted token: {error:?}"
    );

    let error = fixture
        .authority
        .open_session_for_device(phone, open_request(&fixture.gate))
        .await
        .expect_err("a revoked device cannot open again");
    assert!(
        matches!(error, LiveError::DeviceRevoked),
        "the new open answers DeviceRevoked: {error:?}"
    );
    assert!(
        token_files(&fixture.gate.config.paths.authority_token_root).len() == 1,
        "the refused fresh mint rolled back; only the dead session's file remains"
    );
}

/// A second device never adopts another device's owned authority: the
/// shared session's token stays claimed by its owner, live, and unrevoked.
#[tokio::test]
async fn a_foreign_device_cannot_claim_another_devices_authority() {
    let fixture = fixture(true).await;
    let phone = device("00000000-0000-4000-8000-0000000000a1");
    let laptop = device("00000000-0000-4000-8000-0000000000b2");
    paired(&fixture.devices, phone).await;
    paired(&fixture.devices, laptop).await;
    let command_id = CommandId::new("device-open-shared").expect("command id");
    fixture
        .authority
        .open_session_for_device(phone, open_request_for(&fixture.gate, &command_id))
        .await
        .expect("the owner opened");

    fixture.launcher.toggle(false);
    let error = fixture
        .authority
        .open_session_for_device(laptop, open_request_for(&fixture.gate, &command_id))
        .await
        .expect_err("the foreign claim refused");
    assert!(
        matches!(error, LiveError::Unauthorized),
        "the foreign open answers Unauthorized: {error:?}"
    );

    let phone_grants = fixture.devices.grants(phone).await.expect("grants");
    assert_eq!(phone_grants.len(), 1, "the owner's grant is untouched");
    assert!(
        fixture
            .devices
            .grants(laptop)
            .await
            .expect("grants")
            .is_empty(),
        "the foreign device claimed nothing"
    );
    assert_eq!(
        token_files(&fixture.gate.config.paths.authority_token_root).len(),
        1,
        "one session, one token file"
    );
    assert!(
        revoked_token_ids(&fixture.ledger).is_empty(),
        "a foreign refusal never revokes the owned token"
    );
}

/// Concurrent opens of one session serialize: exactly one device wins the
/// claim and the open, and the loser leaves the winner's authority intact.
#[tokio::test]
async fn concurrent_opens_of_one_session_admit_exactly_one_claim() {
    let fixture = fixture(true).await;
    let phone = device("00000000-0000-4000-8000-0000000000a1");
    let laptop = device("00000000-0000-4000-8000-0000000000b2");
    paired(&fixture.devices, phone).await;
    paired(&fixture.devices, laptop).await;
    let command_id = CommandId::new("device-open-race").expect("command id");
    let authority = fixture.authority.clone();

    let (first, second) = tokio::join!(
        authority.open_session_for_device(phone, open_request_for(&fixture.gate, &command_id)),
        authority.open_session_for_device(laptop, open_request_for(&fixture.gate, &command_id)),
    );
    let winners = [&first, &second].iter().filter(|r| r.is_ok()).count();
    assert_eq!(winners, 1, "exactly one concurrent open succeeded");
    assert_eq!(
        fixture.launcher.manifests().len(),
        1,
        "the supervisor admitted one session"
    );
    let total_grants = fixture.devices.grants(phone).await.expect("grants").len()
        + fixture.devices.grants(laptop).await.expect("grants").len();
    assert_eq!(total_grants, 1, "exactly one device owns the token");
    assert_eq!(
        token_files(&fixture.gate.config.paths.authority_token_root).len(),
        1
    );
    assert!(
        revoked_token_ids(&fixture.ledger).is_empty(),
        "the losing claim never revokes the winner's authority"
    );
}

/// The owning shutdown seam: a closed authority refuses new opens typed
/// before anything is minted, and no grant or token file appears.
#[tokio::test]
async fn a_stopped_authority_refuses_new_opens_before_any_mint() {
    let fixture = fixture(true).await;
    let phone = device("00000000-0000-4000-8000-0000000000a1");
    paired(&fixture.devices, phone).await;
    fixture
        .authority
        .stop_handle()
        .stop_until(tokio::time::Instant::now() + std::time::Duration::from_secs(5))
        .await
        .expect("authority stops");

    let error = fixture
        .authority
        .open_session_for_device(phone, open_request(&fixture.gate))
        .await
        .expect_err("the closed authority refuses");
    assert!(
        matches!(&error, LiveError::Unavailable { code, .. } if code == "deviceOpenStopping"),
        "the closed authority answers deviceOpenStopping: {error:?}"
    );
    assert!(token_files(&fixture.gate.config.paths.authority_token_root).is_empty());
    assert!(fixture
        .devices
        .grants(phone)
        .await
        .expect("grants")
        .is_empty());
}

#[tokio::test]
async fn inactive_owner_cannot_reuse_its_existing_grant() {
    let fixture = fixture(true).await;
    let phone = device("00000000-0000-4000-8000-0000000000a1");
    paired(&fixture.devices, phone).await;
    let request = open_request(&fixture.gate);
    fixture
        .authority
        .open_session_for_device(phone, request.clone())
        .await
        .unwrap();
    let before = fixture.devices.grants(phone).await.unwrap();
    fixture
        .devices
        .begin_revoke(phone, OffsetDateTime::now_utc())
        .await
        .unwrap();
    let error = fixture
        .authority
        .open_session_for_device(phone, request)
        .await
        .unwrap_err();
    assert!(matches!(error, LiveError::DeviceRevoked));
    assert_eq!(fixture.launcher.manifests().len(), 1);
    assert_eq!(
        fixture.devices.grants(phone).await.unwrap()[0].token_id,
        before[0].token_id
    );
    assert!(
        revoked_token_ids(&fixture.ledger).is_empty(),
        "refusal never rolls back reused authority"
    );
}

/// Cover the internal workload supervisor boundary independently of the paired
/// route. The launch port's private profile resolver is not exercised here;
/// its resulting token and workload binding are supplied to the same real
/// ensure/open_workload seams that it uses after kube admission.
#[tokio::test]
async fn internally_provisioned_workload_open_leaves_paired_device_grants_empty() {
    let fixture = fixture(true).await;
    let phone = device("00000000-0000-4000-8000-0000000000a1");
    paired(&fixture.devices, phone).await;
    let mut request = open_request(&fixture.gate);
    let composition = composition_of(&fixture.gate, &request.command_id);
    let provisioned = ensure_session_token(
        &fixture.gate.config,
        &composition,
        DEFAULT_TOKEN_TTL_SECONDS,
        TokenRenewalPolicy::OperatorOnly,
    )
    .expect("internal workload authority provisions");
    request.served_revision = None;
    let binding = odin_domain::huginn::WorkloadSessionBinding {
        profile: "grant-free-workload".to_owned(),
        snapshot_revision: 1,
        operation: "operation:grant-free-workload".to_owned(),
        inputs: Vec::new(),
        launching_run: None,
        unresolved_hosts: Default::default(),
    };
    let opened = fixture
        .gate
        .supervisor
        .open_workload(request, binding.clone())
        .await
        .expect("workload uses the internal supervisor route");

    assert_eq!(opened.session_id, composition.live_session);
    assert!(provisioned.token_path.exists());
    let manifests = fixture.launcher.manifests();
    assert_eq!(manifests.len(), 1);
    assert_eq!(manifests[0].workload.as_ref(), Some(&binding));
    assert!(fixture
        .devices
        .grants(phone)
        .await
        .expect("device grants")
        .is_empty());
    assert!(revoked_token_ids(&fixture.ledger).is_empty());
}

#[tokio::test]
async fn stop_aborts_blocked_fresh_open_and_joins_its_rollback() {
    let fixture = fixture(true).await;
    let phone = device("00000000-0000-4000-8000-0000000000a1");
    paired(&fixture.devices, phone).await;
    let barrier = Arc::new(LaunchBarrier::default());
    *fixture.launcher.barrier.lock() = Some(Arc::clone(&barrier));
    let request = open_request(&fixture.gate);
    let authority = fixture.authority.clone();
    let mut open =
        tokio::spawn(async move { authority.open_session_for_device(phone, request).await });
    tokio::select! {
        biased;
        result = &mut open => panic!("admission completed before launch barrier: {result:?}"),
        () = barrier.entered.notified() => {}
    }
    let minted = fixture.devices.grants(phone).await.unwrap()[0]
        .token_id
        .clone();

    // Never release the launch barrier: stop must cancel, not wait for launch.
    fixture
        .authority
        .stop_handle()
        .stop_until(tokio::time::Instant::now() + std::time::Duration::from_secs(1))
        .await
        .expect("stop joins cancelled open rollback within its deadline");

    assert!(
        barrier.terminated.load(Ordering::SeqCst),
        "actual launcher dropped before clean stop"
    );
    assert!(
        matches!(open.await.unwrap(), Err(LiveError::Unavailable { code, .. }) if code == "open_cancelled")
    );
    assert!(fixture.devices.grants(phone).await.unwrap().is_empty());
    assert!(token_files(&fixture.gate.config.paths.authority_token_root).is_empty());
    assert_eq!(
        revoked_token_ids(&fixture.ledger),
        vec![minted.as_str().to_owned()]
    );
    assert!(fixture.launcher.manifests().is_empty());
    assert!(fixture.authority.tasks.lock().await.is_empty());
    assert!(fixture.authority.sessions.lock().is_empty());
}
