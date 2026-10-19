//! Device-specific token admission and cleanup with a headless launcher.
//! Route startup is bypassed, so fixtures provision the seat binding and token root.
//! Barrier waits race admission completion to expose refusals rather than hang.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use odin_cli::authority_provision::{
    compose, ensure_session_token, LaunchSelection, TokenRenewalPolicy, DEFAULT_TOKEN_TTL_SECONDS,
};
use odin_domain::huginn::{
    LiveError, LiveMessage, OpenSessionRequest, SessionEpoch, SessionManifest, TailnetNodeId,
};
use odin_domain::{CommandId, Digest, NodeId};
use odin_huginn::devices::{DeviceTrustStore, NewDeviceRecord, SqliteDeviceTrustStore};
use odin_kernel::{LedgerRevocations, RevocationStore as _};
use odin_ledger::Ledger;
use odin_omp::live::control::LiveControlBackend;
use odin_omp::live::supervisor::{LiveSessionLauncher, SessionRuntime};
use time::OffsetDateTime;

use super::{unix_ms, DeviceOpenAuthority};

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
            control: Arc::new(NullBackend {
                prompt_barrier: self.prompt_barrier.lock().clone(),
            }),
            terminal: None,
            observations: None,
            failed_notices: None,
        })
    }
}

/// A ready control backend with an optional initial-prompt barrier. Admission,
/// actor creation, and cancellation still run through the real supervisor.
struct NullBackend {
    prompt_barrier: Option<Arc<LaunchBarrier>>,
}

#[async_trait::async_trait]
impl LiveControlBackend for NullBackend {
    async fn bridge_ready(&self) -> bool {
        true
    }
    async fn prompt(&self, _: &LiveMessage) -> Result<(), LiveError> {
        if let Some(barrier) = &self.prompt_barrier {
            let _termination = TerminationWitness(Arc::clone(barrier));
            barrier.entered.notify_one();
            barrier.resume.notified().await;
        }
        Ok(())
    }
    async fn follow_up(&self, _: &LiveMessage) -> Result<(), LiveError> {
        Ok(())
    }
    async fn steer(&self, _: &LiveMessage) -> Result<(), LiveError> {
        Ok(())
    }
    async fn pause(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn resume(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn checkpoint(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn restart(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn rehome(&self, _: &odin_domain::NodeId) -> Result<(), LiveError> {
        Ok(())
    }
    async fn set_model(
        &self,
        _: &odin_domain::huginn::ProviderName,
        _: &odin_domain::huginn::ModelName,
    ) -> Result<(), LiveError> {
        Ok(())
    }
    async fn abort_turn(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn abort_session(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn shutdown(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn decide_permission(
        &self,
        _: &odin_domain::huginn::PermissionRequestId,
        _: odin_domain::huginn::PermissionDecision,
    ) -> Result<(), LiveError> {
        Ok(())
    }
    async fn decide_approval(
        &self,
        _: &odin_domain::ApprovalId,
        _: u64,
        _: odin_domain::huginn::ApprovalDecision,
    ) -> Result<(), LiveError> {
        Ok(())
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
    let ledger = &fixture.ledger;
    admin
        .revoke_ledger_first(phone, |grants| async move {
            let guard = ledger.lock().expect("fixture ledger lock");
            let mut revocations = LedgerRevocations::new(&guard);
            let now_ms = unix_ms(OffsetDateTime::now_utc());
            for grant in grants {
                revocations
                    .revoke(&grant.token_id, now_ms)
                    .map_err(|error| error.to_string())?;
            }
            Ok(())
        })
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
        matches!(&error, LiveError::Unavailable { code } if code == "deviceOpenStopping"),
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
async fn cli_premint_routes_to_session_opened_without_replacing_authority() {
    assert_authenticated_open_routes(true).await;
}

#[tokio::test]
async fn fresh_authenticated_route_mints_binds_and_launches() {
    assert_authenticated_open_routes(false).await;
}

async fn assert_authenticated_open_routes(premint: bool) {
    use odin_domain::huginn::{HuginnCommandPort, HuginnRequest, HuginnResponse};
    use odin_huginn::dispatch::AuthenticatedCommandPort;
    use odin_huginn::streams::{BoundedMultiplexer, DurableReplayStore};

    let fixture = fixture(true).await;
    let phone = device("00000000-0000-4000-8000-0000000000a1");
    paired(&fixture.devices, phone).await;
    let request = open_request(&fixture.gate);
    let composition = composition_of(&fixture.gate, &request.command_id);
    let pre = premint.then(|| {
        ensure_session_token(
            &fixture.gate.config,
            &composition,
            DEFAULT_TOKEN_TTL_SECONDS,
            TokenRenewalPolicy::OperatorOnly,
        )
        .expect("CLI pre-mint")
    });
    let bytes = pre
        .as_ref()
        .map(|pre| std::fs::read(&pre.token_path).unwrap());
    let replay = DurableReplayStore::open(
        fixture
            .gate
            .config
            .paths
            .state_root
            .join("device-replay.sqlite3"),
        256,
        1 << 20,
    )
    .expect("replay store");
    let limits = odin_domain::huginn::StreamBackpressureLimits {
        max_buffered_items: std::num::NonZeroU32::new(64).unwrap(),
        max_buffered_bytes: std::num::NonZeroU64::new(64 << 20).unwrap(),
        max_item_bytes: std::num::NonZeroU64::new(1 << 20).unwrap(),
        max_items_per_second: std::num::NonZeroU32::new(256).unwrap(),
        max_in_flight_bytes: std::num::NonZeroU64::new(64 << 20).unwrap(),
    };
    let port = crate::kube::RuntimeCommandPort::new(
        Arc::clone(&fixture.ledger),
        Arc::clone(&fixture.gate.read_model),
        None,
        Arc::new(BoundedMultiplexer::new(replay, 64, 64)),
        None,
        limits,
    )
    .with_device_open(Some(Arc::new(fixture.authority.clone())));
    assert!(matches!(
        port.execute(HuginnRequest::OpenSession(request.clone()))
            .await,
        Err(odin_domain::huginn::HuginnProtocolError::Unauthenticated)
    ));
    assert!(fixture.launcher.manifests().is_empty());
    assert!(fixture.devices.grants(phone).await.unwrap().is_empty());
    if !premint {
        assert!(token_files(&fixture.gate.config.paths.authority_token_root).is_empty());
    }
    let response = port
        .execute_authenticated(phone, HuginnRequest::OpenSession(request))
        .await
        .expect("authenticated open");
    let HuginnResponse::SessionOpened(summary) = response else {
        panic!("open must return SessionOpened");
    };
    assert_eq!(summary.session_id, composition.live_session);
    if let Some(pre) = pre.as_ref() {
        assert_eq!(std::fs::read(&pre.token_path).unwrap(), bytes.unwrap());
    }
    let grants = fixture.devices.grants(phone).await.unwrap();
    assert_eq!(grants.len(), 1);
    let token: odin_domain::SeatToken = serde_json::from_slice(
        &std::fs::read(
            fixture
                .gate
                .config
                .paths
                .authority_token_root
                .join(format!("{}.json", composition.session.as_str())),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(grants[0].token_id, token.token_id);
    assert_eq!(fixture.launcher.manifests().len(), 1);
    assert!(revoked_token_ids(&fixture.ledger).is_empty());
}

#[tokio::test]
async fn malformed_premint_is_not_replaced_or_admitted() {
    let fixture = fixture(true).await;
    let phone = device("00000000-0000-4000-8000-0000000000a1");
    paired(&fixture.devices, phone).await;
    let request = open_request(&fixture.gate);
    let composition = composition_of(&fixture.gate, &request.command_id);
    let pre = ensure_session_token(
        &fixture.gate.config,
        &composition,
        DEFAULT_TOKEN_TTL_SECONDS,
        TokenRenewalPolicy::OperatorOnly,
    )
    .expect("pre-mint");
    std::fs::write(&pre.token_path, b"not a token").unwrap();
    let error = fixture
        .authority
        .open_session_for_device(phone, request)
        .await
        .unwrap_err();
    assert!(
        matches!(error, LiveError::Unavailable { code } if code == super::AUTHORITY_UNAVAILABLE)
    );
    assert_eq!(std::fs::read(&pre.token_path).unwrap(), b"not a token");
    assert!(fixture.launcher.manifests().is_empty());
    assert!(fixture.devices.grants(phone).await.unwrap().is_empty());
    assert!(revoked_token_ids(&fixture.ledger).is_empty());
}

#[tokio::test]
async fn stop_closes_admission_for_all_authority_clones() {
    let fixture = fixture(true).await;
    let clone = fixture.authority.clone();
    clone
        .stop_handle()
        .stop_until(tokio::time::Instant::now() + std::time::Duration::from_secs(1))
        .await
        .expect("authority clone stops");
    let phone = device("00000000-0000-4000-8000-0000000000a1");
    paired(&fixture.devices, phone).await;
    let error = fixture
        .authority
        .open_session_for_device(phone, open_request(&fixture.gate))
        .await
        .unwrap_err();
    assert!(matches!(error, LiveError::Unavailable { code } if code == "deviceOpenStopping"));
    assert!(token_files(&fixture.gate.config.paths.authority_token_root).is_empty());
    assert!(fixture.launcher.manifests().is_empty());
}

#[tokio::test]
async fn token_and_device_grant_exist_before_backend_launch_completes() {
    let fixture = fixture(true).await;
    let phone = device("00000000-0000-4000-8000-0000000000a1");
    paired(&fixture.devices, phone).await;
    let barrier = Arc::new(LaunchBarrier::default());
    *fixture.launcher.barrier.lock() = Some(Arc::clone(&barrier));
    let request = open_request(&fixture.gate);
    let composition = composition_of(&fixture.gate, &request.command_id);
    let authority = fixture.authority.clone();
    let mut open =
        tokio::spawn(async move { authority.open_session_for_device(phone, request).await });
    tokio::select! {
        biased;
        result = &mut open => panic!("admission completed before launch barrier: {result:?}"),
        () = barrier.entered.notified() => {}
    }
    let grants = fixture.devices.grants(phone).await.expect("durable grants");
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].device_id, phone);
    assert_eq!(grants[0].session_id, composition.session);
    assert_eq!(grants[0].revoked_at, None);
    let token: odin_domain::SeatToken = serde_json::from_slice(
        &std::fs::read(
            fixture
                .gate
                .config
                .paths
                .authority_token_root
                .join(format!("{}.json", composition.session.as_str())),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(grants[0].token_id, token.token_id);
    assert!(
        fixture.launcher.manifests().is_empty(),
        "launch still blocked"
    );
    barrier.resume.notify_one();
    open.await
        .unwrap()
        .expect("new authenticated session launches");
}

#[tokio::test]
async fn admission_closing_while_open_waits_for_task_lock_prevents_mint() {
    let fixture = fixture(true).await;
    let phone = device("00000000-0000-4000-8000-0000000000a1");
    paired(&fixture.devices, phone).await;
    let held = fixture.authority.tasks.lock().await;
    let authority = fixture.authority.clone();
    let request = open_request(&fixture.gate);
    let mut open = Box::pin(authority.open_session_for_device(phone, request));
    tokio::select! {
        biased;
        result = &mut open => panic!("open escaped held task lock: {result:?}"),
        () = std::future::ready(()) => {}
    }
    let stop_handle = fixture.authority.stop_handle();
    let mut stop = Box::pin(
        stop_handle.stop_until(tokio::time::Instant::now() + std::time::Duration::from_secs(1)),
    );
    tokio::select! {
        biased;
        result = &mut stop => panic!("stop escaped held task lock: {result:?}"),
        () = std::future::ready(()) => {}
    }
    drop(held);
    let (opened, stopped) = tokio::join!(open, stop);
    stopped.expect("stop joins after task lock releases");
    assert!(matches!(opened, Err(LiveError::Unavailable { code }) if code == "deviceOpenStopping"));
    assert!(token_files(&fixture.gate.config.paths.authority_token_root).is_empty());
    assert!(fixture.devices.grants(phone).await.unwrap().is_empty());
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

#[tokio::test]
async fn aborted_fresh_open_rolls_back_before_retry() {
    let fixture = fixture(true).await;
    let phone = device("00000000-0000-4000-8000-0000000000a1");
    paired(&fixture.devices, phone).await;
    let barrier = Arc::new(LaunchBarrier::default());
    *fixture.launcher.barrier.lock() = Some(Arc::clone(&barrier));
    let request = open_request(&fixture.gate);
    // A cancelled launch leaves durable history; a new command requests
    // an actual fresh launch rather than replaying that old summary.
    let retry = open_request(&fixture.gate);
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
    fixture
        .authority
        .stop_handle()
        .stop_until(tokio::time::Instant::now() + std::time::Duration::from_secs(1))
        .await
        .expect("cooperative stop joins real launcher and rollback");
    assert!(
        barrier.terminated.load(Ordering::SeqCst),
        "actual launcher dropped before clean stop"
    );
    assert!(
        matches!(open.await.unwrap(), Err(LiveError::Unavailable { code }) if code == "open_cancelled")
    );
    assert!(fixture.devices.grants(phone).await.unwrap().is_empty());
    assert!(token_files(&fixture.gate.config.paths.authority_token_root).is_empty());
    assert_eq!(
        revoked_token_ids(&fixture.ledger),
        vec![minted.as_str().to_owned()]
    );
    *fixture.launcher.barrier.lock() = None;
    let restarted = DeviceOpenAuthority::new(
        fixture.gate.config.clone(),
        Arc::clone(&fixture.devices),
        Arc::clone(&fixture.ledger),
        fixture.gate.omp.clone(),
    );
    restarted
        .open_session_for_device(phone, retry)
        .await
        .expect("retry launches with fresh authority");
    let grants = fixture.devices.grants(phone).await.unwrap();
    assert_eq!(grants.len(), 1);
    assert_ne!(grants[0].token_id, minted);
    assert!(
        revoked_token_ids(&fixture.ledger).contains(&minted.as_str().to_owned()),
        "fresh retry never revives the cancelled token"
    );
    assert_eq!(fixture.launcher.manifests().len(), 1);
}

#[tokio::test]
async fn disconnected_request_does_not_detach_open_cleanup() {
    let fixture = fixture(false).await;
    let phone = device("00000000-0000-4000-8000-0000000000a1");
    paired(&fixture.devices, phone).await;
    let barrier = Arc::new(LaunchBarrier::default());
    *fixture.launcher.barrier.lock() = Some(Arc::clone(&barrier));
    let authority = fixture.authority.clone();
    let request = open_request(&fixture.gate);
    let mut open =
        tokio::spawn(async move { authority.open_session_for_device(phone, request).await });
    tokio::select! {
        biased;
        result = &mut open => panic!("admission completed before launch barrier: {result:?}"),
        () = barrier.entered.notified() => {}
    }
    open.abort();
    assert!(open.await.unwrap_err().is_cancelled());
    barrier.resume.notify_one();
    fixture
        .authority
        .stop_handle()
        .stop_until(tokio::time::Instant::now() + std::time::Duration::from_secs(1))
        .await
        .expect("disconnected open cleanup joins");
    assert!(fixture.devices.grants(phone).await.unwrap().is_empty());
    assert!(token_files(&fixture.gate.config.paths.authority_token_root).is_empty());
    assert_eq!(revoked_token_ids(&fixture.ledger).len(), 1);
    assert!(fixture.authority.tasks.lock().await.is_empty());
}

#[tokio::test]
async fn failed_reused_open_preserves_preexisting_held_grant() {
    let fixture = fixture(true).await;
    let phone = device("00000000-0000-4000-8000-0000000000a1");
    paired(&fixture.devices, phone).await;
    let mut request = open_request(&fixture.gate);
    fixture
        .authority
        .open_session_for_device(phone, request.clone())
        .await
        .unwrap();
    let before = fixture.devices.grants(phone).await.unwrap();
    let path = token_files(&fixture.gate.config.paths.authority_token_root).remove(0);
    let bytes = std::fs::read(&path).unwrap();
    request.target_node = NodeId::new("not-an-allowed-node").unwrap();
    assert!(matches!(
        fixture
            .authority
            .open_session_for_device(phone, request)
            .await,
        Err(LiveError::Unauthorized)
    ));
    let after = fixture.devices.grants(phone).await.unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].token_id, before[0].token_id);
    assert_eq!(after[0].revoked_at, None);
    assert_eq!(std::fs::read(path).unwrap(), bytes);
    assert!(revoked_token_ids(&fixture.ledger).is_empty());
}

#[tokio::test]
async fn aborted_reused_open_releases_only_its_claim() {
    let fixture = fixture(true).await;
    let phone = device("00000000-0000-4000-8000-0000000000a1");
    paired(&fixture.devices, phone).await;
    let request = open_request(&fixture.gate);
    let composition = composition_of(&fixture.gate, &request.command_id);
    let pre = ensure_session_token(
        &fixture.gate.config,
        &composition,
        DEFAULT_TOKEN_TTL_SECONDS,
        TokenRenewalPolicy::OperatorOnly,
    )
    .unwrap();
    let bytes = std::fs::read(&pre.token_path).unwrap();
    let barrier = Arc::new(LaunchBarrier::default());
    *fixture.launcher.barrier.lock() = Some(Arc::clone(&barrier));
    let authority = fixture.authority.clone();
    let retry = request.clone();
    let mut open =
        tokio::spawn(async move { authority.open_session_for_device(phone, request).await });
    tokio::select! {
        biased;
        result = &mut open => panic!("admission completed before launch barrier: {result:?}"),
        () = barrier.entered.notified() => {}
    }
    let claimed = fixture.devices.grants(phone).await.unwrap().remove(0);
    let wrong_session =
        composition_of(&fixture.gate, &open_request(&fixture.gate).command_id).session;
    assert!(
        !fixture
            .devices
            .relinquish_grant_sync(&claimed.token_id, phone, &wrong_session,)
            .unwrap(),
        "same token with another session cannot relinquish the claim"
    );
    assert!(
        !fixture
            .devices
            .relinquish_grant_sync(
                &claimed.token_id,
                device("00000000-0000-4000-8000-0000000000b2"),
                &composition.session,
            )
            .unwrap(),
        "same token with another device cannot relinquish the claim"
    );
    assert_eq!(fixture.devices.grants(phone).await.unwrap(), vec![claimed]);
    fixture
        .authority
        .stop_handle()
        .stop_until(tokio::time::Instant::now() + std::time::Duration::from_secs(1))
        .await
        .expect("cooperative stop joins real launcher and relinquishes claim");
    assert!(
        barrier.terminated.load(Ordering::SeqCst),
        "actual launcher dropped before clean stop"
    );
    assert!(
        matches!(open.await.unwrap(), Err(LiveError::Unavailable { code }) if code == "open_cancelled")
    );
    assert!(fixture.devices.grants(phone).await.unwrap().is_empty());
    assert_eq!(std::fs::read(&pre.token_path).unwrap(), bytes);
    assert!(revoked_token_ids(&fixture.ledger).is_empty());
    assert!(fixture.authority.sessions.lock().is_empty());
    *fixture.launcher.barrier.lock() = None;
    let restarted = DeviceOpenAuthority::new(
        fixture.gate.config.clone(),
        Arc::clone(&fixture.devices),
        Arc::clone(&fixture.ledger),
        fixture.gate.omp.clone(),
    );
    restarted
        .open_session_for_device(phone, retry)
        .await
        .expect("same command can reclaim live token, including durable summary replay");
    let grants = fixture.devices.grants(phone).await.unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].token_id.as_str(), pre.token_id);
    assert_eq!(std::fs::read(&pre.token_path).unwrap(), bytes);
    assert!(revoked_token_ids(&fixture.ledger).is_empty());
}

/// Cancellation after actor admission is not rollback: the device retains
/// ownership so ledger-first revoke can still find the live session token.
#[tokio::test]
async fn stopped_initial_prompt_preserves_new_claim_on_preminted_token() {
    let fixture = fixture(true).await;
    let phone = device("00000000-0000-4000-8000-0000000000a1");
    paired(&fixture.devices, phone).await;
    let mut request = open_request(&fixture.gate);
    let composition = composition_of(&fixture.gate, &request.command_id);
    let pre = ensure_session_token(
        &fixture.gate.config,
        &composition,
        DEFAULT_TOKEN_TTL_SECONDS,
        TokenRenewalPolicy::OperatorOnly,
    )
    .unwrap();
    let bytes = std::fs::read(&pre.token_path).unwrap();
    assert!(fixture.devices.grants(phone).await.unwrap().is_empty());
    request.initial_prompt = Some(
        LiveMessage::new(vec![odin_domain::huginn::LiveContentBlock::Text(
            "blocked initial prompt".to_owned(),
        )])
        .unwrap(),
    );
    let barrier = Arc::new(LaunchBarrier::default());
    *fixture.launcher.prompt_barrier.lock() = Some(Arc::clone(&barrier));
    let authority = fixture.authority.clone();
    let mut open =
        tokio::spawn(async move { authority.open_session_for_device(phone, request).await });
    tokio::select! {
        biased;
        result = &mut open => panic!("admission completed before initial-prompt barrier: {result:?}"),
        () = barrier.entered.notified() => {}
    }
    assert_eq!(
        fixture.launcher.manifests().len(),
        1,
        "real supervisor admitted the actor before prompt"
    );
    let before = fixture.devices.grants(phone).await.unwrap();
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].session_id, composition.session);
    assert_eq!(before[0].token_id.as_str(), pre.token_id);
    fixture
        .authority
        .stop_handle()
        .stop_until(tokio::time::Instant::now() + std::time::Duration::from_secs(1))
        .await
        .expect("stop interrupts the postcommit initial prompt");
    assert!(
        matches!(open.await.unwrap(), Err(LiveError::Unavailable { code }) if code == "open_cancelled")
    );
    assert_eq!(
        fixture.devices.grants(phone).await.unwrap(),
        before,
        "committed claim remains visible to later revocation"
    );
    assert_eq!(std::fs::read(&pre.token_path).unwrap(), bytes);
    assert!(revoked_token_ids(&fixture.ledger).is_empty());
    // The committed actor owns its command independently of the cancelled
    // request waiter; release it before the fixture runtime shuts down.
    barrier.resume.notify_one();
}

/// The observer's production provisioning and concrete-supervisor route must
/// stay usable without borrowing the paired device authority next to it.
#[tokio::test]
async fn observer_provision_and_open_leave_paired_device_grants_empty() {
    let fixture = fixture(true).await;
    let phone = device("00000000-0000-4000-8000-0000000000a1");
    paired(&fixture.devices, phone).await;
    let mut request = open_request(&fixture.gate);
    request.served_revision = None;
    let composition = composition_of(&fixture.gate, &request.command_id);

    crate::harness::provision_observer(&fixture.gate.config, &request)
        .expect("observer authority provisions without a device");
    let opened = fixture
        .gate
        .supervisor
        .open(request)
        .await
        .expect("observer uses the internal supervisor route");

    assert_eq!(opened.session_id, composition.live_session);
    assert_eq!(
        token_files(&fixture.gate.config.paths.authority_token_root).len(),
        1
    );
    assert_eq!(fixture.launcher.manifests().len(), 1);
    assert!(fixture.launcher.manifests()[0].workload.is_none());
    assert!(fixture
        .devices
        .grants(phone)
        .await
        .expect("device grants")
        .is_empty());
    assert!(revoked_token_ids(&fixture.ledger).is_empty());
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
        matches!(open.await.unwrap(), Err(LiveError::Unavailable { code }) if code == "open_cancelled")
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

/// These cases exercise the conservative production policy, not real carrier
/// termination: a fixture future Drop must never stand in for descendant joins.
#[tokio::test]
async fn stop_retains_fresh_authority_when_launcher_descendant_termination_is_unknown() {
    assert_unknown_launcher_retains_authority(false).await;
}

#[tokio::test]
async fn stop_retains_reused_authority_when_launcher_descendant_termination_is_unknown() {
    assert_unknown_launcher_retains_authority(true).await;
}

async fn assert_unknown_launcher_retains_authority(premint: bool) {
    // Simulate launch effects without a carrier or confirmation that those effects terminated.
    let fixture = fixture(true).await;
    fixture
        .launcher
        .known_resources
        .store(false, Ordering::SeqCst);
    let phone = device("00000000-0000-4000-8000-0000000000a1");
    paired(&fixture.devices, phone).await;
    let barrier = Arc::new(LaunchBarrier::default());
    *fixture.launcher.barrier.lock() = Some(Arc::clone(&barrier));
    let request = open_request(&fixture.gate);
    let pre = premint.then(|| {
        let composition = composition_of(&fixture.gate, &request.command_id);
        let report = ensure_session_token(
            &fixture.gate.config,
            &composition,
            DEFAULT_TOKEN_TTL_SECONDS,
            TokenRenewalPolicy::OperatorOnly,
        )
        .unwrap();
        let bytes = std::fs::read(&report.token_path).unwrap();
        (report, bytes)
    });
    assert!(fixture.devices.grants(phone).await.unwrap().is_empty());
    let authority = fixture.authority.clone();
    let mut open =
        tokio::spawn(async move { authority.open_session_for_device(phone, request).await });
    tokio::select! {
        biased;
        result = &mut open => panic!("admission completed before launch barrier: {result:?}"),
        () = barrier.entered.notified() => {}
    }
    let grants = fixture.devices.grants(phone).await.unwrap();
    assert_eq!(grants.len(), 1);
    let path = token_files(&fixture.gate.config.paths.authority_token_root).remove(0);
    let bytes = std::fs::read(&path).unwrap();
    if let Some((report, original_bytes)) = &pre {
        assert_eq!(grants[0].token_id.as_str(), report.token_id);
        assert_eq!(&bytes, original_bytes);
    }
    assert!(
        fixture
            .authority
            .stop_handle()
            .stop_until(tokio::time::Instant::now() + std::time::Duration::from_secs(1),)
            .await
            .is_err(),
        "joining a launcher future alone cannot prove descendant termination"
    );
    assert!(
        barrier.terminated.load(Ordering::SeqCst),
        "even a dropped launcher is insufficient"
    );
    assert!(
        matches!(open.await.unwrap(), Err(LiveError::Unavailable { code })
        if code == "open_launcher_join_failed")
    );
    assert_eq!(fixture.devices.grants(phone).await.unwrap(), grants);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert!(revoked_token_ids(&fixture.ledger).is_empty());
    assert!(
        fixture
            .authority
            .stop_handle()
            .stop_until(tokio::time::Instant::now() + std::time::Duration::from_secs(1),)
            .await
            .is_err(),
        "unknown termination stays incomplete after task drain"
    );
}

#[tokio::test]
async fn stop_reports_incomplete_when_cleanup_failed_even_after_tasks_drain() {
    let fixture = fixture(true).await;
    fixture
        .authority
        .cleanup_failed
        .store(true, Ordering::Release);
    assert!(fixture
        .authority
        .stop_handle()
        .stop_until(tokio::time::Instant::now() + std::time::Duration::from_secs(1),)
        .await
        .is_err());
    assert!(!*fixture.authority.admitting.lock());
    assert!(fixture.authority.tasks.lock().await.is_empty());
}

#[tokio::test]
async fn stop_reports_incomplete_when_deadline_elapsed_with_task_lock_held() {
    let fixture = fixture(true).await;
    let held = fixture.authority.tasks.lock().await;
    assert!(fixture
        .authority
        .stop_handle()
        .stop_until(tokio::time::Instant::now() - std::time::Duration::from_secs(1),)
        .await
        .is_err());
    assert!(!*fixture.authority.admitting.lock());
    drop(held);
    fixture
        .authority
        .stop_handle()
        .stop_until(tokio::time::Instant::now() + std::time::Duration::from_secs(1))
        .await
        .expect("a later owner can observe actual drain");
}

#[tokio::test]
async fn stop_does_not_report_a_panicked_owned_task_as_clean() {
    let fixture = fixture(true).await;
    let (entered, observed) = tokio::sync::oneshot::channel();
    fixture.authority.tasks.lock().await.spawn(async move {
        entered.send(()).expect("test observes owned task");
        panic!("owned open task failure");
    });
    // No await separates the signal and panic in the owned task, so its panic
    // is recorded before the test resumes and asks stop to join it.
    observed.await.expect("owned task ran");
    assert!(fixture
        .authority
        .stop_handle()
        .stop_until(tokio::time::Instant::now() + std::time::Duration::from_secs(1),)
        .await
        .is_err());
    assert!(fixture.authority.tasks.lock().await.is_empty());
    assert!(!*fixture.authority.admitting.lock());
    assert!(
        fixture
            .authority
            .stop_handle()
            .stop_until(tokio::time::Instant::now() + std::time::Duration::from_secs(1),)
            .await
            .is_err(),
        "draining the panic must not clear its failure witness"
    );
}

#[tokio::test]
async fn stop_reports_failed_ledger_rollback_without_detaching_the_open() {
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
    let grants = fixture.devices.grants(phone).await.expect("minted grant");
    assert_eq!(grants.len(), 1);
    let files = token_files(&fixture.gate.config.paths.authority_token_root);
    assert_eq!(files.len(), 1);
    let token_bytes = std::fs::read(&files[0]).expect("minted token bytes");

    // Poison the real ledger lock after mint/claim, not a synthetic cleanup
    // result. Cancellation must attempt ledger-first rollback and report that
    // it failed, retaining the token and grant for the owning revoke pass.
    let ledger = Arc::clone(&fixture.ledger);
    assert!(std::thread::spawn(move || {
        let _held = ledger.lock().expect("ledger initially healthy");
        panic!("inject poisoned revocation ledger");
    })
    .join()
    .is_err());

    assert!(fixture
        .authority
        .stop_handle()
        .stop_until(tokio::time::Instant::now() + std::time::Duration::from_secs(5),)
        .await
        .is_err());
    assert!(barrier.terminated.load(Ordering::SeqCst));
    assert!(
        matches!(open.await.unwrap(), Err(LiveError::Unavailable { code }) if code == "open_cancelled")
    );
    assert!(fixture.authority.cleanup_failed.load(Ordering::Acquire));
    assert_eq!(
        fixture.devices.grants(phone).await.expect("retained grant"),
        grants
    );
    assert_eq!(
        std::fs::read(&files[0]).expect("unrevoked token remains"),
        token_bytes
    );
    assert!(fixture.launcher.manifests().is_empty());
    assert!(fixture.authority.tasks.lock().await.is_empty());
    assert!(fixture.authority.sessions.lock().is_empty());
    assert!(!*fixture.authority.admitting.lock());
}

// The connection is in-memory, but frame encoding, authentication identity
// propagation, dispatch, command routing, authority, and admission are real.
struct OpenConnection {
    incoming: tokio::sync::mpsc::UnboundedReceiver<odin_huginn::dispatch::ConnectionFrame>,
    outgoing: tokio::sync::mpsc::UnboundedSender<odin_huginn::dispatch::ConnectionFrame>,
}

struct OpenReader(tokio::sync::mpsc::UnboundedReceiver<odin_huginn::dispatch::ConnectionFrame>);
struct OpenWriter(tokio::sync::mpsc::UnboundedSender<odin_huginn::dispatch::ConnectionFrame>);

impl odin_huginn::dispatch::ServerConnection for OpenConnection {
    type Reader = OpenReader;
    type Writer = OpenWriter;

    fn split(self) -> (Self::Reader, Self::Writer) {
        (OpenReader(self.incoming), OpenWriter(self.outgoing))
    }
}

#[async_trait::async_trait]
impl odin_huginn::dispatch::FrameReader for OpenReader {
    async fn receive(&mut self) -> Result<Option<odin_huginn::dispatch::ConnectionFrame>, String> {
        Ok(self.0.recv().await)
    }
}

#[async_trait::async_trait]
impl odin_huginn::dispatch::FrameWriter for OpenWriter {
    async fn send(&mut self, frame: odin_huginn::dispatch::ConnectionFrame) -> Result<(), String> {
        self.0.send(frame).map_err(|error| error.to_string())
    }
}

struct OpenDispatchGuard;

#[async_trait::async_trait]
impl odin_huginn::dispatch::DispatchGuard for OpenDispatchGuard {
    async fn check_stop(&self) -> Result<(), odin_domain::huginn::HuginnProtocolError> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl odin_domain::huginn::ContentTicketIssuer for OpenDispatchGuard {
    async fn issue(
        &self,
        _: odin_domain::huginn::DeviceId,
        _: odin_domain::huginn::ContentTicketRequest,
    ) -> Result<odin_domain::huginn::ContentTicket, odin_domain::huginn::HuginnProtocolError> {
        panic!("session open must not issue a content ticket")
    }
}

#[tokio::test]
async fn framed_general_missing_token_open_consumes_authority_before_ready() {
    assert_framed_open(false).await;
}

#[tokio::test]
async fn framed_live_missing_token_open_consumes_authority_before_ready() {
    assert_framed_open(true).await;
}

async fn assert_framed_open(live_channel: bool) {
    use odin_domain::huginn::*;
    use odin_huginn::dispatch::{ConnectionFrame, ConnectionRegistry, LiveDispatcher};
    use odin_huginn::protocol::{
        decode_frame, encode_frame, ClientFrame, CodecLimits, ServerFrame,
    };
    use odin_huginn::service::HuginnCommandPlane;
    use odin_huginn::streams::{BoundedMultiplexer, DurableReplayStore};

    let fixture = fixture(true).await;
    let phone = device("00000000-0000-4000-8000-0000000000a1");
    paired(&fixture.devices, phone).await;
    let request = open_request(&fixture.gate);
    let composition = composition_of(&fixture.gate, &request.command_id);
    assert!(token_files(&fixture.gate.config.paths.authority_token_root).is_empty());
    let validation = Arc::new(OpenAuthorityValidation::new(&fixture, phone, &composition));
    *fixture.launcher.validation.lock() = Some(validation.clone());

    let replay = DurableReplayStore::open(
        fixture
            .gate
            .config
            .paths
            .state_root
            .join("framed-open-replay.sqlite3"),
        256,
        1 << 20,
    )
    .expect("replay store");
    let streams = Arc::new(BoundedMultiplexer::new(replay, 64, 64));
    let limits = StreamBackpressureLimits {
        max_buffered_items: std::num::NonZeroU32::new(64).unwrap(),
        max_buffered_bytes: std::num::NonZeroU64::new(64 << 20).unwrap(),
        max_item_bytes: std::num::NonZeroU64::new(1 << 20).unwrap(),
        max_items_per_second: std::num::NonZeroU32::new(256).unwrap(),
        max_in_flight_bytes: std::num::NonZeroU64::new(64 << 20).unwrap(),
    };
    let port = Arc::new(
        crate::kube::RuntimeCommandPort::new(
            Arc::clone(&fixture.ledger),
            Arc::clone(&fixture.gate.read_model),
            None,
            streams.clone(),
            None,
            limits,
        )
        .with_device_open(Some(Arc::new(fixture.authority.clone()))),
    );
    let plane = Arc::new(HuginnCommandPlane::new(port, fixture.gate.omp.clone()));
    assert!(matches!(
        plane
            .execute(HuginnRequest::OpenSession(request.clone()))
            .await,
        Err(HuginnProtocolError::Unauthenticated)
    ));
    assert!(fixture.launcher.manifests().is_empty());
    assert!(fixture.devices.grants(phone).await.unwrap().is_empty());
    let dispatcher = LiveDispatcher::new(
        fixture.gate.read_model.clone(),
        plane,
        streams,
        Arc::new(OpenDispatchGuard),
        Arc::new(OpenDispatchGuard),
    );
    let verified = VerifiedColinDevice {
        device_id: phone,
        tailnet_node_id: TailnetNodeId::parse("node.phone").unwrap(),
        connection_id: ConnectionId::new(uuid::Uuid::new_v4()).unwrap(),
    };
    let registration = fixture
        .devices
        .register_connection(&verified, &ConnectionRegistry::new(), usize::MAX)
        .await
        .unwrap();
    let (send, incoming) = tokio::sync::mpsc::unbounded_channel();
    let (outgoing, mut receive) = tokio::sync::mpsc::unbounded_channel();
    let serving = tokio::spawn(async move {
        dispatcher
            .serve_connection(
                OpenConnection { incoming, outgoing },
                verified,
                registration,
            )
            .await
    });
    let request_id = RequestId::new(uuid::Uuid::new_v4()).unwrap();
    let frame = if live_channel {
        ClientFrame::Live(LiveClientRequest::OpenSession {
            request_id,
            command_id: request.command_id,
            seat_id: request.seat_id,
            project_id: request.project_id,
            slice_id: request.slice_id,
            provider: request.provider,
            model: request.model,
            title: request.title,
            target_node: request.target_node,
            open_tab: request.open_tab,
            initial_prompt: request.initial_prompt,
            served_revision: request.served_revision,
        })
    } else {
        ClientFrame::General(HuginnRequest::OpenSession(request))
    };
    let codec = CodecLimits::default();
    send.send(ConnectionFrame::Binary(
        encode_frame(&frame, &codec).unwrap().into(),
    ))
    .unwrap();
    let response = tokio::time::timeout(std::time::Duration::from_secs(5), receive.recv())
        .await
        .expect("open responds promptly")
        .expect("connection remains open");
    let ConnectionFrame::Binary(bytes) = response else {
        panic!("binary response required")
    };
    let summary = match decode_frame::<ServerFrame>(&bytes, &codec).unwrap().value {
        ServerFrame::General(HuginnMessage::Response {
            result: HuginnResponse::SessionOpened(summary),
            ..
        }) if !live_channel => summary,
        ServerFrame::Live(LiveServerMessage::Response {
            request_id: actual,
            result: LiveResponse::SessionOpened(summary),
        }) if live_channel && actual == request_id => summary,
        other => panic!("expected successful open on requested channel: {other:?}"),
    };
    assert_eq!(summary.session_id, composition.live_session);
    assert_eq!(
        summary.state,
        LiveSessionState::Idle,
        "durable admission alone is not readiness"
    );
    assert!(
        validation.consumed.load(Ordering::SeqCst),
        "launcher consumed real authority"
    );
    assert_eq!(fixture.launcher.manifests().len(), 1);
    assert!(fixture
        .gate
        .supervisor
        .actor(summary.session_id)
        .await
        .is_ok());
    // This fixture is genuinely headless; never manufacture terminal success.
    let error = fixture
        .gate
        .omp
        .acquire_terminal_control(
            CommandId::new("headless-control").unwrap(),
            phone,
            TerminalControlRequest {
                session_id: summary.session_id,
                expected_epoch: summary.epoch,
                columns: std::num::NonZeroU16::new(80).unwrap(),
                rows: std::num::NonZeroU16::new(24).unwrap(),
                requested_ttl_seconds: std::num::NonZeroU32::new(30).unwrap(),
            },
        )
        .await
        .expect_err("ready headless session has no terminal");
    assert!(
        matches!(error, LiveError::Unsupported { operation } if operation == "terminal_unavailable_for_headless_session")
    );
    assert!(revoked_token_ids(&fixture.ledger).is_empty());
    send.send(ConnectionFrame::Binary(
        encode_frame(&frame, &codec).unwrap().into(),
    ))
    .unwrap();
    let replay = tokio::time::timeout(std::time::Duration::from_secs(5), receive.recv())
        .await
        .expect("replay responds promptly")
        .expect("connection remains open");
    let ConnectionFrame::Binary(bytes) = replay else {
        panic!("binary replay required")
    };
    let replayed = match decode_frame::<ServerFrame>(&bytes, &codec).unwrap().value {
        ServerFrame::General(HuginnMessage::Response {
            result: HuginnResponse::SessionOpened(summary),
            ..
        }) if !live_channel => summary,
        ServerFrame::Live(LiveServerMessage::Response {
            request_id: actual,
            result: LiveResponse::SessionOpened(summary),
        }) if live_channel && actual == request_id => summary,
        other => panic!("expected successful replay: {other:?}"),
    };
    assert_eq!(replayed.session_id, summary.session_id);
    assert_eq!(replayed.state, LiveSessionState::Idle);
    assert_eq!(
        fixture.launcher.manifests().len(),
        1,
        "exact replay never launches twice"
    );
    drop(send);
    tokio::time::timeout(std::time::Duration::from_secs(5), serving)
        .await
        .expect("connection loop drains")
        .expect("connection task joins")
        .expect("clean connection close");
}

struct OpenAuthorityValidation {
    operations: odin_omp::host_tools::operations::HostToolOperations,
    binding: odin_omp::host_tools::operations::SessionOperationBinding,
    composition: odin_cli::authority_provision::SessionComposition,
    devices: Arc<SqliteDeviceTrustStore>,
    token_root: std::path::PathBuf,
    device: odin_domain::huginn::DeviceId,
    consumed: AtomicBool,
}

impl OpenAuthorityValidation {
    fn new(
        fixture: &Fixture,
        device: odin_domain::huginn::DeviceId,
        composition: &odin_cli::authority_provision::SessionComposition,
    ) -> Self {
        use odin_omp::host_tools::operations::*;
        let revisions = odin_cli::runtime_bindings::StoreRevisionMaterial::new(
            odin_registry::SnapshotStore::new(&fixture.gate.config.paths.registry_snapshot),
            fixture.gate.config.clone(),
        );
        let material = revisions
            .material_at(composition.snapshot_revision)
            .expect("published operation material");
        assert!(
            !material.contracts.is_empty(),
            "exercise the nonempty operation authority gate"
        );
        let binding = SessionOperationBinding {
            policy: composition.policy.policy.clone(),
            context_policy_digest: composition.policy.context_policy_digest,
            capsule_id: session_capsule_id(&composition.session).unwrap(),
            served_revision: composition.snapshot_revision,
            parent: None,
        };
        let provider = ProvisionedFreshAuthorityProvider::open(
            fixture.gate.config.paths.authority_token_root.clone(),
            std::fs::read(&fixture.gate.config.paths.authority_verification_key_file).unwrap(),
        )
        .expect("real provisioned reader");
        let mut registry = odin_omp::host_tools::HostToolRegistry::new();
        // Listing does not invoke tasks. The real task tools remain fail-closed
        // on invocation until a task owner is installed, just as at startup.
        registry
            .register_task_capabilities(Arc::new(
                odin_omp::host_tools::delegation::TaskOwnerSlot::default(),
            ))
            .expect("register production task tools");
        let registry = Arc::new(registry);
        let catalog = Arc::new(
            DeclaredOperationCatalog::from_contracts(
                &material.contracts,
                i64::try_from(composition.snapshot_revision)
                    .expect("snapshot revision fits the admission range"),
                material.admission_digest,
                registry.clone(),
                &std::collections::BTreeSet::new(),
            )
            .expect("real admitted contract catalog"),
        );
        let executor = Arc::new(odin_omp::host_tools::executor::HostToolExecutor::new(
            registry,
        ));
        let operations = HostToolOperations::new(
            OperationStackInputs {
                catalog,
                schemas: Arc::new(FilesystemSchemaCatalog::new(
                    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."),
                )),
                adapter_executor: executor.clone(),
                executor,
                adapter_status: Arc::new(SupervisedAdapterStatus::new(
                    Arc::new(UnsupervisedAdapterStatus),
                    std::collections::BTreeSet::new(),
                    std::time::Duration::ZERO,
                )),
                limits: odin_domain::operation::Limits::new(100, 100, 100),
                clock: wall_clock(),
                ledger: fixture.ledger.clone(),
                revisions: Arc::new(revisions),
                workload_drafts: None,
            },
            (*material.contracts).clone(),
            Arc::new(provider),
        )
        .expect("real operation stack");
        assert!(
            matches!(
                operations.session_listing(&binding, &composition.session),
                Err(HostToolOperationError::PublishedAuthorityUnavailable { .. })
            ),
            "the production consumer refuses the initially missing token"
        );
        Self {
            operations,
            binding,
            composition: composition.clone(),
            devices: fixture.devices.clone(),
            token_root: fixture.gate.config.paths.authority_token_root.clone(),
            device,
            consumed: AtomicBool::new(false),
        }
    }
}

#[async_trait::async_trait]
impl LaunchValidation for OpenAuthorityValidation {
    async fn validate(&self, manifest: &SessionManifest) {
        assert_eq!(manifest.session_id, self.composition.live_session);
        assert_eq!(manifest.seat_id, self.composition.seat);
        assert_eq!(manifest.slice_id, self.composition.slice);
        assert_eq!(manifest.project_id, self.composition.project);
        assert_eq!(
            manifest.served_revision,
            Some(self.composition.snapshot_revision)
        );
        let grants = self
            .devices
            .grants(self.device)
            .await
            .expect("durable pre-launch grant");
        assert_eq!(
            grants.len(),
            1,
            "grant exists before the runtime returns ready"
        );
        assert_eq!(grants[0].device_id, self.device);
        assert_eq!(grants[0].session_id, self.composition.session);
        assert!(grants[0].revoked_at.is_none());
        let token: odin_domain::SeatToken = serde_json::from_slice(
            &std::fs::read(
                self.token_root
                    .join(format!("{}.json", self.composition.session.as_str())),
            )
            .expect("ensured token file"),
        )
        .expect("seat token");
        assert_eq!(token.token_id, grants[0].token_id);
        self.operations
            .session_listing(&self.binding, &self.composition.session)
            .expect(
                "actual production listing reloads and verifies the ensured token before launch",
            );
        self.consumed.store(true, Ordering::SeqCst);
    }
}
