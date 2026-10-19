//! Device revocation and protocol limits through the local admin socket.

use std::os::unix::fs::PermissionsExt as _;
use std::sync::{Arc, Mutex};

use odin_cli::authority_provision::{admin_socket_path, revoke_device, AdminRevokeResponse};
use odin_domain::huginn::{ConnectionId, DeviceId, TailnetNodeId, VerifiedColinDevice};
use odin_huginn::devices::{
    DeviceAdmin, DeviceTrustStore as _, NewDeviceGrant, SqliteDeviceTrustStore,
};
use odin_huginn::dispatch::ConnectionRegistry;

const NODE: &str = "00000000-0000-4000-8000-000000000009";

async fn insert_device(store: &SqliteDeviceTrustStore, label: &str) -> DeviceId {
    use odin_huginn::devices::NewDeviceRecord;
    let device = DeviceId::new(uuid::Uuid::new_v4()).expect("device id");
    store
        .insert(NewDeviceRecord {
            device_id: device,
            tailnet_node_id: TailnetNodeId::parse(NODE).expect("node id"),
            label: label.to_owned(),
            credential_digest: odin_domain::Digest::hash(label.as_bytes()),
            created_at: time::OffsetDateTime::now_utc(),
        })
        .await
        .expect("device inserted");
    device
}

async fn register_served(
    store: &SqliteDeviceTrustStore,
    registry: &ConnectionRegistry,
    device: DeviceId,
) -> odin_huginn::dispatch::ConnectionRegistration {
    store
        .register_connection(
            &VerifiedColinDevice {
                device_id: device,
                tailnet_node_id: TailnetNodeId::parse(NODE).expect("node id"),
                connection_id: ConnectionId::new(uuid::Uuid::new_v4()).expect("connection id"),
            },
            registry,
            usize::MAX,
        )
        .await
        .expect("device serves")
}

fn arm_daemon(
    state_root: &std::path::Path,
    admin: DeviceAdmin<SqliteDeviceTrustStore>,
    ledger: Arc<Mutex<odin_ledger::Ledger>>,
) -> tokio::task::JoinSet<Result<(), String>> {
    let listener = crate::device_admin::bind_device_admin_socket(&admin_socket_path(state_root))
        .expect("socket binds");
    let mut pumps = tokio::task::JoinSet::new();
    crate::device_admin::arm_device_admin_socket(
        &mut pumps,
        listener,
        crate::device_admin::DeviceAdminHandle { admin, ledger },
    );
    pumps
}

/// Same-uid clients are required because the socket accepts only the daemon's uid.
#[tokio::test]
async fn admin_socket_cuts_the_revoked_device_and_preserves_others() {
    use odin_kernel::RevocationStore as _;
    let temporary = tempfile::TempDir::new().expect("state root");
    let state_root = temporary.path().to_path_buf();
    let store = Arc::new(SqliteDeviceTrustStore::open_in_memory().expect("store opens"));
    let registry = ConnectionRegistry::with_limit(8);
    let admin = DeviceAdmin::new(Arc::clone(&store), registry.clone());
    let target = insert_device(store.as_ref(), "phone-target").await;
    let other = insert_device(store.as_ref(), "phone-other").await;
    let target_registration = register_served(&store, &registry, target).await;
    let other_registration = register_served(&store, &registry, other).await;
    let target_revocation = target_registration.revocation();
    let other_revocation = other_registration.revocation();
    let token = odin_domain::SeatTokenId::new("seat-token:1:socket-held").expect("token id");
    store
        .claim_grant(NewDeviceGrant {
            device_id: target,
            session_id: odin_domain::SessionId::new("session-held-open").expect("session id"),
            token_id: token.clone(),
            created_at: time::OffsetDateTime::now_utc(),
        })
        .await
        .expect("grant claims");
    let ledger = Arc::new(Mutex::new(
        odin_ledger::Ledger::open_in_memory().expect("ledger opens"),
    ));
    let mut pumps = arm_daemon(&state_root, admin, Arc::clone(&ledger));

    let report = revoke_device(&state_root, target)
        .await
        .expect("the daemon executes the revoke");
    assert!(report.revoked);
    assert!(report.daemon, "a daemon answer says so");
    assert_eq!(report.streams_closed, 1);
    assert!(
        *target_revocation.borrow(),
        "the revoked device's stream observes the revoke"
    );
    assert!(
        !other_revocation.has_changed().unwrap(),
        "the other served device is untouched"
    );
    assert_eq!(registry.active_for_device(target), 0);
    assert_eq!(registry.active_for_device(other), 1);
    {
        let ledger = ledger.lock().expect("ledger lock");
        assert!(
            odin_kernel::LedgerRevocations::new(&ledger)
                .is_revoked(&token)
                .expect("ledger reads"),
            "the daemon ledger-revokes the device's grant"
        );
    }
    let record = store
        .get(target)
        .await
        .expect("record reads")
        .expect("kept");
    assert!(record.revoked_at.is_some());

    let socket_path = admin_socket_path(&state_root);
    let socket_mode = std::fs::metadata(&socket_path)
        .expect("socket exists")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(socket_mode, 0o600, "the socket file is private");
    let parent_mode = std::fs::metadata(socket_path.parent().expect("has parent"))
        .expect("parent exists")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(parent_mode, 0o700, "the socket's directory is private");

    let again = revoke_device(&state_root, target)
        .await
        .expect_err("a revoked device is refused through the daemon too");
    assert!(again.contains("unknownDevice"), "{again}");

    let unknown = DeviceId::new(uuid::Uuid::new_v4()).unwrap();
    let refused = revoke_device(&state_root, unknown).await.unwrap_err();
    assert!(refused.contains("unknownDevice"), "{refused}");
    assert_eq!(registry.active_for_device(other), 1);
    assert!(!*other_revocation.borrow());
    pumps.abort_all();
}

#[tokio::test]
async fn admin_socket_revokes_grants_after_origin_disconnects() {
    use odin_kernel::RevocationStore as _;
    let temporary = tempfile::TempDir::new().unwrap();
    let store = Arc::new(SqliteDeviceTrustStore::open_in_memory().unwrap());
    let registry = ConnectionRegistry::new();
    let device = insert_device(&store, "disconnected").await;
    let other = insert_device(&store, "unrelated").await;
    let registration = register_served(&store, &registry, device).await;
    drop(registration);
    let token = odin_domain::SeatTokenId::new("seat-token:2:disconnected").unwrap();
    let other_token = odin_domain::SeatTokenId::new("seat-token:3:unrelated").unwrap();
    for (owner, token_id) in [(device, token.clone()), (other, other_token.clone())] {
        store
            .claim_grant(NewDeviceGrant {
                device_id: owner,
                session_id: odin_domain::SessionId::new("session-disconnected").unwrap(),
                token_id,
                created_at: time::OffsetDateTime::now_utc(),
            })
            .await
            .unwrap();
    }
    let ledger = Arc::new(Mutex::new(odin_ledger::Ledger::open_in_memory().unwrap()));
    let mut pumps = arm_daemon(
        temporary.path(),
        DeviceAdmin::new(store.clone(), registry),
        ledger.clone(),
    );
    let report = revoke_device(temporary.path(), device).await.unwrap();
    assert!(report.daemon && report.revoked);
    assert_eq!(report.streams_closed, 0);
    {
        let ledger = ledger.lock().unwrap();
        let revocations = odin_kernel::LedgerRevocations::new(&ledger);
        assert!(revocations.is_revoked(&token).unwrap());
        assert!(!revocations.is_revoked(&other_token).unwrap());
    }
    assert!(store.grants(device).await.unwrap().is_empty());
    assert_eq!(store.grants(other).await.unwrap().len(), 1);
    assert!(store
        .get(other)
        .await
        .unwrap()
        .unwrap()
        .revoked_at
        .is_none());
    pumps.abort_all();
}

/// Startup's first activity-pump tick resumes a durable interrupted revoke,
/// even though the connection that created the grant no longer exists.
#[tokio::test]
async fn activity_pump_resumes_reopened_revocation_before_closing_streams() {
    use odin_kernel::RevocationStore as _;
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("devices.sqlite");
    let store = SqliteDeviceTrustStore::open(&path).unwrap();
    let target = insert_device(&store, "interrupted").await;
    let other = insert_device(&store, "unrelated").await;
    let token = odin_domain::SeatTokenId::new("seat-token:4:interrupted").unwrap();
    let other_token = odin_domain::SeatTokenId::new("seat-token:5:unrelated").unwrap();
    for (device, token_id) in [(target, token.clone()), (other, other_token.clone())] {
        store
            .claim_grant(NewDeviceGrant {
                device_id: device,
                session_id: odin_domain::SessionId::new("session-interrupted").unwrap(),
                token_id,
                created_at: time::OffsetDateTime::UNIX_EPOCH,
            })
            .await
            .unwrap();
    }
    let registry = ConnectionRegistry::new();
    let target_registration = register_served(&store, &registry, target).await;
    let other_registration = register_served(&store, &registry, other).await;
    assert!(store
        .begin_revoke(target, time::OffsetDateTime::UNIX_EPOCH)
        .await
        .unwrap());
    drop(store);
    let store = Arc::new(SqliteDeviceTrustStore::open(&path).unwrap());
    let mut target_revocation = target_registration.revocation();
    let other_revocation = other_registration.revocation();
    let ledger_path = temporary.path().join("ledger.sqlite");
    let ledger = Arc::new(Mutex::new(odin_ledger::Ledger::open(&ledger_path).unwrap()));
    let admin = Arc::new(DeviceAdmin::new(store.clone(), registry.clone()));
    let model = Arc::new(odin_huginn::read_model::MaterializedReadModel::new(
        64,
        time::OffsetDateTime::now_utc(),
    ));
    let mut pumps = tokio::task::JoinSet::new();
    crate::pumps::arm_device_activity_pump(
        &mut pumps,
        (store.clone(), registry.clone()),
        model,
        admin,
        ledger.clone(),
    );
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        target_revocation.changed(),
    )
    .await
    .expect("first tick resumes without waiting five seconds")
    .unwrap();
    assert!(*target_revocation.borrow());
    // Read the durable ledger at the first observed close, not a callback flag.
    let reopened_ledger = odin_ledger::Ledger::open(&ledger_path).unwrap();
    let revocations = odin_kernel::LedgerRevocations::new(&reopened_ledger);
    assert!(revocations.is_revoked(&token).unwrap());
    assert!(!revocations.is_revoked(&other_token).unwrap());
    assert!(store
        .get(target)
        .await
        .unwrap()
        .unwrap()
        .revoked_at
        .is_some());
    assert!(store.grants(target).await.unwrap().is_empty());
    assert!(store.pending_revokes().await.unwrap().is_empty());
    assert_eq!(store.grants(other).await.unwrap().len(), 1);
    assert_eq!(registry.active_for_device(other), 1);
    assert!(!*other_revocation.borrow());
    pumps.abort_all();
}

#[tokio::test]
async fn admin_socket_refuses_malformed_and_oversized_requests() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let temporary = tempfile::TempDir::new().expect("state root");
    let state_root = temporary.path().to_path_buf();
    let store = Arc::new(SqliteDeviceTrustStore::open_in_memory().expect("store opens"));
    let registry = ConnectionRegistry::with_limit(8);
    let admin = DeviceAdmin::new(Arc::clone(&store), registry.clone());
    let target = insert_device(store.as_ref(), "phone-target").await;
    let ledger = Arc::new(Mutex::new(
        odin_ledger::Ledger::open_in_memory().expect("ledger opens"),
    ));
    let mut pumps = arm_daemon(&state_root, admin, ledger);
    let socket_path = admin_socket_path(&state_root);

    let mut stream = tokio::net::UnixStream::connect(&socket_path)
        .await
        .expect("socket dials");
    stream
        .write_all(b"{\"deviceId\": \"not-a-device-id\"}")
        .await
        .expect("request written");
    stream.shutdown().await.expect("write half closed");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("response read");
    let refusal: AdminRevokeResponse = serde_json::from_slice(&response).expect("typed response");
    assert_eq!(
        refusal.refusal.expect("malformed request refused").code,
        "malformedRequest"
    );

    let mut stream = tokio::net::UnixStream::connect(&socket_path)
        .await
        .expect("socket dials");
    stream
        .write_all(&vec![b'a'; 4096])
        .await
        .expect("oversized request written");
    stream.shutdown().await.expect("write half closed");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("response read");
    let refusal: AdminRevokeResponse = serde_json::from_slice(&response).expect("typed response");
    assert_eq!(
        refusal.refusal.expect("oversized request refused").code,
        "requestTooLarge"
    );

    let record = store
        .get(target)
        .await
        .expect("record reads")
        .expect("kept");
    assert!(
        record.revoked_at.is_none(),
        "a refused request never touches the device"
    );

    pumps.abort_all();
}

/// A refusal must arrive without waiting for the oversized sender's EOF,
/// while the receive half stays open to discard a delayed request tail.
#[tokio::test]
async fn admin_socket_refuses_oversized_request_before_client_eof() {
    use odin_cli::authority_provision::MAX_ADMIN_REQUEST_BYTES;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let temporary = tempfile::TempDir::new().expect("state root");
    let store = Arc::new(SqliteDeviceTrustStore::open_in_memory().expect("store opens"));
    let target = insert_device(store.as_ref(), "phone-target").await;
    let registry = ConnectionRegistry::with_limit(8);
    let registration = register_served(&store, &registry, target).await;
    let admin = DeviceAdmin::new(Arc::clone(&store), registry.clone());
    let ledger = Arc::new(Mutex::new(
        odin_ledger::Ledger::open_in_memory().expect("ledger opens"),
    ));
    let mut pumps = arm_daemon(temporary.path(), admin, ledger);
    let mut stream = tokio::net::UnixStream::connect(admin_socket_path(temporary.path()))
        .await
        .expect("socket dials");
    stream
        .write_all(&vec![b'a'; MAX_ADMIN_REQUEST_BYTES + 1])
        .await
        .expect("oversized prefix written");

    let mut response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        stream.read_to_end(&mut response),
    )
    .await
    .expect("refusal arrives before client EOF")
    .expect("response reads without reset");
    let refusal: AdminRevokeResponse = serde_json::from_slice(&response).expect("typed response");
    assert_eq!(
        refusal.refusal.expect("oversized request refused").code,
        "requestTooLarge"
    );

    stream
        .write_all(&[b'b'; 4096])
        .await
        .expect("delayed request tail accepted for discard");
    stream.shutdown().await.expect("write half closed");
    let unknown = DeviceId::new(uuid::Uuid::new_v4()).expect("device id");
    let refused = revoke_device(temporary.path(), unknown)
        .await
        .expect_err("listener serves another request after draining");
    assert!(refused.contains("unknownDevice"), "{refused}");
    assert!(store
        .get(target)
        .await
        .expect("record reads")
        .expect("device kept")
        .revoked_at
        .is_none());
    assert_eq!(registry.active_for_device(target), 1);
    assert!(!*registration.revocation().borrow());
    pumps.abort_all();
}

/// A sender that never closes its write half cannot monopolize the inline
/// accept loop beyond the response deadline.
#[tokio::test]
async fn admin_socket_bounds_stalled_oversized_request_drain() {
    use odin_cli::authority_provision::{ADMIN_EXCHANGE_TIMEOUT, MAX_ADMIN_REQUEST_BYTES};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let temporary = tempfile::TempDir::new().expect("state root");
    let store = Arc::new(SqliteDeviceTrustStore::open_in_memory().expect("store opens"));
    let admin = DeviceAdmin::new(store, ConnectionRegistry::new());
    let ledger = Arc::new(Mutex::new(
        odin_ledger::Ledger::open_in_memory().expect("ledger opens"),
    ));
    let mut pumps = arm_daemon(temporary.path(), admin, ledger);
    let socket_path = admin_socket_path(temporary.path());
    let mut stalled = tokio::net::UnixStream::connect(&socket_path)
        .await
        .expect("socket dials");
    stalled
        .write_all(&vec![b'a'; MAX_ADMIN_REQUEST_BYTES + 1])
        .await
        .expect("oversized prefix written");
    let mut response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        stalled.read_to_end(&mut response),
    )
    .await
    .expect("refusal arrives while the sender remains open")
    .expect("response reads without reset");
    let refusal: AdminRevokeResponse = serde_json::from_slice(&response).expect("typed response");
    assert_eq!(
        refusal.refusal.expect("oversized request refused").code,
        "requestTooLarge"
    );

    // Keep the first client's write half open throughout the next exchange.
    // Use a raw client so its own exchange timeout cannot race the drain's.
    tokio::time::timeout(
        ADMIN_EXCHANGE_TIMEOUT + std::time::Duration::from_secs(1),
        async {
            let mut next = tokio::net::UnixStream::connect(&socket_path)
                .await
                .expect("next client dials");
            next.write_all(b"{}").await.expect("next request written");
            next.shutdown().await.expect("next write half closed");
            let mut response = Vec::new();
            next.read_to_end(&mut response)
                .await
                .expect("next response reads");
            let refusal: AdminRevokeResponse =
                serde_json::from_slice(&response).expect("next typed response");
            assert_eq!(
                refusal.refusal.expect("next request refused").code,
                "malformedRequest"
            );
        },
    )
    .await
    .expect("response deadline releases the listener despite absent client EOF");
    drop(stalled);
    pumps.abort_all();
}

#[test]
fn admin_peer_credential_law_refuses_foreign_uids() {
    assert!(crate::device_admin::admin_peer_accepted(1000, 1000));
    assert!(!crate::device_admin::admin_peer_accepted(1001, 1000));
    assert!(!crate::device_admin::admin_peer_accepted(0, 1000));
}
