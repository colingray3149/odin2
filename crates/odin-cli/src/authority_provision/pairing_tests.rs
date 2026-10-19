use super::*;

use crate::authority_provision::dir_mode;
use tempfile::TempDir;

// -----------------------------------------------------------------------
// local device pairing
// -----------------------------------------------------------------------

#[test]
fn pair_device_replaces_only_the_stored_credential_device_under_force() {
    let temporary = TempDir::new().expect("state root");
    let state_root = temporary.path().to_path_buf();
    let node = "00000000-0000-4000-8000-000000000009";
    let runtime = tokio::runtime::Runtime::new().expect("test runtime");

    let first = runtime
        .block_on(pair_device(&state_root, "laptop-console", node, false))
        .expect("first pairing succeeds");
    assert!(!first.replaced_existing);
    let credential_path = state_root.join("huginn/device.credential");
    let store_path = state_root.join("huginn/devices.sqlite3");
    assert_eq!(first.credential_path, credential_path);
    assert_eq!(dir_mode(&credential_path), 0o600);
    assert_eq!(dir_mode(store_path.parent().unwrap()), 0o700);
    assert_eq!(dir_mode(&store_path), 0o600);
    let credential_digest =
        odin_domain::Digest::hash(&fs::read(&credential_path).expect("credential readable"));
    let report_value = serde_json::to_value(&first).expect("report serializes");
    let report_fields = report_value.as_object().expect("report is an object");
    assert!(!report_fields.contains_key("credential"));
    assert!(!report_fields.contains_key("bearer"));
    assert!(!report_fields.contains_key("bearer_token"));

    // An unrelated active client on the same node and label, with no
    // stored credential of its own on this workstation.
    let unrelated = {
        let store = SqliteDeviceTrustStore::open(&store_path).expect("store opens");
        let admin = DeviceAdmin::new(Arc::new(store), ConnectionRegistry::new());
        let bundle = runtime
            .block_on(admin.pair_local(LocalPairRequest {
                label: "laptop-console".to_owned(),
                tailnet_node_id: odin_domain::huginn::TailnetNodeId::parse(node).unwrap(),
            }))
            .expect("unrelated client pairs");
        bundle.device_id().to_string()
    };

    let error = runtime
        .block_on(pair_device(&state_root, "laptop-console", node, false))
        .expect_err("replacement without --force is refused");
    assert!(error.contains("--force"), "unexpected error: {error}");

    let replacement = runtime
        .block_on(pair_device(&state_root, "laptop-console", node, true))
        .expect("forced pairing is the explicit operator choice");
    assert!(replacement.replaced_existing);
    assert_ne!(replacement.device_id, first.device_id);
    assert_ne!(
        odin_domain::Digest::hash(
            &fs::read(&credential_path).expect("replacement credential readable"),
        ),
        credential_digest,
        "the explicit replacement installs a fresh credential"
    );

    let records = list_records(&store_path);
    assert_eq!(records.len(), 3, "replacement adds exactly one new device");
    let state_of = |device: &str| {
        records
            .iter()
            .find(|record| record.device_id.to_string() == device)
            .unwrap_or_else(|| panic!("record for {device} missing"))
            .revoked_at
            .is_some()
    };
    assert!(state_of(&first.device_id), "the replaced device is retired");
    assert!(
        !state_of(&unrelated),
        "an unrelated active device must survive the replacement untouched"
    );
    assert!(
        !state_of(&replacement.device_id),
        "the replacement stays active"
    );
}

#[test]
fn pair_device_without_stored_credential_never_revokes_existing_records() {
    let temporary = TempDir::new().expect("state root");
    let state_root = temporary.path().to_path_buf();
    let node = "00000000-0000-4000-8000-000000000009";
    let store_path = state_root.join("huginn/devices.sqlite3");
    let runtime = tokio::runtime::Runtime::new().expect("test runtime");
    let other_clients = {
        let store = SqliteDeviceTrustStore::open(&store_path).expect("store opens");
        let admin = DeviceAdmin::new(Arc::new(store), ConnectionRegistry::new());
        let mut devices = Vec::new();
        for _ in 0..2 {
            let bundle = runtime
                .block_on(admin.pair_local(LocalPairRequest {
                    label: "other-client".to_owned(),
                    tailnet_node_id: odin_domain::huginn::TailnetNodeId::parse(node).unwrap(),
                }))
                .expect("other client pairs");
            devices.push(bundle.device_id().to_string());
        }
        devices
    };

    let fresh = runtime
        .block_on(pair_device(&state_root, "laptop-console", node, false))
        .expect("a workstation without a stored credential pairs plainly");
    assert!(!fresh.replaced_existing);
    let records = list_records(&store_path);
    assert_eq!(records.len(), 3);
    for device in &other_clients {
        let record = records
            .iter()
            .find(|record| record.device_id.to_string() == *device)
            .expect("other client record");
        assert!(
            record.revoked_at.is_none(),
            "pairing this console must never revoke other clients"
        );
    }
    assert!(records
        .iter()
        .find(|record| record.device_id.to_string() == fresh.device_id)
        .expect("new record")
        .revoked_at
        .is_none());
}

#[test]
fn pair_device_refuses_replacement_when_the_store_record_drifts() {
    let temporary = TempDir::new().expect("state root");
    let state_root = temporary.path().to_path_buf();
    let node = "00000000-0000-4000-8000-000000000009";
    let credential_path = state_root.join("huginn/device.credential");
    let store_path = state_root.join("huginn/devices.sqlite3");
    let runtime = tokio::runtime::Runtime::new().expect("test runtime");
    let first = runtime
        .block_on(pair_device(&state_root, "laptop-console", node, false))
        .expect("initial pairing");
    let stored_digest =
        odin_domain::Digest::hash(&fs::read(&credential_path).expect("credential readable"));

    let connection = rusqlite::Connection::open(&store_path).expect("direct store opens");
    let drifted_digest = odin_domain::Digest::hash(b"drifted");
    connection
        .execute(
            "UPDATE trusted_devices SET credential_digest = ?1 WHERE device_id = ?2",
            rusqlite::params![drifted_digest.as_bytes().as_slice(), first.device_id,],
        )
        .expect("drift record digest");
    drop(connection);
    let error = runtime
        .block_on(pair_device(&state_root, "laptop-console", node, true))
        .expect_err("drifted record is refused");
    assert!(
        error.contains("no matching trust-store record"),
        "unexpected error: {error}"
    );
    assert_eq!(
        odin_domain::Digest::hash(&fs::read(&credential_path).expect("credential kept")),
        stored_digest,
        "a refused replacement must not touch the stored credential"
    );
    assert_eq!(list_records(&store_path).len(), 1, "nothing was added");

    let connection = rusqlite::Connection::open(&store_path).expect("direct store opens");
    connection
        .execute("DELETE FROM trusted_devices", [])
        .expect("remove the record behind the stored credential");
    drop(connection);
    let error = runtime
        .block_on(pair_device(&state_root, "laptop-console", node, true))
        .expect_err("a credential without its record is refused");
    assert!(
        error.contains("no matching trust-store record"),
        "unexpected error: {error}"
    );
    assert_eq!(
        odin_domain::Digest::hash(&fs::read(&credential_path).expect("credential kept")),
        stored_digest
    );
}

#[test]
fn failed_credential_store_keeps_the_previous_local_pairing() {
    let temporary = TempDir::new().expect("state root");
    let state_root = temporary.path().to_path_buf();
    let node =
        odin_domain::huginn::TailnetNodeId::parse("00000000-0000-4000-8000-000000000009").unwrap();
    let store_path = state_root.join("huginn/devices.sqlite3");
    let runtime = tokio::runtime::Runtime::new().expect("test runtime");
    let admin = {
        let store = SqliteDeviceTrustStore::open(&store_path).expect("store opens");
        DeviceAdmin::new(Arc::new(store), ConnectionRegistry::new())
    };
    let previous = runtime
        .block_on(admin.pair_local(LocalPairRequest {
            label: "laptop-console".to_owned(),
            tailnet_node_id: node.clone(),
        }))
        .expect("previous local pairing");

    let error = runtime
        .block_on(admit_local_pair(
            &admin,
            &{
                struct FailingStage;
                impl CredentialTransaction for FailingStage {
                    fn stage(&self, _encoded: &SecretBytes) -> Result<(), String> {
                        Err("injected credential-store failure".to_owned())
                    }

                    fn commit(&self) -> Result<CommitOutcome, String> {
                        unreachable!("stage refuses first")
                    }

                    fn restore(&self) -> Result<(), String> {
                        Ok(())
                    }
                }
                FailingStage
            },
            ledger_file_revoke_pass(state_root.join("ledger.sqlite3")),
            &state_root.join("huginn/device.credential"),
            "laptop-console",
            node,
            Some(previous.device_id()),
        ))
        .expect_err("a failed store must not retire the old pairing");
    assert!(
        error.contains("every earlier pairing remains usable"),
        "unexpected error: {error}"
    );
    let records = list_records(&store_path);
    assert_eq!(records.len(), 2);
    let previous_record = records
        .iter()
        .find(|record| record.device_id == previous.device_id())
        .expect("previous record");
    assert!(
        previous_record.revoked_at.is_none(),
        "the failed replacement must keep the old pairing active"
    );
    let new_record = records
        .iter()
        .find(|record| record.device_id != previous.device_id())
        .expect("new record");
    assert!(
        new_record.revoked_at.is_some(),
        "the unused new device is revoked so no dead authority remains"
    );
}

/// A pre-install failure followed by a failed restoration must report both
/// failures without retiring the still-installed old credential or its grants.
#[tokio::test]
async fn failed_pre_install_restoration_preserves_old_bytes_and_grants() {
    use odin_huginn::devices::NewDeviceGrant;

    struct FailedRestore<'a> {
        inner: &'a CredentialInstall,
        restore_attempted: AtomicBool,
    }
    impl CredentialTransaction for FailedRestore<'_> {
        fn stage(&self, encoded: &SecretBytes) -> Result<(), String> {
            self.inner.stage(encoded)
        }

        fn commit(&self) -> Result<CommitOutcome, String> {
            Err("injected pre-install failure".to_owned())
        }

        fn restore(&self) -> Result<(), String> {
            self.restore_attempted.store(true, Ordering::Relaxed);
            Err("injected restoration failure".to_owned())
        }
    }

    let temporary = TempDir::new().unwrap();
    let state = temporary.path();
    let node = "00000000-0000-4000-8000-000000000009";
    let first = pair_device(state, "workstation", node, false)
        .await
        .unwrap();
    let previous = odin_domain::huginn::DeviceId::parse(&first.device_id).unwrap();
    let original = fs::read(&first.credential_path).unwrap();
    let store =
        Arc::new(SqliteDeviceTrustStore::open(state.join("huginn/devices.sqlite3")).unwrap());
    let token = odin_domain::SeatTokenId::new("seat-token:1:preserved-device").unwrap();
    store
        .claim_grant(NewDeviceGrant {
            device_id: previous,
            session_id: odin_domain::SessionId::new("preserved-device-session").unwrap(),
            token_id: token.clone(),
            created_at: OffsetDateTime::now_utc(),
        })
        .await
        .unwrap();
    let admin = DeviceAdmin::new(Arc::clone(&store), ConnectionRegistry::new());
    let transaction = CredentialInstall::for_replacement(
        CredentialSlot::open(&first.credential_path).unwrap(),
        Some(SecretBytes::new(original.clone())),
    );
    let failure = FailedRestore {
        inner: &transaction,
        restore_attempted: AtomicBool::new(false),
    };
    let error = admit_local_pair(
        &admin,
        &failure,
        ledger_file_revoke_pass(state.join("ledger.sqlite3")),
        &first.credential_path,
        "replacement",
        odin_domain::huginn::TailnetNodeId::parse(node).unwrap(),
        Some(previous),
    )
    .await
    .unwrap_err();
    assert!(error.contains("injected pre-install failure"), "{error}");
    assert!(error.contains("injected restoration failure"), "{error}");
    assert!(error.contains("need review"), "{error}");
    assert!(
        !error.contains("every earlier pairing remains usable"),
        "{error}"
    );
    assert!(failure.restore_attempted.load(Ordering::Relaxed));
    drop(transaction);
    assert_eq!(fs::read(&first.credential_path).unwrap(), original);
    assert_eq!(dir_mode(&first.credential_path), 0o600);
    assert!(store
        .get(previous)
        .await
        .unwrap()
        .unwrap()
        .revoked_at
        .is_none());
    let grant = store.grant_snapshot(&token).await.unwrap().unwrap();
    assert_eq!(grant.device_id, previous);
    assert!(grant.revoked_at.is_none());
    assert!(!state.join("ledger.sqlite3").exists());
    let records = store.list().await.unwrap();
    assert_eq!(records.len(), 2);
    assert!(records
        .iter()
        .find(|record| record.device_id != previous)
        .unwrap()
        .revoked_at
        .is_some());
    let authenticated = TailnetAuthenticator::new(store)
        .authenticate(
            VerifiedTailnetPeer::local(std::net::SocketAddr::from(([127, 0, 0, 1], 0))),
            SecretBytes::new(original),
        )
        .await
        .unwrap();
    assert_eq!(authenticated.device_id, previous);
}

/// The real injected point: the swap genuinely lands inside `commit`, and
/// only the directory entry's durability is then declared uncertain. The
/// installed credential is valid and stays — never restored over, never
/// revoked — the previous device is still retired after it, and the
/// condition is reported typed.
struct UncertainAfterSwap<'a> {
    inner: &'a CredentialInstall,
    swapped_in: Mutex<Option<Vec<u8>>>,
    restore_attempted: AtomicBool,
}

impl CredentialTransaction for UncertainAfterSwap<'_> {
    fn stage(&self, encoded: &SecretBytes) -> Result<(), String> {
        *self.swapped_in.lock().expect("capture lock") = Some(encoded.as_slice().to_vec());
        self.inner.stage(encoded)
    }

    fn commit(&self) -> Result<CommitOutcome, String> {
        self.inner.commit()?;
        Ok(CommitOutcome::DurabilityUncertain(
            "injected directory fsync failure".to_owned(),
        ))
    }

    fn restore(&self) -> Result<(), String> {
        self.restore_attempted.store(true, Ordering::Relaxed);
        self.inner.restore()
    }
}

#[test]
fn durability_failure_after_the_swap_keeps_the_installed_credential() {
    let temporary = TempDir::new().expect("state root");
    let state_root = temporary.path().to_path_buf();
    let node = "00000000-0000-4000-8000-000000000009";
    let store_path = state_root.join("huginn/devices.sqlite3");
    let credential_path = state_root.join("huginn/device.credential");
    let runtime = tokio::runtime::Runtime::new().expect("test runtime");
    let first = runtime
        .block_on(pair_device(&state_root, "laptop-console", node, false))
        .expect("initial pairing");
    let original = fs::read(&credential_path).expect("credential readable");
    let admin = {
        let store = SqliteDeviceTrustStore::open(&store_path).expect("store opens");
        DeviceAdmin::new(Arc::new(store), ConnectionRegistry::new())
    };

    let transaction = CredentialInstall::for_replacement(
        CredentialSlot::open(&credential_path).expect("slot opens"),
        Some(SecretBytes::new(original.clone())),
    );
    let failure = UncertainAfterSwap {
        inner: &transaction,
        swapped_in: Mutex::new(None),
        restore_attempted: AtomicBool::new(false),
    };
    let report = runtime
        .block_on(admit_local_pair(
            &admin,
            &failure,
            ledger_file_revoke_pass(state_root.join("ledger.sqlite3")),
            &credential_path,
            "laptop-console",
            odin_domain::huginn::TailnetNodeId::parse(node).unwrap(),
            Some(odin_domain::huginn::DeviceId::parse(&first.device_id).expect("device id")),
        ))
        .expect("a landed swap with uncertain durability is kept, not rolled back");
    assert_eq!(
        report.durability_warning.as_deref(),
        Some("injected directory fsync failure"),
        "the durability condition is reported typed: {report:?}"
    );
    assert!(
        !failure.restore_attempted.load(Ordering::Relaxed),
        "a durability warning must never restore over the installed credential"
    );

    // The installed credential is the new one, on disk, protected, and it
    // authenticates as the new device.
    let swapped = failure
        .swapped_in
        .lock()
        .expect("capture lock")
        .clone()
        .expect("a real swap happened");
    assert_ne!(swapped, original);
    assert_eq!(
        fs::read(&credential_path).expect("credential installed"),
        swapped
    );
    assert_eq!(dir_mode(&credential_path), 0o600);
    let authenticator = {
        let store = SqliteDeviceTrustStore::open(&store_path).expect("store opens");
        TailnetAuthenticator::new(Arc::new(store))
    };
    let verified = runtime
        .block_on(authenticator.authenticate(
            VerifiedTailnetPeer::local(std::net::SocketAddr::from(([127, 0, 0, 1], 0))),
            SecretBytes::new(swapped),
        ))
        .expect("the kept new credential authenticates");
    assert_ne!(verified.device_id.to_string(), first.device_id);

    // Honest ordering: the previous device was still retired after the swap.
    let previous_error = runtime
        .block_on(authenticator.authenticate(
            VerifiedTailnetPeer::local(std::net::SocketAddr::from(([127, 0, 0, 1], 0))),
            SecretBytes::new(original),
        ))
        .expect_err("the previous device is retired after the kept swap");
    assert!(matches!(
        previous_error,
        odin_huginn::auth::AuthError::DeviceRevoked
    ));
    let records = list_records(&store_path);
    assert_eq!(records.len(), 2);
    assert!(records
        .iter()
        .find(|record| record.device_id.to_string() == first.device_id)
        .expect("previous record")
        .revoked_at
        .is_some());
    assert!(records
        .iter()
        .find(|record| record.device_id.to_string() != first.device_id)
        .expect("new record")
        .revoked_at
        .is_none());
}

#[test]
fn durability_warning_keeps_an_installed_enrollment() {
    let temporary = TempDir::new().expect("state root");
    let state_root = temporary.path().to_path_buf();
    let node = "00000000-0000-4000-8000-000000000009";
    let store_path = state_root.join("huginn/devices.sqlite3");
    let runtime = tokio::runtime::Runtime::new().expect("test runtime");
    let out = temporary.path().join("kept/phone.credential");

    let transaction = CredentialInstall::for_new(CredentialSlot::open(&out).expect("slot opens"));
    let failure = UncertainAfterSwap {
        inner: &transaction,
        swapped_in: Mutex::new(None),
        restore_attempted: AtomicBool::new(false),
    };
    let admin = {
        let store = SqliteDeviceTrustStore::open(&store_path).expect("store opens");
        DeviceAdmin::new(Arc::new(store), ConnectionRegistry::new())
    };
    let report = runtime
        .block_on(admit_local_pair(
            &admin,
            &failure,
            ledger_file_revoke_pass(temporary.path().join("ledger.sqlite3")),
            &out,
            "phone",
            odin_domain::huginn::TailnetNodeId::parse(node).unwrap(),
            None,
        ))
        .expect("an installed enrollment with uncertain durability is kept");
    assert_eq!(
        report.durability_warning.as_deref(),
        Some("injected directory fsync failure")
    );
    assert!(!failure.restore_attempted.load(Ordering::Relaxed));
    assert!(!report.replaced_existing);
    assert_eq!(dir_mode(&out), 0o600);
    let bearer = fs::read_to_string(&out).expect("the installed enrollment is on disk");
    assert!(odin_huginn::client::DeviceCredential::parse_base64url(&bearer).is_ok());
    let swapped = failure
        .swapped_in
        .lock()
        .expect("capture lock")
        .clone()
        .expect("a real install happened");
    assert_eq!(bearer.trim().as_bytes(), swapped.as_slice());
    let records = list_records(&store_path);
    assert_eq!(records.len(), 1);
    assert!(records.iter().all(|record| record.revoked_at.is_none()));
}

/// The workstation's own credential slot is reserved: an enrollment aimed at
/// it — directly, through dot components, or through a symlinked directory —
/// is refused before any device is admitted, and an initially absent
/// workstation credential stays absent.
#[test]
fn enroll_refuses_the_workstation_credential_slot_before_admitting_anything() {
    let temporary = TempDir::new().expect("state root");
    let state_root = temporary.path().to_path_buf();
    let node = "00000000-0000-4000-8000-000000000009";
    let slot = state_root.join("huginn/device.credential");
    let store_path = state_root.join("huginn/devices.sqlite3");
    let runtime = tokio::runtime::Runtime::new().expect("test runtime");

    for out in [
        slot.clone(),
        state_root.join("huginn/../huginn/device.credential"),
        state_root.join("huginn/./device.credential"),
    ] {
        let error = runtime
            .block_on(enroll_device(&state_root, "phone", node, &out))
            .expect_err("the workstation slot is reserved");
        assert!(
            error.contains("own credential slot"),
            "unexpected error: {error}"
        );
        assert!(
            fs::symlink_metadata(&slot).is_err(),
            "an initially absent workstation credential stays absent"
        );
        assert_eq!(list_records(&store_path).len(), 0, "no device was admitted");
    }

    // A symlinked directory that resolves into the slot's directory is the
    // same refusal.
    std::os::unix::fs::symlink(state_root.join("huginn"), temporary.path().join("linked"))
        .expect("slot alias");
    let error = runtime
        .block_on(enroll_device(
            &state_root,
            "phone",
            node,
            &temporary.path().join("linked/device.credential"),
        ))
        .expect_err("the slot through a symlinked directory is the same refusal");
    assert!(
        error.contains("own credential slot"),
        "unexpected error: {error}"
    );
    assert!(fs::symlink_metadata(&slot).is_err());
    assert_eq!(list_records(&store_path).len(), 0);

    // A paired workstation's slot is never touched either.
    let workstation = runtime
        .block_on(pair_device(&state_root, "laptop-console", node, false))
        .expect("workstation pairs");
    let stored = fs::read(&slot).expect("workstation credential readable");
    let error = runtime
        .block_on(enroll_device(&state_root, "phone", node, &slot))
        .expect_err("the paired slot stays reserved");
    assert!(
        error.contains("own credential slot"),
        "unexpected error: {error}"
    );
    assert_eq!(fs::read(&slot).expect("credential untouched"), stored);
    assert_eq!(dir_mode(&slot), 0o600);
    let records = list_records(&store_path);
    assert_eq!(records.len(), 1, "no enrollment was admitted");
    assert!(records
        .iter()
        .all(|record| record.device_id.to_string() == workstation.device_id));
}

/// A bare `--out phone.credential` names the current directory and passes
/// the same descriptor-based checks as any explicit path; `./second.credential`
/// is its exact equivalent.
#[test]
fn enroll_accepts_equivalent_bare_and_dot_slash_outputs_in_a_private_working_directory() {
    use std::os::unix::fs::PermissionsExt as _;

    const CHILD_ROOT: &str = "ODIN_PAIRING_BARE_PATH_TEST_ROOT";
    const TEST_PATH: &str = "authority_provision::pairing::tests::enroll_accepts_equivalent_bare_and_dot_slash_outputs_in_a_private_working_directory";
    let Some(state_root) = std::env::var_os(CHILD_ROOT).map(PathBuf::from) else {
        let temporary = TempDir::new().expect("state root");
        let work = temporary.path().join("private");
        fs::create_dir(&work).expect("working directory");
        fs::set_permissions(&work, fs::Permissions::from_mode(0o700))
            .expect("private working directory");
        let output = std::process::Command::new(std::env::current_exe().expect("test harness"))
            .args(["--exact", TEST_PATH, "--test-threads", "1"])
            .env(CHILD_ROOT, temporary.path())
            .current_dir(&work)
            .output()
            .expect("isolated pairing child");
        assert!(
            output.status.success(),
            "isolated pairing failed: {output:?}"
        );
        assert!(
            temporary.path().join("completed").is_file(),
            "child test was not selected: {output:?}"
        );
        return;
    };
    let node = "00000000-0000-4000-8000-000000000009";
    let store_path = state_root.join("huginn/devices.sqlite3");
    let runtime = tokio::runtime::Runtime::new().expect("test runtime");
    let work = std::env::current_dir().expect("private working directory");

    let phone = runtime
        .block_on(enroll_device(
            &state_root,
            "phone",
            node,
            Path::new("phone.credential"),
        ))
        .expect("a bare output name enrolls into the current directory");
    let second = runtime
        .block_on(enroll_device(
            &state_root,
            "second-phone",
            node,
            Path::new("./second.credential"),
        ))
        .expect("a ./ output name enrolls into the current directory");

    assert_eq!(dir_mode(&work.join("phone.credential")), 0o600);
    assert_eq!(dir_mode(&work.join("second.credential")), 0o600);
    assert!(odin_huginn::client::DeviceCredential::parse_base64url(
        &fs::read_to_string(work.join("phone.credential")).expect("phone credential readable"),
    )
    .is_ok());
    assert_ne!(phone.device_id, second.device_id);
    let records = list_records(&store_path);
    assert_eq!(
        records.len(),
        2,
        "each bare-path enroll admitted exactly one device"
    );
    assert!(records.iter().all(|record| record.revoked_at.is_none()));
    assert!(
        fs::symlink_metadata(state_root.join("huginn/device.credential")).is_err(),
        "the workstation's own slot stays out of reach"
    );
    fs::write(state_root.join("completed"), b"paired").expect("child completion acknowledgment");
}

/// The slot's descriptor is retained from validation through commit:
/// swapping the validated directory's name for a symlink — or occupying the
/// output name — between stage and commit cannot redirect the install, make
/// it follow a symlink, or touch anything the descriptors do not point at.
#[test]
fn staged_installations_ignore_parent_and_output_swaps() {
    use std::os::unix::fs::PermissionsExt as _;

    let temporary = TempDir::new().expect("workspace");
    let work = temporary.path().join("work");
    fs::create_dir(&work).expect("workspace");
    let private = work.join("private");
    fs::create_dir(&private).expect("private directory");
    fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).expect("private directory");
    let victim_directory = work.join("victim");
    fs::create_dir(&victim_directory).expect("victim directory");
    let victim_file = victim_directory.join("phone.credential");
    fs::write(&victim_file, b"victim").expect("victim file");
    fs::set_permissions(&victim_file, fs::Permissions::from_mode(0o640)).expect("victim mode");

    let out = private.join("phone.credential");
    let slot = CredentialSlot::open(&out).expect("the slot opens");

    // The parent swap: the validated directory's name now points elsewhere.
    fs::rename(&private, work.join("private.moved")).expect("parent swap");
    std::os::unix::fs::symlink(&victim_directory, &private).expect("parent symlink");

    let staged = stage_private_new(&slot.directory, OsStr::new("phone.credential"), b"staged")
        .expect("staging uses the retained descriptor");
    assert!(matches!(
        staged
            .install_new("phone.credential")
            .expect("the commit lands in the original directory"),
        InstallOutcome::Durable
    ));

    // Nothing followed the symlink: the victim directory holds only its own
    // untouched file, and the credential sits in the original inode.
    assert_eq!(
        fs::read_dir(&victim_directory)
            .expect("victim listed")
            .count(),
        1
    );
    assert_eq!(fs::read(&victim_file).expect("victim untouched"), b"victim");
    assert_eq!(dir_mode(&victim_file), 0o640);
    assert_eq!(
        fs::read(work.join("private.moved/phone.credential")).expect("credential installed"),
        b"staged"
    );
    assert_eq!(
        dir_mode(&work.join("private.moved/phone.credential")),
        0o600
    );

    // The output swap: a symlink occupying the output name is never
    // followed — the no-clobber commit refuses it, and a replacement swaps
    // the symlink itself out, leaving the victim intact.
    let second_slot =
        CredentialSlot::open(&work.join("private.moved/second.credential")).expect("slot opens");
    let staged_link = stage_private_new(
        &second_slot.directory,
        OsStr::new("second.credential"),
        b"second",
    )
    .expect("staged");
    std::os::unix::fs::symlink(&victim_file, work.join("private.moved/second.credential"))
        .expect("output swap");
    assert!(matches!(
        staged_link
            .install_new("second.credential")
            .expect("occupied names refuse"),
        InstallOutcome::Occupied
    ));
    assert!(
        fs::symlink_metadata(work.join("private.moved/second.credential"))
            .expect("still a symlink")
            .file_type()
            .is_symlink()
    );
    let staged_replacement = stage_private_new(
        &second_slot.directory,
        OsStr::new("second.credential"),
        b"second",
    )
    .expect("staged");
    assert!(matches!(
        staged_replacement
            .install_replacing("second.credential")
            .expect("a replacement swaps the symlink itself"),
        InstallOutcome::Durable
    ));
    assert!(
        !fs::symlink_metadata(work.join("private.moved/second.credential"))
            .expect("no longer a symlink")
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(&victim_file).expect("victim untouched"), b"victim");
    assert_eq!(dir_mode(&victim_file), 0o640);
    assert_eq!(
        fs::read(work.join("private.moved/second.credential")).expect("replacement installed"),
        b"second"
    );
}

fn list_records(store_path: &Path) -> Vec<odin_huginn::devices::DeviceRecord> {
    let store = SqliteDeviceTrustStore::open(store_path).expect("store reopens");
    let admin = DeviceAdmin::new(Arc::new(store), ConnectionRegistry::new());
    let runtime = tokio::runtime::Runtime::new().expect("list runtime");
    runtime.block_on(admin.list()).expect("records list")
}

/// `odin huginn devices revoke` without a daemon: a paired device is
/// revoked through the store with the same persisted ordering, the report
/// truthfully says no daemon cut streams, a second revoke is refused
/// typed, a grant-free host never gains a ledger file, and a host without
/// a trust store says where revocation happens.
#[test]
fn revoke_device_retires_a_paired_device_once() {
    use odin_huginn::devices::DeviceTrustStore as _;
    let temporary = TempDir::new().expect("state root");
    let state_root = temporary.path().to_path_buf();
    let runtime = tokio::runtime::Runtime::new().expect("test runtime");
    let paired = runtime
        .block_on(pair_device(
            &state_root,
            "laptop-console",
            "00000000-0000-4000-8000-000000000009",
            false,
        ))
        .expect("pairing succeeds");
    let device = odin_domain::huginn::DeviceId::parse(&paired.device_id).expect("device id");
    let report = runtime
        .block_on(revoke_device(&state_root, device))
        .expect("revoke succeeds");
    assert!(report.revoked);
    assert_eq!(report.streams_closed, 0, "the fallback serves no streams");
    assert!(!report.daemon);
    let report_json = serde_json::to_string(&report).expect("report serializes");
    assert!(
        !report_json.contains("daemon"),
        "a local-only revoke does not advertise a daemon: {report_json}"
    );
    let record = runtime
        .block_on(
            SqliteDeviceTrustStore::open(state_root.join("huginn/devices.sqlite3"))
                .expect("store opens")
                .get(device),
        )
        .expect("store reads")
        .expect("record kept");
    assert!(record.revoked_at.is_some(), "the record says revoked");
    assert!(
        !state_root.join("ledger.sqlite3").exists(),
        "a grant-free device gains no revocation ledger file"
    );
    let again = runtime
        .block_on(revoke_device(&state_root, device))
        .expect_err("a revoked device is not revoked twice");
    assert!(again.contains("was not revoked"), "{again}");
    let elsewhere = TempDir::new().expect("other root");
    let refused = runtime
        .block_on(revoke_device(elsewhere.path(), device))
        .expect_err("no trust store here");
    assert!(refused.contains("on the authority"), "{refused}");
}

/// Q34: a workstation that already stored its credential could reach another
/// device only through --force, which revoked the workstation itself.
/// Enrolling inserts one record and writes its credential to a new 0600 file
/// under a private directory; the workstation credential and record are
/// untouched, a device on the same tailnet node is its own device id, and
/// the serialized report carries the path but never the bearer.
#[test]
fn enroll_device_inserts_a_beside_record_without_touching_the_workstation_pairing() {
    let temporary = TempDir::new().expect("state root");
    let state_root = temporary.path().to_path_buf();
    let node = "00000000-0000-4000-8000-000000000009";
    let runtime = tokio::runtime::Runtime::new().expect("test runtime");
    let workstation = runtime
        .block_on(pair_device(&state_root, "laptop-console", node, false))
        .expect("workstation pairs");
    let credential_path = state_root.join("huginn/device.credential");
    let store_path = state_root.join("huginn/devices.sqlite3");
    let stored_credential = fs::read(&credential_path).expect("credential readable");

    let out = temporary.path().join("phones/first/phone.credential");
    let phone = runtime
        .block_on(enroll_device(&state_root, "phone", node, &out))
        .expect("the phone enrolls beside the workstation");
    assert_eq!(phone.credential_path, out);
    assert!(!phone.replaced_existing);
    assert_ne!(phone.device_id, workstation.device_id);
    assert_eq!(dir_mode(&out), 0o600);
    assert_eq!(dir_mode(out.parent().unwrap()), 0o700);
    let bearer = fs::read_to_string(&out).expect("phone credential readable");
    assert!(odin_huginn::client::DeviceCredential::parse_base64url(&bearer).is_ok());
    let serialized = serde_json::to_string(&phone).expect("report serializes");
    assert!(
        !serialized.contains(&bearer),
        "the report must not carry the bearer: {serialized}"
    );
    assert_eq!(fs::read(&credential_path).unwrap(), stored_credential);
    assert_eq!(dir_mode(&credential_path), 0o600);

    let records = list_records(&store_path);
    assert_eq!(records.len(), 2, "enrolling adds exactly one new device");
    assert!(records
        .iter()
        .all(|record| record.revoked_at.is_none() && record.tailnet_node_id.to_string() == node));
    assert!(records
        .iter()
        .any(|record| record.device_id.to_string() == workstation.device_id));
    assert!(records
        .iter()
        .any(|record| record.device_id.to_string() == phone.device_id));
}

/// Q34: every failed output refuses typed and never writes through or over
/// anything: an occupied name — a file or a symlink — is refused after
/// admission and revokes only the new record it created, while an unusable
/// parent (a shared mode, or not a directory) is refused before any device
/// is admitted at all.
#[test]
fn enroll_output_failures_leave_only_the_new_record_revoked() {
    use std::os::unix::fs::PermissionsExt as _;

    let temporary = TempDir::new().expect("state root");
    let state_root = temporary.path().to_path_buf();
    let node = "00000000-0000-4000-8000-000000000009";
    let runtime = tokio::runtime::Runtime::new().expect("test runtime");
    let workstation = runtime
        .block_on(pair_device(&state_root, "laptop-console", node, false))
        .expect("workstation pairs");
    let store_path = state_root.join("huginn/devices.sqlite3");

    // An existing target file is never overwritten.
    let existing = temporary.path().join("existing.credential");
    fs::write(&existing, b"keep").unwrap();
    let error = runtime
        .block_on(enroll_device(&state_root, "phone", node, &existing))
        .expect_err("an existing file is never overwritten");
    assert!(
        error.contains("already exists"),
        "unexpected error: {error}"
    );
    assert_eq!(fs::read(&existing).unwrap(), b"keep");

    // A symlinked target is never followed.
    let victim = temporary.path().join("victim");
    fs::write(&victim, b"victim").unwrap();
    let linked = temporary.path().join("linked.credential");
    std::os::unix::fs::symlink(&victim, &linked).unwrap();
    let error = runtime
        .block_on(enroll_device(&state_root, "phone", node, &linked))
        .expect_err("a symlinked target is never written through");
    assert!(
        error.contains("already exists"),
        "unexpected error: {error}"
    );
    assert_eq!(fs::read(&victim).unwrap(), b"victim");
    assert!(fs::symlink_metadata(&linked)
        .unwrap()
        .file_type()
        .is_symlink());

    // A shared parent directory is refused, not re-permissioned.
    let shared = temporary.path().join("shared");
    fs::create_dir(&shared).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o755)).unwrap();
    let error = runtime
        .block_on(enroll_device(
            &state_root,
            "phone",
            node,
            &shared.join("phone.credential"),
        ))
        .expect_err("a shared parent directory is a typed refusal");
    assert!(
        error.contains("broader than 0700"),
        "unexpected error: {error}"
    );
    assert_eq!(dir_mode(&shared), 0o755);
    assert!(
        fs::read_dir(&shared).unwrap().next().is_none(),
        "nothing is written into the shared directory"
    );

    // A parent that is not a directory is a typed refusal.
    let error = runtime
        .block_on(enroll_device(
            &state_root,
            "phone",
            node,
            &store_path.join("phone.credential"),
        ))
        .expect_err("a file parent is a typed refusal");
    assert!(
        error.contains("is not a directory"),
        "unexpected error: {error}"
    );

    let records = list_records(&store_path);
    // The workstation's own pairing survives every failed enroll active, and
    // nothing else is left usable: each occupied-name refusal admitted one
    // unusable device that was revoked, and the pre-admission parent refusals
    // never created a record at all.
    let workstation_id =
        odin_domain::huginn::DeviceId::parse(&workstation.device_id).expect("device id");
    let workstation_record = records
        .iter()
        .find(|record| record.device_id == workstation_id)
        .expect("workstation record");
    assert!(
        workstation_record.revoked_at.is_none(),
        "the workstation pairing survives every failed enroll"
    );
    assert!(
        records
            .iter()
            .filter(|record| record.device_id != workstation_record.device_id)
            .all(|record| record.revoked_at.is_some()),
        "no device outside the workstation's own pairing stays active"
    );
}

/// A granted device revoked without a daemon: the fallback ledger-revokes
/// the device's seat tokens over the runtime ledger and the grants
/// tombstone with the finalize.
#[test]
fn fallback_ledger_revokes_device_grants_before_finalizing() {
    use odin_huginn::devices::{DeviceTrustStore as _, GrantClaim, NewDeviceGrant};
    let temporary = TempDir::new().expect("state root");
    let state_root = temporary.path().to_path_buf();
    let runtime = tokio::runtime::Runtime::new().expect("test runtime");
    let paired = runtime
        .block_on(pair_device(
            &state_root,
            "laptop-console",
            "00000000-0000-4000-8000-000000000009",
            false,
        ))
        .expect("pairing succeeds");
    let device = odin_domain::huginn::DeviceId::parse(&paired.device_id).expect("device id");
    let token = odin_domain::SeatTokenId::new("seat-token:1:device-held").expect("token id");
    let store_path = state_root.join("huginn/devices.sqlite3");
    {
        let store = SqliteDeviceTrustStore::open(&store_path).expect("store opens");
        let claimed = runtime
            .block_on(store.claim_grant(NewDeviceGrant {
                device_id: device,
                session_id: odin_domain::SessionId::new("session-held-open").expect("session id"),
                token_id: token.clone(),
                created_at: time::OffsetDateTime::now_utc(),
            }))
            .expect("grant claims");
        assert!(matches!(claimed, GrantClaim::Claimed));
    }
    let report = runtime
        .block_on(revoke_device(&state_root, device))
        .expect("revoke succeeds");
    assert!(report.revoked);
    let ledger = odin_ledger::Ledger::open(state_root.join("ledger.sqlite3"))
        .expect("the runtime ledger exists");
    let revoked = odin_kernel::LedgerRevocations::new(&ledger)
        .is_revoked(&token)
        .expect("ledger reads");
    assert!(revoked, "the device's seat token is ledger-revoked");
    let store = SqliteDeviceTrustStore::open(&store_path).expect("store reopens");
    let snapshot = runtime
        .block_on(store.grant_snapshot(&token))
        .expect("snapshot reads")
        .expect("the grant row is retained");
    assert!(snapshot.revoked_at.is_some(), "the grant tombstoned");
    let record = runtime
        .block_on(store.get(device))
        .expect("record reads")
        .expect("record kept");
    assert!(record.revoked_at.is_some());
}

/// A failed ledger pass never finalizes and never reports success: the
/// device stays revoking (its credential is refused), the grant row stays
/// live for the revoker's snapshot, and the pump's pending set names it
/// for redrive.
#[test]
fn failed_ledger_revoke_leaves_the_device_revoking_and_pending() {
    use odin_huginn::devices::{DeviceTrustStore as _, NewDeviceGrant};
    let temporary = TempDir::new().expect("state root");
    let state_root = temporary.path().to_path_buf();
    let runtime = tokio::runtime::Runtime::new().expect("test runtime");
    let paired = runtime
        .block_on(pair_device(
            &state_root,
            "laptop-console",
            "00000000-0000-4000-8000-000000000009",
            false,
        ))
        .expect("pairing succeeds");
    let device = odin_domain::huginn::DeviceId::parse(&paired.device_id).expect("device id");
    let token = odin_domain::SeatTokenId::new("seat-token:1:device-held").expect("token id");
    let store_path = state_root.join("huginn/devices.sqlite3");
    {
        let store = SqliteDeviceTrustStore::open(&store_path).expect("store opens");
        runtime
            .block_on(store.claim_grant(NewDeviceGrant {
                device_id: device,
                session_id: odin_domain::SessionId::new("session-held-open").expect("session id"),
                token_id: token.clone(),
                created_at: time::OffsetDateTime::now_utc(),
            }))
            .expect("grant claims");
    }
    // The runtime ledger cannot be opened, so the pass must fail closed.
    fs::create_dir(state_root.join("ledger.sqlite3")).expect("ledger path blocked");
    let error = runtime
        .block_on(revoke_device(&state_root, device))
        .expect_err("the ledger pass fails");
    assert!(error.contains("was not revoked"), "{error}");
    assert!(error.contains("ledger"), "{error}");
    let store = SqliteDeviceTrustStore::open(&store_path).expect("store reopens");
    let record = runtime
        .block_on(store.get(device))
        .expect("record reads")
        .expect("record kept");
    assert!(
        record.revoked_at.is_none(),
        "a failed ledger pass never finalizes"
    );
    let snapshot = runtime
        .block_on(store.grant_snapshot(&token))
        .expect("snapshot reads")
        .expect("the grant row is retained");
    assert!(snapshot.revoked_at.is_none(), "the grant stays live");
    let pending = runtime
        .block_on(store.pending_revokes())
        .expect("pending reads");
    assert!(
        pending.iter().any(|record| record.device_id == device),
        "the pump's redrive set names the device"
    );
}

/// Crash resume: a device stuck revoking (gate persisted, ledger pass not
/// finished) is redriven — grants ledger-revoked, record finalized, its
/// live stream closed, every other device untouched — and a device
/// revoked while its stream was still served is cut by the same tick.
#[test]
fn redrive_finishes_pending_revocations_and_cuts_stale_streams() {
    use odin_huginn::devices::{DeviceTrustStore as _, NewDeviceGrant, NewDeviceRecord};
    use odin_kernel::RevocationStore as _;
    let runtime = tokio::runtime::Runtime::new().expect("test runtime");
    let store = Arc::new(SqliteDeviceTrustStore::open_in_memory().expect("store opens"));
    let registry = ConnectionRegistry::with_limit(8);
    let admin = DeviceAdmin::new(Arc::clone(&store), registry.clone());
    let node = odin_domain::huginn::TailnetNodeId::parse("00000000-0000-4000-8000-000000000009")
        .expect("node id");
    let insert = |runtime: &tokio::runtime::Runtime, label: &str| {
        let device = odin_domain::huginn::DeviceId::new(uuid::Uuid::new_v4()).expect("device id");
        runtime
            .block_on(store.insert(NewDeviceRecord {
                device_id: device,
                tailnet_node_id: node.clone(),
                label: label.to_owned(),
                credential_digest: odin_domain::Digest::hash(label.as_bytes()),
                created_at: time::OffsetDateTime::now_utc(),
            }))
            .expect("device inserted");
        device
    };
    let pending = insert(&runtime, "phone-pending");
    let untouched = insert(&runtime, "phone-untouched");
    let legacy = insert(&runtime, "phone-legacy-revoked");
    let register = |device| {
        runtime
            .block_on(
                store.register_connection(
                    &odin_domain::huginn::VerifiedColinDevice {
                        device_id: device,
                        tailnet_node_id: node.clone(),
                        connection_id: odin_domain::huginn::ConnectionId::new(uuid::Uuid::new_v4())
                            .expect("connection id"),
                    },
                    &registry,
                    usize::MAX,
                ),
            )
            .expect("device serves")
    };
    let pending_registration = register(pending);
    let untouched_registration = register(untouched);
    let legacy_registration = register(legacy);
    let pending_revocation = pending_registration.revocation();
    let untouched_revocation = untouched_registration.revocation();
    let legacy_revocation = legacy_registration.revocation();
    let token = odin_domain::SeatTokenId::new("seat-token:1:pending-device").expect("token id");
    runtime
        .block_on(store.claim_grant(NewDeviceGrant {
            device_id: pending,
            session_id: odin_domain::SessionId::new("session-held-open").expect("session id"),
            token_id: token.clone(),
            created_at: time::OffsetDateTime::now_utc(),
        }))
        .expect("grant claims");
    // The crash: the gate is durable, the ledger pass never ran.
    runtime
        .block_on(admin.begin_revoke(pending))
        .expect("gate persists");
    runtime
        .block_on(store.revoke(legacy, time::OffsetDateTime::now_utc()))
        .expect("legacy revoke");
    let ledger = Arc::new(Mutex::new(
        odin_ledger::Ledger::open_in_memory().expect("ledger opens"),
    ));
    let closed = runtime.block_on(redrive_device_revocations(
        &admin,
        store.as_ref(),
        &registry,
        Arc::clone(&ledger),
    ));
    assert_eq!(closed, 2, "the pending and the stale-revoked stream close");
    assert!(
        *pending_revocation.borrow(),
        "the pending device's stream observes the revoke"
    );
    assert!(
        *legacy_revocation.borrow(),
        "the stale-revoked device's stream closes"
    );
    assert!(
        !untouched_revocation.has_changed().unwrap(),
        "an unrelated served device is untouched"
    );
    assert_eq!(registry.active_for_device(pending), 0);
    assert_eq!(registry.active_for_device(untouched), 1);
    assert_eq!(registry.active_for_device(legacy), 0);
    let ledger_guard = ledger.lock().expect("ledger lock");
    assert!(
        odin_kernel::LedgerRevocations::new(&ledger_guard)
            .is_revoked(&token)
            .expect("ledger reads"),
        "the redrive ledger-revokes the granted token"
    );
    drop(ledger_guard);
    let record = runtime
        .block_on(store.get(pending))
        .expect("record reads")
        .expect("record kept");
    assert!(record.revoked_at.is_some(), "the redrive finalizes");
    let snapshot = runtime
        .block_on(store.grant_snapshot(&token))
        .expect("snapshot reads")
        .expect("the grant row is retained");
    assert!(
        snapshot.revoked_at.is_some(),
        "grants tombstone with the finalize"
    );
    let still_pending = runtime
        .block_on(admin.pending_revokes())
        .expect("pending reads");
    assert!(
        still_pending.is_empty(),
        "the redriven device leaves the pending set"
    );
    let again = runtime.block_on(redrive_device_revocations(
        &admin,
        store.as_ref(),
        &registry,
        Arc::clone(&ledger),
    ));
    assert_eq!(again, 0, "a quiet tick closes nothing");
}

/// A credential that stores but cannot be protected (chmod or fsync) is
/// the same rollback case as a failed store: the unused new device is
/// revoked and the previous pairing stays active.
#[test]
fn failed_credential_protection_revokes_the_unused_new_record() {
    use odin_huginn::devices::{DeviceTrustStore as _, NewDeviceRecord};
    let temporary = TempDir::new().expect("state root");
    let runtime = tokio::runtime::Runtime::new().expect("test runtime");
    let store = Arc::new(SqliteDeviceTrustStore::open_in_memory().expect("store opens"));
    let admin = DeviceAdmin::new(Arc::clone(&store), ConnectionRegistry::new());
    let node = odin_domain::huginn::TailnetNodeId::parse("00000000-0000-4000-8000-000000000009")
        .expect("node id");
    let previous = odin_domain::huginn::DeviceId::new(uuid::Uuid::new_v4()).expect("device id");
    runtime
        .block_on(store.insert(NewDeviceRecord {
            device_id: previous,
            tailnet_node_id: node.clone(),
            label: "previous-pairing".to_owned(),
            credential_digest: odin_domain::Digest::hash(b"previous"),
            created_at: time::OffsetDateTime::now_utc(),
        }))
        .expect("previous inserted");
    struct FailingProtection;
    impl CredentialTransaction for FailingProtection {
        fn stage(&self, _encoded: &SecretBytes) -> Result<(), String> {
            Err("injected credential protection failure".to_owned())
        }

        fn commit(&self) -> Result<CommitOutcome, String> {
            unreachable!("protection failed before installation")
        }

        fn restore(&self) -> Result<(), String> {
            Ok(())
        }
    }
    let credential_path = temporary.path().join("missing").join("device.credential");
    let error = runtime
        .block_on(admit_local_pair(
            &admin,
            &FailingProtection,
            ledger_file_revoke_pass(temporary.path().join("ledger.sqlite3")),
            &credential_path,
            "replacement-laptop",
            node,
            Some(previous),
        ))
        .expect_err("an unprotectable credential never pairs");
    assert!(error.contains("store and protect"), "{error}");
    assert!(error.contains("was revoked"), "{error}");
    let records = runtime.block_on(admin.list()).expect("records list");
    assert_eq!(records.len(), 2, "the previous and the unused new record");
    let unused_new = records
        .iter()
        .find(|record| record.device_id != previous)
        .expect("unused new record kept");
    assert!(
        unused_new.revoked_at.is_some(),
        "the protection failure revokes the unused new device"
    );
    let previous_record = runtime
        .block_on(store.get(previous))
        .expect("record reads")
        .expect("previous record kept");
    assert!(
        previous_record.revoked_at.is_none(),
        "the previous pairing stays usable"
    );
    assert!(
        !temporary.path().join("ledger.sqlite3").exists(),
        "the previous device was never ledger-touched"
    );
}

#[tokio::test]
async fn admin_success_uses_daemon_result_without_a_local_store() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let temporary = TempDir::new().expect("state root");
    let socket = admin_socket_path(temporary.path());
    fs::create_dir_all(socket.parent().unwrap()).unwrap();
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let device = odin_domain::huginn::DeviceId::new(uuid::Uuid::new_v4()).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).await.unwrap();
        let request: AdminRevokeRequest = serde_json::from_slice(&request).unwrap();
        assert_eq!(request.device_id, device);
        stream.write_all(br#"{"streamsClosed":2}"#).await.unwrap();
    });
    let report = revoke_device(temporary.path(), device).await.unwrap();
    server.await.unwrap();
    assert!(report.daemon);
    assert_eq!(report.streams_closed, 2);
    assert!(!temporary.path().join("huginn/devices.sqlite3").exists());
}

#[tokio::test]
async fn malformed_or_refused_admin_response_never_falls_back_to_local_revocation() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    for response in [
        "not-json",
        "",
        "{}",
        r#"{"streamsClosed":-1}"#,
        r#"{"refusal":{"code":"registryUnavailable","detail":"unavailable"}}"#,
        r#"{"streamsClosed":2,"refusal":{"code":"registryUnavailable","detail":"unavailable"}}"#,
    ] {
        let temporary = TempDir::new().expect("state root");
        let paired = pair_device(
            temporary.path(),
            "workstation",
            "00000000-0000-4000-8000-000000000009",
            false,
        )
        .await
        .unwrap();
        let device = odin_domain::huginn::DeviceId::parse(&paired.device_id).unwrap();
        let listener = tokio::net::UnixListener::bind(admin_socket_path(temporary.path())).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await.unwrap();
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let error = revoke_device(temporary.path(), device).await.unwrap_err();
        server.await.unwrap();
        assert!(error.contains("device admin"), "{response}: {error}");
        let store =
            SqliteDeviceTrustStore::open(temporary.path().join("huginn/devices.sqlite3")).unwrap();
        assert!(store
            .get(device)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_none());
        assert!(!temporary.path().join("ledger.sqlite3").exists());
    }
}

#[tokio::test]
async fn forced_pairing_retires_old_grants_after_installing_the_new_credential() {
    use odin_huginn::devices::{DeviceTrustStore as _, NewDeviceGrant};
    use odin_kernel::RevocationStore as _;

    let temporary = TempDir::new().unwrap();
    let state = temporary.path();
    let node = "00000000-0000-4000-8000-000000000009";
    let first = pair_device(state, "workstation", node, false)
        .await
        .unwrap();
    let previous = odin_domain::huginn::DeviceId::parse(&first.device_id).unwrap();
    let token = odin_domain::SeatTokenId::new("seat-token:1:old-device").unwrap();
    let store = SqliteDeviceTrustStore::open(state.join("huginn/devices.sqlite3")).unwrap();
    store
        .claim_grant(NewDeviceGrant {
            device_id: previous,
            session_id: odin_domain::SessionId::new("old-device-session").unwrap(),
            token_id: token.clone(),
            created_at: OffsetDateTime::now_utc(),
        })
        .await
        .unwrap();
    let replacement = pair_device(state, "workstation", node, true).await.unwrap();
    assert!(replacement.replaced_existing);
    let installed = fs::read_to_string(&replacement.credential_path).unwrap();
    let credential = odin_huginn::client::DeviceCredential::parse_base64url(&installed).unwrap();
    assert_eq!(
        credential.device_id().unwrap().to_string(),
        replacement.device_id
    );
    assert!(store
        .get(previous)
        .await
        .unwrap()
        .unwrap()
        .revoked_at
        .is_some());
    assert!(store
        .grant_snapshot(&token)
        .await
        .unwrap()
        .unwrap()
        .revoked_at
        .is_some());
    let ledger = Ledger::open(state.join("ledger.sqlite3")).unwrap();
    assert!(LedgerRevocations::new(&ledger).is_revoked(&token).unwrap());
}
