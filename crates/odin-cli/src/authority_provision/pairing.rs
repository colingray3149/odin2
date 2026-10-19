use std::ffi::OsStr;
use std::fs;
use std::future::Future;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use odin_huginn::auth::{SecretBytes, TailnetAuthenticator};
use odin_huginn::client::FileCredentialStore;
use odin_huginn::devices::{
    DeviceAdmin, DeviceGrant, DeviceTrustStore as _, LocalPairRequest, SqliteDeviceTrustStore,
};
use odin_huginn::dispatch::ConnectionRegistry;
use odin_huginn::private_network::VerifiedTailnetPeer;
use odin_huginn::DeviceCredentialStore as _;
use odin_kernel::{LedgerRevocations, RevocationStore as _};
use odin_ledger::Ledger;
use rustix::fs::AtFlags;
use serde::Serialize;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::admin_wire::{
    admin_socket_path, AdminRevokeRequest, AdminRevokeResponse, ADMIN_EXCHANGE_TIMEOUT,
    MAX_ADMIN_REQUEST_BYTES, MAX_ADMIN_RESPONSE_BYTES,
};
use super::private_fs::{
    open_private_dir, open_private_parent, reject_unprovisionable_root, stage_private_new,
    InstallOutcome, PrivateDir, StagedFile,
};

/// What one local pairing provisioned. Never carries the bearer secret.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicePairReport {
    pub device_id: String,
    pub tailnet_node_id: String,
    pub label: String,
    pub credential_path: PathBuf,
    pub replaced_existing: bool,
    /// Set when the credential was installed but the directory entry's
    /// durability could not be confirmed: the installed credential is valid
    /// and was kept in place — never rolled back or revoked — and this is
    /// the typed report of that condition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub durability_warning: Option<String>,
}

/// What `odin huginn devices revoke` did.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRevokeReport {
    pub device_id: String,
    pub revoked: bool,
    /// Live device streams the daemon cut for this revoke; a fallback
    /// revoke never touches sockets (the daemon's pump redrives those).
    pub streams_closed: usize,
    /// True when the running daemon executed the revoke over its admin
    /// socket. Skipped while false: the fallback wrote the store locally.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub daemon: bool,
}
/// Revokes one paired device. The running daemon is asked first over its
/// local admin socket (uid-gated loopback administration), so its live
/// connections are cut by the process that serves them; without a daemon
/// the same persisted begin → ledger revoke → finalized revoke ordering
/// runs against the authority's store directly, and the report truthfully
/// carries `daemon: false` and `streamsClosed: 0`. An unknown or already
/// revoked device is a typed refusal, never a silent success.
pub async fn revoke_device(
    state_root: &Path,
    device: odin_domain::huginn::DeviceId,
) -> Result<DeviceRevokeReport, String> {
    match dial_admin_revoke(&admin_socket_path(state_root), device).await? {
        AdminDial::Revoked(streams_closed) => Ok(DeviceRevokeReport {
            device_id: device.to_string(),
            revoked: true,
            streams_closed,
            daemon: true,
        }),
        AdminDial::NoDaemon => fallback_revoke_device(state_root, device).await,
    }
}

enum AdminDial {
    Revoked(usize),
    NoDaemon,
}

async fn dial_admin_revoke(
    socket_path: &Path,
    device: odin_domain::huginn::DeviceId,
) -> Result<AdminDial, String> {
    let stream = match tokio::net::UnixStream::connect(socket_path).await {
        Ok(stream) => stream,
        // A stale socket file or a daemon mid-restart is no daemon here.
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Ok(AdminDial::NoDaemon);
        }
        Err(error) => {
            return Err(format!(
                "device admin socket {} could not be dialed: {error}",
                socket_path.display()
            ));
        }
    };
    let request = serde_json::to_vec(&AdminRevokeRequest { device_id: device })
        .map_err(|error| format!("device admin request could not be encoded: {error}"))?;
    if request.len() > MAX_ADMIN_REQUEST_BYTES {
        return Err(format!(
            "device admin request exceeded {MAX_ADMIN_REQUEST_BYTES} bytes"
        ));
    }
    let socket = socket_path.display();
    let encoded = tokio::time::timeout(ADMIN_EXCHANGE_TIMEOUT, async {
        let (reader, mut writer) = stream.into_split();
        writer
            .write_all(&request)
            .await
            .map_err(|error| format!("device admin request was not delivered: {error}"))?;
        writer
            .shutdown()
            .await
            .map_err(|error| format!("device admin request was not delivered: {error}"))?;
        drop(writer);
        let mut buffer = Vec::with_capacity(256);
        let mut bounded = reader.take((MAX_ADMIN_RESPONSE_BYTES + 1) as u64);
        bounded
            .read_to_end(&mut buffer)
            .await
            .map_err(|error| format!("device admin response was not received: {error}"))?;
        Ok::<_, String>(buffer)
    })
    .await
    .map_err(|_| format!("device admin socket {socket} did not answer in time"))??;
    if encoded.len() > MAX_ADMIN_RESPONSE_BYTES {
        return Err(format!(
            "device admin response exceeded {MAX_ADMIN_RESPONSE_BYTES} bytes"
        ));
    }
    let response: AdminRevokeResponse = serde_json::from_slice(&encoded)
        .map_err(|error| format!("device admin response was not understood: {error}"))?;
    match (response.streams_closed, response.refusal) {
        (Some(streams_closed), None) => Ok(AdminDial::Revoked(streams_closed)),
        (None, Some(refusal)) => Err(format!(
            "device admin socket refused the revoke ({}): {}",
            refusal.code, refusal.detail
        )),
        _ => Err("device admin response named neither an outcome nor a refusal".to_owned()),
    }
}

/// The no-daemon path: the same persisted begin → ledger revoke →
/// finalized revoke ordering against the store, with a private registry
/// only because the admin type requires one — this process serves no
/// device streams, so the count is zero, and a daemon that is somehow
/// still serving closes them in its own pump.
async fn fallback_revoke_device(
    state_root: &Path,
    device: odin_domain::huginn::DeviceId,
) -> Result<DeviceRevokeReport, String> {
    let store_path = state_root.join("huginn").join("devices.sqlite3");
    if !store_path.is_file() {
        return Err(format!(
            "no device trust store at {}: devices are revoked on the authority, where they pair",
            store_path.display()
        ));
    }
    let store =
        Arc::new(SqliteDeviceTrustStore::open(&store_path).map_err(|error| error.to_string())?);
    let admin = DeviceAdmin::new(store, ConnectionRegistry::new());
    let streams_closed = admin
        .revoke_ledger_first(
            device,
            ledger_file_revoke_pass(state_root.join("ledger.sqlite3")),
        )
        .await
        .map_err(|error| format!("device {device} was not revoked: {error}"))?;
    Ok(DeviceRevokeReport {
        device_id: device.to_string(),
        revoked: true,
        streams_closed,
        daemon: false,
    })
}

/// One driven grant-batch revocation: what both ledger passes hand back,
/// awaited before the device record finalizes.
type LedgerRevokeFuture = Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;

/// The daemon-side ledger pass: revokes every granted token id over the
/// bridge ledger the token verifiers consult. Idempotent per token, so a
/// resumed revocation re-revokes harmlessly.
pub fn ledger_revoke_pass(
    ledger: Arc<Mutex<Ledger>>,
) -> impl FnOnce(Vec<DeviceGrant>) -> LedgerRevokeFuture {
    move |grants| {
        Box::pin(async move {
            let guard = ledger
                .lock()
                .map_err(|_| "revocation ledger lock is poisoned".to_owned())?;
            let mut revocations = LedgerRevocations::new(&guard);
            let now_ms = unix_ms(OffsetDateTime::now_utc());
            for grant in &grants {
                revocations
                    .revoke(&grant.token_id, now_ms)
                    .map_err(|error| {
                        format!(
                            "ledger revocation failed for seat token {}: {error}",
                            grant.token_id.as_str()
                        )
                    })?;
            }
            Ok(())
        })
    }
}

/// The fallback's ledger pass: opens the revocation ledger only when a
/// grant actually needs revoking, so a grant-free host gains no files.
pub fn ledger_file_revoke_pass(
    ledger_path: PathBuf,
) -> impl FnOnce(Vec<DeviceGrant>) -> LedgerRevokeFuture {
    move |grants| {
        Box::pin(async move {
            if grants.is_empty() {
                return Ok(());
            }
            let ledger = Ledger::open(&ledger_path).map_err(|error| {
                format!(
                    "could not open the revocation ledger at {}: {error}",
                    ledger_path.display()
                )
            })?;
            let mut revocations = LedgerRevocations::new(&ledger);
            let now_ms = unix_ms(OffsetDateTime::now_utc());
            for grant in &grants {
                revocations
                    .revoke(&grant.token_id, now_ms)
                    .map_err(|error| {
                        format!(
                            "ledger revocation failed for seat token {}: {error}",
                            grant.token_id.as_str()
                        )
                    })?;
            }
            Ok(())
        })
    }
}

/// One device-pump tick in odind: finish revocations a crash interrupted
/// (rows still revoking: grants ledger-revoked, record finalized, live
/// streams closed), then close any already-revoked device whose streams
/// this process still serves (a revoke that landed while the socket
/// handler was down). Idempotent; one failing device stays revoking,
/// fail-closed, and is redriven on the next tick.
pub async fn redrive_device_revocations(
    admin: &DeviceAdmin<SqliteDeviceTrustStore>,
    devices: &SqliteDeviceTrustStore,
    connections: &ConnectionRegistry,
    ledger: Arc<Mutex<Ledger>>,
) -> usize {
    let mut streams_closed = 0;
    match admin.pending_revokes().await {
        Ok(pending) => {
            for record in pending {
                match admin
                    .revoke_ledger_first(record.device_id, ledger_revoke_pass(Arc::clone(&ledger)))
                    .await
                {
                    Ok(closed) => {
                        if closed > 0 {
                            tracing::info!(
                                "device-revoke-resumed device={} streamsClosed={closed}",
                                record.device_id
                            );
                        }
                        streams_closed += closed;
                    }
                    Err(error) => tracing::error!(
                        "device-revoke-redrive-failed device={} error=\"{error}\"",
                        record.device_id
                    ),
                }
            }
        }
        Err(error) => tracing::error!("device-revoke-pending-list-failed error=\"{error}\""),
    }
    match devices.list().await {
        Ok(records) => {
            for record in records {
                if record.revoked_at.is_some() {
                    match connections.close_device(record.device_id) {
                        Ok(closed) => {
                            if closed > 0 {
                                tracing::info!(
                                    "revoked-device-streams-closed device={} streamsClosed={closed}",
                                    record.device_id
                                );
                            }
                            streams_closed += closed;
                        }
                        Err(error) => tracing::error!(
                            "revoked-device-stream-close-failed device={} error=\"{error}\"",
                            record.device_id
                        ),
                    }
                }
            }
        }
        Err(error) => tracing::error!("revoked-device-scan-failed error=\"{error}\""),
    }
    streams_closed
}

fn unix_ms(at: OffsetDateTime) -> u64 {
    let millis = at.unix_timestamp_nanos() / 1_000_000;
    u64::try_from(millis.max(0)).unwrap_or(0)
}

/// Opens this host's device trust store under private directories,
/// accepting nothing but one private regular sqlite file.
fn open_device_store(state_root: &Path) -> Result<(PathBuf, Arc<SqliteDeviceTrustStore>), String> {
    reject_unprovisionable_root(state_root, "runtime state root")?;
    open_private_dir(state_root, "runtime state root")?;
    let huginn_root = state_root.join("huginn");
    reject_unprovisionable_root(&huginn_root, "Huginn state root")?;
    open_private_dir(&huginn_root, "Huginn state root")?;
    let device_store_path = huginn_root.join("devices.sqlite3");
    match fs::symlink_metadata(&device_store_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.nlink() != 1 {
                return Err(format!(
                    "device trust store {} is not one private regular file",
                    device_store_path.display()
                ));
            }
            if metadata.permissions().mode() & 0o777 != 0o600 {
                fs::set_permissions(&device_store_path, fs::Permissions::from_mode(0o600))
                    .map_err(|error| {
                        format!(
                            "could not protect device trust store {}: {error}",
                            device_store_path.display()
                        )
                    })?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "could not inspect device trust store {}: {error}",
                device_store_path.display()
            ));
        }
    }
    let store = Arc::new(
        SqliteDeviceTrustStore::open(&device_store_path).map_err(|error| error.to_string())?,
    );
    Ok((huginn_root, store))
}

/// Enrolls one more device — a phone, a second laptop — beside this
/// workstation's own pairing: one new trust-store record whose credential is
/// written to `out` as a new 0600 file under a private directory. The
/// workstation's own credential slot is refused first, under any equivalent
/// spelling, so an enrollment can never install itself there; the
/// workstation's stored credential and every existing record are left
/// untouched (same-node and same-label records are fine), a failed write
/// restores the untouched slot and revokes only the unused new record, and
/// the bearer is never printed, logged, or returned.
pub async fn enroll_device(
    state_root: &Path,
    label: &str,
    tailnet_node_id: &str,
    out: &Path,
) -> Result<DevicePairReport, String> {
    if label.trim().is_empty() {
        return Err("pairing label must not be empty".to_owned());
    }
    let node_id = odin_domain::huginn::TailnetNodeId::parse(tailnet_node_id)
        .map_err(|error| format!("invalid tailnet node id {tailnet_node_id:?}: {error}"))?;
    let (huginn_root, store) = open_device_store(state_root)?;
    refuse_workstation_slot(out, &huginn_root)?;
    let admin = DeviceAdmin::new(store, ConnectionRegistry::new());
    admit_local_pair(
        &admin,
        &CredentialInstall::for_new(CredentialSlot::open(out)?),
        ledger_file_revoke_pass(state_root.join("ledger.sqlite3")),
        out,
        label,
        node_id,
        None,
    )
    .await
}

/// Reserves this workstation's own credential slot: an enrollment whose
/// destination is the slot — under any equivalent spelling, including a
/// symlinked or dot-resolved parent — is refused before a device is ever
/// admitted, so no other device can be installed into the file this
/// workstation's own pairing uses.
fn refuse_workstation_slot(out: &Path, huginn_root: &Path) -> Result<(), String> {
    if out.file_name() != Some(OsStr::new("device.credential")) {
        return Ok(());
    }
    let parent = match out.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    // The slot's directory always exists here; a parent that cannot be
    // resolved — because it does not exist — cannot be the slot's directory.
    let (Ok(resolved_parent), Ok(resolved_root)) =
        (fs::canonicalize(parent), fs::canonicalize(huginn_root))
    else {
        return Ok(());
    };
    if resolved_parent == resolved_root {
        return Err(format!(
            "refusing to enroll onto this workstation's own credential slot {}; enroll the device beside it under a new name",
            huginn_root.join("device.credential").display()
        ));
    }
    Ok(())
}

/// The retained descriptor of the directory that will hold one credential,
/// plus the credential's final plain name within it. Every operation below
/// resolves through the descriptor, never through the credential pathname.
struct CredentialSlot {
    directory: PrivateDir,
    name: String,
}

impl CredentialSlot {
    /// Opens the parent of `out` and keeps its descriptor: components are
    /// traversed or created no-follow, and ownership and privacy are
    /// validated on the descriptor (see `open_private_parent`).
    fn open(out: &Path) -> Result<Self, String> {
        let name = out
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| format!("{} is not a plain file name", out.display()))?
            .to_owned();
        Ok(Self {
            name,
            directory: open_private_parent(out)?,
        })
    }
}

/// One explicit credential-store transaction: `stage` puts the new
/// credential into the slot protected (exactly 0600) and durable on its own
/// descriptor without touching anything at the live credential name,
/// `commit` is the single atomic install step, and `restore` puts whatever
/// the slot held before the transaction back. A replacement whose install
/// lands reports success even when only the directory entry's durability is
/// uncertain — the installed credential is kept — so `restore` runs only
/// for pre-install failures, before the unused new device is revoked, and
/// the operator always keeps a usable pairing.
trait CredentialTransaction: Send + Sync {
    fn stage(&self, encoded: &SecretBytes) -> Result<(), String>;
    fn commit(&self) -> Result<CommitOutcome, String>;
    fn restore(&self) -> Result<(), String>;
}

/// The credential transaction over one `CredentialSlot`. An enrollment
/// commits with a no-clobber link (an occupied name is a typed refusal); a
/// workstation replacement commits by one atomic swap over the previous
/// credential. `previous` holds the slot's verified prior bytes — restored
/// through the same descriptor discipline on any failure — and absence
/// means an installed enrollment is removed again.
struct CredentialInstall {
    slot: CredentialSlot,
    no_clobber: bool,
    previous: Option<SecretBytes>,
    staged: Mutex<Option<StagedFile>>,
    installed: AtomicBool,
}

impl CredentialInstall {
    /// A transaction for a brand-new credential file: the slot must be
    /// empty and is restored to emptiness on any failure.
    fn for_new(slot: CredentialSlot) -> Self {
        Self {
            slot,
            no_clobber: true,
            previous: None,
            staged: Mutex::new(None),
            installed: AtomicBool::new(false),
        }
    }

    /// A transaction that replaces this workstation's stored credential;
    /// `previous` — the verified stored bytes, `None` for a fresh slot — is
    /// what a failure restores.
    fn for_replacement(slot: CredentialSlot, previous: Option<SecretBytes>) -> Self {
        Self {
            slot,
            no_clobber: false,
            previous,
            staged: Mutex::new(None),
            installed: AtomicBool::new(false),
        }
    }

    fn remove_installed(&self) -> Result<(), String> {
        match rustix::fs::unlinkat(&self.slot.directory.dir, &self.slot.name, AtFlags::empty()) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!(
                "could not remove the installed credential in {}: {error}",
                self.slot.directory.path.display()
            )),
        }
    }
}

impl CredentialTransaction for CredentialInstall {
    fn stage(&self, encoded: &SecretBytes) -> Result<(), String> {
        let mut staged = self.staged.lock().expect("credential stage lock");
        if staged.is_some() {
            return Err("the new credential is already staged".to_owned());
        }
        *staged = Some(stage_private_new(
            &self.slot.directory,
            OsStr::new(&self.slot.name),
            encoded.as_slice(),
        )?);
        Ok(())
    }

    fn commit(&self) -> Result<CommitOutcome, String> {
        let staged = self.staged.lock().expect("credential stage lock").take();
        let Some(staged) = staged else {
            return Err("the new credential was never staged".to_owned());
        };
        let outcome = if self.no_clobber {
            match staged.install_new(&self.slot.name)? {
                InstallOutcome::Occupied => {
                    return Err(format!(
                        "refusing to overwrite {}: it already exists; enroll to a new credential path",
                        self.slot.directory.path.join(&self.slot.name).display()
                    ));
                }
                InstallOutcome::Durable => CommitOutcome::Durable,
                InstallOutcome::DurabilityUncertain(warning) => {
                    CommitOutcome::DurabilityUncertain(warning)
                }
            }
        } else {
            match staged.install_replacing(&self.slot.name)? {
                InstallOutcome::Durable => CommitOutcome::Durable,
                InstallOutcome::DurabilityUncertain(warning) => {
                    CommitOutcome::DurabilityUncertain(warning)
                }
                InstallOutcome::Occupied => {
                    unreachable!("a replacement commit swaps over any occupant")
                }
            }
        };
        // The rename/link landed, so the credential occupies the slot: a
        // durability warning must never lead to a restore or revoke of it.
        self.installed.store(true, Ordering::Release);
        Ok(outcome)
    }

    fn restore(&self) -> Result<(), String> {
        if !self.installed.load(Ordering::Acquire) {
            // Nothing was ever installed: the slot is exactly as it was.
            return Ok(());
        }
        match &self.previous {
            Some(previous) => stage_private_new(
                &self.slot.directory,
                OsStr::new(&self.slot.name),
                previous.as_slice(),
            )?
            .install_replacing(&self.slot.name)
            .map(|_| ()),
            None => self.remove_installed(),
        }
    }
}

/// What one credential-store commit produced.
enum CommitOutcome {
    /// The credential is installed and its directory entry is durable.
    Durable,
    /// The credential is installed and valid — the file's own bytes were
    /// fsynced at stage time — but the directory entry's durability could
    /// not be confirmed. Kept in place and reported, never rolled back:
    /// the operator is never left without a credential, and the installed
    /// one is never revoked after it landed.
    DurabilityUncertain(String),
}

/// Pairs this loopback workstation through the real device trust store and
/// stores the credential where the shared Huginn client expects it.
///
/// The pairing is loopback-local by construction: it registers one device
/// record under this controller's own state root and writes the device
/// credential file with 0600 protection. Without a stored credential this is
/// a fresh local pair that never revokes anything. A stored credential is
/// replaced only by the explicit `--force` operator choice, and then only the
/// exact device that stored credential belongs to: its trust-store record and
/// credential digest must still match, the replacement credential is staged
/// protected and durable before one atomic commit and the old device is
/// retired only after it, a failed store restores the previous credential
/// before the unused new record is revoked, and a commit that lands but
/// cannot confirm the directory entry's durability keeps the installed
/// credential in place — never restored over or revoked — and reports the
/// condition in the report, so the operator always keeps a usable pairing.
/// Other devices —
/// including same-node or same-label clients — are never touched, and the
/// bearer secret is never displayed, logged, or returned.
pub async fn pair_device(
    state_root: &Path,
    label: &str,
    tailnet_node_id: &str,
    force: bool,
) -> Result<DevicePairReport, String> {
    if label.trim().is_empty() {
        return Err("pairing label must not be empty".to_owned());
    }
    let node_id = odin_domain::huginn::TailnetNodeId::parse(tailnet_node_id)
        .map_err(|error| format!("invalid tailnet node id {tailnet_node_id:?}: {error}"))?;
    let (huginn_root, store) = open_device_store(state_root)?;
    let credential_path = huginn_root.join("device.credential");
    let credentials = FileCredentialStore::open(&huginn_root).map_err(|error| error.to_string())?;
    let admin = DeviceAdmin::new(Arc::clone(&store), ConnectionRegistry::new());
    let authenticator = TailnetAuthenticator::new(store);
    let stored = credentials.load().map_err(|error| error.to_string())?;
    let (previous, previous_credential) = match stored {
        None => (None, None),
        Some(current) => {
            if !force {
                return Err(
                    "this workstation already stores a device credential; pair again with --force to revoke and replace it explicitly"
                        .to_owned(),
                );
            }
            let current_device = current.device_id().map_err(|error| {
                format!(
                    "the stored device credential has no valid device identity; review it before replacing anything: {error}"
                )
            })?;
            let raw = fs::read(&credential_path).map_err(|error| {
                format!(
                    "could not read stored device credential {} for local verification: {error}",
                    credential_path.display()
                )
            })?;
            // These verified bytes are what a failed replacement restores.
            let backup = SecretBytes::new(raw.clone());
            let encoded = SecretBytes::new(raw);
            let encoded_text = std::str::from_utf8(encoded.as_slice()).map_err(|error| {
                format!(
                    "the stored device credential {} is not valid UTF-8: {error}",
                    credential_path.display()
                )
            })?;
            let observed = odin_huginn::client::DeviceCredential::parse_base64url(encoded_text)
                .map_err(|error| {
                    format!(
                        "the stored device credential {} is malformed: {error}",
                        credential_path.display()
                    )
                })?;
            if observed != current {
                return Err(
                    "the stored device credential changed while it was being verified; review it before replacing anything"
                        .to_owned(),
                );
            }
            drop(observed);
            let verified = authenticator
                .authenticate(
                    VerifiedTailnetPeer::local(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        0,
                    ))),
                    encoded,
                )
                .await
                .map_err(|error| {
                    format!(
                        "the stored credential references device {current_device}, but no matching trust-store record could be verified; review the store before replacing anything: {error}"
                    )
                })?;
            if verified.device_id != current_device {
                return Err(format!(
                    "the stored credential changed while device {current_device} was being verified; review it before replacing anything"
                ));
            }
            (Some(verified.device_id), Some(backup))
        }
    };
    admit_local_pair(
        &admin,
        &CredentialInstall::for_replacement(
            CredentialSlot::open(&credential_path)?,
            previous_credential,
        ),
        ledger_file_revoke_pass(state_root.join("ledger.sqlite3")),
        &credential_path,
        label,
        node_id,
        previous,
    )
    .await
}

/// Registers one new local device, installs its credential through the
/// explicit store transaction, and only then retires the previous local
/// device, if any.
///
/// Ordering is the operator-safety contract: the replacement credential is
/// staged before atomic install; the previous device's session grants are
/// ledger-revoked only after installation. A post-install durability warning
/// keeps the installed credential; pre-install failures restore the old slot
/// before revoking the unused new device.
async fn admit_local_pair(
    admin: &DeviceAdmin<SqliteDeviceTrustStore>,
    store_new: &dyn CredentialTransaction,
    ledger_revoke: impl FnOnce(Vec<DeviceGrant>) -> LedgerRevokeFuture + Send,
    credential_path: &Path,
    label: &str,
    node_id: odin_domain::huginn::TailnetNodeId,
    previous: Option<odin_domain::huginn::DeviceId>,
) -> Result<DevicePairReport, String> {
    let tailnet_node_id = node_id.to_string();
    let bundle = admin
        .pair_local(LocalPairRequest {
            label: label.to_owned(),
            tailnet_node_id: node_id,
        })
        .await
        .map_err(|error| error.to_string())?;
    let encoded = SecretBytes::new(bundle.credential().encode().into_bytes());
    let store_result = store_new.stage(&encoded).and_then(|()| store_new.commit());
    drop(encoded);
    let durability_warning = match store_result {
        Ok(CommitOutcome::Durable) => None,
        Ok(CommitOutcome::DurabilityUncertain(warning)) => Some(warning),
        Err(error) => {
            // Pre-install failure: nothing valid was installed, so restoring
            // what the slot held is the remaining legitimate path — run
            // before the unused new device is revoked.
            let restored = store_new.restore();
            let restore_outcome = match &restored {
                Ok(()) => " the previous credential was restored;".to_owned(),
                Err(restore_error) => {
                    format!(" the previous credential could not be restored: {restore_error};")
                }
            };
            let safety = if restored.is_ok() {
                "every earlier pairing remains usable"
            } else {
                "the credential slot and the trust store need review before anything pairs again"
            };
            return match admin.revoke(bundle.device_id()).await {
                Ok(()) => Err(format!(
                    "could not store and protect the new device credential: {error};{restore_outcome} the unused new device {} was revoked and {safety}",
                    bundle.device_id()
                )),
                Err(cleanup_error) => Err(format!(
                    "could not store and protect the new device credential: {error};{restore_outcome} could not revoke the unused new device {}: {cleanup_error}; {safety}",
                    bundle.device_id()
                )),
            };
        }
    };
    if let Some(previous) = previous {
        admin
            .revoke_ledger_first(previous, ledger_revoke)
            .await
            .map_err(|error| error.to_string())?;
    }
    Ok(DevicePairReport {
        device_id: bundle.device_id().to_string(),
        tailnet_node_id,
        label: label.to_owned(),
        credential_path: credential_path.to_path_buf(),
        replaced_existing: previous.is_some(),
        durability_warning,
    })
}

#[cfg(test)]
#[path = "pairing_tests.rs"]
mod tests;
