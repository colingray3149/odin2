//! The local device-admin socket: odind's loopback administration
//! endpoint for device revocation. Every accepted stream must prove the
//! daemon's own uid (SO_PEERCRED); requests are one bounded JSON revoke of
//! a `DeviceId`, executed with the same persisted begin → ledger revoke →
//! finalized revoke → live close ordering the CLI fallback uses, but
//! against the live connection registry so the revoked device's streams
//! close in this process. No tailnet endpoint exists: a paired device can
//! never reach or name revocations, and nothing on the Huginn wire is
//! trusted here.
//! Oversized requests receive a refusal before their remaining bytes are
//! discarded with bounded memory and time. The response write half closes
//! first, so a client need not finish sending to observe the refusal.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use odin_cli::authority_provision::{
    ledger_revoke_pass, AdminRevokeRequest, AdminRevokeResponse, ADMIN_EXCHANGE_TIMEOUT,
    MAX_ADMIN_REQUEST_BYTES,
};
use odin_huginn::auth::AuthError;
use odin_huginn::devices::{DeviceAdmin, SqliteDeviceTrustStore};
use odin_ledger::Ledger;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinSet;

pub(crate) struct DeviceAdminHandle {
    pub(crate) admin: DeviceAdmin<SqliteDeviceTrustStore>,
    pub(crate) ledger: Arc<Mutex<Ledger>>,
}

/// Reclaim stale socket paths only after a failed connection probe.
pub(crate) struct DeviceAdminListener {
    listener: UnixListener,
    path: PathBuf,
}

pub(crate) fn bind_device_admin_socket(socket_path: &Path) -> Result<DeviceAdminListener, String> {
    let bind_failed = |error: std::io::Error| {
        format!(
            "device admin socket {} could not be bound: {error}",
            socket_path.display()
        )
    };
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).map_err(bind_failed)?;
        set_mode(parent, 0o700).map_err(bind_failed)?;
    }
    if socket_path.exists() {
        // A local unix connect answers instantly: success means a live
        // daemon still owns the path; refusal or absence means a stale
        // file from a crashed daemon, which this bind reclaims.
        match std::os::unix::net::UnixStream::connect(socket_path) {
            Ok(_) => {
                return Err(format!(
                    "device admin socket {} is already served by a running daemon",
                    socket_path.display()
                ));
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) => {}
            Err(error) => return Err(bind_failed(error)),
        }
        std::fs::remove_file(socket_path).map_err(bind_failed)?;
    }
    let listener = UnixListener::bind(socket_path).map_err(bind_failed)?;
    set_mode(socket_path, 0o600).map_err(bind_failed)?;
    Ok(DeviceAdminListener {
        listener,
        path: socket_path.to_path_buf(),
    })
}

fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// Arms the accept loop into the daemon's shared pump set: the owning
/// shutdown aborts it like every other pump, and per-connection work runs
/// inline under exchange timeouts, so an abort never orphans a task. A
/// connection aborted mid-ledger-pass leaves the device revoking,
/// fail-closed; the pump redrives it after restart.
pub(crate) fn arm_device_admin_socket(
    pumps: &mut JoinSet<Result<(), String>>,
    listener: DeviceAdminListener,
    handle: DeviceAdminHandle,
) {
    let DeviceAdminListener { listener, path } = listener;
    pumps.spawn(async move {
        tracing::info!("device-admin-listening path={}", path.display());
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    if let Err(error) = serve_admin_connection(stream, &handle).await {
                        tracing::error!("device-admin-request-refused error=\"{error}\"");
                    }
                }
                Err(error) => {
                    tracing::error!("device-admin-accept-failed error=\"{error}\"");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    });
}

async fn serve_admin_connection(
    stream: UnixStream,
    handle: &DeviceAdminHandle,
) -> Result<(), String> {
    let mut stream = stream;
    let outcome = admin_outcome(&mut stream, handle).await;
    let response = match &outcome {
        Ok(streams_closed) => AdminRevokeResponse::revoked(*streams_closed),
        Err((code, detail)) => AdminRevokeResponse::refused(code, detail.clone()),
    };
    let oversized = matches!(&outcome, Err(("requestTooLarge", _)));
    respond(&mut stream, &response, oversized).await;
    outcome
        .map(|_| ())
        .map_err(|(code, detail)| format!("device admin revoke refused ({code}): {detail}"))
}

/// One bounded exchange: the peer-cred gate, the request read, and the
/// revoke execution.
async fn admin_outcome(
    stream: &mut UnixStream,
    handle: &DeviceAdminHandle,
) -> Result<usize, (&'static str, String)> {
    let peer = peer_uid(stream).map_err(|error| ("peerUid", error.to_string()))?;
    if !admin_peer_accepted(peer, daemon_euid()) {
        return Err((
            "peerUid",
            "requesting uid does not match the daemon's".to_owned(),
        ));
    }
    let request = read_admin_request(stream).await?;
    match handle
        .admin
        .revoke_ledger_first(
            request.device_id,
            ledger_revoke_pass(Arc::clone(&handle.ledger)),
        )
        .await
    {
        Ok(streams_closed) => {
            tracing::info!(
                "device-revoked device={} streamsClosed={streams_closed}",
                request.device_id
            );
            Ok(streams_closed)
        }
        Err(error) => Err(refusal_of(&error)),
    }
}

fn refusal_of(error: &AuthError) -> (&'static str, String) {
    match error {
        AuthError::UnknownDevice(_) => ("unknownDevice", error.to_string()),
        AuthError::LedgerRevoke { .. } => ("ledgerRevoke", error.to_string()),
        AuthError::Registry(_) => ("registry", error.to_string()),
        _ => ("refused", error.to_string()),
    }
}

async fn read_admin_request(
    stream: &mut UnixStream,
) -> Result<AdminRevokeRequest, (&'static str, String)> {
    let mut buffer = Vec::with_capacity(128);
    let mut bounded = (&mut *stream).take((MAX_ADMIN_REQUEST_BYTES + 1) as u64);
    match tokio::time::timeout(ADMIN_EXCHANGE_TIMEOUT, bounded.read_to_end(&mut buffer)).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => {
            return Err((
                "malformedRequest",
                format!("request could not be read: {error}"),
            ));
        }
        Err(_) => {
            return Err(("timedOut", "request was not completed in time".to_owned()));
        }
    }
    if buffer.len() > MAX_ADMIN_REQUEST_BYTES {
        return Err((
            "requestTooLarge",
            format!("request exceeds {MAX_ADMIN_REQUEST_BYTES} bytes"),
        ));
    }
    serde_json::from_slice(&buffer).map_err(|error| {
        (
            "malformedRequest",
            format!("request was not understood: {error}"),
        )
    })
}

async fn respond(stream: &mut UnixStream, response: &AdminRevokeResponse, drain_request: bool) {
    let encoded = match serde_json::to_vec(response) {
        Ok(encoded) => encoded,
        Err(error) => {
            tracing::error!("device-admin-response-encode-failed error=\"{error}\"");
            return;
        }
    };
    let exchange = async {
        stream.write_all(&encoded).await?;
        stream.shutdown().await?;
        if drain_request {
            // Closing a Unix socket with unread input can reset the peer even
            // after sending its refusal. Discard the excess without retaining
            // it or letting an endless sender occupy the accept loop forever.
            // Writing, half-closing, and draining share one deadline below;
            // receiving more bytes never resets that deadline.
            let mut discarded = [0_u8; 1024];
            while stream.read(&mut discarded).await? != 0 {}
        }
        Ok::<(), std::io::Error>(())
    };
    match tokio::time::timeout(ADMIN_EXCHANGE_TIMEOUT, exchange).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            tracing::error!("device-admin-response-failed error=\"{error}\"");
        }
        Err(error) => {
            tracing::error!("device-admin-response-timed-out error=\"{error}\"");
        }
    }
}

fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    let credentials =
        rustix::net::sockopt::socket_peercred(stream).map_err(std::io::Error::from)?;
    Ok(credentials.uid.as_raw())
}

fn daemon_euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

pub(crate) fn admin_peer_accepted(peer_uid: u32, daemon_euid: u32) -> bool {
    peer_uid == daemon_euid
}
