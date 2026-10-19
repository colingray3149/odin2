//! The device-bound session authority: an authenticated open mints or
//! reuses the seat token where the signing key lives, claims the device's
//! grant over that exact token identity, and only then admits the open.
//! The whole ensure→claim→open sequence is serialized per session — a
//! second device can never interleave between a fresh mint and its claim —
//! and every open is a tracked operation of this authority: the asking
//! connection may go away mid-open, but the operation finishes its own
//! rollback, and the owning shutdown closes admission, cancels, and joins
//! the tracked set against one cooperative deadline with explicit failure.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use odin_cli::authority_provision::{
    compose, ensure_session_token, remove_session_token_if_owned, LaunchSelection,
    SessionComposition, TokenRenewalPolicy, DEFAULT_TOKEN_TTL_SECONDS,
};
use odin_domain::huginn::{
    DeviceId, LiveError, LiveSessionSummary, OmpLivePlane, OpenSessionRequest,
};
use odin_domain::SeatTokenId;
use odin_huginn::devices::{DeviceStoreError, GrantClaim, NewDeviceGrant, SqliteDeviceTrustStore};
use odin_kernel::{LedgerRevocations, RevocationStore as _};
use odin_ledger::Ledger;
use parking_lot::Mutex;
use time::OffsetDateTime;
use tokio::task::JoinSet;

/// The seat authority for the session could not be provisioned — the same
/// surface a missing seat token reports at dispatch.
const AUTHORITY_UNAVAILABLE: &str = "published_operation_authority:seat_token";

#[derive(Clone)]
pub(super) struct DeviceOpenAuthority {
    config: odin_huginn::config::OdindConfig,
    devices: Arc<SqliteDeviceTrustStore>,
    ledger: Arc<StdMutex<Ledger>>,
    live: Arc<dyn OmpLivePlane>,
    /// One gate per token-bound session, so ensure→claim→open is atomic per
    /// session within this daemon: no concurrent open can reuse a token
    /// between its fresh mint and its claim.
    sessions: Arc<Mutex<BTreeMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    /// The tracked set of in-flight opens. The authority owns every
    /// operation it starts; nothing it spawns is detached.
    tasks: Arc<tokio::sync::Mutex<JoinSet<()>>>,
    /// The admission gate: once closed, new device opens refuse typed while
    /// the tracked set is cancelled and joined.
    admitting: Arc<Mutex<bool>>,
    cleanup_failed: Arc<AtomicBool>,
    stopping: Arc<tokio::sync::watch::Sender<bool>>,
}

impl DeviceOpenAuthority {
    pub(super) fn new(
        config: odin_huginn::config::OdindConfig,
        devices: Arc<SqliteDeviceTrustStore>,
        ledger: Arc<StdMutex<Ledger>>,
        live: Arc<dyn OmpLivePlane>,
    ) -> Self {
        Self {
            config,
            devices,
            ledger,
            live,
            sessions: Arc::new(Mutex::new(BTreeMap::new())),
            tasks: Arc::new(tokio::sync::Mutex::new(JoinSet::new())),
            admitting: Arc::new(Mutex::new(true)),
            cleanup_failed: Arc::new(AtomicBool::new(false)),
            stopping: Arc::new(tokio::sync::watch::channel(false).0),
        }
    }

    /// The authenticated device open. The device always rides the argument —
    /// it is the socket's authenticated identity, never a request field.
    pub(super) async fn open_session_for_device(
        &self,
        device: DeviceId,
        request: OpenSessionRequest,
    ) -> Result<LiveSessionSummary, LiveError> {
        if !*self.admitting.lock() {
            return Err(LiveError::Unavailable {
                code: "deviceOpenStopping".to_owned(),
            });
        }
        let composition = compose(
            &self.config,
            request.seat_id.as_str(),
            request.project_id.as_str(),
            &request.command_id,
            LaunchSelection::new(request.provider.as_str(), request.model.as_str()),
        )
        .map_err(|error| {
            tracing::error!(
                "device open composition refused device={device} command={} error=\"{error}\"",
                request.command_id
            );
            LiveError::Unavailable {
                code: AUTHORITY_UNAVAILABLE.to_owned(),
            }
        })?;
        let answer = {
            let mut tasks = self.tasks.lock().await;
            // Hold admission through registration so close() cannot return before a racing
            // opener has either been rejected or entered the tracked rollback set.
            let admitting = self.admitting.lock();
            if !*admitting {
                return Err(LiveError::Unavailable {
                    code: "deviceOpenStopping".to_owned(),
                });
            }
            while let Some(result) = tasks.try_join_next() {
                if result.is_err() {
                    self.cleanup_failed.store(true, Ordering::Release);
                }
            }
            let gate = SessionGateGuard {
                sessions: Arc::clone(&self.sessions),
                key: composition.session.as_str().to_owned(),
                gate: self.session_gate(composition.session.as_str()),
            };
            let authority = self.clone();
            let (reply, answer) = tokio::sync::oneshot::channel();
            tasks.spawn(async move {
                let _held = gate.gate.lock().await;
                let opened = authority.open_owned(device, request, &composition).await;
                drop(_held);
                drop(gate);
                if reply.send(opened).is_err() {
                    // The asking connection went away; the operation above still
                    // finished its own rollback before answering.
                    tracing::error!("device open answer dropped device={device}");
                }
            });
            answer
        };
        match answer.await {
            Ok(opened) => opened,
            Err(_) => Err(LiveError::Unavailable {
                code: "deviceOpenTask".to_owned(),
            }),
        }
    }

    /// Shares ownership of admission and tracked rollback with the daemon shutdown.
    pub(super) fn stop_handle(&self) -> DeviceOpenStop {
        DeviceOpenStop {
            tasks: Arc::clone(&self.tasks),
            admitting: Arc::clone(&self.admitting),
            cleanup_failed: Arc::clone(&self.cleanup_failed),
            stopping: Arc::clone(&self.stopping),
        }
    }

    async fn open_owned(
        &self,
        device: DeviceId,
        mut request: OpenSessionRequest,
        composition: &SessionComposition,
    ) -> Result<LiveSessionSummary, LiveError> {
        if *self.stopping.borrow() {
            return Err(LiveError::Unavailable {
                code: "deviceOpenStopping".to_owned(),
            });
        }
        let report = ensure_session_token(
            &self.config,
            composition,
            DEFAULT_TOKEN_TTL_SECONDS,
            TokenRenewalPolicy::OperatorOnly,
        )
        .map_err(|error| {
            tracing::error!(
                "device open authority refused device={device} session={} error=\"{error}\"",
                composition.live_session
            );
            LiveError::Unavailable {
                code: AUTHORITY_UNAVAILABLE.to_owned(),
            }
        })?;
        // OperatorOnly re-issues never happen, so a non-reuse report is a
        // file this call minted and this call owns on every exit path.
        let fresh = !report.reused_existing;
        let token_id = SeatTokenId::parse(&report.token_id).map_err(|error| {
            tracing::error!(
                "device open token id refused device={device} token={} error={error}",
                report.token_id
            );
            LiveError::Unavailable {
                code: AUTHORITY_UNAVAILABLE.to_owned(),
            }
        })?;
        let mut mint = fresh.then(|| FreshMintGuard {
            ledger: Arc::clone(&self.ledger),
            devices: Arc::clone(&self.devices),
            cleanup_failed: Arc::clone(&self.cleanup_failed),
            claim_owned: false,
            token_id: token_id.clone(),
            token_path: report.token_path.clone(),
            device,
            armed: true,
        });
        // Claim synchronously: dropping an async spawn_blocking waiter can
        // lose its committed outcome before the rollback guard owns it.
        let claim = self
            .devices
            .claim_grant_sync(NewDeviceGrant {
                device_id: device,
                session_id: composition.session.clone(),
                token_id: token_id.clone(),
                created_at: OffsetDateTime::now_utc(),
            })
            .map_err(|error| {
                tracing::error!(
                    "device open claim failed device={device} session={} error=\"{error}\"",
                    composition.live_session
                );
                store_unavailable(&error)
            })?;
        if let Some(guard) = mint.as_mut() {
            guard.claim_owned = matches!(claim, GrantClaim::Claimed);
        }
        let mut reused_claim =
            (mint.is_none() && matches!(claim, GrantClaim::Claimed)).then(|| ReusedClaimGuard {
                devices: Arc::clone(&self.devices),
                cleanup_failed: Arc::clone(&self.cleanup_failed),
                token_id: token_id.clone(),
                session: composition.session.clone(),
                device,
                armed: true,
            });
        let opened = match claim {
            GrantClaim::Claimed | GrantClaim::Held => {
                // The token just ensured is the generation the supervisor
                // must see; the caller's value is never trusted.
                request.served_revision = report.served_revision;
                let (opened, retain_authority) = self
                    .live
                    .open_session_owned(request, self.stopping.subscribe())
                    .await;
                if retain_authority {
                    // A committed actor or unproven launch cleanup must
                    // remain device-owned for later ledger-first revoke.
                    if let Some(guard) = mint.as_mut() {
                        guard.disarm();
                    }
                    if let Some(guard) = reused_claim.as_mut() {
                        guard.armed = false;
                    }
                }
                if matches!(&opened, Err(LiveError::Unavailable { code }) if code == "open_launcher_join_failed")
                {
                    self.cleanup_failed.store(true, Ordering::Release);
                }
                opened
            }
            GrantClaim::Foreign => {
                tracing::error!(
                    "device open authority foreign device={device} session={} token={}",
                    composition.live_session,
                    report.token_id
                );
                Err(LiveError::Unauthorized)
            }
            GrantClaim::Inactive => {
                tracing::error!(
                    "device open device inactive device={device} session={}",
                    composition.live_session
                );
                Err(LiveError::DeviceRevoked)
            }
        };
        match opened {
            Ok(summary) => {
                if let Some(guard) = mint.as_mut() {
                    guard.disarm();
                }
                if let Some(guard) = reused_claim.as_mut() {
                    guard.armed = false;
                }
                tracing::info!(
                    "device open accepted device={device} session={} token={} reused={}",
                    summary.session_id,
                    report.token_id,
                    report.reused_existing
                );
                Ok(summary)
            }
            Err(error) => {
                if let Some(guard) = mint.as_mut() {
                    // Fresh authority owns synchronous ledger-first cleanup,
                    // including cancellation while the backend is pending.
                    if guard.armed {
                        guard.roll_back();
                    }
                }
                Err(error)
            }
        }
    }

    fn session_gate(&self, session: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.sessions
            .lock()
            .entry(session.to_owned())
            .or_default()
            .clone()
    }
}

/// Retires the map entry on success, refusal, or task cancellation. The
/// map lock makes the strong-count decision atomic with new gate lookup.
struct SessionGateGuard {
    sessions: Arc<Mutex<BTreeMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    key: String,
    gate: Arc<tokio::sync::Mutex<()>>,
}

impl Drop for SessionGateGuard {
    fn drop(&mut self) {
        let mut sessions = self.sessions.lock();
        if Arc::strong_count(&self.gate) == 2 {
            sessions.remove(&self.key);
        }
    }
}

/// Tracks one token this call minted. Every exit path — explicit failure,
/// task abort, or drop — ledger-revokes it, and removes only the file whose
/// bytes still carry this exact token id, so a concurrently renewed file
/// for the same session is never destroyed.
struct FreshMintGuard {
    ledger: Arc<StdMutex<Ledger>>,
    devices: Arc<SqliteDeviceTrustStore>,
    cleanup_failed: Arc<AtomicBool>,
    claim_owned: bool,
    token_id: SeatTokenId,
    token_path: PathBuf,
    device: DeviceId,
    armed: bool,
}

impl FreshMintGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }

    /// Ledger-revokes the minted token, then removes its file: the open
    /// never happened, so no bounded authority survives it. The ledger is
    /// the kill switch; the file is only the minted artifact.
    fn roll_back(&mut self) -> bool {
        let revoked = revoke_token_in_ledger(&self.ledger, &self.token_id, self.device);
        if revoked {
            if self.claim_owned {
                match self.devices.release_grant_sync(
                    &self.token_id,
                    self.device,
                    OffsetDateTime::now_utc(),
                ) {
                    Ok(_) => self.claim_owned = false,
                    Err(error) => {
                        tracing::error!(
                            "fresh rollback grant release failed token={} error=\"{error}\"",
                            self.token_id.as_str()
                        );
                        return false;
                    }
                }
            }
            if !self.remove_owned_file() {
                return false;
            }
            self.disarm();
        }
        revoked
    }

    /// Removes the minted file only while it still holds THIS token id: a
    /// replacement minted concurrently for the same session is preserved.
    fn remove_owned_file(&self) -> bool {
        if let Err(error) = remove_session_token_if_owned(&self.token_path, &self.token_id) {
            tracing::error!(
                "device open rollback cleanup failed path={} error=\"{error}\"",
                self.token_path.display()
            );
            return false;
        }
        true
    }
}

impl Drop for FreshMintGuard {
    fn drop(&mut self) {
        if self.armed && !self.roll_back() {
            self.cleanup_failed.store(true, Ordering::Release);
            tracing::error!(
                "device open rollback stays with the revoke pass device={} token={}",
                self.device,
                self.token_id.as_str()
            );
        }
    }
}

fn revoke_token_in_ledger(
    ledger: &StdMutex<Ledger>,
    token_id: &SeatTokenId,
    device: DeviceId,
) -> bool {
    let revoked = match ledger.lock() {
        Ok(ledger) => {
            LedgerRevocations::new(&ledger).revoke(token_id, unix_ms(OffsetDateTime::now_utc()))
        }
        Err(_) => {
            tracing::error!(
                "device open rollback refused device={device} token={} error=\"revocation ledger lock is poisoned\"",
                token_id.as_str()
            );
            return false;
        }
    };
    match revoked {
        Ok(()) => true,
        Err(error) => {
            tracing::error!(
                "device open rollback refused device={device} token={} error={error}",
                token_id.as_str()
            );
            false
        }
    }
}

fn store_unavailable(error: &DeviceStoreError) -> LiveError {
    tracing::error!("device grant store failed error=\"{error}\"");
    LiveError::Unavailable {
        code: "deviceGrantStore".to_owned(),
    }
}

fn unix_ms(at: OffsetDateTime) -> u64 {
    let millis = at.unix_timestamp_nanos() / 1_000_000;
    u64::try_from(millis.max(0)).unwrap_or(0)
}

#[cfg(test)]
#[path = "tests/device_open.rs"]
mod tests;

/// A reused token is never revoked by a refused/cancelled open, but a
/// newly acquired claim still belongs to that open until it succeeds.
struct ReusedClaimGuard {
    devices: Arc<SqliteDeviceTrustStore>,
    cleanup_failed: Arc<AtomicBool>,
    token_id: SeatTokenId,
    session: odin_domain::SessionId,
    device: DeviceId,
    armed: bool,
}

impl Drop for ReusedClaimGuard {
    fn drop(&mut self) {
        if self.armed {
            if let Err(error) =
                self.devices
                    .relinquish_grant_sync(&self.token_id, self.device, &self.session)
            {
                self.cleanup_failed.store(true, Ordering::Release);
                tracing::error!(
                    "reused claim release failed token={} error=\"{error}\"",
                    self.token_id.as_str()
                );
            }
        }
    }
}

/// The serving owner's device admission and rollback drain, without the live plane.
/// Closing is synchronous; joining never aborts a task whose rollback may be uninterruptible.
#[derive(Clone)]
pub(super) struct DeviceOpenStop {
    tasks: Arc<tokio::sync::Mutex<JoinSet<()>>>,
    admitting: Arc<Mutex<bool>>,
    cleanup_failed: Arc<AtomicBool>,
    stopping: Arc<tokio::sync::watch::Sender<bool>>,
}

impl DeviceOpenStop {
    pub(super) fn close(&self) {
        *self.admitting.lock() = false;
        self.stopping.send_replace(true);
    }

    /// The absolute budget includes mutex acquisition, joins, and synchronous rollback.
    /// A timeout cannot preempt ledger/filesystem work: elapsed cleanup is incomplete too.
    pub(super) async fn stop_until(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), DeviceOpenStopIncomplete> {
        self.close();
        let joined = tokio::time::timeout_at(deadline, async {
            let mut tasks = self.tasks.lock().await;
            while let Some(result) = tasks.join_next().await {
                if result.is_err() {
                    self.cleanup_failed.store(true, Ordering::Release);
                }
            }
        })
        .await;
        if joined.is_ok()
            && !self.cleanup_failed.load(Ordering::Acquire)
            && tokio::time::Instant::now() <= deadline
        {
            Ok(())
        } else {
            // Retain task owners and authority; aborting the outer task could detach descendants.
            Err(DeviceOpenStopIncomplete)
        }
    }

    #[cfg(test)]
    pub(super) fn test_owner(tasks: JoinSet<()>) -> (Self, tokio::sync::watch::Receiver<bool>) {
        let (stopping, witness) = tokio::sync::watch::channel(false);
        (
            Self {
                tasks: Arc::new(tokio::sync::Mutex::new(tasks)),
                admitting: Arc::new(Mutex::new(true)),
                cleanup_failed: Arc::new(AtomicBool::new(false)),
                stopping: Arc::new(stopping),
            },
            witness,
        )
    }
}

#[derive(Debug)]
pub(super) struct DeviceOpenStopIncomplete;

impl std::fmt::Display for DeviceOpenStopIncomplete {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("device open shutdown incomplete: deadline, task, or rollback failure; authority not retired")
    }
}

#[cfg(test)]
mod stop_owner_tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn close_is_synchronous_even_while_task_ownership_is_locked() {
        let (stop, witness) = DeviceOpenStop::test_owner(JoinSet::new());
        let tasks = stop.tasks.lock().await;
        stop.close();
        assert!(!*stop.admitting.lock());
        assert!(*witness.borrow());
        let deadline = tokio::time::Instant::now();
        assert!(stop.stop_until(deadline).await.is_err());
        assert!(tasks.is_empty());
        drop(tasks);
    }

    #[tokio::test]
    async fn failed_rollback_remains_incomplete_after_all_tasks_join() {
        let (stop, _) = DeviceOpenStop::test_owner(JoinSet::new());
        stop.cleanup_failed.store(true, Ordering::Release);
        assert!(stop
            .stop_until(tokio::time::Instant::now() + std::time::Duration::from_secs(1))
            .await
            .is_err());
        assert!(!*stop.admitting.lock());
    }
}
