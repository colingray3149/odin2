//! Generation and lifecycle ownership: the exclusive session lease with
//! its heartbeat, and the bounded parent-stop hook for delegated
//! children.

use super::*;

/// Lease object kind the bridge claims for its session.
pub const LEASE_OBJECT_KIND: &str = "odin_omp_session";

/// Process-local entropy for lease ids minted before the bridge exists;
/// keeps same-millisecond acquisitions distinct.
static LEASE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(super) async fn release_lease_record(
    ledger: &Arc<Mutex<Ledger>>,
    record: &LeaseRecord,
) -> Result<(), BridgeError> {
    let ledger = Arc::clone(ledger);
    let lease_id = record.lease_id.clone();
    let owner = record.owner_id.clone();
    let revision = record.revision;
    tokio::task::spawn_blocking(move || -> Result<(), BridgeError> {
        let guard = ledger.lock().map_err(|_| {
            BridgeError::Ledger(LedgerError::invalid_data(
                "ledger mutex poisoned".to_owned(),
            ))
        })?;
        let now = now_utc();
        lease::release_lease(
            guard.connection(),
            &lease_id,
            &owner,
            revision,
            now,
            unix_ms(now),
        )
        .map_err(map_lease_error)?;
        Ok(())
    })
    .await
    .map_err(|error| BridgeError::Serialization {
        detail: format!("lease release task failed: {error}"),
    })?
}

/// Updates only the matching epoch, idempotently for the same exit; `ended` is immutable.
/// Accepts the ledger directly so failed startup can finish before `Shared` exists.
pub(super) async fn finish_live_row_at(
    ledger: &Arc<Mutex<Ledger>>,
    session_id: SessionId,
    epoch: i64,
    exit: LiveSessionExit,
) -> Result<(), BridgeError> {
    let ledger = Arc::clone(ledger);
    tokio::task::spawn_blocking(move || -> Result<(), BridgeError> {
        let mut guard = ledger.lock().map_err(|_| {
            BridgeError::Ledger(LedgerError::invalid_data(
                "ledger mutex poisoned".to_owned(),
            ))
        })?;
        guard.finish_live_session(&session_id, epoch, exit, now_utc())?;
        Ok(())
    })
    .await
    .map_err(|error| BridgeError::Serialization {
        detail: format!("live-session finish task failed: {error}"),
    })?
}

// Release the lease and failed live row so an unsuccessful launch cannot appear ready.
pub(super) async fn settle_failed_start(
    ledger: &Arc<Mutex<Ledger>>,
    lease: &LeaseRecord,
    live: &LiveSession,
    primary: BridgeError,
) -> BridgeError {
    let retired = finish_live_row_at(
        ledger,
        live.session_id.clone(),
        live.epoch,
        LiveSessionExit::Failed,
    )
    .await;
    let cleanup = match (retired, release_lease_record(ledger, lease).await) {
        (Ok(()), Ok(())) => None,
        (Err(retired), Ok(())) => Some(retired),
        (Ok(()), Err(released)) => Some(released),
        (Err(retired), Err(released)) => Some(BridgeError::StartupSettlement {
            primary: Box::new(retired),
            cleanup: Box::new(released),
        }),
    };
    match cleanup {
        None => primary,
        Some(cleanup) => BridgeError::StartupSettlement {
            primary: Box::new(primary),
            cleanup: Box::new(cleanup),
        },
    }
}

pub(super) fn bridge_stop_budget(spec: &OmpProcessSpec) -> Duration {
    // Graceful drain + root reap + group disappearance + side-task/result
    // drain, with one kill window of scheduling/acknowledgement margin.
    spec.drain_timeout
        .saturating_add(spec.kill_timeout.saturating_mul(5))
}

fn heartbeat_period(ttl: Duration) -> Duration {
    ttl.checked_div(2)
        .filter(|period| !period.is_zero())
        .unwrap_or(ttl)
}

pub(super) async fn lease_heartbeat(shared: Weak<Shared>, mut shutdown: watch::Receiver<bool>) {
    let Some(initial) = shared.upgrade() else {
        return;
    };
    let period = heartbeat_period(initial.lease_ttl);
    drop(initial);
    loop {
        if *shutdown.borrow() {
            return;
        }
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
            () = tokio::time::sleep(period) => {
                let Some(shared) = shared.upgrade() else {
                    return;
                };
                if let Err(error) = shared.renew_lease().await {
                    let reason = format!("session lease heartbeat failed: {error}");
                    if shared.mark_failed(&reason).is_err() {
                        let _ = shared.shutdown.send(true);
                    }
                    let (ack, dropped) = oneshot::channel();
                    drop(dropped);
                    let _ = shared
                        .pump_tx
                        .send(PumpMessage::Terminate {
                            reason,
                            planned: true,
                            ack,
                        })
                        .await;
                }
            }
        }
    }
}

pub(super) async fn acquire_lease_record(
    ledger: &Arc<Mutex<Ledger>>,
    binding: &BridgeBinding,
    ttl: Duration,
) -> Result<LeaseRecord, BridgeError> {
    let now = now_utc();
    let expires = now
        + time::Duration::try_from(ttl).map_err(|_| BridgeError::Config {
            detail: "lease TTL is not representable".to_owned(),
        })?;
    let lease = NewLease {
        // Minted before the lock; `acquire_lease` may return an existing
        // same-owner record instead, in which case this id stays unused and
        // no row references it.
        lease_id: LeaseId::from_parts(
            "odin-omp:lease",
            unix_ms(now),
            format!(
                "{}-{}",
                binding_nonce(binding),
                LEASE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ),
        )
        .map_err(|error| BridgeError::Config {
            detail: error.to_string(),
        })?,
        object_kind: LEASE_OBJECT_KIND.to_owned(),
        object_id: binding.session_id.to_string(),
        owner_id: binding.owner_id.clone(),
        acquired_at: now,
        expires_at: expires,
        acquired_logical: unix_ms(now),
        expires_logical: unix_ms(expires),
    };
    let ledger = Arc::clone(ledger);
    let owner = binding.owner_id.clone();
    let record = tokio::task::spawn_blocking(move || -> Result<LeaseRecord, BridgeError> {
        let mut guard = ledger.lock().map_err(|_| {
            BridgeError::Ledger(LedgerError::invalid_data(
                "ledger mutex poisoned".to_owned(),
            ))
        })?;
        let record = guard
            .with_tx(|tx| lease::acquire_lease(tx, &lease))
            .map_err(map_lease_error)?;
        if record.owner_id == owner && record.expires_at < expires {
            let extended = lease::extend_lease(
                &lease::LeaseExtension {
                    connection: guard.connection(),
                    lease_id: &record.lease_id,
                    owner_id: &owner,
                    expected_revision: record.revision,
                },
                now,
                unix_ms(now),
                expires,
                unix_ms(expires),
            )
            .map_err(map_lease_error)?;
            Ok(extended)
        } else {
            Ok(record)
        }
    })
    .await
    .map_err(|error| BridgeError::Serialization {
        detail: error.to_string(),
    })??;
    Ok(record)
}

fn map_lease_error(error: LedgerError) -> BridgeError {
    match &error {
        LedgerError::Conflict(_) => BridgeError::LeaseConflict {
            detail: error.to_string(),
        },
        _ => BridgeError::Ledger(error),
    }
}

impl Shared {
    /// Installs the bounded parent-stop hook. Runtime composition calls this
    /// exactly once per bridge, right after start.
    pub(super) fn set_child_stop_coordinator(
        &self,
        coordinator: &Arc<dyn ChildStopCoordinator>,
    ) -> Result<(), BridgeError> {
        *shared_lock(&self.child_stop, "child-stop")? = Some(Arc::downgrade(coordinator));
        Ok(())
    }

    /// Bounded await of every active delegated child. A successor handoff is not an unverified stop.
    pub(super) async fn await_delegated_children(
        &self,
        budget: Duration,
    ) -> Result<Vec<ChildStopRecord>, BridgeError> {
        let coordinator = {
            let guard = shared_lock(&self.child_stop, "child-stop")?;
            guard.as_ref().and_then(Weak::upgrade)
        };
        let Some(coordinator) = coordinator else {
            return Ok(Vec::new());
        };
        let session = self.binding_snapshot()?.session_id;
        let uuid =
            uuid::Uuid::parse_str(session.as_str()).map_err(|error| BridgeError::ChildStop {
                detail: format!("session identity {session} is not a live session: {error}"),
            })?;
        let parent = odin_domain::huginn::LiveSessionId::new(uuid).map_err(|error| {
            BridgeError::ChildStop {
                detail: format!("session identity {session} is not a live session: {error}"),
            }
        })?;
        let records =
            tokio::task::spawn_blocking(move || coordinator.await_children_on_stop(parent, budget))
                .await
                .map_err(|error| BridgeError::ChildStop {
                    detail: format!("child-stop coordinator task failed: {error}"),
                })?
                .map_err(|error| BridgeError::ChildStop {
                    detail: format!("bounded child await failed: {error}"),
                })?;
        let unverified: Vec<String> = records
            .iter()
            .filter(|record| !record.stopped && !record.handed_off)
            .map(|record| {
                format!(
                    "child {}: {}",
                    record.child,
                    record
                        .detail
                        .clone()
                        .unwrap_or_else(|| "no stop evidence".to_owned())
                )
            })
            .collect();
        if !unverified.is_empty() {
            return Err(BridgeError::ChildStop {
                detail: format!(
                    "the bounded stop could not prove every delegated child stopped: {}",
                    unverified.join("; ")
                ),
            });
        }
        Ok(records)
    }

    pub(super) async fn renew_lease(&self) -> Result<(), BridgeError> {
        let _gate = self.lease_gate.lock().await;
        if matches!(self.status()?, BridgeStatus::Stopped) {
            return Ok(());
        }
        let record = self
            .lease_snapshot()?
            .ok_or_else(|| BridgeError::LeaseConflict {
                detail: "the bridge has no live session lease to renew".to_owned(),
            })?;
        let now = now_utc();
        let expires = now
            + time::Duration::try_from(self.lease_ttl).map_err(|_| BridgeError::Config {
                detail: "lease TTL is not representable".to_owned(),
            })?;
        let lease_id = record.lease_id.clone();
        let owner_id = record.owner_id.clone();
        let expected_revision = record.revision;
        let health = match self.status()? {
            BridgeStatus::Starting => json!({ "state": "starting" }),
            BridgeStatus::Ready => json!({ "state": "ready" }),
            BridgeStatus::Blocked { commands } => {
                json!({ "state": "blocked", "blocked_commands": commands.len() })
            }
            BridgeStatus::Failed { reason } => {
                json!({ "state": "failed", "reason": reason })
            }
            BridgeStatus::Stopped => json!({ "state": "stopped" }),
        };
        let heartbeat = NewHeartbeat {
            heartbeat_id: format!("odin-omp:heartbeat:{}:{}", lease_id, expected_revision),
            lease_id: lease_id.clone(),
            owner_id: owner_id.clone(),
            observed_at: now,
            observed_logical: unix_ms(now),
            health,
            progress_marker: None,
        };
        let renewed = self
            .ledger_op(move |ledger| {
                ledger.with_tx(|tx| {
                    let extended = lease::extend_lease(
                        &lease::LeaseExtension {
                            connection: tx,
                            lease_id: &lease_id,
                            owner_id: &owner_id,
                            expected_revision,
                        },
                        now,
                        unix_ms(now),
                        expires,
                        unix_ms(expires),
                    )?;
                    lease::record_heartbeat(tx, &heartbeat, extended.revision)
                })
            })
            .await?;
        self.set_lease(Some(renewed.clone()))?;
        self.update_binding(|binding| {
            binding.lease_id = Some(renewed.lease_id.clone());
            binding.lease_expires_at = Some(renewed.expires_at);
        })?;
        Ok(())
    }

    pub(super) async fn release_lease(&self) -> Result<bool, BridgeError> {
        let _gate = self.lease_gate.lock().await;
        let Some(record) = self.lease_snapshot()? else {
            return Ok(false);
        };
        let lease_id = record.lease_id.clone();
        let owner = record.owner_id.clone();
        let revision = record.revision;
        self.ledger_op(move |ledger| {
            let now = now_utc();
            lease::release_lease(
                ledger.connection(),
                &lease_id,
                &owner,
                revision,
                now,
                unix_ms(now),
            )
        })
        .await?;
        self.set_lease(None)?;
        self.update_binding(|binding| {
            binding.lease_id = None;
            binding.lease_expires_at = None;
        })?;
        Ok(true)
    }
}
