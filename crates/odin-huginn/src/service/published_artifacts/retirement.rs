use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex as StdMutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use odin_domain::huginn::HuginnProtocolError;
use odin_domain::ArtifactId;

use crate::service::unavailable_protocol;
use crate::streams::StreamRetentionLease;

use super::pointer::{persist_or_remove_browser_pointer, read_browser_pointer};
use super::publication::retire_published_record;
use super::{
    browser_retirement_resource_limit, BrowserArtifactRetirement, PublishedArtifactRecord,
    BROWSER_RETIREMENT_BACKLOG_CAPACITY, BROWSER_RETIREMENT_COMMAND_CAPACITY,
    BROWSER_RETIREMENT_FLUSH_TIMEOUT,
};

#[derive(Default)]
struct BrowserArtifactLeaseEntry {
    current: Option<PublishedArtifactRecord>,
    leases: usize,
    retirement: Option<BrowserArtifactRetirement>,
    retirement_reservation: Option<BrowserArtifactRetirement>,
    processing: bool,
}

#[derive(Default)]
struct BrowserArtifactLeaseState {
    artifacts: BTreeMap<ArtifactId, BrowserArtifactLeaseEntry>,
    retirement_failure: Option<HuginnProtocolError>,
}

enum BrowserRetirementCommand {
    Wake,
    Flush(SyncSender<Result<(), HuginnProtocolError>>),
    Shutdown,
}

pub(super) struct BrowserArtifactTracker {
    state: Arc<StdMutex<BrowserArtifactLeaseState>>,
    commands: Option<SyncSender<BrowserRetirementCommand>>,
    worker: StdMutex<Option<JoinHandle<()>>>,
}

struct BrowserArtifactLease {
    artifact_id: ArtifactId,
    tracker: Arc<BrowserArtifactTracker>,
}

impl StreamRetentionLease for BrowserArtifactLease {}

impl Drop for BrowserArtifactLease {
    fn drop(&mut self) {
        self.tracker.release(&self.artifact_id);
    }
}
fn browser_retirement_backlog_len(state: &BrowserArtifactLeaseState) -> usize {
    state
        .artifacts
        .values()
        .filter(|entry| entry.retirement.is_some() || entry.retirement_reservation.is_some())
        .count()
}

impl BrowserArtifactTracker {
    pub(super) fn start(
        root: Arc<PathBuf>,
        publication_lock: Arc<StdMutex<()>>,
        recovered_retirements: Vec<BrowserArtifactRetirement>,
    ) -> Result<Arc<Self>, HuginnProtocolError> {
        if recovered_retirements.len() > BROWSER_RETIREMENT_BACKLOG_CAPACITY {
            return Err(browser_retirement_resource_limit());
        }
        let mut initial_state = BrowserArtifactLeaseState::default();
        for retirement in recovered_retirements {
            let entry = initial_state
                .artifacts
                .entry(retirement.record.artifact.artifact_id.clone())
                .or_default();
            if entry.retirement.is_some() {
                return Err(unavailable_protocol("publishedArtifactBinding"));
            }
            entry.retirement = Some(retirement);
        }
        let state = Arc::new(StdMutex::new(initial_state));
        let worker_state = state.clone();
        let (commands, receiver) = mpsc::sync_channel(BROWSER_RETIREMENT_COMMAND_CAPACITY);
        let worker = thread::Builder::new()
            .name("huginn-browser-retirement".to_owned())
            .spawn(move || {
                browser_retirement_worker(
                    root.as_ref(),
                    publication_lock.as_ref(),
                    worker_state.as_ref(),
                    receiver,
                );
            })
            .map_err(|_| unavailable_protocol("publishedArtifactRetirement"))?;
        Ok(Arc::new(Self {
            state,
            commands: Some(commands),
            worker: StdMutex::new(Some(worker)),
        }))
    }

    pub(super) fn ensure_retirement_healthy(&self) -> Result<(), HuginnProtocolError> {
        let state = self
            .state
            .lock()
            .map_err(|_| unavailable_protocol("publishedArtifactRetirement"))?;
        if let Some(error) = state.retirement_failure.as_ref() {
            return Err(error.clone());
        }
        Ok(())
    }

    pub(super) fn activate_frame(
        &self,
        record: &PublishedArtifactRecord,
    ) -> Result<(), HuginnProtocolError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| unavailable_protocol("publishedArtifactRetirement"))?;
        let entry = state
            .artifacts
            .entry(record.artifact.artifact_id.clone())
            .or_default();
        if entry
            .current
            .as_ref()
            .is_some_and(|current| current != record)
            || entry
                .retirement
                .as_ref()
                .is_some_and(|retirement| retirement.record != *record)
            || entry
                .retirement_reservation
                .as_ref()
                .is_some_and(|retirement| retirement.record != *record)
        {
            return Err(unavailable_protocol("publishedArtifactBinding"));
        }
        entry.current = Some(record.clone());
        entry.retirement = None;
        entry.retirement_reservation = None;
        entry.processing = false;
        Ok(())
    }

    pub(super) fn reserve_retirement(
        &self,
        retirement: &BrowserArtifactRetirement,
    ) -> Result<(), HuginnProtocolError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| unavailable_protocol("publishedArtifactRetirement"))?;
        if let Some(error) = state.retirement_failure.as_ref() {
            return Err(error.clone());
        }
        if let Some(entry) = state.artifacts.get(&retirement.record.artifact.artifact_id) {
            if entry
                .current
                .as_ref()
                .is_some_and(|current| current != &retirement.record)
                || entry
                    .retirement
                    .as_ref()
                    .is_some_and(|existing| existing != retirement)
                || entry
                    .retirement_reservation
                    .as_ref()
                    .is_some_and(|existing| existing != retirement)
            {
                return Err(unavailable_protocol("publishedArtifactBinding"));
            }
            if entry.retirement.as_ref() == Some(retirement)
                || entry.retirement_reservation.as_ref() == Some(retirement)
            {
                return Ok(());
            }
        }
        if browser_retirement_backlog_len(&state) >= BROWSER_RETIREMENT_BACKLOG_CAPACITY {
            return Err(browser_retirement_resource_limit());
        }
        state
            .artifacts
            .entry(retirement.record.artifact.artifact_id.clone())
            .or_default()
            .retirement_reservation = Some(retirement.clone());
        Ok(())
    }

    pub(super) fn cancel_retirement_reservation(
        &self,
        retirement: &BrowserArtifactRetirement,
    ) -> Result<(), HuginnProtocolError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| unavailable_protocol("publishedArtifactRetirement"))?;
        let artifact_id = &retirement.record.artifact.artifact_id;
        let remove = if let Some(entry) = state.artifacts.get_mut(artifact_id) {
            if entry.retirement_reservation.as_ref() == Some(retirement) {
                entry.retirement_reservation = None;
            }
            entry.current.is_none()
                && entry.leases == 0
                && entry.retirement.is_none()
                && entry.retirement_reservation.is_none()
        } else {
            false
        };
        if remove {
            state.artifacts.remove(artifact_id);
        }
        Ok(())
    }

    pub(super) fn mark_retiring(
        &self,
        retirement: BrowserArtifactRetirement,
    ) -> Result<(), HuginnProtocolError> {
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| unavailable_protocol("publishedArtifactRetirement"))?;
            if let Some(error) = state.retirement_failure.as_ref() {
                return Err(error.clone());
            }
            if let Some(entry) = state.artifacts.get(&retirement.record.artifact.artifact_id) {
                if entry
                    .current
                    .as_ref()
                    .is_some_and(|current| current != &retirement.record)
                    || entry
                        .retirement
                        .as_ref()
                        .is_some_and(|existing| existing != &retirement)
                    || entry
                        .retirement_reservation
                        .as_ref()
                        .is_some_and(|existing| existing != &retirement)
                {
                    return Err(unavailable_protocol("publishedArtifactBinding"));
                }
                if entry.retirement.is_none()
                    && entry.retirement_reservation.is_none()
                    && browser_retirement_backlog_len(&state) >= BROWSER_RETIREMENT_BACKLOG_CAPACITY
                {
                    return Err(browser_retirement_resource_limit());
                }
            } else if browser_retirement_backlog_len(&state) >= BROWSER_RETIREMENT_BACKLOG_CAPACITY
            {
                return Err(browser_retirement_resource_limit());
            }
            let entry = state
                .artifacts
                .entry(retirement.record.artifact.artifact_id.clone())
                .or_default();
            entry.current = None;
            entry.retirement_reservation = None;
            entry.retirement = Some(retirement);
            entry.processing = false;
        }
        self.wake()
    }

    pub(super) fn acquire_current(
        self: &Arc<Self>,
        artifact_id: &ArtifactId,
    ) -> Result<Option<Arc<dyn StreamRetentionLease>>, HuginnProtocolError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| unavailable_protocol("publishedArtifactRetirement"))?;
        let Some(entry) = state.artifacts.get_mut(artifact_id) else {
            return Ok(None);
        };
        if entry.current.is_none() {
            return Ok(None);
        }
        entry.leases = entry
            .leases
            .checked_add(1)
            .ok_or_else(|| unavailable_protocol("publishedArtifactRetirement"))?;
        Ok(Some(Arc::new(BrowserArtifactLease {
            artifact_id: artifact_id.clone(),
            tracker: self.clone(),
        })))
    }

    fn release(&self, artifact_id: &ArtifactId) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let Some(entry) = state.artifacts.get_mut(artifact_id) else {
            return;
        };
        let Some(leases) = entry.leases.checked_sub(1) else {
            return;
        };
        entry.leases = leases;
        let should_wake = leases == 0 && entry.retirement.is_some();
        drop(state);
        if should_wake {
            let _ = self.wake();
        }
    }

    fn wake(&self) -> Result<(), HuginnProtocolError> {
        let disconnected = match self.commands.as_ref() {
            Some(commands) => match commands.try_send(BrowserRetirementCommand::Wake) {
                Ok(()) | Err(TrySendError::Full(_)) => false,
                Err(TrySendError::Disconnected(_)) => true,
            },
            None => true,
        };
        if disconnected {
            let error = unavailable_protocol("publishedArtifactRetirement");
            let mut state = self
                .state
                .lock()
                .map_err(|_| unavailable_protocol("publishedArtifactRetirement"))?;
            return Err(state.retirement_failure.get_or_insert(error).clone());
        }
        Ok(())
    }

    pub(super) fn flush(&self) -> Result<(), HuginnProtocolError> {
        let Some(commands) = self.commands.as_ref() else {
            let error = unavailable_protocol("publishedArtifactRetirement");
            let mut state = self
                .state
                .lock()
                .map_err(|_| unavailable_protocol("publishedArtifactRetirement"))?;
            return Err(state.retirement_failure.get_or_insert(error).clone());
        };
        let (completion, completed) = mpsc::sync_channel(0);
        let deadline = Instant::now()
            .checked_add(BROWSER_RETIREMENT_FLUSH_TIMEOUT)
            .ok_or_else(|| unavailable_protocol("publishedArtifactRetirement"))?;
        let mut command = BrowserRetirementCommand::Flush(completion);
        loop {
            match commands.try_send(command) {
                Ok(()) => break,
                Err(TrySendError::Full(returned)) => {
                    command = returned;
                    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                        return Err(unavailable_protocol("publishedArtifactRetirement"));
                    };
                    thread::sleep(remaining.min(Duration::from_millis(1)));
                }
                Err(TrySendError::Disconnected(_)) => {
                    let error = unavailable_protocol("publishedArtifactRetirement");
                    let mut state = self
                        .state
                        .lock()
                        .map_err(|_| unavailable_protocol("publishedArtifactRetirement"))?;
                    return Err(state.retirement_failure.get_or_insert(error).clone());
                }
            }
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| unavailable_protocol("publishedArtifactRetirement"))?;
        completed
            .recv_timeout(remaining)
            .map_err(|_| unavailable_protocol("publishedArtifactRetirement"))?
    }
}

impl Drop for BrowserArtifactTracker {
    fn drop(&mut self) {
        if let Some(commands) = self.commands.take() {
            let _ = commands.try_send(BrowserRetirementCommand::Shutdown);
            drop(commands);
        }
        if let Ok(worker) = self.worker.get_mut() {
            if let Some(worker) = worker.take() {
                let _ = worker.join();
            }
        }
    }
}

enum BrowserRetirementOutcome {
    Retired,
    Canceled,
    Deferred,
}

fn browser_retirement_worker(
    root: &Path,
    publication_lock: &StdMutex<()>,
    state: &StdMutex<BrowserArtifactLeaseState>,
    receiver: Receiver<BrowserRetirementCommand>,
) {
    loop {
        match receiver.recv() {
            Ok(BrowserRetirementCommand::Wake) => {
                let should_drain = match state.lock() {
                    Ok(state) => state.retirement_failure.is_none(),
                    Err(_) => break,
                };
                if should_drain {
                    let _ =
                        drain_browser_retirements_and_latch_failure(root, publication_lock, state);
                }
            }
            Ok(BrowserRetirementCommand::Flush(completion)) => {
                let first_failure = match state.lock() {
                    Ok(state) => state.retirement_failure.clone(),
                    Err(_) => {
                        let _ = completion
                            .send(Err(unavailable_protocol("publishedArtifactRetirement")));
                        break;
                    }
                };
                let retry =
                    drain_browser_retirements_and_latch_failure(root, publication_lock, state);
                let recovered_failure = first_failure.clone().filter(|_| retry.is_ok());
                let result = match (first_failure, retry) {
                    (Some(error), _) | (None, Err(error)) => Err(error),
                    (None, Ok(())) => Ok(()),
                };
                if completion.send(result).is_ok() {
                    if let Some(recovered_failure) = recovered_failure {
                        let Ok(mut state) = state.lock() else {
                            break;
                        };
                        if state.retirement_failure.as_ref() == Some(&recovered_failure) {
                            state.retirement_failure = None;
                        }
                    }
                }
            }
            Ok(BrowserRetirementCommand::Shutdown) => {
                let _ = drain_browser_retirements_and_latch_failure(root, publication_lock, state);
                break;
            }
            Err(_) => {
                let _ = drain_browser_retirements_and_latch_failure(root, publication_lock, state);
                break;
            }
        }
    }
}

fn drain_browser_retirements_and_latch_failure(
    root: &Path,
    publication_lock: &StdMutex<()>,
    state: &StdMutex<BrowserArtifactLeaseState>,
) -> Result<(), HuginnProtocolError> {
    match drain_browser_retirements(root, publication_lock, state) {
        Ok(()) => Ok(()),
        Err(error) => {
            let mut state = state
                .lock()
                .map_err(|_| unavailable_protocol("publishedArtifactRetirement"))?;
            if state.retirement_failure.is_none() {
                state.retirement_failure = Some(error.clone());
            }
            Err(error)
        }
    }
}

fn drain_browser_retirements(
    root: &Path,
    publication_lock: &StdMutex<()>,
    state: &StdMutex<BrowserArtifactLeaseState>,
) -> Result<(), HuginnProtocolError> {
    loop {
        let candidate = {
            let mut state = state
                .lock()
                .map_err(|_| unavailable_protocol("publishedArtifactRetirement"))?;
            state.artifacts.iter_mut().find_map(|(artifact_id, entry)| {
                if entry.current.is_some() || entry.leases != 0 || entry.processing {
                    return None;
                }
                let retirement = entry.retirement.as_ref()?.clone();
                entry.processing = true;
                Some((artifact_id.clone(), retirement))
            })
        };
        let Some((artifact_id, retirement)) = candidate else {
            return Ok(());
        };

        let _publication_guard = publication_lock
            .lock()
            .map_err(|_| unavailable_protocol("publishedArtifactLock"))?;
        let should_process = {
            let state = state
                .lock()
                .map_err(|_| unavailable_protocol("publishedArtifactRetirement"))?;
            state.artifacts.get(&artifact_id).is_some_and(|entry| {
                entry.current.is_none()
                    && entry.leases == 0
                    && entry.processing
                    && entry.retirement.as_ref() == Some(&retirement)
            })
        };
        if !should_process {
            clear_browser_retirement_processing(state, &artifact_id, &retirement)?;
            continue;
        }

        let outcome = finish_browser_retirement(root, &retirement);
        match outcome {
            Ok(BrowserRetirementOutcome::Retired | BrowserRetirementOutcome::Canceled) => {
                let mut state = state
                    .lock()
                    .map_err(|_| unavailable_protocol("publishedArtifactRetirement"))?;
                let remove = if let Some(entry) = state.artifacts.get_mut(&artifact_id) {
                    if entry.retirement.as_ref() == Some(&retirement) {
                        entry.retirement = None;
                    }
                    entry.processing = false;
                    entry.current.is_none() && entry.leases == 0 && entry.retirement.is_none()
                } else {
                    false
                };
                if remove {
                    state.artifacts.remove(&artifact_id);
                }
            }
            Ok(BrowserRetirementOutcome::Deferred) => {
                clear_browser_retirement_processing(state, &artifact_id, &retirement)?;
                return Ok(());
            }
            Err(error) => {
                clear_browser_retirement_processing(state, &artifact_id, &retirement)?;
                let mut state = state
                    .lock()
                    .map_err(|_| unavailable_protocol("publishedArtifactRetirement"))?;
                if state.retirement_failure.is_none() {
                    state.retirement_failure = Some(error.clone());
                }
                return Err(error);
            }
        }
    }
}

fn clear_browser_retirement_processing(
    state: &StdMutex<BrowserArtifactLeaseState>,
    artifact_id: &ArtifactId,
    retirement: &BrowserArtifactRetirement,
) -> Result<(), HuginnProtocolError> {
    let mut state = state
        .lock()
        .map_err(|_| unavailable_protocol("publishedArtifactRetirement"))?;
    if let Some(entry) = state.artifacts.get_mut(artifact_id) {
        if entry.retirement.as_ref() == Some(retirement) {
            entry.processing = false;
        }
    }
    Ok(())
}

fn finish_browser_retirement(
    root: &Path,
    retirement: &BrowserArtifactRetirement,
) -> Result<BrowserRetirementOutcome, HuginnProtocolError> {
    let Some(mut pointer) =
        read_browser_pointer(root, retirement.browser_session, retirement.kind)?
    else {
        retire_published_record(root, &retirement.record)?;
        return Ok(BrowserRetirementOutcome::Retired);
    };
    if pointer.pending.as_ref() == Some(&retirement.record)
        || pointer
            .awaiting_projection
            .iter()
            .any(|awaiting| awaiting == &retirement.record)
    {
        return Ok(BrowserRetirementOutcome::Deferred);
    }
    if pointer
        .retained
        .iter()
        .any(|retained| retained == &retirement.record)
    {
        return Ok(BrowserRetirementOutcome::Canceled);
    }
    let Some(index) = pointer
        .retiring
        .iter()
        .position(|retiring| retiring == &retirement.record)
    else {
        retire_published_record(root, &retirement.record)?;
        return Ok(BrowserRetirementOutcome::Retired);
    };

    retire_published_record(root, &retirement.record)?;
    pointer.retiring.remove(index);
    persist_or_remove_browser_pointer(root, &pointer)?;
    Ok(BrowserRetirementOutcome::Retired)
}
