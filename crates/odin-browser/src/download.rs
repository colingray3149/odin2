//! Bounded download staging beneath the marked profile.
//!
//! The Playwright worker writes each admitted download into a GUID-named staging
//! directory under the session's download root. Every directory and file operation is pinned
//! beneath an already-open canonical root descriptor. Admission, progress,
//! and final reads share one aggregate byte budget. Exact bytes are scanned by
//! a deadline-aware, killable scanner before publication. Only a confirmed
//! malicious verdict causes quarantine; formats, MIME types, extensions,
//! sites, and domains are never consulted.

use std::collections::{HashMap, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use blake3::Hasher;
use odin_confined_fs::validate_relative_path;
use odin_domain::huginn::artifact::{ArtifactKind, ArtifactRef};
use odin_domain::huginn::browser::{BrowserDownloadStatus, BrowserDownloadView};
use odin_domain::huginn::ids::{BrowserSessionId, DownloadId};
use odin_domain::Digest;
use thiserror::Error;
use time::OffsetDateTime;
use tokio::task::spawn_blocking;
use tokio::time::{timeout, timeout_at, Instant as TokioInstant};
use uuid::Uuid;

use crate::capability::{ArtifactPublication, ArtifactPublisher, PublicationKind, SanitizedUrl};
use crate::config::DownloadLimits;
use crate::safety::{
    ActiveMalwareScan, BrowserSafetyGate, MalwareVerdict, ScanControl, ScanFailure,
};

/// Neutral wire media type required by the frozen artifact contract when the
/// true type is unknown. This is not a format decision.
pub const UNKNOWN_MEDIA_TYPE: &str = "application/octet-stream";

const MAX_SUGGESTED_NAME_BYTES: usize = 240;
const MAX_QUARANTINE_NAME_BYTES: usize = 240;
const READ_CHUNK_BYTES: usize = 64 * 1024;
const MAX_RETAINED_TERMINAL_DOWNLOADS: usize = 256;
const MAX_RETAINED_QUARANTINES: usize = 256;
const MAX_STAGING_ENTRIES: usize = 1_024;
const QUARANTINE_DIRECTORY: &str = "confirmed-malware";
const MALWARE_SCAN_TIMEOUT: Duration = Duration::from_secs(30);
const MALWARE_KILL_GRACE: Duration = Duration::from_secs(2);

/// One scanner-confirmed quarantine event, safe for evidence output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantineRecord {
    pub download_id: DownloadId,
    pub signature: String,
    pub quarantined_at: OffsetDateTime,
}

#[derive(Debug, Error)]
pub enum DownloadError {
    #[error("download staging root is unusable: {0}")]
    StagingRoot(String),
    #[error("staging I/O failed: {0}")]
    StagingIo(String),
    #[error("unknown download {0}")]
    UnknownDownload(DownloadId),
    #[error("download {0} is not awaiting completion")]
    WrongState(DownloadId),
    #[error("source URL is unusable")]
    InvalidSourceUrl,
    #[error("download limit reached: at most {limit} active downloads")]
    ActiveCeiling { limit: u32 },
    #[error("download exceeds the per-file ceiling of {limit} bytes")]
    FileCeiling { limit: u64 },
    #[error("download exceeds the aggregate ceiling of {limit} bytes")]
    TotalCeiling { limit: u64 },
}

struct DownloadState {
    revision: u64,
    suggested_name: String,
    source_url: String,
    expected_bytes: Option<u64>,
    received_bytes: u64,
    reserved_bytes: u64,
    status: BrowserDownloadStatus,
    content: Option<ArtifactRef>,
    started_at: OffsetDateTime,
    finished_at: Option<OffsetDateTime>,
    failure: Option<String>,
    dir_name: String,
    dir_fd: Arc<File>,
}

impl DownloadState {
    fn view(&self, session_id: BrowserSessionId, download_id: DownloadId) -> BrowserDownloadView {
        BrowserDownloadView {
            session_id,
            download_id,
            revision: self.revision,
            suggested_name: self.suggested_name.clone(),
            source_url: self.source_url.clone(),
            media_type: None,
            expected_bytes: self.expected_bytes,
            received_bytes: self.received_bytes,
            status: self.status,
            content: self.content.clone(),
            started_at: self.started_at,
            finished_at: self.finished_at,
            failure: self.failure.clone(),
        }
    }

    fn is_active(&self) -> bool {
        matches!(
            self.status,
            BrowserDownloadStatus::Pending | BrowserDownloadStatus::InProgress
        )
    }
}

struct ManagerState {
    downloads: HashMap<DownloadId, DownloadState>,
    staged_total: u64,
    reserved_total: u64,
    terminal_order: VecDeque<DownloadId>,
    quarantined: VecDeque<QuarantineRecord>,
}

/// Per-session download stager. `Send + Sync`; the session actor drives it
/// from typed Playwright worker download events.
pub struct DownloadManager {
    session_id: BrowserSessionId,
    root_fd: Arc<File>,
    quarantine_fd: Arc<File>,
    limits: DownloadLimits,
    gate: Arc<BrowserSafetyGate>,
    publisher: Arc<dyn ArtifactPublisher>,
    state: Mutex<ManagerState>,
}

impl DownloadManager {
    /// Adopts `staging_root` as the download staging area. The canonical root
    /// and quarantine directory are opened with `O_DIRECTORY|O_NOFOLLOW` and
    /// retained for the lifetime of the manager.
    pub fn new(
        session_id: BrowserSessionId,
        staging_root: PathBuf,
        limits: DownloadLimits,
        gate: Arc<BrowserSafetyGate>,
        publisher: Arc<dyn ArtifactPublisher>,
    ) -> Result<Self, DownloadError> {
        if !staging_root.is_absolute() {
            return Err(DownloadError::StagingRoot("must be absolute".into()));
        }
        let supplied_meta = fs::symlink_metadata(&staging_root)
            .map_err(|error| DownloadError::StagingRoot(error.to_string()))?;
        if supplied_meta.file_type().is_symlink() || !supplied_meta.is_dir() {
            return Err(DownloadError::StagingRoot(
                "must be a real directory, not a symlink".into(),
            ));
        }
        let staging_root = fs::canonicalize(&staging_root)
            .map_err(|error| DownloadError::StagingRoot(error.to_string()))?;
        let root_fd = open_directory(&staging_root)
            .map_err(|error| DownloadError::StagingRoot(error.to_string()))?;
        validate_private_directory(&root_fd)
            .map_err(|detail| DownloadError::StagingRoot(detail.into()))?;

        match rustix::fs::mkdirat(&root_fd, QUARANTINE_DIRECTORY, rustix::fs::Mode::RWXU) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(DownloadError::StagingRoot(error.to_string())),
        }
        let quarantine_fd = open_directory_at(&root_fd, OsStr::new(QUARANTINE_DIRECTORY))
            .map_err(|error| DownloadError::StagingRoot(error.to_string()))?;
        validate_private_directory(&quarantine_fd)
            .map_err(|detail| DownloadError::StagingRoot(detail.into()))?;

        Ok(Self {
            session_id,
            root_fd: Arc::new(root_fd),
            quarantine_fd: Arc::new(quarantine_fd),
            limits,
            gate,
            publisher,
            state: Mutex::new(ManagerState {
                downloads: HashMap::new(),
                staged_total: 0,
                reserved_total: 0,
                terminal_order: VecDeque::new(),
                quarantined: VecDeque::new(),
            }),
        })
    }

    /// Admits one download and reserves its declared size against the aggregate
    /// ceiling before the worker receives staging authority.
    pub async fn begin(
        &self,
        download_id: DownloadId,
        suggested_name: &str,
        source_url: &str,
        expected_bytes: Option<u64>,
        now: OffsetDateTime,
    ) -> Result<BrowserDownloadView, DownloadError> {
        let source_url = SanitizedUrl::parse(source_url)
            .map_err(|_| DownloadError::InvalidSourceUrl)?
            .display_url()
            .to_owned();
        let suggested_name = sanitize_suggested_name(suggested_name, &download_id);
        let reservation = expected_bytes.unwrap_or(0);

        {
            let state = self.lock();
            if let Some(existing) = state.downloads.get(&download_id) {
                return Ok(existing.view(self.session_id, download_id));
            }
            if let Some(error) = self.admission_error(&state, reservation) {
                return Err(error);
            }
        }

        let dir_name = download_id.to_string();
        if !is_single_component(&dir_name) {
            return Err(DownloadError::StagingIo(
                "download id is not a safe path component".into(),
            ));
        }
        let root_fd = Arc::clone(&self.root_fd);
        let create_name = dir_name.clone();
        let dir_fd =
            match spawn_blocking(move || create_guid_directory(root_fd.as_ref(), &create_name))
                .await
            {
                Ok(Ok(dir_fd)) => Arc::new(dir_fd),
                Ok(Err(error)) => return Err(DownloadError::StagingIo(error)),
                Err(_) => {
                    return Err(DownloadError::StagingIo(
                        "staging directory task failed".into(),
                    ));
                }
            };

        let result = {
            let mut state = self.lock();
            if let Some(existing) = state.downloads.get(&download_id) {
                Ok(existing.view(self.session_id, download_id))
            } else if let Some(error) = self.admission_error(&state, reservation) {
                Err(error)
            } else {
                state.reserved_total += reservation;
                let record = DownloadState {
                    revision: 1,
                    suggested_name,
                    source_url,
                    expected_bytes,
                    received_bytes: 0,
                    reserved_bytes: reservation,
                    status: BrowserDownloadStatus::Pending,
                    content: None,
                    started_at: now,
                    finished_at: None,
                    failure: None,
                    dir_name: dir_name.clone(),
                    dir_fd: Arc::clone(&dir_fd),
                };
                let view = record.view(self.session_id, download_id);
                state.downloads.insert(download_id, record);
                return Ok(view);
            }
        };

        let cleanup_root = Arc::clone(&self.root_fd);
        let cleanup_dir = Arc::clone(&dir_fd);
        let cleanup_name = dir_name;
        let _ = spawn_blocking(move || {
            cleanup_guid_directory(cleanup_root.as_ref(), cleanup_dir.as_ref(), &cleanup_name)
        })
        .await;
        result
    }

    /// Records monotonic progress and grows the aggregate reservation before
    /// accepting any newly observed bytes.
    pub async fn progress(
        &self,
        download_id: DownloadId,
        received_bytes: u64,
        now: OffsetDateTime,
    ) -> Result<BrowserDownloadView, DownloadError> {
        let failure = {
            let mut state = self.lock();
            let (active, previous_received, previous_reservation) = state
                .downloads
                .get(&download_id)
                .map(|record| {
                    (
                        record.is_active(),
                        record.received_bytes,
                        record.reserved_bytes,
                    )
                })
                .ok_or(DownloadError::UnknownDownload(download_id))?;
            if !active {
                return Ok(state.downloads[&download_id].view(self.session_id, download_id));
            }

            let received_bytes = received_bytes.max(previous_received);
            let target_reservation = previous_reservation.max(received_bytes);
            let failure = if received_bytes > self.limits.max_file_bytes {
                Some(format!(
                    "file byte ceiling exceeded: limit {}",
                    self.limits.max_file_bytes
                ))
            } else if !can_grow_reservation(
                &state,
                target_reservation - previous_reservation,
                self.limits.max_total_bytes,
            ) {
                Some(format!(
                    "aggregate byte ceiling exceeded: limit {}",
                    self.limits.max_total_bytes
                ))
            } else {
                let additional = target_reservation - previous_reservation;
                state.reserved_total += additional;
                let record = state
                    .downloads
                    .get_mut(&download_id)
                    .expect("known download");
                record.reserved_bytes = target_reservation;
                None
            };

            let record = state
                .downloads
                .get_mut(&download_id)
                .expect("known download");
            record.received_bytes = received_bytes;
            record.status = BrowserDownloadStatus::InProgress;
            record.revision = record.revision.saturating_add(1);
            failure
        };

        if let Some(reason) = failure {
            return Ok(self.fail_after_cleanup(download_id, reason, now).await);
        }
        self.view(download_id)
            .ok_or(DownloadError::UnknownDownload(download_id))
    }

    /// Verifies, accounts, scans, and publishes one completed download.
    pub async fn complete(
        &self,
        download_id: DownloadId,
        now: OffsetDateTime,
    ) -> Result<BrowserDownloadView, DownloadError> {
        let (dir_fd, discovery_limit) = {
            let mut state = self.lock();
            let record = state
                .downloads
                .get_mut(&download_id)
                .ok_or(DownloadError::UnknownDownload(download_id))?;
            if !record.is_active() {
                return Err(DownloadError::WrongState(download_id));
            }
            record.status = BrowserDownloadStatus::InProgress;
            record.revision = record.revision.saturating_add(1);
            let own_reservation = record.reserved_bytes;
            let dir_fd = Arc::clone(&record.dir_fd);
            let occupied_by_others = state
                .staged_total
                .saturating_add(state.reserved_total.saturating_sub(own_reservation));
            let total_available = self
                .limits
                .max_total_bytes
                .saturating_sub(occupied_by_others);
            (dir_fd, self.limits.max_file_bytes.min(total_available))
        };

        let discovered =
            match spawn_blocking(move || discover_payload(dir_fd, discovery_limit)).await {
                Ok(result) => result,
                Err(_) => {
                    return Ok(self
                        .fail_after_cleanup(download_id, "staging verifier task failed".into(), now)
                        .await);
                }
            };
        let payload = match discovered {
            Ok(payload) => payload,
            Err(failure) => {
                return Ok(self
                    .fail_after_cleanup(download_id, failure.to_string(), now)
                    .await);
            }
        };

        if !self.commit_staged_bytes(download_id, payload.byte_len) {
            return Ok(self
                .fail_after_cleanup(
                    download_id,
                    format!(
                        "aggregate byte ceiling exceeded: limit {}",
                        self.limits.max_total_bytes
                    ),
                    now,
                )
                .await);
        }

        if self.remove_staging(download_id).await.is_err() {
            return Ok(self.fail(
                download_id,
                "staging cleanup failed before scanning".into(),
                now,
            ));
        }

        let (bytes, verdict) = scan_exact_bytes(
            Arc::clone(&self.gate),
            Arc::clone(&self.quarantine_fd),
            payload.bytes,
        )
        .await;

        match verdict {
            Err(failure) => {
                return Ok(self.fail(
                    download_id,
                    format!("scanner failed: {}", failure.code()),
                    now,
                ));
            }
            Ok(MalwareVerdict::Malicious { signature }) => {
                let quarantine_fd = Arc::clone(&self.quarantine_fd);
                let quarantine_name = self.quarantine_name(download_id);
                let quarantined_bytes = bytes;
                let quarantined = spawn_blocking(move || {
                    quarantine_payload(quarantine_fd.as_ref(), &quarantine_name, &quarantined_bytes)
                })
                .await;
                return Ok(match quarantined {
                    Ok(Ok(())) => self.reject_malware(download_id, signature, now),
                    Ok(Err(())) | Err(_) => self.fail(
                        download_id,
                        "malware confirmed but quarantine failed".into(),
                        now,
                    ),
                });
            }
            Ok(MalwareVerdict::Clean) => {}
        }

        let display_name = self.suggested_name(download_id);
        let byte_len = payload.byte_len;
        let digest = payload.digest;
        let published = match self.publisher.publish(ArtifactPublication {
            session_id: self.session_id,
            kind: PublicationKind::Download,
            display_name: display_name.clone(),
            media_type: UNKNOWN_MEDIA_TYPE.to_owned(),
            content_digest: digest,
            bytes,
        }) {
            Ok(artifact) => artifact,
            Err(_) => {
                return Ok(self.fail(download_id, "publication refused".into(), now));
            }
        };
        if let Err(reason) = validate_download_artifact(
            &published,
            &display_name,
            UNKNOWN_MEDIA_TYPE,
            byte_len,
            digest,
        ) {
            return Ok(self.fail(
                download_id,
                format!("published artifact binding mismatch: {reason}"),
                now,
            ));
        }

        let mut state = self.lock();
        let record = state
            .downloads
            .get_mut(&download_id)
            .ok_or(DownloadError::UnknownDownload(download_id))?;
        record.status = BrowserDownloadStatus::Complete;
        record.revision = record.revision.saturating_add(1);
        record.received_bytes = byte_len;
        record.finished_at = Some(now);
        record.content = Some(published);
        retain_terminal(&mut state, download_id);
        Ok(state.downloads[&download_id].view(self.session_id, download_id))
    }

    /// Cancels an active download and removes its descriptor-pinned staging
    /// directory before releasing the aggregate reservation.
    pub async fn cancel(
        &self,
        download_id: DownloadId,
        now: OffsetDateTime,
    ) -> Result<BrowserDownloadView, DownloadError> {
        let active = self
            .lock()
            .downloads
            .get(&download_id)
            .map(DownloadState::is_active)
            .ok_or(DownloadError::UnknownDownload(download_id))?;
        if !active {
            return self
                .view(download_id)
                .ok_or(DownloadError::UnknownDownload(download_id));
        }

        let cleaned = self.remove_staging(download_id).await.is_ok();
        let mut state = self.lock();
        if cleaned {
            release_reservation(&mut state, download_id);
        }
        let record = state
            .downloads
            .get_mut(&download_id)
            .ok_or(DownloadError::UnknownDownload(download_id))?;
        record.status = BrowserDownloadStatus::Cancelled;
        record.revision = record.revision.saturating_add(1);
        record.finished_at = Some(now);
        record.failure = Some(if cleaned {
            "cancelled".into()
        } else {
            "cancelled; staging cleanup failed".into()
        });
        retain_terminal(&mut state, download_id);
        Ok(state.downloads[&download_id].view(self.session_id, download_id))
    }

    pub fn view(&self, download_id: DownloadId) -> Option<BrowserDownloadView> {
        self.lock()
            .downloads
            .get(&download_id)
            .map(|record| record.view(self.session_id, download_id))
    }

    pub fn views(&self) -> Vec<BrowserDownloadView> {
        let state = self.lock();
        let mut views: Vec<_> = state
            .downloads
            .iter()
            .map(|(id, record)| record.view(self.session_id, *id))
            .collect();
        views.sort_unstable_by_key(|left| left.download_id);
        views
    }

    /// Bounded scanner-confirmed quarantine history.
    pub fn quarantine_records(&self) -> Vec<QuarantineRecord> {
        self.lock().quarantined.iter().cloned().collect()
    }

    /// Cumulative bytes admitted into final staging during this session.
    pub fn staged_total(&self) -> u64 {
        self.lock().staged_total
    }

    async fn remove_staging(&self, download_id: DownloadId) -> Result<(), ()> {
        let (dir_fd, dir_name) = self
            .lock()
            .downloads
            .get(&download_id)
            .map(|record| (Arc::clone(&record.dir_fd), record.dir_name.clone()))
            .ok_or(())?;
        let root_fd = Arc::clone(&self.root_fd);
        match spawn_blocking(move || {
            cleanup_guid_directory(root_fd.as_ref(), dir_fd.as_ref(), &dir_name)
        })
        .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(())) | Err(_) => Err(()),
        }
    }

    async fn fail_after_cleanup(
        &self,
        download_id: DownloadId,
        mut reason: String,
        now: OffsetDateTime,
    ) -> BrowserDownloadView {
        if self.remove_staging(download_id).await.is_ok() {
            release_reservation(&mut self.lock(), download_id);
        } else {
            reason.push_str("; staging cleanup failed");
        }
        self.fail(download_id, reason, now)
    }

    fn admission_error(&self, state: &ManagerState, reservation: u64) -> Option<DownloadError> {
        let active = state
            .downloads
            .values()
            .filter(|record| record.is_active())
            .count();
        let limit = usize::try_from(self.limits.max_active_downloads.get()).unwrap_or(usize::MAX);
        if active >= limit {
            return Some(DownloadError::ActiveCeiling {
                limit: self.limits.max_active_downloads.get(),
            });
        }
        if reservation > self.limits.max_file_bytes {
            return Some(DownloadError::FileCeiling {
                limit: self.limits.max_file_bytes,
            });
        }
        if !can_grow_reservation(state, reservation, self.limits.max_total_bytes) {
            return Some(DownloadError::TotalCeiling {
                limit: self.limits.max_total_bytes,
            });
        }
        None
    }

    fn commit_staged_bytes(&self, download_id: DownloadId, byte_len: u64) -> bool {
        let mut state = self.lock();
        let Some(current_reservation) = state
            .downloads
            .get(&download_id)
            .map(|record| record.reserved_bytes)
        else {
            return false;
        };
        let additional = byte_len.saturating_sub(current_reservation);
        if !can_grow_reservation(&state, additional, self.limits.max_total_bytes) {
            return false;
        }
        state.reserved_total += additional;
        let final_reservation = current_reservation + additional;
        let Some(staged_total) = state.staged_total.checked_add(byte_len) else {
            return false;
        };
        state.reserved_total = state.reserved_total.saturating_sub(final_reservation);
        state.staged_total = staged_total;
        let record = state
            .downloads
            .get_mut(&download_id)
            .expect("known download");
        record.reserved_bytes = 0;
        record.received_bytes = record.received_bytes.max(byte_len);
        true
    }

    fn suggested_name(&self, download_id: DownloadId) -> String {
        self.lock()
            .downloads
            .get(&download_id)
            .map(|record| record.suggested_name.clone())
            .unwrap_or_else(|| "download".into())
    }

    fn quarantine_name(&self, download_id: DownloadId) -> String {
        let prefix = format!("{download_id}-");
        let suggested = self.suggested_name(download_id);
        let available = MAX_QUARANTINE_NAME_BYTES.saturating_sub(prefix.len());
        format!("{prefix}{}", utf8_prefix(&suggested, available))
    }

    fn reject_malware(
        &self,
        download_id: DownloadId,
        signature: String,
        now: OffsetDateTime,
    ) -> BrowserDownloadView {
        let mut state = self.lock();
        if let Some(record) = state.downloads.get_mut(&download_id) {
            if record.is_active() {
                record.status = BrowserDownloadStatus::Rejected;
                record.revision = record.revision.saturating_add(1);
                record.finished_at = Some(now);
                record.failure = Some(format!("malware confirmed: {signature}"));
            }
        }
        state.quarantined.push_back(QuarantineRecord {
            download_id,
            signature,
            quarantined_at: now,
        });
        while state.quarantined.len() > MAX_RETAINED_QUARANTINES {
            state.quarantined.pop_front();
        }
        retain_terminal(&mut state, download_id);
        state
            .downloads
            .get(&download_id)
            .map(|record| record.view(self.session_id, download_id))
            .unwrap_or_else(|| placeholder_view(self.session_id, download_id))
    }

    fn fail(
        &self,
        download_id: DownloadId,
        reason: String,
        now: OffsetDateTime,
    ) -> BrowserDownloadView {
        let mut state = self.lock();
        let transitioned = if let Some(record) = state.downloads.get_mut(&download_id) {
            if record.is_active() {
                record.status = BrowserDownloadStatus::Failed;
                record.revision = record.revision.saturating_add(1);
                record.finished_at = Some(now);
                record.failure = Some(reason);
                true
            } else {
                false
            }
        } else {
            return placeholder_view(self.session_id, download_id);
        };
        if transitioned {
            retain_terminal(&mut state, download_id);
        }
        state.downloads[&download_id].view(self.session_id, download_id)
    }

    fn lock(&self) -> MutexGuard<'_, ManagerState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn can_grow_reservation(state: &ManagerState, additional: u64, limit: u64) -> bool {
    state
        .staged_total
        .checked_add(state.reserved_total)
        .and_then(|used| used.checked_add(additional))
        .is_some_and(|projected| projected <= limit)
}

fn release_reservation(state: &mut ManagerState, download_id: DownloadId) {
    let Some(reservation) = state
        .downloads
        .get(&download_id)
        .map(|record| record.reserved_bytes)
    else {
        return;
    };
    state.reserved_total = state.reserved_total.saturating_sub(reservation);
    if let Some(record) = state.downloads.get_mut(&download_id) {
        record.reserved_bytes = 0;
    }
}

fn retain_terminal(state: &mut ManagerState, download_id: DownloadId) {
    state.terminal_order.push_back(download_id);
    while state.terminal_order.len() > MAX_RETAINED_TERMINAL_DOWNLOADS {
        if let Some(expired) = state.terminal_order.pop_front() {
            if state
                .downloads
                .get(&expired)
                .is_some_and(|record| !record.is_active())
            {
                state.downloads.remove(&expired);
            }
        }
    }
}

struct DiscoveredPayload {
    bytes: Vec<u8>,
    byte_len: u64,
    digest: Digest,
}

#[derive(Debug, Error)]
enum DiscoverFailure {
    #[error("no staged file found")]
    Missing,
    #[error("staging directory is ambiguous")]
    Ambiguous,
    #[error("staged object is not a regular file")]
    NotRegularFile,
    #[error("staged file exceeds an active byte ceiling")]
    TooLarge,
    #[error("staged file changed while being read")]
    Changed,
    #[error("staging read failed")]
    Io,
}

fn discover_payload(
    dir_fd: Arc<File>,
    max_bytes: u64,
) -> Result<DiscoveredPayload, DiscoverFailure> {
    let names = directory_entry_names(dir_fd.as_ref()).map_err(|()| DiscoverFailure::Io)?;
    let name = match names.as_slice() {
        [] => return Err(DiscoverFailure::Missing),
        [name] => name,
        _ => return Err(DiscoverFailure::Ambiguous),
    };
    let descriptor = rustix::fs::openat(
        dir_fd.as_ref(),
        name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| DiscoverFailure::Io)?;
    let mut file = File::from(descriptor);
    let metadata = file.metadata().map_err(|_| DiscoverFailure::Io)?;
    if !metadata.is_file() {
        return Err(DiscoverFailure::NotRegularFile);
    }
    let byte_len = metadata.len();
    if byte_len > max_bytes {
        return Err(DiscoverFailure::TooLarge);
    }
    let capacity = usize::try_from(byte_len).map_err(|_| DiscoverFailure::TooLarge)?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut hasher = Hasher::new();
    let mut chunk = [0_u8; READ_CHUNK_BYTES];
    let mut read = 0_u64;
    loop {
        let count = file.read(&mut chunk).map_err(|_| DiscoverFailure::Io)?;
        if count == 0 {
            break;
        }
        read = read
            .checked_add(count as u64)
            .ok_or(DiscoverFailure::TooLarge)?;
        if read > max_bytes {
            return Err(DiscoverFailure::TooLarge);
        }
        hasher.update(&chunk[..count]);
        bytes.extend_from_slice(&chunk[..count]);
    }
    let final_metadata = file.metadata().map_err(|_| DiscoverFailure::Io)?;
    if read != byte_len || final_metadata.len() != byte_len {
        return Err(DiscoverFailure::Changed);
    }
    Ok(DiscoveredPayload {
        bytes,
        byte_len,
        digest: Digest::new(*hasher.finalize().as_bytes()),
    })
}

#[derive(Clone, Copy)]
enum ScanProjectionFailure {
    SnapshotUnavailable,
    StartTaskFailed,
    WaitTaskFailed,
    DeadlineExceeded,
    Scanner(ScanFailure),
}

impl ScanProjectionFailure {
    const fn code(self) -> &'static str {
        match self {
            Self::SnapshotUnavailable => "scanner_snapshot_unavailable",
            Self::StartTaskFailed => "scanner_start_task_failed",
            Self::WaitTaskFailed => "scanner_wait_task_failed",
            Self::DeadlineExceeded => "scanner_deadline_exceeded",
            Self::Scanner(failure) => failure.code(),
        }
    }
}

struct ScanCancelGuard {
    control: ScanControl,
    active: Option<ActiveMalwareScan>,
    armed: bool,
}

impl ScanCancelGuard {
    fn new(control: ScanControl) -> Self {
        Self {
            control,
            active: None,
            armed: true,
        }
    }

    fn attach(&mut self, active: ActiveMalwareScan) {
        self.active = Some(active);
    }

    fn kill_now(&self) {
        self.control.cancel();
        if let Some(active) = &self.active {
            active.kill();
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
        self.active = None;
    }
}

impl Drop for ScanCancelGuard {
    fn drop(&mut self) {
        if self.armed {
            self.kill_now();
        }
    }
}

async fn scan_exact_bytes(
    gate: Arc<BrowserSafetyGate>,
    scan_dir: Arc<File>,
    bytes: Vec<u8>,
) -> (Vec<u8>, Result<MalwareVerdict, ScanProjectionFailure>) {
    let deadline = Instant::now() + MALWARE_SCAN_TIMEOUT;
    let control = ScanControl::new(deadline);
    let mut guard = ScanCancelGuard::new(control.clone());
    let start_control = control;
    let mut starter = spawn_blocking(move || {
        let file = create_unlinked_scan_snapshot(scan_dir.as_ref(), &bytes)?;
        let active = gate
            .start_download_scan(file, bytes.len() as u64, start_control)
            .map_err(ScanProjectionFailure::Scanner)?;
        Ok::<_, ScanProjectionFailure>((bytes, active))
    });

    let (bytes, active) = match timeout_at(TokioInstant::from_std(deadline), &mut starter).await {
        Ok(Ok(Ok(started))) => started,
        Ok(Ok(Err(failure))) => return (Vec::new(), Err(failure)),
        Ok(Err(_)) => return (Vec::new(), Err(ScanProjectionFailure::StartTaskFailed)),
        Err(_) => {
            guard.kill_now();
            starter.abort();
            return (Vec::new(), Err(ScanProjectionFailure::DeadlineExceeded));
        }
    };
    guard.attach(active.clone());

    let waiter_scan = active;
    let mut waiter = spawn_blocking(move || waiter_scan.wait());
    let verdict = match timeout_at(TokioInstant::from_std(deadline), &mut waiter).await {
        Ok(Ok(result)) => result.map_err(ScanProjectionFailure::Scanner),
        Ok(Err(_)) => Err(ScanProjectionFailure::WaitTaskFailed),
        Err(_) => {
            guard.kill_now();
            if timeout(MALWARE_KILL_GRACE, &mut waiter).await.is_err() {
                waiter.abort();
            }
            Err(ScanProjectionFailure::DeadlineExceeded)
        }
    };
    let scan_reaped = match &verdict {
        Ok(_) | Err(ScanProjectionFailure::Scanner(_)) => true,
        Err(_) => false,
    };
    if scan_reaped {
        guard.disarm();
    }
    (bytes, verdict)
}

fn create_unlinked_scan_snapshot(
    dir_fd: &File,
    bytes: &[u8],
) -> Result<File, ScanProjectionFailure> {
    let name = format!(".odin-scan-{}", Uuid::new_v4());
    let descriptor = rustix::fs::openat(
        dir_fd,
        name.as_str(),
        rustix::fs::OFlags::RDWR
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map_err(|_| ScanProjectionFailure::SnapshotUnavailable)?;
    let mut file = File::from(descriptor);
    if rustix::fs::unlinkat(dir_fd, name.as_str(), rustix::fs::AtFlags::empty()).is_err() {
        return Err(ScanProjectionFailure::SnapshotUnavailable);
    }
    file.write_all(bytes)
        .and_then(|()| file.seek(SeekFrom::Start(0)).map(|_| ()))
        .map_err(|_| ScanProjectionFailure::SnapshotUnavailable)?;
    Ok(file)
}

fn quarantine_payload(dir_fd: &File, name: &str, bytes: &[u8]) -> Result<(), ()> {
    if !is_single_component(name) {
        return Err(());
    }
    let descriptor = rustix::fs::openat(
        dir_fd,
        name,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map_err(|_| ())?;
    let mut file = File::from(descriptor);
    if file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .is_err()
    {
        drop(file);
        let _ = rustix::fs::unlinkat(dir_fd, name, rustix::fs::AtFlags::empty());
        return Err(());
    }
    Ok(())
}

fn open_directory(path: &Path) -> Result<File, rustix::io::Errno> {
    rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
}

fn open_directory_at(dir_fd: &File, name: &OsStr) -> Result<File, rustix::io::Errno> {
    rustix::fs::openat(
        dir_fd,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
}

fn validate_private_directory(dir_fd: &File) -> Result<(), &'static str> {
    let metadata = dir_fd
        .metadata()
        .map_err(|_| "directory metadata is unavailable")?;
    if !metadata.is_dir() {
        return Err("descriptor is not a directory");
    }
    if metadata.mode() & 0o077 != 0 {
        return Err("group/other permission bits must be clear");
    }
    Ok(())
}

fn create_guid_directory(root_fd: &File, name: &str) -> Result<File, String> {
    if !is_single_component(name) {
        return Err("staging name is not a single component".into());
    }
    rustix::fs::mkdirat(root_fd, name, rustix::fs::Mode::RWXU)
        .map_err(|error| error.to_string())?;
    let dir_fd = open_directory_at(root_fd, OsStr::new(name)).map_err(|error| error.to_string())?;
    validate_private_directory(&dir_fd).map_err(str::to_owned)?;
    Ok(dir_fd)
}

fn cleanup_guid_directory(root_fd: &File, dir_fd: &File, name: &str) -> Result<(), ()> {
    if !is_single_component(name) {
        return Err(());
    }
    for entry in directory_entry_names(dir_fd)? {
        match rustix::fs::unlinkat(dir_fd, &entry, rustix::fs::AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => {}
            Err(rustix::io::Errno::ISDIR | rustix::io::Errno::PERM) => {
                rustix::fs::unlinkat(dir_fd, &entry, rustix::fs::AtFlags::REMOVEDIR)
                    .map_err(|_| ())?;
            }
            Err(_) => return Err(()),
        }
    }
    match rustix::fs::unlinkat(root_fd, name, rustix::fs::AtFlags::REMOVEDIR) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(_) => Err(()),
    }
}

fn directory_entry_names(dir_fd: &File) -> Result<Vec<OsString>, ()> {
    let descriptor_path = PathBuf::from(format!("/proc/self/fd/{}", dir_fd.as_raw_fd()));
    let mut names = Vec::new();
    for entry in fs::read_dir(descriptor_path).map_err(|_| ())? {
        if names.len() >= MAX_STAGING_ENTRIES {
            return Err(());
        }
        names.push(entry.map_err(|_| ())?.file_name());
    }
    Ok(names)
}

/// Reject both Unix and Windows separators in names supplied by remote origins.
fn is_single_component(name: &str) -> bool {
    !name.contains('/') && !name.contains('\\') && validate_relative_path(Path::new(name)).is_ok()
}

fn validate_download_artifact(
    artifact: &ArtifactRef,
    display_name: &str,
    media_type: &str,
    byte_len: u64,
    digest: Digest,
) -> Result<(), &'static str> {
    if artifact.kind != ArtifactKind::File {
        return Err("artifact kind is not a file");
    }
    if artifact.display_name != display_name {
        return Err("display name disagrees with the publication");
    }
    if artifact.media_type != media_type {
        return Err("media type disagrees with the publication");
    }
    if artifact.byte_len != byte_len {
        return Err("byte length disagrees with the staged bytes");
    }
    if artifact.content_digest != digest {
        return Err("digest disagrees with the staged bytes");
    }
    Ok(())
}

fn utf8_prefix(value: &str, max_bytes: usize) -> &str {
    let mut end = value.len().min(max_bytes);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

/// Bounded metadata sanitization only; no extension or format is rejected.
fn sanitize_suggested_name(raw: &str, download_id: &DownloadId) -> String {
    let candidate = raw.trim();
    let acceptable = !candidate.is_empty()
        && candidate.len() <= MAX_SUGGESTED_NAME_BYTES
        && candidate != "."
        && candidate != ".."
        && !candidate.starts_with('.')
        && !candidate
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control() || byte == b'/' || byte == b'\\');
    if acceptable {
        candidate.to_owned()
    } else {
        format!("download-{download_id}")
    }
}

fn placeholder_view(session_id: BrowserSessionId, download_id: DownloadId) -> BrowserDownloadView {
    BrowserDownloadView {
        session_id,
        download_id,
        revision: 0,
        suggested_name: String::new(),
        source_url: String::new(),
        media_type: None,
        expected_bytes: None,
        received_bytes: 0,
        status: BrowserDownloadStatus::Failed,
        content: None,
        started_at: OffsetDateTime::UNIX_EPOCH,
        finished_at: Some(OffsetDateTime::UNIX_EPOCH),
        failure: Some("download record disappeared during finalization".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarantine_refuses_escape_symlinks_and_replacement() {
        let root = std::env::temp_dir().join(format!("odin-download-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let staging = root.join("staging");
        fs::create_dir(&staging).unwrap();
        let outside = root.join("outside");
        fs::write(&outside, b"original").unwrap();
        let directory = open_directory(&staging).unwrap();

        assert!(quarantine_payload(&directory, "../outside", b"escaped").is_err());
        std::os::unix::fs::symlink(&outside, staging.join("link")).unwrap();
        assert!(quarantine_payload(&directory, "link", b"followed").is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"original");

        quarantine_payload(&directory, "payload", b"evidence").unwrap();
        assert!(quarantine_payload(&directory, "payload", b"replaced").is_err());
        assert_eq!(fs::read(staging.join("payload")).unwrap(), b"evidence");
        fs::remove_dir_all(root).unwrap();
    }
}
