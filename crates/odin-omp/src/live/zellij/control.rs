use odin_domain::huginn::{
    DeviceId, LiveError, LiveSessionId, SessionEpoch, TerminalControlLease, TerminalControlLeaseId,
    TerminalControlRequest, TerminalControlState, TerminalControlStatus, TerminalInput,
    TerminalResize, TerminalSeq,
};
use odin_domain::{CommandId, Digest};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::{Arc, RwLock as StdRwLock};
use time::{Duration, OffsetDateTime};
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

use super::{
    invalid_terminal, io_error, limit_error, unavailable, TerminalState, ZellijLiveAdapter,
    ZellijPane, MAX_LEASE_TTL_SECONDS, MAX_TERMINAL_BYTES,
};
use crate::live::ledger::segment::{SegmentLayout, SegmentReader, SegmentWriter};
use crate::live::ledger::{decode_cbor, encode_cbor};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind", content = "value")]
pub enum TerminalAuditRecord {
    AcquireAccepted {
        operation_id: CommandId,
        request_digest: Digest,
        recorded_at: OffsetDateTime,
    },
    AcquireCompleted {
        operation_id: CommandId,
        status: TerminalControlStatus,
        recorded_at: OffsetDateTime,
    },
    Acquired(TerminalControlLease),
    RawInputAccepted {
        operation_id: CommandId,
        lease_id: TerminalControlLeaseId,
        byte_len: u64,
        digest: Digest,
        recorded_at: OffsetDateTime,
    },
    RawInputApplied {
        operation_id: CommandId,
        recorded_at: OffsetDateTime,
    },
    ResizeAccepted {
        operation_id: CommandId,
        lease_id: TerminalControlLeaseId,
        columns: u16,
        rows: u16,
        recorded_at: OffsetDateTime,
    },
    ResizeApplied {
        operation_id: CommandId,
        recorded_at: OffsetDateTime,
    },
    ReleaseAccepted {
        operation_id: CommandId,
        lease_id: TerminalControlLeaseId,
        recorded_at: OffsetDateTime,
    },
    ReleaseCompleted {
        operation_id: CommandId,
        status: TerminalControlStatus,
        recorded_at: OffsetDateTime,
    },
    Released {
        lease_id: TerminalControlLeaseId,
        state: TerminalControlState,
        recorded_at: OffsetDateTime,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct DurableLeaseState {
    lease: Option<TerminalControlLease>,
}

impl ZellijLiveAdapter {
    pub fn open(
        state_root: impl AsRef<Path>,
        session_id: LiveSessionId,
        epoch: SessionEpoch,
        terminal_head: TerminalSeq,
        pane: Arc<dyn ZellijPane>,
    ) -> Result<Self, LiveError> {
        std::fs::create_dir_all(state_root.as_ref()).map_err(io_error)?;
        let root = state_root.as_ref().canonicalize().map_err(io_error)?;
        let session_root = root.join(session_id.to_string());
        std::fs::create_dir_all(&session_root).map_err(io_error)?;
        let lease_path = session_root.join("terminal-lease.cbor");
        let mut lease = load_lease(&lease_path)?;
        if lease.as_ref().is_some_and(|candidate| {
            candidate.epoch != epoch || candidate.expires_at <= OffsetDateTime::now_utc()
        }) {
            lease = None;
            store_lease(&lease_path, None)?;
        }
        let audit_layout = SegmentLayout::Single {
            path: session_root.join("terminal-control.seg"),
        };
        Ok(Self {
            session_id,
            epoch: RwLock::new(epoch),
            pane,
            sink: StdRwLock::new(None),
            state: Mutex::new(TerminalState {
                head: terminal_head,
                snapshots: VecDeque::new(),
                lease,
            }),
            ops: Mutex::new(()),
            lease_path,
            session_root,
            audit: std::sync::Mutex::new(AuditLog::load(audit_layout)?),
        })
    }

    pub(crate) fn remove_capture(&self) -> Result<(), LiveError> {
        match std::fs::remove_dir_all(&self.session_root) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io_error(error)),
        }
    }

    pub async fn set_epoch(&self, epoch: SessionEpoch) -> Result<(), LiveError> {
        *self.epoch.write().await = epoch;
        let released = {
            let mut state = self.state.lock().await;
            state.lease.take()
        };
        if let Some(lease) = released {
            store_lease(&self.lease_path, None)?;
            self.append_audit(&TerminalAuditRecord::Released {
                lease_id: lease.lease_id,
                state: TerminalControlState::Revoked,
                recorded_at: OffsetDateTime::now_utc(),
            })?;
        }
        Ok(())
    }

    pub async fn acquire_control(
        &self,
        operation_id: CommandId,
        device_id: DeviceId,
        request: TerminalControlRequest,
    ) -> Result<TerminalControlStatus, LiveError> {
        let epoch = *self.epoch.read().await;
        if request.session_id != self.session_id {
            return Err(LiveError::NotFound {
                object_kind: "session".to_owned(),
                object_id: request.session_id.to_string(),
            });
        }
        if request.expected_epoch != epoch {
            return Err(LiveError::EpochMismatch {
                expected: epoch,
                actual: request.expected_epoch,
            });
        }
        let request_digest =
            Digest::hash(&encode_cbor(&(device_id, &request)).map_err(unavailable)?);
        let _ops = self.ops.lock().await;
        let records = self.operation_records(&operation_id)?;
        if let Some(status) = replay_acquire(&records, &operation_id, request_digest)? {
            return Ok(status);
        }
        let was_accepted = operation_accepted(&records, &operation_id);
        if !was_accepted {
            self.append_audit(&TerminalAuditRecord::AcquireAccepted {
                operation_id: operation_id.clone(),
                request_digest,
                recorded_at: OffsetDateTime::now_utc(),
            })?;
        }
        let now = OffsetDateTime::now_utc();
        let existing = {
            let state = self.state.lock().await;
            state
                .lease
                .as_ref()
                .filter(|lease| lease.expires_at > now)
                .cloned()
        };
        if let Some(existing) = existing {
            let recovering =
                was_accepted && existing.device_id == device_id && existing.epoch == epoch;
            let status = if recovering {
                let known = self
                    .audit
                    .lock()
                    .map_err(unavailable)?
                    .has_acquired(existing.lease_id);
                if !known {
                    self.append_audit(&TerminalAuditRecord::Acquired(existing.clone()))?;
                }
                TerminalControlStatus {
                    session_id: self.session_id,
                    state: TerminalControlState::Granted,
                    lease: Some(existing),
                    diagnostic: None,
                }
            } else {
                TerminalControlStatus {
                    session_id: self.session_id,
                    state: TerminalControlState::Denied,
                    lease: None,
                    diagnostic: Some("session already has an active operator lease".to_owned()),
                }
            };
            self.append_audit(&TerminalAuditRecord::AcquireCompleted {
                operation_id,
                status: status.clone(),
                recorded_at: OffsetDateTime::now_utc(),
            })?;
            return Ok(status);
        }
        let ttl = request
            .requested_ttl_seconds
            .get()
            .min(MAX_LEASE_TTL_SECONDS);
        let lease = TerminalControlLease {
            lease_id: TerminalControlLeaseId::new(Uuid::new_v4()).map_err(invalid_terminal)?,
            session_id: self.session_id,
            device_id,
            epoch,
            acquired_at: now,
            expires_at: now + Duration::seconds(i64::from(ttl)),
        };
        lease.validate().map_err(invalid_terminal)?;
        self.pane
            .resize(&operation_id, request.columns, request.rows)
            .await?;
        {
            let mut state = self.state.lock().await;
            if state
                .lease
                .as_ref()
                .is_some_and(|current| current.expires_at > OffsetDateTime::now_utc())
            {
                return Err(LiveError::Unauthorized);
            }
            store_lease(&self.lease_path, Some(&lease))?;
            self.append_audit(&TerminalAuditRecord::Acquired(lease.clone()))?;
            state.lease = Some(lease.clone());
        }
        let status = TerminalControlStatus {
            session_id: self.session_id,
            state: TerminalControlState::Granted,
            lease: Some(lease),
            diagnostic: None,
        };
        self.append_audit(&TerminalAuditRecord::AcquireCompleted {
            operation_id,
            status: status.clone(),
            recorded_at: OffsetDateTime::now_utc(),
        })?;
        Ok(status)
    }

    pub async fn write_input(
        &self,
        operation_id: CommandId,
        input: TerminalInput,
    ) -> Result<(), LiveError> {
        input.validate().map_err(invalid_terminal)?;
        if input.bytes.len() > MAX_TERMINAL_BYTES {
            return Err(limit_error("terminal input", MAX_TERMINAL_BYTES));
        }
        let digest = Digest::hash(&input.bytes);
        let _ops = self.ops.lock().await;
        let records = self.operation_records(&operation_id)?;
        validate_operation(&records, &operation_id, input.lease_id, digest)?;
        if operation_applied(&records, &operation_id) {
            return Ok(());
        }
        // The write may have reached the pane before the crash or lost reply; typing it
        // again would repeat the keystrokes.
        if operation_accepted(&records, &operation_id) {
            return Err(LiveError::Conflict {
                code: "terminal_input_uncertain".to_owned(),
                message: format!(
                    "operation {operation_id} was accepted but never confirmed applied, so its keystrokes may already have reached the pane; send them again as a new operation if they are still wanted"
                ),
            });
        }
        let lease = {
            let mut state = self.state.lock().await;
            active_lease(&mut state, input.lease_id, &self.lease_path)?
        };
        self.append_audit(&TerminalAuditRecord::RawInputAccepted {
            operation_id: operation_id.clone(),
            lease_id: lease.lease_id,
            byte_len: input.bytes.len() as u64,
            digest,
            recorded_at: OffsetDateTime::now_utc(),
        })?;
        self.pane.write_input(&operation_id, &input.bytes).await?;
        {
            let mut state = self.state.lock().await;
            active_lease(&mut state, input.lease_id, &self.lease_path)?;
        }
        self.append_audit(&TerminalAuditRecord::RawInputApplied {
            operation_id,
            recorded_at: OffsetDateTime::now_utc(),
        })
    }

    pub async fn resize(
        &self,
        operation_id: CommandId,
        resize: TerminalResize,
    ) -> Result<(), LiveError> {
        let _ops = self.ops.lock().await;
        let records = self.operation_records(&operation_id)?;
        validate_resize_operation(
            &records,
            &operation_id,
            resize.lease_id,
            resize.columns.get(),
            resize.rows.get(),
        )?;
        if operation_applied(&records, &operation_id) {
            return Ok(());
        }
        let lease = {
            let mut state = self.state.lock().await;
            active_lease(&mut state, resize.lease_id, &self.lease_path)?
        };
        if !operation_accepted(&records, &operation_id) {
            self.append_audit(&TerminalAuditRecord::ResizeAccepted {
                operation_id: operation_id.clone(),
                lease_id: lease.lease_id,
                columns: resize.columns.get(),
                rows: resize.rows.get(),
                recorded_at: OffsetDateTime::now_utc(),
            })?;
        }
        self.pane
            .resize(&operation_id, resize.columns, resize.rows)
            .await?;
        {
            let mut state = self.state.lock().await;
            active_lease(&mut state, resize.lease_id, &self.lease_path)?;
        }
        self.append_audit(&TerminalAuditRecord::ResizeApplied {
            operation_id,
            recorded_at: OffsetDateTime::now_utc(),
        })
    }

    pub async fn release_control(
        &self,
        operation_id: CommandId,
        lease_id: TerminalControlLeaseId,
    ) -> Result<TerminalControlStatus, LiveError> {
        let _ops = self.ops.lock().await;
        let records = self.operation_records(&operation_id)?;
        if let Some(status) = replay_release(&records, &operation_id, lease_id)? {
            return Ok(status);
        }
        let was_accepted = operation_accepted(&records, &operation_id);
        if !was_accepted {
            self.append_audit(&TerminalAuditRecord::ReleaseAccepted {
                operation_id: operation_id.clone(),
                lease_id,
                recorded_at: OffsetDateTime::now_utc(),
            })?;
        }
        let released = {
            let mut state = self.state.lock().await;
            if state.lease.is_some() {
                let lease = active_lease(&mut state, lease_id, &self.lease_path)?;
                state.lease = None;
                Some(lease)
            } else if !was_accepted {
                return Err(LiveError::Unauthorized);
            } else {
                None
            }
        };
        if let Some(lease) = released {
            store_lease(&self.lease_path, None)?;
            self.append_audit(&TerminalAuditRecord::Released {
                lease_id: lease.lease_id,
                state: TerminalControlState::Released,
                recorded_at: OffsetDateTime::now_utc(),
            })?;
        }
        let status = TerminalControlStatus {
            session_id: self.session_id,
            state: TerminalControlState::Released,
            lease: None,
            diagnostic: None,
        };
        self.append_audit(&TerminalAuditRecord::ReleaseCompleted {
            operation_id,
            status: status.clone(),
            recorded_at: OffsetDateTime::now_utc(),
        })?;
        Ok(status)
    }

    pub fn audit_records(&self) -> Result<Vec<TerminalAuditRecord>, LiveError> {
        Ok(self.audit.lock().map_err(unavailable)?.records.clone())
    }

    fn operation_records(&self, id: &CommandId) -> Result<Vec<TerminalAuditRecord>, LiveError> {
        Ok(self.audit.lock().map_err(unavailable)?.for_operation(id))
    }

    fn append_audit(&self, record: &TerminalAuditRecord) -> Result<(), LiveError> {
        self.audit.lock().map_err(unavailable)?.append(record)
    }
}

/// In-memory operation index plus the one open writer for
/// `terminal-control.seg`. A failed append drops the writer and does not
/// update the index; the next append resumes and truncates a torn tail.
pub(super) struct AuditLog {
    layout: SegmentLayout,
    writer: Option<SegmentWriter>,
    records: Vec<TerminalAuditRecord>,
    by_operation: HashMap<CommandId, Vec<usize>>,
    acquired: HashSet<TerminalControlLeaseId>,
}

impl AuditLog {
    fn load(layout: SegmentLayout) -> Result<Self, LiveError> {
        // `resume` truncates a torn tail before the index is built.
        let writer = SegmentWriter::resume(layout.clone()).map_err(unavailable)?;
        let mut log = Self {
            layout,
            writer: Some(writer),
            records: Vec::new(),
            by_operation: HashMap::new(),
            acquired: HashSet::new(),
        };
        for frame in SegmentReader::scan(&log.layout).map_err(unavailable)? {
            log.note(&decode_cbor(&frame).map_err(unavailable)?);
        }
        Ok(log)
    }

    fn for_operation(&self, id: &CommandId) -> Vec<TerminalAuditRecord> {
        self.by_operation
            .get(id)
            .map(|indexes| {
                indexes
                    .iter()
                    .map(|index| self.records[*index].clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn has_acquired(&self, lease_id: TerminalControlLeaseId) -> bool {
        self.acquired.contains(&lease_id)
    }

    fn append(&mut self, record: &TerminalAuditRecord) -> Result<(), LiveError> {
        let bytes = encode_cbor(record).map_err(unavailable)?;
        if self
            .writer
            .as_ref()
            .is_none_or(|writer| !writer.is_current())
        {
            self.writer = Some(SegmentWriter::resume(self.layout.clone()).map_err(unavailable)?);
        }
        let writer = self
            .writer
            .as_mut()
            .ok_or_else(|| unavailable("the audit writer is closed"))?;
        if let Err(error) = writer.append(&bytes).and_then(|()| writer.commit()) {
            self.writer = None;
            return Err(unavailable(error));
        }
        self.note(record);
        Ok(())
    }

    fn note(&mut self, record: &TerminalAuditRecord) {
        let index = self.records.len();
        if let Some(id) = record_operation_id(record) {
            self.by_operation.entry(id.clone()).or_default().push(index);
        }
        if let TerminalAuditRecord::Acquired(lease) = record {
            self.acquired.insert(lease.lease_id);
        }
        self.records.push(record.clone());
    }
}

fn operation_accepted(records: &[TerminalAuditRecord], operation_id: &CommandId) -> bool {
    records.iter().any(|record| match record {
        TerminalAuditRecord::AcquireAccepted {
            operation_id: recorded,
            ..
        }
        | TerminalAuditRecord::RawInputAccepted {
            operation_id: recorded,
            ..
        }
        | TerminalAuditRecord::ResizeAccepted {
            operation_id: recorded,
            ..
        }
        | TerminalAuditRecord::ReleaseAccepted {
            operation_id: recorded,
            ..
        } => recorded == operation_id,
        _ => false,
    })
}

fn operation_applied(records: &[TerminalAuditRecord], operation_id: &CommandId) -> bool {
    records.iter().any(|record| match record {
        TerminalAuditRecord::AcquireCompleted {
            operation_id: recorded,
            ..
        }
        | TerminalAuditRecord::RawInputApplied {
            operation_id: recorded,
            ..
        }
        | TerminalAuditRecord::ResizeApplied {
            operation_id: recorded,
            ..
        }
        | TerminalAuditRecord::ReleaseCompleted {
            operation_id: recorded,
            ..
        } => recorded == operation_id,
        _ => false,
    })
}

fn replay_acquire(
    records: &[TerminalAuditRecord],
    operation_id: &CommandId,
    request_digest: Digest,
) -> Result<Option<TerminalControlStatus>, LiveError> {
    let mut accepted = false;
    let mut completed = None;
    for record in records {
        match record {
            TerminalAuditRecord::AcquireAccepted {
                operation_id: recorded,
                request_digest: recorded_digest,
                ..
            } if recorded == operation_id => {
                if *recorded_digest != request_digest {
                    return Err(operation_conflict());
                }
                accepted = true;
            }
            TerminalAuditRecord::AcquireCompleted {
                operation_id: recorded,
                status,
                ..
            } if recorded == operation_id => completed = Some(status.clone()),
            record if record_operation_id(record) == Some(operation_id) => {
                return Err(operation_conflict());
            }
            _ => {}
        }
    }
    if completed.is_some() && !accepted {
        return Err(unavailable(
            "the audit log completes an operation it never accepted",
        ));
    }
    Ok(completed)
}

fn replay_release(
    records: &[TerminalAuditRecord],
    operation_id: &CommandId,
    lease_id: TerminalControlLeaseId,
) -> Result<Option<TerminalControlStatus>, LiveError> {
    let mut accepted = false;
    let mut completed = None;
    for record in records {
        match record {
            TerminalAuditRecord::ReleaseAccepted {
                operation_id: recorded,
                lease_id: recorded_lease,
                ..
            } if recorded == operation_id => {
                if *recorded_lease != lease_id {
                    return Err(operation_conflict());
                }
                accepted = true;
            }
            TerminalAuditRecord::ReleaseCompleted {
                operation_id: recorded,
                status,
                ..
            } if recorded == operation_id => completed = Some(status.clone()),
            record if record_operation_id(record) == Some(operation_id) => {
                return Err(operation_conflict());
            }
            _ => {}
        }
    }
    if completed.is_some() && !accepted {
        return Err(unavailable(
            "the audit log completes an operation it never accepted",
        ));
    }
    Ok(completed)
}

fn record_operation_id(record: &TerminalAuditRecord) -> Option<&CommandId> {
    match record {
        TerminalAuditRecord::AcquireAccepted { operation_id, .. }
        | TerminalAuditRecord::AcquireCompleted { operation_id, .. }
        | TerminalAuditRecord::RawInputAccepted { operation_id, .. }
        | TerminalAuditRecord::RawInputApplied { operation_id, .. }
        | TerminalAuditRecord::ResizeAccepted { operation_id, .. }
        | TerminalAuditRecord::ResizeApplied { operation_id, .. }
        | TerminalAuditRecord::ReleaseAccepted { operation_id, .. }
        | TerminalAuditRecord::ReleaseCompleted { operation_id, .. } => Some(operation_id),
        TerminalAuditRecord::Acquired(_) | TerminalAuditRecord::Released { .. } => None,
    }
}

fn validate_operation(
    records: &[TerminalAuditRecord],
    operation_id: &CommandId,
    lease_id: TerminalControlLeaseId,
    digest: Digest,
) -> Result<(), LiveError> {
    for record in records {
        match record {
            TerminalAuditRecord::RawInputAccepted {
                operation_id: recorded,
                lease_id: recorded_lease,
                digest: recorded_digest,
                ..
            } if recorded == operation_id => {
                return if *recorded_lease == lease_id && *recorded_digest == digest {
                    Ok(())
                } else {
                    Err(operation_conflict())
                };
            }
            record if record_operation_id(record) == Some(operation_id) => {
                return Err(operation_conflict());
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_resize_operation(
    records: &[TerminalAuditRecord],
    operation_id: &CommandId,
    lease_id: TerminalControlLeaseId,
    columns: u16,
    rows: u16,
) -> Result<(), LiveError> {
    for record in records {
        match record {
            TerminalAuditRecord::ResizeAccepted {
                operation_id: recorded,
                lease_id: recorded_lease,
                columns: recorded_columns,
                rows: recorded_rows,
                ..
            } if recorded == operation_id => {
                return if *recorded_lease == lease_id
                    && *recorded_columns == columns
                    && *recorded_rows == rows
                {
                    Ok(())
                } else {
                    Err(operation_conflict())
                };
            }
            record if record_operation_id(record) == Some(operation_id) => {
                return Err(operation_conflict());
            }
            _ => {}
        }
    }
    Ok(())
}

fn operation_conflict() -> LiveError {
    LiveError::Conflict {
        code: "terminal_operation_conflict".to_owned(),
        message: "terminal operation ID is already bound to another action".to_owned(),
    }
}

fn active_lease(
    state: &mut TerminalState,
    lease_id: TerminalControlLeaseId,
    lease_path: &Path,
) -> Result<TerminalControlLease, LiveError> {
    let Some(lease) = state.lease.clone() else {
        return Err(LiveError::Unauthorized);
    };
    if lease.expires_at <= OffsetDateTime::now_utc() {
        state.lease = None;
        store_lease(lease_path, None)?;
        return Err(LiveError::Unauthorized);
    }
    if lease.lease_id != lease_id {
        return Err(LiveError::Unauthorized);
    }
    Ok(lease)
}

fn load_lease(path: &Path) -> Result<Option<TerminalControlLease>, LiveError> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(path).map_err(io_error)?;
    let state: DurableLeaseState = decode_cbor(&bytes).map_err(unavailable)?;
    Ok(state.lease)
}

fn store_lease(path: &Path, lease: Option<&TerminalControlLease>) -> Result<(), LiveError> {
    use std::io::Write as _;
    let bytes = encode_cbor(&DurableLeaseState {
        lease: lease.cloned(),
    })
    .map_err(unavailable)?;
    let parent = path
        .parent()
        .ok_or_else(|| unavailable(format!("{} has no parent directory", path.display())))?;
    let temporary = parent.join(format!(".terminal-lease-{}.tmp", Uuid::new_v4()));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(io_error)?;
    file.write_all(&bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    std::fs::rename(&temporary, path).map_err(io_error)?;
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(io_error)
}

#[cfg(test)]
mod tests {
    use std::num::{NonZeroU16, NonZeroU32};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    use async_trait::async_trait;
    use odin_domain::huginn::{
        DeviceId, LiveError, LiveSessionId, SessionEpoch, TerminalControlLeaseId,
        TerminalControlRequest, TerminalControlState, TerminalInput, TerminalSeq,
    };
    use odin_domain::CommandId;
    use uuid::Uuid;

    use super::super::{unavailable, ZellijLiveAdapter, ZellijPane};
    use super::TerminalAuditRecord;

    struct CountingPane {
        writes: AtomicUsize,
        /// The next write fails after being counted, as a pane that took the bytes and lost the reply.
        fail_next_write: AtomicBool,
    }

    impl CountingPane {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                writes: AtomicUsize::new(0),
                fail_next_write: AtomicBool::new(false),
            })
        }
    }

    #[async_trait]
    impl ZellijPane for CountingPane {
        async fn capture(&self) -> Result<super::super::CapturedTerminal, LiveError> {
            Err(unavailable("the counting pane does not capture"))
        }

        async fn write_input(&self, _: &CommandId, _: &[u8]) -> Result<(), LiveError> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            if self.fail_next_write.swap(false, Ordering::SeqCst) {
                return Err(unavailable("the pane lost the reply"));
            }
            Ok(())
        }

        async fn resize(
            &self,
            _: &CommandId,
            _: NonZeroU16,
            _: NonZeroU16,
        ) -> Result<(), LiveError> {
            Ok(())
        }

        async fn terminate(&self) -> Result<(), LiveError> {
            Ok(())
        }
    }

    fn session() -> LiveSessionId {
        LiveSessionId::parse("00000000-0000-4000-8000-00000000e6a5").expect("session")
    }

    fn request(epoch: SessionEpoch, columns: u16) -> TerminalControlRequest {
        TerminalControlRequest {
            session_id: session(),
            expected_epoch: epoch,
            columns: NonZeroU16::new(columns).expect("columns"),
            rows: NonZeroU16::new(24).expect("rows"),
            requested_ttl_seconds: NonZeroU32::new(60).expect("ttl"),
        }
    }

    fn op(name: &str) -> CommandId {
        CommandId::new(name).expect("id")
    }

    fn device() -> DeviceId {
        DeviceId::new(Uuid::new_v4()).expect("device")
    }

    /// Control belongs to one device at a time, ends at release or an epoch change, and
    /// an operation id names one request.
    #[tokio::test]
    async fn control_is_one_devices_until_it_releases_or_the_epoch_moves() {
        let root = tempfile::tempdir().expect("tempdir");
        let epoch = SessionEpoch::new(1);
        let adapter = ZellijLiveAdapter::open(
            root.path(),
            session(),
            epoch,
            TerminalSeq::new(0),
            CountingPane::new(),
        )
        .expect("open");
        let (first, second) = (device(), device());
        let granted = adapter
            .acquire_control(op("op-1"), first, request(epoch, 80))
            .await
            .expect("first device");
        assert_eq!(granted.state, TerminalControlState::Granted);
        let lease_id = granted.lease.expect("lease").lease_id;

        let denied = adapter
            .acquire_control(op("op-2"), second, request(epoch, 80))
            .await
            .expect("second device");
        assert_eq!(denied.state, TerminalControlState::Denied);
        assert!(denied.lease.is_none());

        let reused = adapter
            .acquire_control(op("op-1"), first, request(epoch, 100))
            .await
            .expect_err("op-1 already names another request");
        assert!(
            matches!(reused, LiveError::Conflict { ref code, .. } if code == "terminal_operation_conflict")
        );

        let stranger = TerminalInput {
            lease_id: TerminalControlLeaseId::new(Uuid::new_v4()).expect("lease id"),
            bytes: b"x".to_vec(),
        };
        let refused = adapter.write_input(op("op-key"), stranger).await;
        assert!(matches!(refused, Err(LiveError::Unauthorized)));

        let released = adapter
            .release_control(op("op-release"), lease_id)
            .await
            .expect("release");
        assert_eq!(released.state, TerminalControlState::Released);
        let regranted = adapter
            .acquire_control(op("op-3"), second, request(epoch, 80))
            .await
            .expect("second device after release");
        assert_eq!(regranted.state, TerminalControlState::Granted);
        let lease_id = regranted.lease.expect("lease").lease_id;

        adapter
            .set_epoch(SessionEpoch::new(2))
            .await
            .expect("epoch");
        let input = TerminalInput {
            lease_id,
            bytes: b"x".to_vec(),
        };
        assert!(matches!(
            adapter.write_input(op("op-late"), input).await,
            Err(LiveError::Unauthorized)
        ));
        assert!(adapter
            .audit_records()
            .expect("audit")
            .iter()
            .any(|record| matches!(
                record,
                TerminalAuditRecord::Released {
                    state: TerminalControlState::Revoked,
                    ..
                }
            )));
    }

    /// Keystrokes whose write may have reached the pane are never typed a second time.
    #[tokio::test]
    async fn an_unconfirmed_keystroke_is_refused_on_retry_not_retyped() {
        let root = tempfile::tempdir().expect("tempdir");
        let epoch = SessionEpoch::new(1);
        let pane = CountingPane::new();
        let adapter = ZellijLiveAdapter::open(
            root.path(),
            session(),
            epoch,
            TerminalSeq::new(0),
            pane.clone(),
        )
        .expect("open");
        let lease_id = adapter
            .acquire_control(op("op-acquire"), device(), request(epoch, 80))
            .await
            .expect("acquire")
            .lease
            .expect("lease")
            .lease_id;
        let input = TerminalInput {
            lease_id,
            bytes: b"rm -rf build".to_vec(),
        };
        pane.fail_next_write.store(true, Ordering::SeqCst);
        adapter
            .write_input(op("op-key"), input.clone())
            .await
            .expect_err("the first write loses its reply");
        let retry = adapter
            .write_input(op("op-key"), input)
            .await
            .expect_err("the retry is refused");
        assert!(
            matches!(retry, LiveError::Conflict { ref code, .. } if code == "terminal_input_uncertain")
        );
        assert_eq!(pane.writes.load(Ordering::SeqCst), 1);
    }
}
