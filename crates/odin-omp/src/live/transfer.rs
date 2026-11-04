use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use odin_domain::huginn::{
    ArtifactChunk, ArtifactDirection, ArtifactKind, ArtifactReadRequest, ArtifactReadStream,
    ArtifactRef, LiveError, TransferChunk, TransferId, TransferManifest, TransferStatus,
    UploadManifest,
};
use odin_domain::{ArtifactId, CommandId, Digest, LaneId, SeatId};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

use super::lane_artifacts::{LaneArtifact, LaneTransferBridge};
use super::ledger::{live_error, BlobKind, BlobRef, BlobSource, LiveLedger};

const MAX_TRANSFER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TRANSFER_CHUNKS: u64 = 4096;
const DOWNLOAD_QUEUE: usize = 8;

#[async_trait]
pub trait TransferLaneResolver: Send + Sync {
    async fn lane_for(&self, manifest: &TransferManifest) -> Result<LaneId, LiveError>;
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeatTransferLanes {
    pub file_ingress: LaneId,
    pub file_egress: LaneId,
    pub render_ingress: LaneId,
    pub render_egress: LaneId,
}

pub struct RegistryTransferLaneResolver {
    ledger: Arc<dyn LiveLedger>,
    seats: BTreeMap<SeatId, SeatTransferLanes>,
}

impl RegistryTransferLaneResolver {
    pub fn new(
        ledger: Arc<dyn LiveLedger>,
        seats: BTreeMap<SeatId, SeatTransferLanes>,
    ) -> Result<Self, LiveError> {
        if seats.is_empty() {
            return Err(transfer_error(
                "lane_registry_empty",
                "registry declares no live seat transfer lanes",
            ));
        }
        Ok(Self { ledger, seats })
    }
    /// Read-only nodes serve no seats, so every transfer lane lookup is denied.
    pub fn read_only(ledger: Arc<dyn LiveLedger>) -> Self {
        Self {
            ledger,
            seats: BTreeMap::new(),
        }
    }
}

#[async_trait]
impl TransferLaneResolver for RegistryTransferLaneResolver {
    async fn lane_for(&self, manifest: &TransferManifest) -> Result<LaneId, LiveError> {
        let session = self
            .ledger
            .session(manifest.session_id)
            .await
            .map_err(live_error)?;
        let lanes =
            self.seats
                .get(&session.manifest.seat_id)
                .ok_or_else(|| LiveError::NotFound {
                    object_kind: "seatTransferLanes".to_owned(),
                    object_id: session.manifest.seat_id.to_string(),
                })?;
        Ok(match (manifest.kind, manifest.direction) {
            (ArtifactKind::File, ArtifactDirection::DeviceToSession) => lanes.file_ingress.clone(),
            (ArtifactKind::File, ArtifactDirection::SessionToDevice) => lanes.file_egress.clone(),
            (ArtifactKind::Render(_), ArtifactDirection::DeviceToSession) => {
                lanes.render_ingress.clone()
            }
            (ArtifactKind::Render(_), ArtifactDirection::SessionToDevice) => {
                lanes.render_egress.clone()
            }
        })
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct DurableTransfer {
    upload: UploadManifest,
    status: TransferStatus,
    chunks: BTreeSet<u32>,
    blob: Option<BlobRef>,
    artifact: Option<ArtifactRef>,
    #[serde(default)]
    cancel_commands: BTreeSet<CommandId>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct DurableArtifact {
    manifest: TransferManifest,
    blob: BlobRef,
    artifact: ArtifactRef,
}

struct TransferState {
    transfers: BTreeMap<TransferId, DurableTransfer>,
    artifacts: BTreeMap<ArtifactId, DurableArtifact>,
    downloads: BTreeMap<TransferId, DownloadControl>,
}

struct DownloadControl {
    operations: BTreeMap<CommandId, DownloadOperation>,
    sender: mpsc::Sender<DownloadCommand>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DownloadOperation {
    Credit(NonZeroU16),
    Cancel,
}

enum DownloadCommand {
    Credit(NonZeroU16),
    Cancel,
}

pub struct TransferManager {
    root: PathBuf,
    ledger: Arc<dyn LiveLedger>,
    lanes: Arc<dyn TransferLaneResolver>,
    lane_artifacts: Arc<LaneTransferBridge>,
    state: Arc<Mutex<TransferState>>,
    /// Per-transfer single-writer gate. A std mutex, not the state lock:
    /// `Drop` runs on the runtime thread, and tokio `blocking_lock` is
    /// `block_on` (it panics there). The guard is `!Send`, so it is locked
    /// only in sync helpers, never as a local of an async fn.
    busy: Arc<TransferGate>,
}

impl TransferManager {
    pub fn open(
        root: impl AsRef<Path>,
        ledger: Arc<dyn LiveLedger>,
        lanes: Arc<dyn TransferLaneResolver>,
        lane_artifacts: Arc<LaneTransferBridge>,
    ) -> Result<Self, LiveError> {
        fs::create_dir_all(root.as_ref()).map_err(unavailable)?;
        let root = root.as_ref().canonicalize().map_err(unavailable)?;
        fs::create_dir_all(root.join("records")).map_err(unavailable)?;
        fs::create_dir_all(root.join("incoming")).map_err(unavailable)?;
        fs::create_dir_all(root.join("artifacts")).map_err(unavailable)?;
        let mut transfers = BTreeMap::new();
        let mut artifacts = BTreeMap::new();
        for entry in fs::read_dir(root.join("records")).map_err(unavailable)? {
            let entry = entry.map_err(unavailable)?;
            if !entry.file_type().map_err(unavailable)?.is_file()
                || entry.path().extension().and_then(|value| value.to_str()) != Some("cbor")
            {
                continue;
            }
            let record: DurableTransfer =
                super::ledger::decode_cbor(&fs::read(entry.path()).map_err(unavailable)?)
                    .map_err(live_error)?;
            if let (Some(artifact), Some(blob)) = (&record.artifact, &record.blob) {
                artifacts.insert(
                    artifact.artifact_id.clone(),
                    DurableArtifact {
                        manifest: record.upload.manifest.clone(),
                        blob: blob.clone(),
                        artifact: artifact.clone(),
                    },
                );
            }
            transfers.insert(record.upload.manifest.transfer_id, record);
        }
        for entry in fs::read_dir(root.join("artifacts")).map_err(unavailable)? {
            let entry = entry.map_err(unavailable)?;
            if !entry.file_type().map_err(unavailable)?.is_file()
                || entry.path().extension().and_then(|value| value.to_str()) != Some("cbor")
            {
                continue;
            }
            let artifact: DurableArtifact =
                super::ledger::decode_cbor(&fs::read(entry.path()).map_err(unavailable)?)
                    .map_err(live_error)?;
            artifacts.insert(artifact.artifact.artifact_id.clone(), artifact);
        }
        Ok(Self {
            root,
            ledger,
            lanes,
            lane_artifacts,
            state: Arc::new(Mutex::new(TransferState {
                transfers,
                artifacts,
                downloads: BTreeMap::new(),
            })),
            busy: Arc::new(TransferGate::new(BTreeMap::new())),
        })
    }

    pub async fn begin(&self, upload: UploadManifest) -> Result<TransferStatus, LiveError> {
        let manifest = &upload.manifest;
        if manifest.direction != ArtifactDirection::DeviceToSession {
            return Err(transfer_error(
                "manifest_bounds",
                "an upload must go from a device to a session",
            ));
        }
        if manifest.byte_len == 0 {
            return Err(transfer_error(
                "manifest_bounds",
                "the file is empty; there is nothing to upload",
            ));
        }
        if manifest.byte_len > MAX_TRANSFER_BYTES || manifest.chunk_count() > MAX_TRANSFER_CHUNKS {
            return Err(transfer_error(
                "manifest_bounds",
                &format!(
                    "{} bytes in {} chunks exceeds the upload limit of {MAX_TRANSFER_BYTES} bytes in {MAX_TRANSFER_CHUNKS} chunks",
                    manifest.byte_len,
                    manifest.chunk_count()
                ),
            ));
        }
        let transfer_id = manifest.transfer_id;
        let _turn = self.exclusive(transfer_id).await;
        {
            let state = self.state.lock().await;
            if let Some(existing) = state.transfers.get(&transfer_id) {
                return if existing.upload == upload {
                    Ok(existing.status)
                } else {
                    Err(transfer_error(
                        "transfer_conflict",
                        "transfer ID already has another manifest",
                    ))
                };
            }
        }
        let path = self.incoming_path(transfer_id);
        let byte_len = upload.manifest.byte_len;
        spawn_io(move || create_incoming(path, byte_len)).await?;
        let record = DurableTransfer {
            upload,
            status: TransferStatus::Declared,
            chunks: BTreeSet::new(),
            blob: None,
            artifact: None,
            cancel_commands: BTreeSet::new(),
        };
        self.persist_record(&record).await?;
        self.state
            .lock()
            .await
            .transfers
            .insert(transfer_id, record);
        Ok(TransferStatus::Declared)
    }

    pub async fn write_chunk(
        &self,
        transfer: TransferId,
        chunk: TransferChunk,
    ) -> Result<(), LiveError> {
        let _turn = self.exclusive(transfer).await;
        let (path, offset, already) = {
            let state = self.state.lock().await;
            let record = state
                .transfers
                .get(&transfer)
                .ok_or_else(|| not_found("transfer", transfer.to_string()))?;
            record
                .upload
                .manifest
                .validate_chunk(&chunk)
                .map_err(invalid_domain)?;
            let offset = u64::from(chunk.index) * u64::from(record.upload.manifest.chunk_len.get());
            let already = record.chunks.contains(&chunk.index);
            (self.incoming_path(transfer), offset, already)
        };
        if already {
            let len = chunk.bytes.len();
            let digest = spawn_io(move || read_chunk_digest(path, offset, len)).await?;
            return if digest == chunk.digest {
                Ok(())
            } else {
                Err(transfer_error(
                    "chunk_conflict",
                    "chunk index already contains other bytes",
                ))
            };
        }
        let index = chunk.index;
        let bytes = chunk.bytes;
        let write_path = path;
        spawn_io(move || write_chunk_bytes(write_path, offset, bytes)).await?;
        let snapshot = {
            let mut state = self.state.lock().await;
            let record = state
                .transfers
                .get_mut(&transfer)
                .ok_or_else(|| not_found("transfer", transfer.to_string()))?;
            record.chunks.insert(index);
            record.status = TransferStatus::Receiving;
            record.clone()
        };
        self.persist_record(&snapshot).await
    }

    pub async fn commit(&self, transfer: TransferId) -> Result<ArtifactRef, LiveError> {
        let _turn = self.exclusive(transfer).await;
        let (path, manifest) = {
            let state = self.state.lock().await;
            let record = state
                .transfers
                .get(&transfer)
                .ok_or_else(|| not_found("transfer", transfer.to_string()))?;
            if let Some(artifact) = &record.artifact {
                return Ok(artifact.clone());
            }
            if record.chunks.len() as u64 != record.upload.manifest.chunk_count() {
                return Err(transfer_error(
                    "incomplete",
                    "not every declared chunk is durable",
                ));
            }
            (self.incoming_path(transfer), record.upload.manifest.clone())
        };
        let hash_path = path.clone();
        let (file, byte_len, digest) = spawn_io(move || hash_file_rewind(&hash_path)).await?;
        manifest
            .validate_final(byte_len, digest)
            .map_err(invalid_domain)?;
        {
            let snapshot = {
                let mut state = self.state.lock().await;
                let record = state
                    .transfers
                    .get_mut(&transfer)
                    .ok_or_else(|| not_found("transfer", transfer.to_string()))?;
                if let Some(artifact) = &record.artifact {
                    return Ok(artifact.clone());
                }
                // Published before the ledger awaits so a retry no-ops once
                // the artifact is stored, and a crash resumes from Verified.
                record.status = TransferStatus::Verified;
                record.clone()
            };
            self.persist_record(&snapshot).await?;
        }
        let session = self
            .ledger
            .session(manifest.session_id)
            .await
            .map_err(live_error)?;
        let blob = self
            .ledger
            .store_blob(BlobSource::HashedFile {
                session_id: manifest.session_id,
                epoch: session.epoch,
                kind: BlobKind::Transfer,
                source: file,
                byte_len,
                digest,
            })
            .await
            .map_err(live_error)?;
        let lane = self.lanes.lane_for(&manifest).await?;
        self.lane_artifacts
            .publish_ingress(lane.clone(), manifest.clone(), blob.clone())
            .await?;
        let durable_artifact = durable_artifact(&manifest, blob.clone(), lane)?;
        let artifact = durable_artifact.artifact.clone();
        self.persist_artifact(&durable_artifact).await?;
        let snapshot = {
            let mut state = self.state.lock().await;
            let record = state
                .transfers
                .get_mut(&transfer)
                .ok_or_else(|| not_found("transfer", transfer.to_string()))?;
            record.status = TransferStatus::Published;
            record.blob = Some(blob);
            record.artifact = Some(artifact.clone());
            record.clone()
        };
        self.persist_record(&snapshot).await?;
        self.state
            .lock()
            .await
            .artifacts
            .insert(artifact.artifact_id.clone(), durable_artifact);
        Ok(artifact)
    }

    pub async fn cancel(
        &self,
        command_id: CommandId,
        transfer: TransferId,
    ) -> Result<TransferStatus, LiveError> {
        let _turn = self.exclusive(transfer).await;
        let pending = {
            let mut state = self.state.lock().await;
            for (candidate, record) in &state.transfers {
                if *candidate != transfer && record.cancel_commands.contains(&command_id) {
                    return Err(operation_conflict());
                }
            }
            for (candidate, control) in &state.downloads {
                if *candidate != transfer && control.operations.contains_key(&command_id) {
                    return Err(operation_conflict());
                }
            }
            if let Some(control) = state.downloads.get_mut(&transfer) {
                match control.operations.get(&command_id) {
                    Some(DownloadOperation::Cancel) => return Ok(TransferStatus::Cancelled),
                    Some(DownloadOperation::Credit(_)) => return Err(operation_conflict()),
                    None => {}
                }
                control
                    .sender
                    .try_send(DownloadCommand::Cancel)
                    .map_err(|error| {
                        transfer_error(
                            "download_closed",
                            &format!("download is no longer active: {error}"),
                        )
                    })?;
                control
                    .operations
                    .insert(command_id, DownloadOperation::Cancel);
                return Ok(TransferStatus::Cancelled);
            }
            let record = state
                .transfers
                .get_mut(&transfer)
                .ok_or_else(|| not_found("transfer", transfer.to_string()))?;
            if record.status == TransferStatus::Published {
                return Err(transfer_error(
                    "already_published",
                    "published content is immutable",
                ));
            }
            record.cancel_commands.insert(command_id);
            if record.status != TransferStatus::Cancelled {
                record.status = TransferStatus::Cancelled;
                Some((record.clone(), self.incoming_path(transfer)))
            } else {
                None
            }
        };
        if let Some((snapshot, path)) = pending {
            spawn_io(move || remove_incoming(path)).await?;
            self.persist_record(&snapshot).await?;
        }
        Ok(TransferStatus::Cancelled)
    }

    pub async fn grant_download_credit(
        &self,
        command_id: CommandId,
        transfer: TransferId,
        chunks: NonZeroU16,
    ) -> Result<(), LiveError> {
        let mut state = self.state.lock().await;
        for (candidate, control) in &state.downloads {
            if *candidate != transfer && control.operations.contains_key(&command_id) {
                return Err(operation_conflict());
            }
        }
        let control = state
            .downloads
            .get_mut(&transfer)
            .ok_or_else(|| not_found("download", transfer.to_string()))?;
        match control.operations.get(&command_id) {
            Some(DownloadOperation::Credit(existing)) if *existing == chunks => return Ok(()),
            Some(_) => return Err(operation_conflict()),
            None => {}
        }
        control
            .sender
            .try_send(DownloadCommand::Credit(chunks))
            .map_err(|error| {
                transfer_error(
                    "download_closed",
                    &format!("download is no longer active: {error}"),
                )
            })?;
        control
            .operations
            .insert(command_id, DownloadOperation::Credit(chunks));
        Ok(())
    }

    pub async fn register_egress(
        &self,
        lane_artifact: LaneArtifact,
    ) -> Result<ArtifactRef, LiveError> {
        let manifest = &lane_artifact.manifest;
        if manifest.direction != ArtifactDirection::SessionToDevice
            || manifest.session_id != lane_artifact.blob.session_id
            || manifest.content_digest != lane_artifact.blob.digest
            || manifest.byte_len != lane_artifact.blob.byte_len
        {
            return Err(transfer_error(
                "egress_binding",
                "egress lane artifact does not match its durable blob",
            ));
        }
        let expected_lane = self.lanes.lane_for(manifest).await?;
        if expected_lane != lane_artifact.lane_id {
            return Err(transfer_error(
                "egress_lane",
                "artifact arrived from an undeclared egress lane",
            ));
        }
        let _ = self
            .ledger
            .read_blob(&lane_artifact.blob)
            .await
            .map_err(live_error)?;
        let durable = durable_artifact(manifest, lane_artifact.blob, lane_artifact.lane_id)?;
        let artifact = durable.artifact.clone();
        self.persist_artifact(&durable).await?;
        self.state
            .lock()
            .await
            .artifacts
            .insert(artifact.artifact_id.clone(), durable);
        Ok(artifact)
    }

    pub async fn read(
        &self,
        request: ArtifactReadRequest,
    ) -> Result<(ArtifactRef, ArtifactReadStream), LiveError> {
        let (artifact, blob, chunk_len, chunk_count) = {
            let state = self.state.lock().await;
            let record = state
                .artifacts
                .get(&request.artifact_id)
                .ok_or_else(|| not_found("artifact", request.artifact_id.to_string()))?;
            (
                record.artifact.clone(),
                record.blob.clone(),
                record.manifest.chunk_len,
                record.manifest.chunk_count(),
            )
        };
        if u64::from(request.first_chunk) >= chunk_count {
            return Err(transfer_error(
                "chunk_range",
                "first chunk lies beyond the artifact",
            ));
        }
        let mut stream = self.ledger.read_blob(&blob).await.map_err(live_error)?;
        let mut remaining_skip = u64::from(request.first_chunk) * u64::from(chunk_len.get());
        let mut discard = [0u8; 64 * 1024];
        while remaining_skip > 0 {
            let take =
                usize::try_from(remaining_skip.min(discard.len() as u64)).map_err(unavailable)?;
            let read = stream.read(&mut discard[..take]).map_err(unavailable)?;
            if read == 0 {
                return Err(transfer_error(
                    "chunk_range",
                    "artifact ended before first chunk",
                ));
            }
            remaining_skip -= read as u64;
        }
        let transfer_id = loop {
            let candidate = TransferId::new(Uuid::new_v4()).map_err(invalid_domain)?;
            if !self.state.lock().await.downloads.contains_key(&candidate) {
                break candidate;
            }
        };
        let initial_credit = usize::from(request.initial_credit.get());
        let (sender, receiver) = mpsc::channel(DOWNLOAD_QUEUE);
        let (control_sender, mut control_receiver) = mpsc::channel(DOWNLOAD_QUEUE);
        self.state.lock().await.downloads.insert(
            transfer_id,
            DownloadControl {
                operations: BTreeMap::new(),
                sender: control_sender,
            },
        );
        let response_artifact = artifact.clone();
        let state = Arc::clone(&self.state);
        tokio::task::spawn_blocking(move || {
            let mut index = request.first_chunk;
            let mut credit = initial_credit;
            loop {
                while credit == 0 {
                    match control_receiver.blocking_recv() {
                        Some(DownloadCommand::Credit(chunks)) => {
                            credit = credit.saturating_add(usize::from(chunks.get()));
                        }
                        Some(DownloadCommand::Cancel) | None => {
                            state.blocking_lock().downloads.remove(&transfer_id);
                            return;
                        }
                    }
                }
                let mut bytes = vec![0u8; chunk_len.get() as usize];
                let mut filled = 0usize;
                while filled < bytes.len() {
                    match stream.read(&mut bytes[filled..]) {
                        Ok(0) => break,
                        Ok(read) => filled += read,
                        Err(error) => {
                            let _ = sender.blocking_send(Err(unavailable(error)));
                            state.blocking_lock().downloads.remove(&transfer_id);
                            return;
                        }
                    }
                }
                bytes.truncate(filled);
                if bytes.is_empty() {
                    state.blocking_lock().downloads.remove(&transfer_id);
                    return;
                }
                let final_chunk = u64::from(index) + 1 == chunk_count;
                let digest = Digest::hash(&bytes);
                let chunk = match ArtifactChunk::new(
                    transfer_id,
                    artifact.artifact_id.clone(),
                    index,
                    bytes,
                    digest,
                    final_chunk,
                ) {
                    Ok(chunk) => chunk,
                    Err(error) => {
                        let _ = sender.blocking_send(Err(invalid_domain(error)));
                        state.blocking_lock().downloads.remove(&transfer_id);
                        return;
                    }
                };
                if sender.blocking_send(Ok(chunk)).is_err() || final_chunk {
                    state.blocking_lock().downloads.remove(&transfer_id);
                    return;
                }
                credit -= 1;
                index = match index.checked_add(1) {
                    Some(value) => value,
                    None => {
                        state.blocking_lock().downloads.remove(&transfer_id);
                        return;
                    }
                };
            }
        });
        Ok((response_artifact, Box::pin(ReceiverStream::new(receiver))))
    }

    fn incoming_path(&self, transfer: TransferId) -> PathBuf {
        self.root.join("incoming").join(format!("{transfer}.part"))
    }

    fn record_path(&self, transfer: TransferId) -> PathBuf {
        self.root.join("records").join(format!("{transfer}.cbor"))
    }

    fn artifact_path(&self, artifact: &ArtifactId) -> PathBuf {
        self.root
            .join("artifacts")
            .join(format!("{}.cbor", artifact.as_str()))
    }

    async fn persist_record(&self, record: &DurableTransfer) -> Result<(), LiveError> {
        let bytes = super::ledger::encode_cbor(record).map_err(live_error)?;
        let path = self.record_path(record.upload.manifest.transfer_id);
        let dir = self.root.join("records");
        spawn_io(move || persist_atomic(dir, path, bytes)).await
    }

    async fn persist_artifact(&self, artifact: &DurableArtifact) -> Result<(), LiveError> {
        let bytes = super::ledger::encode_cbor(artifact).map_err(live_error)?;
        let path = self.artifact_path(&artifact.artifact.artifact_id);
        let dir = self.root.join("artifacts");
        spawn_io(move || persist_atomic(dir, path, bytes)).await
    }

    /// Sole mutator of one transfer. The state lock is taken only to publish
    /// the result; fsync and `.await` run without it.
    async fn exclusive(&self, transfer: TransferId) -> TransferTurn {
        loop {
            match admit(&self.busy, transfer) {
                Admit::Held(turn) => return turn,
                Admit::Wait(waiter) => {
                    let _ = waiter.await;
                }
            }
        }
    }
}

/// In-flight transfer ids. std mutex so `Drop` can release a slot on a
/// runtime thread without `block_on`. Waiters are oneshot senders so
/// registration finishes inside the lock: a `MutexGuard` is `!Send` and
/// must not be captured by the async state machine.
type TransferGate = std::sync::Mutex<BTreeMap<TransferId, Vec<oneshot::Sender<()>>>>;

fn lock_gate(
    gate: &TransferGate,
) -> std::sync::MutexGuard<'_, BTreeMap<TransferId, Vec<oneshot::Sender<()>>>> {
    gate.lock().unwrap_or_else(|poison| poison.into_inner())
}

enum Admit {
    Held(TransferTurn),
    Wait(oneshot::Receiver<()>),
}

/// `Held` owns the slot. `Wait` is already registered, so a release cannot
/// land between unlock and the first poll (oneshot buffers the wake).
fn admit(gate: &Arc<TransferGate>, transfer: TransferId) -> Admit {
    let mut busy = lock_gate(gate);
    if let Some(waiters) = busy.get_mut(&transfer) {
        waiters.retain(|waiter| !waiter.is_closed());
        let (sender, receiver) = oneshot::channel();
        waiters.push(sender);
        Admit::Wait(receiver)
    } else {
        busy.insert(transfer, Vec::new());
        Admit::Held(TransferTurn {
            busy: Arc::clone(gate),
            transfer,
        })
    }
}

struct TransferTurn {
    busy: Arc<TransferGate>,
    transfer: TransferId,
}

impl Drop for TransferTurn {
    fn drop(&mut self) {
        let mut busy = lock_gate(&self.busy);
        if let Some(waiters) = busy.remove(&self.transfer) {
            for waiter in waiters {
                let _ = waiter.send(());
            }
        }
    }
}

async fn spawn_io<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, LiveError> + Send + 'static,
) -> Result<T, LiveError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(unavailable)?
}

fn create_incoming(path: PathBuf, byte_len: u64) -> Result<(), LiveError> {
    let file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(path)
        .map_err(unavailable)?;
    file.set_len(byte_len).map_err(unavailable)?;
    file.sync_all().map_err(unavailable)?;
    Ok(())
}

fn write_chunk_bytes(path: PathBuf, offset: u64, bytes: Vec<u8>) -> Result<(), LiveError> {
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(unavailable)?;
    file.seek(SeekFrom::Start(offset)).map_err(unavailable)?;
    file.write_all(&bytes).map_err(unavailable)?;
    file.sync_data().map_err(unavailable)?;
    Ok(())
}

fn read_chunk_digest(path: PathBuf, offset: u64, len: usize) -> Result<Digest, LiveError> {
    let mut file = File::open(path).map_err(unavailable)?;
    file.seek(SeekFrom::Start(offset)).map_err(unavailable)?;
    let mut existing = vec![0u8; len];
    file.read_exact(&mut existing).map_err(unavailable)?;
    Ok(Digest::hash(&existing))
}

fn remove_incoming(path: PathBuf) -> Result<(), LiveError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(unavailable(error)),
    }
}

fn persist_atomic(dir: PathBuf, path: PathBuf, bytes: Vec<u8>) -> Result<(), LiveError> {
    let temporary = dir.join(format!(".{}.tmp", Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(unavailable)?;
    file.write_all(&bytes).map_err(unavailable)?;
    file.sync_all().map_err(unavailable)?;
    fs::rename(temporary, path).map_err(unavailable)?;
    File::open(dir)
        .and_then(|directory| directory.sync_all())
        .map_err(unavailable)
}

/// Hashes `path` once and leaves the handle at byte 0 for the copy.
fn hash_file_rewind(path: &Path) -> Result<(File, u64, Digest), LiveError> {
    let mut file = File::open(path).map_err(unavailable)?;
    let mut hasher = blake3::Hasher::new();
    let mut byte_len = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(unavailable)?;
        if read == 0 {
            break;
        }
        byte_len += read as u64;
        hasher.update(&buffer[..read]);
    }
    file.seek(SeekFrom::Start(0)).map_err(unavailable)?;
    Ok((file, byte_len, Digest::new(*hasher.finalize().as_bytes())))
}

/// The published record of `blob`, which carries `manifest`'s bytes on `lane`.
fn durable_artifact(
    manifest: &TransferManifest,
    blob: BlobRef,
    lane: LaneId,
) -> Result<DurableArtifact, LiveError> {
    let artifact_id = ArtifactId::new(format!(
        "artifact:{}:{}",
        manifest.session_id,
        blob.digest.hex()
    ))
    .map_err(invalid_domain)?;
    let artifact = ArtifactRef::new(odin_domain::huginn::ArtifactRefInit {
        artifact_id,
        session_id: manifest.session_id,
        lane_id: lane,
        kind: manifest.kind,
        display_name: manifest.display_name.clone(),
        media_type: manifest.media_type.clone(),
        byte_len: blob.byte_len,
        content_digest: blob.digest,
    })
    .map_err(invalid_domain)?;
    Ok(DurableArtifact {
        manifest: manifest.clone(),
        blob,
        artifact,
    })
}

fn transfer_error(code: &str, message: &str) -> LiveError {
    LiveError::Transfer {
        code: code.to_owned(),
        message: message.to_owned(),
    }
}
fn operation_conflict() -> LiveError {
    transfer_error(
        "command_id_reuse",
        "command ID is already bound to another transfer operation",
    )
}

fn not_found(kind: &str, id: String) -> LiveError {
    LiveError::NotFound {
        object_kind: kind.to_owned(),
        object_id: id,
    }
}

fn invalid_domain(error: impl std::fmt::Display) -> LiveError {
    LiveError::InvalidRequest {
        code: "invalid_transfer".to_owned(),
        message: error.to_string(),
    }
}

fn unavailable(cause: impl std::fmt::Display) -> LiveError {
    LiveError::unavailable("transfer_store", cause)
}

#[cfg(test)]
mod tests {

    use std::num::{NonZeroU16, NonZeroU32};
    use std::sync::Arc;

    use async_trait::async_trait;
    use odin_domain::huginn::{
        ArtifactDirection, ArtifactKind, ArtifactReadRequest, DeviceId, LiveError, LiveSessionId,
        ModelName, ProviderName, SessionEpoch, SessionManifest, TransferChunk, TransferManifest,
        TransferManifestInit, TransferStatus, UploadManifest,
    };
    use odin_domain::{Digest, LaneId, NodeId, ProjectId, SeatId, SliceId};
    use tokio_stream::StreamExt;
    use uuid::Uuid;

    use super::super::lane_artifacts::{
        LaneArtifact, LaneArtifactPort, LaneEgressStream, LaneTransferBridge,
    };
    use super::super::ledger::fs::FsLiveLedger;
    use super::super::ledger::{BlobKind, BlobRef, LiveLedger};
    use super::{TransferLaneResolver, TransferManager};

    struct FixedLane(LaneId);

    #[async_trait]
    impl TransferLaneResolver for FixedLane {
        async fn lane_for(&self, _: &TransferManifest) -> Result<LaneId, LiveError> {
            Ok(self.0.clone())
        }
    }

    struct AcceptLane;

    #[async_trait]
    impl LaneArtifactPort for AcceptLane {
        async fn publish(&self, _: LaneArtifact) -> Result<(), LiveError> {
            Ok(())
        }

        async fn subscribe(&self, _: &LaneId) -> Result<LaneEgressStream, LiveError> {
            Err(LiveError::unavailable(
                "unused",
                "the fixture has no egress",
            ))
        }
    }

    /// A session, its ledger and a transfer manager over one directory.
    struct Fixture {
        root: tempfile::TempDir,
        session: LiveSessionId,
        ledger: Arc<FsLiveLedger>,
        manager: TransferManager,
    }

    impl Fixture {
        async fn new() -> Self {
            let root = tempfile::tempdir().expect("tempdir");
            let session =
                LiveSessionId::parse("00000000-0000-4000-8000-00000000e6a5").expect("session");
            let ledger = Arc::new(FsLiveLedger::open(root.path().join("ledger")).expect("ledger"));
            ledger
                .create_session(SessionManifest {
                    session_id: session,
                    seat_id: SeatId::new("seat:transfer").expect("seat"),
                    slice_id: SliceId::new("slice:transfer").expect("slice"),
                    project_id: ProjectId::new("project:transfer").expect("project"),
                    provider: ProviderName::new("fixture").expect("provider"),
                    model: ModelName::new("fixture-model").expect("model"),
                    title: None,
                    target_node: NodeId::new("node:transfer").expect("node"),
                    open_tab: false,
                    workload: None,
                    served_revision: None,
                    harness: None,
                })
                .await
                .expect("session");
            let mut fixture = Self {
                root,
                session,
                ledger,
                manager: unreachable_manager(),
            };
            fixture.manager = fixture.reopen();
            fixture
        }

        /// A manager over the same directory, as after a restart.
        fn reopen(&self) -> TransferManager {
            TransferManager::open(
                self.root.path().join("transfers"),
                self.ledger.clone(),
                Arc::new(FixedLane(LaneId::new("lane.transfer").expect("lane"))),
                Arc::new(LaneTransferBridge::new(Arc::new(AcceptLane))),
            )
            .expect("transfers")
        }

        /// An upload of `bytes` in `chunk_len`-byte chunks under a fresh transfer id.
        fn upload(&self, bytes: &[u8], chunk_len: u32) -> Upload {
            let transfer_id =
                odin_domain::huginn::TransferId::new(Uuid::new_v4()).expect("transfer");
            let manifest = TransferManifest::new(TransferManifestInit {
                transfer_id,
                session_id: self.session,
                kind: ArtifactKind::File,
                direction: ArtifactDirection::DeviceToSession,
                display_name: "note.txt".to_owned(),
                media_type: "text/plain".to_owned(),
                byte_len: bytes.len() as u64,
                chunk_len: NonZeroU32::new(chunk_len).expect("chunk"),
                content_digest: Digest::hash(bytes),
            })
            .expect("manifest");
            let chunks = bytes
                .chunks(chunk_len as usize)
                .enumerate()
                .map(|(index, part)| {
                    TransferChunk::new(index as u32, part.to_vec(), Digest::hash(part))
                        .expect("chunk")
                })
                .collect();
            Upload {
                transfer_id,
                manifest: UploadManifest {
                    manifest,
                    source_device: DeviceId::new(Uuid::new_v4()).expect("device"),
                },
                chunks,
            }
        }

        async fn publish(&self, upload: &Upload) -> odin_domain::huginn::ArtifactRef {
            self.manager
                .begin(upload.manifest.clone())
                .await
                .expect("begin");
            for chunk in &upload.chunks {
                self.manager
                    .write_chunk(upload.transfer_id, chunk.clone())
                    .await
                    .expect("chunk");
            }
            self.manager
                .commit(upload.transfer_id)
                .await
                .expect("commit")
        }
    }

    struct Upload {
        transfer_id: odin_domain::huginn::TransferId,
        manifest: UploadManifest,
        chunks: Vec<TransferChunk>,
    }

    /// The manager `Fixture::new` replaces before returning; it needs a ledger that exists first.
    fn unreachable_manager() -> TransferManager {
        let root = tempfile::tempdir().expect("tempdir");
        let ledger = Arc::new(FsLiveLedger::open(root.path().join("ledger")).expect("ledger"));
        TransferManager::open(
            root.path().join("transfers"),
            ledger,
            Arc::new(FixedLane(LaneId::new("lane.unused").expect("lane"))),
            Arc::new(LaneTransferBridge::new(Arc::new(AcceptLane))),
        )
        .expect("transfers")
    }

    async fn read_all(
        manager: &TransferManager,
        artifact: &odin_domain::huginn::ArtifactRef,
        first_chunk: u32,
    ) -> Result<Vec<u8>, LiveError> {
        let (_, mut stream) = manager
            .read(ArtifactReadRequest {
                artifact_id: artifact.artifact_id.clone(),
                first_chunk,
                initial_credit: NonZeroU16::new(8).expect("credit"),
            })
            .await?;
        let mut got = Vec::new();
        while let Some(chunk) = stream.next().await {
            got.extend(chunk?.bytes);
        }
        Ok(got)
    }

    fn transfer_code(error: LiveError) -> String {
        transfer_failure(error).0
    }

    fn transfer_failure(error: LiveError) -> (String, String) {
        match error {
            LiveError::Transfer { code, message } => (code, message),
            other => panic!("expected a transfer error, got {other:?}"),
        }
    }

    /// The transfer futures cross threads; this fails to compile if one stops being `Send`.
    #[allow(dead_code)]
    fn transfer_futures_are_send(
        manager: &TransferManager,
        id: odin_domain::huginn::TransferId,
        upload: UploadManifest,
        chunk: TransferChunk,
        command: odin_domain::CommandId,
    ) {
        fn assert_send<T: Send>(_: T) {}
        assert_send(manager.exclusive(id));
        assert_send(manager.begin(upload));
        assert_send(manager.write_chunk(id, chunk));
        assert_send(manager.commit(id));
        assert_send(manager.cancel(command, id));
    }

    /// Commit hashes the incoming file once, copies that handle, and a second
    /// commit returns the published artifact without writing it again.
    #[tokio::test]
    async fn commit_publishes_the_hashed_bytes_and_a_second_commit_noops() {
        let fixture = Fixture::new().await;
        let bytes = b"hello-transfer".to_vec();
        let upload = fixture.upload(&bytes, 64);
        let artifact = fixture.publish(&upload).await;
        let again = fixture
            .manager
            .commit(upload.transfer_id)
            .await
            .expect("second commit");
        assert_eq!(artifact, again);
        assert_eq!(artifact.content_digest, Digest::hash(&bytes));
        let mut stream = fixture
            .ledger
            .read_blob(&BlobRef {
                session_id: fixture.session,
                epoch: SessionEpoch::new(1),
                kind: BlobKind::Transfer,
                digest: Digest::hash(&bytes),
                byte_len: bytes.len() as u64,
            })
            .await
            .expect("blob");
        let mut got = Vec::new();
        std::io::Read::read_to_end(&mut stream, &mut got).expect("read");
        assert_eq!(got, bytes);
    }

    #[tokio::test]
    async fn a_repeated_declaration_or_chunk_is_idempotent_and_a_conflicting_one_is_refused() {
        let fixture = Fixture::new().await;
        let upload = fixture.upload(b"abcdefgh", 4);
        let id = upload.transfer_id;
        fixture
            .manager
            .begin(upload.manifest.clone())
            .await
            .expect("begin");
        fixture
            .manager
            .begin(upload.manifest.clone())
            .await
            .expect("same manifest again");

        let other = fixture.upload(b"zzzzzzzz", 4);
        let mut rebound = other.manifest.clone();
        rebound.manifest = TransferManifest {
            transfer_id: id,
            ..other.manifest.manifest.clone()
        };
        let error = fixture
            .manager
            .begin(rebound)
            .await
            .expect_err("another manifest");
        assert_eq!(transfer_code(error), "transfer_conflict");

        fixture
            .manager
            .write_chunk(id, upload.chunks[0].clone())
            .await
            .expect("chunk");
        fixture
            .manager
            .write_chunk(id, upload.chunks[0].clone())
            .await
            .expect("same chunk again");
        let other_bytes =
            TransferChunk::new(0, b"WXYZ".to_vec(), Digest::hash(b"WXYZ")).expect("chunk");
        let error = fixture
            .manager
            .write_chunk(id, other_bytes)
            .await
            .expect_err("other bytes");
        assert_eq!(transfer_code(error), "chunk_conflict");

        let error = fixture
            .manager
            .commit(id)
            .await
            .expect_err("one chunk missing");
        assert_eq!(transfer_code(error), "incomplete");
    }

    #[tokio::test]
    async fn a_cancel_is_final_until_publication_and_a_command_id_binds_one_transfer() {
        let fixture = Fixture::new().await;
        let published = fixture.upload(b"kept", 4);
        fixture.publish(&published).await;
        let command = odin_domain::CommandId::new("command:cancel").expect("command");
        let error = fixture
            .manager
            .cancel(command.clone(), published.transfer_id)
            .await
            .expect_err("published content is immutable");
        assert_eq!(transfer_code(error), "already_published");

        let dropped = fixture.upload(b"dropped", 4);
        fixture
            .manager
            .begin(dropped.manifest.clone())
            .await
            .expect("begin");
        let status = fixture
            .manager
            .cancel(command.clone(), dropped.transfer_id)
            .await;
        assert_eq!(status.expect("cancel"), TransferStatus::Cancelled);
        let again = fixture
            .manager
            .cancel(command.clone(), dropped.transfer_id)
            .await;
        assert_eq!(
            again.expect("the same command is idempotent"),
            TransferStatus::Cancelled
        );

        let elsewhere = fixture.upload(b"elsewhere", 4);
        fixture
            .manager
            .begin(elsewhere.manifest.clone())
            .await
            .expect("begin");
        let error = fixture
            .manager
            .cancel(command, elsewhere.transfer_id)
            .await
            .expect_err("a command id belongs to one transfer");
        assert_eq!(transfer_code(error), "command_id_reuse");
    }

    #[tokio::test]
    async fn a_published_artifact_streams_back_whole_and_survives_a_restart() {
        let fixture = Fixture::new().await;
        let bytes = b"0123456789abcdefghij".to_vec();
        let upload = fixture.upload(&bytes, 8);
        let artifact = fixture.publish(&upload).await;

        assert_eq!(
            read_all(&fixture.manager, &artifact, 0)
                .await
                .expect("whole"),
            bytes
        );
        assert_eq!(
            read_all(&fixture.manager, &artifact, 1)
                .await
                .expect("from chunk 1"),
            bytes[8..]
        );
        let error = read_all(&fixture.manager, &artifact, 3)
            .await
            .expect_err("past the last chunk");
        assert_eq!(transfer_code(error), "chunk_range");

        let restarted = fixture.reopen();
        assert_eq!(
            restarted
                .commit(upload.transfer_id)
                .await
                .expect("committed again"),
            artifact
        );
        assert_eq!(
            read_all(&restarted, &artifact, 0)
                .await
                .expect("after restart"),
            bytes
        );
    }
}
