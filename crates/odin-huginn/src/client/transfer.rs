use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::path::{Path, PathBuf};

use odin_domain::huginn::artifact::TransferManifestInit;
use odin_domain::huginn::{
    ArtifactChunk, ArtifactDirection, ArtifactKind, ArtifactRef, BinaryChunk, ContentSource,
    FileReadRequest, HuginnProtocolError, HuginnRequest, HuginnResponse, LiveClientRequest,
    LiveResponse, LiveServerMessage, LiveSessionId, RequestId, TransferChunk, TransferChunkRequest,
    TransferCreditRequest, TransferId, TransferManifest, TransferStatus, UploadManifest,
};
use odin_domain::{ArtifactId, CommandId, Digest};
use tokio::io::AsyncReadExt as _;

use super::api::{ColinRemoteClient, HuginnTransport, LiveConnection, TransportFrame};
use super::model::{io_error, ClientError, DeviceCredentialStore};

const TRANSFER_ATTEMPTS: usize = 3;
const DOWNLOAD_CREDIT_CHUNKS: NonZeroU16 = NonZeroU16::new(1).expect("one is non-zero");

#[derive(Clone, Debug)]
pub enum UploadSource {
    Bytes {
        display_name: String,
        media_type: String,
        data: Vec<u8>,
    },
    Path {
        display_name: String,
        media_type: String,
        path: PathBuf,
    },
}

impl UploadSource {
    fn metadata(&self) -> (&str, &str) {
        match self {
            Self::Bytes {
                display_name,
                media_type,
                ..
            }
            | Self::Path {
                display_name,
                media_type,
                ..
            } => (display_name, media_type),
        }
    }

    async fn digest_and_len(&self, chunk_len: usize) -> Result<(Digest, u64), ClientError> {
        match self {
            Self::Bytes { data, .. } => Ok((Digest::hash(data), data.len() as u64)),
            Self::Path { path, .. } => {
                let mut file = tokio::fs::File::open(path).await.map_err(io_error)?;
                let mut hasher = blake3::Hasher::new();
                let mut total = 0u64;
                let mut chunk = vec![0u8; chunk_len];
                loop {
                    let read = file.read(&mut chunk).await.map_err(io_error)?;
                    if read == 0 {
                        break;
                    }
                    total = total
                        .checked_add(read as u64)
                        .ok_or_else(|| ClientError::Limit("upload byte length".to_owned()))?;
                    hasher.update(&chunk[..read]);
                }
                Ok((Digest::new(*hasher.finalize().as_bytes()), total))
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct UploadTarget {
    pub session_id: LiveSessionId,
    pub kind: ArtifactKind,
    pub display_name: String,
    pub media_type: String,
    pub chunk_len: NonZeroU32,
}

pub trait DownloadSink: Send {
    fn begin(&mut self, byte_len: Option<u64>) -> Result<(), ClientError>;
    fn write_chunk(&mut self, offset: u64, bytes: &[u8]) -> Result<(), ClientError>;
    fn commit(&mut self, digest: Digest) -> Result<(), ClientError>;
}

#[derive(Clone, Debug)]
pub struct MemorySink {
    limit: u64,
    bytes: Vec<u8>,
    digest: Option<Digest>,
}

impl MemorySink {
    pub fn new(limit: u64) -> Self {
        Self {
            limit,
            bytes: Vec::new(),
            digest: None,
        }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn digest(&self) -> Option<Digest> {
        self.digest
    }
}

impl DownloadSink for MemorySink {
    fn begin(&mut self, byte_len: Option<u64>) -> Result<(), ClientError> {
        if byte_len.is_some_and(|len| len > self.limit) {
            return Err(ClientError::Limit("download memory sink".to_owned()));
        }
        self.bytes.clear();
        self.digest = None;
        Ok(())
    }

    fn write_chunk(&mut self, offset: u64, bytes: &[u8]) -> Result<(), ClientError> {
        if offset != self.bytes.len() as u64 {
            return Err(ClientError::InvalidInput(
                "download chunk offset is not contiguous".to_owned(),
            ));
        }
        let next = offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| ClientError::Limit("download memory sink".to_owned()))?;
        if next > self.limit {
            return Err(ClientError::Limit("download memory sink".to_owned()));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn commit(&mut self, digest: Digest) -> Result<(), ClientError> {
        self.digest = Some(digest);
        Ok(())
    }
}

#[derive(Debug)]
pub struct FileSink {
    final_path: PathBuf,
    temporary_path: PathBuf,
    file: Option<std::fs::File>,
    next_offset: u64,
}

impl FileSink {
    pub fn create(path: impl AsRef<Path>) -> Result<Self, ClientError> {
        let final_path = path.as_ref().to_path_buf();
        let parent = final_path.parent().ok_or_else(|| {
            ClientError::InvalidInput("download path has no parent directory".to_owned())
        })?;
        std::fs::create_dir_all(parent).map_err(io_error)?;
        let temporary_path = parent.join(format!(".huginn-{}.part", uuid::Uuid::new_v4()));
        Ok(Self {
            final_path,
            temporary_path,
            file: None,
            next_offset: 0,
        })
    }
}

impl DownloadSink for FileSink {
    fn begin(&mut self, _byte_len: Option<u64>) -> Result<(), ClientError> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        if self.temporary_path.exists() {
            std::fs::remove_file(&self.temporary_path).map_err(io_error)?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        self.file = Some(options.open(&self.temporary_path).map_err(io_error)?);
        self.next_offset = 0;
        Ok(())
    }

    fn write_chunk(&mut self, offset: u64, bytes: &[u8]) -> Result<(), ClientError> {
        use std::io::Write as _;
        if offset != self.next_offset {
            return Err(ClientError::InvalidInput(
                "download chunk offset is not contiguous".to_owned(),
            ));
        }
        self.file
            .as_mut()
            .ok_or_else(|| ClientError::InvalidInput("download sink was not begun".to_owned()))?
            .write_all(bytes)
            .map_err(io_error)?;
        self.next_offset = self
            .next_offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| ClientError::Limit("download file length".to_owned()))?;
        Ok(())
    }

    fn commit(&mut self, _digest: Digest) -> Result<(), ClientError> {
        let file = self
            .file
            .take()
            .ok_or_else(|| ClientError::InvalidInput("download sink was not begun".to_owned()))?;
        file.sync_all().map_err(io_error)?;
        std::fs::rename(&self.temporary_path, &self.final_path).map_err(io_error)
    }
}

impl Drop for FileSink {
    fn drop(&mut self) {
        self.file.take();
        let _ = std::fs::remove_file(&self.temporary_path);
    }
}

pub(crate) async fn upload<T, K>(
    client: &ColinRemoteClient<T, K>,
    source: UploadSource,
    target: UploadTarget,
) -> Result<ArtifactRef, ClientError>
where
    T: HuginnTransport,
    K: DeviceCredentialStore,
{
    let (source_name, source_media) = source.metadata();
    if source_name != target.display_name || source_media != target.media_type {
        return Err(ClientError::InvalidInput(
            "upload source and target metadata differ".to_owned(),
        ));
    }
    let (digest, byte_len) = source
        .digest_and_len(target.chunk_len.get() as usize)
        .await?;
    let transfer_id = TransferId::new(uuid::Uuid::new_v4())
        .map_err(|error| ClientError::InvalidInput(error.to_string()))?;
    let manifest = TransferManifest::new(TransferManifestInit {
        transfer_id,
        session_id: target.session_id,
        kind: target.kind,
        direction: ArtifactDirection::DeviceToSession,
        display_name: target.display_name,
        media_type: target.media_type,
        byte_len,
        chunk_len: target.chunk_len,
        content_digest: digest,
    })
    .map_err(|error| ClientError::InvalidInput(error.to_string()))?;
    let upload = UploadManifest {
        manifest,
        source_device: client.device_id()?,
    };

    let mut last_error = ClientError::ConnectionClosed;
    for attempt in 0..TRANSFER_ATTEMPTS {
        match upload_attempt(client, &source, &upload).await {
            Ok(artifact) => return Ok(artifact),
            Err(error) if attempt + 1 < TRANSFER_ATTEMPTS && retriable(&error) => {
                last_error = error;
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error)
}

async fn upload_attempt<T, K>(
    client: &ColinRemoteClient<T, K>,
    source: &UploadSource,
    upload: &UploadManifest,
) -> Result<ArtifactRef, ClientError>
where
    T: HuginnTransport,
    K: DeviceCredentialStore,
{
    let mut connection = client.connect().await?;
    let status = match connection
        .request_live(LiveClientRequest::BeginUpload {
            request_id: request_id()?,
            manifest: upload.clone(),
        })
        .await?
    {
        LiveResponse::Transfer(status) => status,
        _ => return Err(unexpected_response("BeginUpload")),
    };
    match status {
        TransferStatus::Declared | TransferStatus::Receiving => {
            send_source_chunks(
                &mut connection,
                upload.manifest.transfer_id,
                source,
                upload.manifest.chunk_len,
            )
            .await?;
        }
        TransferStatus::Verified | TransferStatus::Published => {}
        TransferStatus::Rejected | TransferStatus::Cancelled => {
            return Err(ClientError::Protocol(HuginnProtocolError::Conflict {
                code: "transferUnavailable".to_owned(),
                message: format!("upload transfer is {status:?}"),
            }));
        }
    }

    match connection
        .request_live(LiveClientRequest::CommitUpload {
            request_id: request_id()?,
            transfer_id: upload.manifest.transfer_id,
        })
        .await?
    {
        LiveResponse::Artifact(artifact) => {
            if artifact.content_digest != upload.manifest.content_digest
                || artifact.byte_len != upload.manifest.byte_len
                || artifact.session_id != upload.manifest.session_id
                || artifact.kind != upload.manifest.kind
            {
                return Err(ClientError::Protocol(HuginnProtocolError::Conflict {
                    code: "transferPublicationMismatch".to_owned(),
                    message: "published artifact does not match upload manifest".to_owned(),
                }));
            }
            Ok(artifact)
        }
        _ => Err(unexpected_response("CommitUpload")),
    }
}

async fn send_source_chunks<S, T>(
    connection: &mut LiveConnection<S, T>,
    transfer_id: TransferId,
    source: &UploadSource,
    chunk_len: NonZeroU32,
) -> Result<(), ClientError>
where
    S: TransportFrame,
    T: HuginnTransport<Socket = S>,
{
    match source {
        UploadSource::Bytes { data, .. } => {
            for (index, bytes) in data.chunks(chunk_len.get() as usize).enumerate() {
                let index = u32::try_from(index)
                    .map_err(|_| ClientError::Limit("upload chunk count".to_owned()))?;
                send_chunk(connection, transfer_id, index, bytes.to_vec()).await?;
            }
        }
        UploadSource::Path { path, .. } => {
            let mut file = tokio::fs::File::open(path).await.map_err(io_error)?;
            let mut bytes = vec![0u8; chunk_len.get() as usize];
            let mut index = 0u32;
            loop {
                let read = file.read(&mut bytes).await.map_err(io_error)?;
                if read == 0 {
                    break;
                }
                send_chunk(connection, transfer_id, index, bytes[..read].to_vec()).await?;
                index = index
                    .checked_add(1)
                    .ok_or_else(|| ClientError::Limit("upload chunk count".to_owned()))?;
            }
        }
    }
    Ok(())
}

async fn send_chunk<S, T>(
    connection: &mut LiveConnection<S, T>,
    transfer_id: TransferId,
    index: u32,
    bytes: Vec<u8>,
) -> Result<(), ClientError>
where
    S: TransportFrame,
    T: HuginnTransport<Socket = S>,
{
    let digest = Digest::hash(&bytes);
    let chunk = TransferChunk::new(index, bytes, digest)
        .map_err(|error| ClientError::InvalidInput(error.to_string()))?;
    connection
        .send_live(LiveClientRequest::UploadChunk {
            request: TransferChunkRequest { transfer_id, chunk },
        })
        .await
}

pub(crate) async fn download<T, K>(
    client: &ColinRemoteClient<T, K>,
    source: ContentSource,
    sink: &mut dyn DownloadSink,
) -> Result<Digest, ClientError>
where
    T: HuginnTransport,
    K: DeviceCredentialStore,
{
    match source {
        ContentSource::Artifact(artifact_id) => download_artifact(client, artifact_id, sink).await,
        ContentSource::File {
            root,
            relative,
            expected_revision,
        } => {
            let max_bytes = u64::try_from(client.limits().max_frame_bytes)
                .ok()
                .and_then(NonZeroU64::new)
                .ok_or_else(|| ClientError::Limit("download byte length".to_owned()))?;
            let request = FileReadRequest {
                root_id: root,
                relative_path: relative,
                expected_revision,
                range: None,
                max_bytes,
            };
            download_file(client, request, sink).await
        }
        ContentSource::BrowserDownload { .. } => {
            Err(ClientError::Unsupported("browser download fetch"))
        }
        ContentSource::SimulationOutput { .. } => {
            Err(ClientError::Unsupported("simulation output fetch"))
        }
    }
}

struct DownloadResume<'a> {
    metadata: &'a mut Option<ArtifactRef>,
    next_chunk: &'a mut u32,
    next_offset: &'a mut u64,
    hasher: &'a mut blake3::Hasher,
}

async fn download_artifact<T, K>(
    client: &ColinRemoteClient<T, K>,
    artifact_id: ArtifactId,
    sink: &mut dyn DownloadSink,
) -> Result<Digest, ClientError>
where
    T: HuginnTransport,
    K: DeviceCredentialStore,
{
    let mut metadata = None;
    let mut next_chunk = 0u32;
    let mut next_offset = 0u64;
    let mut hasher = blake3::Hasher::new();
    let mut last_error = ClientError::ConnectionClosed;

    for attempt in 0..TRANSFER_ATTEMPTS {
        let resume = DownloadResume {
            metadata: &mut metadata,
            next_chunk: &mut next_chunk,
            next_offset: &mut next_offset,
            hasher: &mut hasher,
        };
        let result = download_artifact_attempt(client, &artifact_id, sink, resume).await;
        match result {
            Ok(digest) => return Ok(digest),
            Err(error) if attempt + 1 < TRANSFER_ATTEMPTS && retriable(&error) => {
                last_error = error;
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error)
}

async fn download_artifact_attempt<T, K>(
    client: &ColinRemoteClient<T, K>,
    artifact_id: &ArtifactId,
    sink: &mut dyn DownloadSink,
    resume: DownloadResume<'_>,
) -> Result<Digest, ClientError>
where
    T: HuginnTransport,
    K: DeviceCredentialStore,
{
    let DownloadResume {
        metadata,
        next_chunk,
        next_offset,
        hasher,
    } = resume;
    let mut connection = client.connect().await?;
    let artifact = match connection
        .request_live(LiveClientRequest::FetchArtifact {
            request_id: request_id()?,
            artifact_id: artifact_id.clone(),
            first_chunk: *next_chunk,
        })
        .await?
    {
        LiveResponse::Artifact(artifact) => artifact,
        _ => return Err(unexpected_response("FetchArtifact")),
    };
    if &artifact.artifact_id != artifact_id {
        return Err(transfer_conflict(
            "artifactIdentity",
            "download metadata refers to a different artifact",
        ));
    }
    let expected = if let Some(expected) = metadata.as_ref() {
        if expected != &artifact {
            return Err(transfer_conflict(
                "artifactChanged",
                "download metadata changed while resuming",
            ));
        }
        expected.clone()
    } else {
        sink.begin(Some(artifact.byte_len))?;
        *metadata = Some(artifact.clone());
        artifact
    };
    if expected.byte_len == 0 {
        let digest = Digest::hash(&[]);
        if digest != expected.content_digest {
            return Err(transfer_conflict(
                "downloadDigest",
                "empty artifact digest does not match metadata",
            ));
        }
        sink.commit(digest)?;
        return Ok(digest);
    }

    let mut transfer_id = None;
    loop {
        match connection.next_live().await {
            Some(Ok(LiveServerMessage::ArtifactChunk(chunk))) => {
                verify_artifact_chunk(&chunk, &expected, *next_chunk)?;
                if let Some(active) = transfer_id {
                    if active != chunk.transfer_id {
                        return Err(transfer_conflict(
                            "transferIdentity",
                            "artifact chunks changed transfer identity",
                        ));
                    }
                } else {
                    transfer_id = Some(chunk.transfer_id);
                }

                let end = next_offset
                    .checked_add(chunk.bytes.len() as u64)
                    .ok_or_else(|| ClientError::Limit("download byte length".to_owned()))?;
                if end > expected.byte_len {
                    return Err(ClientError::Limit("download byte length".to_owned()));
                }
                sink.write_chunk(*next_offset, &chunk.bytes)?;
                hasher.update(&chunk.bytes);
                *next_offset = end;

                if chunk.final_chunk {
                    let digest = Digest::new(*hasher.finalize().as_bytes());
                    if *next_offset != expected.byte_len || digest != expected.content_digest {
                        return Err(transfer_conflict(
                            "downloadDigest",
                            "assembled artifact does not match its declared length and digest",
                        ));
                    }
                    sink.commit(digest)?;
                    return Ok(digest);
                }
                *next_chunk = next_chunk
                    .checked_add(1)
                    .ok_or_else(|| ClientError::Limit("download chunk count".to_owned()))?;
                connection
                    .send_live(LiveClientRequest::GrantDownloadCredit {
                        request: TransferCreditRequest {
                            command_id: credit_command_id(chunk.transfer_id, chunk.index)?,
                            transfer_id: chunk.transfer_id,
                            chunks: DOWNLOAD_CREDIT_CHUNKS,
                        },
                    })
                    .await?;
            }
            Some(Ok(LiveServerMessage::TransferStatus(
                TransferStatus::Rejected | TransferStatus::Cancelled,
            ))) => {
                return Err(transfer_conflict(
                    "transferUnavailable",
                    "artifact download was rejected or cancelled",
                ));
            }
            Some(Ok(_)) => {}
            Some(Err(error)) => return Err(error),
            None => return Err(ClientError::ConnectionClosed),
        }
    }
}

fn verify_artifact_chunk(
    chunk: &ArtifactChunk,
    artifact: &ArtifactRef,
    expected_index: u32,
) -> Result<(), ClientError> {
    if chunk.artifact_id != artifact.artifact_id || chunk.index != expected_index {
        return Err(transfer_conflict(
            "downloadChunk",
            "artifact chunk identity or index is not contiguous",
        ));
    }
    if chunk.bytes.is_empty() || Digest::hash(&chunk.bytes) != chunk.digest {
        return Err(transfer_conflict(
            "downloadDigest",
            "artifact chunk digest does not match its bytes",
        ));
    }
    Ok(())
}

async fn download_file<T, K>(
    client: &ColinRemoteClient<T, K>,
    request: FileReadRequest,
    sink: &mut dyn DownloadSink,
) -> Result<Digest, ClientError>
where
    T: HuginnTransport,
    K: DeviceCredentialStore,
{
    let mut last_error = ClientError::ConnectionClosed;
    for attempt in 0..TRANSFER_ATTEMPTS {
        sink.begin(None)?;
        match download_file_attempt(client, &request, sink).await {
            Ok(digest) => return Ok(digest),
            Err(error) if attempt + 1 < TRANSFER_ATTEMPTS && retriable(&error) => {
                last_error = error;
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error)
}

async fn download_file_attempt<T, K>(
    client: &ColinRemoteClient<T, K>,
    request: &FileReadRequest,
    sink: &mut dyn DownloadSink,
) -> Result<Digest, ClientError>
where
    T: HuginnTransport,
    K: DeviceCredentialStore,
{
    let mut connection = client.connect().await?;
    match connection
        .request(HuginnRequest::ReadFile(request.clone()))
        .await?
    {
        HuginnResponse::Ack => {}
        _ => return Err(unexpected_response("ReadFile")),
    }

    let mut next_offset = 0u64;
    let mut hasher = blake3::Hasher::new();
    loop {
        match connection.next().await {
            Some(Ok(odin_domain::huginn::HuginnMessage::BinaryChunk(chunk))) => {
                verify_download_chunk(&chunk, next_offset)?;
                let end = next_offset
                    .checked_add(chunk.bytes.len() as u64)
                    .ok_or_else(|| ClientError::Limit("download byte length".to_owned()))?;
                if end > request.max_bytes.get() {
                    return Err(ClientError::Limit("download byte length".to_owned()));
                }
                sink.write_chunk(chunk.offset, &chunk.bytes)?;
                hasher.update(&chunk.bytes);
                next_offset = end;
                if chunk.final_chunk {
                    let digest = Digest::new(*hasher.finalize().as_bytes());
                    sink.commit(digest)?;
                    return Ok(digest);
                }
            }
            Some(Ok(_)) => {}
            Some(Err(error)) => return Err(error),
            None => return Err(ClientError::ConnectionClosed),
        }
    }
}

fn verify_download_chunk(chunk: &BinaryChunk, expected_offset: u64) -> Result<(), ClientError> {
    if chunk.offset != expected_offset {
        return Err(transfer_conflict(
            "downloadOffset",
            "download chunk offset is not contiguous",
        ));
    }
    if !chunk.has_valid_digest() {
        return Err(transfer_conflict(
            "downloadDigest",
            "download chunk digest does not match its bytes",
        ));
    }
    Ok(())
}

fn request_id() -> Result<RequestId, ClientError> {
    RequestId::new(uuid::Uuid::new_v4())
        .map_err(|error| ClientError::InvalidInput(error.to_string()))
}

fn credit_command_id(transfer: TransferId, after_chunk: u32) -> Result<CommandId, ClientError> {
    CommandId::new(format!("download-credit:{transfer}:{after_chunk}"))
        .map_err(|error| ClientError::InvalidInput(error.to_string()))
}

fn retriable(error: &ClientError) -> bool {
    matches!(
        error,
        ClientError::ConnectionClosed | ClientError::Transport(_)
    )
}

fn unexpected_response(operation: &'static str) -> ClientError {
    transfer_conflict(
        "unexpectedResponse",
        &format!("unexpected response for {operation}"),
    )
}

fn transfer_conflict(code: &'static str, message: &str) -> ClientError {
    ClientError::Protocol(HuginnProtocolError::Conflict {
        code: code.to_owned(),
        message: message.to_owned(),
    })
}
