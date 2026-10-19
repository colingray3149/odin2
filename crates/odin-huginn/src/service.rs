use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use futures_util::StreamExt as _;
use odin_domain::huginn::{
    ArtifactReadRequest, ArtifactReadStream, ArtifactRef, CommandReceipt, ContentSource,
    ContentTicket, ContentTicketIssuer, ContentTicketRequest, DeviceId, FileEntryKind, FileGateway,
    FileReadRequest, HistoryPage, HistoryQuery, HuginnCommandPort, HuginnProtocolError,
    HuginnRequest, HuginnResponse, LiveError, LiveEventStream, LiveSessionId, LiveSessionSummary,
    OmpLivePlane, OpenSessionRequest, RenderGateway, SeatRoster, SessionListPage, SessionListQuery,
    SubscribeRequest, TerminalControlLeaseId, TerminalControlRequest, TerminalControlStatus,
    TerminalInput, TerminalResize, TerminalTargetStatus, TransferChunk, TransferId, TransferStatus,
    UploadManifest,
};
use odin_domain::{ArtifactId, CommandId, Digest};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::sync::Mutex;

use crate::config::{HuginnConfig, ValidatedHuginnConfig};
use crate::devices::DeviceTrustStore;
use crate::dispatch::AuthenticatedCommandPort;
use crate::private_network::TailnetVerifier;
use crate::router::{live_router_with_runtime, ContentTicketError, ContentTicketStore};
use crate::state::HuginnLiveState;

mod published_artifacts;

pub use published_artifacts::{BrowserArtifactKind, FsPublishedArtifactStore};

pub struct HuginnCommandPlane<C: ?Sized> {
    general: Arc<C>,
    live: Arc<dyn OmpLivePlane>,
}

impl<C: ?Sized> Clone for HuginnCommandPlane<C> {
    fn clone(&self) -> Self {
        Self {
            general: self.general.clone(),
            live: self.live.clone(),
        }
    }
}

impl<C: ?Sized> HuginnCommandPlane<C> {
    pub fn new(general: Arc<C>, live: Arc<dyn OmpLivePlane>) -> Self {
        Self { general, live }
    }

    pub fn general(&self) -> &Arc<C> {
        &self.general
    }

    pub fn live(&self) -> &Arc<dyn OmpLivePlane> {
        &self.live
    }
}

#[async_trait]
impl<C> HuginnCommandPort for HuginnCommandPlane<C>
where
    C: HuginnCommandPort + ?Sized,
{
    async fn execute(&self, request: HuginnRequest) -> Result<HuginnResponse, HuginnProtocolError> {
        match request {
            // Session tokens require the calling device, available only on the authenticated port.
            HuginnRequest::OpenSession(_) => Err(HuginnProtocolError::Unauthenticated),
            HuginnRequest::SessionCommand(command) => self
                .live
                .command(command)
                .await
                .map(HuginnResponse::Command)
                .map_err(crate::state::live_error_into_protocol),
            request => self.general.execute(request).await,
        }
    }
}

#[async_trait]
impl<C> AuthenticatedCommandPort for HuginnCommandPlane<C>
where
    C: AuthenticatedCommandPort + ?Sized,
{
    async fn execute_authenticated(
        &self,
        device: DeviceId,
        request: HuginnRequest,
    ) -> Result<HuginnResponse, HuginnProtocolError> {
        self.general.execute_authenticated(device, request).await
    }
}

#[async_trait]
impl<C> OmpLivePlane for HuginnCommandPlane<C>
where
    C: HuginnCommandPort + ?Sized,
{
    async fn terminal_snapshot(
        &self,
        session: odin_domain::huginn::LiveSessionId,
    ) -> Result<odin_domain::huginn::TerminalSnapshot, LiveError> {
        self.live.terminal_snapshot(session).await
    }

    async fn roster(&self) -> Result<SeatRoster, LiveError> {
        self.live.roster().await
    }

    async fn sessions(&self, query: SessionListQuery) -> Result<SessionListPage, LiveError> {
        self.live.sessions(query).await
    }

    async fn history(&self, query: HistoryQuery) -> Result<HistoryPage, LiveError> {
        self.live.history(query).await
    }

    async fn subscribe(&self, request: SubscribeRequest) -> Result<LiveEventStream, LiveError> {
        self.live.subscribe(request).await
    }

    async fn open_session(
        &self,
        request: OpenSessionRequest,
    ) -> Result<LiveSessionSummary, LiveError> {
        self.live.open_session(request).await
    }

    async fn open_session_owned(
        &self,
        request: OpenSessionRequest,
        cancellation: tokio::sync::watch::Receiver<bool>,
    ) -> (Result<LiveSessionSummary, LiveError>, bool) {
        self.live.open_session_owned(request, cancellation).await
    }

    async fn command(
        &self,
        command: odin_domain::huginn::LiveCommand,
    ) -> Result<CommandReceipt, LiveError> {
        self.live.command(command).await
    }

    async fn begin_upload(&self, manifest: UploadManifest) -> Result<TransferStatus, LiveError> {
        self.live.begin_upload(manifest).await
    }

    async fn upload_chunk(
        &self,
        transfer: TransferId,
        chunk: TransferChunk,
    ) -> Result<(), LiveError> {
        self.live.upload_chunk(transfer, chunk).await
    }

    async fn commit_upload(&self, transfer: TransferId) -> Result<ArtifactRef, LiveError> {
        self.live.commit_upload(transfer).await
    }

    async fn cancel_transfer(
        &self,
        command_id: CommandId,
        transfer: TransferId,
    ) -> Result<TransferStatus, LiveError> {
        self.live.cancel_transfer(command_id, transfer).await
    }

    async fn grant_download_credit(
        &self,
        command_id: CommandId,
        transfer: TransferId,
        chunks: NonZeroU16,
    ) -> Result<(), LiveError> {
        self.live
            .grant_download_credit(command_id, transfer, chunks)
            .await
    }

    async fn read_artifact(
        &self,
        request: ArtifactReadRequest,
    ) -> Result<(ArtifactRef, ArtifactReadStream), LiveError> {
        self.live.read_artifact(request).await
    }

    async fn acquire_terminal_control(
        &self,
        command_id: CommandId,
        device: DeviceId,
        request: TerminalControlRequest,
    ) -> Result<TerminalControlStatus, LiveError> {
        self.live
            .acquire_terminal_control(command_id, device, request)
            .await
    }

    async fn write_terminal(
        &self,
        command_id: CommandId,
        session: LiveSessionId,
        input: TerminalInput,
    ) -> Result<(), LiveError> {
        self.live.write_terminal(command_id, session, input).await
    }

    async fn resize_terminal(
        &self,
        command_id: CommandId,
        session: LiveSessionId,
        resize: TerminalResize,
    ) -> Result<(), LiveError> {
        self.live.resize_terminal(command_id, session, resize).await
    }

    async fn release_terminal_control(
        &self,
        command_id: CommandId,
        session: LiveSessionId,
        lease: TerminalControlLeaseId,
    ) -> Result<TerminalControlStatus, LiveError> {
        self.live
            .release_terminal_control(command_id, session, lease)
            .await
    }

    async fn bind_terminal_target(
        &self,
        zellij_session: String,
    ) -> Result<TerminalTargetStatus, LiveError> {
        self.live.bind_terminal_target(zellij_session).await
    }

    async fn unbind_terminal_target(&self) -> Result<TerminalTargetStatus, LiveError> {
        self.live.unbind_terminal_target().await
    }

    async fn terminal_target_status(&self) -> Result<TerminalTargetStatus, LiveError> {
        self.live.terminal_target_status().await
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExternalContentAlias {
    source: ContentSource,
    artifact_id: ArtifactId,
}

#[derive(Clone)]
pub struct FsExternalContentIndex {
    root: Arc<PathBuf>,
}

impl FsExternalContentIndex {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, HuginnProtocolError> {
        fs::create_dir_all(root.as_ref()).map_err(|_| unavailable_protocol("contentAliasRoot"))?;
        let root = root
            .as_ref()
            .canonicalize()
            .map_err(|_| unavailable_protocol("contentAliasRoot"))?;
        Ok(Self {
            root: Arc::new(root),
        })
    }

    pub fn register(
        &self,
        source: ContentSource,
        artifact_id: ArtifactId,
    ) -> Result<(), HuginnProtocolError> {
        if matches!(
            &source,
            ContentSource::Artifact(_) | ContentSource::File { .. }
        ) {
            return Err(invalid_protocol(
                "contentAliasSource",
                "only browser downloads and simulation outputs require aliases",
            ));
        }
        let alias = ExternalContentAlias {
            source: source.clone(),
            artifact_id,
        };
        let encoded = encode_content(&alias)?;
        let path = self.alias_path(&source)?;
        if path
            .try_exists()
            .map_err(|_| unavailable_protocol("contentAlias"))?
        {
            let existing: ExternalContentAlias = decode_content(
                &fs::read(&path).map_err(|_| unavailable_protocol("contentAlias"))?,
            )?;
            return if existing == alias {
                Ok(())
            } else {
                Err(HuginnProtocolError::Conflict {
                    code: "contentAliasReuse".to_owned(),
                    message: "content source already identifies another artifact".to_owned(),
                })
            };
        }
        let temporary = self.root.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|_| unavailable_protocol("contentAlias"))?;
        file.write_all(&encoded)
            .and_then(|()| file.sync_all())
            .map_err(|_| unavailable_protocol("contentAlias"))?;
        fs::rename(&temporary, &path).map_err(|_| unavailable_protocol("contentAlias"))?;
        File::open(self.root.as_ref())
            .and_then(|directory| directory.sync_all())
            .map_err(|_| unavailable_protocol("contentAlias"))
    }

    fn resolve(&self, source: &ContentSource) -> Result<ArtifactId, HuginnProtocolError> {
        let path = self.alias_path(source)?;
        let alias: ExternalContentAlias = decode_content(&fs::read(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                HuginnProtocolError::NotFound {
                    object_kind: "contentSource".to_owned(),
                    object_id: content_key(source),
                }
            } else {
                unavailable_protocol("contentAlias")
            }
        })?)?;
        if &alias.source != source {
            return Err(unavailable_protocol("contentAliasBinding"));
        }
        Ok(alias.artifact_id)
    }

    fn alias_path(&self, source: &ContentSource) -> Result<PathBuf, HuginnProtocolError> {
        let encoded = encode_content(source)?;
        Ok(self.root.join(format!(
            "{}.cbor",
            Digest::hash(&encoded).to_string().replace(':', "-")
        )))
    }
}

#[derive(Clone)]
struct IssuedTicket {
    request: ContentTicketRequest,
    device: DeviceId,
    ticket: ContentTicket,
}

pub struct HuginnContentTicketIssuer {
    store: ContentTicketStore,
    live: Arc<dyn OmpLivePlane>,
    files: Arc<crate::files::HuginnFileService>,
    artifacts: Arc<FsPublishedArtifactStore>,
    external: FsExternalContentIndex,
    ttl: Duration,
    max_commands: usize,
    commands: Mutex<BTreeMap<CommandId, IssuedTicket>>,
}

impl HuginnContentTicketIssuer {
    pub fn new(
        store: ContentTicketStore,
        live: Arc<dyn OmpLivePlane>,
        files: Arc<crate::files::HuginnFileService>,
        artifacts: Arc<FsPublishedArtifactStore>,
        external: FsExternalContentIndex,
        ttl: Duration,
        max_commands: usize,
    ) -> Result<Self, HuginnProtocolError> {
        if ttl.is_zero() || max_commands == 0 {
            return Err(invalid_protocol(
                "contentTicketLimits",
                "content ticket TTL and command capacity must be positive",
            ));
        }
        Ok(Self {
            store,
            live,
            files,
            artifacts,
            external,
            ttl,
            max_commands,
            commands: Mutex::new(BTreeMap::new()),
        })
    }

    async fn resolve(
        &self,
        source: &ContentSource,
        max_bytes: u64,
    ) -> Result<ResolvedContent, HuginnProtocolError> {
        match source {
            ContentSource::File {
                root,
                relative,
                expected_revision,
            } => {
                let metadata = self.files.stat(root, relative).await?;
                if metadata.entry_kind != FileEntryKind::File {
                    return Err(invalid_protocol(
                        "contentTicketFile",
                        "content ticket source is not a regular file",
                    ));
                }
                if metadata.byte_len > max_bytes {
                    return Err(HuginnProtocolError::ResourceLimit {
                        limit: "contentTicketBytes".to_owned(),
                    });
                }
                let media_type = metadata.media_type.ok_or_else(|| {
                    invalid_protocol(
                        "contentTicketMedia",
                        "content source has no declared media type",
                    )
                })?;
                let max_bytes = std::num::NonZeroU64::new(max_bytes).ok_or_else(|| {
                    invalid_protocol("contentTicketBytes", "content byte limit must be positive")
                })?;
                let mut stream = self
                    .files
                    .read(FileReadRequest {
                        root_id: root.clone(),
                        relative_path: relative.clone(),
                        expected_revision: *expected_revision,
                        range: None,
                        max_bytes,
                    })
                    .await?;
                let mut bytes = Vec::with_capacity(
                    usize::try_from(metadata.byte_len)
                        .map_err(|_| unavailable_protocol("contentTicketBytes"))?,
                );
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk?;
                    if !chunk.has_valid_digest() || chunk.offset != bytes.len() as u64 {
                        return Err(unavailable_protocol("contentTicketFileStream"));
                    }
                    if (bytes.len() as u64).saturating_add(chunk.bytes.len() as u64)
                        > max_bytes.get()
                    {
                        return Err(HuginnProtocolError::ResourceLimit {
                            limit: "contentTicketBytes".to_owned(),
                        });
                    }
                    bytes.extend_from_slice(&chunk.bytes);
                }
                if bytes.len() as u64 != metadata.byte_len {
                    return Err(unavailable_protocol("contentTicketFileStream"));
                }
                Ok(ResolvedContent {
                    media_type,
                    digest: Digest::hash(&bytes),
                    bytes,
                })
            }
            ContentSource::Artifact(artifact_id) => {
                self.resolve_artifact(artifact_id.clone(), max_bytes).await
            }
            ContentSource::BrowserDownload { .. } | ContentSource::SimulationOutput { .. } => {
                let external = self.external.clone();
                let source = source.clone();
                let artifact_id = tokio::task::spawn_blocking(move || external.resolve(&source))
                    .await
                    .map_err(|_| unavailable_protocol("contentAlias"))??;
                self.resolve_artifact(artifact_id, max_bytes).await
            }
        }
    }

    async fn resolve_artifact(
        &self,
        artifact_id: ArtifactId,
        max_bytes: u64,
    ) -> Result<ResolvedContent, HuginnProtocolError> {
        let artifacts = Arc::clone(&self.artifacts);
        let id = artifact_id.clone();
        let content = tokio::task::spawn_blocking(move || artifacts.read(&id, max_bytes))
            .await
            .map_err(|_| unavailable_protocol("publishedArtifactPayload"))??;
        if let Some(content) = content {
            return Ok(content);
        }
        let (artifact, mut stream) = self
            .live
            .read_artifact(ArtifactReadRequest {
                artifact_id: artifact_id.clone(),
                first_chunk: 0,
                initial_credit: NonZeroU16::MAX,
            })
            .await
            .map_err(crate::state::live_error_into_protocol)?;
        if artifact.artifact_id != artifact_id {
            return Err(unavailable_protocol("contentTicketArtifactBinding"));
        }
        if artifact.byte_len > max_bytes {
            return Err(HuginnProtocolError::ResourceLimit {
                limit: "contentTicketBytes".to_owned(),
            });
        }
        let mut bytes = Vec::with_capacity(
            usize::try_from(artifact.byte_len)
                .map_err(|_| unavailable_protocol("contentTicketBytes"))?,
        );
        let mut expected_index = 0_u32;
        let mut final_chunk = false;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(crate::state::live_error_into_protocol)?;
            if chunk.artifact_id != artifact.artifact_id
                || chunk.index != expected_index
                || Digest::hash(&chunk.bytes) != chunk.digest
                || final_chunk
            {
                return Err(unavailable_protocol("contentTicketArtifactStream"));
            }
            if (bytes.len() as u64).saturating_add(chunk.bytes.len() as u64) > max_bytes {
                return Err(HuginnProtocolError::ResourceLimit {
                    limit: "contentTicketBytes".to_owned(),
                });
            }
            final_chunk = chunk.final_chunk;
            bytes.extend_from_slice(&chunk.bytes);
            expected_index = expected_index
                .checked_add(1)
                .ok_or_else(|| unavailable_protocol("contentTicketArtifactStream"))?;
        }
        if !final_chunk
            || bytes.len() as u64 != artifact.byte_len
            || Digest::hash(&bytes) != artifact.content_digest
        {
            return Err(unavailable_protocol("contentTicketArtifactStream"));
        }
        Ok(ResolvedContent {
            media_type: artifact.media_type,
            digest: artifact.content_digest,
            bytes,
        })
    }
}

struct ResolvedContent {
    media_type: String,
    digest: Digest,
    bytes: Vec<u8>,
}

#[async_trait]
impl ContentTicketIssuer for HuginnContentTicketIssuer {
    async fn issue(
        &self,
        device: DeviceId,
        request: ContentTicketRequest,
    ) -> Result<ContentTicket, HuginnProtocolError> {
        let mut commands = self.commands.lock().await;
        let now = OffsetDateTime::now_utc();
        commands.retain(|_, issued| issued.ticket.expires_at > now);
        if let Some(existing) = commands.get(&request.command_id) {
            return if existing.request == request && existing.device == device {
                Ok(existing.ticket.clone())
            } else {
                Err(HuginnProtocolError::Conflict {
                    code: "contentTicketCommandReuse".to_owned(),
                    message: "command ID is already bound to another content ticket".to_owned(),
                })
            };
        }
        if commands.len() >= self.max_commands {
            return Err(HuginnProtocolError::ResourceLimit {
                limit: "contentTicketCommands".to_owned(),
            });
        }
        let content = self
            .resolve(&request.source, request.max_bytes.get())
            .await?;
        let byte_len = content.bytes.len() as u64;
        let issued_at = OffsetDateTime::now_utc();
        let ttl_seconds = i64::try_from(self.ttl.as_secs())
            .map_err(|_| unavailable_protocol("contentTicketTtl"))?;
        let ticket_id = self
            .store
            .issue_download(device, content.media_type.clone(), content.bytes)
            .map_err(ticket_error)?;
        let ticket = ContentTicket::new(
            ticket_id.to_string(),
            request.source.clone(),
            content.media_type,
            byte_len,
            content.digest,
            issued_at,
            issued_at + time::Duration::seconds(ttl_seconds),
        )
        .map_err(|_| unavailable_protocol("contentTicketEnvelope"))?;
        commands.insert(
            request.command_id.clone(),
            IssuedTicket {
                request,
                device,
                ticket: ticket.clone(),
            },
        );
        Ok(ticket)
    }
}

fn content_key(source: &ContentSource) -> String {
    encode_content(source)
        .map(|bytes| Digest::hash(&bytes).to_string())
        .unwrap_or_else(|_| "invalid".to_owned())
}

fn encode_content(value: &impl Serialize) -> Result<Vec<u8>, HuginnProtocolError> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map_err(|_| unavailable_protocol("contentAliasCodec"))?;
    Ok(bytes)
}

fn decode_content<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, HuginnProtocolError> {
    ciborium::from_reader(bytes).map_err(|_| unavailable_protocol("contentAliasCodec"))
}

fn ticket_error(error: ContentTicketError) -> HuginnProtocolError {
    match error {
        ContentTicketError::TooLarge | ContentTicketError::Capacity => {
            HuginnProtocolError::ResourceLimit {
                limit: "contentTicket".to_owned(),
            }
        }
        ContentTicketError::Unauthorized => HuginnProtocolError::Unauthorized,
        ContentTicketError::InvalidMediaType
        | ContentTicketError::LengthMismatch
        | ContentTicketError::DigestMismatch
        | ContentTicketError::WrongDirection
        | ContentTicketError::InvalidTicket => {
            invalid_protocol("contentTicket", "content ticket request is invalid")
        }
        ContentTicketError::NotFound => HuginnProtocolError::NotFound {
            object_kind: "contentTicket".to_owned(),
            object_id: "expired".to_owned(),
        },
        ContentTicketError::Poisoned => unavailable_protocol("contentTicketStore"),
    }
}

fn invalid_protocol(code: &str, message: &str) -> HuginnProtocolError {
    HuginnProtocolError::InvalidRequest {
        code: code.to_owned(),
        message: message.to_owned(),
    }
}

fn unavailable_protocol(code: &str) -> HuginnProtocolError {
    HuginnProtocolError::Unavailable {
        code: code.to_owned(),
    }
}

pub struct HuginnService<R, C, S, F, V, D, T> {
    config: ValidatedHuginnConfig,
    state: HuginnLiveState<R, C, S, F, V, D, T>,
    tickets: ContentTicketStore,
}

impl<R, C, S, F, V, D, T> HuginnService<R, C, S, F, V, D, T> {
    pub fn new(
        config: ValidatedHuginnConfig,
        state: HuginnLiveState<R, C, S, F, V, D, T>,
        tickets: ContentTicketStore,
    ) -> Self {
        Self {
            config,
            state,
            tickets,
        }
    }

    pub fn from_config(
        config: HuginnConfig,
        state: HuginnLiveState<R, C, S, F, V, D, T>,
        tickets: ContentTicketStore,
    ) -> Result<Self, crate::config::ConfigError> {
        Ok(Self::new(config.validate()?, state, tickets))
    }

    pub fn config(&self) -> &ValidatedHuginnConfig {
        &self.config
    }

    pub fn content_tickets(&self) -> ContentTicketStore {
        self.tickets.clone()
    }
}

impl<R, C, S, F, V, D, T> HuginnService<R, C, S, F, V, D, T>
where
    R: odin_domain::huginn::HuginnReadModel + Send + Sync + 'static,
    C: HuginnCommandPort + AuthenticatedCommandPort + OmpLivePlane + Send + Sync + 'static,
    S: odin_domain::huginn::HuginnStreamSource + Send + Sync + 'static,
    F: FileGateway + 'static,
    V: RenderGateway + 'static,
    D: DeviceTrustStore + 'static,
    T: TailnetVerifier + 'static,
{
    pub fn mount(self) -> Router {
        live_router_with_runtime(self.state, self.config.limits(), self.tickets)
    }

    pub async fn serve(self) -> std::io::Result<()> {
        let listener = tokio::net::TcpListener::bind(self.config.bind().address()).await?;
        self.serve_on(listener).await
    }

    /// Serves on a listener bound by the caller, so clients started before
    /// serving (odind's observer tabs) can already connect.
    pub async fn serve_on(self, listener: tokio::net::TcpListener) -> std::io::Result<()> {
        axum::serve(
            listener,
            self.mount()
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
    }
}

#[cfg(test)]
mod open_routing_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use odin_domain::huginn::{
        ArtifactReadRequest, ArtifactReadStream, ArtifactRef, CommandReceipt, HistoryPage,
        HistoryQuery, LiveError, LiveEventStream, LiveSessionId, LiveSessionSummary, SeatRoster,
        SessionListPage, SessionListQuery, SubscribeRequest, TransferChunk, TransferId,
        TransferStatus, UploadManifest,
    };
    use uuid::Uuid;

    use super::*;

    fn plane_unreached() -> LiveError {
        LiveError::Unavailable {
            code: "open routing probe".to_owned(),
        }
    }

    /// The device-less plane surface: only its open is interesting — every
    /// call must stay at zero while the ports under test refuse or forward.
    #[derive(Default)]
    struct UnreachedPlane {
        opens: AtomicUsize,
    }

    #[async_trait]
    impl OmpLivePlane for UnreachedPlane {
        async fn terminal_snapshot(
            &self,
            _session: odin_domain::huginn::LiveSessionId,
        ) -> Result<odin_domain::huginn::TerminalSnapshot, LiveError> {
            Err(plane_unreached())
        }

        async fn roster(&self) -> Result<SeatRoster, LiveError> {
            Err(plane_unreached())
        }

        async fn sessions(&self, _query: SessionListQuery) -> Result<SessionListPage, LiveError> {
            Err(plane_unreached())
        }

        async fn history(&self, _query: HistoryQuery) -> Result<HistoryPage, LiveError> {
            Err(plane_unreached())
        }

        async fn subscribe(
            &self,
            _request: SubscribeRequest,
        ) -> Result<LiveEventStream, LiveError> {
            Err(plane_unreached())
        }

        async fn open_session(
            &self,
            _request: OpenSessionRequest,
        ) -> Result<LiveSessionSummary, LiveError> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            Err(plane_unreached())
        }

        async fn command(
            &self,
            _command: odin_domain::huginn::LiveCommand,
        ) -> Result<CommandReceipt, LiveError> {
            Err(plane_unreached())
        }

        async fn begin_upload(
            &self,
            _manifest: UploadManifest,
        ) -> Result<TransferStatus, LiveError> {
            Err(plane_unreached())
        }

        async fn upload_chunk(
            &self,
            _transfer: TransferId,
            _chunk: TransferChunk,
        ) -> Result<(), LiveError> {
            Err(plane_unreached())
        }

        async fn commit_upload(&self, _transfer: TransferId) -> Result<ArtifactRef, LiveError> {
            Err(plane_unreached())
        }

        async fn cancel_transfer(
            &self,
            _command_id: odin_domain::CommandId,
            _transfer: TransferId,
        ) -> Result<TransferStatus, LiveError> {
            Err(plane_unreached())
        }

        async fn grant_download_credit(
            &self,
            _command_id: odin_domain::CommandId,
            _transfer: TransferId,
            _chunks: NonZeroU16,
        ) -> Result<(), LiveError> {
            Err(plane_unreached())
        }

        async fn read_artifact(
            &self,
            _request: ArtifactReadRequest,
        ) -> Result<(ArtifactRef, ArtifactReadStream), LiveError> {
            Err(plane_unreached())
        }

        async fn acquire_terminal_control(
            &self,
            _command_id: odin_domain::CommandId,
            _device: DeviceId,
            _request: odin_domain::huginn::TerminalControlRequest,
        ) -> Result<odin_domain::huginn::TerminalControlStatus, LiveError> {
            Err(plane_unreached())
        }

        async fn write_terminal(
            &self,
            _command_id: odin_domain::CommandId,
            _session: LiveSessionId,
            _input: odin_domain::huginn::TerminalInput,
        ) -> Result<(), LiveError> {
            Err(plane_unreached())
        }

        async fn resize_terminal(
            &self,
            _command_id: odin_domain::CommandId,
            _session: LiveSessionId,
            _resize: odin_domain::huginn::TerminalResize,
        ) -> Result<(), LiveError> {
            Err(plane_unreached())
        }

        async fn release_terminal_control(
            &self,
            _command_id: odin_domain::CommandId,
            _session: LiveSessionId,
            _lease: odin_domain::huginn::TerminalControlLeaseId,
        ) -> Result<odin_domain::huginn::TerminalControlStatus, LiveError> {
            Err(plane_unreached())
        }
    }

    /// The device-capable general port: records the device each open
    /// arrived with, answering exactly as odind's port would.
    #[derive(Default)]
    struct ProbeGeneral {
        authenticated_opens: Mutex<Vec<DeviceId>>,
    }

    #[async_trait]
    impl HuginnCommandPort for ProbeGeneral {
        async fn execute(
            &self,
            _request: HuginnRequest,
        ) -> Result<HuginnResponse, HuginnProtocolError> {
            Err(HuginnProtocolError::Unsupported {
                operation: "probe general device-less".to_owned(),
            })
        }
    }

    #[async_trait]
    impl AuthenticatedCommandPort for ProbeGeneral {
        async fn execute_authenticated(
            &self,
            device: DeviceId,
            request: HuginnRequest,
        ) -> Result<HuginnResponse, HuginnProtocolError> {
            if let HuginnRequest::OpenSession(_) = request {
                self.authenticated_opens.lock().unwrap().push(device);
                return Ok(HuginnResponse::Ack);
            }
            Err(HuginnProtocolError::Unsupported {
                operation: "probe general".to_owned(),
            })
        }
    }

    fn open_request() -> HuginnRequest {
        HuginnRequest::OpenSession(OpenSessionRequest {
            command_id: odin_domain::CommandId::new("plane-open").unwrap(),
            seat_id: odin_domain::SeatId::new("gungnir").unwrap(),
            project_id: odin_domain::ProjectId::new("research").unwrap(),
            slice_id: odin_domain::SliceId::new("slice:research").unwrap(),
            provider: odin_domain::huginn::ProviderName::new("fixture").unwrap(),
            model: odin_domain::huginn::ModelName::new("fixture-model").unwrap(),
            title: None,
            target_node: odin_domain::NodeId::new("laptop").unwrap(),
            open_tab: false,
            initial_prompt: None,
            workload: None,
            served_revision: None,
        })
    }

    #[tokio::test]
    async fn the_device_less_port_refuses_open_session() {
        let unreached = Arc::new(UnreachedPlane::default());
        let plane = HuginnCommandPlane::new(
            Arc::new(ProbeGeneral::default()),
            Arc::clone(&unreached) as Arc<dyn OmpLivePlane>,
        );
        let error = HuginnCommandPort::execute(&plane, open_request())
            .await
            .expect_err("the device-less port refused");
        assert_eq!(error, HuginnProtocolError::Unauthenticated);
        assert_eq!(unreached.opens.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn the_authenticated_port_carries_the_device_for_open_session() {
        let general = Arc::new(ProbeGeneral::default());
        let plane = HuginnCommandPlane::new(
            Arc::clone(&general),
            Arc::new(UnreachedPlane::default()) as Arc<dyn OmpLivePlane>,
        );
        let device = DeviceId::new(Uuid::new_v4()).unwrap();
        let answered =
            AuthenticatedCommandPort::execute_authenticated(&plane, device, open_request())
                .await
                .expect("the authenticated port answered");
        assert!(matches!(answered, HuginnResponse::Ack));
        assert_eq!(
            general.authenticated_opens.lock().unwrap().as_slice(),
            &[device]
        );
    }
}
