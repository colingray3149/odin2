pub mod registry;
pub mod request;
pub mod stream;

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::Duration;

use async_trait::async_trait;
use odin_domain::huginn::{
    ArtifactKind, ArtifactRef, HuginnProtocolError, RenderGateway, RenderId, RenderKind,
    RenderManifest, RenderManifestInit, RenderRequest, RenderState, RenderStatus,
    RenderStatusStream,
};
use odin_domain::{CommandId, Digest};
use time::OffsetDateTime;
use tokio::sync::{mpsc, watch, Semaphore};
use tokio::time::Instant;
use uuid::Uuid;

pub use registry::{
    RegisteredRenderer, RenderInput, Renderer, RendererDescriptor, RendererRegistry,
};
pub use request::{CopyRenderer, FileRenderSource, RenderSourceResolver, SvgSanitizingRenderer};

use crate::config::RenderLimits as ServiceRenderLimits;
use crate::files::roots::{
    file_conflict, file_limit, file_not_found, file_unavailable, invalid_file, map_domain,
};

#[derive(Clone, Debug)]
pub struct VerifiedRender {
    pub render_id: RenderId,
    pub request: RenderRequest,
    pub path: PathBuf,
    pub kind: RenderKind,
    pub media_type: String,
    pub byte_len: u64,
    pub content_digest: Digest,
}

#[async_trait]
pub trait RenderPublisher: Send + Sync {
    async fn publish_render(
        &self,
        render: VerifiedRender,
    ) -> Result<ArtifactRef, HuginnProtocolError>;
}

#[derive(Clone)]
pub struct HuginnRenderService {
    inner: Arc<Inner>,
}

struct Inner {
    registry: RendererRegistry,
    sources: Arc<dyn RenderSourceResolver>,
    publisher: Arc<dyn RenderPublisher>,
    root: PathBuf,
    limits: ServiceRenderLimits,
    jobs: RwLock<BTreeMap<RenderId, Arc<RenderJob>>>,
    commands: Mutex<BTreeMap<CommandId, RenderId>>,
    queue: mpsc::Sender<RenderId>,
    permits: Arc<Semaphore>,
}

struct RenderJob {
    request: RenderRequest,
    status: watch::Sender<RenderStatus>,
}

impl HuginnRenderService {
    pub fn new(
        root: impl AsRef<Path>,
        limits: ServiceRenderLimits,
        registry: RendererRegistry,
        sources: Arc<dyn RenderSourceResolver>,
        publisher: Arc<dyn RenderPublisher>,
    ) -> Result<Self, HuginnProtocolError> {
        let root = prepare_private_root(root.as_ref())?;
        let (queue, receiver) = mpsc::channel(limits.queue_depth.get());
        let inner = Arc::new(Inner {
            registry,
            sources,
            publisher,
            root,
            permits: Arc::new(Semaphore::new(limits.max_concurrent_renders.get())),
            limits,
            jobs: RwLock::new(BTreeMap::new()),
            commands: Mutex::new(BTreeMap::new()),
            queue,
        });
        tokio::runtime::Handle::try_current()
            .map_err(|_| file_unavailable("render-runtime"))?
            .spawn(run_scheduler(Arc::downgrade(&inner), receiver));
        Ok(Self { inner })
    }

    /// Publishes changed job metadata and returns the number of changed objects.
    /// Unchanged jobs keep their revision.
    pub fn publish_jobs(
        &self,
        read_model: &crate::read_model::MaterializedReadModel,
        observed_at: OffsetDateTime,
    ) -> Result<usize, String> {
        use odin_domain::huginn::{
            Freshness, FreshnessState, ObjectKind, ObjectRef, ObjectSnapshot, Revision,
            RevisionSource,
        };
        let jobs: Vec<(RenderId, Arc<RenderJob>)> = self
            .inner
            .jobs
            .read()
            .map_err(|_| "render jobs lock is poisoned".to_owned())?
            .iter()
            .map(|(id, job)| (*id, Arc::clone(job)))
            .collect();
        let mut changed = 0;
        for (render_id, job) in jobs {
            let status = job.status.borrow().clone();
            let value = serde_json::json!({
                "renderId": render_id,
                "commandId": status.command_id,
                "renderer": job.request.renderer,
                "rendererVersion": job.request.renderer_version,
                "state": status.state,
                "manifest": status.manifest,
                "diagnostic": status.diagnostic,
            });
            let object = ObjectRef {
                kind: ObjectKind::Render,
                id: render_id.to_string(),
            };
            let current = read_model.get(&object).map_err(|error| error.to_string())?;
            if current
                .as_ref()
                .is_some_and(|current| current.value == value)
            {
                continue;
            }
            let revision = current.map_or(1, |current| current.revision.get().saturating_add(1));
            let encoded = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
            read_model
                .upsert(ObjectSnapshot {
                    object,
                    revision: Revision::new(revision),
                    revision_source: RevisionSource::Kernel,
                    freshness: Freshness {
                        state: FreshnessState::Fresh,
                        observed_at,
                        source_updated_at: None,
                        stale_after_seconds: None,
                    },
                    content_digest: Digest::hash(&encoded),
                    value,
                })
                .map_err(|error| error.to_string())?;
            changed += 1;
        }
        Ok(changed)
    }

    async fn enqueue(&self, request: RenderRequest) -> Result<RenderStatus, HuginnProtocolError> {
        request.validate().map_err(map_domain)?;
        if request.limits.max_output_bytes.get() > self.inner.limits.max_render_bytes.get() {
            return Err(file_limit("render-output-bytes"));
        }
        self.inner
            .registry
            .resolve(&request.renderer, &request.renderer_version)?;

        if let Some(render_id) = self
            .inner
            .commands
            .lock()
            .map_err(|_| file_unavailable("render-commands"))?
            .get(&request.command_id)
            .copied()
        {
            let job = self.job(&render_id)?;
            if job.request != request {
                return Err(file_conflict(
                    "commandIdReuse",
                    "render command id is already bound to a different request",
                ));
            }
            let status = job.status.borrow().clone();
            return Ok(status);
        }

        let render_id = RenderId::new(Uuid::new_v4()).map_err(map_domain)?;
        let status = RenderStatus {
            render_id,
            command_id: request.command_id.clone(),
            state: RenderState::Queued,
            manifest: None,
            diagnostic: None,
        };
        let (status_tx, _) = watch::channel(status.clone());
        let job = Arc::new(RenderJob {
            request: request.clone(),
            status: status_tx,
        });
        self.inner
            .jobs
            .write()
            .map_err(|_| file_unavailable("render-jobs"))?
            .insert(render_id, job);
        self.inner
            .commands
            .lock()
            .map_err(|_| file_unavailable("render-commands"))?
            .insert(request.command_id.clone(), render_id);
        if self.inner.queue.try_send(render_id).is_err() {
            self.inner
                .jobs
                .write()
                .map_err(|_| file_unavailable("render-jobs"))?
                .remove(&render_id);
            self.inner
                .commands
                .lock()
                .map_err(|_| file_unavailable("render-commands"))?
                .remove(&request.command_id);
            return Err(file_limit("render-queue"));
        }
        Ok(status)
    }

    fn job(&self, render_id: &RenderId) -> Result<Arc<RenderJob>, HuginnProtocolError> {
        job_handle(&self.inner, render_id)
    }
}

#[async_trait]
impl RenderGateway for HuginnRenderService {
    async fn request_render(
        &self,
        request: RenderRequest,
    ) -> Result<RenderStatus, HuginnProtocolError> {
        self.enqueue(request).await
    }

    async fn render_status(
        &self,
        render_id: RenderId,
    ) -> Result<RenderStatus, HuginnProtocolError> {
        let job = self.job(&render_id)?;
        let status = job.status.borrow().clone();
        Ok(status)
    }

    async fn watch_render(
        &self,
        render_id: RenderId,
    ) -> Result<RenderStatusStream, HuginnProtocolError> {
        Ok(stream::status_stream(
            self.job(&render_id)?.status.subscribe(),
        ))
    }
}

async fn run_scheduler(inner: Weak<Inner>, mut receiver: mpsc::Receiver<RenderId>) {
    while let Some(render_id) = receiver.recv().await {
        let Some(inner) = inner.upgrade() else {
            return;
        };
        let permits = inner.permits.clone();
        let Ok(permit) = permits.acquire_owned().await else {
            return;
        };
        let weak = Arc::downgrade(&inner);
        tokio::spawn(async move {
            let _permit = permit;
            if let Some(inner) = weak.upgrade() {
                execute_job(inner, render_id).await;
            }
        });
    }
}

fn job_handle(inner: &Inner, render_id: &RenderId) -> Result<Arc<RenderJob>, HuginnProtocolError> {
    inner
        .jobs
        .read()
        .map_err(|_| file_unavailable("render-jobs"))?
        .get(render_id)
        .cloned()
        .ok_or_else(|| file_not_found("render", render_id.to_string()))
}

async fn execute_job(inner: Arc<Inner>, render_id: RenderId) {
    let Ok(job) = job_handle(&inner, &render_id) else {
        // The job record is unreachable, so no status channel remains to report
        // through; no successful outcome may be fabricated in its place.
        return;
    };
    job.status.send_replace(RenderStatus {
        render_id,
        command_id: job.request.command_id.clone(),
        state: RenderState::Rendering,
        manifest: None,
        diagnostic: None,
    });
    let timeout = Duration::from_millis(
        u64::try_from(inner.limits.timeout.whole_milliseconds()).unwrap_or(u64::MAX),
    );
    // One absolute deadline for the whole job; nothing below grants more time.
    let result = match Instant::now().checked_add(timeout) {
        Some(deadline) => run_job(&inner, render_id, &job.request, deadline).await,
        None => Err(JobFailure {
            error: file_unavailable("render-deadline-out-of-range"),
            cleanup: None,
        }),
    };
    let status = match result {
        Ok(manifest) => RenderStatus {
            render_id,
            command_id: job.request.command_id.clone(),
            state: RenderState::Completed,
            manifest: Some(manifest),
            diagnostic: None,
        },
        Err(failure) => RenderStatus {
            render_id,
            command_id: job.request.command_id.clone(),
            state: failure.state(),
            manifest: None,
            diagnostic: Some(bounded_diagnostic(failure.diagnostic())),
        },
    };
    job.status.send_replace(status);
}

/// Cleanup errors force Failed status because staging files remain on disk.
struct JobFailure {
    error: HuginnProtocolError,
    cleanup: Option<std::io::Error>,
}

impl JobFailure {
    fn state(&self) -> RenderState {
        if self.cleanup.is_some() {
            RenderState::Failed
        } else {
            rejection_state(&self.error)
        }
    }

    fn diagnostic(&self) -> String {
        match &self.cleanup {
            None => self.error.to_string(),
            Some(cleanup) => format!(
                "{}; staging directory was left in place: cleanup failed ({:?})",
                self.error,
                cleanup.kind()
            ),
        }
    }
}

/// Reached only while nothing was handed to the publisher: the job's own work
/// ran past the deadline, so it must not publish.
fn deadline_exceeded() -> HuginnProtocolError {
    file_unavailable("render-deadline-before-publication")
}

/// The deadline fired while the publisher held the render, so the artifact may
/// or may not exist.
fn publication_unknown() -> HuginnProtocolError {
    file_unavailable("render-publication-outcome-unknown")
}

fn before_deadline(deadline: Instant) -> Result<(), HuginnProtocolError> {
    if Instant::now() < deadline {
        Ok(())
    } else {
        Err(deadline_exceeded())
    }
}

/// Awaits `work` up to `deadline`. Synchronous work inside `work` cannot be
/// interrupted, so a success that only arrives after the deadline is discarded
/// instead of being treated as in time.
async fn until<T>(
    deadline: Instant,
    work: impl Future<Output = Result<T, HuginnProtocolError>>,
) -> Result<T, HuginnProtocolError> {
    match tokio::time::timeout_at(deadline, work).await {
        Ok(Ok(value)) => before_deadline(deadline).map(|()| value),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(deadline_exceeded()),
    }
}

// Not an await: the work stays owned by the calling job until it returns, so a
// deadline cannot report the job ended while this work can still run.
fn blocking<T>(work: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(work)
        }
        _ => work(),
    }
}

async fn run_job(
    inner: &Inner,
    render_id: RenderId,
    request: &RenderRequest,
    deadline: Instant,
) -> Result<RenderManifest, JobFailure> {
    let mut staging = StagingDirectory::new(inner.root.join(render_id.to_string()));
    match produce(inner, render_id, request, deadline, &mut staging).await {
        Ok(manifest) => Ok(manifest),
        Err(error) => Err(JobFailure {
            error,
            cleanup: blocking(|| staging.release()).err(),
        }),
    }
}

async fn produce(
    inner: &Inner,
    render_id: RenderId,
    request: &RenderRequest,
    deadline: Instant,
    staging: &mut StagingDirectory,
) -> Result<RenderManifest, HuginnProtocolError> {
    let registered = inner
        .registry
        .resolve(&request.renderer, &request.renderer_version)?;
    let input = until(deadline, inner.sources.resolve(&request.source)).await?;
    if !registered.descriptor.accepts(&input.media_type) {
        return Err(invalid_file(
            "renderer does not declare the source media type",
        ));
    }
    blocking(|| staging.create())?;
    let part = staging.path.join("output.part");
    until(
        deadline,
        registered
            .executor
            .render(input, request.parameters.clone(), request.limits, &part),
    )
    .await?;
    let verified = verify_output(
        &part,
        registered.descriptor.output_kind,
        &registered.descriptor.output_media_type,
        request
            .limits
            .max_output_bytes
            .get()
            .min(inner.limits.max_render_bytes.get()),
    )?;
    let output = staging.path.join("output");
    blocking(|| -> Result<(), HuginnProtocolError> {
        std::fs::set_permissions(&part, std::fs::Permissions::from_mode(0o444))
            .map_err(|_| file_unavailable("render-output-mode"))?;
        std::fs::rename(&part, &output).map_err(|_| file_unavailable("render-output-publish"))?;
        File::open(&staging.path)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| file_unavailable("render-output-sync"))?;
        Ok(())
    })?;

    // The last point at which the original deadline can still stop publication.
    before_deadline(deadline)?;
    // From here the publisher may read `output` and may have published even if
    // the call errors or the deadline cuts it off, so staging is kept as evidence.
    staging.keep();
    let published = tokio::time::timeout_at(
        deadline,
        inner.publisher.publish_render(VerifiedRender {
            render_id,
            request: request.clone(),
            path: output,
            kind: registered.descriptor.output_kind,
            media_type: registered.descriptor.output_media_type.clone(),
            byte_len: verified.byte_len,
            content_digest: verified.digest,
        }),
    )
    .await
    .map_err(|_| publication_unknown())?;
    let artifact = published?;
    if artifact.kind != ArtifactKind::Render(registered.descriptor.output_kind)
        || artifact.media_type != registered.descriptor.output_media_type
        || artifact.byte_len != verified.byte_len
        || artifact.content_digest != verified.digest
    {
        return Err(file_conflict(
            "renderArtifact",
            "publisher returned an artifact that does not match verified render output",
        ));
    }
    RenderManifest::new(RenderManifestInit {
        render_id,
        command_id: request.command_id.clone(),
        renderer: request.renderer.clone(),
        renderer_version: request.renderer_version.clone(),
        kind: registered.descriptor.output_kind,
        media_type: registered.descriptor.output_media_type,
        byte_len: verified.byte_len,
        content_digest: verified.digest,
        artifact_id: artifact.artifact_id,
        completed_at: OffsetDateTime::now_utc(),
    })
    .map_err(map_domain)
}

struct VerifiedOutput {
    byte_len: u64,
    digest: Digest,
}

fn verify_output(
    path: &Path,
    kind: RenderKind,
    media_type: &str,
    maximum: u64,
) -> Result<VerifiedOutput, HuginnProtocolError> {
    if !kind.media_type_is_valid(media_type)
        || matches!(media_type, "text/html" | "application/xhtml+xml")
    {
        return Err(invalid_file("renderer emitted undeclared or active media"));
    }
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| file_unavailable("render-output-stat"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(invalid_file("renderer output is not a regular file"));
    }
    if metadata.len() > maximum {
        return Err(file_limit("render-output-bytes"));
    }
    if kind == RenderKind::SanitizedSvg {
        let capacity =
            usize::try_from(metadata.len()).map_err(|_| file_limit("render-output-bytes"))?;
        let bytes = std::fs::read(path).map_err(|_| file_unavailable("render-svg-read"))?;
        let sanitized = sanitize_svg(&bytes, capacity)?;
        if sanitized != bytes {
            let mut file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(path)
                .map_err(|_| file_unavailable("render-svg-open"))?;
            file.write_all(&sanitized)
                .and_then(|()| file.sync_all())
                .map_err(|_| file_unavailable("render-svg-write"))?;
        }
    }
    hash_output(path, maximum)
}

fn hash_output(path: &Path, maximum: u64) -> Result<VerifiedOutput, HuginnProtocolError> {
    let mut file = File::open(path).map_err(|_| file_unavailable("render-output-open"))?;
    let mut buffer = vec![0_u8; 256 * 1024];
    let mut byte_len = 0_u64;
    let mut hasher = blake3::Hasher::new();
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| file_unavailable("render-output-read"))?;
        if read == 0 {
            break;
        }
        byte_len = byte_len
            .checked_add(read as u64)
            .ok_or_else(|| file_limit("render-output-bytes"))?;
        if byte_len > maximum {
            return Err(file_limit("render-output-bytes"));
        }
        hasher.update(&buffer[..read]);
    }
    Ok(VerifiedOutput {
        byte_len,
        digest: Digest::new(hasher.finalize().into()),
    })
}

fn prepare_private_root(path: &Path) -> Result<PathBuf, HuginnProtocolError> {
    std::fs::create_dir_all(path).map_err(|_| file_unavailable("render-root-create"))?;
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| file_unavailable("render-root-stat"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(invalid_file("render root must be a real directory"));
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|_| file_unavailable("render-root-mode"))?;
    path.canonicalize()
        .map_err(|_| file_unavailable("render-root-canonicalize"))
}

/// The per-render directory this job created, identified by device and inode.
/// `release` removes it only if that same directory is still at the path and
/// returns the failure otherwise, so a settling job reports what it left behind.
/// A directory that already existed is never adopted, and a foreign file,
/// symlink or directory found at the path is never removed or replaced.
struct StagingDirectory {
    path: PathBuf,
    created: bool,
    identity: Option<(u64, u64)>,
}

impl StagingDirectory {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            created: false,
            identity: None,
        }
    }

    fn create(&mut self) -> Result<(), HuginnProtocolError> {
        std::fs::create_dir(&self.path).map_err(|_| file_unavailable("render-directory-create"))?;
        self.created = true;
        let metadata = std::fs::symlink_metadata(&self.path)
            .map_err(|_| file_unavailable("render-directory-stat"))?;
        self.identity = Some((metadata.dev(), metadata.ino()));
        std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| file_unavailable("render-directory-mode"))
    }

    /// Publication may have begun: the directory is evidence, not ours to remove.
    fn keep(&mut self) {
        self.created = false;
    }

    fn release(&mut self) -> std::io::Result<()> {
        if !std::mem::take(&mut self.created) {
            return Ok(());
        }
        let metadata = std::fs::symlink_metadata(&self.path)?;
        if !metadata.is_dir() || self.identity != Some((metadata.dev(), metadata.ino())) {
            return Err(std::io::Error::other(
                "staging path no longer names the directory this job created",
            ));
        }
        std::fs::remove_dir_all(&self.path)
    }
}

// Backstop for a job future dropped before it settles (runtime shutdown or a
// panic), where nobody can be told; settlement calls `release` and reports it.
impl Drop for StagingDirectory {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

fn rejection_state(error: &HuginnProtocolError) -> RenderState {
    match error {
        HuginnProtocolError::InvalidRequest { .. }
        | HuginnProtocolError::Unauthorized
        | HuginnProtocolError::NotFound { .. }
        | HuginnProtocolError::RevisionMismatch { .. }
        | HuginnProtocolError::Conflict { .. }
        | HuginnProtocolError::ResourceLimit { .. }
        | HuginnProtocolError::Unsupported { .. } => RenderState::Rejected,
        HuginnProtocolError::UnsupportedVersion { .. }
        | HuginnProtocolError::Unauthenticated
        | HuginnProtocolError::CursorExpired
        | HuginnProtocolError::Unavailable { .. } => RenderState::Failed,
    }
}

fn bounded_diagnostic(mut diagnostic: String) -> String {
    const MAX: usize = 2_048;
    if diagnostic.len() > MAX {
        let mut boundary = MAX;
        while !diagnostic.is_char_boundary(boundary) {
            boundary -= 1;
        }
        diagnostic.truncate(boundary);
    }
    diagnostic
}

pub fn sanitize_svg(bytes: &[u8], maximum: usize) -> Result<Vec<u8>, HuginnProtocolError> {
    if bytes.len() > maximum {
        return Err(file_limit("render-svg-bytes"));
    }
    let source = std::str::from_utf8(bytes).map_err(|_| invalid_file("SVG is not valid UTF-8"))?;
    if source.as_bytes().contains(&0) {
        return Err(invalid_file("SVG contains NUL"));
    }
    let mut output = String::with_capacity(source.len());
    let mut cursor = 0;
    let mut stack: Vec<String> = Vec::new();
    let mut saw_root = false;
    while cursor < source.len() {
        let Some(relative) = source[cursor..].find('<') else {
            output.push_str(&source[cursor..]);
            break;
        };
        let start = cursor + relative;
        output.push_str(&source[cursor..start]);
        if source[start..].starts_with("<!--") {
            let end = source[start + 4..]
                .find("-->")
                .ok_or_else(|| invalid_file("unterminated SVG comment"))?;
            cursor = start + 4 + end + 3;
            continue;
        }
        if source[start..].starts_with("<!") || source[start..].starts_with("<?") {
            return Err(invalid_file(
                "SVG declarations and processing instructions are prohibited",
            ));
        }
        let end = find_tag_end(source, start + 1)?;
        let parsed = parse_tag(&source[start + 1..end])?;
        let normalized = parsed.name.to_ascii_lowercase();
        if !allowed_svg_tag(&normalized) {
            return Err(invalid_file(
                "SVG contains an active or unsupported element",
            ));
        }
        if parsed.closing {
            let open = stack
                .pop()
                .ok_or_else(|| invalid_file("SVG has an unmatched closing element"))?;
            if open != normalized {
                return Err(invalid_file("SVG elements are not properly nested"));
            }
            output.push_str("</");
            output.push_str(&parsed.name);
            output.push('>');
        } else {
            if !saw_root {
                if normalized != "svg" {
                    return Err(invalid_file("SVG root element is missing"));
                }
                saw_root = true;
            }
            output.push('<');
            output.push_str(&parsed.name);
            for (name, value) in parsed.attributes {
                if let Some(value) = sanitized_attribute(&name, &value)? {
                    output.push(' ');
                    output.push_str(&name);
                    output.push_str("=\"");
                    output.push_str(&value);
                    output.push('"');
                }
            }
            if parsed.self_closing {
                output.push_str("/>");
            } else {
                output.push('>');
                stack.push(normalized);
            }
        }
        cursor = end + 1;
    }
    if !saw_root || !stack.is_empty() {
        return Err(invalid_file("SVG document is incomplete"));
    }
    if output.len() > maximum {
        return Err(file_limit("render-svg-bytes"));
    }
    Ok(output.into_bytes())
}

struct ParsedTag {
    name: String,
    closing: bool,
    self_closing: bool,
    attributes: Vec<(String, String)>,
}

fn find_tag_end(source: &str, mut cursor: usize) -> Result<usize, HuginnProtocolError> {
    let bytes = source.as_bytes();
    let mut quote = None;
    while cursor < bytes.len() {
        let byte = bytes[cursor];
        if let Some(expected) = quote {
            if byte == expected {
                quote = None;
            }
        } else if matches!(byte, b'\'' | b'"') {
            quote = Some(byte);
        } else if byte == b'>' {
            return Ok(cursor);
        }
        cursor += 1;
    }
    Err(invalid_file("unterminated SVG element"))
}

fn parse_tag(raw: &str) -> Result<ParsedTag, HuginnProtocolError> {
    let bytes = raw.as_bytes();
    let mut cursor = 0;
    skip_space(bytes, &mut cursor);
    let closing = bytes.get(cursor) == Some(&b'/');
    if closing {
        cursor += 1;
        skip_space(bytes, &mut cursor);
    }
    let name_start = cursor;
    while bytes.get(cursor).is_some_and(|byte| is_xml_name(*byte)) {
        cursor += 1;
    }
    if cursor == name_start {
        return Err(invalid_file("SVG element has no valid name"));
    }
    let name = raw[name_start..cursor].to_owned();
    let mut attributes = Vec::new();
    let mut self_closing = false;
    loop {
        skip_space(bytes, &mut cursor);
        if cursor == bytes.len() {
            break;
        }
        if bytes[cursor] == b'/' && cursor + 1 == bytes.len() {
            self_closing = true;
            cursor += 1;
            break;
        }
        if closing {
            return Err(invalid_file("closing SVG element carries attributes"));
        }
        let attr_start = cursor;
        while bytes.get(cursor).is_some_and(|byte| is_xml_name(*byte)) {
            cursor += 1;
        }
        if cursor == attr_start {
            return Err(invalid_file("SVG attribute has no valid name"));
        }
        let attr = raw[attr_start..cursor].to_owned();
        skip_space(bytes, &mut cursor);
        if bytes.get(cursor) != Some(&b'=') {
            return Err(invalid_file("SVG attribute has no value"));
        }
        cursor += 1;
        skip_space(bytes, &mut cursor);
        let quote = *bytes
            .get(cursor)
            .filter(|byte| matches!(**byte, b'\'' | b'"'))
            .ok_or_else(|| invalid_file("SVG attribute value is not quoted"))?;
        cursor += 1;
        let value_start = cursor;
        while bytes.get(cursor).is_some_and(|byte| *byte != quote) {
            if bytes[cursor] == b'<' {
                return Err(invalid_file("SVG attribute contains markup"));
            }
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&quote) {
            return Err(invalid_file("unterminated SVG attribute"));
        }
        let value = raw[value_start..cursor].to_owned();
        cursor += 1;
        attributes.push((attr, value));
    }
    if cursor != bytes.len() || (closing && self_closing) {
        return Err(invalid_file("invalid SVG element syntax"));
    }
    Ok(ParsedTag {
        name,
        closing,
        self_closing,
        attributes,
    })
}

fn skip_space(bytes: &[u8], cursor: &mut usize) {
    while bytes.get(*cursor).is_some_and(u8::is_ascii_whitespace) {
        *cursor += 1;
    }
}

fn is_xml_name(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b':' | b'.')
}

fn allowed_svg_tag(tag: &str) -> bool {
    matches!(
        tag,
        "svg"
            | "g"
            | "defs"
            | "symbol"
            | "use"
            | "path"
            | "rect"
            | "circle"
            | "ellipse"
            | "line"
            | "polyline"
            | "polygon"
            | "text"
            | "tspan"
            | "textpath"
            | "marker"
            | "pattern"
            | "clippath"
            | "mask"
            | "lineargradient"
            | "radialgradient"
            | "stop"
            | "filter"
            | "fegaussianblur"
            | "feoffset"
            | "feblend"
            | "fecolormatrix"
            | "fecomponenttransfer"
            | "fefunca"
            | "fefuncb"
            | "fefuncg"
            | "fefuncr"
            | "femerge"
            | "femergenode"
            | "title"
            | "desc"
    )
}

fn sanitized_attribute(name: &str, value: &str) -> Result<Option<String>, HuginnProtocolError> {
    let normalized = name.to_ascii_lowercase();
    if normalized.starts_with("on")
        || matches!(normalized.as_str(), "src" | "target" | "formaction")
    {
        return Ok(None);
    }
    if matches!(normalized.as_str(), "href" | "xlink:href") {
        return Ok(value.starts_with('#').then(|| value.to_owned()));
    }
    if normalized == "xmlns" {
        return if value == "http://www.w3.org/2000/svg" {
            Ok(Some(value.to_owned()))
        } else {
            Err(invalid_file("SVG declares an unexpected namespace"))
        };
    }
    if normalized == "xmlns:xlink" {
        return Ok(None);
    }
    if !allowed_svg_attribute(&normalized) {
        return Ok(None);
    }
    let lower_value = value.to_ascii_lowercase();
    if lower_value.contains("javascript:")
        || lower_value.contains("data:")
        || lower_value.contains("file:")
        || lower_value.contains("http:")
        || lower_value.contains("https:")
        || lower_value.contains("@import")
        || lower_value.contains("expression(")
        || lower_value.contains("behavior:")
    {
        return Ok(None);
    }
    if lower_value.contains("url(")
        && !(lower_value.trim().starts_with("url(#") && lower_value.trim().ends_with(')'))
    {
        return Ok(None);
    }
    Ok(Some(value.to_owned()))
}

fn allowed_svg_attribute(attribute: &str) -> bool {
    matches!(
        attribute,
        "id" | "class"
            | "style"
            | "version"
            | "viewbox"
            | "preserveaspectratio"
            | "x"
            | "y"
            | "x1"
            | "y1"
            | "x2"
            | "y2"
            | "cx"
            | "cy"
            | "r"
            | "rx"
            | "ry"
            | "width"
            | "height"
            | "d"
            | "points"
            | "pathlength"
            | "transform"
            | "fill"
            | "fill-opacity"
            | "fill-rule"
            | "stroke"
            | "stroke-width"
            | "stroke-opacity"
            | "stroke-linecap"
            | "stroke-linejoin"
            | "stroke-dasharray"
            | "stroke-dashoffset"
            | "opacity"
            | "color"
            | "display"
            | "visibility"
            | "clip-path"
            | "clip-rule"
            | "mask"
            | "filter"
            | "marker-start"
            | "marker-mid"
            | "marker-end"
            | "font-family"
            | "font-size"
            | "font-style"
            | "font-weight"
            | "text-anchor"
            | "dominant-baseline"
            | "dx"
            | "dy"
            | "rotate"
            | "textlength"
            | "lengthadjust"
            | "offset"
            | "stop-color"
            | "stop-opacity"
            | "gradientunits"
            | "gradienttransform"
            | "spreadmethod"
            | "patternunits"
            | "patterncontentunits"
            | "patterntransform"
            | "markerwidth"
            | "markerheight"
            | "markerunits"
            | "refx"
            | "refy"
            | "orient"
            | "filterunits"
            | "primitiveunits"
            | "stddeviation"
            | "result"
            | "in"
            | "in2"
            | "mode"
            | "type"
            | "values"
            | "tablevalues"
            | "slope"
            | "intercept"
            | "amplitude"
            | "exponent"
            | "k1"
            | "k2"
            | "k3"
            | "k4"
    )
}

#[cfg(test)]
mod publish_tests {
    use super::*;

    struct NoSource;
    #[async_trait]
    impl RenderSourceResolver for NoSource {
        async fn resolve(
            &self,
            _source: &odin_domain::huginn::ContentSource,
        ) -> Result<RenderInput, HuginnProtocolError> {
            Err(file_unavailable("fixture-source"))
        }
    }
    struct NoPublisher;
    #[async_trait]
    impl RenderPublisher for NoPublisher {
        async fn publish_render(
            &self,
            _render: VerifiedRender,
        ) -> Result<ArtifactRef, HuginnProtocolError> {
            Err(file_unavailable("fixture-publisher"))
        }
    }

    #[tokio::test]
    async fn render_jobs_reach_the_read_model_and_move_revision_on_change() {
        let root = tempfile::tempdir().unwrap();
        let service = HuginnRenderService::new(
            root.path().join("renders"),
            ServiceRenderLimits::default(),
            RendererRegistry::new(),
            Arc::new(NoSource),
            Arc::new(NoPublisher),
        )
        .unwrap();
        let read_model = crate::read_model::MaterializedReadModel::with_limits(
            16,
            32,
            OffsetDateTime::now_utc(),
        );
        assert_eq!(
            service
                .publish_jobs(&read_model, OffsetDateTime::now_utc())
                .unwrap(),
            0
        );
        let request = RenderRequest {
            command_id: CommandId::new("cmd-render-publish-1").unwrap(),
            source: odin_domain::huginn::ContentSource::Artifact(
                odin_domain::ArtifactId::new("fixture-artifact").unwrap(),
            ),
            renderer: odin_domain::huginn::RendererId::parse("copy").unwrap(),
            renderer_version: "1".to_owned(),
            parameters: serde_json::json!({}),
            limits: odin_domain::huginn::RenderLimits {
                max_output_bytes: std::num::NonZeroU64::new(1024).unwrap(),
                max_width_pixels: std::num::NonZeroU32::new(64).unwrap(),
                max_height_pixels: std::num::NonZeroU32::new(64).unwrap(),
                max_frames: std::num::NonZeroU32::new(1).unwrap(),
            },
        };
        let render_id = RenderId::new(Uuid::new_v4()).unwrap();
        let (status, _) = watch::channel(RenderStatus {
            render_id,
            command_id: request.command_id.clone(),
            state: RenderState::Queued,
            manifest: None,
            diagnostic: None,
        });
        service
            .inner
            .jobs
            .write()
            .unwrap()
            .insert(render_id, Arc::new(RenderJob { request, status }));
        let now = OffsetDateTime::now_utc();
        assert_eq!(service.publish_jobs(&read_model, now).unwrap(), 1);
        assert_eq!(
            service.publish_jobs(&read_model, now).unwrap(),
            0,
            "unchanged"
        );
        let object = odin_domain::huginn::ObjectRef {
            kind: odin_domain::huginn::ObjectKind::Render,
            id: render_id.to_string(),
        };
        let published = read_model.get(&object).unwrap().expect("render object");
        assert_eq!(published.value["state"], "queued");
        assert_eq!(published.value["renderer"], "copy");
        assert_eq!(published.revision.get(), 1);

        let job = service.job(&render_id).unwrap();
        job.status.send_modify(|status| {
            status.state = RenderState::Failed;
            status.diagnostic = Some("fixture failure".to_owned());
        });
        assert_eq!(service.publish_jobs(&read_model, now).unwrap(), 1);
        let published = read_model.get(&object).unwrap().unwrap();
        assert_eq!(published.value["state"], "failed");
        assert_eq!(published.revision.get(), 2);
    }
}
