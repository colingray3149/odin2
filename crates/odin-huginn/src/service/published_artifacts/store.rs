use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};

use async_trait::async_trait;
use odin_domain::huginn::artifact::ArtifactRefInit;
use odin_domain::huginn::{
    ArtifactKind, ArtifactRef, BrowserSessionId, HuginnProtocolError, LiveSessionId,
};
use odin_domain::{ArtifactId, Digest, LaneId};

use crate::renders::{RenderPublisher, VerifiedRender};
use crate::streams::StreamRetentionLease;

use crate::service::{invalid_protocol, unavailable_protocol, ResolvedContent};

use super::pointer::{
    load_browser_pointer, persist_browser_pointer, recover_browser_pointers,
    replace_browser_artifact, retire_browser_pointer,
};
use super::publication::{
    payload_name, persist_payload, persist_payload_bytes, persist_published_record,
    read_published_record,
};
use super::retirement::BrowserArtifactTracker;
use super::{
    is_browser_retirement_resource_limit, BrowserArtifactKind, BrowserArtifactRetirement,
    PublishedArtifactRecord,
};

struct PublishPathParams {
    session_id: LiveSessionId,
    kind: ArtifactKind,
    display_name: String,
    media_type: String,
    byte_len: u64,
    content_digest: Digest,
    source: PathBuf,
}

#[derive(Clone)]
pub struct FsPublishedArtifactStore {
    root: Arc<PathBuf>,
    render_session: LiveSessionId,
    file_lane: LaneId,
    render_lane: LaneId,
    publication_lock: Arc<StdMutex<()>>,
    browser_artifacts: Arc<BrowserArtifactTracker>,
}

impl FsPublishedArtifactStore {
    pub fn open(
        root: impl AsRef<Path>,
        render_session: LiveSessionId,
        file_lane: LaneId,
        render_lane: LaneId,
    ) -> Result<Self, HuginnProtocolError> {
        fs::create_dir_all(root.as_ref().join("records"))
            .and_then(|()| fs::create_dir_all(root.as_ref().join("payloads")))
            .and_then(|()| fs::create_dir_all(root.as_ref().join("browser-pointers")))
            .map_err(|_| unavailable_protocol("publishedArtifactRoot"))?;
        let root = Arc::new(
            root.as_ref()
                .canonicalize()
                .map_err(|_| unavailable_protocol("publishedArtifactRoot"))?,
        );
        let publication_lock = Arc::new(StdMutex::new(()));
        let recovered_retirements = {
            let _guard = publication_lock
                .lock()
                .map_err(|_| unavailable_protocol("publishedArtifactLock"))?;
            recover_browser_pointers(root.as_ref())?
        };
        let browser_artifacts = BrowserArtifactTracker::start(
            root.clone(),
            publication_lock.clone(),
            recovered_retirements,
        )?;
        Ok(Self {
            root,
            render_session,
            file_lane,
            render_lane,
            publication_lock,
            browser_artifacts,
        })
    }

    async fn publish_path(
        &self,
        params: PublishPathParams,
    ) -> Result<ArtifactRef, HuginnProtocolError> {
        let root = self.root.as_ref().clone();
        let publication_lock = self.publication_lock.clone();
        let lane = match params.kind {
            ArtifactKind::File => self.file_lane.clone(),
            ArtifactKind::Render(_) => self.render_lane.clone(),
        };
        tokio::task::spawn_blocking(move || {
            let _guard = publication_lock
                .lock()
                .map_err(|_| unavailable_protocol("publishedArtifactLock"))?;
            let digest_text = params.content_digest.to_string();
            let digest_hex = digest_text
                .strip_prefix("blake3:")
                .ok_or_else(|| unavailable_protocol("publishedArtifactDigest"))?;
            let identity = serde_json::to_vec(&(
                params.session_id,
                params.kind,
                &params.display_name,
                &params.media_type,
                params.byte_len,
                params.content_digest,
            ))
            .map_err(|_| unavailable_protocol("publishedArtifactId"))?;
            let identity_text = Digest::hash(&identity).to_string();
            let identity_hex = identity_text
                .strip_prefix("blake3:")
                .ok_or_else(|| unavailable_protocol("publishedArtifactId"))?;
            let artifact_id = ArtifactId::new(format!("artifact:huginn:{identity_hex}"))
                .map_err(|_| unavailable_protocol("publishedArtifactId"))?;
            let artifact = ArtifactRef::new(ArtifactRefInit {
                artifact_id: artifact_id.clone(),
                session_id: params.session_id,
                lane_id: lane,
                kind: params.kind,
                display_name: params.display_name,
                media_type: params.media_type,
                byte_len: params.byte_len,
                content_digest: params.content_digest,
            })
            .map_err(|_| unavailable_protocol("publishedArtifactEnvelope"))?;
            let payload_name = format!("{digest_hex}.blob");
            let payload_path = root.join("payloads").join(&payload_name);
            persist_payload(
                &params.source,
                &payload_path,
                params.byte_len,
                params.content_digest,
            )?;
            let record = PublishedArtifactRecord {
                artifact: artifact.clone(),
                payload_name,
            };
            persist_published_record(&root, &record)?;
            Ok(artifact)
        })
        .await
        .map_err(|_| unavailable_protocol("publishedArtifactJoin"))?
    }

    /// Synchronously validates and durably publishes a bounded browser payload.
    ///
    /// Browser sessions have their own identity while artifact delivery remains
    /// scoped to this store's composing Huginn live session.
    pub fn publish_browser_artifact(
        &self,
        browser_session: BrowserSessionId,
        browser_kind: BrowserArtifactKind,
        display_name: String,
        media_type: String,
        content_digest: Digest,
        bytes: Vec<u8>,
    ) -> Result<ArtifactRef, HuginnProtocolError> {
        let byte_len = u64::try_from(bytes.len())
            .map_err(|_| unavailable_protocol("publishedArtifactBytes"))?;
        if Digest::hash(&bytes) != content_digest {
            return Err(invalid_protocol(
                "publishedArtifactDigest",
                "browser payload digest does not match its bytes",
            ));
        }
        if browser_kind == BrowserArtifactKind::Timeline && media_type != "application/x-ndjson" {
            return Err(invalid_protocol(
                "publishedArtifactMedia",
                "browser timelines require application/x-ndjson",
            ));
        }
        let (kind, lane) = match browser_kind {
            BrowserArtifactKind::Frame | BrowserArtifactKind::Screenshot => (
                ArtifactKind::Render(odin_domain::huginn::RenderKind::RasterImage),
                self.render_lane.clone(),
            ),
            BrowserArtifactKind::Download | BrowserArtifactKind::Timeline => {
                (ArtifactKind::File, self.file_lane.clone())
            }
        };
        let identity = serde_json::to_vec(&(
            "browser",
            browser_session,
            browser_kind,
            kind,
            &display_name,
            &media_type,
            byte_len,
            content_digest,
        ))
        .map_err(|_| unavailable_protocol("publishedArtifactId"))?;
        let identity_text = Digest::hash(&identity).to_string();
        let identity_hex = identity_text
            .strip_prefix("blake3:")
            .ok_or_else(|| unavailable_protocol("publishedArtifactId"))?;
        let artifact_id = ArtifactId::new(format!("artifact:huginn:{identity_hex}"))
            .map_err(|_| unavailable_protocol("publishedArtifactId"))?;
        let artifact = ArtifactRef::new(ArtifactRefInit {
            artifact_id,
            session_id: self.render_session,
            lane_id: lane,
            kind,
            display_name,
            media_type,
            byte_len,
            content_digest,
        })
        .map_err(|_| unavailable_protocol("publishedArtifactEnvelope"))?;
        let payload_name = payload_name(content_digest)?;
        let record = PublishedArtifactRecord {
            artifact: artifact.clone(),
            payload_name,
        };
        if matches!(
            browser_kind,
            BrowserArtifactKind::Frame | BrowserArtifactKind::Timeline
        ) {
            let mut drained = false;
            loop {
                let result = (|| {
                    let _guard = self
                        .publication_lock
                        .lock()
                        .map_err(|_| unavailable_protocol("publishedArtifactLock"))?;
                    self.browser_artifacts.ensure_retirement_healthy()?;
                    let retirements = replace_browser_artifact(
                        self.root.as_ref(),
                        browser_session,
                        browser_kind,
                        &record,
                        &bytes,
                        self.browser_artifacts.as_ref(),
                    )?;
                    if browser_kind == BrowserArtifactKind::Frame {
                        self.browser_artifacts.activate_frame(&record)?;
                    }
                    for retired in retirements {
                        self.browser_artifacts
                            .mark_retiring(BrowserArtifactRetirement {
                                browser_session,
                                kind: browser_kind,
                                record: retired,
                            })?;
                    }
                    Ok(())
                })();
                match result {
                    Err(error) if !drained && is_browser_retirement_resource_limit(&error) => {
                        self.browser_artifacts.flush()?;
                        drained = true;
                    }
                    Err(error) => return Err(error),
                    Ok(()) => break,
                }
            }
        } else {
            let _guard = self
                .publication_lock
                .lock()
                .map_err(|_| unavailable_protocol("publishedArtifactLock"))?;
            self.browser_artifacts.ensure_retirement_healthy()?;
            persist_payload_bytes(
                &bytes,
                &self.root.join("payloads").join(&record.payload_name),
                byte_len,
                content_digest,
            )?;
            persist_published_record(self.root.as_ref(), &record)?;
        }
        Ok(artifact)
    }

    /// Durably validates and publishes one bounded durable-feed frame
    /// payload. The artifact identity is deterministic
    /// per (session, tag, content), so a producer retrying after a partial
    /// failure republishes the identical record instead of duplicating or
    /// losing payload, and every replayed frame can resolve its content.
    pub async fn publish_feed_payload(
        &self,
        session: LiveSessionId,
        tag: &str,
        bytes: &[u8],
    ) -> Result<ArtifactRef, HuginnProtocolError> {
        let byte_len = u64::try_from(bytes.len())
            .map_err(|_| unavailable_protocol("publishedArtifactBytes"))?;
        let content_digest = Digest::hash(bytes);
        let identity = serde_json::to_vec(&("feed", session, tag, byte_len, content_digest))
            .map_err(|_| unavailable_protocol("publishedArtifactId"))?;
        let identity_text = Digest::hash(&identity).to_string();
        let identity_hex = identity_text
            .strip_prefix("blake3:")
            .ok_or_else(|| unavailable_protocol("publishedArtifactId"))?;
        let artifact_id = ArtifactId::new(format!("artifact:huginn:{identity_hex}"))
            .map_err(|_| unavailable_protocol("publishedArtifactId"))?;
        let artifact = ArtifactRef::new(ArtifactRefInit {
            artifact_id,
            session_id: session,
            lane_id: self.file_lane.clone(),
            kind: ArtifactKind::File,
            display_name: format!("feed-{tag}.json"),
            media_type: "application/json".to_owned(),
            byte_len,
            content_digest,
        })
        .map_err(|_| unavailable_protocol("publishedArtifactEnvelope"))?;
        let payload_name = payload_name(content_digest)?;
        let record = PublishedArtifactRecord {
            artifact: artifact.clone(),
            payload_name,
        };
        let root = self.root.as_ref().clone();
        let publication_lock = Arc::clone(&self.publication_lock);
        let bytes = bytes.to_vec();
        tokio::task::spawn_blocking(move || {
            let _guard = publication_lock
                .lock()
                .map_err(|_| unavailable_protocol("publishedArtifactLock"))?;
            persist_payload_bytes(
                &bytes,
                &root.join("payloads").join(&record.payload_name),
                byte_len,
                content_digest,
            )?;
            persist_published_record(&root, &record)?;
            Ok(artifact)
        })
        .await
        .map_err(|_| unavailable_protocol("publishedArtifactJoin"))?
    }

    /// Marks all transient frame publications for one browser session for
    /// retirement. Records and payloads remain readable until their last
    /// outbound-stream lease is dropped.
    pub fn retire_browser_session(
        &self,
        browser_session: BrowserSessionId,
    ) -> Result<(), HuginnProtocolError> {
        let mut drained = false;
        loop {
            let result = (|| {
                let _guard = self
                    .publication_lock
                    .lock()
                    .map_err(|_| unavailable_protocol("publishedArtifactLock"))?;
                self.browser_artifacts.ensure_retirement_healthy()?;
                for record in retire_browser_pointer(
                    self.root.as_ref(),
                    browser_session,
                    BrowserArtifactKind::Frame,
                    self.browser_artifacts.as_ref(),
                )? {
                    self.browser_artifacts
                        .mark_retiring(BrowserArtifactRetirement {
                            browser_session,
                            kind: BrowserArtifactKind::Frame,
                            record,
                        })?;
                }
                Ok(())
            })();
            match result {
                Err(error) if !drained && is_browser_retirement_resource_limit(&error) => {
                    self.browser_artifacts.flush()?;
                    drained = true;
                }
                Err(error) => return Err(error),
                Ok(()) => return Ok(()),
            }
        }
    }

    /// Retains the current browser frame while outbound stream items refer to
    /// it. Validation and lease acquisition are memory-only.
    pub fn lease_browser_artifact(
        &self,
        artifact_id: &ArtifactId,
    ) -> Result<Arc<dyn StreamRetentionLease>, HuginnProtocolError> {
        self.browser_artifacts
            .acquire_current(artifact_id)?
            .ok_or_else(|| {
                invalid_protocol(
                    "browserArtifactLease",
                    "artifact is not the current browser frame",
                )
            })
    }

    /// Acknowledges that the read model now points at `new_artifact_id`, making
    /// every predecessor timeline eligible for worker-thread retirement.
    pub fn acknowledge_browser_timeline(
        &self,
        browser_session: BrowserSessionId,
        new_artifact_id: &ArtifactId,
    ) -> Result<(), HuginnProtocolError> {
        let mut drained = false;
        loop {
            let result = (|| {
                let _guard = self
                    .publication_lock
                    .lock()
                    .map_err(|_| unavailable_protocol("publishedArtifactLock"))?;
                self.browser_artifacts.ensure_retirement_healthy()?;
                let mut pointer = load_browser_pointer(
                    self.root.as_ref(),
                    browser_session,
                    BrowserArtifactKind::Timeline,
                )?
                .ok_or_else(|| {
                    invalid_protocol(
                        "browserTimelineAcknowledgement",
                        "browser timeline does not exist",
                    )
                })?;
                if pointer
                    .retained
                    .back()
                    .map(|record| &record.artifact.artifact_id)
                    != Some(new_artifact_id)
                {
                    return Err(invalid_protocol(
                        "browserTimelineAcknowledgement",
                        "acknowledged artifact is not the current browser timeline",
                    ));
                }
                for record in &pointer.awaiting_projection {
                    self.browser_artifacts
                        .reserve_retirement(&BrowserArtifactRetirement {
                            browser_session,
                            kind: BrowserArtifactKind::Timeline,
                            record: record.clone(),
                        })?;
                }
                pointer.retiring.append(&mut pointer.awaiting_projection);
                if let Err(error) = persist_browser_pointer(self.root.as_ref(), &pointer) {
                    for record in &pointer.retiring {
                        self.browser_artifacts.cancel_retirement_reservation(
                            &BrowserArtifactRetirement {
                                browser_session,
                                kind: BrowserArtifactKind::Timeline,
                                record: record.clone(),
                            },
                        )?;
                    }
                    return Err(error);
                }
                for record in pointer.retiring {
                    self.browser_artifacts
                        .mark_retiring(BrowserArtifactRetirement {
                            browser_session,
                            kind: BrowserArtifactKind::Timeline,
                            record,
                        })?;
                }
                Ok(())
            })();
            match result {
                Err(error) if !drained && is_browser_retirement_resource_limit(&error) => {
                    self.browser_artifacts.flush()?;
                    drained = true;
                }
                Err(error) => return Err(error),
                Ok(()) => return Ok(()),
            }
        }
    }

    /// Waits for every retirement eligible at the barrier to finish on the
    /// store-owned worker.
    pub fn flush_browser_retirements(&self) -> Result<(), HuginnProtocolError> {
        self.browser_artifacts.flush()
    }

    pub(in crate::service) fn read(
        &self,
        artifact_id: &ArtifactId,
        max_bytes: u64,
    ) -> Result<Option<ResolvedContent>, HuginnProtocolError> {
        let _guard = self
            .publication_lock
            .lock()
            .map_err(|_| unavailable_protocol("publishedArtifactLock"))?;
        let Some(record) = read_published_record(self.root.as_ref(), artifact_id)? else {
            return Ok(None);
        };
        if record.artifact.byte_len > max_bytes {
            return Err(HuginnProtocolError::ResourceLimit {
                limit: "contentTicketBytes".to_owned(),
            });
        }
        let capacity = usize::try_from(record.artifact.byte_len)
            .map_err(|_| unavailable_protocol("publishedArtifactBytes"))?;
        let mut bytes = Vec::with_capacity(capacity);
        File::open(self.root.join("payloads").join(record.payload_name))
            .and_then(|file| {
                file.take(max_bytes.saturating_add(1))
                    .read_to_end(&mut bytes)
            })
            .map_err(|_| unavailable_protocol("publishedArtifactPayload"))?;
        if bytes.len() as u64 != record.artifact.byte_len
            || Digest::hash(&bytes) != record.artifact.content_digest
        {
            return Err(unavailable_protocol("publishedArtifactPayload"));
        }
        Ok(Some(ResolvedContent {
            media_type: record.artifact.media_type,
            digest: record.artifact.content_digest,
            bytes,
        }))
    }
}

impl odin_browser::ArtifactPublisher for FsPublishedArtifactStore {
    fn publish(
        &self,
        publication: odin_browser::ArtifactPublication,
    ) -> Result<ArtifactRef, odin_browser::capability::CapabilityError> {
        let kind = match publication.kind {
            odin_browser::capability::PublicationKind::Frame => BrowserArtifactKind::Frame,
            odin_browser::capability::PublicationKind::Screenshot => {
                BrowserArtifactKind::Screenshot
            }
            odin_browser::capability::PublicationKind::Download => BrowserArtifactKind::Download,
            odin_browser::capability::PublicationKind::Timeline => BrowserArtifactKind::Timeline,
        };
        self.publish_browser_artifact(
            publication.session_id,
            kind,
            publication.display_name,
            publication.media_type,
            publication.content_digest,
            publication.bytes,
        )
        .map_err(
            |error| odin_browser::capability::CapabilityError::PublisherFailure {
                reason: error.to_string(),
            },
        )
    }
}

#[async_trait]
impl RenderPublisher for FsPublishedArtifactStore {
    async fn publish_render(
        &self,
        render: VerifiedRender,
    ) -> Result<ArtifactRef, HuginnProtocolError> {
        self.publish_path(PublishPathParams {
            session_id: self.render_session,
            kind: ArtifactKind::Render(render.kind),
            display_name: format!("render-{}", render.render_id),
            media_type: render.media_type,
            byte_len: render.byte_len,
            content_digest: render.content_digest,
            source: render.path,
        })
        .await
    }
}
