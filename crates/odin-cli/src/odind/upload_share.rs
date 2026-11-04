//! Huginn uploads (`odin huginn files upload`) land in the
//! controller artifact store too, readable by the uploading session's seat
//! and project. The upload's `artifact:<session>:<hex>` id then names the same
//! bytes `artifact.read` and `discord.file.send` serve as `blake3:<hex>`.

use std::io::Read as _;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use odin_domain::huginn::LiveError;
use odin_domain::LaneId;
use odin_omp::live::lane_artifacts::{LaneArtifact, LaneArtifactPort, LaneEgressStream};
use odin_omp::live::ledger::LiveLedger;

pub(crate) struct SharedUploads {
    pub(crate) inner: Arc<dyn LaneArtifactPort>,
    pub(crate) ledger: Arc<dyn LiveLedger>,
    pub(crate) state_root: PathBuf,
}

impl SharedUploads {
    async fn share(&self, artifact: &LaneArtifact) -> Result<(), String> {
        let session = self
            .ledger
            .session(artifact.manifest.session_id)
            .await
            .map_err(|error| format!("the uploading session is unreadable: {error}"))?;
        let mut blob = self
            .ledger
            .read_blob(&artifact.blob)
            .await
            .map_err(|error| format!("the uploaded bytes are unreadable: {error}"))?;
        let media_type = artifact.manifest.media_type.clone();
        let shares = [
            ("seat", session.manifest.seat_id.to_string()),
            ("project", session.manifest.project_id.to_string()),
        ];
        let state_root = self.state_root.clone();
        tokio::task::spawn_blocking(move || {
            let mut bytes = Vec::new();
            blob.read_to_end(&mut bytes)
                .map_err(|error| format!("the uploaded bytes are unreadable: {error}"))?;
            crate::coding_route::store_artifact(&state_root, &bytes, &media_type, &shares)
        })
        .await
        .map_err(|error| format!("the artifact store task failed: {error}"))??;
        Ok(())
    }
}

#[async_trait]
impl LaneArtifactPort for SharedUploads {
    async fn publish(&self, artifact: LaneArtifact) -> Result<(), LiveError> {
        self.inner.publish(artifact.clone()).await?;
        self.share(&artifact).await.map_err(|error| {
            tracing::error!(
                "upload {} of session {} not shared into the artifact store: {error}",
                artifact.blob.digest,
                artifact.manifest.session_id
            );
            LiveError::unavailable("controller_artifact_store", error)
        })?;
        tracing::info!(
            "upload {} of session {} shared into the artifact store as {}",
            artifact.manifest.display_name,
            artifact.manifest.session_id,
            artifact.blob.digest
        );
        Ok(())
    }

    async fn subscribe(&self, lane: &LaneId) -> Result<LaneEgressStream, LiveError> {
        self.inner.subscribe(lane).await
    }
}
