//! Ledger-authorized content transport into immutable Job input volumes.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use k8s_openapi::api::core::v1::{ConfigMap, ConfigMapVolumeSource, Volume, VolumeMount};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::ByteString;
use kube::api::{DeleteParams, Patch, PatchParams, PostParams, Preconditions};
use odin_confined_fs::Capability;
use odin_domain::huginn::{
    KubeCheckpointProjection, KubeContentIdentity, KubeJobLabels, KubeStagingProjection,
};
use odin_domain::{ArtifactId, Digest, RunId};
use odin_ledger::artifact::NewArtifactReference;
use odin_ledger::Ledger;

use crate::client::{KubeClient, KubeError};
use crate::job::{
    bounded_label_value, checkpoint_configmap_name, staging_configmap_name, JOB_LABEL_RUN_ID,
    KUBE_CHECKPOINT_MOUNT_PATH, KUBE_CHECKPOINT_VOLUME, KUBE_STAGING_MOUNT_PATH,
    KUBE_STAGING_VOLUME,
};

pub use odin_domain::huginn::{ArtifactKind, ArtifactRef};

const MAX_MAP_BYTES: u64 = 512 * 1024;
const MAX_INPUTS: usize = 64;
const BINDING_ANNOTATION: &str = "odin.dev/staging-binding";
/// Written on a run's own residue once its Job is Complete or Failed.
pub(crate) const RUN_FINISHED: &str = "odin.dev/run-finished";

pub struct ArtifactStore {
    ledger: Arc<Mutex<Ledger>>,
    root: PathBuf,
}

pub struct StagedVolumes {
    pub volumes: Vec<Volume>,
    pub mounts: Vec<VolumeMount>,
    pub configmaps: Vec<ConfigMap>,
    /// Paths come from published ConfigMap keys; consumers must not infer filenames.
    pub staged_paths: BTreeMap<ArtifactId, String>,
}

/// Validated labels and content bytes retained so staging does not re-read files.
#[derive(Debug)]
pub struct PreparedStaging {
    labels: KubeJobLabels,
    inputs: Vec<PreparedContent>,
    checkpoint: Option<PreparedCheckpoint>,
}

#[derive(Debug)]
struct PreparedContent {
    identity: KubeContentIdentity,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct PreparedCheckpoint {
    projection: KubeCheckpointProjection,
    bytes: Vec<u8>,
}

impl ArtifactStore {
    pub fn new(ledger: Arc<Mutex<Ledger>>, root: PathBuf) -> Self {
        Self { ledger, root }
    }

    /// Checks scope, size, and digests before any cluster writes.
    pub fn prepare_stage(
        &self,
        labels: &KubeJobLabels,
        staging: &KubeStagingProjection,
        checkpoint: Option<&KubeCheckpointProjection>,
    ) -> Result<PreparedStaging, KubeError> {
        if staging.inputs.len() > MAX_INPUTS {
            return Err(rejected("too many Job staging inputs"));
        }
        if staging.resumed_from.as_ref() != checkpoint.map(|value| &value.checkpoint_id) {
            return Err(rejected(
                "resume checkpoint identity does not match staging",
            ));
        }
        let mut total = 0u64;
        for input in &staging.inputs {
            total = total
                .checked_add(input.byte_len)
                .ok_or_else(|| rejected("staging size overflow"))?;
            if total > MAX_MAP_BYTES {
                return Err(rejected(
                    "Job staging exceeds the bounded ConfigMap transport",
                ));
            }
        }
        let mut inputs = Vec::with_capacity(staging.inputs.len());
        for input in &staging.inputs {
            inputs.push(self.prepare_verified(labels, input)?);
        }
        let checkpoint = match checkpoint {
            Some(checkpoint) => {
                let state = self.prepare_verified(labels, &checkpoint.state)?;
                Some(PreparedCheckpoint {
                    projection: checkpoint.clone(),
                    bytes: state.bytes,
                })
            }
            None => None,
        };
        Ok(PreparedStaging {
            labels: labels.clone(),
            inputs,
            checkpoint,
        })
    }

    /// Publishes the prepared bytes without re-reading files and adds retention references.
    pub async fn stage(
        &self,
        client: &KubeClient,
        job_name: &str,
        prepared: PreparedStaging,
    ) -> Result<StagedVolumes, KubeError> {
        let PreparedStaging {
            labels,
            inputs,
            checkpoint,
        } = prepared;
        let manifest: Vec<KubeContentIdentity> =
            inputs.iter().map(|input| input.identity.clone()).collect();
        let checkpoint_state = checkpoint
            .as_ref()
            .map(|value| value.projection.state.clone());
        let mut maps = Vec::with_capacity(2);
        let mut staged_paths = BTreeMap::new();
        if !inputs.is_empty() {
            let mut bytes = BTreeMap::new();
            for (index, input) in inputs.into_iter().enumerate() {
                let PreparedContent {
                    identity,
                    bytes: buffer,
                } = input;
                bytes.insert(format!("input-{index}"), ByteString(buffer));
                staged_paths.insert(
                    identity.artifact_id.clone(),
                    format!("{KUBE_STAGING_MOUNT_PATH}/input-{index}"),
                );
            }
            maps.push((
                make_map(staging_configmap_name(job_name), &labels, bytes, &manifest)?,
                KUBE_STAGING_VOLUME,
                KUBE_STAGING_MOUNT_PATH,
            ));
        }
        if let Some(checkpoint) = checkpoint {
            let bytes = BTreeMap::from([("state".to_owned(), ByteString(checkpoint.bytes))]);
            maps.push((
                make_map(
                    checkpoint_configmap_name(job_name),
                    &labels,
                    bytes,
                    &checkpoint.projection,
                )?,
                KUBE_CHECKPOINT_VOLUME,
                KUBE_CHECKPOINT_MOUNT_PATH,
            ));
        }
        {
            let mut ledger = self
                .ledger
                .lock()
                .map_err(|_| storage("artifact ledger lock poisoned"))?;
            for identity in manifest.iter().chain(checkpoint_state.iter()) {
                let metadata = ledger
                    .artifact(&identity.artifact_id)
                    .map_err(|error| storage(error.to_string()))?
                    .ok_or_else(|| storage("verified Job artifact disappeared before retention"))?;
                if metadata.digest != identity.content_digest
                    || metadata.size_bytes != identity.byte_len
                {
                    return Err(storage("Job artifact identity changed before retention"));
                }
                ledger
                    .attach_artifact_reference(
                        &identity.artifact_id,
                        metadata.revision,
                        NewArtifactReference {
                            object_kind: "run",
                            object_id: labels.run_id.as_str(),
                            relation: "kube-content",
                            created_at: time::OffsetDateTime::now_utc(),
                        },
                    )
                    .map_err(|error| storage(error.to_string()))?;
            }
        }
        // Maps outlive Job recreation so checkpoint state is not garbage-collected.
        let mut staged = StagedVolumes {
            volumes: Vec::new(),
            mounts: Vec::new(),
            configmaps: Vec::new(),
            staged_paths: BTreeMap::new(),
        };
        staged.staged_paths.extend(staged_paths);
        for (map, volume_name, mount_path) in maps {
            let map = publish(client, map).await?;
            let name = map
                .metadata
                .name
                .clone()
                .ok_or_else(|| storage("API returned unnamed staging ConfigMap"))?;
            staged.volumes.push(Volume {
                name: volume_name.to_owned(),
                config_map: Some(ConfigMapVolumeSource {
                    name,
                    default_mode: Some(0o444),
                    optional: Some(false),
                    ..Default::default()
                }),
                ..Default::default()
            });
            staged.mounts.push(VolumeMount {
                name: volume_name.to_owned(),
                mount_path: mount_path.to_owned(),
                read_only: Some(true),
                ..Default::default()
            });
            staged.configmaps.push(map);
        }
        Ok(staged)
    }

    /// Pins content in the ledger; identical registrations reuse the read-only file.
    pub fn register_bytes(
        &self,
        bytes: &[u8],
        storage_path: &str,
    ) -> Result<odin_ledger::artifact::ArtifactMetadata, KubeError> {
        self.register_content(
            bytes,
            "application/json",
            storage_path,
            odin_ledger::artifact::RetentionClass::Pinned,
        )
    }

    /// Retains the state-volume tar so rehome can resume after deleting the old volume.
    pub fn register_checkpoint(
        &self,
        bytes: &[u8],
    ) -> Result<odin_ledger::artifact::ArtifactMetadata, KubeError> {
        let digest = Digest::hash(bytes).to_string();
        let hex = digest.trim_start_matches("blake3:");
        self.register_content(
            bytes,
            "application/x-tar",
            &format!("cas/{}/{hex}", &hex[..2]),
            odin_ledger::artifact::RetentionClass::Canonical,
        )
    }

    fn register_content(
        &self,
        bytes: &[u8],
        media_type: &str,
        storage_path: &str,
        retention: odin_ledger::artifact::RetentionClass,
    ) -> Result<odin_ledger::artifact::ArtifactMetadata, KubeError> {
        let absolute = self.root.join(storage_path);
        if !absolute.exists() {
            std::fs::create_dir_all(
                absolute
                    .parent()
                    .ok_or_else(|| storage("content-addressed artifact path has no parent"))?,
            )
            .map_err(|error| storage(error.to_string()))?;
            std::fs::write(&absolute, bytes).map_err(|error| storage(error.to_string()))?;
            let mut permissions = std::fs::metadata(&absolute)
                .map_err(|error| storage(error.to_string()))?
                .permissions();
            use std::os::unix::fs::PermissionsExt as _;
            permissions.set_mode(0o444);
            std::fs::set_permissions(&absolute, permissions)
                .map_err(|error| storage(error.to_string()))?;
        }
        let metadata = {
            let ledger = self
                .ledger
                .lock()
                .map_err(|_| storage("artifact ledger lock poisoned"))?;
            ledger
                .register_artifact(odin_ledger::artifact::ArtifactRegistration {
                    bytes,
                    media_type,
                    storage_path,
                    retention,
                    created_at: time::OffsetDateTime::now_utc(),
                })
                .map_err(|error| storage(error.to_string()))?
        };
        Ok(metadata)
    }

    /// Checks size and digest on every read, subject to the ConfigMap size limit.
    pub fn read_registered(&self, artifact_id: &ArtifactId) -> Result<Vec<u8>, KubeError> {
        self.read_bounded(artifact_id, MAX_MAP_BYTES)
    }

    /// Checkpoint archives use their declared storage limit instead of the ConfigMap limit.
    pub fn read_bounded(
        &self,
        artifact_id: &ArtifactId,
        max_bytes: u64,
    ) -> Result<Vec<u8>, KubeError> {
        let metadata = {
            let ledger = self
                .ledger
                .lock()
                .map_err(|_| storage("artifact ledger lock poisoned"))?;
            ledger
                .artifact(artifact_id)
                .map_err(|error| storage(error.to_string()))?
                .ok_or_else(|| rejected("artifact is not registered"))?
        };
        let byte_len = metadata.size_bytes;
        if byte_len > max_bytes {
            return Err(rejected(
                "registered artifact exceeds the bounded transport",
            ));
        }
        let capability =
            Capability::seal(&self.root).map_err(|error| storage(error.to_string()))?;
        let mut file = capability
            .open_read(Path::new(&metadata.storage_path))
            .map_err(|error| storage(error.to_string()))?;
        if file
            .metadata()
            .map_err(|error| storage(error.to_string()))?
            .len()
            != byte_len
        {
            return Err(storage("registered artifact size changed"));
        }
        let mut bytes = Vec::with_capacity(byte_len as usize);
        (&mut file)
            .take(byte_len + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| storage(error.to_string()))?;
        if bytes.len() as u64 != byte_len
            || Digest::hash(&bytes).to_string() != metadata.digest.to_string()
        {
            return Err(storage("registered artifact content changed"));
        }
        Ok(bytes)
    }

    /// Requires matching ledger scope, digest, and size without reading files or contacting Kubernetes.
    pub fn prepare_content(
        &self,
        labels: &KubeJobLabels,
        identity: &KubeContentIdentity,
    ) -> Result<odin_ledger::artifact::ArtifactMetadata, KubeError> {
        if identity.byte_len > MAX_MAP_BYTES {
            return Err(rejected("artifact exceeds the bounded Job transport"));
        }
        let metadata = {
            let ledger = self
                .ledger
                .lock()
                .map_err(|_| storage("artifact ledger lock poisoned"))?;
            let references = ledger
                .artifact_references(&identity.artifact_id)
                .map_err(|error| storage(error.to_string()))?;
            if !references.iter().any(|reference| {
                let expected = match reference.object_kind.as_str() {
                    "run" => Some(labels.run_id.as_str()),
                    "attempt" => Some(labels.attempt_id.as_str()),
                    "seat" => Some(labels.seat_id.as_str()),
                    "project" => Some(labels.project_id.as_str()),
                    "lane" => Some(labels.lane_id.as_str()),
                    _ => None,
                };
                expected == Some(reference.object_id.as_str())
            }) {
                return Err(rejected(
                    "no ledger reference binds the artifact to the Job scope",
                ));
            }
            ledger
                .artifact(&identity.artifact_id)
                .map_err(|error| storage(error.to_string()))?
                .ok_or_else(|| rejected("Job artifact is not registered"))?
        };
        if metadata.digest != identity.content_digest || metadata.size_bytes != identity.byte_len {
            return Err(rejected(
                "Job content identity differs from registered artifact metadata",
            ));
        }
        Ok(metadata)
    }

    fn prepare_verified(
        &self,
        labels: &KubeJobLabels,
        identity: &KubeContentIdentity,
    ) -> Result<PreparedContent, KubeError> {
        let metadata = self.prepare_content(labels, identity)?;
        let bytes = self.read_verified(identity, &metadata)?;
        Ok(PreparedContent {
            identity: identity.clone(),
            bytes,
        })
    }

    /// Opens within the artifact root and checks the bytes against the declared size and digest.
    fn read_verified(
        &self,
        identity: &KubeContentIdentity,
        metadata: &odin_ledger::artifact::ArtifactMetadata,
    ) -> Result<Vec<u8>, KubeError> {
        let capability =
            Capability::seal(&self.root).map_err(|error| storage(error.to_string()))?;
        let mut file = capability
            .open_read(Path::new(&metadata.storage_path))
            .map_err(|error| storage(error.to_string()))?;
        if file
            .metadata()
            .map_err(|error| storage(error.to_string()))?
            .len()
            != identity.byte_len
        {
            return Err(storage("registered artifact size changed"));
        }
        let mut bytes = Vec::with_capacity(identity.byte_len as usize);
        (&mut file)
            .take(identity.byte_len + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| storage(error.to_string()))?;
        if bytes.len() as u64 != identity.byte_len
            || Digest::hash(&bytes) != identity.content_digest
        {
            return Err(storage("registered artifact content changed"));
        }
        Ok(bytes)
    }

    /// Call only after confirming that no pods still use these volumes.
    /// UID preconditions prevent removal of a replacement object; ledger bytes are retained.
    pub async fn remove(&self, client: &KubeClient, maps: &[ConfigMap]) -> Result<(), KubeError> {
        let api: kube::Api<ConfigMap> =
            kube::Api::namespaced(client.client.clone(), &client.config.namespace);
        let deadline = tokio::time::Instant::now() + client.config.teardown_timeout;
        for map in maps {
            let name = map
                .metadata
                .name
                .as_deref()
                .ok_or_else(|| rejected("staging map name missing"))?;
            let uid = map
                .metadata
                .uid
                .clone()
                .ok_or_else(|| rejected("staging map UID missing"))?;
            if !map
                .metadata
                .annotations
                .as_ref()
                .is_some_and(|annotations| annotations.contains_key(BINDING_ANNOTATION))
            {
                return Err(rejected(
                    "foreign ConfigMap cannot be removed as Job staging",
                ));
            }
            let params = DeleteParams {
                preconditions: Some(Preconditions {
                    uid: Some(uid),
                    resource_version: None,
                }),
                ..Default::default()
            };
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(storage(format!(
                    "staging ConfigMap {name} teardown deadline expired"
                )));
            }
            match tokio::time::timeout(
                remaining.min(client.config.request_timeout),
                api.delete(name, &params),
            )
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(kube::Error::Api(error))) if error.code == 404 => {}
                Ok(Err(error)) => return Err(error.into()),
                Err(_) => {
                    return Err(KubeError::unavailable(
                        "staging ConfigMap deletion timed out",
                    ))
                }
            }
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    return Err(storage(format!(
                        "staging ConfigMap {name} residue remains after deletion"
                    )));
                }
                if tokio::time::timeout(
                    remaining.min(client.config.request_timeout),
                    api.get_opt(name),
                )
                .await
                .map_err(|_| KubeError::unavailable("staging absence query timed out"))??
                .is_none()
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50).min(remaining)).await;
            }
        }
        Ok(())
    }

    /// Leaves maps belonging to another run untouched, even if their names match.
    pub async fn remove_run_maps(
        &self,
        client: &KubeClient,
        run_id: &RunId,
    ) -> Result<(), KubeError> {
        let job = crate::job::job_name(run_id);
        let api: kube::Api<ConfigMap> =
            kube::Api::namespaced(client.client.clone(), &client.config.namespace);
        let mut maps = Vec::new();
        for name in [
            staging_configmap_name(&job),
            checkpoint_configmap_name(&job),
        ] {
            let existing = tokio::time::timeout(client.config.request_timeout, api.get_opt(&name))
                .await
                .map_err(|_| KubeError::unavailable("staging ConfigMap query timed out"))?
                .map_err(KubeError::from)?;
            let Some(map) = existing else {
                continue;
            };
            if !binding_is_run(&map, run_id) {
                tracing::warn!(
                    run = %run_id,
                    "ConfigMap {name} is not run {}'s staging; left in place",
                    run_id.as_str()
                );
                continue;
            }
            maps.push(map);
        }
        if maps.is_empty() {
            return Ok(());
        }
        self.remove(client, &maps).await
    }

    /// Leaves maps belonging to another run untouched.
    pub(crate) async fn set_run_maps_finished(
        &self,
        client: &KubeClient,
        run_id: &RunId,
        finished: bool,
    ) -> Result<(), KubeError> {
        let job = crate::job::job_name(run_id);
        let api: kube::Api<ConfigMap> =
            kube::Api::namespaced(client.client.clone(), &client.config.namespace);
        for name in [
            staging_configmap_name(&job),
            checkpoint_configmap_name(&job),
        ] {
            let existing = tokio::time::timeout(client.config.request_timeout, api.get_opt(&name))
                .await
                .map_err(|_| KubeError::unavailable("staging ConfigMap query timed out"))?
                .map_err(KubeError::from)?;
            let Some(map) = existing else {
                continue;
            };
            if !binding_is_run(&map, run_id) || map_marked(&map) == finished {
                continue;
            }
            let patch = serde_json::json!({
                "metadata": {
                    "annotations": {
                        RUN_FINISHED: if finished { "true" } else { "false" }
                    }
                }
            });
            match tokio::time::timeout(
                client.config.request_timeout,
                api.patch(&name, &PatchParams::default(), &Patch::Merge(patch)),
            )
            .await
            {
                Err(_) => return Err(KubeError::unavailable("staging ConfigMap patch timed out")),
                Ok(Ok(_)) => {}
                Ok(Err(kube::Error::Api(error))) if error.code == 404 => {}
                Ok(Err(kube::Error::Api(error))) if error.code == 409 => {
                    return Err(KubeError::Conflict {
                        reason: format!(
                            "staging ConfigMap {name} changed during the finished mark"
                        ),
                    });
                }
                Ok(Err(error)) => return Err(error.into()),
            }
        }
        Ok(())
    }

    pub(crate) async fn run_maps_marked(
        &self,
        client: &KubeClient,
        run_id: &RunId,
    ) -> Result<bool, KubeError> {
        let job = crate::job::job_name(run_id);
        let api: kube::Api<ConfigMap> =
            kube::Api::namespaced(client.client.clone(), &client.config.namespace);
        for name in [
            staging_configmap_name(&job),
            checkpoint_configmap_name(&job),
        ] {
            let existing = tokio::time::timeout(client.config.request_timeout, api.get_opt(&name))
                .await
                .map_err(|_| KubeError::unavailable("staging ConfigMap query timed out"))?
                .map_err(KubeError::from)?;
            if existing.is_some_and(|map| binding_is_run(&map, run_id) && map_marked(&map)) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn binding_is_run(map: &ConfigMap, run_id: &RunId) -> bool {
    map.metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(BINDING_ANNOTATION))
        .and_then(|raw| serde_json::from_str::<KubeJobLabels>(raw).ok())
        .is_some_and(|labels| labels.run_id == *run_id)
}

fn map_marked(map: &ConfigMap) -> bool {
    map.metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(RUN_FINISHED))
        .is_some_and(|value| value == "true")
}

fn make_map(
    name: String,
    labels: &KubeJobLabels,
    binary_data: BTreeMap<String, ByteString>,
    manifest: &impl serde::Serialize,
) -> Result<ConfigMap, KubeError> {
    Ok(ConfigMap {
        metadata: ObjectMeta {
            name: Some(name),
            annotations: Some(BTreeMap::from([(
                BINDING_ANNOTATION.to_owned(),
                serde_json::to_string(labels).map_err(|error| storage(error.to_string()))?,
            )])),
            // Labelled lists cannot see a map that only carries the binding annotation.
            labels: Some(BTreeMap::from([(
                JOB_LABEL_RUN_ID.to_owned(),
                bounded_label_value(labels.run_id.as_str()),
            )])),
            ..Default::default()
        },
        immutable: Some(true),
        binary_data: Some(binary_data),
        data: Some(BTreeMap::from([(
            "manifest.json".to_owned(),
            serde_json::to_string(manifest).map_err(|error| storage(error.to_string()))?,
        )])),
    })
}

async fn publish(client: &KubeClient, desired: ConfigMap) -> Result<ConfigMap, KubeError> {
    let api: kube::Api<ConfigMap> =
        kube::Api::namespaced(client.client.clone(), &client.config.namespace);
    let result = tokio::time::timeout(
        client.config.request_timeout,
        api.create(&PostParams::default(), &desired),
    )
    .await
    .map_err(|_| KubeError::unavailable("staging ConfigMap creation timed out"))?;
    match result {
        Ok(map) => {
            verify_map(&map, &desired)?;
            Ok(map)
        }
        Err(kube::Error::Api(error)) if error.code == 409 => {
            let name = desired
                .metadata
                .name
                .as_deref()
                .ok_or_else(|| storage("staging map name missing"))?;
            let existing = tokio::time::timeout(client.config.request_timeout, api.get(name))
                .await
                .map_err(|_| KubeError::unavailable("staging ConfigMap observation timed out"))??;
            verify_map(&existing, &desired)?;
            Ok(existing)
        }
        Err(error) => Err(error.into()),
    }
}

fn verify_map(existing: &ConfigMap, desired: &ConfigMap) -> Result<(), KubeError> {
    if existing.immutable != Some(true)
        || existing.metadata.uid.as_deref().is_none_or(str::is_empty)
        || existing
            .metadata
            .resource_version
            .as_deref()
            .is_none_or(str::is_empty)
        || existing.metadata.name != desired.metadata.name
        || existing.metadata.deletion_timestamp.is_some()
        || existing
            .metadata
            .owner_references
            .as_ref()
            .is_some_and(|owners| !owners.is_empty())
        || existing
            .metadata
            .annotations
            .as_ref()
            .and_then(|values| values.get(BINDING_ANNOTATION))
            != desired
                .metadata
                .annotations
                .as_ref()
                .and_then(|values| values.get(BINDING_ANNOTATION))
        || existing.binary_data != desired.binary_data
        || existing.data != desired.data
    {
        return Err(KubeError::Conflict {
            reason: format!(
                "staging ConfigMap {:?} differs in content, identity, or ownership",
                desired.metadata.name
            ),
        });
    }
    Ok(())
}

fn rejected(reason: impl Into<String>) -> KubeError {
    KubeError::Rejected {
        reason: reason.into(),
    }
}

fn storage(reason: impl Into<String>) -> KubeError {
    KubeError::Storage {
        reason: reason.into(),
    }
}
