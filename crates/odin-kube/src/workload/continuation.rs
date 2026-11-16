//! Hand a finished run's state volume to the run that continues it. The volume is rebound
//! under the new run's claim name, so every later restart, rehome, and reap addresses it
//! exactly as it addresses a claim the run created itself.

use super::*;
use k8s_openapi::api::core::v1::{PersistentVolume, PersistentVolumeClaim};
use kube::api::DeleteParams;

/// Names the claim a handover rebinds the volume to, so a crash between the old claim's
/// deletion and the new claim's creation can find the volume again.
pub const CONTINUED_BY: &str = "odin.dev/continued-by";

/// Rebind `from`'s state volume to `to`'s claim and return the nodes its affinity admits.
/// Every step is idempotent: a replay finds the new claim, or the annotated volume.
pub async fn hand_over_state_claim(
    client: &KubeClient,
    from: &RunId,
    to: &RunId,
    plan: &WorkloadPodPlan,
) -> Result<Vec<String>, KubeError> {
    let claims = client.persistent_volume_claims();
    let volumes = client.persistent_volumes();
    let timeout = client.request_timeout();
    let new_name = state_claim_name(to);
    let get_claim = |name: String| {
        let claims = claims.clone();
        async move {
            tokio::time::timeout(timeout, claims.get_opt(&name))
                .await
                .map_err(|error| {
                    KubeError::unavailable(format!("state claim query timed out: {error}"))
                })?
                .map_err(KubeError::from)
        }
    };
    if let Some(claim) = get_claim(new_name.clone()).await? {
        // A replay, or a restart of the continuation: the claim is already the run's own.
        verify_claim(&claim, to, plan)?;
        let Some(volume) = claim.spec.and_then(|spec| spec.volume_name) else {
            return Ok(vec![]);
        };
        let pv = tokio::time::timeout(timeout, volumes.get_opt(&volume))
            .await
            .map_err(|error| {
                KubeError::unavailable(format!("state volume query timed out: {error}"))
            })?
            .map_err(KubeError::from)?;
        return match pv {
            Some(pv)
                if pv
                    .metadata
                    .annotations
                    .as_ref()
                    .is_some_and(|annotations| annotations.contains_key(CONTINUED_BY)) =>
            {
                settle_volume(&volumes, &volume, timeout).await
            }
            Some(pv) => Ok(pv_admitted_nodes(&pv)),
            None => Ok(vec![]),
        };
    }
    let volume = match get_claim(state_claim_name(from)).await? {
        Some(old) => {
            verify_claim(&old, from, plan).map_err(|error| {
                KubeError::rejected(format!(
                    "continueFrom run {from}'s state claim does not match this profile's state: {error}"
                ))
            })?;
            let volume = bound_volume(&old, from)?;
            let pv = tokio::time::timeout(timeout, volumes.get(&volume))
                .await
                .map_err(|error| KubeError::unavailable(format!("state volume query timed out: {error}")))?
                .map_err(KubeError::from)?;
            if pv.metadata.annotations.as_ref()
                .and_then(|annotations| annotations.get(CONTINUED_BY))
                .is_some_and(|holder| holder != &new_name)
            {
                return Err(KubeError::rejected(format!(
                    "continueFrom run {from}'s state is already reserved by another continuation"
                )));
            }
            // Retain first, so deleting the old claim cannot delete the volume.
            patch_volume(
                &volumes,
                &volume,
                serde_json::json!({
                    "metadata": {"resourceVersion": pv.metadata.resource_version, "annotations": {CONTINUED_BY: new_name}},
                    "spec": {"persistentVolumeReclaimPolicy": "Retain"},
                }),
                timeout,
            )
            .await?;
            if old.metadata.deletion_timestamp.is_none() {
                let params = DeleteParams {
                    preconditions: Some(kube::api::Preconditions {
                        uid: old.metadata.uid.clone(),
                        resource_version: None,
                    }),
                    ..DeleteParams::default()
                };
                tokio::time::timeout(
                    timeout,
                    claims.delete(old.metadata.name.as_deref().unwrap_or_default(), &params),
                )
                .await
                .map_err(|error| {
                    KubeError::unavailable(format!("state claim delete timed out: {error}"))
                })?
                .map_err(KubeError::from)?;
            }
            if get_claim(state_claim_name(from)).await?.is_some() {
                return Err(KubeError::unavailable(format!(
                    "run {from}'s state claim is still being released; continue again shortly"
                )));
            }
            volume
        }
        None => handed_volume(&volumes, &new_name, timeout)
            .await?
            .ok_or_else(|| {
                KubeError::rejected(format!(
                    "continueFrom run {from}'s state claim is gone; there is no state to continue from"
                ))
            })?,
    };
    let pv = tokio::time::timeout(timeout, volumes.get_opt(&volume))
        .await
        .map_err(|error| KubeError::unavailable(format!("state volume query timed out: {error}")))?
        .map_err(KubeError::from)?
        .ok_or_else(|| {
            KubeError::rejected(format!(
                "continueFrom run {from}'s state volume {volume} is gone"
            ))
        })?;
    // Reserve the volume for the new claim alone; null clears the old claim's identity.
    patch_volume(
        &volumes,
        &volume,
        serde_json::json!({"spec": {"claimRef": {
            "namespace": client.config.namespace,
            "name": new_name,
            "uid": null,
            "resourceVersion": null,
        }}}),
        timeout,
    )
    .await?;
    let storage_class = plan.state_storage_class.clone().or_else(|| {
        pv.spec
            .as_ref()
            .and_then(|spec| spec.storage_class_name.clone())
    });
    let claim = PersistentVolumeClaim {
        metadata: ObjectMeta {
            name: Some(new_name.clone()),
            labels: Some(run_claim_labels(to)),
            ..Default::default()
        },
        spec: Some(k8s_openapi::api::core::v1::PersistentVolumeClaimSpec {
            access_modes: Some(vec!["ReadWriteOnce".to_owned()]),
            resources: Some(k8s_openapi::api::core::v1::VolumeResourceRequirements {
                requests: Some(BTreeMap::from([(
                    "storage".to_owned(),
                    k8s_openapi::apimachinery::pkg::api::resource::Quantity(
                        plan.state_storage.clone(),
                    ),
                )])),
                limits: None,
            }),
            storage_class_name: storage_class,
            volume_mode: Some("Filesystem".to_owned()),
            volume_name: Some(volume.clone()),
            ..Default::default()
        }),
        status: None,
    };
    match tokio::time::timeout(timeout, claims.create(&PostParams::default(), &claim))
        .await
        .map_err(|error| KubeError::unavailable(format!("state claim create timed out: {error}")))?
    {
        Ok(_) => {}
        Err(kube::Error::Api(status)) if status.code == 409 => {}
        Err(error) => return Err(error.into()),
    }
    settle_volume(&volumes, &volume, timeout).await
}

fn bound_volume(claim: &PersistentVolumeClaim, run: &RunId) -> Result<String, KubeError> {
    claim
        .spec
        .as_ref()
        .and_then(|spec| spec.volume_name.clone())
        .ok_or_else(|| {
            KubeError::rejected(format!(
                "run {run}'s state claim holds no bound volume; there is no state to continue from"
            ))
        })
}

/// Finds a volume reserved by an interrupted handover before its new claim exists.
pub async fn continued_state_binding(
    client: &KubeClient,
    run: &RunId,
) -> Result<Option<WorkloadStateBinding>, KubeError> {
    let volumes = client.persistent_volumes();
    let claim = state_claim_name(run);
    let Some(volume) = handed_volume(&volumes, &claim, client.request_timeout()).await? else {
        return Ok(None);
    };
    let pv = tokio::time::timeout(client.request_timeout(), volumes.get_opt(&volume))
        .await
        .map_err(|error| KubeError::unavailable(format!("state volume query timed out: {error}")))?
        .map_err(KubeError::from)?;
    Ok(Some(WorkloadStateBinding {
        claim,
        bound_volume: Some(volume),
        admitted_nodes: pv.as_ref().map(pv_admitted_nodes),
    }))
}

/// The volume a crashed handover left reserved for `claim`.
async fn handed_volume(
    volumes: &kube::Api<PersistentVolume>,
    claim: &str,
    timeout: std::time::Duration,
) -> Result<Option<String>, KubeError> {
    let mut continue_token: Option<String> = None;
    loop {
        let mut params = ListParams::default().limit(1024);
        if let Some(token) = continue_token.as_deref() {
            params = params.continue_token(token);
        }
        let listed = tokio::time::timeout(timeout, volumes.list(&params))
            .await
            .map_err(|error| {
                KubeError::unavailable(format!("state volume list timed out: {error}"))
            })?
            .map_err(KubeError::from)?;
        if let Some(name) = listed.items.into_iter().find_map(|pv| {
            let annotations = pv.metadata.annotations.as_ref()?;
            (annotations.get(CONTINUED_BY).map(String::as_str) == Some(claim))
                .then(|| pv.metadata.name.clone())
                .flatten()
        }) {
            return Ok(Some(name));
        }
        continue_token = listed.metadata.continue_.filter(|token| !token.is_empty());
        if continue_token.is_none() {
            return Ok(None);
        }
    }
}

/// Restore deletion with the claim and drop the handover mark; return the admitted nodes.
async fn settle_volume(
    volumes: &kube::Api<PersistentVolume>,
    volume: &str,
    timeout: std::time::Duration,
) -> Result<Vec<String>, KubeError> {
    let pv = patch_volume(
        volumes,
        volume,
        serde_json::json!({
            "metadata": {"annotations": {CONTINUED_BY: null}},
            "spec": {"persistentVolumeReclaimPolicy": "Delete"},
        }),
        timeout,
    )
    .await?;
    Ok(pv_admitted_nodes(&pv))
}

async fn patch_volume(
    volumes: &kube::Api<PersistentVolume>,
    volume: &str,
    patch: serde_json::Value,
    timeout: std::time::Duration,
) -> Result<PersistentVolume, KubeError> {
    tokio::time::timeout(
        timeout,
        volumes.patch(volume, &PatchParams::default(), &Patch::Merge(&patch)),
    )
    .await
    .map_err(|error| KubeError::unavailable(format!("state volume patch timed out: {error}")))?
    .map_err(KubeError::from)
}
