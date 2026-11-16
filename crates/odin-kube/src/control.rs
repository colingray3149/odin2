//! The one mutable per-run channel: a ConfigMap the pod reads and `kube.workload.steer` rewrites.
//!
//! Mounted without subPath so the kubelet swaps updates in place (typically within a minute).
//! Every write bumps `seq` under a resourceVersion precondition; the pod acknowledges with an
//! `ODIN-STATUS` counter `control_seq`.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{ConfigMap, ConfigMapVolumeSource, Volume, VolumeMount};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::PostParams;
use odin_domain::huginn::KubeJobLabels;
use odin_domain::RunId;
use serde::{Deserialize, Serialize};

use crate::artifacts::{binding_is_run, BINDING_ANNOTATION};
use crate::client::{KubeClient, KubeError};
use crate::job::{bounded_label_value, JOB_LABEL_RUN_ID};

pub const CONTROL_MOUNT_PATH: &str = "/var/run/odin/control";
pub const CONTROL_KEY: &str = "control.json";
const CONTROL_VOLUME: &str = "odin-control";

pub fn control_configmap_name(job_name: &str) -> String {
    format!("{job_name}-control")
}

/// What the pod reads at `/var/run/odin/control/control.json`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ControlDocument {
    pub seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    /// The steer operation that wrote it, so a replay is recognised.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document: Option<serde_json::Value>,
}

/// A settled steer: the sequence now in the map, and whether this call wrote it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SteerApplied {
    pub seq: u64,
    pub duplicate: bool,
}

pub(crate) fn control_volume(job_name: &str) -> (Volume, VolumeMount) {
    (
        Volume {
            name: CONTROL_VOLUME.to_owned(),
            config_map: Some(ConfigMapVolumeSource {
                name: control_configmap_name(job_name),
                default_mode: Some(0o444),
                optional: Some(false),
                ..Default::default()
            }),
            ..Default::default()
        },
        VolumeMount {
            name: CONTROL_VOLUME.to_owned(),
            mount_path: CONTROL_MOUNT_PATH.to_owned(),
            read_only: Some(true),
            ..Default::default()
        },
    )
}

fn api(client: &KubeClient) -> kube::Api<ConfigMap> {
    kube::Api::namespaced(client.client.clone(), &client.config.namespace)
}

async fn get(client: &KubeClient, name: &str) -> Result<Option<ConfigMap>, KubeError> {
    tokio::time::timeout(client.config.request_timeout, api(client).get_opt(name))
        .await
        .map_err(|error| KubeError::unavailable(format!("control map query timed out: {error}")))?
        .map_err(KubeError::from)
}

fn encode(document: &ControlDocument) -> Result<BTreeMap<String, String>, KubeError> {
    let text = serde_json::to_string(document).map_err(|error| KubeError::Storage {
        reason: error.to_string(),
    })?;
    Ok(BTreeMap::from([(CONTROL_KEY.to_owned(), text)]))
}

fn decode(map: &ConfigMap) -> Result<ControlDocument, KubeError> {
    let text = map
        .data
        .as_ref()
        .and_then(|data| data.get(CONTROL_KEY))
        .ok_or_else(|| KubeError::rejected("the run's control map holds no control.json"))?;
    serde_json::from_str(text).map_err(|error| {
        KubeError::rejected(format!(
            "the run's control map is not a control document: {error}"
        ))
    })
}

/// The run's control map at seq 0: run-labelled and bound like its staging, so it is reaped
/// with the run, and mutable, unlike every other run map.
fn control_map(job_name: &str, labels: &KubeJobLabels) -> Result<ConfigMap, KubeError> {
    let initial = ControlDocument {
        seq: 0,
        at: None,
        by: None,
        operation: None,
        document: None,
    };
    Ok(ConfigMap {
        metadata: ObjectMeta {
            name: Some(control_configmap_name(job_name)),
            annotations: Some(BTreeMap::from([(
                BINDING_ANNOTATION.to_owned(),
                serde_json::to_string(labels).map_err(|error| KubeError::Storage {
                    reason: error.to_string(),
                })?,
            )])),
            labels: Some(BTreeMap::from([(
                JOB_LABEL_RUN_ID.to_owned(),
                bounded_label_value(labels.run_id.as_str()),
            )])),
            ..Default::default()
        },
        data: Some(encode(&initial)?),
        ..Default::default()
    })
}

/// Publishes `{"seq":0}` once; an existing map of the same run keeps its steered content.
pub(crate) async fn ensure_control_map(
    client: &KubeClient,
    job_name: &str,
    labels: &KubeJobLabels,
) -> Result<(), KubeError> {
    let name = control_configmap_name(job_name);
    let desired = control_map(job_name, labels)?;
    let created = tokio::time::timeout(
        client.config.request_timeout,
        api(client).create(&PostParams::default(), &desired),
    )
    .await
    .map_err(|error| KubeError::unavailable(format!("control map creation timed out: {error}")))?;
    match created {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(error)) if error.code == 409 => match get(client, &name).await? {
            Some(map) if binding_is_run(&map, &labels.run_id) => Ok(()),
            _ => Err(KubeError::Conflict {
                reason: format!("control map {name} belongs to another run"),
            }),
        },
        Err(error) => Err(error.into()),
    }
}

/// The run's current control document, if it declares one.
pub async fn read_control(
    client: &KubeClient,
    run_id: &RunId,
) -> Result<Option<ControlDocument>, KubeError> {
    let name = control_configmap_name(&crate::job::job_name(run_id));
    match get(client, &name).await? {
        Some(map) if binding_is_run(&map, run_id) => decode(&map).map(Some),
        _ => Ok(None),
    }
}

/// Writes `document` as `expected_seq + 1`. A stale sequence is refused; the same operation
/// replayed after it landed settles as a duplicate.
pub async fn steer(
    client: &KubeClient,
    run_id: &RunId,
    expected_seq: u64,
    document: serde_json::Value,
    operation: &str,
    by: &str,
) -> Result<SteerApplied, KubeError> {
    let name = control_configmap_name(&crate::job::job_name(run_id));
    let Some(map) = get(client, &name).await? else {
        return Err(KubeError::rejected(format!(
            "run {run_id} has no control map: its profile declares no [control], or the run is gone"
        )));
    };
    if !binding_is_run(&map, run_id) {
        return Err(KubeError::rejected(format!(
            "control map {name} is not run {run_id}'s"
        )));
    }
    let current = decode(&map)?;
    if current.operation.as_deref() == Some(operation) {
        return Ok(SteerApplied {
            seq: current.seq,
            duplicate: true,
        });
    }
    if current.seq != expected_seq {
        return Err(KubeError::Conflict {
            reason: format!(
                "expectedSeq {expected_seq} is stale; run {run_id}'s control is at seq {}",
                current.seq
            ),
        });
    }
    let next = ControlDocument {
        seq: expected_seq + 1,
        at: Some(
            time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|error| KubeError::Storage {
                    reason: error.to_string(),
                })?,
        ),
        by: Some(by.to_owned()),
        operation: Some(operation.to_owned()),
        document: Some(document),
    };
    let mut updated = map.clone();
    updated.data = Some(encode(&next)?);
    // The read resourceVersion rides in the object: a concurrent write fails with 409.
    match tokio::time::timeout(
        client.config.request_timeout,
        api(client).replace(&name, &PostParams::default(), &updated),
    )
    .await
    .map_err(|error| KubeError::unavailable(format!("control map write timed out: {error}")))?
    {
        Ok(_) => Ok(SteerApplied {
            seq: next.seq,
            duplicate: false,
        }),
        Err(kube::Error::Api(error)) if error.code == 409 => Err(KubeError::Conflict {
            reason: format!("run {run_id}'s control changed during the steer; read it again"),
        }),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_api::ScriptedApi;
    use odin_domain::{AttemptId, Digest, LaneId, ProjectId, SeatId, TaskId};

    fn labels() -> KubeJobLabels {
        KubeJobLabels {
            task_id: TaskId::new("steer-task").expect("task id"),
            run_id: RunId::new("steer-run").expect("run id"),
            attempt_id: AttemptId::new("steer-attempt").expect("attempt id"),
            seat_id: SeatId::new("worker").expect("seat id"),
            project_id: ProjectId::new("example").expect("project id"),
            lane_id: LaneId::new("worker-example").expect("lane id"),
            model: "fixture".to_owned(),
            budget_policy_digest: Digest::hash(b"fixture"),
            container_identity: Digest::hash(b"fixture"),
        }
    }

    fn stored(document: &ControlDocument) -> String {
        let job = crate::job::job_name(&labels().run_id);
        let mut map = control_map(&job, &labels()).expect("control map");
        map.data = Some(encode(document).expect("encode"));
        map.metadata.resource_version = Some("7".to_owned());
        serde_json::to_string(&map).expect("map json")
    }

    fn at(seq: u64, operation: Option<&str>) -> ControlDocument {
        ControlDocument {
            seq,
            at: None,
            by: None,
            operation: operation.map(str::to_owned),
            document: None,
        }
    }

    #[test]
    fn a_control_profile_publishes_a_mutable_run_map_reaped_with_the_run() {
        let job = crate::job::job_name(&labels().run_id);
        let map = control_map(&job, &labels()).expect("control map");
        assert_eq!(
            map.metadata.name.as_deref(),
            Some(format!("{job}-control").as_str())
        );
        assert_ne!(map.immutable, Some(true));
        // The run binding and label are what remove_run_maps and the residue sweep key on.
        assert!(binding_is_run(&map, &labels().run_id));
        assert!(map
            .metadata
            .labels
            .as_ref()
            .is_some_and(|labels| labels.contains_key(JOB_LABEL_RUN_ID)));
        assert_eq!(decode(&map).expect("decode").seq, 0);
        let (volume, mount) = control_volume(&job);
        assert_eq!(mount.mount_path, CONTROL_MOUNT_PATH);
        assert!(
            mount.sub_path.is_none(),
            "subPath would freeze the mounted file"
        );
        assert_eq!(
            volume.config_map.map(|source| source.name),
            Some(format!("{job}-control"))
        );
    }

    #[tokio::test]
    async fn steer_with_a_stale_seq_is_refused() {
        let api = ScriptedApi::start(vec![stored(&at(3, Some("earlier")))]).await;
        let refused = steer(
            &api.client(),
            &labels().run_id,
            1,
            serde_json::json!({"maxCo": 0.5}),
            "op-1",
            "kubert",
        )
        .await;
        assert!(matches!(refused, Err(KubeError::Conflict { reason }) if reason.contains("seq 3")));
        assert_eq!(api.requests().len(), 1, "a stale steer writes nothing");
    }

    #[tokio::test]
    async fn steer_replays_by_operation_id() {
        let api = ScriptedApi::start(vec![stored(&at(2, Some("op-2")))]).await;
        let replay = steer(
            &api.client(),
            &labels().run_id,
            1,
            serde_json::json!({"maxCo": 0.5}),
            "op-2",
            "kubert",
        )
        .await
        .expect("replay settles");
        assert_eq!(
            replay,
            SteerApplied {
                seq: 2,
                duplicate: true
            }
        );
        assert_eq!(api.requests().len(), 1);
    }

    #[tokio::test]
    async fn a_fresh_steer_writes_the_next_seq() {
        let next = stored(&at(1, Some("op-1")));
        let api = ScriptedApi::start(vec![stored(&at(0, None)), next]).await;
        let applied = steer(
            &api.client(),
            &labels().run_id,
            0,
            serde_json::json!({"maxCo": 0.5}),
            "op-1",
            "kubert",
        )
        .await
        .expect("steer");
        assert_eq!(
            applied,
            SteerApplied {
                seq: 1,
                duplicate: false
            }
        );
        assert_eq!(api.requests().len(), 2);
    }
}
