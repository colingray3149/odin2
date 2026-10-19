//! State moves explicitly because the cluster's default volumes are node-local.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::api::core::v1::{
    Affinity, Container, HostPathVolumeSource, NodeAffinity, NodeSelector, NodeSelectorRequirement,
    NodeSelectorTerm, PersistentVolumeClaimVolumeSource, Pod, PodSpec, Volume, VolumeMount,
};
use k8s_openapi::api::networking::v1::{NetworkPolicy, NetworkPolicySpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta, Status};
use kube::api::{AttachParams, DeleteParams, PostParams, Preconditions};
use odin_domain::{Digest, RunId};
use odin_kernel::stop::{CorrelationId, PodWorkerIdentity, StopAuthority, WorkerId};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::client::{KubeClient, KubeError};
use crate::object_wait::Settle;
use crate::reconciler::{
    bounded_resources, worker_pod_security, worker_security, WORKER_RESERVATION,
};
use crate::terminal_pod::{label_worker, stop_error};
use crate::workload::{state_claim_name, WorkloadPodPlan};

const CARRY_MOUNT: &str = "/odin-carry";
/// The label a helper's own policy selects it by: its unique name.
const HELPER_LABEL: &str = "odin.carry/helper";
/// Stops leaked helper pods even if the daemon cannot clean them up.
const HELPER_DEADLINE_SECONDS: i64 = 900;
/// How long a helper may take to start (image pull on a fresh node).
const HELPER_START: Duration = Duration::from_secs(120);
/// Includes attach, stream I/O, and exit status within the helper pod's lifetime.
const HELPER_TRANSFER: Duration = Duration::from_secs(600);
/// The stderr a failed helper command reports; the rest is drained unread.
const STDERR_KEPT: usize = 4096;
const CLAIM_GONE: Duration = Duration::from_secs(120);

/// The node a run's bound state volume lives on, when it is node-local.
pub async fn state_node(client: &KubeClient, run_id: &RunId) -> Result<Option<String>, KubeError> {
    let custody = crate::workload::state_custody(client, run_id).await?;
    Ok(custody
        .and_then(|custody| custody.admitted_nodes)
        .and_then(|nodes| (nodes.len() == 1).then(|| nodes[0].clone())))
}

fn helper_identity(seed: &str, purpose: &str) -> Result<(String, CorrelationId), KubeError> {
    let digest = Digest::hash(seed.as_bytes()).to_string();
    let hex = digest.trim_start_matches("blake3:");
    let correlation =
        CorrelationId::new(&hex[..32]).map_err(|error| KubeError::rejected(error.to_string()))?;
    Ok((format!("odin-carry-{purpose}-{}", &hex[..20]), correlation))
}

fn carry_helper(
    run_id: &RunId,
    purpose: &str,
    node: &str,
) -> Result<(String, CorrelationId), KubeError> {
    helper_identity(&format!("carry:{run_id}:{purpose}:{node}"), purpose)
}

enum Carried<'a> {
    Claim(&'a str),
    HostFolder { path: &'a str, sub_path: &'a str },
}

fn claim_helper(name: &str, claim: &str, node: &str, image: &str, read_only: bool) -> Pod {
    helper_pod(name, Carried::Claim(claim), node, image, read_only)
}

fn helper_pod(name: &str, carried: Carried<'_>, node: &str, image: &str, read_only: bool) -> Pod {
    let (volume, sub_path) = match carried {
        Carried::Claim(claim) => (
            Volume {
                name: "state".to_owned(),
                persistent_volume_claim: Some(PersistentVolumeClaimVolumeSource {
                    claim_name: claim.to_owned(),
                    read_only: Some(read_only),
                }),
                ..Default::default()
            },
            None,
        ),
        Carried::HostFolder { path, sub_path } => (
            Volume {
                name: "state".to_owned(),
                host_path: Some(HostPathVolumeSource {
                    path: path.to_owned(),
                    type_: Some("Directory".to_owned()),
                }),
                ..Default::default()
            },
            Some(sub_path.to_owned()),
        ),
    };
    Pod {
        metadata: ObjectMeta {
            name: Some(name.to_owned()),
            labels: Some(helper_labels(name)),
            ..Default::default()
        },
        spec: Some(PodSpec {
            // WaitForFirstConsumer needs scheduler selection; nodeName would bypass it.
            affinity: Some(Affinity {
                node_affinity: Some(NodeAffinity {
                    required_during_scheduling_ignored_during_execution: Some(NodeSelector {
                        node_selector_terms: vec![NodeSelectorTerm {
                            match_expressions: Some(vec![NodeSelectorRequirement {
                                key: "kubernetes.io/hostname".to_owned(),
                                operator: "In".to_owned(),
                                values: Some(vec![node.to_owned()]),
                            }]),
                            match_fields: None,
                        }],
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            active_deadline_seconds: Some(HELPER_DEADLINE_SECONDS),
            automount_service_account_token: Some(false),
            restart_policy: Some("Never".to_owned()),
            termination_grace_period_seconds: Some(0),
            security_context: Some(worker_pod_security()),
            containers: vec![Container {
                name: "carry".to_owned(),
                image: Some(image.to_owned()),
                command: Some(vec![
                    "sleep".to_owned(),
                    HELPER_DEADLINE_SECONDS.to_string(),
                ]),
                volume_mounts: Some(vec![VolumeMount {
                    name: "state".to_owned(),
                    mount_path: CARRY_MOUNT.to_owned(),
                    read_only: Some(read_only),
                    sub_path,
                    ..Default::default()
                }]),
                resources: Some(bounded_resources(WORKER_RESERVATION)),
                security_context: Some(worker_security()),
                ..Default::default()
            }],
            volumes: Some(vec![volume]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn helper_labels(name: &str) -> BTreeMap<String, String> {
    BTreeMap::from([(HELPER_LABEL.to_owned(), name.to_owned())])
}

// Archive transfer uses exec and needs no network egress.
fn helper_policy(name: &str) -> NetworkPolicy {
    NetworkPolicy {
        metadata: ObjectMeta {
            name: Some(name.to_owned()),
            labels: Some(helper_labels(name)),
            ..Default::default()
        },
        spec: Some(NetworkPolicySpec {
            pod_selector: Some(LabelSelector {
                match_labels: Some(helper_labels(name)),
                ..Default::default()
            }),
            policy_types: Some(vec!["Egress".to_owned()]),
            egress: Some(Vec::new()),
            ingress: None,
        }),
    }
}

async fn request<T>(
    client: &KubeClient,
    future: impl Future<Output = Result<T, kube::Error>>,
) -> Result<T, KubeError> {
    tokio::time::timeout(client.request_timeout(), future)
        .await
        .map_err(|_| KubeError::unavailable("state carry API request timed out"))?
        .map_err(KubeError::from)
}

struct Helper {
    stops: Arc<StopAuthority>,
    worker: WorkerId,
    name: String,
    armed: bool,
}

impl Helper {
    async fn start(
        client: &KubeClient,
        stops: &Arc<StopAuthority>,
        correlation: &CorrelationId,
        pod: Pod,
    ) -> Result<Self, KubeError> {
        let name = pod.metadata.name.clone().unwrap_or_default();
        let worker = odin_kernel::stop::mint_worker_id()
            .map_err(|error| KubeError::unavailable(error.to_string()))?;
        let mut identity = PodWorkerIdentity {
            cluster: client.config.cluster.clone(),
            namespace: client.config.namespace.clone(),
            pod_name: name.clone(),
            pod_uid: None,
            policy_name: name.clone(),
            policy_uid: None,
            secret_name: None,
            secret_uid: None,
            correlation_id: correlation.as_str().to_owned(),
        };
        stops
            .register_pod_worker(&worker, &identity, correlation)
            .map_err(stop_error)?;
        let mut helper = Self {
            stops: Arc::clone(stops),
            worker,
            name,
            armed: true,
        };
        let started = async {
            let uid = helper
                .launch(client, correlation, pod, &mut identity)
                .await?;
            helper.started(client, &uid).await
        }
        .await;
        match started {
            Ok(()) => Ok(helper),
            Err(error) => {
                if helper.armed {
                    let name = helper.name.clone();
                    if let Err(cleanup) = helper.stop() {
                        tracing::error!(name = %name, "state carry helper stop failed: {cleanup}");
                    }
                } else {
                    tracing::error!(worker = %helper.worker, name = %helper.name,
                        "state carry helper creation did not finish; cleanup deferred to startup: {error}");
                }
                Err(error)
            }
        }
    }

    async fn launch(
        &mut self,
        client: &KubeClient,
        correlation: &CorrelationId,
        mut pod: Pod,
        identity: &mut PodWorkerIdentity,
    ) -> Result<String, KubeError> {
        let mut policy = helper_policy(&self.name);
        label_worker(&mut policy.metadata, &self.worker, correlation);
        label_worker(&mut pod.metadata, &self.worker, correlation);
        let (policies, pods) = (client.network_policies(), client.pods());
        // An interrupted create may still commit, so retain its ledger row until startup.
        self.armed = false;
        let created = tokio::time::timeout(
            client.request_timeout(),
            policies.create(&PostParams::default(), &policy),
        )
        .await
        .map_err(|error| {
            KubeError::unavailable(format!("state carry policy creation timed out: {error}"))
        })?;
        self.armed = true;
        let created = created?;
        identity.policy_uid = created.metadata.uid;
        self.stops
            .update_pod_worker_identity(&self.worker, identity)
            .map_err(stop_error)?;
        self.armed = false;
        let created = tokio::time::timeout(
            client.request_timeout(),
            pods.create(&PostParams::default(), &pod),
        )
        .await
        .map_err(|error| {
            KubeError::unavailable(format!("state carry pod creation timed out: {error}"))
        })?;
        self.armed = true;
        let created = created?;
        identity.pod_uid = created.metadata.uid;
        self.stops
            .update_pod_worker_identity(&self.worker, identity)
            .map_err(stop_error)?;
        identity.pod_uid.clone().ok_or_else(|| {
            KubeError::unavailable(format!(
                "state carry helper {} creation returned no UID",
                self.name
            ))
        })
    }

    async fn started(&self, client: &KubeClient, uid: &str) -> Result<(), KubeError> {
        let name = &self.name;
        crate::object_wait::wait_for(
            &client.pods(),
            name,
            HELPER_START,
            || {
                format!(
                    "state carry helper {name} did not start within {}s",
                    HELPER_START.as_secs()
                )
            },
            |pod| match pod {
                Some(pod) if pod.metadata.uid.as_deref() != Some(uid) => {
                    Settle::Fail(replaced(name))
                }
                None => Settle::Fail(replaced(name)),
                Some(pod) => match phase(pod) {
                    Some("Running") => Settle::Done(()),
                    Some(phase @ ("Failed" | "Succeeded")) => Settle::Fail(KubeError::rejected(
                        format!("state carry helper {name} ended before it ran ({phase})"),
                    )),
                    _ => Settle::Wait,
                },
            },
        )
        .await
    }

    async fn run(
        &self,
        client: &KubeClient,
        argv: &[&str],
        input: Option<&[u8]>,
        limit: u64,
    ) -> Result<Vec<u8>, KubeError> {
        helper_exec(client, &self.name, argv, input, limit, HELPER_TRANSFER).await
    }

    fn stop(mut self) -> Result<(), KubeError> {
        self.armed = false;
        let outcome = self
            .stops
            .stop_pod_worker(&self.worker)
            .map_err(stop_error)?;
        if outcome.verdict != odin_domain::StopVerdictTag::Stopped {
            return Err(KubeError::unavailable(format!(
                "stop state carry helper {}: {:?}",
                self.worker, outcome.evidence.missing
            )));
        }
        Ok(())
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Err(error) = self.stops.request_pod_stop(&self.worker) {
            tracing::error!(
                "carry helper stop request failed worker={} error={error}",
                self.worker
            );
        }
        let runtime = match tokio::runtime::Handle::try_current() {
            Ok(runtime) => runtime,
            Err(error) => {
                tracing::error!(worker = %self.worker, "state carry helper stop could not start: {error}");
                return;
            }
        };
        let (stops, worker) = (Arc::clone(&self.stops), self.worker.clone());
        drop(runtime.spawn_blocking(move || {
            if let Err(error) = stops.stop_pod_worker(&worker) {
                tracing::error!(worker = %worker, "state carry helper stop failed: {error}");
            }
        }));
    }
}

fn phase(pod: &Pod) -> Option<&str> {
    pod.status.as_ref()?.phase.as_deref()
}

fn replaced(name: &str) -> KubeError {
    KubeError::Conflict {
        reason: format!("state carry helper {name} is no longer the Pod this carry created"),
    }
}

async fn in_helper(
    client: &KubeClient,
    stops: &Arc<StopAuthority>,
    correlation: &CorrelationId,
    pod: Pod,
    argv: &[&str],
    input: Option<&[u8]>,
    limit: u64,
) -> Result<Vec<u8>, KubeError> {
    let helper = Helper::start(client, stops, correlation, pod).await?;
    let name = helper.name.clone();
    let used = helper.run(client, argv, input, limit).await;
    if let Err(error) = helper.stop() {
        tracing::error!(name = %name, "state carry helper stop failed: {error}");
    }
    used
}

fn gone<K>(object: Option<&K>) -> Settle<()> {
    match object {
        None => Settle::Done(()),
        Some(_) => Settle::Wait,
    }
}

async fn helper_exec(
    client: &KubeClient,
    pod: &str,
    argv: &[&str],
    input: Option<&[u8]>,
    limit: u64,
    bound: Duration,
) -> Result<Vec<u8>, KubeError> {
    let deadline = tokio::time::Instant::now() + bound;
    let params = AttachParams {
        stdin: input.is_some(),
        stdout: true,
        stderr: true,
        tty: false,
        ..AttachParams::default()
    }
    .container("carry");
    let attach = deadline.min(tokio::time::Instant::now() + client.request_timeout());
    let mut process = tokio::time::timeout_at(
        attach,
        client.pods().exec(pod, argv.iter().copied(), &params),
    )
    .await
    .map_err(|_| KubeError::unavailable("state carry exec attach timed out"))??;
    let status = process.take_status();
    let stdout = process
        .stdout()
        .ok_or_else(|| KubeError::unavailable("state carry exec opened without stdout"))?;
    let (feed, stderr) = (process.stdin().zip(input), process.stderr());
    let exchanged = exchange(feed, stdout, stderr, status, limit, deadline).await;
    if exchanged.is_err() {
        process.abort();
    }
    let joined = tokio::time::timeout_at(deadline, process.join()).await;
    let (out, err, verdict) = exchanged?;
    match joined {
        Ok(Ok(())) => settle(argv, out, &err, verdict),
        Ok(Err(error)) => Err(KubeError::unavailable(format!(
            "state carry exec stream failed: {error}"
        ))),
        Err(_) => Err(KubeError::unavailable(
            "state carry exec stream did not close within its bound",
        )),
    }
}

fn stream_error(stream: &'static str) -> impl Fn(std::io::Error) -> KubeError {
    move |error| KubeError::unavailable(format!("state carry {stream}: {error}"))
}

// Drain all streams concurrently so a full stderr pipe cannot stall an archive.
async fn exchange(
    feed: Option<(impl AsyncWrite + Unpin, &[u8])>,
    stdout: impl AsyncRead + Unpin,
    stderr: Option<impl AsyncRead + Unpin>,
    status: Option<impl Future<Output = Option<Status>>>,
    limit: u64,
    deadline: tokio::time::Instant,
) -> Result<(Vec<u8>, Vec<u8>, Option<Status>), KubeError> {
    let transfer = async move {
        let writer = async move {
            if let Some((mut stdin, input)) = feed {
                stdin
                    .write_all(input)
                    .await
                    .map_err(stream_error("stdin"))?;
                stdin.shutdown().await.map_err(stream_error("stdin"))?;
            }
            Ok::<_, KubeError>(())
        };
        let reader = async move {
            let mut out = Vec::new();
            stdout
                .take(limit + 1)
                .read_to_end(&mut out)
                .await
                .map_err(stream_error("stdout"))?;
            if out.len() as u64 > limit {
                return Err(KubeError::rejected(format!(
                    "the state volume holds more than its declared {limit} bytes"
                )));
            }
            Ok::<_, KubeError>(out)
        };
        let ((), out) = tokio::try_join!(writer, reader)?;
        Ok::<_, KubeError>(out)
    };
    let errors = async move {
        let (mut kept, mut chunk) = (Vec::new(), [0u8; 4096]);
        if let Some(mut stderr) = stderr {
            loop {
                let read = stderr
                    .read(&mut chunk)
                    .await
                    .map_err(stream_error("stderr"))?;
                if read == 0 {
                    break;
                }
                let room = STDERR_KEPT.saturating_sub(kept.len()).min(read);
                kept.extend_from_slice(&chunk[..room]);
            }
        }
        Ok::<_, KubeError>(kept)
    };
    let complete = async move {
        let (out, err) = tokio::try_join!(transfer, errors)?;
        let verdict = match status {
            Some(status) => status.await,
            None => None,
        };
        Ok::<_, KubeError>((out, err, verdict))
    };
    tokio::time::timeout_at(deadline, complete)
        .await
        .map_err(|_| {
            KubeError::unavailable("state carry helper I/O did not finish within its bound")
        })?
}

fn settle(
    argv: &[&str],
    out: Vec<u8>,
    err: &[u8],
    verdict: Option<Status>,
) -> Result<Vec<u8>, KubeError> {
    if verdict
        .as_ref()
        .is_some_and(|status| status.status.as_deref() == Some("Success"))
    {
        return Ok(out);
    }
    let reason = verdict
        .and_then(|status| status.message.or(status.reason))
        .unwrap_or_else(|| "no exit status".to_owned());
    Err(KubeError::rejected(format!(
        "`{}` failed in the pod's image: {reason}; {}",
        argv.join(" "),
        String::from_utf8_lossy(err).trim()
    )))
}

fn carry_limit(plan: &WorkloadPodPlan) -> u64 {
    odin_registry::schema::storage_quantity_bytes(&plan.state_storage).unwrap_or(1 << 30)
}

/// Stop the worker first so the read-only tar snapshot is consistent.
pub async fn snapshot(
    client: &KubeClient,
    stops: &Arc<StopAuthority>,
    run_id: &RunId,
    plan: &WorkloadPodPlan,
    node: &str,
    image: &str,
) -> Result<Vec<u8>, KubeError> {
    let (name, correlation) = carry_helper(run_id, "out", node)?;
    let pod = claim_helper(&name, &state_claim_name(run_id), node, image, true);
    in_helper(
        client,
        stops,
        &correlation,
        pod,
        &["tar", "-C", CARRY_MOUNT, "-cf", "-", "."],
        None,
        carry_limit(plan) + (1 << 20),
    )
    .await
}

/// Export location from the Job's pod template and the node its pod ran on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportSite {
    pub node: String,
    pub image: String,
    pub host_folder: String,
    pub subfolder: String,
}

/// Use the Job's saved declaration, not live configuration; no per-run mount returns `None`.
pub fn export_site(job: &k8s_openapi::api::batch::v1::Job, node: &str) -> Option<ExportSite> {
    let spec = job.spec.as_ref()?.template.spec.as_ref()?;
    let host_folder = spec
        .volumes
        .as_ref()?
        .iter()
        .find(|volume| volume.name == crate::workload::WORKLOAD_EXPORT_VOLUME)?
        .host_path
        .as_ref()?
        .path
        .clone();
    let (container, mount) = spec.containers.iter().find_map(|container| {
        container
            .volume_mounts
            .as_ref()?
            .iter()
            .find(|mount| mount.name == crate::workload::WORKLOAD_EXPORT_VOLUME)
            .map(|mount| (container, mount))
    })?;
    Some(ExportSite {
        node: node.to_owned(),
        image: container.image.clone()?,
        host_folder,
        subfolder: mount.sub_path.clone().filter(|sub| !sub.is_empty())?,
    })
}

/// The workload image supplies Python's tarfile module but no tar executable.
const EXPORT_ARCHIVE: [&str; 4] = [
    "/bin/python3",
    "-c",
    "import sys, tarfile\nwith tarfile.open(fileobj=sys.stdout.buffer, mode='w|') as archive:\n    archive.add(sys.argv[1], arcname='.')",
    CARRY_MOUNT,
];

pub async fn export_tar(
    client: &KubeClient,
    stops: &Arc<StopAuthority>,
    site: &ExportSite,
    limit: u64,
) -> Result<Vec<u8>, KubeError> {
    let (name, correlation) = helper_identity(
        &format!("export:{}:{}", site.subfolder, site.node),
        "export",
    )?;
    let pod = helper_pod(
        &name,
        Carried::HostFolder {
            path: &site.host_folder,
            sub_path: &site.subfolder,
        },
        &site.node,
        &site.image,
        true,
    );
    in_helper(
        client,
        stops,
        &correlation,
        pod,
        &EXPORT_ARCHIVE,
        None,
        limit,
    )
    .await
}

/// Ignore directory entries so an empty export folder counts as no export.
pub fn tar_file_count(tar: &[u8]) -> usize {
    let mut files = 0;
    let mut offset = 0;
    while offset + 512 <= tar.len() {
        let header = &tar[offset..offset + 512];
        if header.iter().all(|byte| *byte == 0) {
            break;
        }
        let size = std::str::from_utf8(&header[124..136])
            .ok()
            .map(|field| field.trim_matches(|c: char| c == '\0' || c == ' '))
            .and_then(|field| u64::from_str_radix(field, 8).ok())
            .unwrap_or(0);
        if matches!(header[156], b'0' | 0) {
            files += 1;
        }
        let blocks = size.div_ceil(512);
        offset += 512 + usize::try_from(blocks * 512).unwrap_or(usize::MAX - offset);
    }
    files
}

// Strip the snapshot's `./` prefix so extraction leaves mounted-root metadata alone.
fn replant_argv(mount: &str) -> [&str; 6] {
    ["tar", "-C", mount, "--strip-components=1", "-xf", "-"]
}

/// Persist the snapshot before calling: moving to another node deletes the old volume.
pub async fn replant(
    client: &KubeClient,
    stops: &Arc<StopAuthority>,
    run_id: &RunId,
    plan: &WorkloadPodPlan,
    target: &str,
    image: &str,
    tar: &[u8],
) -> Result<(), KubeError> {
    let claims = client.persistent_volume_claims();
    let claim = state_claim_name(run_id);
    let original = request(client, claims.get_opt(&claim)).await?;
    let stale = crate::workload::state_custody(client, run_id)
        .await?
        .and_then(|custody| custody.admitted_nodes)
        .is_some_and(|nodes| !nodes.is_empty() && !nodes.iter().any(|node| node == target));
    if stale {
        let uid = original
            .and_then(|claim| claim.metadata.uid)
            .ok_or_else(|| {
                KubeError::unavailable(format!("state claim {claim} has no UID for deletion"))
            })?;
        let delete = DeleteParams {
            preconditions: Some(Preconditions {
                uid: Some(uid),
                resource_version: None,
            }),
            ..DeleteParams::default()
        };
        match tokio::time::timeout(client.request_timeout(), claims.delete(&claim, &delete)).await {
            Ok(Ok(_)) => {}
            Ok(Err(kube::Error::Api(status))) if status.code == 404 => {}
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => return Err(KubeError::unavailable("state claim deletion timed out")),
        }
        crate::object_wait::wait_for(
            &claims,
            &claim,
            CLAIM_GONE,
            || format!("state claim {claim} is still in use; its old pod has not gone away"),
            gone,
        )
        .await?;
    }
    crate::workload::ensure_state_claim(client, run_id, plan).await?;
    let (name, correlation) = carry_helper(run_id, "in", target)?;
    let pod = claim_helper(&name, &claim, target, image, false);
    in_helper(
        client,
        stops,
        &correlation,
        pod,
        &replant_argv(CARRY_MOUNT),
        Some(tar),
        1 << 20,
    )
    .await
    .map(|_| ())
}

/// Rehome must satisfy the same placement labels as the initial launch.
pub async fn require_node_fits(
    client: &KubeClient,
    target: &str,
    selector: &BTreeMap<String, String>,
) -> Result<(), KubeError> {
    let nodes: kube::Api<k8s_openapi::api::core::v1::Node> = kube::Api::all(client.client.clone());
    let node = tokio::time::timeout(client.request_timeout(), nodes.get_opt(target))
        .await
        .map_err(|_| KubeError::unavailable("rehome target node query timed out"))??
        .ok_or_else(|| {
            KubeError::rejected(format!(
                "rehome target node {target:?} is not in the cluster"
            ))
        })?;
    let missing = missing_placement(&node.metadata.labels.unwrap_or_default(), selector);
    if missing.is_empty() {
        Ok(())
    } else {
        Err(KubeError::rejected(format!(
            "node {target} does not satisfy the pod's declared placement (missing {})",
            missing.join(", ")
        )))
    }
}

fn missing_placement(
    labels: &BTreeMap<String, String>,
    selector: &BTreeMap<String, String>,
) -> Vec<String> {
    selector
        .iter()
        .filter(|(key, value)| labels.get(*key) != Some(*value))
        .map(|(key, value)| format!("{key}={value}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tar_header(name: &str, kind: u8, size: usize) -> Vec<u8> {
        let mut header = vec![0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        let size = format!("{size:011o}\0");
        header[124..136].copy_from_slice(size.as_bytes());
        header[156] = kind;
        header
    }

    #[test]
    fn the_tar_walk_counts_regular_files_only() {
        let mut tar = tar_header("./", b'5', 0);
        tar.extend(vec![0u8; 1024]);
        assert_eq!(tar_file_count(&tar), 0, "an empty folder exports nothing");
        let mut tar = tar_header("./", b'5', 0);
        tar.extend(tar_header("./result.csv", b'0', 600));
        tar.extend(vec![b'x'; 1024]);
        tar.extend(tar_header("./plots", b'5', 0));
        tar.extend(tar_header("./plots/a.png", b'0', 3));
        tar.extend(vec![b'y'; 512]);
        tar.extend(vec![0u8; 1024]);
        assert_eq!(tar_file_count(&tar), 2);
    }

    #[cfg(unix)]
    #[test]
    fn replant_preserves_payload_without_restoring_mount_root_metadata() {
        use std::io::Write;
        use std::os::unix::fs::{symlink, PermissionsExt};
        use std::process::{Command, Stdio};

        let archived_time = std::time::UNIX_EPOCH + Duration::from_secs(60);
        for populated in [false, true] {
            let source = tempfile::tempdir().expect("source volume");
            let destination = tempfile::tempdir().expect("destination volume");
            if populated {
                std::fs::write(source.path().join("counter"), b"42\n").expect("counter");
                std::fs::write(source.path().join(".hidden"), b"hidden").expect("hidden file");
                std::fs::create_dir(source.path().join("nested")).expect("nested directory");
                std::fs::write(source.path().join("nested/worker"), b"payload")
                    .expect("nested file");
                std::fs::set_permissions(
                    source.path().join("nested/worker"),
                    std::fs::Permissions::from_mode(0o751),
                )
                .expect("payload mode");
                std::fs::create_dir(source.path().join("empty")).expect("empty directory");
                symlink("nested/worker", source.path().join("link")).expect("payload symlink");
            }
            std::fs::set_permissions(source.path(), std::fs::Permissions::from_mode(0o700))
                .expect("source root mode");
            std::fs::File::open(source.path())
                .expect("source root")
                .set_modified(archived_time)
                .expect("source root timestamp");
            std::fs::set_permissions(destination.path(), std::fs::Permissions::from_mode(0o750))
                .expect("destination root mode");
            let archive = Command::new("tar")
                .arg("-C")
                .arg(source.path())
                .args(["-cf", "-", "."])
                .output()
                .expect("snapshot tar");
            assert!(archive.status.success(), "{:?}", archive);

            let argv = replant_argv(destination.path().to_str().expect("destination path"));
            let mut extract = Command::new(argv[0])
                .args(&argv[1..])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("replant tar");
            extract
                .stdin
                .take()
                .expect("archive input")
                .write_all(&archive.stdout)
                .expect("feed archive");
            let extracted = extract.wait_with_output().expect("replant completion");
            assert!(extracted.status.success(), "{:?}", extracted);

            let root = std::fs::metadata(destination.path()).expect("destination root");
            assert_eq!(root.permissions().mode() & 0o777, 0o750);
            assert_ne!(root.modified().expect("root timestamp"), archived_time);
            if populated {
                assert_eq!(
                    std::fs::read(destination.path().join("counter")).expect("carried counter"),
                    b"42\n"
                );
                assert_eq!(
                    std::fs::read(destination.path().join(".hidden")).expect("carried hidden file"),
                    b"hidden"
                );
                assert_eq!(
                    std::fs::read(destination.path().join("nested/worker"))
                        .expect("carried nested file"),
                    b"payload"
                );
                let worker = std::fs::metadata(destination.path().join("nested/worker"))
                    .expect("payload metadata");
                assert_eq!(worker.permissions().mode() & 0o777, 0o751);
                assert!(destination.path().join("empty").is_dir());
                assert_eq!(
                    std::fs::read_link(destination.path().join("link")).expect("payload link"),
                    std::path::Path::new("nested/worker")
                );
            } else {
                assert_eq!(std::fs::read_dir(destination.path()).unwrap().count(), 0);
            }
        }
    }

    #[test]
    fn the_export_site_is_the_jobs_own_declaration() {
        use k8s_openapi::api::batch::v1::{Job, JobSpec};
        use k8s_openapi::api::core::v1::PodTemplateSpec;
        let run = RunId::new("run:live:export-site:pod:counter").expect("run id");
        let plan = counter_plan();
        let job = |mounts: Vec<VolumeMount>, volumes: Vec<Volume>| Job {
            spec: Some(JobSpec {
                template: PodTemplateSpec {
                    spec: Some(PodSpec {
                        containers: vec![Container {
                            name: "odin-worker".to_owned(),
                            image: Some("python@sha256:1".to_owned()),
                            volume_mounts: Some(mounts),
                            ..Default::default()
                        }],
                        volumes: Some(volumes),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                ..Default::default()
            }),
            ..Default::default()
        };
        let (mut volumes, mut mounts) = (Vec::new(), Vec::new());
        crate::workload::inject_pod_volumes(&plan, &run, &mut volumes, &mut mounts);
        assert_eq!(
            export_site(&job(mounts.clone(), volumes.clone()), "pc"),
            Some(ExportSite {
                node: "pc".to_owned(),
                image: "python@sha256:1".to_owned(),
                host_folder: "/srv/odin/export".to_owned(),
                subfolder: crate::job::job_name(&run),
            })
        );
        for mount in &mut mounts {
            mount.sub_path = None;
        }
        assert_eq!(
            export_site(&job(mounts, volumes), "pc"),
            None,
            "a shared export folder cannot say which files are this run's"
        );
    }

    #[test]
    fn a_rehome_target_must_carry_the_declared_placement() {
        let labels = |pairs: &[(&str, &str)]| {
            pairs
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect::<BTreeMap<_, _>>()
        };
        let declared = labels(&[("odin.capability/scrape", "true")]);
        let pc = labels(&[
            ("odin.capability/cfd", "true"),
            ("odin.capability/gpu", "true"),
        ]);
        let mini = labels(&[
            ("odin.capability/scrape", "true"),
            ("odin.capability/embed", "true"),
        ]);
        assert_eq!(
            missing_placement(&pc, &declared),
            vec!["odin.capability/scrape=true".to_owned()]
        );
        assert!(missing_placement(&mini, &declared).is_empty());
        assert!(missing_placement(&pc, &BTreeMap::new()).is_empty());
    }

    fn assert_helper_confined_like_its_admitted_workload(pod: &Pod) {
        let spec = pod.spec.as_ref().expect("helper spec");
        let security = spec
            .security_context
            .as_ref()
            .expect("a helper is confined pod-wide exactly as its admitted workload is");
        assert_eq!(security.run_as_non_root, Some(true));
        assert_eq!(
            security.run_as_user,
            Some(crate::reconciler::WORKER_RUN_AS_USER),
            "the admitted workload's pinned non-root uid (WORKER_RUN_AS_USER)"
        );
        assert_eq!(
            security
                .seccomp_profile
                .as_ref()
                .map(|profile| profile.type_.as_str()),
            Some("RuntimeDefault")
        );
        let container = spec
            .containers
            .first()
            .expect("a helper runs exactly one container");
        let confined = container
            .security_context
            .as_ref()
            .expect("the helper container carries the admitted container confinement");
        assert_eq!(confined.allow_privilege_escalation, Some(false));
        let capabilities = confined
            .capabilities
            .as_ref()
            .expect("the helper's capability set");
        assert_eq!(
            capabilities
                .drop
                .as_ref()
                .expect("every capability dropped"),
            &["ALL"]
        );
        assert!(
            capabilities.add.as_deref().unwrap_or_default().is_empty(),
            "a helper adds no capability"
        );
        assert_eq!(confined.run_as_non_root, Some(true));
        let resources = container
            .resources
            .as_ref()
            .expect("the helper declares the admitted workload's resource bound");
        let limits = resources.limits.as_ref().expect("a helper is bounded");
        for bound in ["cpu", "memory", "ephemeral-storage"] {
            assert!(limits.contains_key(bound), "a helper is bounded in {bound}");
        }
        assert_eq!(
            resources.requests.as_ref(),
            Some(limits),
            "a helper's bound is flat (requests == limits) like every admitted container's"
        );
    }

    #[test]
    fn a_state_carry_helper_is_confined_like_its_admitted_workload() {
        let run = RunId::new("run:live:carry-confinement:pod:counter").expect("run id");
        let pod = claim_helper(
            "odin-carry-out-confined",
            &state_claim_name(&run),
            "mini",
            "python@sha256:1",
            true,
        );
        assert_helper_confined_like_its_admitted_workload(&pod);
    }

    fn counter_plan() -> WorkloadPodPlan {
        WorkloadPodPlan {
            profile: "counter".to_owned(),
            state_mount: "/state".to_owned(),
            export_mount: "/export".to_owned(),
            export_host_folder: "/srv/odin/export".to_owned(),
            state_storage: "1Gi".to_owned(),
            state_storage_class: None,
            allow_hosts: Vec::new(),
            agent: None,
        }
    }

    fn status(summary: &str) -> Status {
        Status {
            status: Some(summary.to_owned()),
            message: Some(format!("exit {summary}")),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn exchange_copies_archive_and_drains_stderr() {
        let input = b"archive input";
        let stdout = b"archive output";
        let stderr = vec![b'e'; STDERR_KEPT * 2];
        let mut sent = Vec::new();
        let (out, err, verdict) = exchange(
            Some((&mut sent, input.as_slice())),
            stdout.as_slice(),
            Some(stderr.as_slice()),
            Some(std::future::ready(Some(status("Success")))),
            stdout.len() as u64,
            tokio::time::Instant::now() + HELPER_TRANSFER,
        )
        .await
        .expect("archive transfer");
        assert_eq!(sent, input);
        assert_eq!(out, stdout);
        assert_eq!(err, vec![b'e'; STDERR_KEPT]);
        assert_eq!(settle(&["tar"], out, &err, verdict).unwrap(), stdout);
    }

    #[tokio::test]
    async fn exchange_rejects_output_over_the_limit() {
        let result = exchange(
            None::<(tokio::io::Sink, &[u8])>,
            b"too large".as_slice(),
            None::<tokio::io::Empty>,
            Some(std::future::ready(Some(status("Success")))),
            3,
            tokio::time::Instant::now() + HELPER_TRANSFER,
        )
        .await;
        assert!(matches!(result, Err(KubeError::Rejected { .. })));
    }

    #[tokio::test]
    async fn exchange_deadline_includes_exit_status() {
        let result = exchange(
            None::<(tokio::io::Sink, &[u8])>,
            tokio::io::empty(),
            None::<tokio::io::Empty>,
            Some(std::future::pending::<Option<Status>>()),
            0,
            tokio::time::Instant::now(),
        )
        .await;
        assert!(matches!(result, Err(KubeError::Unavailable { .. })));
    }

    #[test]
    fn only_a_reported_success_settles_a_helper_command() {
        let failed = settle(
            &["tar", "-xf", "-"],
            b"partial".to_vec(),
            b"tar: short read",
            Some(status("Failure")),
        )
        .expect_err("a failed command")
        .to_string();
        assert!(
            failed.contains("exit Failure") && failed.contains("tar: short read"),
            "{failed}"
        );
        assert!(settle(&["tar"], Vec::new(), b"", None).is_err());
    }
}
