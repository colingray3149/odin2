use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Args;
use odin_domain::{StopVerdict, StopVerdictTag};
use odin_huginn::RuntimeManifest;
use odin_kernel::stop::StopOutcome;
use odin_kernel::{recovery_worker_channel, JobStopOutcome, ParentAuthorityClient, StopAuthority};
use odin_kube::{job_worker_backend, KubeClient, KubeConfig};
use odin_ledger::stop::JobStopAction;
use odin_ledger::Ledger;
use odin_types::WorkerId;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmergencyStopConfig {
    state_root: PathBuf,
    worker_bus: String,
    #[serde(default)]
    worker_ids: Vec<String>,
    /// Trusted deployment manifest naming the packaged odind config whose
    /// `kube` section alone authorizes host-side Kubernetes Job actuation.
    #[serde(default)]
    runtime_manifest: Option<PathBuf>,
}
#[derive(Debug, Args)]
pub(crate) struct EmergencyStopArgs {
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
    #[arg(long, value_name = "PATH")]
    output: PathBuf,
}
pub(crate) fn emergency_stop(arguments: EmergencyStopArgs) -> Result<(), String> {
    let metadata = fs::metadata(&arguments.config).map_err(|error| {
        format!(
            "could not inspect emergency-stop config {}: {error}",
            arguments.config.display()
        )
    })?;
    let caller_uid = fs::metadata("/proc/self")
        .map_err(|error| format!("could not inspect caller identity: {error}"))?
        .uid();
    let mode = metadata.permissions().mode() & 0o777;
    if !metadata.is_file() || metadata.uid() != caller_uid || mode != 0o600 {
        return Err(format!(
            "emergency-stop config {} must be a caller-owned mode-0600 regular file",
            arguments.config.display()
        ));
    }
    if metadata.len() > 1024 * 1024 {
        return Err("emergency-stop config exceeds the 1 MiB ceiling".to_owned());
    }
    let bytes = fs::read(&arguments.config).map_err(|error| {
        format!(
            "could not read emergency-stop config {}: {error}",
            arguments.config.display()
        )
    })?;
    let config: EmergencyStopConfig = serde_json::from_slice(&bytes)
        .map_err(|error| format!("emergency-stop config is invalid: {error}"))?;
    if !config.state_root.is_absolute() || config.worker_bus.trim().is_empty() {
        return Err(
            "emergency-stop config requires an absolute state_root and explicit worker_bus"
                .to_owned(),
        );
    }
    if config
        .runtime_manifest
        .as_ref()
        .is_some_and(|path| !path.is_absolute())
    {
        return Err("emergency-stop runtime manifest must be an absolute path".to_owned());
    }
    let ledger_path = config.state_root.join("ledger.sqlite3");
    let parent = ParentAuthorityClient::from_env()
        .map_err(|error| format!("emergency-stop parent authority rejected: {error}"))?;
    if parent.is_remote()
        && parent
            .expected_store_path()
            .map_err(|error| error.to_string())?
            != ledger_path
    {
        return Err("emergency-stop config does not name the assigned authority ledger".to_owned());
    }
    let ledger = Ledger::open(&ledger_path).map_err(|error| {
        format!(
            "could not open stop ledger {}: {error}",
            ledger_path.display()
        )
    })?;
    let store = Arc::new(Mutex::new(ledger));
    // A remote parent-scoped child keeps only the process paths: the Job
    // backend is host-only and never constructed, and no Job stop intent is
    // ever journaled from a remote child.
    let remote = parent.is_remote();
    // The CLI keeps its own ledger handle: explicit-id disambiguation and
    // the pending-Job sweep read the registry read-only while the authority
    // owns its own handle to the same store.
    let authority = if parent.is_remote() {
        StopAuthority::from_parent(store.clone(), parent)
            .map_err(|error| format!("emergency-stop scoped authority rejected: {error}"))?
    } else {
        let channel = recovery_worker_channel(&config.worker_bus)
            .map_err(|error| format!("worker recovery channel rejected: {error}"))?;
        StopAuthority::new(store.clone(), channel)
    };
    let kube_store = additional_kube_store(&config, remote, &ledger_path)?;
    let kube_authority = kube_store
        .as_ref()
        .map(|store| {
            recovery_worker_channel(&config.worker_bus)
                .map(|channel| StopAuthority::new(Arc::clone(store), channel))
                .map_err(|error| format!("kube worker recovery channel rejected: {error}"))
        })
        .transpose()?;
    let mut extra_pods = Vec::new();
    let mut extra_jobs = Vec::new();
    let mut documents: Vec<serde_json::Value> = Vec::new();
    let mut unresolved: Vec<String> = Vec::new();
    let mut attempted = 0usize;
    let mut pod_ids = if config.worker_ids.is_empty() && !remote {
        pending_pod_worker_ids(&store)?
    } else {
        Vec::new()
    };
    let job_targets = if config.worker_ids.is_empty() {
        let outcomes = authority
            .recover_pending(None)
            .map_err(|error| format!("worker stop recovery failed: {error}"))?;
        attempted += outcomes.len();
        record_process_outcomes(outcomes, &mut documents, &mut unresolved)?;
        if let Some(store) = &kube_store {
            extra_pods = pending_pod_worker_ids(store)?;
            extra_jobs = pending_job_worker_ids(store)?;
        }
        JobTargets::AllPending
    } else {
        let mut explicit = Vec::with_capacity(config.worker_ids.len());
        for raw in &config.worker_ids {
            let worker_id = WorkerId::new(raw)
                .map_err(|error| format!("invalid emergency worker id {raw:?}: {error}"))?;
            if pod_worker_record(&store, &worker_id)? {
                if remote {
                    return Err(format!("pod worker {raw} requires the host authority; a remote parent-scoped child never actuates Kubernetes"));
                }
                pod_ids.push(worker_id);
                continue;
            }
            if job_worker_record(&store, &worker_id)?.is_some() {
                if remote {
                    return Err(format!(
                        "job worker {raw} requires the host authority; a remote parent-scoped child never actuates Kubernetes"
                    ));
                }
                explicit.push(worker_id);
                continue;
            }
            if let Some(store) = &kube_store {
                if pod_worker_record(store, &worker_id)? {
                    extra_pods.push(worker_id);
                    continue;
                }
                if job_worker_record(store, &worker_id)?.is_some() {
                    extra_jobs.push(worker_id);
                    continue;
                }
            }
            attempted += 1;
            let outcome = authority
                .stop_worker(&worker_id)
                .map_err(|error| format!("worker {raw} stop failed: {error}"))?;
            record_process_outcomes([outcome], &mut documents, &mut unresolved)?;
        }
        JobTargets::Explicit(explicit)
    };

    let job_result = emergency_job_section(
        &authority,
        &store,
        config.runtime_manifest.as_deref(),
        remote,
        job_targets,
    );
    let pod_result =
        emergency_pod_section(&authority, config.runtime_manifest.as_deref(), &pod_ids);
    let extra_result = if let (Some(authority), Some(store)) = (&kube_authority, &kube_store) {
        let jobs = emergency_job_section(
            authority,
            store,
            config.runtime_manifest.as_deref(),
            false,
            JobTargets::Explicit(extra_jobs),
        );
        let pods =
            emergency_pod_section(authority, config.runtime_manifest.as_deref(), &extra_pods);
        Some((jobs, pods))
    } else {
        None
    };
    let (job_documents, job_unresolved, job_attempted) = job_result?;
    documents.extend(job_documents);
    unresolved.extend(job_unresolved);
    attempted += job_attempted;
    let (pod_documents, pod_unresolved, pod_attempted) = pod_result?;
    documents.extend(pod_documents);
    unresolved.extend(pod_unresolved);
    attempted += pod_attempted;
    if let Some((jobs, pods)) = extra_result {
        for result in [jobs, pods] {
            let (evidence, pending, count) = result?;
            documents.extend(evidence);
            unresolved.extend(pending);
            attempted += count;
        }
    }

    if attempted == 0 {
        return Err("emergency-stop found no durable nonterminal workers".to_owned());
    }
    let document = if documents.len() == 1 {
        documents.swap_remove(0)
    } else {
        serde_json::Value::Array(documents)
    };
    write_private_json(&arguments.output, &document)?;
    if unresolved.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "emergency-stop did not prove every worker stopped: {}",
            unresolved.join(", ")
        ))
    }
}

fn additional_kube_store(
    config: &EmergencyStopConfig,
    remote: bool,
    primary_ledger: &Path,
) -> Result<Option<Arc<Mutex<Ledger>>>, String> {
    if remote {
        return Ok(None);
    }
    let Some(manifest) = config.runtime_manifest.as_deref() else {
        return Ok(None);
    };
    let runtime = RuntimeManifest::load(manifest)
        .map_err(|error| format!("runtime manifest rejected: {error}"))?;
    let odind = runtime
        .load_config()
        .map_err(|error| format!("odind config rejected: {error}"))?;
    if odind.kube.is_none() {
        return Ok(None);
    }
    open_additional_kube_store(primary_ledger, &odind.paths.state_root)
}

fn open_additional_kube_store(
    primary_ledger: &Path,
    odind_state_root: &Path,
) -> Result<Option<Arc<Mutex<Ledger>>>, String> {
    let path = odind_state_root
        .join("kube-authority")
        .join("ledger.sqlite3");
    match fs::metadata(&path) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => {
            return Err(format!(
                "declared kube authority {} is not a file",
                path.display()
            ))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "could not inspect declared kube authority {}: {error}",
                path.display()
            ))
        }
    }
    if path
        .canonicalize()
        .map_err(|error| format!("kube authority path failed: {error}"))?
        == primary_ledger
            .canonicalize()
            .map_err(|error| format!("primary authority path failed: {error}"))?
    {
        return Ok(None);
    }
    let ledger = Ledger::open(&path).map_err(|error| {
        format!(
            "could not open declared kube authority {}: {error}",
            path.display()
        )
    })?;
    Ok(Some(Arc::new(Mutex::new(ledger))))
}

/// Which durable Job workers one emergency-stop run owes Kubernetes
/// actuation for. `AllPending` is the global recovery sweep;
/// `Explicit` carries ids already proven to name durable Job rows.
enum JobTargets {
    AllPending,
    Explicit(Vec<WorkerId>),
}

/// Ready-to-actuate Job work for one run: the ids are nonempty and the
/// caller is the host authority.
enum JobWork {
    /// Global recovery sweep; the authority re-enumerates pending rows.
    Sweep(Vec<WorkerId>),
    /// These explicit ids, each proven to name a durable Job row.
    Explicit(Vec<WorkerId>),
}

/// Journals and actuates one explicit Delete stop per id under the current
/// backend registration state.
fn explicit_job_stops(
    authority: &StopAuthority,
    ids: &[WorkerId],
) -> Result<Vec<JobStopOutcome>, String> {
    ids.iter()
        .map(|worker_id| {
            authority
                .stop_job_worker(worker_id, JobStopAction::Delete)
                .map_err(|error| format!("job worker {} stop failed: {error}", worker_id.as_str()))
        })
        .collect()
}

/// Serializes Job stop outcomes into evidence documents plus unresolved
/// tags. Each document is the `worker-stop-evidence` schema's Kubernetes
/// Job branch — the backend-observed `JobStopEvidenceBody` wire body; the
/// full durable `JobStopAudit` stays in the ledger's `job_stop_record`.
fn record_job_outcomes(
    outcomes: &[JobStopOutcome],
) -> Result<(Vec<serde_json::Value>, Vec<String>), String> {
    let mut documents = Vec::with_capacity(outcomes.len());
    let mut unresolved = Vec::new();
    for outcome in outcomes {
        documents.push(serde_json::to_value(&outcome.evidence).map_err(|error| {
            format!("could not serialize emergency-stop job evidence: {error}")
        })?);
        if outcome.verdict != StopVerdictTag::Stopped {
            unresolved.push(format!(
                "{}={}",
                outcome.worker_id.as_str(),
                outcome.verdict.as_str()
            ));
        }
    }
    Ok((documents, unresolved))
}

/// Appends process worker evidence documents and unresolved verdict tags.
/// The serialized shape is the Linux-scope `StopEvidence`, unchanged.
fn record_process_outcomes(
    outcomes: impl IntoIterator<Item = StopOutcome>,
    documents: &mut Vec<serde_json::Value>,
    unresolved: &mut Vec<String>,
) -> Result<(), String> {
    for outcome in outcomes {
        documents
            .push(serde_json::to_value(&outcome.evidence).map_err(|error| {
                format!("could not serialize emergency-stop evidence: {error}")
            })?);
        if !matches!(outcome.verdict, StopVerdict::Stopped) {
            unresolved.push(format!(
                "{}={}",
                outcome.worker_id.as_str(),
                outcome.verdict.tag()
            ));
        }
    }
    Ok(())
}

/// Read-only durable Job worker lookup for explicit-id disambiguation; it
/// never actuates anything.
fn job_worker_record(
    store: &Arc<Mutex<Ledger>>,
    worker_id: &WorkerId,
) -> Result<Option<odin_ledger::worker::JobWorkerRow>, String> {
    let ledger = store
        .lock()
        .map_err(|_| "stop ledger lock is poisoned".to_owned())?;
    odin_ledger::worker::job_worker_row(ledger.connection(), worker_id.as_str())
        .map_err(|error| format!("could not observe job worker registry: {error}"))
}

/// Every durably nonterminal Job worker id, read without actuation.
fn pending_job_worker_ids(store: &Arc<Mutex<Ledger>>) -> Result<Vec<WorkerId>, String> {
    let ledger = store
        .lock()
        .map_err(|_| "stop ledger lock is poisoned".to_owned())?;
    let rows = odin_ledger::worker::nonterminal_job_rows(ledger.connection(), None)
        .map_err(|error| format!("could not observe nonterminal job workers: {error}"))?;
    rows.into_iter()
        .map(|row| {
            WorkerId::new(&row.worker_id).map_err(|error| {
                format!(
                    "durable job worker id {:?} is invalid: {error}",
                    row.worker_id
                )
            })
        })
        .collect()
}

/// The trusted kube connection facts: only the packaged odind config's
/// `kube` section declares them; absence is a typed unavailable, never a
/// fallback.
fn emergency_kube_config(runtime_manifest: &Path) -> Result<KubeConfig, String> {
    let runtime = RuntimeManifest::load(runtime_manifest)
        .map_err(|error| format!("runtime manifest rejected: {error}"))?;
    let odind = runtime
        .load_config()
        .map_err(|error| format!("odind config rejected: {error}"))?;
    let kube = odind.kube.ok_or_else(|| {
        "odind config declares no kube section; Kubernetes Job workers cannot be actuated"
            .to_owned()
    })?;
    Ok(KubeConfig {
        kubeconfig: kube.kubeconfig,
        cluster: kube.cluster,
        namespace: kube.namespace,
        // Emergency teardown grants no authority to place a new workload.
        allowed_nodes: Default::default(),
        request_timeout: Duration::from_secs(kube.request_timeout_seconds.get()),
        teardown_timeout: Duration::from_secs(kube.teardown_timeout_seconds.get()),
    })
}

/// Host-only Kubernetes Job actuation under the same stop authority the
/// process paths use. The multithread runtime and the real cluster client
/// exist exactly for this section; the backend is registered before any
/// stop call and every stop runs synchronously on the runtime worker while
/// the runtime is alive. A remote parent-scoped child constructs neither
/// and journals no Job stop intent.
fn emergency_job_section(
    authority: &StopAuthority,
    store: &Arc<Mutex<Ledger>>,
    runtime_manifest: Option<&Path>,
    remote: bool,
    targets: JobTargets,
) -> Result<(Vec<serde_json::Value>, Vec<String>, usize), String> {
    let work = match targets {
        JobTargets::AllPending => {
            if remote {
                return Ok((Vec::new(), Vec::new(), 0));
            }
            let ids = pending_job_worker_ids(store)?;
            if ids.is_empty() {
                return Ok((Vec::new(), Vec::new(), 0));
            }
            JobWork::Sweep(ids)
        }
        JobTargets::Explicit(ids) => {
            if ids.is_empty() || remote {
                return Ok((Vec::new(), Vec::new(), 0));
            }
            JobWork::Explicit(ids)
        }
    };
    let Some(runtime_manifest) = runtime_manifest else {
        return match work {
            // Global cleanup without the cluster declaration refuses loudly
            // instead of leaving pending rows silently unattempted.
            JobWork::Sweep(ids) => Err(format!(
                "emergency-stop found pending job workers ({}) but the config names no runtime manifest; Kubernetes jobs cannot be actuated",
                ids.iter().map(|id| id.as_str()).collect::<Vec<_>>().join(", ")
            )),
            // An explicit stop demand is still journaled by the authority:
            // the intent stays durably pending for the next host run that
            // names the manifest, and the indeterminate audit is reported.
            JobWork::Explicit(ids) => {
                let outcomes = explicit_job_stops(authority, &ids)?;
                let (documents, unresolved) = record_job_outcomes(&outcomes)?;
                Ok((documents, unresolved, outcomes.len()))
            }
        };
    };
    let kube = emergency_kube_config(runtime_manifest)?;
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|error| format!("could not start the Kubernetes job runtime: {error}"))?;
    runtime.block_on(async {
        let client = KubeClient::connect(kube)
            .await
            .map_err(|error| format!("kubernetes job backend is unavailable: {error}"))?;
        let backend = job_worker_backend(client)
            .map_err(|error| format!("kubernetes job backend rejected: {error}"))?;
        authority.register_job_backend(backend);
        let outcomes = match &work {
            JobWork::Sweep(_) => authority
                .recover_pending_jobs(None)
                .map_err(|error| format!("job worker stop recovery failed: {error}"))?,
            JobWork::Explicit(ids) => explicit_job_stops(authority, ids)?,
        };
        let (documents, unresolved) = record_job_outcomes(&outcomes)?;
        Ok((documents, unresolved, outcomes.len()))
    })
}

fn pod_worker_record(store: &Arc<Mutex<Ledger>>, worker: &WorkerId) -> Result<bool, String> {
    let ledger = store
        .lock()
        .map_err(|_| "stop ledger lock is poisoned".to_owned())?;
    odin_ledger::pod::worker_row(ledger.connection(), worker.as_str())
        .map(|row| row.is_some())
        .map_err(|error| format!("could not observe pod worker registry: {error}"))
}

fn pending_pod_worker_ids(store: &Arc<Mutex<Ledger>>) -> Result<Vec<WorkerId>, String> {
    let ledger = store
        .lock()
        .map_err(|_| "stop ledger lock is poisoned".to_owned())?;
    odin_ledger::pod::pending_rows(ledger.connection(), None)
        .map_err(|error| format!("could not observe nonterminal pod workers: {error}"))?
        .into_iter()
        .map(|row| {
            WorkerId::new(&row.worker_id)
                .map_err(|error| format!("invalid durable pod worker ID: {error}"))
        })
        .collect()
}

fn stop_pod_ids(
    authority: &StopAuthority,
    ids: &[WorkerId],
) -> Result<(Vec<serde_json::Value>, Vec<String>, usize), String> {
    let mut documents = Vec::with_capacity(ids.len());
    let mut unresolved = Vec::new();
    for worker in ids {
        let outcome = authority
            .stop_pod_worker(worker)
            .map_err(|error| format!("pod worker {worker} stop failed: {error}"))?;
        documents.push(serde_json::to_value(&outcome.evidence).map_err(|error| {
            format!("could not serialize emergency-stop pod evidence: {error}")
        })?);
        if outcome.verdict != StopVerdictTag::Stopped {
            unresolved.push(format!("{worker}={}", outcome.verdict.as_str()));
        }
    }
    Ok((documents, unresolved, ids.len()))
}

fn emergency_pod_section(
    authority: &StopAuthority,
    runtime_manifest: Option<&Path>,
    ids: &[WorkerId],
) -> Result<(Vec<serde_json::Value>, Vec<String>, usize), String> {
    if ids.is_empty() {
        return Ok((Vec::new(), Vec::new(), 0));
    }
    let Some(manifest) = runtime_manifest else {
        // Even unavailable actuation must journal the operator's stop demand.
        return stop_pod_ids(authority, ids);
    };
    match emergency_pod_backend(manifest) {
        Ok((runtime, backend)) => {
            let setup = authority
                .register_pod_backend(Arc::new(backend))
                .map_err(|error| format!("could not register pod backend: {error}"));
            if let Err(reason) = setup {
                return journal_unavailable_pod_stop(authority, ids, &reason);
            }
            runtime.block_on(async { stop_pod_ids(authority, ids) })
        }
        // The durable stop demand must survive an unreachable cluster: it
        // stays durably pending for the next authority run that reaches one.
        Err(reason) => journal_unavailable_pod_stop(authority, ids, &reason),
    }
}

fn emergency_pod_backend(
    manifest: &Path,
) -> Result<
    (
        tokio::runtime::Runtime,
        odin_kube::terminal_pod::KubernetesPodBackend,
    ),
    String,
> {
    let config = emergency_kube_config(manifest)?;
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|error| format!("could not start Kubernetes pod runtime: {error}"))?;
    // The backend binds the entered multithread runtime: construct it inside
    // block_on, never after the context is gone.
    let backend = runtime.block_on(async {
        let client = KubeClient::connect(config.clone())
            .await
            .map_err(|error| format!("Kubernetes pod backend is unavailable: {error}"))?;
        odin_kube::terminal_pod::KubernetesPodBackend::new(client, config.cluster, config.namespace)
            .map_err(|error| format!("Kubernetes pod backend rejected: {error}"))
    })?;
    Ok((runtime, backend))
}

fn journal_unavailable_pod_stop(
    authority: &StopAuthority,
    ids: &[WorkerId],
    reason: &str,
) -> Result<(Vec<serde_json::Value>, Vec<String>, usize), String> {
    let (documents, mut unresolved, attempted) = stop_pod_ids(authority, ids)?;
    unresolved.insert(0, format!("kubernetes pod backend unavailable: {reason}"));
    Ok((documents, unresolved, attempted))
}

fn write_private_json(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "emergency-stop output {} is not a regular file",
                path.display()
            ));
        }
    }
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("could not serialize emergency-stop output: {error}"))?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| {
            format!(
                "could not open emergency-stop output {}: {error}",
                path.display()
            )
        })?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| {
            format!(
                "could not protect emergency-stop output {}: {error}",
                path.display()
            )
        })?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| {
            format!(
                "could not persist emergency-stop output {}: {error}",
                path.display()
            )
        })
}

#[cfg(test)]
mod pod_emergency_tests {
    use super::*;

    #[test]
    fn emergency_sweep_finds_pods_and_journals_unavailable_stop() {
        let directory = tempfile::tempdir().expect("ledger directory");
        let store = Arc::new(Mutex::new(
            Ledger::open(directory.path().join("ledger.sqlite3")).expect("ledger"),
        ));
        let authority = StopAuthority::new(
            Arc::clone(&store),
            recovery_worker_channel("unix:path=/run/user/0/bus").expect("channel"),
        );
        let worker = odin_kernel::stop::mint_worker_id().expect("worker");
        let correlation = odin_kernel::stop::CorrelationId::new("0f1e2d3c000040008000000000000001")
            .expect("correlation");
        authority
            .register_pod_worker(
                &worker,
                &odin_kernel::stop::PodWorkerIdentity {
                    cluster: "cluster".to_owned(),
                    namespace: "namespace".to_owned(),
                    pod_name: "terminal".to_owned(),
                    pod_uid: None,
                    policy_name: "policy".to_owned(),
                    policy_uid: None,
                    secret_name: None,
                    secret_uid: None,
                    correlation_id: correlation.as_str().to_owned(),
                },
                &correlation,
            )
            .expect("intent");
        assert!(pod_worker_record(&store, &worker).expect("explicit lookup"));
        let ids = pending_pod_worker_ids(&store).expect("global sweep");
        assert_eq!(ids, vec![worker.clone()]);
        let (documents, unresolved, attempted) =
            emergency_pod_section(&authority, None, &ids).expect("unavailable stop");
        assert_eq!(attempted, 1);
        assert_eq!(documents[0]["backend"], "kube.pod");
        assert_eq!(documents[0]["worker_id"], worker.as_str());
        assert_eq!(unresolved.len(), 1);
        assert_eq!(
            authority
                .pod_stop_record(&worker)
                .expect("record")
                .expect("journaled stop")
                .verdict,
            StopVerdictTag::Indeterminate
        );
        assert_eq!(
            pending_pod_worker_ids(&store).expect("retained recovery"),
            ids
        );
    }

    #[test]
    fn emergency_discovers_declared_kube_store_without_double_counting() {
        let directory = tempfile::tempdir().expect("directory");
        let primary = directory.path().join("ledger.sqlite3");
        let main = Ledger::open(&primary).expect("main ledger");
        assert!(open_additional_kube_store(&primary, directory.path())
            .expect("absent kube store")
            .is_none());
        let kube_root = directory.path().join("kube-authority");
        fs::create_dir(&kube_root).expect("kube root");
        let kube_path = kube_root.join("ledger.sqlite3");
        let mut kube = Ledger::open(&kube_path).expect("kube ledger");
        let worker = odin_kernel::stop::mint_worker_id().expect("worker");
        let identity = odin_kernel::stop::PodWorkerIdentity {
            cluster: "cluster".to_owned(),
            namespace: "namespace".to_owned(),
            pod_name: "pod".to_owned(),
            pod_uid: None,
            policy_name: "policy".to_owned(),
            policy_uid: None,
            secret_name: None,
            secret_uid: None,
            correlation_id: "run:live:emergency-store".to_owned(),
        };
        kube.with_tx(|tx| {
            odin_ledger::pod::register_worker(
                tx,
                worker.as_str(),
                &identity,
                time::OffsetDateTime::now_utc(),
            )
        })
        .expect("pod intent");
        assert!(odin_ledger::pod::pending_rows(main.connection(), None)
            .expect("main empty")
            .is_empty());
        let discovered = open_additional_kube_store(&primary, directory.path())
            .expect("discover")
            .expect("additional store");
        assert_eq!(
            pending_pod_worker_ids(&discovered).expect("kube inventory"),
            vec![worker.clone()]
        );
        assert!(pod_worker_record(&discovered, &worker).expect("explicit lookup"));
        assert!(open_additional_kube_store(&kube_path, directory.path())
            .expect("deduplicate")
            .is_none());
        let config = EmergencyStopConfig {
            state_root: directory.path().to_path_buf(),
            worker_bus: "unix:path=/run/user/0/bus".to_owned(),
            worker_ids: Vec::new(),
            runtime_manifest: Some(directory.path().join("must-not-read.json")),
        };
        assert!(additional_kube_store(&config, true, &primary)
            .expect("remote never discovers host stores")
            .is_none());
    }

    #[test]
    fn emergency_pod_stop_survives_backend_setup_failure() {
        let directory = tempfile::tempdir().expect("ledger directory");
        let store = Arc::new(Mutex::new(
            Ledger::open(directory.path().join("ledger.sqlite3")).expect("ledger"),
        ));
        let authority = StopAuthority::new(
            Arc::clone(&store),
            recovery_worker_channel("unix:path=/run/user/0/bus").expect("channel"),
        );
        let worker = odin_kernel::stop::mint_worker_id().expect("worker");
        let correlation = odin_kernel::stop::CorrelationId::new("0f1e2d3c000040008000000000000002")
            .expect("correlation");
        authority
            .register_pod_worker(
                &worker,
                &odin_kernel::stop::PodWorkerIdentity {
                    cluster: "cluster".to_owned(),
                    namespace: "namespace".to_owned(),
                    pod_name: "terminal".to_owned(),
                    pod_uid: None,
                    policy_name: "policy".to_owned(),
                    policy_uid: None,
                    secret_name: None,
                    secret_uid: None,
                    correlation_id: correlation.as_str().to_owned(),
                },
                &correlation,
            )
            .expect("intent");
        let ids = vec![worker.clone()];
        // A manifest that cannot be loaded must not lose the stop demand.
        let (documents, unresolved, attempted) = emergency_pod_section(
            &authority,
            Some(
                directory
                    .path()
                    .join("absent-runtime-manifest.json")
                    .as_path(),
            ),
            &ids,
        )
        .expect("journaled unavailable stop");
        assert_eq!(attempted, 1);
        assert_eq!(documents[0]["worker_id"], worker.as_str());
        assert!(unresolved[0].contains("kubernetes pod backend unavailable"));
        assert_eq!(
            authority
                .pod_stop_record(&worker)
                .expect("record")
                .expect("journaled stop")
                .verdict,
            StopVerdictTag::Indeterminate
        );
        assert_eq!(
            pending_pod_worker_ids(&store).expect("retained recovery"),
            ids
        );
    }
}
