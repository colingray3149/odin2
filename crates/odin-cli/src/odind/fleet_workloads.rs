//! Drain pods to online nodes matching their declared placement, carrying state.
//! Pods without another eligible node are paused on their volumes and recorded
//! for restore. Moves use kernel lifecycle operations and appear in Huginn.

use std::path::{Path, PathBuf};

use odin_domain::huginn::{KubeOperationKind, KubeResourceOwnership, KubeWorkloadState};
use odin_domain::{Digest, RunId};
use odin_huginn::kube::KubeControl;
use odin_kube::{JobAction, KubeClient};

/// Why pods leave a node: an operator drain, or the node yielding to its owner's mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Departure {
    Drain,
    Yield,
}

impl Departure {
    fn folder(self) -> &'static str {
        match self {
            Self::Drain => "fleet-drain",
            Self::Yield => "fleet-yield",
        }
    }
}

/// What one run does as its node empties.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Leave {
    /// Keep running where it is.
    Keep,
    /// Suspend in place and resume on return.
    Pause,
    /// Move with its state to a node its placement fits, else pause.
    Move,
}

/// A drain moves what it can. A yield follows the profile's `on_yield`; a state that may not
/// leave its node (`state.carry = false`) is paused rather than moved either way.
pub(super) fn leave(
    departure: Departure,
    on_yield: odin_registry::OnYield,
    state_carry: bool,
) -> Leave {
    let wanted = match (departure, on_yield) {
        (Departure::Drain, _) | (Departure::Yield, odin_registry::OnYield::Rehome) => Leave::Move,
        (Departure::Yield, odin_registry::OnYield::Pause) => Leave::Pause,
        (Departure::Yield, odin_registry::OnYield::Stay) => Leave::Keep,
    };
    if wanted == Leave::Move && !state_carry {
        Leave::Pause
    } else {
        wanted
    }
}

fn record_path(state_root: &Path, host: &str, departure: Departure) -> PathBuf {
    state_root
        .join(departure.folder())
        .join(format!("{host}.json"))
}

fn research(profile: Option<&str>) -> bool {
    profile.is_none_or(|profile| profile.starts_with("research"))
}

fn save_record(path: &Path, runs: &[String]) -> Result<(), String> {
    let bytes = serde_json::to_vec(runs).map_err(|error| error.to_string())?;
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, bytes)
        .and_then(|()| std::fs::rename(&temporary, path))
        .map_err(|error| format!("{}: {error}", path.display()))
}

async fn operate(
    control: &KubeControl,
    run: &RunId,
    kind: KubeOperationKind,
    target_node: Option<String>,
    purpose: &str,
) -> Result<odin_kube::JobObservation, String> {
    let observed = control
        .reconciler()
        .observe_run(run)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("run {run} has no Job any more"))?;
    let resource_version = observed.projection.identity.resource_version;
    let seed = format!(
        "fleet:{purpose}:{run}:{}:{}",
        resource_version.as_str(),
        target_node.as_deref().unwrap_or("-")
    );
    let operation_id =
        odin_types::OperationId::new(&format!("op-{}", uuid::Uuid::new_v4().simple()))
            .map_err(|error| error.to_string())?;
    let action = JobAction {
        run_id: run.clone(),
        kind,
        expected_resource_version: resource_version,
        operation_id,
        idempotency_digest: Digest::hash(seed.as_bytes()),
        target_node,
    };
    control
        .operate_at_live_version(action, time::OffsetDateTime::now_utc())
        .await
        .map_err(|error| error.to_string())
}

/// Moves every running Odin pod off `nodes`: rehome to the first candidate
/// node its declared placement fits, else pause and remember it. Returns
/// one sentence per pod.
pub(super) async fn drain(
    control: &KubeControl,
    client: &KubeClient,
    host: &str,
    nodes: &[String],
    candidates: &[String],
    state_root: &Path,
) -> Result<Vec<String>, String> {
    depart(
        control,
        client,
        host,
        nodes,
        candidates,
        state_root,
        Departure::Drain,
    )
    .await
    .map(|moved| moved.into_iter().map(|(_, line)| line).collect())
}

/// The drain and the yield: each run on `nodes` leaves per [`leave`]; paused runs are recorded
/// under the departure's folder for [`restore_after`]. One (run, sentence) per pod.
pub(super) async fn depart(
    control: &KubeControl,
    client: &KubeClient,
    host: &str,
    nodes: &[String],
    candidates: &[String],
    state_root: &Path,
    departure: Departure,
) -> Result<Vec<(Option<RunId>, String)>, String> {
    let reconciler = control.reconciler();
    let observed = reconciler.list().await.map_err(|error| error.to_string())?;
    let mut lines = Vec::new();
    let mut failures = Vec::new();
    let path = record_path(state_root, host, departure);
    let mut paused: Vec<String> = match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|error| format!("{}: {error}", path.display()))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    std::fs::create_dir_all(path.parent().unwrap_or(state_root))
        .map_err(|error| format!("{}: {error}", path.display()))?;
    for observation in observed {
        let KubeResourceOwnership::Odin { run_id: run, .. } = &observation.workload.ownership
        else {
            continue;
        };
        if departure == Departure::Yield && research(observation.workload.profile.as_deref()) {
            continue;
        }
        if !matches!(
            observation.workload.state,
            KubeWorkloadState::Running | KubeWorkloadState::Pending | KubeWorkloadState::Scheduling
        ) {
            continue;
        }
        let Some(node) = reconciler
            .workload_placement(run)
            .await
            .map_err(|error| error.to_string())?
            .and_then(|placement| placement.node)
        else {
            continue;
        };
        if !nodes.contains(&node) {
            continue;
        }
        let job = observation.workload.resource.name.clone();
        let label = observation
            .workload
            .profile
            .clone()
            .unwrap_or_else(|| job.clone());
        let Some(launch) = reconciler
            .stored_launch(run)
            .map_err(|error| error.to_string())?
        else {
            if departure == Departure::Drain {
                lines.push((
                    Some(run.clone()),
                    format!("{label}: no admitted launch is stored; left alone"),
                ));
            }
            continue;
        };
        let mut target = None;
        let plan = launch.workload.as_ref();
        let choice = leave(
            departure,
            plan.map_or_else(Default::default, |plan| plan.on_yield),
            plan.is_none_or(|plan| plan.state_carry),
        );
        if choice == Leave::Keep {
            // Staying is already converged and should not emit a finding on each pass.
            continue;
        }
        let data = plan.map_or(&[][..], |plan| plan.data.as_slice());
        for candidate in candidates.iter().filter(|_| choice == Leave::Move) {
            if odin_kube::state_carry::require_node_fits(
                client,
                candidate,
                &launch.node_requirements(),
                data,
            )
            .await
            .is_ok()
            {
                target = Some(candidate.clone());
                break;
            }
        }
        let line = match target {
            Some(target) => match operate(
                control,
                run,
                KubeOperationKind::Restart,
                Some(target.clone()),
                "drain-rehome",
            )
            .await
            {
                Ok(_) => format!("{label}: moved {node} → {target} with its state"),
                Err(error) => {
                    failures.push(format!("{label}: rehome to {target} failed: {error}"));
                    format!("{label}: rehome to {target} failed: {error}")
                }
            },
            None => {
                match operate(control, run, KubeOperationKind::Pause, None, "drain-pause").await {
                    Ok(_) => {
                        if !paused.iter().any(|held| held == run.as_str()) {
                            paused.push(run.to_string());
                        }
                        save_record(&path, &paused)?;
                        format!("{label}: paused on {node}; it resumes when {host} is back")
                    }
                    Err(error) => {
                        failures.push(format!("{label}: pause failed: {error}"));
                        format!("{label}: pause failed: {error}")
                    }
                }
            }
        };
        tracing::debug!("fleet {departure:?} host={host} {line}");
        lines.push((Some(run.clone()), line));
    }
    if failures.is_empty() {
        Ok(lines)
    } else {
        Err(failures.join("; "))
    }
}

/// Resumes the pods a drain of `host` paused. Returns one sentence per pod.
pub(super) async fn restore(control: &KubeControl, host: &str, state_root: &Path) -> Vec<String> {
    restore_after(control, host, state_root, Departure::Drain)
        .await
        .into_iter()
        .map(|(_, line)| line)
        .collect()
}

/// Resumes the pods a drain or yield of `host` paused. Returns one sentence per pod.
pub(super) async fn restore_after(
    control: &KubeControl,
    host: &str,
    state_root: &Path,
    departure: Departure,
) -> Vec<(Option<RunId>, String)> {
    let path = record_path(state_root, host, departure);
    let Ok(bytes) = std::fs::read(&path) else {
        return Vec::new();
    };
    let runs: Vec<String> = match serde_json::from_slice(&bytes) {
        Ok(runs) => runs,
        Err(error) => {
            return vec![(
                None,
                format!("the paused-pod record for {host} is unreadable: {error}"),
            )]
        }
    };
    let mut lines = Vec::new();
    let mut unresumed = Vec::new();
    for record in runs {
        let raw = record.as_str();
        let run = match RunId::new(raw.to_owned()) {
            Ok(run) => run,
            Err(error) => {
                lines.push((None, format!("{raw}: not a run id ({error})")));
                unresumed.push(record);
                continue;
            }
        };
        let observed = match control.reconciler().observe_run(&run).await {
            Ok(Some(observed)) => observed,
            Ok(None) => {
                lines.push((Some(run), format!("{raw}: Job no longer exists")));
                continue;
            }
            Err(error) => {
                lines.push((Some(run), format!("{raw}: observation failed: {error}")));
                unresumed.push(record);
                continue;
            }
        };
        if research(observed.workload.profile.as_deref()) {
            lines.push((Some(run), format!("{raw}: research left untouched")));
            unresumed.push(record);
            continue;
        }
        if observed.workload.state != KubeWorkloadState::Suspended {
            lines.push((
                Some(run),
                format!("{raw}: no longer suspended; left untouched"),
            ));
            continue;
        }
        let result = operate(control, &run, KubeOperationKind::Resume, None, "restore").await;
        let line = match result {
            Ok(_) => format!("{run}: resumed"),
            Err(error) => {
                unresumed.push(record);
                format!("{run}: resume failed: {error}")
            }
        };
        tracing::debug!("fleet restore host={host} {line}");
        lines.push((Some(run), line));
    }
    // A pod that would not resume stays recorded for the next restore.
    let settled = if unresumed.is_empty() {
        std::fs::remove_file(&path)
    } else {
        save_record(&path, &unresumed).map_err(std::io::Error::other)
    };
    if let Err(error) = settled {
        tracing::error!("fleet restore record not updated host={host}: {error}");
    }
    lines
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::num::{NonZeroU64, NonZeroUsize};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;

    /// A control whose cluster refuses every connection: each operation fails.
    fn unreachable_control(dir: &Path) -> KubeControl {
        let client = KubeClient {
            client: kube::Client::try_from(kube::Config::new(
                "http://127.0.0.1:9".parse().expect("cluster uri"),
            ))
            .expect("lazy kube client"),
            config: odin_kube::KubeConfig {
                node_data_roots: Default::default(),
                kubeconfig: dir.join("kubeconfig"),
                cluster: "pc".to_owned(),
                namespace: "default".to_owned(),
                allowed_nodes: BTreeSet::from(["pc".to_owned()]),
                request_timeout: Duration::from_secs(2),
                teardown_timeout: Duration::from_secs(2),
                vpn_transport: None,
            },
        };
        let ledger = Arc::new(Mutex::new(
            odin_ledger::Ledger::open(dir.join("ledger.sqlite3")).expect("ledger"),
        ));
        let channel =
            odin_kernel::recovery_worker_channel("unix:path=/run/user/0/bus").expect("channel");
        let stops = Arc::new(odin_kernel::StopAuthority::new(
            Arc::clone(&ledger),
            channel,
        ));
        let artifacts = dir.join("artifacts");
        std::fs::create_dir_all(&artifacts).expect("artifact root");
        let reconciler = odin_kube::JobReconciler::new(
            client.clone(),
            Arc::clone(&ledger),
            stops,
            Arc::default(),
            artifacts,
        )
        .expect("reconciler");
        let catalog = odin_huginn::kube::KubeCatalog::new(
            odin_huginn::kube::SurfaceArtifacts::new(
                odin_domain::huginn::LiveSessionId::parse(super::super::kube::KUBE_SURFACE_SESSION)
                    .expect("surface session"),
                odin_domain::LaneId::new(super::super::kube::KUBE_SURFACE_LANE)
                    .expect("surface lane"),
                NonZeroU64::new(65_536).expect("nonzero"),
                NonZeroU64::new(1_048_576).expect("nonzero"),
            ),
            NonZeroUsize::new(256).expect("nonzero"),
            NonZeroU64::new(16_384).expect("nonzero"),
            NonZeroU64::new(128).expect("nonzero"),
        );
        KubeControl::new(catalog, Arc::new(reconciler), ledger, client)
    }

    #[test]
    fn entering_a_yield_mode_pauses_pause_profiles_and_rehomes_the_rest() {
        use odin_registry::OnYield;
        assert_eq!(leave(Departure::Yield, OnYield::Pause, true), Leave::Pause);
        assert_eq!(leave(Departure::Yield, OnYield::Rehome, true), Leave::Move);
        assert_eq!(leave(Departure::Yield, OnYield::Stay, true), Leave::Keep);
        // A state that never leaves its node pauses instead of moving.
        assert_eq!(
            leave(Departure::Yield, OnYield::Rehome, false),
            Leave::Pause
        );
        // A drain moves everything it can, whatever the yield choice.
        assert_eq!(leave(Departure::Drain, OnYield::Stay, true), Leave::Move);
        assert_eq!(leave(Departure::Drain, OnYield::Pause, false), Leave::Pause);
    }

    #[test]
    fn research_and_unknown_profiles_are_never_yielded() {
        assert!(research(Some("research")));
        assert!(research(Some("research-deep")));
        assert!(research(None));
        assert!(!research(Some("simulation")));
    }

    #[tokio::test]
    async fn yield_cordons_preserve_manual_ownership() {
        let dir = tempfile::tempdir().expect("state root");
        let api = crate::kube_runtime::fake_api::FakeKubeApi::start().await;
        let client = api.client(dir.path());
        odin_kube::node_admin::cordon(&client, "pc")
            .await
            .expect("manual cordon");
        odin_kube::node_admin::reconcile_yield_cordon(&client, "pc", Some("gaming since now"))
            .await
            .expect("yield");
        assert!(
            !odin_kube::node_admin::reconcile_yield_cordon(&client, "pc", None)
                .await
                .expect("return")
        );
        assert!(!odin_kube::node_admin::schedulable(&client, "pc")
            .await
            .expect("node"));
        odin_kube::node_admin::uncordon(&client, "pc")
            .await
            .expect("operator release");
        odin_kube::node_admin::reconcile_yield_cordon(&client, "pc", Some("gaming since now"))
            .await
            .expect("yield");
        assert!(
            odin_kube::node_admin::reconcile_yield_cordon(&client, "pc", None)
                .await
                .expect("return")
        );
        assert!(odin_kube::node_admin::schedulable(&client, "pc")
            .await
            .expect("node"));
    }

    #[tokio::test]
    async fn yield_cordon_and_uncordon_change_the_live_node() {
        let dir = tempfile::tempdir().expect("state root");
        let api = crate::kube_runtime::fake_api::FakeKubeApi::start().await;
        let client = api.client(dir.path());
        odin_kube::node_admin::cordon(&client, "pc")
            .await
            .expect("cordon");
        odin_kube::node_admin::set_mode(&client, "pc", Some("gaming since 2026-11-15T00:00:00Z"))
            .await
            .expect("mode annotation");
        assert!(!odin_kube::node_admin::schedulable(&client, "pc")
            .await
            .expect("node"));
        let nodes = kube::Api::<k8s_openapi::api::core::v1::Node>::all(client.client.clone());
        let node = nodes.get("pc").await.expect("node");
        let view = odin_kube::placement::node_view("fake", &node, 1).expect("node view");
        assert_eq!(
            view.mode.as_deref(),
            Some("gaming since 2026-11-15T00:00:00Z")
        );
        assert!(odin_kube::node_admin::uncordon(&client, "pc")
            .await
            .expect("uncordon"));
        odin_kube::node_admin::set_mode(&client, "pc", None)
            .await
            .expect("clear mode");
        assert!(odin_kube::node_admin::schedulable(&client, "pc")
            .await
            .expect("node"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn leaving_it_resumes_the_runs_the_yield_recorded() {
        let dir = tempfile::tempdir().expect("state root");
        let control = unreachable_control(dir.path());
        let yielded = record_path(dir.path(), "pc", Departure::Yield);
        std::fs::create_dir_all(yielded.parent().expect("record directory")).expect("directory");
        std::fs::write(&yielded, br#"["run.yielded-one"]"#).expect("record");

        // A drain's restore reads its own record, never the yield's.
        assert!(restore(&control, "pc", dir.path()).await.is_empty());
        let lines = restore_after(&control, "pc", dir.path(), Departure::Yield).await;
        assert_eq!(lines.len(), 1);
        assert_eq!(
            lines[0].0.as_ref().map(RunId::as_str),
            Some("run.yielded-one")
        );
        assert!(lines[0].1.contains("observation failed"), "{lines:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pod_that_would_not_resume_stays_recorded_for_the_next_restore() {
        let dir = tempfile::tempdir().expect("state root");
        let control = unreachable_control(dir.path());
        let path = record_path(dir.path(), "pc", Departure::Drain);
        std::fs::create_dir_all(path.parent().expect("record directory")).expect("directory");
        std::fs::write(&path, br#"["run.paused-one"]"#).expect("record");

        let lines = restore(&control, "pc", dir.path()).await;

        assert!(lines[0].contains("observation failed"), "{lines:?}");
        let kept: Vec<String> =
            serde_json::from_slice(&std::fs::read(&path).expect("record kept")).expect("record");
        assert_eq!(kept, ["run.paused-one"]);
    }
}
