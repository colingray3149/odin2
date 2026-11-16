//! Offload over a stub Slurm: shell fakes of sbatch, squeue, sacct and scancel on a local
//! "ssh". The scripts Odin renders run for real; only the scheduler is simulated.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use odin_domain::huginn::{KubeStagingProjection, KubeWorkloadState};
use odin_domain::{AttemptId, Digest, LaneId, ProjectId, RunId, SeatId, TaskId};
use odin_kube::JobLaunch;
use odin_registry::{ObjectConfig, RegistryObject, Snapshot};
use odin_types::{OperationId, WorkerId};

use super::{Offload, OffloadRefusal, OffloadState, Transport};
use crate::live::workload_monitor::AlertTracker;

const SBATCH: &str = r#"#!/bin/sh
# sbatch --parsable ... <script>: runs the script in its own process group.
jobs=$(dirname "$0")/../jobs; mkdir -p "$jobs"
for script; do :; done
id=$(( $(ls "$jobs" | wc -l) + 4200 ))
setsid bash "$script" >/dev/null 2>&1 &
echo $! > "$jobs/$id"
echo "$id"
"#;

const SQUEUE: &str = r#"#!/bin/sh
# squeue -h -j <id> -o %T
jobs=$(dirname "$0")/../jobs
pid=$(cat "$jobs/$3" 2>/dev/null) && kill -0 "$pid" 2>/dev/null && echo RUNNING
true
"#;

const SACCT: &str = r#"#!/bin/sh
# sacct's duplicate allocation query includes -D before -j.
jobs=$(dirname "$0")/../jobs
if [ "$8" = SLUID,Submit,Start,ElapsedRaw,Suspended ]; then
  if [ -f "$jobs/$6.elapsed" ]; then elapsed=$(cat "$jobs/$6.elapsed"); else elapsed='1000|0|'; fi
  if [ -f "$jobs/$6.suspended" ]; then suspended=$(cat "$jobs/$6.suspended"); else suspended=00:00:00; fi
  printf '%s|%s|%s%s|\n' "$6" "$(date +%s)" "$elapsed" "$suspended"
elif [ -f "$jobs/$5.cancelled" ]; then echo CANCELLED; elif [ -f "$jobs/$5" ]; then echo COMPLETED; fi
"#;

const SCANCEL: &str = r#"#!/bin/sh
# scancel [--signal=TERM --full] <id>
jobs=$(dirname "$0")/../jobs
for id; do :; done
pid=$(cat "$jobs/$id")
touch "$jobs/$id.cancelled"
case "$1" in --signal=TERM) kill -TERM -- "-$pid" ;; *) kill -KILL -- "-$pid" ;; esac 2>/dev/null
true
"#;

/// The case: prints a status line per step (nan_seen from the environment), and finishes,
/// writing its export, once `go` appears beside its inputs.
const CASE: &str = r#"#!/bin/sh
step=0
while [ ! -f "$ODIN_STAGE/../go" ]; do
  step=$((step + 1))
  echo "ODIN-STATUS {\"sim_time_us\": $step, \"nan_seen\": ${NAN:-0}}"
  sleep 0.1
done
cat "$ODIN_STAGE/input-0" > "$ODIN_EXPORT/result.txt"
"#;

struct Fixture {
    root: tempfile::TempDir,
    offload: Offload,
    nan: bool,
}

impl Fixture {
    fn path(&self, rest: &str) -> std::path::PathBuf {
        self.root.path().join(rest)
    }
}

fn executable(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn object(kind: &str, id: &str, config: ObjectConfig) -> RegistryObject {
    RegistryObject {
        id: id.to_owned(),
        relative_config: format!("registry/{kind}/{id}/x.toml").into(),
        config,
    }
}

/// `target` and `offload` are extra lines for the compute target and the profile's `[offload]`.
fn fixture(nan: bool, target: &str, offload: &str) -> Fixture {
    let root = tempfile::tempdir().unwrap();
    let base = root.path();
    for (name, body) in [
        ("sbatch", SBATCH),
        ("squeue", SQUEUE),
        ("sacct", SACCT),
        ("scancel", SCANCEL),
    ] {
        executable(&base.join("bin").join(name), body);
    }
    executable(&base.join("case.sh"), CASE);
    let extra = target;
    let target = toml::from_str(&format!(
        r#"
schema = "odin.registry.v1"
kind = "compute-target"
enabled = true
description = "Stub Slurm."
executor = "slurm"
ssh_host = "hpc"
known_host = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIStub"
remote_root = "{remote}"
runtime = "host"
max_concurrent = 1
poll_seconds = 1
stop_grace_seconds = 1
allowed_projects = ["odin"]
{extra}"#,
        remote = base.join("remote").display(),
    ))
    .expect("target fixture");
    let watchdog = if nan {
        r#"
[monitoring]
cadence_seconds = 5
[[monitoring.watchdogs]]
id = "nan"
condition = "nan_seen > 0"
consecutive_hits = 1
cooldown_seconds = 0
severity = "critical"
slice = "simulation"
action = "stop"
"#
    } else {
        ""
    };
    let profile = toml::from_str(&format!(
        r#"
schema = "odin.registry.v1"
kind = "workload"
enabled = true
description = "Offloaded case."
harness = "script"

[offload]
targets = ["hpc"]
{offload}

[image]
reference = "platform"

[script]
command = ["sh", "case.sh"]

[seat]
seat = "kubert"
project = "odin"

[network]
allow_hosts = []

[state]
path = "/state"
storage = "1Gi"

[export]
pod_path = "/export"
host_folder = "{export}"

[brief]
text = "Case."

[lifetime]
deadline_seconds = 600
{watchdog}"#,
        export = base.join("export").display(),
    ))
    .expect("profile fixture");
    let snapshot = Arc::new(
        Snapshot::build(
            1,
            vec![
                object(
                    "compute-targets",
                    "hpc",
                    ObjectConfig::ComputeTarget(Box::new(target)),
                ),
                object(
                    "workloads",
                    "case",
                    ObjectConfig::Workload(Box::new(profile)),
                ),
            ],
        )
        .expect("snapshot"),
    );
    let offload = Offload::open(
        base.join("state"),
        base.join("huginn"),
        Transport::Local {
            path: base.join("bin"),
        },
        Arc::new(move || Arc::clone(&snapshot)),
    )
    .expect("offload opens");
    Fixture { root, offload, nan }
}

fn launch(fixture: &Fixture, run: &str) -> JobLaunch {
    JobLaunch {
        label: None,
        labels: odin_domain::huginn::KubeJobLabels {
            task_id: TaskId::new("offload-task").unwrap(),
            run_id: RunId::new(run).unwrap(),
            attempt_id: AttemptId::new("offload-attempt").unwrap(),
            seat_id: SeatId::new("kubert").unwrap(),
            project_id: ProjectId::new("odin").unwrap(),
            lane_id: LaneId::new("kubert-odin").unwrap(),
            model: "none".to_owned(),
            budget_policy_digest: Digest::hash(b"offload-budget"),
            container_identity: Digest::hash(b"offload-image"),
        },
        worker_id: WorkerId::new("worker-offload").unwrap(),
        budget_lane: None,
        staging: KubeStagingProjection {
            inputs: Vec::new(),
            resumed_from: None,
        },
        checkpoint: None,
        continue_from: None,
        image: "platform".to_owned(),
        command: vec!["sh".to_owned(), "-c".to_owned()],
        args: vec![format!(
            "NAN={} exec sh {}",
            u8::from(fixture.nan),
            fixture.path("case.sh").display()
        )],
        node_selector: Default::default(),
        initial_target_node: None,
        admitted_node: None,
        campaign_reservation: None,
        gpu_count: 0,
        gpu_min_vram_gib: None,
        gpu_vram_gib: None,
        tolerate: Default::default(),
        deadline_seconds: Some(600),
        service: false,
        workload: None,
        extension: None,
        models_config: None,
        operation_id: OperationId::new("op-00000000000000000000000000000041").unwrap(),
        idempotency_digest: Digest::hash(run.as_bytes()),
    }
}

async fn submit(fixture: &Fixture, run: &str) -> Result<super::OffloadRun, OffloadRefusal> {
    let snapshot = (fixture.offload.snapshot)();
    let profile = snapshot
        .workload_profile_ref("case")
        .expect("profile")
        .profile
        .clone();
    fixture
        .offload
        .submit(
            &launch(fixture, run),
            "case",
            &profile,
            vec![("input-0".to_owned(), b"case input".to_vec())],
        )
        .await
}

/// Polls until `done` holds or ten seconds pass; every poll is due.
async fn poll_until(
    fixture: &Fixture,
    monitors: &mut AlertTracker,
    done: impl Fn(&[(super::OffloadRun, String)]) -> bool,
) -> Vec<(super::OffloadRun, String)> {
    for _ in 0..100 {
        let observed = fixture.offload.poll(|_, _| true, monitors).await;
        if done(&observed) {
            return observed;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the offload run never reached the awaited state");
}

#[test]
fn slurm_elapsed_rejects_incomplete_or_overflowing_rows() {
    assert_eq!(
        super::parse_slurm_elapsed("1700000000|123|"),
        Some((1_700_000_000_000, 1_700_000_123_000))
    );
    assert_eq!(super::parse_slurm_elapsed("Unknown|0|"), Some((0, 0)));
    assert_eq!(super::parse_slurm_elapsed("Unknown|1|"), None);
    assert_eq!(super::parse_slurm_elapsed("1700000000||"), None);
    assert_eq!(super::parse_slurm_elapsed("1700000000|12|extra"), None);
    assert_eq!(super::parse_slurm_elapsed("18446744073709551615|1|"), None);
    assert_eq!(
        super::parse_slurm_allocations("a|100|100|4|00:00:00|;b|105|105|6|00:00:00|;", 100),
        Some(vec![
            ("a".to_owned(), 100_000, 4_000),
            ("b".to_owned(), 105_000, 6_000)
        ])
    );
    assert!(super::parse_slurm_allocations("a|100|Unknown|2|00:00:00|;", 100).is_none());
    assert_eq!(
        super::parse_slurm_allocations("a|100|100|10|00:00:01|;", 100),
        Some(vec![("a".to_owned(), 100_000, 9_000)])
    );
    assert!(super::parse_slurm_allocations("a|100|100|10|00:00:11|;", 100).is_none());
    assert_eq!(super::parse_slurm_duration("1-02:03:04"), Some(93_784));
}

#[tokio::test]
async fn slurm_elapsed_is_charged_once_and_final_poll_catches_short_jobs() {
    let fixture = fixture(false, "", "");
    let run = submit(&fixture, "offload-elapsed")
        .await
        .expect("submitted");
    std::fs::write(fixture.path("jobs/4200.elapsed"), "1000|7|\n").unwrap();
    std::fs::create_dir_all(&run.remote_dir).unwrap();
    let mut monitors = AlertTracker::default();
    poll_until(&fixture, &mut monitors, |rows| {
        rows.iter()
            .any(|(run, _)| run.state == OffloadState::Running)
    })
    .await;
    fixture.offload.poll(|_, _| true, &mut monitors).await;
    std::fs::write(Path::new(&run.remote_dir).join("go"), b"").unwrap();
    std::fs::write(fixture.path("jobs/4200.elapsed"), "1000|12|\n").unwrap();
    let observed = poll_until(&fixture, &mut monitors, |rows| {
        rows.iter().any(|(run, _)| run.state.finished())
    })
    .await;
    assert_eq!(observed[0].0.elapsed_seconds, 12);
    let usage = odin_registry::ComputeUsage::load(&fixture.path("huginn")).unwrap();
    let source = format!("offload:{}:slurm-total:4200", run.run_id);
    let charges = &usage.source_charges[&source];
    let charge = charges.values().next().unwrap();
    assert_eq!(charge.core_seconds, 12.0 * f64::from(run.cores));
    assert_eq!(charge.gpu_seconds, 12.0 * f64::from(run.gpus));
}

#[tokio::test]
async fn slurm_suspension_is_removed_from_cumulative_usage() {
    let fixture = fixture(false, "", "[resources]\ncpu = 2\nmemory = \"1Gi\"");
    let run = submit(&fixture, "offload-suspended-usage").await.unwrap();
    std::fs::write(fixture.path("jobs/4200.elapsed"), "1000|12|\n").unwrap();
    std::fs::write(fixture.path("jobs/4200.suspended"), "00:00:04\n").unwrap();
    let mut monitors = AlertTracker::default();
    poll_until(&fixture, &mut monitors, |rows| {
        rows.iter()
            .any(|(run, _)| run.state == OffloadState::Running)
    })
    .await;
    fixture.offload.poll(|_, _| true, &mut monitors).await;
    let usage = odin_registry::ComputeUsage::load(&fixture.path("huginn")).unwrap();
    let source = format!("offload:{}:slurm-total:4200", run.run_id);
    let charge = usage.source_charges[&source].values().next().unwrap();
    assert_eq!(charge.core_seconds, 16.0);
    std::fs::write(Path::new(&run.remote_dir).join("go"), b"").unwrap();
}

#[tokio::test]
async fn an_offload_run_reaches_running_and_streams_telemetry() {
    let fixture = fixture(false, "", "");
    let run = submit(&fixture, "offload-telemetry")
        .await
        .expect("submitted");
    assert_eq!(run.job, "4200");
    assert_eq!(run.state, OffloadState::Pending);
    let mut monitors = AlertTracker::default();
    let observed = poll_until(&fixture, &mut monitors, |observed| {
        observed
            .iter()
            .any(|(run, log)| run.state == OffloadState::Running && log.contains("ODIN-STATUS"))
    })
    .await;
    let (run, log) = &observed[0];
    assert_eq!(run.workload_state(), KubeWorkloadState::Running);
    assert_eq!(run.node_id().unwrap().as_str(), "offload:hpc");
    // Pod-log shape: an RFC 3339 stamp before every status line.
    let (_, latest) = odin_kube::telemetry::latest_report(log).expect("a stamped status line");
    assert!(latest.contains_key("sim_time_us"), "{latest:?}");
    // The target takes one run at a time: a second launch waits.
    let waits = submit(&fixture, "offload-second").await;
    assert!(
        matches!(&waits, Err(OffloadRefusal::Full(reason)) if reason.contains("runs 1 of 1")),
        "{waits:?}"
    );
    std::fs::write(Path::new(&run.remote_dir).join("go"), b"").unwrap();
    poll_until(&fixture, &mut monitors, |observed| {
        observed.iter().any(|(run, _)| run.state.finished())
    })
    .await;
}

#[tokio::test]
async fn a_finished_run_lands_in_the_export_folder() {
    let fixture = fixture(false, "", "");
    let run = submit(&fixture, "offload-export").await.expect("submitted");
    std::fs::create_dir_all(&run.remote_dir).unwrap();
    std::fs::write(Path::new(&run.remote_dir).join("go"), b"").unwrap();
    let mut monitors = AlertTracker::default();
    let observed = poll_until(&fixture, &mut monitors, |observed| {
        observed.iter().any(|(run, _)| run.exported)
    })
    .await;
    assert_eq!(observed[0].0.state, OffloadState::Succeeded);
    let landed = fixture.path("export").join(&run.name).join("result.txt");
    assert_eq!(std::fs::read(&landed).unwrap(), b"case input");
    // A finished, exported run is not read again, and survives a daemon restart.
    assert!(fixture
        .offload
        .poll(|_, _| true, &mut monitors)
        .await
        .is_empty());
    let reopened = Offload::open(
        fixture.path("state"),
        fixture.path("huginn"),
        Transport::Local {
            path: fixture.path("bin"),
        },
        Arc::clone(&fixture.offload.snapshot),
    )
    .unwrap();
    assert_eq!(
        reopened.run(&run.run_id).unwrap().state,
        OffloadState::Succeeded
    );
}

#[tokio::test]
async fn a_nan_watchdog_scancels() {
    let fixture = fixture(true, "", "");
    let run = submit(&fixture, "offload-nan").await.expect("submitted");
    let mut monitors = AlertTracker::default();
    let observed = poll_until(&fixture, &mut monitors, |observed| {
        observed
            .iter()
            .any(|(run, _)| run.state == OffloadState::Aborted)
    })
    .await;
    let stopped = &observed[0].0;
    assert!(stopped.stopping_since.is_some());
    assert_eq!(
        stopped
            .detail
            .as_deref()
            .map(|detail| detail.contains("CANCELLED")),
        Some(true)
    );
    assert!(fixture
        .path("jobs")
        .join(format!("{}.cancelled", run.job))
        .exists());
}

#[tokio::test]
async fn an_unmanaged_master_cannot_bypass_the_host_pin() {
    let missing = tempfile::tempdir().unwrap();
    let socket = missing.path().join("hpc.sock");
    let fixture = fixture(
        false,
        &format!("control_master = \"{}\"", socket.display()),
        "",
    );
    let refused = submit(&fixture, "offload-mfa").await;
    assert!(
        matches!(&refused, Err(OffloadRefusal::Full(reason)) if reason.contains("odin offload login")),
        "{refused:?}"
    );
    // Even an existing socket is not proof of which host key established it.
    std::fs::write(&socket, b"").unwrap();
    let refused = submit(&fixture, "offload-mfa").await;
    assert!(
        matches!(&refused, Err(OffloadRefusal::Full(reason)) if reason.contains("odin offload login"))
    );
    assert!(!fixture.path("jobs").exists());
}

#[tokio::test]
async fn a_managed_master_is_bound_to_the_declared_pin_and_socket() {
    use std::os::unix::fs::MetadataExt;
    let fixture = fixture(false, "control_master = \"/unused/socket\"", "");
    let target = fixture.offload.target("hpc").unwrap();
    let dir = fixture.path("state/masters");
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join("hpc");
    let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let metadata = std::fs::symlink_metadata(&socket).unwrap();
    let proof = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        target.ssh_host,
        target.ssh_port(),
        target.known_host.trim(),
        target.identity_file.as_deref().unwrap_or(""),
        metadata.dev(),
        metadata.ino(),
        metadata.ctime(),
        metadata.ctime_nsec()
    );
    std::fs::write(dir.join("hpc.proof"), proof).unwrap();
    assert!(fixture.offload.unavailable("hpc", &target).await.is_none());
    let mut changed = target.clone();
    changed.known_host.push('x');
    assert!(fixture.offload.unavailable("hpc", &changed).await.is_some());
    changed = target;
    changed.ssh_port = std::num::NonZeroU16::new(2222);
    assert!(fixture.offload.unavailable("hpc", &changed).await.is_some());
}

#[tokio::test]
async fn a_target_refuses_what_it_can_never_take() {
    let restricted = fixture(false, "", "restricted_data = true");
    let refused = submit(&restricted, "offload-restricted").await;
    assert!(
        matches!(&refused, Err(OffloadRefusal::Refused(reason)) if reason.contains("restricted data")),
        "{refused:?}"
    );
    // A cap well under the profile's request, whatever the numbers, refuses rather than waits.
    let capped = fixture(
        false,
        "max_core_hours_per_run = 1",
        "[resources]\ncpu = 64\nmemory = \"1Gi\"",
    );
    let refused = submit(&capped, "offload-capped").await;
    assert!(
        matches!(&refused, Err(OffloadRefusal::Refused(reason)) if reason.contains("core-hours")),
        "{refused:?}"
    );
}

#[tokio::test]
async fn an_ambiguous_submission_is_journaled_and_never_submitted_twice() {
    let fixture = fixture(false, "", "");
    executable(
        &fixture.path("bin/sbatch"),
        "#!/bin/sh\necho invoked >> \"$(dirname \"$0\")/../attempts\"\nexit 1\n",
    );
    let first = submit(&fixture, "offload-ambiguous").await;
    assert!(matches!(&first, Err(OffloadRefusal::Refused(reason)) if reason.contains("unknown")));
    let second = submit(&fixture, "offload-ambiguous").await;
    assert!(matches!(&second, Err(OffloadRefusal::Refused(reason)) if reason.contains("unknown")));
    assert_eq!(
        std::fs::read_to_string(fixture.path("attempts")).unwrap(),
        "invoked\n"
    );
    let run = fixture
        .offload
        .run(&RunId::new("offload-ambiguous").unwrap())
        .unwrap();
    assert!(run.job.is_empty());
}

#[tokio::test]
async fn a_drained_target_refuses_launches_until_released() {
    let fixture = fixture(false, "", "");
    assert!(fixture.offload.drain_target("hpc").await.unwrap());
    let result = submit(&fixture, "offload-drained").await;
    assert!(matches!(&result, Err(OffloadRefusal::Full(reason)) if reason.contains("draining")));
    assert!(fixture.path("state/drained-targets.json").exists());
    fixture.offload.release_target("hpc").await.unwrap();
    let run = submit(&fixture, "offload-drained").await.unwrap();
    assert!(!fixture.offload.drain_target("hpc").await.unwrap());
    std::fs::write(Path::new(&run.remote_dir).join("go"), b"").unwrap();
}

#[tokio::test]
async fn offload_control_checks_schema_and_compare_and_swap() {
    let fixture = fixture(
        false,
        "",
        "[control]\nmax_bytes = 100\nschema = { type = \"object\", required = [\"speed\"] }",
    );
    let run = submit(&fixture, "offload-control").await.unwrap();
    let document = serde_json::json!({"speed": 2});
    assert!(fixture
        .offload
        .steer(&run, 0, serde_json::json!({}), "op-invalid", "test")
        .await
        .is_err());
    let applied = fixture
        .offload
        .steer(&run, 0, document.clone(), "op-1", "test")
        .await
        .unwrap();
    assert_eq!(applied.seq, 1);
    assert!(
        fixture
            .offload
            .steer(&run, 0, document.clone(), "op-1", "test")
            .await
            .unwrap()
            .duplicate
    );
    assert!(fixture
        .offload
        .steer(&run, 0, document, "op-2", "test")
        .await
        .is_err());
    std::fs::write(Path::new(&run.remote_dir).join("go"), b"").unwrap();
}

#[tokio::test]
async fn an_ambiguous_restart_is_never_replayed() {
    let fixture = fixture(false, "", "");
    let mut run = submit(&fixture, "offload-restart").await.unwrap();
    run.restart_pending = true;
    fixture.offload.save(&run).unwrap();
    executable(
        &fixture.path("bin/scontrol"),
        "#!/bin/sh\necho invoked >> \"$(dirname \"$0\")/../restart-attempts\"\nexit 1\n",
    );
    assert!(fixture.offload.restart_stalled(&run.run_id).await.is_err());
    assert!(fixture.offload.restart_stalled(&run.run_id).await.is_err());
    assert_eq!(
        std::fs::read_to_string(fixture.path("restart-attempts")).unwrap(),
        "invoked\n"
    );
    assert!(fixture.offload.run(&run.run_id).unwrap().restart_inflight);
    std::fs::write(Path::new(&run.remote_dir).join("go"), b"").unwrap();
}

#[tokio::test]
async fn pending_restart_survives_reopening_and_dispatches_once() {
    let fixture = fixture(false, "", "");
    let mut run = submit(&fixture, "offload-pending-restart").await.unwrap();
    run.restart_pending = true;
    fixture.offload.save(&run).unwrap();
    let reopened = Offload::open(
        fixture.path("state"),
        fixture.path("huginn"),
        Transport::Local {
            path: fixture.path("bin"),
        },
        fixture.offload.snapshot.clone(),
    )
    .unwrap();
    assert!(reopened.run(&run.run_id).unwrap().restart_pending);
    executable(
        &fixture.path("bin/scontrol"),
        "#!/bin/sh\necho invoked >> \"$(dirname \"$0\")/../restart-attempts\"\n",
    );
    reopened.restart_stalled(&run.run_id).await.unwrap();
    let saved = reopened.run(&run.run_id).unwrap();
    assert!(!saved.restart_pending && !saved.restart_inflight);
    assert_eq!(saved.restart_generation, 1);
    std::fs::write(Path::new(&run.remote_dir).join("go"), b"").unwrap();
}
