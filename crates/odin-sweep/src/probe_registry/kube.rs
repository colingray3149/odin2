//! INT-KUBE: the real-cluster disposable Job lifecycle suite.

use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Instant;

use odin_huginn::RuntimeManifest;

use crate::report::{CheckResult, CheckStatus};
use crate::syscheck::SystemContext;

use super::cargo::{run_cargo_tests, suite_output_confirms_full_pass, CargoRun};
use super::{elapsed_ms, KUBE_CHECK_ID};

const KUBE_CHECK_NAME: &str = "Kube job lifecycle";

const KUBE_PACKAGE: &str = "odin-kube";
const KUBE_LIFECYCLE_TEST: &str = "job_lifecycle";
/// Required coverage includes Job success, command conflicts/replays,
/// foreign read-only access, and pod teardown.
const KUBE_REQUIRED_SELECTORS: [&str; 4] = [
    "created_job_reaches_observed_success_status",
    "optimistic_conflict_and_idempotent_replay_follow_command_law",
    "foreign_objects_stay_read_only",
    "cancel_teardown_proves_authoritative_pod_absence",
];
/// Lifecycle stdout marker mapped to BLOCKED when the cluster is unavailable.
const KUBE_UNAVAILABLE_MARKER: &str = "kube unavailable:";
const K3S_PREREQUISITE: &str = "activate then sudo systemctl start k3s";
/// Suite kube parameters: cluster comes from the configured odind kube
/// config, then `ODIN_KUBE_CLUSTER`. Namespace and timeout defaults remain.
const KUBE_DEFAULT_NAMESPACE: &str = "default";
const KUBE_DEFAULT_REQUEST_TIMEOUT_SECONDS: &str = "30";
const KUBE_DEFAULT_TEARDOWN_TIMEOUT_SECONDS: &str = "120";

pub(super) fn kube_job_lifecycle_check(context: &SystemContext) -> CheckResult {
    let started = Instant::now();
    let Some(cluster) = configured_cluster(context) else {
        return CheckResult::new(
            KUBE_CHECK_ID,
            KUBE_CHECK_NAME,
            CheckStatus::Blocked,
            elapsed_ms(started),
            "Kube job lifecycle unavailable",
            vec!["kube cluster is not configured".to_owned()],
        )
        .with_reason("set kube.cluster in the odind config or ODIN_KUBE_CLUSTER");
    };
    let parameters = kube_suite_parameters(context, &cluster);
    let mut evidence = vec![
        "coverage: real disposable Job creation with observed live status, \
         optimistic-conflict and idempotent-replay command law, foreign \
         read-only safety, and teardown proving authoritative pod absence; \
         no simulated cluster exists in this suite"
            .to_owned(),
        format!("cargo test -p {KUBE_PACKAGE} --test {KUBE_LIFECYCLE_TEST} -j 3 -- --ignored"),
        format!("from odin root: {}", context.odin_root.display()),
    ];
    evidence.push("kube parameters:".to_owned());
    evidence.extend(parameters_evidence(&parameters));
    let run = run_cargo_tests(
        &context.odin_root,
        &context.scratch_root.join("cargo"),
        &[
            "test",
            "-p",
            KUBE_PACKAGE,
            "--test",
            KUBE_LIFECYCLE_TEST,
            "--",
            "--ignored",
        ],
        &parameters,
    );
    match kube_lifecycle_verdict(&run) {
        Ok(summary) => CheckResult::new(
            KUBE_CHECK_ID,
            KUBE_CHECK_NAME,
            CheckStatus::Pass,
            elapsed_ms(started),
            summary,
            evidence,
        ),
        Err((status, reason)) => {
            let summary = if status == CheckStatus::Blocked {
                "Kube job lifecycle unavailable"
            } else {
                "Kube job lifecycle suite did not pass"
            };
            CheckResult::new(
                KUBE_CHECK_ID,
                KUBE_CHECK_NAME,
                status,
                elapsed_ms(started),
                summary,
                evidence,
            )
            .with_reason(reason)
        }
    }
}

/// Every selection must pass; BLOCKED requires unavailability in every failed test, and unrelated defects take precedence.
pub(super) fn kube_lifecycle_verdict(run: &CargoRun) -> Result<String, (CheckStatus, String)> {
    let unavailable = kube_unavailable_reasons(&run.stdout);
    if let Some(reason) = unavailable.first() {
        let mut failed_count = 0;
        for name in run.stdout.lines().filter_map(|line| {
            line.trim()
                .strip_prefix("test ")?
                .strip_suffix(" ... FAILED")
        }) {
            failed_count += 1;
            let header = format!("---- {name} stdout ----");
            let own_output = run
                .stdout
                .split_once(&header)
                .map(|(_, output)| output.split("\n---- ").next().unwrap_or(output));
            if !own_output.is_some_and(|output| !kube_unavailable_reasons(output).is_empty()) {
                return Err((
                    CheckStatus::Fail,
                    format!("lifecycle test {name} failed without typed unavailability"),
                ));
            }
        }
        if run.ok || failed_count == 0 || !run.stdout.contains("test result: FAILED.") {
            return Err((
                CheckStatus::Fail,
                "unavailability output does not establish a completed unavailable test run"
                    .to_owned(),
            ));
        }
        let mut blocked = format!(
            "K3s cluster unavailable: the lifecycle tests reported \
             {KUBE_UNAVAILABLE_MARKER} {reason}"
        );
        if unavailable.len() > 1 {
            blocked.push_str(&format!(
                " (and {} further unavailability reports)",
                unavailable.len() - 1
            ));
        }
        blocked.push_str("; prerequisite: ");
        blocked.push_str(K3S_PREREQUISITE);
        return Err((CheckStatus::Blocked, blocked));
    }
    let confirmed = suite_output_confirms_full_pass(&run.stdout, &KUBE_REQUIRED_SELECTORS);
    match (run.ok, confirmed) {
        (true, true) => Ok(format!(
            "all {KUBE_PACKAGE} {KUBE_LIFECYCLE_TEST} lifecycle tests passed against the \
             real cluster, including every required selection"
        )),
        (true, false) => Err((
            CheckStatus::Fail,
            format!(
                "cargo reported success but its output does not confirm every required \
                 selection {KUBE_REQUIRED_SELECTORS:?} inside a full pass; a zero-match \
                 or failed selection never counts as success"
            ),
        )),
        (false, _) => Err((
            CheckStatus::Fail,
            run.failure
                .clone()
                .unwrap_or_else(|| "the lifecycle suite did not pass".to_owned()),
        )),
    }
}

fn kube_unavailable_reasons(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|line| line.trim().strip_prefix(KUBE_UNAVAILABLE_MARKER))
        .map(|reason| reason.trim().to_owned())
        .filter(|reason| !reason.is_empty())
        .collect()
}

/// The configured odind `.kube` section when the integration context
/// carries a loadable runtime manifest and odind config; any failure here
/// only falls back to the environment and defaults, because the kube
/// lifecycle suite does not depend on the composition runtime.
fn configured_kube(context: &SystemContext) -> Option<odin_huginn::OdindKubeConfig> {
    let manifest = RuntimeManifest::load(context.runtime_manifest.as_ref()?).ok()?;
    manifest.load_config().ok()?.kube
}

/// Preserve caller KUBECONFIG, else use odind's kubeconfig or the default k3s path to avoid scratch-HOME discovery.
/// Namespace and timeouts prefer odind configuration over ODIN_KUBE_*; cluster is already resolved.
fn kube_suite_parameters(context: &SystemContext, cluster: &str) -> Vec<(String, OsString)> {
    let configured = configured_kube(context);
    let mut parameters: Vec<(String, OsString)> = Vec::new();
    if env::var_os("KUBECONFIG").is_none_or(|value| value.is_empty()) {
        let kubeconfig = configured
            .as_ref()
            .map(|kube| kube.kubeconfig.clone())
            .unwrap_or_else(|| PathBuf::from(crate::runner::K3S_KUBECONFIG_PATH));
        parameters.push(("KUBECONFIG".to_owned(), kubeconfig.into_os_string()));
    }
    let namespace = configured
        .as_ref()
        .map(|kube| kube.namespace.clone())
        .or_else(|| env_value("ODIN_KUBE_NAMESPACE"))
        .unwrap_or_else(|| KUBE_DEFAULT_NAMESPACE.to_owned());
    let request_seconds = configured
        .as_ref()
        .map(|kube| kube.request_timeout_seconds.get().to_string())
        .or_else(|| env_value("ODIN_KUBE_REQUEST_TIMEOUT_SECONDS"))
        .unwrap_or_else(|| KUBE_DEFAULT_REQUEST_TIMEOUT_SECONDS.to_owned());
    let teardown_seconds = configured
        .as_ref()
        .map(|kube| kube.teardown_timeout_seconds.get().to_string())
        .or_else(|| env_value("ODIN_KUBE_TEARDOWN_TIMEOUT_SECONDS"))
        .unwrap_or_else(|| KUBE_DEFAULT_TEARDOWN_TIMEOUT_SECONDS.to_owned());
    for (key, value) in [
        ("ODIN_KUBE_CLUSTER", cluster.to_owned()),
        ("ODIN_KUBE_NAMESPACE", namespace),
        ("ODIN_KUBE_REQUEST_TIMEOUT_SECONDS", request_seconds),
        ("ODIN_KUBE_TEARDOWN_TIMEOUT_SECONDS", teardown_seconds),
    ] {
        parameters.push((key.to_owned(), OsString::from(value)));
    }
    parameters
}

fn env_value(key: &str) -> Option<String> {
    env::var_os(key)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string_lossy().into_owned())
}

fn configured_cluster(context: &SystemContext) -> Option<String> {
    configured_kube(context)
        .map(|kube| kube.cluster)
        .filter(|cluster| !cluster.is_empty())
        .or_else(|| env_value("ODIN_KUBE_CLUSTER"))
}

/// Evidence naming the exact kube parameters handed to the suite: paths
/// for configuration and values for the bounds. Credential contents never
/// appear because they are never read.
fn parameters_evidence(parameters: &[(String, OsString)]) -> Vec<String> {
    parameters
        .iter()
        .map(|(key, value)| format!("  {key}={}", value.to_string_lossy()))
        .collect()
}
