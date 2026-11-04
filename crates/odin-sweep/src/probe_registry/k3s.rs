//! INT-K3S: the bounded real-cluster readiness probe.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::report::{CheckResult, CheckStatus};
use crate::syscheck::probe::{run_bounded, trimmed_stdout, BoundedOutput};
use crate::syscheck::SystemContext;

use super::{elapsed_ms, K3S_CHECK_ID};

const K3S_CHECK_NAME: &str = "K3s cluster API readiness";
const K3S_API_BOUND: Duration = Duration::from_secs(15);

/// Requires a successful live API response with the exact readyz body; missing prerequisites block.
pub(super) fn k3s_api_check(context: &SystemContext) -> CheckResult {
    let started = Instant::now();
    let Some(kubectl) = crate::runner::find_program("kubectl") else {
        return CheckResult::new(
            K3S_CHECK_ID,
            K3S_CHECK_NAME,
            CheckStatus::Blocked,
            elapsed_ms(started),
            "not run: no kubectl on PATH",
            Vec::new(),
        )
        .with_reason(
            "the K3s integration check requires a real kubectl client on PATH (the \
             flake devShell and the installed profile supply it); with no client \
             there is no cluster observation and nothing may report green",
        );
    };
    let kubectl_display = kubectl.display().to_string();
    // Scratch HOME disables kubeconfig discovery; inherit nonempty KUBECONFIG lists intact or pass the k3s default without reading credentials.
    let explicit_kubeconfig: Option<PathBuf> = crate::runner::kube_config_path();
    let mut arguments = vec![
        OsString::from("get"),
        OsString::from("--raw"),
        OsString::from("/readyz"),
        OsString::from("--request-timeout=10s"),
    ];
    if let Some(config) = explicit_kubeconfig {
        arguments.push(OsString::from("--kubeconfig"));
        arguments.push(config.into());
    }
    let probe = match run_bounded(
        &kubectl,
        &arguments,
        &context.scratch_root.join("kubectl"),
        &context.odin_root,
        started + K3S_API_BOUND,
    ) {
        Ok(probe) => probe,
        Err(error) => {
            return CheckResult::new(
                K3S_CHECK_ID,
                K3S_CHECK_NAME,
                CheckStatus::Blocked,
                elapsed_ms(started),
                "not run: kubectl could not be run",
                vec![format!("kubectl: {kubectl_display}")],
            )
            .with_reason(format!(
                "K3s availability unknown: the kubectl probe failed: {error}"
            ));
        }
    };
    let mut evidence = vec![
        format!("kubectl: {kubectl_display}"),
        "bounded `kubectl get --raw /readyz --request-timeout=10s` under the \
         shared bounded runner's disposable environment; a set KUBECONFIG is \
         inherited verbatim and only an absent one is answered with \
         --kubeconfig at /etc/rancher/k3s/k3s.yaml, whose contents are \
         never read"
            .to_owned(),
    ];
    match k3s_verdict(&probe) {
        Ok(body) => {
            evidence.push(format!("readyz body: {body}"));
            CheckResult::new(
                K3S_CHECK_ID,
                K3S_CHECK_NAME,
                CheckStatus::Pass,
                elapsed_ms(started),
                "K3s API /readyz returned ok",
                evidence,
            )
        }
        Err((status, reason)) => {
            let summary = if status == CheckStatus::Blocked {
                "K3s API unavailable"
            } else {
                "K3s API answered without readiness"
            };
            CheckResult::new(
                K3S_CHECK_ID,
                K3S_CHECK_NAME,
                status,
                elapsed_ms(started),
                summary,
                evidence,
            )
            .with_reason(reason)
        }
    }
}

/// Timeout, truncation, and command failure block; a successful response with an unexpected body fails.
pub(super) fn k3s_verdict(probe: &BoundedOutput) -> Result<String, (CheckStatus, String)> {
    let body = trimmed_stdout(probe);
    if probe.timed_out {
        return Err((
            CheckStatus::Blocked,
            "command-timeout: kubectl did not answer within the bounded window".to_owned(),
        ));
    }
    if probe.stdout_truncated != 0 || probe.stderr_truncated != 0 {
        return Err((
            CheckStatus::Blocked,
            "command-output-truncated: kubectl output exceeded the bounded \
             capture cap, so readiness cannot be judged from a partial stream"
                .to_owned(),
        ));
    }
    if probe.exit_code != Some(0) {
        let detail: String = String::from_utf8_lossy(&probe.stderr)
            .trim()
            .chars()
            .take(400)
            .collect();
        let mut reason =
            "K3s API unavailable: `kubectl get --raw /readyz` did not succeed".to_owned();
        if !detail.is_empty() {
            reason.push_str(": ");
            reason.push_str(&detail);
        }
        return Err((CheckStatus::Blocked, reason));
    }
    if body == "ok" {
        Ok(body)
    } else {
        Err((
            CheckStatus::Fail,
            format!("readyz answered {body:?}, expected the exact body \"ok\""),
        ))
    }
}
