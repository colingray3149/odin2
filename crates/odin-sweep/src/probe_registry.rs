//! Integration checks exercise production paths.
//! OMP requires a runtime manifest; child state is isolated under scratch.
//! Cargo output must confirm every selected test passed because empty selections can exit successfully.

use std::time::Instant;

use crate::report::CheckResult;
use crate::syscheck::SystemContext;

mod cargo;
mod omp;
use omp::omp_conformance_check;
mod browser;
use browser::browser_session_check;
mod ledger;
use ledger::ledger_reopen_check;
mod k3s;
use k3s::k3s_api_check;
mod kube;
use kube::kube_job_lifecycle_check;
mod life;
use life::life_workflow_check;
mod vault;
use vault::vault_loopback_check;

pub const OMP_CHECK_ID: &str = "INT-OMP";
pub const BROWSER_CHECK_ID: &str = "INT-BROWSER";
pub const LEDGER_CHECK_ID: &str = "INT-LEDGER";
pub const K3S_CHECK_ID: &str = "INT-K3S";
pub const KUBE_CHECK_ID: &str = "INT-KUBE";
pub const LIFE_CHECK_ID: &str = "INT-LIFE";
pub const VAULT_CHECK_ID: &str = "INT-VAULT";

pub fn run_integration_checks(context: &SystemContext) -> Vec<CheckResult> {
    vec![
        omp_conformance_check(context),
        browser_session_check(context),
        ledger_reopen_check(context),
        k3s_api_check(context),
        kube_job_lifecycle_check(context),
        life_workflow_check(context),
        vault_loopback_check(context),
    ]
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Runner-selection unit tests stay outside integration selection to avoid recursive cargo runs.
#[cfg(test)]
mod runner_selection_tests;
