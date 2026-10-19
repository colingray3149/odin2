//! Direct production check results.

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CheckStatus {
    Pass,
    Flag,
    Blocked,
    Unimplemented,
    Fail,
    /// Authority-only checks are not applicable on declared follower hosts.
    NotApplicable,
}

impl CheckStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Flag => "FLAG",
            Self::Blocked => "BLOCKED",
            Self::Unimplemented => "UNIMPLEMENTED",
            Self::Fail => "FAIL",
            Self::NotApplicable => "N/A",
        }
    }
}

impl fmt::Display for CheckStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckResult {
    pub id: String,
    pub name: String,
    pub status: CheckStatus,
    pub duration_ms: u64,
    pub summary: String,
    pub reason: Option<String>,
    pub evidence: Vec<String>,
}

impl CheckResult {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        status: CheckStatus,
        duration_ms: u64,
        summary: impl Into<String>,
        evidence: Vec<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            status,
            duration_ms,
            summary: summary.into(),
            reason: None,
            evidence,
        }
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
}

/// Runtime executable IDs owned by first-party Cargo packages.
pub fn repository_build_contract(id: &str) -> Option<(&'static str, &'static str)> {
    match id {
        "odin" => Some(("odin-cli", "odin")),
        "odind" => Some(("odin-cli", "odind")),
        "sweep" => Some(("odin-sweep", "sweep")),
        "odin-sidecar" => Some(("odin-sidecar", "odin-sidecar")),
        "odin-effector" => Some(("odin-effector", "odin-effector")),
        "worker_bootstrap" => Some(("odin-process", "odin-worker-bootstrap")),
        _ => None,
    }
}

pub fn exit_code(checks: &[CheckResult]) -> i32 {
    // A follower's authority-only checks are N/A, but at least one check
    // must actually have passed for the run to count as green.
    let passed = checks.iter().any(|check| check.status == CheckStatus::Pass);
    if passed
        && checks
            .iter()
            .all(|check| matches!(check.status, CheckStatus::Pass | CheckStatus::NotApplicable))
    {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_or_failed_checks_never_report_success() {
        assert_eq!(exit_code(&[]), 1);
        let check = |status| CheckResult::new("SYS-01", "check", status, 0, "detail", vec![]);
        // A follower run is green only when something actually passed.
        assert_eq!(exit_code(&[check(CheckStatus::NotApplicable)]), 1);
        assert_eq!(
            exit_code(&[check(CheckStatus::Pass), check(CheckStatus::NotApplicable)]),
            0
        );
        for status in [
            CheckStatus::Flag,
            CheckStatus::Blocked,
            CheckStatus::Unimplemented,
            CheckStatus::Fail,
        ] {
            assert_eq!(
                exit_code(&[CheckResult::new(
                    "SYS-01",
                    "check",
                    status,
                    0,
                    "detail",
                    vec![],
                )]),
                1
            );
        }
        assert_eq!(
            exit_code(&[CheckResult::new(
                "SYS-01",
                "check",
                CheckStatus::Pass,
                0,
                "checked",
                vec![],
            )]),
            0
        );
    }

    #[test]
    fn runtime_inventory_contains_only_retained_products() {
        assert_eq!(repository_build_contract("odin-sweep-grader"), None);
        assert_eq!(
            repository_build_contract("sweep"),
            Some(("odin-sweep", "sweep"))
        );
        assert_eq!(
            repository_build_contract("worker_bootstrap"),
            Some(("odin-process", "odin-worker-bootstrap"))
        );
    }
}
