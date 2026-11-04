//! The Capabilities status rules: pure functions from a row's tests and probes to its tone and
//! label. A probe shows a capability is up, never that it works, so only passing tests make a
//! capability green.

use odin_cli::feature_probe::ProbeState;
use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Tone {
    Red,
    Gray,
    Green,
}

/// One evaluated test or probe, as the status object carries it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct CheckResult {
    pub(crate) check: String,
    pub(crate) state: ProbeState,
    pub(crate) detail: String,
}

impl CheckResult {
    pub(crate) fn new(check: &str, state: ProbeState, detail: impl Into<String>) -> Self {
        Self {
            check: check.to_owned(),
            state,
            detail: detail.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Status {
    pub(crate) tone: Tone,
    pub(crate) label: String,
}

fn verdict(tone: Tone, label: impl Into<String>) -> Status {
    Status {
        tone,
        label: label.into(),
    }
}

fn first<'a>(
    checks: impl IntoIterator<Item = &'a CheckResult>,
    state: ProbeState,
) -> Option<&'a CheckResult> {
    checks.into_iter().find(|check| check.state == state)
}

/// A failing test or probe is red; a capability with no named test is gray and untested; an unknown
/// result is gray; otherwise green, "tested at <sha>", with " · up" when its probes pass too.
pub(crate) fn capability_status(
    tests: &[CheckResult],
    probes: &[CheckResult],
    sha: &str,
) -> Status {
    let all = || tests.iter().chain(probes);
    if let Some(failed) = first(all(), ProbeState::Fail) {
        return verdict(
            Tone::Red,
            format!("Broken: {}: {}", failed.check, failed.detail),
        );
    }
    let up = !probes.is_empty() && probes.iter().all(|probe| probe.state == ProbeState::Pass);
    if tests.is_empty() {
        return verdict(Tone::Gray, if up { "Untested · up" } else { "Untested" });
    }
    if let Some(unknown) = first(all(), ProbeState::Unknown) {
        return verdict(Tone::Gray, format!("Unknown: {}", unknown.detail));
    }
    verdict(
        Tone::Green,
        if up {
            format!("Tested at {sha} · up")
        } else {
            format!("Tested at {sha}")
        },
    )
}

/// A service row has probes only: red on a failing one, gray on an unknown one, otherwise green and up.
pub(crate) fn service_status(probes: &[CheckResult]) -> Status {
    if let Some(failed) = first(probes, ProbeState::Fail) {
        return verdict(
            Tone::Red,
            format!("Broken: {}: {}", failed.check, failed.detail),
        );
    }
    if let Some(unknown) = first(probes, ProbeState::Unknown) {
        return verdict(Tone::Gray, format!("Unknown: {}", unknown.detail));
    }
    verdict(Tone::Green, "Up")
}

#[cfg(test)]
mod tests {
    use super::{capability_status, CheckResult, Tone};
    use odin_cli::feature_probe::ProbeState;

    fn check(state: ProbeState, detail: &str) -> CheckResult {
        CheckResult::new("odin-cli odind::features::tests::a_test", state, detail)
    }

    #[test]
    fn only_a_passing_test_makes_a_capability_green() {
        let up = [check(ProbeState::Pass, "active")];
        let untested = capability_status(&[], &up, "abc1234");
        assert_eq!(
            (untested.tone, untested.label.as_str()),
            (Tone::Gray, "Untested · up")
        );

        let tested = capability_status(&[check(ProbeState::Pass, "passed")], &[], "abc1234");
        assert_eq!(
            (tested.tone, tested.label.as_str()),
            (Tone::Green, "Tested at abc1234")
        );

        let tested_and_up = capability_status(&[check(ProbeState::Pass, "passed")], &up, "abc1234");
        assert_eq!(tested_and_up.label, "Tested at abc1234 · up");
    }

    #[test]
    fn a_failure_is_red_and_an_unknown_is_never_green() {
        let absent = capability_status(
            &[check(ProbeState::Fail, "named test absent at abc1234")],
            &[],
            "abc1234",
        );
        assert_eq!(absent.tone, Tone::Red);
        assert_eq!(
            absent.label,
            "Broken: odin-cli odind::features::tests::a_test: named test absent at abc1234"
        );

        let down = capability_status(
            &[check(ProbeState::Pass, "passed")],
            &[check(ProbeState::Fail, "inactive")],
            "abc1234",
        );
        assert_eq!(down.tone, Tone::Red);

        let waiting = capability_status(
            &[check(ProbeState::Pass, "passed")],
            &[check(ProbeState::Unknown, "pc unreachable: ssh timed out")],
            "abc1234",
        );
        assert_eq!(waiting.tone, Tone::Gray);
        assert_eq!(waiting.label, "Unknown: pc unreachable: ssh timed out");
    }
}
