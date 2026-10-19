//! INT-BROWSER: the odin-browser worker and durable session-control suite.

use std::time::Instant;

use crate::report::{CheckResult, CheckStatus};
use crate::syscheck::SystemContext;

use super::cargo::{run_cargo_tests, suite_output_confirms_full_pass};
use super::{elapsed_ms, BROWSER_CHECK_ID};

const BROWSER_CHECK_NAME: &str = "Browser worker and session suite";

const BROWSER_PACKAGE: &str = "odin-browser";
pub(super) const BROWSER_REQUIRED_SELECTORS: [&str; 3] = [
    "session::runtime::tests::worker_teardown",
    "scanner::tests::scanner_stop_authority",
    "session::control::durable_control_tests::durable_control_reopen_invalidates_holder_and_advances_revision",
];

pub(super) fn browser_session_check(context: &SystemContext) -> CheckResult {
    let started = Instant::now();
    let scratch = context.scratch_root.join("cargo");
    let evidence = vec![
        "coverage: worker teardown stop-evidence semantics, scanner fail-closed \
         StopAuthority recovery channel, durable SQLite session-control reopen; \
         no Chromium rendering is exercised"
            .to_owned(),
        format!("cargo test -p {BROWSER_PACKAGE} --lib -j 3"),
        format!("from odin root: {}", context.odin_root.display()),
    ];
    let run = run_cargo_tests(
        &context.odin_root,
        &scratch,
        &["test", "-p", BROWSER_PACKAGE, "--lib"],
        &[],
    );
    let outcome = run.ok_stdout().map_err(str::to_owned).and_then(|stdout| {
        if suite_output_confirms_full_pass(stdout, &BROWSER_REQUIRED_SELECTORS) {
            Ok(())
        } else {
            Err(format!(
                "cargo reported success but its output does not confirm every required \
                 selection {BROWSER_REQUIRED_SELECTORS:?} inside a full pass; a zero-match \
                 or failed selection never counts as success"
            ))
        }
    });
    match outcome {
        Ok(()) => CheckResult::new(
            BROWSER_CHECK_ID,
            BROWSER_CHECK_NAME,
            CheckStatus::Pass,
            elapsed_ms(started),
            format!("all {BROWSER_PACKAGE} lib tests passed, including every required selection"),
            evidence,
        ),
        Err(reason) => CheckResult::new(
            BROWSER_CHECK_ID,
            BROWSER_CHECK_NAME,
            CheckStatus::Fail,
            elapsed_ms(started),
            format!("{BROWSER_PACKAGE} lib suite did not pass"),
            evidence,
        )
        .with_reason(reason),
    }
}
