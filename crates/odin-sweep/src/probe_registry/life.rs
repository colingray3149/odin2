//! INT-LIFE: life-workflow integration suites.

use std::time::Instant;

use crate::report::{CheckResult, CheckStatus};
use crate::syscheck::SystemContext;

use super::cargo::{run_cargo_tests, suite_output_confirms_full_pass};
use super::{elapsed_ms, LIFE_CHECK_ID};

const LIFE_CHECK_NAME: &str = "ODIN-02 life workflow suite";

const LIFE_PACKAGE: &str = "odin-hermes";
const LIFE_SUITES: [&str; 3] = ["finance_purchase", "email_calendar", "discord"];
const LIFE_REQUIRED_SELECTORS: [&str; 6] = [
    "fixture_summary_scopes_the_month_and_narrows_to_aggregates",
    "planted_identifiers_never_reach_any_outgoing_envelope",
    "runtime::dispatch_handler_tests::a_denied_purchase_never_reaches_the_backend_or_records_an_intent",
    "runtime::dispatch_handler_tests::approved_checkout_purchase_settles_once_through_the_real_handler",
    "email_fixture_drives_the_exported_search_adapter",
    "calendar_fixture_selects_only_reminder_flagged_fridays",
];

pub(super) fn life_workflow_check(context: &SystemContext) -> CheckResult {
    let started = Instant::now();
    let scratch = context.scratch_root.join("cargo");
    let evidence = vec![
        "coverage: synthetic-fixture finance summary and nonexposure, the \
         shared-authority purchase approval/denial and exactly-once dispatch, \
         the email/calendar adapter gates, and the Discord intent wire law; \
         no live mailbox, calendar, or Discord account is exercised"
            .to_owned(),
        format!(
            "cargo test -p {LIFE_PACKAGE} --lib {} -j 3",
            LIFE_SUITES
                .iter()
                .map(|suite| format!("--test {suite}"))
                .collect::<Vec<_>>()
                .join(" ")
        ),
        format!("from odin root: {}", context.odin_root.display()),
    ];
    let mut arguments = vec!["test", "-p", LIFE_PACKAGE, "--lib"];
    arguments.extend(LIFE_SUITES.iter().flat_map(|suite| ["--test", *suite]));
    let run = run_cargo_tests(&context.odin_root, &scratch, &arguments, &[]);
    let outcome = run.ok_stdout().map_err(str::to_owned).and_then(|stdout| {
        if suite_output_confirms_full_pass(stdout, &LIFE_REQUIRED_SELECTORS) {
            Ok(())
        } else {
            Err(format!(
                "the {LIFE_PACKAGE} life-workflow suites did not pass with every \
                 required selection {LIFE_REQUIRED_SELECTORS:?} inside a full pass"
            ))
        }
    });
    match outcome {
        Ok(()) => CheckResult::new(
            LIFE_CHECK_ID,
            LIFE_CHECK_NAME,
            CheckStatus::Pass,
            elapsed_ms(started),
            format!(
                "all {LIFE_PACKAGE} life-workflow suites passed, including every \
             required ODIN-02 selection"
            ),
            evidence,
        ),
        Err(reason) => CheckResult::new(
            LIFE_CHECK_ID,
            LIFE_CHECK_NAME,
            CheckStatus::Fail,
            elapsed_ms(started),
            format!("{LIFE_PACKAGE} life-workflow suite did not pass"),
            evidence,
        )
        .with_reason(reason),
    }
}
