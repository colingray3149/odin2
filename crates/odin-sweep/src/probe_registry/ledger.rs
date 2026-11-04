//! INT-LEDGER: the retained ledger extension-migration suite.

use std::time::Instant;

use crate::report::{CheckResult, CheckStatus};
use crate::syscheck::SystemContext;

use super::cargo::{run_cargo_tests, single_test_passed};
use super::{elapsed_ms, LEDGER_CHECK_ID};

const LEDGER_CHECK_NAME: &str = "Ledger snapshot and reopen";

const LEDGER_PACKAGE: &str = "odin-ledger";
pub(super) const LEDGER_SELECTOR: &str = "migration::tests::extension_reopens_with_same_set";

pub(super) fn ledger_reopen_check(context: &SystemContext) -> CheckResult {
    let started = Instant::now();
    let scratch = context.scratch_root.join("cargo");
    let evidence = vec![
        "coverage: filesystem SQLite ledger extension, backup snapshot, reopen with \
         durable content and canonical checksums, restore to a fresh destination, \
         checksum-drift denial without destination publication, and open denial \
         without the extension migration set"
            .to_owned(),
        format!("cargo test -p {LEDGER_PACKAGE} --lib {LEDGER_SELECTOR} -j 3 -- --exact"),
        format!("from odin root: {}", context.odin_root.display()),
    ];
    let run = run_cargo_tests(
        &context.odin_root,
        &scratch,
        &[
            "test",
            "-p",
            LEDGER_PACKAGE,
            "--lib",
            LEDGER_SELECTOR,
            "--",
            "--exact",
        ],
        &[],
    );
    let outcome = run.ok_stdout().map_err(str::to_owned).and_then(|stdout| {
        if single_test_passed(stdout, LEDGER_SELECTOR) {
            Ok(())
        } else {
            Err(format!(
                "cargo reported success but its output does not confirm exactly one pass \
                 of {LEDGER_SELECTOR}; a zero-match selection never counts as success"
            ))
        }
    });
    match outcome {
        Ok(()) => CheckResult::new(
            LEDGER_CHECK_ID,
            LEDGER_CHECK_NAME,
            CheckStatus::Pass,
            elapsed_ms(started),
            format!("{LEDGER_PACKAGE} {LEDGER_SELECTOR}: exactly one test passed"),
            evidence,
        ),
        Err(reason) => CheckResult::new(
            LEDGER_CHECK_ID,
            LEDGER_CHECK_NAME,
            CheckStatus::Fail,
            elapsed_ms(started),
            format!("{LEDGER_PACKAGE} {LEDGER_SELECTOR}: selection did not pass"),
            evidence,
        )
        .with_reason(reason),
    }
}
