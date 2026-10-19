//! INT-VAULT: the two SilverBullet loopback smokes against the host's real vault service.

use std::time::Instant;

use crate::report::{CheckResult, CheckStatus};
use crate::syscheck::SystemContext;

use super::cargo::{run_cargo_tests, single_test_passed};
use super::{elapsed_ms, VAULT_CHECK_ID};

const VAULT_CHECK_NAME: &str = "SilverBullet vault loopback";

const VAULT_SELECTOR: &str = "live_loopback_smoke";
const VAULT_SUITES: [(&str, &str); 2] = [("odin-brain", "vault_source"), ("odin-hermes", "vault")];

pub(super) fn vault_loopback_check(context: &SystemContext) -> CheckResult {
    let started = Instant::now();
    let scratch = context.scratch_root.join("cargo");
    let mut evidence = vec![
        "coverage: the real SilverBullet /.fs/ API on loopback — scoped pin of exactly one \
         disposable probe page, byte-exact round trip, exclusion refusals, removal"
            .to_owned(),
        format!("from odin root: {}", context.odin_root.display()),
    ];
    let mut failures = Vec::new();
    for (package, suite) in VAULT_SUITES {
        evidence.push(format!(
            "cargo test -p {package} --test {suite} -j 3 -- --ignored --exact {VAULT_SELECTOR}"
        ));
        let run = run_cargo_tests(
            &context.odin_root,
            &scratch,
            &[
                "test",
                "-p",
                package,
                "--test",
                suite,
                "--",
                "--ignored",
                "--exact",
                VAULT_SELECTOR,
            ],
            &[],
        );
        match run.ok_stdout() {
            Ok(stdout) if single_test_passed(stdout, VAULT_SELECTOR) => {}
            Ok(_) => failures.push(format!(
                "{package} {suite}: cargo succeeded but did not confirm exactly one pass of \
                 {VAULT_SELECTOR}"
            )),
            Err(reason) => failures.push(format!("{package} {suite}: {reason}")),
        }
    }
    if failures.is_empty() {
        CheckResult::new(
            VAULT_CHECK_ID,
            VAULT_CHECK_NAME,
            CheckStatus::Pass,
            elapsed_ms(started),
            "both SilverBullet loopback smokes passed against the live vault service",
            evidence,
        )
    } else {
        CheckResult::new(
            VAULT_CHECK_ID,
            VAULT_CHECK_NAME,
            CheckStatus::Fail,
            elapsed_ms(started),
            "a SilverBullet loopback smoke did not pass",
            evidence,
        )
        .with_reason(failures.join("; "))
    }
}
