use super::browser::BROWSER_REQUIRED_SELECTORS;
use super::cargo::{single_test_passed, suite_output_confirms_full_pass, CargoRun};
use super::k3s::k3s_verdict;
use super::kube::kube_lifecycle_verdict;
use super::ledger::LEDGER_SELECTOR;
use crate::report::CheckStatus;
use crate::syscheck::probe::BoundedOutput;

#[test]
fn success_requires_the_exact_test_line_and_the_one_pass_summary() {
    let selector = LEDGER_SELECTOR;
    let good = "running 1 test\n\
                test migration::tests::extension_reopens_with_same_set ... ok\n\n\
                test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; \
                84 filtered out; finished in 0.01s\n";
    assert!(single_test_passed(good, selector));

    // A filter matching nothing exits zero: the zero-pass summary must not
    // be mistaken for a passing selection.
    let zero_match = "running 0 tests\n\n\
                      test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; \
                      85 filtered out; finished in 0.00s\n";
    assert!(!single_test_passed(zero_match, selector));

    // A different test passing cannot satisfy the exact selection.
    let other = "test migration::tests::something_else ... ok\n\n\
                 test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; \
                 84 filtered out; finished in 0.01s\n";
    assert!(!single_test_passed(other, selector));

    let failed = "test migration::tests::extension_reopens_with_same_set ... FAILED\n\n\
                  test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; \
                  84 filtered out; finished in 0.01s\n";
    assert!(!single_test_passed(failed, selector));
}

#[test]
fn browser_suite_requires_required_lines_and_a_full_pass_summary() {
    let ok = "running 30 tests\n\
              test session::runtime::tests::worker_teardown ... ok\n\
              test scanner::tests::scanner_stop_authority ... ok\n\
              test session::control::durable_control_tests::durable_control_reopen_invalidates_holder_and_advances_revision ... ok\n\
              test session::control::durable_control_tests::another ... ok\n\n\
              test result: ok. 30 passed; 0 failed; 0 ignored; 0 measured; \
              0 filtered out; finished in 0.5s\n";
    assert!(suite_output_confirms_full_pass(
        ok,
        &BROWSER_REQUIRED_SELECTORS
    ));

    let zero_match = "running 0 tests\n\n\
                      test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; \
                      30 filtered out; finished in 0.00s\n";
    assert!(!suite_output_confirms_full_pass(
        zero_match,
        &BROWSER_REQUIRED_SELECTORS
    ));

    let missing_required = ok.replace("test scanner::tests::scanner_stop_authority ... ok\n", "");
    assert!(!suite_output_confirms_full_pass(
        &missing_required,
        &BROWSER_REQUIRED_SELECTORS
    ));

    let failed = "test scanner::tests::scanner_stop_authority ... FAILED\n\n\
                  test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; \
                  29 filtered out; finished in 0.1s\n";
    assert!(!suite_output_confirms_full_pass(
        failed,
        &BROWSER_REQUIRED_SELECTORS
    ));

    let ten_failed = "test session::runtime::tests::worker_teardown ... ok\n\n\
                      test result: ok. 1 passed; 10 failed; 0 ignored; 0 measured; \
                      19 filtered out; finished in 0.2s\n";
    assert!(!suite_output_confirms_full_pass(
        ten_failed,
        &BROWSER_REQUIRED_SELECTORS
    ));
}

#[test]
fn k3s_passes_only_on_a_zero_exit_with_the_exact_ready_body() {
    let probe = BoundedOutput {
        exit_code: Some(0),
        timed_out: false,
        stdout: b"ok\n".to_vec(),
        stderr: Vec::new(),
        stdout_truncated: 0,
        stderr_truncated: 0,
    };
    assert_eq!(k3s_verdict(&probe), Ok("ok".to_owned()));
}

#[test]
fn k3s_zero_exit_without_the_ready_body_is_a_real_failure() {
    let probe = BoundedOutput {
        exit_code: Some(0),
        timed_out: false,
        stdout: b"ok\nsome-probe failed\n".to_vec(),
        stderr: Vec::new(),
        stdout_truncated: 0,
        stderr_truncated: 0,
    };
    let (status, reason) = k3s_verdict(&probe).expect_err("an unexpected body must not pass");
    assert_eq!(status, CheckStatus::Fail);
    assert!(
        reason.contains("expected"),
        "reason names the law: {reason}"
    );
}

#[test]
fn k3s_timeout_and_failed_conversations_are_blocked_never_green() {
    let timed_out = BoundedOutput {
        exit_code: None,
        timed_out: true,
        stdout: Vec::new(),
        stderr: Vec::new(),
        stdout_truncated: 0,
        stderr_truncated: 0,
    };
    let (status, reason) = k3s_verdict(&timed_out).expect_err("a timeout must not pass");
    assert_eq!(status, CheckStatus::Blocked);
    assert!(reason.contains("command-timeout"), "reason: {reason}");

    let unreachable = BoundedOutput {
        exit_code: Some(1),
        timed_out: false,
        stdout: Vec::new(),
        stderr: b"E0910 error: connection refused\n".to_vec(),
        stdout_truncated: 0,
        stderr_truncated: 0,
    };
    let (status, reason) = k3s_verdict(&unreachable).expect_err("a failed call must not pass");
    assert_eq!(status, CheckStatus::Blocked);
    assert!(reason.contains("unavailable"), "reason: {reason}");
    assert!(reason.contains("connection refused"), "reason: {reason}");
}

#[test]
fn k3s_truncated_output_is_blocked_even_when_the_prefix_trims_to_ready() {
    let truncated = BoundedOutput {
        exit_code: Some(0),
        timed_out: false,
        stdout: b"ok\n".to_vec(),
        stderr: b"truncated diagnostic trailer\n".to_vec(),
        stdout_truncated: 512,
        stderr_truncated: 0,
    };
    let (status, reason) =
        k3s_verdict(&truncated).expect_err("truncated output cannot prove cluster readiness");
    assert_eq!(status, CheckStatus::Blocked);
    assert!(
        reason.contains("command-output-truncated"),
        "reason: {reason}"
    );
}
#[test]
fn kube_lifecycle_passes_only_on_a_confirmed_full_pass() {
    let ok = "running 4 tests\n\
              test created_job_reaches_observed_success_status ... ok\n\
              test optimistic_conflict_and_idempotent_replay_follow_command_law ... ok\n\
              test foreign_objects_stay_read_only ... ok\n\
              test cancel_teardown_proves_authoritative_pod_absence ... ok\n\n\
              test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; \
              0 filtered out; finished in 2.5s\n";
    let run = CargoRun {
        ok: true,
        stdout: ok.to_owned(),
        failure: None,
    };
    assert!(kube_lifecycle_verdict(&run).is_ok());
}

#[test]
fn kube_zero_match_or_partial_output_is_a_real_failure() {
    let zero_match = "running 0 tests\n\n\
                      test result: ok. 0 passed; 0 failed; 0 ignored; \
                      4 filtered out; finished in 0.0s\n";
    let run = CargoRun {
        ok: true,
        stdout: zero_match.to_owned(),
        failure: None,
    };
    let (status, reason) =
        kube_lifecycle_verdict(&run).expect_err("a zero-match run must not pass");
    assert_eq!(status, CheckStatus::Fail);
    assert!(reason.contains("does not confirm"), "reason: {reason}");
}

#[test]
fn kube_unavailable_cluster_is_blocked_with_the_exact_prerequisite() {
    let unavailable = "running 4 tests\n\
                       test created_job_reaches_observed_success_status ... FAILED\n\n\
                       failures:\n\n\
                       ---- created_job_reaches_observed_success_status stdout ----\n\
                       kube unavailable: kube config \
                       /etc/rancher/k3s/k3s.yaml is unreadable: cluster \
                       unreachable\n\n\
                       test result: FAILED. 0 passed; 1 failed; 3 ignored; \
                       0 measured; 0 filtered out; finished in 0.4s\n";
    let run = CargoRun {
        ok: false,
        stdout: unavailable.to_owned(),
        failure: Some("cargo [\"test\"] exited with exit status: 101".to_owned()),
    };
    let (status, reason) =
        kube_lifecycle_verdict(&run).expect_err("an unavailable cluster must not pass");
    assert_eq!(status, CheckStatus::Blocked);
    assert!(
        reason.contains("activate then sudo systemctl start k3s"),
        "reason names the exact prerequisite: {reason}"
    );
}

#[test]
fn kube_unavailability_does_not_hide_an_independent_failure() {
    let run = CargoRun {
        ok: false,
        stdout: "test create ... FAILED\n\
                 test cancel ... FAILED\n\
                 ---- create stdout ----\n\
                 kube unavailable: API unreachable\n\
                 ---- cancel stdout ----\n\
                 assertion failed: surviving pod\n\
                 test result: FAILED. 0 passed; 2 failed;\n"
            .to_owned(),
        failure: Some("cargo exited with 101".to_owned()),
    };
    assert_eq!(
        kube_lifecycle_verdict(&run).unwrap_err().0,
        CheckStatus::Fail
    );
}

#[test]
fn kube_failure_without_an_unavailability_marker_is_fail() {
    let failed = "running 4 tests\n\
                  test cancel_teardown_proves_authoritative_pod_absence ... FAILED\n\n\
                  test result: FAILED. 3 passed; 1 failed; 0 ignored; \
                  0 measured; 0 filtered out; finished in 9.1s\n";
    let run = CargoRun {
        ok: false,
        stdout: failed.to_owned(),
        failure: Some("cargo [\"test\"] exited with exit status: 101".to_owned()),
    };
    let (status, reason) =
        kube_lifecycle_verdict(&run).expect_err("a failed lifecycle must not pass");
    assert_eq!(status, CheckStatus::Fail);
    assert!(reason.contains("exited with"), "reason: {reason}");
}

#[test]
fn printed_pass_lines_need_summaries_that_count_them() {
    let forged = "running 1 test\n\
                  test session::runtime::tests::worker_teardown ... ok\n\
                  test scanner::tests::scanner_stop_authority ... ok\n\
                  test session::control::durable_control_tests::durable_control_reopen_invalidates_holder_and_advances_revision ... ok\n\n\
                  test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; \
                  29 filtered out; finished in 0.5s\n";
    assert!(!suite_output_confirms_full_pass(
        forged,
        &BROWSER_REQUIRED_SELECTORS
    ));
}
