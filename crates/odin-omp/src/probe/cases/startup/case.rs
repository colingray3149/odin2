//! Case 1 experiment: the bounded cold-start run against the pinned OMP
//! child — fresh-start launch contract, identity probe, raw driver startup,
//! negotiation window, and graceful exit.

use std::fs;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::json;

use crate::frames::RpcProtocolVersion;
use crate::probe::{
    CaseContext, CaseEvidence, CaseOutcome, CleanupReceipt, ConformanceCase, ConformanceCaseId,
    RawRpcDriver, DEFAULT_MODEL_SELECTOR, PINNED_OMP_SOURCE_REVISION,
};
use crate::process::OmpLifecycleState;

use super::evidence::*;
use super::*;

const CASE_DEADLINE: Duration = Duration::from_secs(120);
const NO_SESSION_ARGUMENT: &str = "--no-session";

pub(super) struct ReadyStartup;

#[async_trait]
impl ConformanceCase for ReadyStartup {
    fn id(&self) -> ConformanceCaseId {
        READY_STARTUP
    }

    fn name(&self) -> &'static str {
        "ready_startup"
    }

    fn deadline(&self) -> Duration {
        CASE_DEADLINE
    }

    async fn run(&self, context: &CaseContext) -> CaseOutcome {
        let mut failures = Vec::new();
        let mut evidence = Vec::new();
        let mut cleanup = CleanupReceipt::default();

        let no_session_is_preconfigured = context
            .config()
            .omp
            .explicit_args
            .iter()
            .any(|argument| argument == NO_SESSION_ARGUMENT);
        let extra_args = if no_session_is_preconfigured {
            Vec::new()
        } else {
            vec![NO_SESSION_ARGUMENT.to_owned()]
        };
        let spec = context.process_spec(DEFAULT_MODEL_SELECTOR, extra_args);
        let no_session_count = spec
            .explicit_args
            .iter()
            .filter(|argument| argument.as_str() == NO_SESSION_ARGUMENT)
            .count();
        let session_selectors = spec
            .explicit_args
            .iter()
            .filter(|argument| selects_existing_session(argument))
            .map(String::as_str)
            .collect::<Vec<_>>();

        evidence.push(CaseEvidence {
            kind: "launch_contract",
            label: "fresh-start.json".to_owned(),
            bytes: json!({
                "configuredExecutable": spec.executable.to_string_lossy(),
                "workingDirectory": spec.cwd.to_string_lossy(),
                "expectedSourceRevision": spec.expected_source_revision.as_str(),
                "argumentCount": spec.explicit_args.len(),
                "environmentNames": spec
                    .explicit_env
                    .iter()
                    .map(|(name, _)| name.as_str())
                    .collect::<Vec<_>>(),
                "noSessionArgumentCount": no_session_count,
                "sessionSelectors": &session_selectors,
                "caseIssuedCommands": 0,
            })
            .to_string()
            .into_bytes(),
        });

        if no_session_count != 1 {
            push_failure(
                &mut failures,
                "fresh_start",
                format!(
                    "expected exactly one {NO_SESSION_ARGUMENT} argument, observed {no_session_count}"
                ),
            );
        }
        if !session_selectors.is_empty() {
            push_failure(
                &mut failures,
                "fresh_start",
                format!("session selection arguments are forbidden: {session_selectors:?}"),
            );
        }
        if spec.expected_source_revision != PINNED_OMP_SOURCE_REVISION {
            push_failure(
                &mut failures,
                "source_revision",
                format!(
                    "expected {PINNED_OMP_SOURCE_REVISION}, observed {}",
                    spec.expected_source_revision
                ),
            );
        }
        if !failures.is_empty() {
            return finish(failures, evidence, cleanup);
        }

        if let Err(error) = fs::create_dir_all(context.work_dir()) {
            push_failure(
                &mut failures,
                "work_directory",
                format!("failed to prepare retained case directory: {error}"),
            );
            evidence.push(error_evidence("work-directory-error.txt", &error));
            return finish(failures, evidence, cleanup);
        }

        let identity = match spec.establish_identity(&context.worker_for(&spec)).await {
            Ok(identity) => identity,
            Err(error) => {
                push_failure(
                    &mut failures,
                    "executable_identity",
                    format!("bounded identity probe failed: {error}"),
                );
                retain_process_error(&error, &mut evidence);
                return finish(failures, evidence, cleanup);
            }
        };
        retain_identity(&identity, &mut evidence);
        validate_identity(&spec.executable, &identity, &mut failures);
        if !failures.is_empty() {
            return finish(failures, evidence, cleanup);
        }

        let mut driver = match {
            let worker = context.worker_for(&spec);
            RawRpcDriver::spawn(spec, worker)
        }
        .await
        {
            Ok(driver) => driver,
            Err(error) => {
                push_failure(
                    &mut failures,
                    "startup",
                    format!("pinned OMP did not complete its bounded startup handshake: {error}"),
                );
                retain_raw_driver_error(&error, &mut evidence);
                return finish(failures, evidence, cleanup);
            }
        };

        let worker = driver.process().worker_id().map(ToString::to_string);
        if worker.is_none() {
            push_failure(
                &mut failures,
                "child_identity",
                "ready child has no logical worker identity",
            );
        }
        if driver.process().state() != OmpLifecycleState::Ready(RpcProtocolVersion::V2) {
            push_failure(
                &mut failures,
                "negotiated_protocol",
                format!(
                    "expected lifecycle ready(v2), observed {}",
                    driver.process().state()
                ),
            );
        }

        let ready = driver.process().ready_frame().cloned();
        let negotiation = driver.process().negotiation_frame().cloned();
        match ready.as_ref() {
            Some(frame) => {
                validate_ready(frame, &mut failures);
                evidence.push(frame_evidence(
                    "ready_frame",
                    "ready.raw.jsonl",
                    "ready_raw",
                    frame,
                    &mut failures,
                ));
            }
            None => push_failure(
                &mut failures,
                "ready_frame",
                "startup returned ready without retaining the ready frame",
            ),
        }
        match negotiation.as_ref() {
            Some(frame) => {
                validate_negotiation(frame, &mut failures);
                evidence.push(frame_evidence(
                    "protocol_negotiation",
                    "negotiate-protocol.raw.jsonl",
                    "negotiation_raw",
                    frame,
                    &mut failures,
                ));
            }
            None => push_failure(
                &mut failures,
                "negotiated_protocol",
                "protocol v2 is ready without a retained negotiation response",
            ),
        }
        validate_startup_transcript(
            driver.transcript(),
            ready.as_ref(),
            negotiation.as_ref(),
            &mut evidence,
            &mut failures,
        );

        let startup_transcript_len = driver.transcript().len();
        let cleanup_subject = format!("pinned OMP session {}", context.ids().session);
        match driver.cleanup(&mut cleanup, cleanup_subject).await {
            Ok(exit) => {
                evidence.push(CaseEvidence {
                    kind: "process_exit",
                    label: "graceful-exit.json".to_owned(),
                    bytes: json!({
                        "success": exit.success(),
                        "code": exit.code(),
                        "stderrBytes": exit.stderr_tail().len(),
                        "unfinishedSequence": exit.unfinished_sequence().is_some(),
                    })
                    .to_string()
                    .into_bytes(),
                });
                if !exit.stderr_tail().is_empty() {
                    evidence.push(CaseEvidence {
                        kind: "process_stderr",
                        label: "graceful-exit.stderr".to_owned(),
                        bytes: exit.stderr_tail().to_vec(),
                    });
                }
                if !exit.success() || exit.code() != Some(0) {
                    push_failure(
                        &mut failures,
                        "graceful_exit",
                        format!(
                            "expected successful exit code 0, observed success={} code={:?}",
                            exit.success(),
                            exit.code()
                        ),
                    );
                }
                if exit.unfinished_sequence().is_some() {
                    push_failure(
                        &mut failures,
                        "graceful_exit",
                        "stdout ended with an unfinished frame sequence",
                    );
                }
            }
            Err(error) => {
                push_failure(
                    &mut failures,
                    "cleanup",
                    format!("bounded graceful stop and forced cleanup failed: {error}"),
                );
                retain_raw_driver_error(&error, &mut evidence);
            }
        }

        if driver.process().state() != OmpLifecycleState::Exited {
            push_failure(
                &mut failures,
                "graceful_exit",
                format!(
                    "expected terminal exited lifecycle, observed {}",
                    driver.process().state()
                ),
            );
        }
        validate_cleanup(&cleanup, &mut failures);
        if let Some(shutdown) = shutdown_evidence(
            driver
                .transcript()
                .get(startup_transcript_len..)
                .unwrap_or_default(),
            &mut failures,
        ) {
            evidence.push(shutdown);
        }
        enforce_success_evidence(&evidence, &mut failures);

        finish(failures, evidence, cleanup)
    }
}
