//! The shared case harness: the `ControlRun` turn driver, fixture and file
//! plumbing, frame predicates, and failure helpers for cases 6-10.

use super::*;

pub(super) const ACTIVE_TURN_DELAY_MS: u64 = 4_000;
pub(super) const RESPONSE_BOUND: Duration = Duration::from_secs(5);
pub(super) const TURN_BOUND: Duration = Duration::from_secs(15);
pub(super) const ABORT_BOUND: Duration = Duration::from_secs(5);
pub(super) const STANDARD_CASE_DEADLINE: Duration = Duration::from_secs(30);

struct MarkerFixture {
    directory: PathBuf,
    started: PathBuf,
    orphan: PathBuf,
}

pub(super) struct ControlRun {
    pub(super) name: &'static str,
    pub(super) driver: RawRpcDriver,
    pub(super) started: Instant,
    pub(super) timing: Vec<Value>,
    pub(super) evidence: Vec<CaseEvidence>,
    pub(super) cleanup: CleanupReceipt,
    marker_fixture: Option<MarkerFixture>,
}

impl ControlRun {
    pub(super) fn new(name: &'static str, driver: RawRpcDriver) -> Self {
        let worker = driver.process().worker_id().map(ToString::to_string);
        let mut run = Self {
            name,
            driver,
            started: Instant::now(),
            timing: Vec::new(),
            evidence: Vec::new(),
            cleanup: CleanupReceipt::default(),
            marker_fixture: None,
        };
        run.mark("child_ready", json!({ "workerId": worker }));
        run
    }

    pub(super) fn mark(&mut self, label: impl Into<String>, detail: Value) {
        let elapsed_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.timing.push(json!({
            "label": label.into(),
            "elapsed_ms": elapsed_ms,
            "detail": detail,
        }));
    }

    pub(super) async fn send(
        &mut self,
        command: &'static str,
        fields: Value,
        label: &'static str,
    ) -> Result<(String, usize), CaseFailure> {
        let start = self.driver.transcript().len();
        let id = self
            .driver
            .send(command, fields)
            .await
            .map_err(|error| failure(label, format!("failed to send {command}: {error}")))?;
        self.mark(
            format!("{label}.sent"),
            json!({ "request_id": id, "command": command }),
        );
        Ok((id, start))
    }

    pub(super) async fn response(
        &mut self,
        id: &str,
        command: &'static str,
        bound: Duration,
        check: &'static str,
    ) -> Result<DecodedRpcFrame, CaseFailure> {
        self.response_until(id, command, Instant::now() + bound, check)
            .await
    }

    pub(super) async fn response_until(
        &mut self,
        id: &str,
        command: &'static str,
        deadline: Instant,
        check: &'static str,
    ) -> Result<DecodedRpcFrame, CaseFailure> {
        let frame = self
            .driver
            .wait_for_response(id, command, deadline)
            .await
            .map_err(|error| {
                failure(
                    check,
                    format!("missing {command} response for {id}: {error}"),
                )
            })?;
        self.mark(
            format!("{check}.received"),
            json!({ "request_id": id, "command": command }),
        );
        if frame.value().get("success").and_then(Value::as_bool) != Some(true) {
            return Err(failure(
                check,
                format!("command returned a non-success response: {}", frame.value()),
            ));
        }
        Ok(frame)
    }

    pub(super) async fn wait_frame<F>(
        &mut self,
        start: usize,
        bound: Duration,
        check: &'static str,
        mut predicate: F,
    ) -> Result<DecodedRpcFrame, CaseFailure>
    where
        F: FnMut(&DecodedRpcFrame) -> bool,
    {
        if let Some(frame) = self
            .driver
            .transcript()
            .iter()
            .skip(start)
            .find(|frame| predicate(frame))
            .cloned()
        {
            self.mark(
                format!("{check}.observed"),
                json!({ "from_transcript": true }),
            );
            return Ok(frame);
        }
        let frames = self
            .driver
            .collect_until(Instant::now() + bound, |frame| predicate(frame))
            .await
            .map_err(|error| failure(check, format!("required frame was not observed: {error}")))?;
        let frame = frames
            .last()
            .cloned()
            .ok_or_else(|| failure(check, "frame collection returned no frames"))?;
        self.mark(
            format!("{check}.observed"),
            json!({ "from_transcript": false }),
        );
        Ok(frame)
    }

    pub(super) async fn state(&mut self, label: &'static str) -> Result<Value, CaseFailure> {
        let (id, _) = self.send("get_state", json!({}), label).await?;
        let frame = self
            .response(&id, "get_state", RESPONSE_BOUND, label)
            .await?;
        let state = frame
            .value()
            .get("data")
            .cloned()
            .ok_or_else(|| failure(label, "get_state response omitted data"))?;
        self.record_json("state", label, &state)?;
        Ok(state)
    }

    pub(super) async fn messages(&mut self, label: &'static str) -> Result<Value, CaseFailure> {
        let (id, _) = self.send("get_messages", json!({}), label).await?;
        let frame = self
            .response(&id, "get_messages", RESPONSE_BOUND, label)
            .await?;
        let messages = frame
            .value()
            .pointer("/data/messages")
            .cloned()
            .ok_or_else(|| failure(label, "get_messages response omitted data.messages"))?;
        self.record_json("messages", label, &messages)?;
        Ok(messages)
    }

    pub(super) fn record_json(
        &mut self,
        kind: &'static str,
        label: impl Into<String>,
        value: &Value,
    ) -> Result<(), CaseFailure> {
        let label = label.into();
        let bytes = serde_json::to_vec_pretty(value).map_err(|error| {
            failure(
                "evidence_serialization",
                format!("could not encode {label}: {error}"),
            )
        })?;
        self.record_bytes(kind, label, bytes);
        Ok(())
    }

    pub(super) fn record_bytes(
        &mut self,
        kind: &'static str,
        label: impl Into<String>,
        bytes: Vec<u8>,
    ) {
        self.evidence.push(CaseEvidence {
            kind,
            label: label.into(),
            bytes,
        });
    }

    pub(super) fn register_marker_fixture(
        &mut self,
        directory: PathBuf,
        started: PathBuf,
        orphan: PathBuf,
    ) {
        self.marker_fixture = Some(MarkerFixture {
            directory,
            started,
            orphan,
        });
    }

    pub(super) fn cleanup_registered_marker(&mut self, safe_to_remove: bool) {
        let Some(fixture) = self.marker_fixture.take() else {
            return;
        };
        if !safe_to_remove {
            self.cleanup.push(
                "fixture_remove",
                fixture.directory.display().to_string(),
                CleanupOutcome::Failed {
                    reason: "OMP child was not confirmed stopped; marker evidence retained"
                        .to_owned(),
                },
            );
            return;
        }
        let orphan_exists = match path_exists(&fixture.orphan) {
            Ok(exists) => exists,
            Err(error) => {
                self.cleanup.push(
                    "fixture_remove",
                    fixture.directory.display().to_string(),
                    CleanupOutcome::Failed {
                        reason: error.detail,
                    },
                );
                return;
            }
        };
        self.cleanup.push(
            "fixture_remove",
            fixture.directory.display().to_string(),
            cleanup_marker_fixture(&fixture.directory, &fixture.started, orphan_exists),
        );
    }

    pub(super) async fn finish(
        mut self,
        pass_summary: &'static str,
        fail_summary: &'static str,
        result: Result<Vec<CaseFailure>, CaseFailure>,
    ) -> CaseOutcome {
        let mut failures = match result {
            Ok(failures) => failures,
            Err(error) => vec![error],
        };

        match self.driver.cleanup(&mut self.cleanup, self.name).await {
            Ok(exit) if !exit.success() => {
                failures.push(failure(
                    "cleanup_exit",
                    format!("child cleanup ended with {exit}"),
                ));
            }
            Ok(_) => {}
            Err(error) => {
                failures.push(failure("cleanup", format!("child cleanup failed: {error}")))
            }
        }
        let child_stopped = self.cleanup.steps.iter().any(|step| {
            matches!(step.kind.as_str(), "child_stop" | "child_kill")
                && matches!(&step.outcome, CleanupOutcome::Clean)
        });
        self.cleanup_registered_marker(child_stopped);
        if self.cleanup.steps.is_empty() {
            failures.push(failure("cleanup", "no child cleanup receipt was recorded"));
        } else if !self.cleanup.is_clean() {
            failures.push(failure("cleanup", "one or more cleanup steps left residue"));
        }

        let has_effect_evidence = self
            .evidence
            .iter()
            .any(|item| matches!(item.kind, "effect" | "state" | "messages" | "model"));
        if !has_effect_evidence {
            failures.push(failure(
                "effect_evidence",
                "case produced no state or effect evidence",
            ));
        }

        let transcript = self.driver.transcript();
        let wire = wire_transcript(transcript);
        if transcript.is_empty() || wire.is_empty() {
            failures.push(failure(
                "raw_evidence",
                "decoded transcript had no retained physical frame bytes",
            ));
        } else if transcript.iter().any(|frame| frame.lines().is_empty()) {
            failures.push(failure(
                "raw_evidence",
                "a decoded frame lacked exact physical-line evidence",
            ));
        } else {
            self.record_bytes("rpc_wire", format!("{}-physical.jsonl", self.name), wire);
        }

        let timing = json!({
            "clock": "monotonic_case_elapsed",
            "unit": "milliseconds",
            "marks": std::mem::take(&mut self.timing),
        });
        match serde_json::to_vec_pretty(&timing) {
            Ok(bytes) if !bytes.is_empty() => {
                self.record_bytes("timing", format!("{}-timing.json", self.name), bytes)
            }
            Ok(_) => failures.push(failure("timing_evidence", "timing evidence was empty")),
            Err(error) => failures.push(failure(
                "timing_evidence",
                format!("timing serialization failed: {error}"),
            )),
        }

        let mut outcome = if failures.is_empty() {
            CaseOutcome::pass(pass_summary)
        } else {
            CaseOutcome::fail(fail_summary, failures)
        };
        outcome.evidence = self.evidence;
        outcome.cleanup = self.cleanup;
        outcome
    }
}

pub(super) fn startup_failure(name: &'static str, error: impl std::fmt::Display) -> CaseOutcome {
    let detail = format!("could not start pinned OMP for {name}: {error}");
    let mut outcome = CaseOutcome::fail(
        "pinned OMP startup failed",
        vec![failure("child_start", detail.clone())],
    );
    outcome.evidence.push(CaseEvidence {
        kind: "startup_error",
        label: format!("{name}-startup-error"),
        bytes: detail.into_bytes(),
    });
    outcome
}

pub(super) fn failure(check: &'static str, detail: impl Into<String>) -> CaseFailure {
    CaseFailure {
        check: check.to_owned(),
        detail: detail.into(),
    }
}

pub(super) fn require(
    failures: &mut Vec<CaseFailure>,
    condition: bool,
    check: &'static str,
    detail: impl Into<String>,
) {
    if !condition {
        failures.push(failure(check, detail));
    }
}

pub(super) fn require_order(
    failures: &mut Vec<CaseFailure>,
    before: Option<usize>,
    after: Option<usize>,
    check: &'static str,
    before_name: &'static str,
    after_name: &'static str,
) {
    require(
        failures,
        before
            .zip(after)
            .is_some_and(|(before, after)| before < after),
        check,
        format!(
            "expected {before_name} before {after_name}, observed indices {before:?} and {after:?}"
        ),
    );
}

pub(super) fn frame_type(frame: &DecodedRpcFrame, expected: &str) -> bool {
    frame.value().get("type").and_then(Value::as_str) == Some(expected)
}

pub(super) fn response_is(frame: &DecodedRpcFrame, id: &str, command: &str) -> bool {
    frame_type(frame, "response")
        && frame.value().get("id").and_then(Value::as_str) == Some(id)
        && frame.value().get("command").and_then(Value::as_str) == Some(command)
}

pub(super) fn event_message<'a>(
    frame: &'a DecodedRpcFrame,
    event_type: &'static str,
) -> Option<&'a Value> {
    if !frame_type(frame, event_type) {
        return None;
    }
    frame.value().get("message")
}

pub(super) fn message_text(message: &Value) -> Option<&str> {
    let content = message.get("content")?;
    if let Some(text) = content.as_str() {
        return Some(text);
    }
    content.as_array()?.iter().find_map(|block| {
        if block.get("type").and_then(Value::as_str) == Some("text") {
            block.get("text").and_then(Value::as_str)
        } else {
            None
        }
    })
}

pub(super) fn assistant_text_is(frame: &DecodedRpcFrame, expected: &str) -> bool {
    event_message(frame, "message_end").is_some_and(|message| {
        message.get("role").and_then(Value::as_str) == Some("assistant")
            && message_text(message) == Some(expected)
    })
}

pub(super) fn user_text_is(frame: &DecodedRpcFrame, expected: &str) -> bool {
    event_message(frame, "message_start").is_some_and(|message| {
        message.get("role").and_then(Value::as_str) == Some("user")
            && message_text(message) == Some(expected)
    })
}

pub(super) fn frame_index<F>(
    frames: &[DecodedRpcFrame],
    start: usize,
    mut predicate: F,
) -> Option<usize>
where
    F: FnMut(&DecodedRpcFrame) -> bool,
{
    frames
        .iter()
        .enumerate()
        .skip(start)
        .find_map(|(index, frame)| predicate(frame).then_some(index))
}

fn wire_transcript(frames: &[DecodedRpcFrame]) -> Vec<u8> {
    let size = frames
        .iter()
        .flat_map(|frame| frame.lines())
        .fold(0usize, |size, line| size.saturating_add(line.len()));
    let mut bytes = Vec::with_capacity(size);
    for frame in frames {
        for line in frame.lines() {
            bytes.extend_from_slice(line);
        }
    }
    bytes
}

pub(super) fn path_exists(path: &Path) -> Result<bool, CaseFailure> {
    match std::fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(failure(
            "background_bash_no_orphan",
            format!(
                "could not inspect orphan marker {}: {error}",
                path.display()
            ),
        )),
    }
}

fn cleanup_marker_fixture(
    marker_dir: &Path,
    started_path: &Path,
    orphan_exists: bool,
) -> CleanupOutcome {
    if orphan_exists {
        return CleanupOutcome::Failed {
            reason: "orphan marker retained as failure evidence".to_owned(),
        };
    }
    match std::fs::remove_file(started_path) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return CleanupOutcome::Failed {
                reason: format!(
                    "could not remove disposable start marker {}: {error}",
                    started_path.display()
                ),
            };
        }
    }
    match std::fs::remove_dir(marker_dir) {
        Ok(()) => CleanupOutcome::Clean,
        Err(error) => CleanupOutcome::Failed {
            reason: format!(
                "could not remove disposable marker directory {}: {error}",
                marker_dir.display()
            ),
        },
    }
}
