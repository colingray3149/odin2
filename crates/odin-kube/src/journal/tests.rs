use super::*;
use std::collections::BTreeMap;

use odin_domain::huginn::{KubeJobLabels, KubeResourceVersion, KubeStagingProjection};
use odin_domain::{AttemptId, LaneId, ProjectId, SeatId, TaskId};

fn journal() -> (Journal, tempfile::TempDir) {
    let directory = tempfile::tempdir().expect("disposable journal ledger directory");
    let ledger = Ledger::open(directory.path().join("journal-tests.sqlite3"))
        .expect("disposable ledger opens");
    (
        Journal::new(
            Arc::new(Mutex::new(ledger)),
            "test-cluster".to_owned(),
            "test-namespace".to_owned(),
        ),
        directory,
    )
}

fn admit(journal: &Journal, operation: &str, workload: &str) -> Started {
    journal
        .begin(
            &OperationId::new(operation).expect("valid operation id"),
            &RunId::new("run-journal-tests").expect("valid run id"),
            KubeOperationKind::Create,
            &Digest::hash(workload.as_bytes()),
            &serde_json::json!({ "workload": { "name": workload } }),
        )
        .expect("operation admits")
}

fn operation_row(journal: &Journal, operation: &str) -> (String, Option<String>, Option<String>) {
    let ledger = journal.ledger.lock().expect("operation ledger lock");
    ledger.connection().query_row(
            "SELECT state,progress_json,failure_kind FROM kube_job_operations WHERE operation_id=?1",
            [operation],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).expect("operation row exists")
}

fn latest_attempt_verdict(journal: &Journal, operation: &str) -> String {
    let ledger = journal.ledger.lock().expect("operation ledger lock");
    ledger.connection().query_row(
            "SELECT verdict FROM kube_job_attempts WHERE canonical_operation_id=?1 ORDER BY created_at DESC LIMIT 1",
            [operation],
            |row| row.get(0),
        ).expect("attempt row exists")
}

#[test]
fn unproved_unavailable_keeps_the_recovery_record_pending() {
    let (journal, _directory) = journal();
    let operation_id = "op-unproved";
    let started = admit(&journal, operation_id, "workload-unproved");
    assert!(started.replay.is_none(), "fresh admission is not a replay");

    let mut progress = started.progress;
    progress.stop_worker = Some(WorkerId::new("worker-unproved").expect("valid worker id"));
    journal
        .progress(operation_id, &progress)
        .expect("progress stores while pending");

    let error = journal
        .finish(
            operation_id,
            Err(KubeError::unavailable(
                "stop did not settle (verdict Indeterminate)",
            )),
        )
        .expect_err("unproved attempt propagates unavailable");
    match error {
        KubeError::Unavailable { reason } => {
            assert_eq!(reason, "stop did not settle (verdict Indeterminate)")
        }
        other => panic!("unproved attempt must propagate unavailable, got {other:?}"),
    }
    let (state, progress_json, failure_kind) = operation_row(&journal, operation_id);
    assert_eq!(state, "pending", "unproved attempt stays recoverable");
    assert!(
        progress_json
            .expect("progress retained")
            .contains("worker-unproved"),
        "causal state survives"
    );
    assert!(
        failure_kind.is_none(),
        "no durable verdict is claimed for an unproved attempt"
    );
    assert_eq!(
        latest_attempt_verdict(&journal, operation_id),
        "requested",
        "unproved attempt proves nothing"
    );
    assert!(
        journal
            .operation_outcome(operation_id)
            .expect("outcome reads")
            .is_none(),
        "unsettled operation exposes no verdict"
    );
    assert_eq!(
        journal.pending().expect("pending lists").len(),
        1,
        "recovery still owns the operation"
    );

    let error = journal
        .finish(
            operation_id,
            Err(KubeError::rejected("proved surviving workload residue")),
        )
        .expect_err("proved rejection propagates");
    assert!(matches!(error, KubeError::Rejected { .. }));
    let (state, _, failure_kind) = operation_row(&journal, operation_id);
    assert_eq!(state, "rejected");
    assert_eq!(failure_kind.as_deref(), Some("rejected"));
    assert_eq!(latest_attempt_verdict(&journal, operation_id), "rejected");
    assert!(matches!(
        journal
            .operation_outcome(operation_id)
            .expect("outcome reads"),
        Some(Err(KubeError::Rejected { .. }))
    ));
    assert!(
        journal.pending().expect("pending lists").is_empty(),
        "settled operation leaves recovery"
    );
}

#[test]
fn transient_api_errors_stay_pending_and_only_storage_settles_as_storage() {
    let (journal, _directory) = journal();
    let status = |code: u16, reason: &str| {
        KubeError::Api(kube::Error::Api(
            kube::core::Status {
                code,
                reason: reason.to_owned(),
                message: reason.to_owned(),
                ..kube::core::Status::failure(reason, reason)
            }
            .boxed(),
        ))
    };
    admit(&journal, "op-api-blip", "workload-api-blip");
    let error = journal
        .finish("op-api-blip", Err(status(503, "ServiceUnavailable")))
        .expect_err("a 503 propagates");
    assert!(matches!(error, KubeError::Api(_)), "{error:?}");
    assert_eq!(operation_row(&journal, "op-api-blip").0, "pending");

    admit(&journal, "op-connect", "workload-connect");
    let error = journal
        .finish(
            "op-connect",
            Err(KubeError::Api(kube::Error::ReadEvents(
                std::io::Error::other("connection reset"),
            ))),
        )
        .expect_err("a connection error propagates");
    assert!(matches!(error, KubeError::Api(_)), "{error:?}");
    assert_eq!(operation_row(&journal, "op-connect").0, "pending");

    admit(&journal, "op-forbidden", "workload-forbidden");
    let error = journal
        .finish("op-forbidden", Err(status(403, "Forbidden")))
        .expect_err("a definite API refusal settles");
    assert!(matches!(error, KubeError::Rejected { .. }), "{error:?}");
    let (state, _, failure_kind) = operation_row(&journal, "op-forbidden");
    assert_eq!(state, "rejected");
    assert_eq!(failure_kind.as_deref(), Some("rejected"));

    admit(&journal, "op-storage", "workload-storage");
    let error = journal
        .finish(
            "op-storage",
            Err(KubeError::Storage {
                reason: "ledger write failed".to_owned(),
            }),
        )
        .expect_err("storage failure settles");
    assert!(matches!(error, KubeError::Storage { .. }), "{error:?}");
    let (state, _, failure_kind) = operation_row(&journal, "op-storage");
    assert_eq!(state, "rejected");
    assert_eq!(failure_kind.as_deref(), Some("storage"));
}

#[test]
fn definite_verdicts_stay_terminal_and_duplicate_keys_replay() {
    let (journal, _directory) = journal();
    let operation_id = "op-definite";
    admit(&journal, operation_id, "workload-definite");

    let error = journal
        .finish(
            operation_id,
            Err(KubeError::rejected("verb rejected before any write")),
        )
        .expect_err("definite rejection propagates");
    assert!(matches!(error, KubeError::Rejected { .. }));
    assert!(
        journal.pending().expect("pending lists").is_empty(),
        "definite rejection is terminal"
    );
    assert!(matches!(
        journal
            .operation_outcome(operation_id)
            .expect("outcome reads"),
        Some(Err(KubeError::Rejected { .. }))
    ));

    let replay = admit(&journal, operation_id, "workload-definite");
    assert!(
        matches!(replay.replay, Some(Err(KubeError::Rejected { .. }))),
        "duplicate key replays the settled verdict"
    );

    let conflict = journal.begin(
        &OperationId::new(operation_id).expect("valid operation id"),
        &RunId::new("run-journal-tests").expect("valid run id"),
        KubeOperationKind::Create,
        &Digest::hash(b"different-arguments"),
        &serde_json::json!({ "workload": { "name": "workload-conflict" } }),
    );
    assert!(
        matches!(conflict, Err(KubeError::Conflict { .. })),
        "reused identity with different arguments stays a terminal conflict"
    );
    assert!(
        journal.pending().expect("pending lists").is_empty(),
        "conflicting admission writes no recovery row"
    );
}

fn launch(run: &str, image: &str) -> JobLaunch {
    JobLaunch {
        labels: KubeJobLabels {
            task_id: TaskId::new("run-journal-task").expect("valid task id"),
            run_id: RunId::new(run).expect("valid run id"),
            attempt_id: AttemptId::new("run-journal-attempt").expect("valid attempt id"),
            seat_id: SeatId::new("colin").expect("valid seat id"),
            project_id: ProjectId::new("odin").expect("valid project id"),
            lane_id: LaneId::new("journal-tests").expect("valid lane id"),
            model: "journal-test-model".to_owned(),
            budget_policy_digest: Digest::hash(b"journal-test-budget-policy"),
            container_identity: Digest::hash(image.as_bytes()),
        },
        worker_id: WorkerId::new("worker-journal-launch").expect("valid worker id"),
        staging: KubeStagingProjection {
            inputs: Vec::new(),
            resumed_from: None,
        },
        checkpoint: None,
        image: image.to_owned(),
        command: vec!["/bin/sh".to_owned(), "-c".to_owned()],
        args: vec!["echo journal-launch-law".to_owned()],
        node_selector: BTreeMap::new(),
        initial_target_node: None,
        gpu_count: 0,
        deadline_seconds: None,
        service: false,
        workload: None,
        extension: None,
        models_config: None,
        operation_id: OperationId::new("op-journal-launch").expect("valid operation id"),
        idempotency_digest: Digest::hash(b"journal-launch-attempt"),
    }
}

#[test]
fn initial_target_is_part_of_create_replay_identity() {
    let (journal, _directory) = journal();
    let mut first = launch("run-target-replay", "registry.example/one:v1");
    first.initial_target_node = Some("mini".to_owned());
    let started = journal
        .begin(
            &first.operation_id,
            &first.labels.run_id,
            KubeOperationKind::Create,
            &first.idempotency_digest,
            &first,
        )
        .expect("initial targeted request admits");
    assert!(started.replay.is_none());
    // Pending requests reject a changed target even when the operation id is fresh.

    for target in [None, Some("pc".to_owned())] {
        let mut changed = first.clone();
        changed.initial_target_node = target;
        assert!(
            matches!(
                journal.begin(
                    &changed.operation_id,
                    &changed.labels.run_id,
                    KubeOperationKind::Create,
                    &changed.idempotency_digest,
                    &changed,
                ),
                Err(KubeError::Conflict { .. })
            ),
            "same digest cannot replay a different target"
        );
        changed.operation_id = OperationId::new("op-target-alias").expect("valid operation id");
        changed.worker_id = WorkerId::new("worker-target-alias").expect("valid worker id");
        assert!(
            matches!(
                journal.begin(
                    &changed.operation_id,
                    &changed.labels.run_id,
                    KubeOperationKind::Create,
                    &changed.idempotency_digest,
                    &changed,
                ),
                Err(KubeError::Conflict { .. })
            ),
            "fresh incarnation cannot alias a different target"
        );
    }
    journal
        .finish(
            first.operation_id.as_str(),
            Err(KubeError::rejected("settled fixture verdict")),
        )
        .expect_err("fixture settles rejected");
    let replay = journal
        .begin(
            &first.operation_id,
            &first.labels.run_id,
            KubeOperationKind::Create,
            &first.idempotency_digest,
            &first,
        )
        .expect("identical target replays");
    assert!(matches!(
        replay.replay,
        Some(Err(KubeError::Rejected { .. }))
    ));
}

#[test]
fn admitted_launch_registration_is_durable_and_conflict_immutable() {
    let (journal, directory) = journal();
    let mut first = launch("run-journal-launch-law", "registry.example/one:v1");
    first.initial_target_node = Some("mini".to_owned());
    journal
        .save_launch(&first)
        .expect("first admission registers");
    assert_eq!(
        journal
            .load_launch(&first.labels.run_id)
            .expect("registered run reads")
            .expect("launch is stored"),
        first,
        "the admitted definition reads back exactly"
    );

    journal
        .save_launch(&first)
        .expect("identical re-registration is a no-op");

    let mut retargeted = first.clone();
    retargeted.initial_target_node = Some("pc".to_owned());
    assert!(
        matches!(
            journal.save_launch(&retargeted),
            Err(KubeError::Conflict { .. })
        ),
        "changing only the initial target changes the immutable run definition"
    );

    // Per-attempt ids do not change the stored profile.
    let mut incarnation = first.clone();
    incarnation.worker_id =
        WorkerId::new("worker-journal-incarnation-two").expect("valid worker id");
    incarnation.operation_id =
        OperationId::new("op-journal-incarnation-two").expect("valid operation id");
    incarnation.idempotency_digest = Digest::hash(b"journal-incarnation-two");
    journal
        .save_launch(&incarnation)
        .expect("fresh incarnation with the same definition is a no-op");
    assert_eq!(
        journal
            .load_launch(&first.labels.run_id)
            .expect("registered run reads")
            .expect("launch is stored"),
        first,
        "incarnation fields never replace the stored definition"
    );

    let conflicting = launch("run-journal-launch-law", "registry.example/two:v2");
    let error = journal
        .save_launch(&conflicting)
        .expect_err("conflicting create is rejected");
    assert!(
        matches!(error, KubeError::Conflict { .. }),
        "conflicting definition is a typed conflict, got {error:?}"
    );
    assert_eq!(
        journal
            .load_launch(&first.labels.run_id)
            .expect("registered run reads")
            .expect("launch is stored"),
        first,
        "the first admitted definition survives the conflicting create"
    );
    journal
        .save_launch(&launch(
            "run-journal-launch-other",
            "registry.example/one:v1",
        ))
        .expect("a different run still registers after a conflict");

    let path = directory.path().join("journal-tests.sqlite3");
    drop(journal);
    let reopened = Journal::new(
        Arc::new(Mutex::new(
            Ledger::open(&path).expect("reopened ledger opens"),
        )),
        "test-cluster".to_owned(),
        "test-namespace".to_owned(),
    );
    assert_eq!(
        reopened
            .load_launch(&first.labels.run_id)
            .expect("registered run reads")
            .expect("launch is stored"),
        first,
        "the admitted definition survives reopen"
    );
    reopened
        .save_launch(&first)
        .expect("identical re-registration stays a no-op after reopen");
    let error = reopened
        .save_launch(&conflicting)
        .expect_err("conflict law holds after reopen");
    assert!(
        matches!(error, KubeError::Conflict { .. }),
        "reopen keeps the conflict law, got {error:?}"
    );
}

fn recovery_action(run: &str, operation: &str, version: &str, seed: &str) -> JobAction {
    JobAction {
        run_id: RunId::new(run).expect("valid run id"),
        kind: KubeOperationKind::Restart,
        expected_resource_version: KubeResourceVersion::new(version)
            .expect("valid resource version"),
        operation_id: OperationId::new(operation).expect("valid operation id"),
        idempotency_digest: Digest::hash(seed.as_bytes()),
        target_node: None,
    }
}

fn admit_action(journal: &Journal, action: &JobAction) -> Started {
    journal
        .begin(
            &action.operation_id,
            &action.run_id,
            action.kind,
            &action.idempotency_digest,
            action,
        )
        .expect("action admits")
}

fn lookup(
    journal: &Journal,
    operation: &OperationId,
    run: &RunId,
    kind: KubeOperationKind,
    digest: &Digest,
) -> Result<Option<JobAction>, KubeError> {
    journal.admitted_action(operation, run, kind, digest)
}

#[test]
fn accepted_attempts_recover_the_exact_persisted_request() {
    let (journal, _directory) = journal();
    let original = recovery_action(
        "run-journal-recovery",
        "op-recovery-canonical",
        "1042",
        "recovery-attempt",
    );
    admit_action(&journal, &original);
    let mut alias = original.clone();
    alias.operation_id = OperationId::new("op-recovery-alias").expect("valid operation id");
    admit_action(&journal, &alias);
    for operation in [&original.operation_id, &alias.operation_id] {
        assert_eq!(
            lookup(
                &journal,
                operation,
                &original.run_id,
                original.kind,
                &original.idempotency_digest
            )
            .expect("admission lookup reads")
            .expect("accepted attempt recovers"),
            original,
            "recovery returns the stored canonical request, never the alias identity"
        );
    }
}

/// A matching digest is insufficient without an accepted attempt for the requested id.
#[test]
fn recovery_stays_scoped_to_the_admitted_owner() {
    let (journal, _directory) = journal();
    let original = recovery_action(
        "run-journal-recovery-scope",
        "op-recovery-scoped",
        "8192",
        "recovery-scope-attempt",
    );
    admit_action(&journal, &original);

    let stranger = OperationId::new("op-never-admitted").expect("valid operation id");
    assert!(
        lookup(
            &journal,
            &stranger,
            &original.run_id,
            original.kind,
            &original.idempotency_digest
        )
        .expect("admission lookup reads")
        .is_none(),
        "an unadmitted id inherits no admission from the matching tuple"
    );

    // Resource versions are preconditions, so changing one refreshes the pending operation.
    let mut versioned = original.clone();
    versioned.operation_id = OperationId::new("op-recovery-versioned").expect("valid operation id");
    versioned.expected_resource_version =
        KubeResourceVersion::new("8193").expect("valid resource version");
    let aliased = journal
        .begin(
            &versioned.operation_id,
            &versioned.run_id,
            versioned.kind,
            &versioned.idempotency_digest,
            &versioned,
        )
        .expect("version-only difference is the same operation identity");
    assert_eq!(
        aliased.operation_id.as_str(),
        original.operation_id.as_str(),
        "the version-only alias resolves to the admitted canonical operation"
    );
    assert_eq!(
        aliased.request["expected_resource_version"], "8193",
        "the pending re-drive carries the caller's fresh precondition"
    );
    assert!(
        lookup(
            &journal,
            &versioned.operation_id,
            &versioned.run_id,
            versioned.kind,
            &versioned.idempotency_digest
        )
        .expect("admission lookup reads")
        .is_some(),
        "the version-only alias shares the admitted command's admission evidence"
    );

    let other_run = RunId::new("run-journal-recovery-other").expect("valid run id");
    let error = lookup(
        &journal,
        &original.operation_id,
        &other_run,
        original.kind,
        &original.idempotency_digest,
    )
    .expect_err("wrong run must conflict, not miss");
    assert!(
        matches!(error, KubeError::Conflict { .. }),
        "mismatched scope is a typed conflict, got {error:?}"
    );
    let foreign = Journal::new(
        Arc::clone(&journal.ledger),
        "other-cluster".to_owned(),
        "other-namespace".to_owned(),
    );
    let error = foreign
        .admitted_action(
            &original.operation_id,
            &original.run_id,
            original.kind,
            &original.idempotency_digest,
        )
        .expect_err("foreign cluster must conflict, not miss");
    assert!(
        matches!(error, KubeError::Conflict { .. }),
        "foreign cluster or namespace is a typed conflict, got {error:?}"
    );
}

#[test]
fn pending_version_race_re_admits_at_the_fresh_precondition() {
    let (journal, _directory) = journal();
    let original = recovery_action(
        "run-journal-recovery-race",
        "op-recovery-raced",
        "8192",
        "recovery-race-seed",
    );
    admit_action(&journal, &original);

    let mut alias = original.clone();
    alias.operation_id = OperationId::new("op-recovery-race-alias").expect("valid operation id");
    alias.expected_resource_version =
        KubeResourceVersion::new("8193").expect("valid resource version");
    let started = admit_action(&journal, &alias);
    assert_eq!(
        started.operation_id.as_str(),
        original.operation_id.as_str(),
        "the alias re-drive targets the canonical operation"
    );
    assert_eq!(
        started.request["expected_resource_version"], "8193",
        "the pending re-drive carries the caller's fresh precondition"
    );
    assert!(
        journal
            .pending_claim(original.operation_id.as_str())
            .expect("claim read"),
        "the raced row stays pending for recovery"
    );

    let mut same_id = original.clone();
    same_id.expected_resource_version =
        KubeResourceVersion::new("8194").expect("valid resource version");
    let started = admit_action(&journal, &same_id);
    assert_eq!(
        started.request["expected_resource_version"], "8194",
        "a same-id re-presentation refreshes its own precondition"
    );

    let mut conflicting = original.clone();
    conflicting.expected_resource_version =
        KubeResourceVersion::new("8195").expect("valid resource version");
    conflicting.target_node = Some("node-rehome".to_owned());
    let error = journal
        .begin(
            &conflicting.operation_id,
            &conflicting.run_id,
            conflicting.kind,
            &conflicting.idempotency_digest,
            &conflicting,
        )
        .expect_err("a different command under the admitted identity conflicts");
    assert!(
        matches!(error, KubeError::Conflict { .. }),
        "identity reuse with different arguments is a typed conflict, got {error:?}"
    );
    assert!(
        journal
            .pending_claim(original.operation_id.as_str())
            .expect("claim read"),
        "the conflicted row stays pending and untouched"
    );

    // Settled rows retain their precondition even when a retry supplies a newer version.
    let error = journal
        .finish(
            original.operation_id.as_str(),
            Err(KubeError::rejected("proved during the race regression")),
        )
        .expect_err("proved rejection propagates");
    assert!(matches!(error, KubeError::Rejected { .. }));
    let mut settled_version = original.clone();
    settled_version.expected_resource_version =
        KubeResourceVersion::new("8196").expect("valid resource version");
    let replay = admit_action(&journal, &settled_version);
    assert!(
        matches!(replay.replay, Some(Err(KubeError::Rejected { .. }))),
        "the settled verdict replays"
    );
    assert_eq!(
        replay.request["expected_resource_version"], "8194",
        "a settled row never refreshes its stored precondition"
    );
}

#[test]
fn admission_mapping_survives_reopen() {
    let (journal, directory) = journal();
    let original = recovery_action(
        "run-journal-recovery-reopen",
        "op-recovery-reopen",
        "16384",
        "recovery-reopen-attempt",
    );
    admit_action(&journal, &original);
    let mut alias = original.clone();
    alias.operation_id = OperationId::new("op-recovery-reopen-alias").expect("valid operation id");
    admit_action(&journal, &alias);
    drop(journal);
    let reopened = Journal::new(
        Arc::new(Mutex::new(
            Ledger::open(directory.path().join("journal-tests.sqlite3"))
                .expect("reopened ledger opens"),
        )),
        "test-cluster".to_owned(),
        "test-namespace".to_owned(),
    );
    assert_eq!(
        lookup(
            &reopened,
            &original.operation_id,
            &original.run_id,
            original.kind,
            &original.idempotency_digest
        )
        .expect("admission lookup reads")
        .expect("canonical admission survives reopen"),
        original,
        "the admitted request survives reopen"
    );
    assert_eq!(
        lookup(
            &reopened,
            &alias.operation_id,
            &alias.run_id,
            alias.kind,
            &alias.idempotency_digest
        )
        .expect("admission lookup reads")
        .expect("alias mapping survives reopen"),
        original,
        "the alias keeps mapping onto the canonical request after reopen"
    );
}

/// Captures every history column that must remain unchanged across later attempts.
fn settled_history(
    journal: &Journal,
    operation: &str,
) -> (
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    String,
    String,
) {
    let ledger = journal.ledger.lock().expect("operation ledger lock");
    ledger.connection().query_row(
            "SELECT state,request_json,progress_json,failure_kind,failure_reason,created_at,updated_at \
             FROM kube_job_operations WHERE operation_id=?1",
        [operation],
        |row| {
            Ok((
                row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?,
                row.get(4)?, row.get(5)?, row.get(6)?,
            ))
        },
    ).expect("operation row exists")
}

fn latest_receipt(journal: &Journal, operation: &str) -> (String, String) {
    let ledger = journal.ledger.lock().expect("operation ledger lock");
    ledger
        .connection()
        .query_row(
            "SELECT canonical_operation_id,verdict FROM kube_job_attempts \
             WHERE operation_id=?1 ORDER BY attempt_id DESC LIMIT 1",
            [operation],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("attempt row exists")
}

#[test]
fn rejected_history_leaves_fresh_operations_their_own_attempt() {
    let (journal, _directory) = journal();
    let rejected_id = "op-rejected-history";
    admit(&journal, rejected_id, "workload-history");
    let error = journal
        .finish(
            rejected_id,
            Err(KubeError::rejected("proved rejection before any write")),
        )
        .expect_err("proved rejection propagates");
    assert!(matches!(error, KubeError::Rejected { .. }));
    let history = settled_history(&journal, rejected_id);

    let replay = admit(&journal, rejected_id, "workload-history");
    assert_eq!(
        replay.operation_id, rejected_id,
        "the exact id replays as itself"
    );
    assert!(
        matches!(replay.replay, Some(Err(KubeError::Rejected { .. }))),
        "the settled rejection replays for its own id"
    );
    assert_eq!(latest_receipt(&journal, rejected_id).1, "replayed");

    let fresh = admit(&journal, "op-history-fresh", "workload-history");
    assert_eq!(
        fresh.operation_id, "op-history-fresh",
        "the fresh id is admitted as its own operation"
    );
    assert!(
        fresh.replay.is_none(),
        "a fresh operation inherits no rejection from history"
    );
    assert_eq!(
        settled_history(&journal, rejected_id),
        history,
        "the rejected row stays byte-immutable"
    );
    let receipt = latest_receipt(&journal, "op-history-fresh");
    assert_eq!(
        receipt,
        ("op-history-fresh".to_owned(), "requested".to_owned()),
        "the fresh attempt is its own canonical operation"
    );
    assert_eq!(
        journal.pending().expect("pending lists").len(),
        1,
        "only the fresh attempt is current for the family"
    );

    let aliased = admit(&journal, "op-history-alias", "workload-history");
    assert_eq!(
        aliased.operation_id, "op-history-fresh",
        "the alias resolves to the current canonical operation"
    );
    assert_eq!(
        latest_receipt(&journal, "op-history-alias"),
        ("op-history-fresh".to_owned(), "requested".to_owned()),
        "the alias receipt keeps the canonical identity"
    );
    assert_eq!(
        journal.pending().expect("pending lists").len(),
        1,
        "the alias mints no second current row"
    );
    assert_eq!(
        settled_history(&journal, rejected_id),
        history,
        "the rejected row stays byte-immutable across the whole flow"
    );
}

#[test]
fn rejected_history_does_not_freeze_fresh_fingerprints() {
    let (journal, _directory) = journal();
    let rejected_id = "op-rejected-authority";
    admit(&journal, rejected_id, "workload-history");
    journal
        .finish(
            rejected_id,
            Err(KubeError::rejected("proved rejection before any write")),
        )
        .expect_err("proved rejection propagates");
    let history = settled_history(&journal, rejected_id);
    let digest = Digest::hash(b"workload-history");

    let divergent = journal
        .begin(
            &OperationId::new("op-history-divergent").expect("valid operation id"),
            &RunId::new("run-journal-tests").expect("valid run id"),
            KubeOperationKind::Create,
            &digest,
            &serde_json::json!({ "workload": { "name": "workload-divergent" } }),
        )
        .expect("a fresh id over rejection history admits its own arguments");
    assert_eq!(divergent.operation_id, "op-history-divergent");
    assert!(divergent.replay.is_none());

    let conflict = journal.begin(
        &OperationId::new("op-history-stranger").expect("valid operation id"),
        &RunId::new("run-journal-tests").expect("valid run id"),
        KubeOperationKind::Create,
        &digest,
        &serde_json::json!({ "workload": { "name": "workload-stranger" } }),
    );
    assert!(
        matches!(conflict, Err(KubeError::Conflict { .. })),
        "the live canonical refuses a different command"
    );
    let identical = journal
        .begin(
            &OperationId::new("op-history-twin").expect("valid operation id"),
            &RunId::new("run-journal-tests").expect("valid run id"),
            KubeOperationKind::Create,
            &digest,
            &serde_json::json!({ "workload": { "name": "workload-divergent" } }),
        )
        .expect("the same command dedupes onto the live canonical");
    assert_eq!(
        identical.operation_id, "op-history-divergent",
        "the equal-fingerprint alias dedupes onto the current operation"
    );
    assert_eq!(journal.pending().expect("pending lists").len(), 1);

    let exact = journal.begin(
        &OperationId::new(rejected_id).expect("valid operation id"),
        &RunId::new("run-journal-tests").expect("valid run id"),
        KubeOperationKind::Create,
        &digest,
        &serde_json::json!({ "workload": { "name": "workload-stranger" } }),
    );
    assert!(
        matches!(exact, Err(KubeError::Conflict { .. })),
        "a reused identity with different arguments stays a terminal conflict"
    );
    assert_eq!(
        settled_history(&journal, rejected_id),
        history,
        "the rejected row stays byte-immutable"
    );
}

/// Aliases retain their original operation even after a fresh attempt replaces a rejection.
#[test]
fn consumed_alias_ids_stay_bound_to_their_original_canonical() {
    let (journal, _directory) = journal();
    let rejected_id = "op-binding-canonical";
    admit(&journal, rejected_id, "workload-history");
    journal
        .finish(
            rejected_id,
            Err(KubeError::rejected("proved rejection before any write")),
        )
        .expect_err("proved rejection propagates");
    let (fingerprint,): (String,) = {
        let ledger = journal.ledger.lock().expect("operation ledger lock");
        ledger
            .connection()
            .query_row(
                "SELECT fingerprint FROM kube_job_operations WHERE operation_id=?1",
                [rejected_id],
                |row| Ok((row.get::<_, String>(0)?,)),
            )
            .expect("canonical row exists")
    };
    {
        // Seed an alias with an attempt record but no operation row of its own.
        let ledger = journal.ledger.lock().expect("operation ledger lock");
        ledger
            .connection()
            .execute(
                "INSERT INTO kube_job_attempts(operation_id,canonical_operation_id,\
                     request_fingerprint,verdict,reason,created_at) \
                 VALUES('op-binding-alias',?1,?2,'replayed',NULL,\
                        '2026-09-24T11:57:07.986Z')",
                params![rejected_id, fingerprint],
            )
            .expect("seed the historical alias binding");
    }

    let replayed = admit(&journal, "op-binding-alias", "workload-history");
    assert_eq!(
        replayed.operation_id, rejected_id,
        "the consumed alias resolves to its original canonical"
    );
    assert!(
        matches!(replayed.replay, Some(Err(KubeError::Rejected { .. }))),
        "the original rejection replays for the consumed alias"
    );

    let current = admit(&journal, "op-binding-current", "workload-history");
    assert_eq!(current.operation_id, "op-binding-current");
    assert!(current.replay.is_none());

    let again = admit(&journal, "op-binding-alias", "workload-history");
    assert_eq!(
        again.operation_id, rejected_id,
        "the binding outlives the newer current operation"
    );
    assert!(
        matches!(again.replay, Some(Err(KubeError::Rejected { .. }))),
        "the original rejection still replays"
    );

    // Conflicting alias mappings must be rejected without writing another attempt.
    {
        let ledger = journal.ledger.lock().expect("operation ledger lock");
        ledger
            .connection()
            .execute(
                "INSERT INTO kube_job_attempts(operation_id,canonical_operation_id,\
                     request_fingerprint,verdict,reason,created_at) \
                 VALUES('op-binding-alias','op-binding-current',?1,'requested',NULL,\
                        '2026-09-24T12:00:00.000Z')",
                params![fingerprint],
            )
            .expect("seed the conflicting binding");
    }
    let (bindings,): (i64,) = {
        let ledger = journal.ledger.lock().expect("operation ledger lock");
        ledger
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM kube_job_attempts WHERE operation_id=?1",
                ["op-binding-alias"],
                |row| Ok((row.get::<_, i64>(0)?,)),
            )
            .expect("count alias receipts")
    };
    let ambiguous = journal.begin(
        &OperationId::new("op-binding-alias").expect("valid operation id"),
        &RunId::new("run-journal-tests").expect("valid run id"),
        KubeOperationKind::Create,
        &Digest::hash(b"workload-history"),
        &serde_json::json!({ "workload": { "name": "workload-history" } }),
    );
    assert!(
        matches!(ambiguous, Err(KubeError::Conflict { .. })),
        "an identity bound to two canonical operations fails closed"
    );
    let (bindings_after,): (i64,) = {
        let ledger = journal.ledger.lock().expect("operation ledger lock");
        ledger
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM kube_job_attempts WHERE operation_id=?1",
                ["op-binding-alias"],
                |row| Ok((row.get::<_, i64>(0)?,)),
            )
            .expect("count alias receipts after refusal")
    };
    assert_eq!(
        bindings_after, bindings,
        "the refused identity writes no new receipt"
    );
    let (rows,): (i64,) = {
        let ledger = journal.ledger.lock().expect("operation ledger lock");
        ledger
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM kube_job_operations WHERE operation_id=?1",
                ["op-binding-alias"],
                |row| Ok((row.get::<_, i64>(0)?,)),
            )
            .expect("count alias rows")
    };
    assert_eq!(rows, 0, "the consumed alias never mints its own row");
}

#[test]
fn missing_bound_canonical_fails_closed() {
    let (journal, _directory) = journal();
    {
        // Disable foreign keys to seed an alias whose operation row is missing.
        let mut ledger = journal.ledger.lock().expect("operation ledger lock");
        ledger
            .connection_mut()
            .execute_batch(
                "PRAGMA foreign_keys=OFF;\
                 INSERT INTO kube_job_attempts(operation_id,canonical_operation_id,\
                     request_fingerprint,verdict,created_at) \
                 VALUES('op-orphan-alias','op-phantom-canonical','blake3:phantom-fingerprint',\
                        'replayed','2026-09-24T12:00:00.000Z');\
                 PRAGMA foreign_keys=ON;",
            )
            .expect("seed the corrupt binding");
    }
    let refused = journal
        .begin(
            &OperationId::new("op-orphan-alias").expect("valid operation id"),
            &RunId::new("run-journal-tests").expect("valid run id"),
            KubeOperationKind::Create,
            &Digest::hash(b"workload-history"),
            &serde_json::json!({ "workload": { "name": "workload-history" } }),
        )
        .expect_err("a missing bound canonical fails closed");
    assert!(
        matches!(refused, KubeError::Conflict { .. }),
        "a missing bound canonical is a typed conflict, got {refused:?}"
    );
    let (rows,): (i64,) = {
        let ledger = journal.ledger.lock().expect("operation ledger lock");
        ledger
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM kube_job_operations WHERE operation_id=?1",
                ["op-orphan-alias"],
                |row| Ok((row.get::<_, i64>(0)?,)),
            )
            .expect("count orphan alias rows")
    };
    assert_eq!(rows, 0, "the corrupted identity never mints a row");
}

/// Script pods run no agent and therefore must not carry a models document.
#[test]
fn a_script_pod_launches_without_a_models_document() {
    let mut script = launch("run-script-pod", "registry.example/cuda-sample@sha256:00");
    script.gpu_count = 1;
    script.deadline_seconds = Some(600);
    script.workload = Some(crate::workload::WorkloadPodPlan {
        profile: "gpu-vectoradd".to_owned(),
        state_mount: "/state".to_owned(),
        export_mount: "/export".to_owned(),
        export_host_folder: "/srv/odin/export".to_owned(),
        state_storage: "100Mi".to_owned(),
        state_storage_class: None,
        allow_hosts: Vec::new(),
        agent: None,
    });
    script
        .validate()
        .expect("a script pod needs no models document");

    let mut with_models = script.clone();
    with_models.models_config = Some(crate::job::JobModelsConfigLaunch {
        config_artifact: odin_domain::ArtifactId::new("artifact-models").expect("artifact id"),
        config_digest: Digest::hash(b"models").to_string(),
        credential_env: "GATEWAY_KEY".to_owned(),
    });
    let refused = with_models
        .validate()
        .expect_err("a script pod carries no models");
    assert!(refused.contains("script pod"), "{refused}");
}
