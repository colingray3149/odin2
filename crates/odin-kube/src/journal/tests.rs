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

fn launch(run: &str, image: &str) -> JobLaunch {
    JobLaunch {
        label: None,
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
        budget_lane: None,
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
        admitted_node: None,
        campaign_reservation: None,
        gpu_count: 0,
        gpu_min_vram_gib: None,
        gpu_vram_gib: None,
        tolerate: Default::default(),
        deadline_seconds: None,
        service: false,
        workload: None,
        extension: None,
        models_config: None,
        continue_from: None,
        operation_id: OperationId::new("op-journal-launch").expect("valid operation id"),
        idempotency_digest: Digest::hash(b"journal-launch-attempt"),
    }
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
    action_of(run, operation, version, seed, KubeOperationKind::Restart)
}

fn action_of(
    run: &str,
    operation: &str,
    version: &str,
    seed: &str,
    kind: KubeOperationKind,
) -> JobAction {
    JobAction {
        run_id: RunId::new(run).expect("valid run id"),
        kind,
        expected_resource_version: KubeResourceVersion::new(version)
            .expect("valid resource version"),
        operation_id: OperationId::new(operation).expect("valid operation id"),
        idempotency_digest: Digest::hash(seed.as_bytes()),
        target_node: None,
    }
}

/// Settles an admitted operation through the ledger's own settlement write,
/// the way an applied outcome lands in production, without rebuilding a full
/// observation here.
fn settle_applied(journal: &Journal, operation: &str) {
    let mut ledger = journal.ledger.lock().expect("operation ledger lock");
    ledger
        .with_tx(|tx| {
            StoredJournal(tx).finish(
                operation,
                &Settlement {
                    state: "applied",
                    result: Some("{}"),
                    failure_kind: None,
                    failure_reason: None,
                },
                "2026-11-06T10:00:00.000Z",
            )
        })
        .expect("applied settlement writes");
}

/// A run the authority cancelled was withdrawn, not lost: only an applied
/// cancel for that run, in this journal's scope, says so.
#[test]
fn run_cancelled_reads_only_applied_cancels_for_the_run() {
    let (journal, _directory) = journal();
    let run = RunId::new("run-journal-cancelled").expect("valid run id");
    let cancel = action_of(
        run.as_str(),
        "op-cancel-applied",
        "8192",
        "cancel-applied-seed",
        KubeOperationKind::Cancel,
    );
    admit_action(&journal, &cancel);
    assert!(
        !journal
            .run_cancelled(&run)
            .expect("a still-pending cancel does not count"),
        "the Job may still exist while the cancel is pending"
    );

    settle_applied(&journal, "op-cancel-applied");
    assert!(journal
        .run_cancelled(&run)
        .expect("an applied cancel counts"));

    let other = RunId::new("run-journal-other").expect("valid run id");
    assert!(
        !journal.run_cancelled(&other).expect("another run reads"),
        "cancels stay scoped to their run"
    );

    let created = action_of(
        "run-journal-created",
        "op-create-applied",
        "8192",
        "create-applied-seed",
        KubeOperationKind::Create,
    );
    admit_action(&journal, &created);
    settle_applied(&journal, "op-create-applied");
    let created_run = RunId::new("run-journal-created").expect("valid run id");
    assert!(
        !journal
            .run_cancelled(&created_run)
            .expect("an applied create reads"),
        "an applied create is not a cancellation"
    );

    let foreign = Journal::new(
        Arc::clone(&journal.ledger),
        "other-cluster".to_owned(),
        "other-namespace".to_owned(),
    );
    assert!(
        !foreign.run_cancelled(&run).expect("a foreign scope reads"),
        "a cancel in another cluster or namespace does not travel"
    );
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
