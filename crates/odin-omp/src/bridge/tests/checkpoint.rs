use super::*;

#[test]
fn committed_checkpoint_crash_window_reconstructs_exact_completion_once() {
    let mut ledger = Ledger::open_in_memory().expect("in-memory ledger");
    ledger
            .connection()
            .execute_batch(
                "INSERT INTO lanes(lane_id, seat_id, template_id, backend, status, created_by, created_at, updated_at)
                 VALUES ('lane:checkpoint-window', 'seat:test', 'template:test', 'local_omp', 'desired', 'test', '1970-01-01T00:00:00Z', '1970-01-01T00:00:00Z');
                 INSERT INTO runs(run_id, lane_id, attempt_number, status, input_hash, created_at, updated_at)
                 VALUES ('run:checkpoint-window', 'lane:checkpoint-window', 1, 'pending', 'hash', '1970-01-01T00:00:00Z', '1970-01-01T00:00:00Z');
                 INSERT INTO commands(command_id, idempotency_key, correlation_id, issuer, target_kind, target_id, capability_id, capability_version, arguments_hash, arguments_json, issued_at, expires_at)
                 VALUES ('odin-omp:cmd:1000:1-checkpoint-window', 'checkpoint-window', 'checkpoint-window', 'test', 'run', 'run:checkpoint-window', 'checkpoint', 1, 'hash', '{}', '1970-01-01T00:00:00Z', '1970-01-02T00:00:00Z');",
            )
            .expect("seed checkpoint run");
    let command_id = command_id("odin-omp:cmd:1000:1-checkpoint-window");
    let session_id = SessionId::new("session:checkpoint-window").expect("session id");
    let live = ledger
        .create_live_session(&NewLiveSession {
            session_id: session_id.clone(),
            seat_id: "seat:test".to_owned(),
            project_id: "project:test".to_owned(),
            slice_id: "slice:test".to_owned(),
            lane_id: "lane:checkpoint-window".to_owned(),
            target_node_id: "target:test".to_owned(),
            provider: "fixture".to_owned(),
            model: "fixture".to_owned(),
            title: None,
            manifest: json!({}),
            open_tab: false,
            state: "ready".to_owned(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        })
        .expect("create live session");
    ledger
        .append_live_command(&NewLiveCommand {
            command_id: command_id.clone(),
            session_id,
            expected_epoch: live.epoch,
            expected_event_head: Some(live.event_head),
            body: json!({"type": "checkpoint", "hostComposite": true}),
            issued_at: OffsetDateTime::UNIX_EPOCH,
        })
        .expect("journal incomplete checkpoint command");
    let run_id = RunId::new("run:checkpoint-window").expect("run id");
    let bytes = br#"{"session_id":"session:checkpoint-window","epoch":1,"state":{},"events":[]}"#;
    let state_digest = Digest::hash(bytes);
    let hex = digest_hex(&state_digest);
    let relative = format!("{}/{}", &hex[..2], hex);
    let root = std::env::temp_dir().join(format!(
        "odin-omp-checkpoint-window-{}-{}",
        std::process::id(),
        ARTIFACT_SEQUENCE.fetch_add(1, Ordering::Relaxed),
    ));
    write_content_addressed(&root.join(&relative), bytes).expect("write artifact");
    let artifact = ledger
        .register_artifact(ArtifactRegistration {
            bytes,
            media_type: "application/json",
            storage_path: &relative,
            retention: RetentionClass::Pinned,
            created_at: OffsetDateTime::UNIX_EPOCH,
        })
        .expect("register artifact");
    let checkpoint = ledger
        .create_checkpoint(&CheckpointSpec {
            id: CheckpointId::new("checkpoint:window").expect("checkpoint id"),
            run_id: run_id.clone(),
            command_id: Some(command_id.clone()),
            compatibility_key: CHECKPOINT_COMPATIBILITY_KEY.to_owned(),
            artifact_ref: artifact.artifact_id.clone(),
            artifact_digest: artifact.digest,
            state_digest,
            created_at: OffsetDateTime::UNIX_EPOCH,
        })
        .expect("create checkpoint");
    ledger
        .commit_checkpoint(
            &checkpoint.id,
            checkpoint.revision,
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect("commit before command completion");

    let record = load_committed_checkpoint_anchor(&ledger, &command_id, &run_id)
        .expect("anchor lookup")
        .expect("committed anchor");
    validate_checkpoint_artifact(&root, &record).expect("artifact/digest proof");
    let completion = checkpoint_completion(&record);
    assert_eq!(completion["kind"], "checkpoint");
    assert_eq!(completion["checkpoint_id"], checkpoint.id.to_string());
    assert_eq!(completion["artifact_id"], artifact.artifact_id.to_string());
    assert_eq!(completion["artifact_digest"], state_digest.to_string());
    assert_eq!(completion["state_digest"], state_digest.to_string());
    assert_eq!(
        checkpoint_completion(
            &load_committed_checkpoint_anchor(&ledger, &command_id, &run_id)
                .expect("second lookup")
                .expect("same committed anchor")
        ),
        completion,
        "recovery is deterministic and never manufactures a second effect"
    );
    let first = ledger
        .complete_live_command_once(&command_id, &completion, OffsetDateTime::UNIX_EPOCH)
        .expect("recovery completes the durable command");
    assert!(matches!(first, CompleteLiveCommand::Completed(_)));
    let second = ledger
        .complete_live_command_once(
            &command_id,
            &json!({"kind": "must-not-replace"}),
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect("duplicate reconciliation reads the first completion");
    let CompleteLiveCommand::Existing(existing) = second else {
        panic!("checkpoint completion must be once-only");
    };
    assert_eq!(existing.outcome, Some(completion.clone()));
    let _ = fs::remove_dir_all(root);
}
