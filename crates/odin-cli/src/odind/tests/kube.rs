use super::*;
use odin_domain::{CapabilityId, Digest};
use odin_kernel::{ApprovalDecision as KernelApprovalDecision, DecisionOutcome};

#[path = "../../../tests/support/browser.rs"]
mod browser_fixture;

#[test]
fn kube_admission_refuses_second_device_before_touching_first_issuer_approval() {
    let ledger = Arc::new(Mutex::new(
        Ledger::open_in_memory().expect("open in-memory ledger"),
    ));
    let issuer =
        live::DeviceId::parse("00000000-0000-4000-8000-0000000000a1").expect("first paired device");
    let other = live::DeviceId::parse("00000000-0000-4000-8000-0000000000b2")
        .expect("second paired device");
    let command = live::KubeCommand::RetryWorkload {
        command_id: odin_domain::CommandId::new("kube-command-binding").expect("command id"),
        run_id: odin_domain::RunId::new("run-kube-binding").expect("run id"),
        expected_revision: 7,
        arguments_digest: Digest::hash(b"kube-command-binding"),
    };
    let issuer_error = || live::HuginnProtocolError::Conflict {
        code: "kubeApprovalIssuer".to_owned(),
        message: "kube approval was requested by a different device".to_owned(),
    };

    // First sight from the issuer: the approval is requested with the
    // submitting device as its immutable issuer and nothing is consumed.
    let requested = match RuntimeCommandPort::admit_kube_command(&ledger, &issuer, &command)
        .expect("first sight admits a request")
    {
        KubeAdmission::Pending(approval) => approval,
        KubeAdmission::Consumed(_) => panic!("first sight must not consume"),
    };
    assert_eq!(requested.issuer, issuer.to_string());
    assert_eq!(requested.status, odin_domain::ApprovalStatus::Requested);
    assert!(requested.consumed_by_command_id.is_none());

    // The paired decision route approves the request at the exact
    // revision it was seen at, exactly like decide_approval does.
    let approved = {
        let mut ledger = ledger.lock().expect("ledger lock");
        match ApprovalGate::new(&mut ledger)
            .decide(
                &requested.approval_id,
                requested.revision,
                KernelApprovalDecision::Approve {
                    evidence_ref: Some("fixture:paired-decision".to_owned()),
                },
                &issuer.to_string(),
                OffsetDateTime::now_utc(),
            )
            .expect("paired decision approves")
        {
            DecisionOutcome::Approved(approval) => approval,
            outcome => panic!("expected an approved decision, got {outcome:?}"),
        }
    };

    // The second paired device presenting the identical command is
    // refused on issuer identity before the gate can consume anything,
    // and the stored approval is untouched.
    let error = RuntimeCommandPort::admit_kube_command(&ledger, &other, &command)
        .expect_err("second device must not consume another issuer's approval");
    assert_eq!(error, issuer_error());
    let untouched = ledger
        .lock()
        .expect("ledger lock")
        .approval(&approved.approval_id)
        .expect("approval lookup")
        .expect("approval still present");
    assert_eq!(untouched, approved);

    // The issuer consumes the decided approval exactly once; even after
    // consumption a replay from the other device stays refused on
    // identity, and the consumed record stays bound to the issuer.
    let consumed = match RuntimeCommandPort::admit_kube_command(&ledger, &issuer, &command)
        .expect("issuer consumes the decided approval")
    {
        KubeAdmission::Consumed(approval) => approval,
        KubeAdmission::Pending(_) => panic!("a decided approval must consume"),
    };
    assert_eq!(
        consumed.consumed_by_command_id.as_ref(),
        Some(command.command_id())
    );

    // The consumption names a durably journaled command row: recorded
    // through the canonical kube spec before the approval could
    // reference it, bound to the exact id, approval, issuer, target,
    // arguments, and expected revision.
    let journaled = ledger
        .lock()
        .expect("ledger lock")
        .command(command.command_id())
        .expect("command lookup")
        .expect("the consumed approval names a journaled command");
    assert_eq!(&journaled.id, command.command_id());
    assert_eq!(journaled.approval_id.as_ref(), Some(&approved.approval_id));
    assert_eq!(journaled.issuer, "odin.huginn.kube");
    assert_eq!(journaled.target_kind, "kubeWorkload");
    assert_eq!(journaled.target_id, command.run_id().to_string());
    assert_eq!(journaled.arguments_hash, approved.scope.arguments_digest);
    assert_eq!(
        journaled.arguments,
        serde_json::to_value(&command).expect("kube command serializes")
    );
    assert_eq!(journaled.expected_desired_revision, Some(7));
    let error = RuntimeCommandPort::admit_kube_command(&ledger, &other, &command)
        .expect_err("consumed replay from another issuer must stay refused");
    assert_eq!(error, issuer_error());
    let after = ledger
        .lock()
        .expect("ledger lock")
        .approval(&consumed.approval_id)
        .expect("approval lookup")
        .expect("approval still present");
    assert_eq!(after, consumed);

    // Exact replay by the same issuer continues the already admitted
    // command: the stored consumption is returned untouched — no
    // re-consumption, no revision drift, no new authority.
    let replay = match RuntimeCommandPort::admit_kube_command(&ledger, &issuer, &command)
        .expect("exact same-issuer replay is accepted")
    {
        KubeAdmission::Consumed(approval) => approval,
        KubeAdmission::Pending(_) => panic!("a consumed approval must not reopen"),
    };
    assert_eq!(replay, consumed);

    // The same command id presenting changed payload derives a
    // different exact scope and stays denied on the existing redirect
    // path; the stored consumption remains untouched.
    let mutated = live::KubeCommand::RetryWorkload {
        command_id: odin_domain::CommandId::new("kube-command-binding").expect("command id"),
        run_id: odin_domain::RunId::new("run-kube-binding").expect("run id"),
        expected_revision: 8,
        arguments_digest: Digest::hash(b"kube-command-binding-v2"),
    };
    let error = RuntimeCommandPort::admit_kube_command(&ledger, &issuer, &mutated)
        .expect_err("changed payload under the same command id stays denied");
    assert_eq!(
        error,
        live::HuginnProtocolError::Conflict {
            code: "kubeApprovalRedirect".to_owned(),
            message: "kube approval did not authorize this command binding".to_owned(),
        }
    );
    let stable = ledger
        .lock()
        .expect("ledger lock")
        .approval(&consumed.approval_id)
        .expect("approval lookup")
        .expect("approval still present");
    assert_eq!(stable, consumed);

    // The denied mutated attempt journaled nothing new and overwrote
    // nothing: the durable row keeps the exact admitted binding.
    let stable_command = ledger
        .lock()
        .expect("ledger lock")
        .command(command.command_id())
        .expect("command lookup")
        .expect("journaled command still present");
    assert_eq!(stable_command, journaled);
}

/// Device authentication cannot replace delivery of the full consequential preview.
#[tokio::test]
async fn huginn_decision_cannot_settle_an_undelivered_consequential_owner_question() {
    let root = tempfile::tempdir().expect("tempdir");
    let ledger = Arc::new(Mutex::new(Ledger::open_in_memory().expect("ledger")));
    let replay = odin_huginn::streams::DurableReplayStore::open(
        root.path().join("replay.sqlite3"),
        256,
        1 << 20,
    )
    .expect("replay store");
    // Production derives this set from capabilities that declare a preview.
    // Without it the route treats task.grant and email.send as ordinary
    // approvals and settles them before any question is delivered.
    let port = RuntimeCommandPort::new(
        Arc::clone(&ledger),
        Arc::new(odin_huginn::read_model::MaterializedReadModel::with_limits(
            1024,
            2048,
            OffsetDateTime::now_utc(),
        )),
        None,
        Arc::new(odin_huginn::streams::BoundedMultiplexer::new(
            replay, 64, 64,
        )),
        None,
        live::StreamBackpressureLimits {
            max_buffered_items: std::num::NonZeroU32::new(64).unwrap(),
            max_buffered_bytes: NonZeroU64::new(64 << 20).unwrap(),
            max_item_bytes: NonZeroU64::new(1 << 20).unwrap(),
            max_items_per_second: std::num::NonZeroU32::new(256).unwrap(),
            max_in_flight_bytes: NonZeroU64::new(64 << 20).unwrap(),
        },
    )
    .with_owner_preview(
        ["email.send", "task.grant"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
    );
    let device = live::DeviceId::parse("00000000-0000-4000-8000-0000000000a1").expect("device");
    let approve = |approval: &Approval, command: &str| {
        live::HuginnRequest::ApprovalDecision(live::ApprovalDecisionCommand {
            command_id: odin_domain::CommandId::new(command).expect("command id"),
            approval_id: approval.approval_id.clone(),
            expected_revision: u64::try_from(approval.revision).expect("revision"),
            decision: live::ApprovalDecision::Approve,
        })
    };
    for capability in ["task.grant", "email.send"] {
        let now = OffsetDateTime::now_utc();
        let requested = ledger
            .lock()
            .expect("ledger lock")
            .request_approval(NewApproval {
                approval_id: ApprovalId::new(format!("approval:undelivered:{capability}"))
                    .expect("approval id"),
                issuer: "atlas".to_owned(),
                scope: ApprovalScope {
                    target_kind: "run".to_owned(),
                    target_id: "run:live:undelivered".to_owned(),
                    capability_id: CapabilityId::new(capability).expect("capability"),
                    arguments_digest: Digest::hash(capability.as_bytes()),
                },
                requested_at: now,
                expires_at: now + time::Duration::hours(1),
            })
            .expect("undelivered owner question");
        let decided = port
            .execute_authenticated(device, approve(&requested, &format!("huginn-{capability}")))
            .await;
        assert!(
            decided.is_err(),
            "{capability} settled undelivered: {decided:?}"
        );
        let guard = ledger.lock().expect("ledger lock");
        let stored = guard
            .approval(&requested.approval_id)
            .expect("approval lookup")
            .expect("approval present");
        assert_eq!(stored.status, odin_domain::ApprovalStatus::Requested);
        assert!(!guard
            .approval_has_owner_decision(&stored, true)
            .expect("witness"));
    }

    // The same pending batch question once Hermes recorded its delivery: a
    // clipped copy still refuses; the complete one lets the SAME command and
    // intake identity decide it, and no further owner question is minted.
    let pending = ledger
        .lock()
        .expect("ledger lock")
        .approval(&ApprovalId::new("approval:undelivered:task.grant").expect("id"))
        .expect("approval lookup")
        .expect("pending question");
    for (event, complete) in [
        ("event:clipped-batch", false),
        ("event:complete-batch", true),
    ] {
        let payload = serde_json::json!({
            "approvalId": pending.approval_id.as_str(), "revision": pending.revision,
            "capabilityId": "task.grant", "session": pending.scope.target_id,
            "argumentsDigest": pending.scope.arguments_digest.to_string(),
            "completeSnapshot": complete,
        });
        ledger
            .lock()
            .expect("ledger lock")
            .append_audit_event(odin_ledger::audit::NewAuditEvent {
                event_id: odin_domain::EventId::new(event).expect("event id"),
                kind: odin_ledger::approval::OWNER_PREVIEW_DELIVERY_KIND.to_owned(),
                actor: odin_domain::Actor::System {
                    name: "odin-hermes.runtime".to_owned(),
                },
                scope: odin_domain::Scope::default(),
                evidence: Vec::new(),
                payload: odin_ledger::audit::RedactedPayload::new(
                    payload,
                    odin_domain::Redaction::None,
                )
                .expect("payload"),
                occurred_at: OffsetDateTime::now_utc(),
            })
            .expect("delivery proof");
        let decided = port
            .execute_authenticated(device, approve(&pending, "huginn-task.grant"))
            .await;
        assert_eq!(decided.is_ok(), complete, "{event}: {decided:?}");
    }
    {
        let guard = ledger.lock().expect("ledger lock");
        let decided = guard
            .approval(&pending.approval_id)
            .expect("approval lookup")
            .expect("approval present");
        assert_eq!(decided.status, odin_domain::ApprovalStatus::Approved);
        assert!(guard
            .approval_has_owner_decision(&decided, true)
            .expect("witness"));
        assert_eq!(guard.approvals().expect("approvals").len(), 2);
    }

    // Control: the device's own kube approval still settles on this route.
    let command = live::KubeCommand::RetryWorkload {
        command_id: odin_domain::CommandId::new("kube-huginn-control").expect("command id"),
        run_id: odin_domain::RunId::new("run-kube-huginn-control").expect("run id"),
        expected_revision: 3,
        arguments_digest: Digest::hash(b"kube-huginn-control"),
    };
    let KubeAdmission::Pending(kube) =
        RuntimeCommandPort::admit_kube_command(&ledger, &device, &command)
            .expect("kube admission requests")
    else {
        panic!("first sight must not consume");
    };
    port.execute_authenticated(device, approve(&kube, "huginn-kube-control"))
        .await
        .expect("the device decides its own kube approval");
    assert_eq!(
        ledger
            .lock()
            .expect("ledger lock")
            .approval(&kube.approval_id)
            .expect("approval lookup")
            .expect("approval present")
            .status,
        odin_domain::ApprovalStatus::Approved
    );
}

/// A configured live plane is not a fallback for missing paired authority.
/// Exercise the production command-plane wrapper as well as its runtime port:
/// neither boundary may turn an unauthenticated open into an internal open.
#[tokio::test]
async fn session_open_requires_identity_and_device_authority_even_with_a_live_plane() {
    use live::HuginnCommandPort as _;
    use odin_huginn::service::HuginnCommandPlane;
    use odin_huginn::streams::{BoundedMultiplexer, DurableReplayStore};

    let fixture = crate::live::hermes_routes::tests::gate_fixture().await;
    let replay = DurableReplayStore::open(
        fixture
            .config
            .paths
            .state_root
            .join("routing-replay.sqlite3"),
        256,
        1 << 20,
    )
    .expect("replay store");
    let limits = live::StreamBackpressureLimits {
        max_buffered_items: std::num::NonZeroU32::new(64).unwrap(),
        max_buffered_bytes: NonZeroU64::new(64 << 20).unwrap(),
        max_item_bytes: NonZeroU64::new(1 << 20).unwrap(),
        max_items_per_second: std::num::NonZeroU32::new(256).unwrap(),
        max_in_flight_bytes: NonZeroU64::new(64 << 20).unwrap(),
    };
    let port = Arc::new(
        RuntimeCommandPort::new(
            Arc::new(Mutex::new(Ledger::open_in_memory().expect("ledger"))),
            Arc::clone(&fixture.read_model),
            None,
            Arc::new(BoundedMultiplexer::new(replay, 64, 64)),
            None,
            limits,
        )
        .with_live(fixture.omp.clone()),
    );
    let plane = HuginnCommandPlane::new(Arc::clone(&port), fixture.omp.clone());
    let seat = &fixture.config.seats[0];
    let option = &seat.launch_options[0];
    let request = live::HuginnRequest::OpenSession(live::OpenSessionRequest {
        command_id: odin_domain::CommandId::new("routing-open").unwrap(),
        seat_id: seat.seat.clone(),
        project_id: fixture
            .config
            .lane_bindings
            .iter()
            .find(|binding| binding.seat == seat.seat)
            .expect("seat project")
            .project
            .clone(),
        slice_id: seat.slice.clone(),
        provider: option.provider.clone(),
        model: option.model.clone(),
        title: None,
        target_node: odin_domain::NodeId::new(&fixture.config.identity.node).unwrap(),
        open_tab: false,
        initial_prompt: None,
        workload: None,
        served_revision: None,
    });
    let device = live::DeviceId::parse("00000000-0000-4000-8000-0000000000a1").expect("device id");
    assert_eq!(
        port.execute(request.clone())
            .await
            .expect_err("identity required"),
        live::HuginnProtocolError::Unauthenticated,
    );
    assert_eq!(
        plane
            .execute(request.clone())
            .await
            .expect_err("identity required"),
        live::HuginnProtocolError::Unauthenticated,
    );
    assert_eq!(
        port.execute_authenticated(device, request.clone())
            .await
            .expect_err("no paired authority"),
        unavailable("deviceSessionAuthority"),
    );
    assert_eq!(
        plane
            .execute_authenticated(device, request)
            .await
            .expect_err("wrapper must not bypass paired authority"),
        unavailable("deviceSessionAuthority"),
    );
}

/// The continuation turn an approved conversation question owes: one per
/// durable decision, never one per device attempt.
const APPROVED_CONTINUATION: &str = "[host] The owner approved your request";

/// One question the conversation's vehicle asked and the owner's
/// conversation durably received, decided from a paired device through the
/// production command port. The serving stack is the mismatch-recovery one
/// (real plane, real root, loopback model harness); the port and the root's
/// approvals are separate connections to the SAME file-backed ledger.
struct ConversationQuestion {
    fixture: crate::mismatch_recovery_tests::GenerationFixture,
    ledger: Arc<Mutex<Ledger>>,
    port: RuntimeCommandPort,
    approval: Approval,
    device: live::DeviceId,
    browser: odin_huginn::browser::BrowserProjection,
}

impl ConversationQuestion {
    fn approve(&self, command: &str) -> live::HuginnRequest {
        live::HuginnRequest::ApprovalDecision(live::ApprovalDecisionCommand {
            command_id: odin_domain::CommandId::new(command).expect("command id"),
            approval_id: self.approval.approval_id.clone(),
            expected_revision: u64::try_from(self.approval.revision).expect("revision"),
            decision: live::ApprovalDecision::Approve,
        })
    }

    fn port_ledger(&self) -> Result<std::sync::MutexGuard<'_, Ledger>, String> {
        self.ledger
            .lock()
            .map_err(|_| "the port ledger lock is poisoned".to_owned())
    }

    /// The durable row and whether it carries an owner decision witness.
    fn stored(&self) -> Result<(Approval, bool), String> {
        let guard = self.port_ledger()?;
        let stored = guard
            .approval(&self.approval.approval_id)
            .map_err(|error| error.to_string())?
            .ok_or("the approval row is missing")?;
        let witnessed = guard
            .approval_has_owner_decision(&stored, false)
            .map_err(|error| error.to_string())?;
        Ok((stored, witnessed))
    }

    fn journaled(&self, command: &str) -> Result<bool, String> {
        let command = odin_domain::CommandId::new(command).map_err(|error| error.to_string())?;
        Ok(self
            .port_ledger()?
            .command(&command)
            .map_err(|error| error.to_string())?
            .is_some())
    }

    fn port_sql(&self, sql: &str) -> Result<(), String> {
        self.port_ledger()?
            .connection()
            .execute_batch(sql)
            .map_err(|error| error.to_string())
    }

    fn planned_wakes(&self) -> usize {
        let record: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&self.fixture.record_path).expect("retained record"),
        )
        .expect("retained record parses");
        record["wakes"].as_array().map_or(0, Vec::len)
    }

    fn answered(&self) -> Result<usize, String> {
        Ok(self
            .fixture
            .probe
            .delivered
            .lock()
            .map_err(|_| "the delivery log lock is poisoned".to_owned())?
            .iter()
            .filter(|message| {
                message
                    .content
                    .contains(crate::mismatch_recovery_tests::OPEN_ACK)
            })
            .count())
    }
}

async fn conversation_question(name: &str) -> ConversationQuestion {
    let fixture = crate::mismatch_recovery_tests::stage_row(false, None, None).await;
    fixture
        .root
        .initialize()
        .await
        .expect("the vehicle recovers in place");
    let now = OffsetDateTime::now_utc();
    let authority = Arc::new(parking_lot::Mutex::new(
        Ledger::open(&fixture.gate.ledger_path).expect("authority ledger"),
    ));
    let approval = {
        let mut guard = authority.lock();
        // Delivery rechecks the requesting vehicle's live row.
        odin_ledger::lane_run::create_lane(
            guard.connection(),
            &odin_ledger::lane_run::NewLane {
                lane_id: odin_domain::LaneId::new("a3-vehicle").expect("lane id"),
                seat_id: odin_domain::SeatId::new("coordinator").expect("seat id"),
                project_id: Some(odin_domain::ProjectId::new("research").expect("project id")),
                template_id: "default".to_owned(),
                backend: "local_omp".to_owned(),
                created_by: "live-session".to_owned(),
                created_at: now,
                retained: false,
            },
        )
        .expect("vehicle lane");
        guard
            .create_live_session(&odin_ledger::live::NewLiveSession {
                session_id: odin_domain::SessionId::new(fixture.session.to_string())
                    .expect("session id"),
                seat_id: "coordinator".to_owned(),
                project_id: "research".to_owned(),
                slice_id: "coordinator-work".to_owned(),
                lane_id: "a3-vehicle".to_owned(),
                target_node_id: String::new(),
                provider: "gateway".to_owned(),
                model: "zai-glm".to_owned(),
                title: None,
                manifest: serde_json::json!({}),
                open_tab: false,
                state: "ready".to_owned(),
                created_at: now,
            })
            .expect("vehicle row");
        guard
            .request_approval(NewApproval {
                approval_id: ApprovalId::new(format!("approval:r3:coord.assist:{name}"))
                    .expect("approval id"),
                issuer: "coordinator".to_owned(),
                scope: ApprovalScope {
                    target_kind: "run".to_owned(),
                    target_id: format!("run:live:{}", fixture.session),
                    capability_id: CapabilityId::new("coord.assist").expect("capability"),
                    arguments_digest: Digest::hash(name.as_bytes()),
                },
                requested_at: now,
                expires_at: now + time::Duration::hours(1),
            })
            .expect("the vehicle asks")
    };
    let discord = fixture
        .gate
        .runtime
        .settings()
        .discord
        .clone()
        .expect("declared transport");
    fixture
        .gate
        .runtime
        .deliver_approval_question(
            &authority,
            &approval.approval_id,
            &discord.notify_channel_id,
            &discord.owner_user_id,
            now,
            None,
        )
        .expect("the question reaches the owner's conversation");
    let ledger = Arc::new(Mutex::new(
        Ledger::open(&fixture.gate.ledger_path).expect("port ledger"),
    ));
    let replay = odin_huginn::streams::DurableReplayStore::open(
        fixture.gate._root.path().join("decision-replay.sqlite3"),
        256,
        1 << 20,
    )
    .expect("replay store");
    let surface = crate::conversation_surface::ConversationSurface::new(
        Arc::clone(&fixture.gate.runtime),
        Arc::clone(&fixture.root),
        Arc::new(odin_huginn::devices::SqliteDeviceTrustStore::open_in_memory().expect("devices")),
    )
    .expect("the conversation surface composes");
    let browser_root = fixture.gate._root.path().join("decision-browser");
    std::fs::create_dir(&browser_root).expect("browser fixture directory");
    let (browser, coordinator) = browser_fixture::open_browser(
        &browser_root,
        Arc::clone(&ledger),
        Arc::new(Mutex::new(Vec::new())),
        Arc::clone(&fixture.gate.read_model),
    )
    .await;
    let port = RuntimeCommandPort::new(
        Arc::clone(&ledger),
        Arc::clone(&fixture.gate.read_model),
        Some(Arc::new(odin_cli::browser_runtime::BrowserRoutes::new(
            Some(coordinator),
            None,
        ))),
        Arc::new(odin_huginn::streams::BoundedMultiplexer::new(
            replay, 64, 64,
        )),
        None,
        live::StreamBackpressureLimits {
            max_buffered_items: std::num::NonZeroU32::new(64).unwrap(),
            max_buffered_bytes: NonZeroU64::new(64 << 20).unwrap(),
            max_item_bytes: NonZeroU64::new(1 << 20).unwrap(),
            max_items_per_second: std::num::NonZeroU32::new(256).unwrap(),
            max_in_flight_bytes: NonZeroU64::new(64 << 20).unwrap(),
        },
    )
    .with_conversation(Some(Arc::new(surface)));
    ConversationQuestion {
        fixture,
        ledger,
        port,
        approval,
        browser,
        device: live::DeviceId::parse("00000000-0000-4000-8000-0000000000a3").expect("device"),
    }
}

/// A durable decision must resume the conversation even if command completion fails.
#[tokio::test]
async fn a_huginn_decision_whose_completion_fails_still_resumes_the_conversation_once(
) -> Result<(), String> {
    let question = conversation_question("completion").await;
    let answered_before = question.answered()?;
    question.port_sql(
        "CREATE TEMP TRIGGER fixture_completion_outage BEFORE UPDATE OF terminal_status
         ON commands WHEN OLD.command_id = 'huginn-a3-completion'
         BEGIN SELECT RAISE(ABORT, 'fixture completion outage'); END;",
    )?;
    let failed = question
        .port
        .execute_authenticated(question.device, question.approve("huginn-a3-completion"))
        .await;
    assert!(failed.is_err(), "the completion fault surfaces: {failed:?}");
    let (stored, witnessed) = question.stored()?;
    assert_eq!(stored.status, odin_domain::ApprovalStatus::Approved);
    assert_eq!(
        stored.decided_by.as_deref(),
        Some(question.device.to_string().as_str())
    );
    assert!(witnessed, "the owner decision witness stays recorded");

    // The device retries the SAME command once storage is back: it replays
    // the journaled command and decides nothing new.
    question.port_sql("DROP TRIGGER temp.fixture_completion_outage")?;
    let replay = question
        .port
        .execute_authenticated(question.device, question.approve("huginn-a3-completion"))
        .await
        .expect("the same command replays");
    assert!(
        matches!(
            replay,
            live::HuginnResponse::Command(live::CommandReceipt::Duplicate { .. })
        ),
        "{replay:?}"
    );

    question
        .fixture
        .root
        .join_background(StdDuration::from_secs(30))
        .await;
    assert_eq!(
        question.fixture.probe.prompt_count(APPROVED_CONTINUATION),
        1,
        "exactly one continuation turn: {:?}",
        question.fixture.probe.prompts()
    );
    assert_eq!(
        question.answered()? - answered_before,
        1,
        "the continuation's answer reached the owner once"
    );
    assert_eq!(question.planned_wakes(), 0, "the continuation settled");
    question
        .browser
        .shutdown()
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

/// Procfs permits reads but prevents staging beside the record, even when running as root.
#[tokio::test]
async fn a_huginn_decision_the_conversation_cannot_own_is_refused_until_it_can(
) -> Result<(), String> {
    use std::os::fd::AsRawFd as _;

    let mut question = conversation_question("unowned").await;
    let before = std::fs::read(&question.fixture.record_path).map_err(|error| error.to_string())?;
    let record =
        std::fs::File::open(&question.fixture.record_path).map_err(|error| error.to_string())?;
    let serving = crate::mismatch_recovery_tests::compose_serving_with(
        &question.fixture.gate,
        Arc::new(crate::mismatch_recovery_tests::BoundaryLauncher::new(
            question.fixture.probe.clone(),
        )),
        question.fixture.ledger.clone(),
        question.fixture.capsules.clone(),
    )
    .await;
    let read_only = crate::mismatch_recovery_tests::compose_root_at(
        &question.fixture.gate,
        &serving.plane,
        std::path::PathBuf::from(format!("/proc/self/fd/{}", record.as_raw_fd())),
    );
    let surface = crate::conversation_surface::ConversationSurface::new(
        Arc::clone(&question.fixture.gate.runtime),
        read_only,
        Arc::new(
            odin_huginn::devices::SqliteDeviceTrustStore::open_in_memory()
                .map_err(|error| error.to_string())?,
        ),
    )?;
    let writable = question.port.conversation.replace(Arc::new(surface));
    let refused = question
        .port
        .execute_authenticated(question.device, question.approve("huginn-a3-unowned"))
        .await;
    question.port.conversation = writable;
    // No permission mutation needs restoration on errors or unwinding; the
    // file descriptor's ordinary RAII lifetime owns the read-only view.
    assert_eq!(
        std::fs::read(&question.fixture.record_path).map_err(|error| error.to_string())?,
        before
    );
    assert!(
        refused.is_err(),
        "an unowned decision must not land: {refused:?}"
    );
    let (stored, witnessed) = question.stored()?;
    assert_eq!(stored.status, odin_domain::ApprovalStatus::Requested);
    assert!(!witnessed, "no owner decision witness");
    assert!(
        !question.journaled("huginn-a3-unowned")?,
        "nothing journaled, so no intake was consumed"
    );

    question
        .port
        .execute_authenticated(question.device, question.approve("huginn-a3-unowned"))
        .await
        .expect("the same command decides once the conversation can own it");
    let (stored, witnessed) = question.stored()?;
    assert_eq!(stored.status, odin_domain::ApprovalStatus::Approved);
    assert!(witnessed);
    question
        .fixture
        .root
        .join_background(StdDuration::from_secs(30))
        .await;
    assert_eq!(
        question.fixture.probe.prompt_count(APPROVED_CONTINUATION),
        1,
        "exactly one continuation turn: {:?}",
        question.fixture.probe.prompts()
    );
    assert_eq!(question.planned_wakes(), 0, "the continuation settled");
    question
        .browser
        .shutdown()
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

/// A stale paired-device decision is refused before its approval commit.
/// Its owned tracker must settle Requested, not leave a plan that blocks
/// queued owner messages or is rebound without an owner at rollover.
#[tokio::test]
async fn a_refused_huginn_decision_leaves_no_continuation_to_rebind() -> Result<(), String> {
    let question = conversation_question("stale").await;
    let before = question.answered()?;
    let mut request = question.approve("huginn-a3-stale");
    let live::HuginnRequest::ApprovalDecision(command) = &mut request else {
        unreachable!("the fixture builds an approval decision");
    };
    command.expected_revision += 1;
    let refused = question
        .port
        .execute_authenticated(question.device, request)
        .await;
    assert!(
        refused.is_err(),
        "the stale revision must not decide: {refused:?}"
    );
    question
        .fixture
        .root
        .join_background(StdDuration::from_secs(30))
        .await;
    let (stored, witnessed) = question.stored()?;
    assert_eq!(stored, question.approval);
    assert!(!witnessed);
    assert_eq!(
        question.planned_wakes(),
        0,
        "no orphan for rollover to rebind"
    );
    assert_eq!(
        question.fixture.probe.prompt_count(APPROVED_CONTINUATION),
        0
    );
    assert_eq!(question.answered()?, before);
    question
        .browser
        .shutdown()
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}
