//! Connected registry publication, runtime binding, authority, context, approval delivery, and durable effect test.
//!
//! Uses production registry validation, kernel tokens, brain compilation, ledgers, Discord transport,
//! and confined writes. Bridge behavior and actor replies are scripted; Discord uses a loopback server.
//! Decisions use the delivered-approval API, not whole-message parsing. Full dispatch is tested separately.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use odin_brain::config::EffectiveBrainPolicy;
use odin_brain::context::PinnedTokenizer;
use odin_brain::service::{BrainService, BrainServiceConfig};
use odin_domain::huginn::{
    CommandReceipt, CommandRejection, EventSeq, HistoryPage, HistoryQuery, LiveCommand,
    LiveCommandBody, LiveContentBlock, LiveError, LiveEventBody, LiveLaunchOption, LiveMessage,
    LiveSessionId, LiveSessionState, LiveSessionSummary, ModelName, OpenSessionRequest,
    ProviderName, SessionEpoch, SessionListPage, SessionListQuery, SessionManifest, TerminalSeq,
};
use odin_domain::knowledge::retrieval::ModelDescriptor;
use odin_domain::knowledge::ToolSchema;
use odin_domain::{
    ApprovalId, ApprovalStatus, CommandId, ContainerId, Digest, EventId, LaneId, NodeId, PlanId,
    ProjectId, RunId, SeatId, SessionId, SliceId,
};
use odin_hermes::config::{DiscordSettings, HermesSettings};
use odin_hermes::conversation::{
    ConversationAuthority, ConversationEgress, ConversationPlane, ConversationRoot,
    ConversationRootConfig, DaemonKernelApprovals, KernelApprovals as _, OwnerSurface,
};
use odin_hermes::discord::{DiscordCredential, DiscordMessage, DiscordRestTransport, SecretToken};
use odin_hermes::egress::DiscordEgressSink;
use odin_hermes::natural::OwnerDecision;
use odin_hermes::runtime::{
    ApprovedIntentRoute, AuthenticatedOwnerMessage, ConversationOwnership, HermesLedgers,
    HermesRuntime, IntakeAuthorityFacts, OwnerDecisionRoute, APPROVAL_DELIVERY_AUDIT_KIND,
};
use odin_kernel::capability::{InvocationTarget, ToolInvocation};
use odin_kernel::policy::{
    authorize, AuthorizationEnvironment, AuthorizationOutcome, PlanGate, PolicyContext,
};
use odin_kernel::token::{
    ExpectedBindings, FreshAuthority, LedgerRevocations, MemoryRevocations, MintRequest,
    TokenIssuer,
};
use odin_kernel::{
    list_capabilities, ApprovalGate, CapabilityContract, KernelError, RevocationStore as _,
    SchemaCatalog,
};
use odin_ledger::approval::{ApprovalDecision, ApprovalScope, DecisionIntake, NewApproval};
use odin_ledger::command::{CommandOutcome, CommandSpec, CommandTerminalStatus};
use odin_ledger::lane_run::{create_lane, create_run, read_lane, read_run, NewLane, NewRun};
use odin_ledger::live::NewLiveSession;
use odin_ledger::{Ledger, LedgerError};
use odin_omp::host_tools::operations::context_policy_digest;
use odin_omp::live::ledger::fs::FsLiveLedger;
use odin_omp::live::ledger::{live_error, LiveLedger, NewLiveEvent};
use odin_omp::live::supervisor::{session_id_for, LiveSeatBinding};
use odin_registry::schema::{ObjectConfig, RegistryKind};
use odin_registry::{
    parse_objects, validate_relations, walk, RegistryObject, RelationContext, SnapshotHandle,
    SnapshotStore, ValidatedSnapshotCandidate,
};
use parking_lot::Mutex;
use serde_json::{json, Value};
use time::OffsetDateTime;

/// Bounded stage tracing for the long integration path: one line per
/// handoff, so a stalled link names itself instead of a bare timeout.
fn stage(name: &str) {
    eprintln!("[integrated-path] {name}");
}

#[tokio::test]
async fn declared_publish_reaches_a_confined_effect_and_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();

    // Links 1-2: publish, then compose the runtime over EXACTLY the
    // published authority. A binding the snapshot does not admit refuses
    // composition before any durable state exists.
    stage("publish: committed snapshot + contracts");
    let published = publish();
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&state_dir).unwrap();
    // Production identity: ONE shared session-state ledger file.
    let ledger_path = state_dir.join("ledger.sqlite3");

    let ownership = ConversationOwnership {
        seat: SeatId::new(SEAT).unwrap(),
        project: ProjectId::new(PROJECT).unwrap(),
        ask_capability: odin_domain::CapabilityId::new(CAP_ASK).unwrap(),
    };
    let seat_bound_projects = BTreeMap::from([(
        SeatId::new(SEAT).unwrap(),
        BTreeSet::from([ProjectId::new(PROJECT).unwrap()]),
    )]);

    let _undeclared_ask = HermesRuntime::open(
        HermesSettings::new(
            dir.path().join("state-negative"),
            Some(discord_settings()),
            None,
            None,
            Vec::new(),
        )
        .unwrap(),
        hermes_ledgers_in_memory(),
        &published.contracts,
        None,
        8_192,
        seat_bound_projects.clone(),
        Some(ConversationOwnership {
            ask_capability: odin_domain::CapabilityId::new(CAP_EFFECT).unwrap(),
            ..ownership.clone()
        }),
    )
    .err()
    .expect("an ownership naming a non-delegating capability must refuse composition");

    // Link 2: the exact declared binding composes.
    let runtime = HermesRuntime::open(
        HermesSettings::new(
            state_dir.clone(),
            Some(discord_settings()),
            None,
            None,
            Vec::new(),
        )
        .unwrap(),
        HermesLedgers {
            conversation: Ledger::open(&ledger_path).unwrap(),
            adapter: Arc::new(Mutex::new(Ledger::open_in_memory().unwrap())),
            purchase: Arc::new(std::sync::Mutex::new(Ledger::open_in_memory().unwrap())),
        },
        &published.contracts,
        None,
        8_192,
        seat_bound_projects,
        Some(ownership),
    )
    .unwrap();

    // Confirm delivery through authenticated HTTP posts to the loopback Discord server.
    stage("composed: exact binding admitted");
    let (api_base, captured) = spawn_capture_server().await;
    runtime
        .bind_notify_sink(Arc::new(DiscordEgressSink::new(Arc::new(transport_to(
            &api_base,
        )))))
        .unwrap();
    let live_tokens: LiveTokens = Arc::new(Mutex::new(BTreeMap::new()));
    let facts = Arc::new(LedgerAuthorityFacts {
        ledger: Arc::new(Mutex::new(Ledger::open(&ledger_path).unwrap())),
        live_tokens: Arc::clone(&live_tokens),
    });
    runtime.set_intake_authority(Arc::clone(&facts) as Arc<dyn IntakeAuthorityFacts>);

    // Record the session before prompting and verify a kernel token against published revisions.
    let lane = LaneId::new(LANE).unwrap();
    let plane = Arc::new(BridgePlane::new(dir.path(), ledger_path.clone(), lane.clone()).await);
    let authority = Arc::new(DeclaredAuthority::new(
        &published,
        &lane,
        Arc::clone(&live_tokens),
    ));
    let approval_handle = Arc::new(Mutex::new(Ledger::open(&ledger_path).unwrap()));
    let record_path = state_dir.join("conversations").join(SEAT).join("root.json");
    let root = ConversationRoot::open(ConversationRootConfig {
        binding: LiveSeatBinding {
            seat_id: SeatId::new(SEAT).unwrap(),
            slice_id: SliceId::new(SLICE).unwrap(),
            display_name: "Fixture warden".to_owned(),
            launch_options: vec![LiveLaunchOption {
                provider: ProviderName::new(PROVIDER).unwrap(),
                model: ModelName::new(MODEL).unwrap(),
                skeleton_ref: "skeleton".to_owned(),
                container_id: ContainerId::new("container-harbor").unwrap(),
                harness: None,
            }],
            allowed_nodes: vec![NodeId::new(NODE).unwrap()],
            max_sessions: 2,
            turn_budget: None,
        },
        project: ProjectId::new(PROJECT).unwrap(),
        lane: lane.clone(),
        provider: ProviderName::new(PROVIDER).unwrap(),
        model: ModelName::new(MODEL).unwrap(),
        target_node: NodeId::new(NODE).unwrap(),
        owner: OwnerSurface {
            owner_user_id: OWNER.to_owned(),
            channel_id: CHANNEL.to_owned(),
            actor: format!("discord-owner:{OWNER}"),
        },
        answer_bound: StdDuration::from_secs(8),
        poll_interval: StdDuration::from_millis(50),
        plane: Arc::clone(&plane) as Arc<dyn ConversationPlane>,
        authority,
        egress: Arc::new(Arc::downgrade(&runtime)) as Arc<dyn ConversationEgress>,
        approvals: Arc::new(DaemonKernelApprovals {
            runtime: Arc::downgrade(&runtime),
            ledger: Arc::clone(&approval_handle),
            delegation_links: None,
        }),
        ledger_path: ledger_path.clone(),
        state_path: record_path.clone(),
        rollover: odin_omp::live::rollover::RolloverPolicy::default(),
        clock: None,
        delegation_links: None,
    })
    .unwrap();
    stage("transport bound: real rest transport on loopback");
    root.initialize()
        .await
        .expect("the conversation vehicle opens");
    stage("root initialized: durable vehicle recorded");
    // The production daemon binds the conversation root as BOTH routes
    // after composition; the reconciler and the decision path fail closed
    // without them.
    runtime.set_approved_intent_route(Arc::clone(&root) as Arc<dyn ApprovedIntentRoute>);
    runtime.set_owner_decision_route(Arc::clone(&root) as Arc<dyn OwnerDecisionRoute>);
    let record_bytes = std::fs::read(&record_path).unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&record_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "the durable record must be 0600"
        );
    }
    let record: Value = serde_json::from_slice(&record_bytes).unwrap();
    assert_eq!(record["seat"], SEAT);
    assert_eq!(record["project"], PROJECT);
    assert!(record["sessionId"].is_string(), "session before any prompt");
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle readable")
        .expect("vehicle recorded before any prompt");
    assert!(
        plane.session_manifest_present(session).await.unwrap(),
        "the durable manifest exists"
    );
    let run_id = RunId::new(format!("run:live:{session}")).unwrap();
    {
        let guard = approval_handle.lock();
        assert!(read_lane(guard.connection(), &lane).unwrap().is_some());
        let run = read_run(guard.connection(), &run_id)
            .unwrap()
            .expect("bridge run");
        assert_eq!(run.lane_id, lane);
    }

    // Link 4: the session's brain and model listing, minted from the
    // published declarations through the kernel authority.
    stage("session authority + shared rows durable");
    compose_session_brain(&published, &dir.path().join("brain"), session);

    // The scripted child actor holds its answer until the R3 gate request
    // is on the ledger, exactly as a real turn stays open behind a gate.
    plane
        .gate_armed
        .store(true, std::sync::atomic::Ordering::SeqCst);

    // Link 5: the owner's intent arrives on the paired surface and is
    // admitted into the durable correlation path.
    stage("session brain composed");
    let intent_projection = runtime
        .admit_message(&DiscordMessage {
            id: "3000000000000000001".to_owned(),
            channel_id: CHANNEL.to_owned(),
            author_id: OWNER.to_owned(),
            guild_id: None,
            content: INTENT_TEXT.to_owned(),
            attachments: Vec::new(),
        })
        .unwrap();
    assert_eq!(intent_projection["status"], "queued", "{intent_projection}");

    // The reconcile tick drives the bound conversation route: plan
    // acceptance, the durable prompt, and the answer wait. While the turn
    // is open, the in-session R3 gate request is journaled through the same
    // public ledger APIs and kernel digest derivation the dispatch gate
    // uses; the conversation then delivers the question itself.
    let effect_key = "vault-seal-harbor-1";
    let command_id = CommandId::new(format!("command:{effect_key}")).unwrap();
    let approval_id = ApprovalId::new(format!("approval:{effect_key}")).unwrap();
    // The reconcile tick runs on its own thread, exactly as a real
    // reconciler runs beside the async runtime: the await here parks the
    // runtime so its spawned tasks keep serving the loopback transport.
    let reconciler = {
        let runtime = Arc::clone(&runtime);
        tokio::task::spawn_blocking(move || runtime.reconcile_admitted_intents().unwrap())
    };
    plane.prompt_admitted.notified().await;
    {
        let mut guard = approval_handle.lock();
        let (fresh, context) = fresh_owner_authority(&published, &lane, session);
        let schemas = FileSchemas {
            root: published.root.path().to_path_buf(),
        };
        let listing = list_capabilities(
            fresh.get(),
            &context,
            &published.contracts,
            &schemas,
            u64::try_from(now().unix_timestamp_nanos() / 1_000_000).unwrap_or(0),
        )
        .expect("kernel lists the published capabilities");
        // Authorization without approval must demand it without consuming or recording anything.
        let arguments = json!({
            "path": "ledger/vault-copy.txt",
            "content": EFFECT_PAYLOAD,
            "preimage_sha256": Value::Null,
        });
        let first = ToolInvocation {
            command_id: command_id.clone(),
            capability_id: odin_domain::CapabilityId::new(CAP_EFFECT).unwrap(),
            capability_version: 1,
            listing_digest: listing.digest,
            arguments: arguments.clone(),
            arguments_digest: odin_kernel::arguments_digest(&arguments),
            target: InvocationTarget {
                kind: "run".to_owned(),
                id: format!("run:live:{session}"),
            },
            executor_binding: None,
            expected_revision: None,
            plan_id: Some(PlanId::new(format!("plan:live:{session}")).unwrap()),
            approval_id: None,
            resource: None,
        };
        let rejection = {
            let outcome = authorize(
                AuthorizationEnvironment {
                    authority: fresh.get(),
                    policy: &context,
                    contracts: &published.contracts,
                    schemas: &schemas,
                    listing: &listing,
                },
                &first,
                PlanGate::Accepted,
                &mut ApprovalGate::new(&mut guard),
                u64::try_from(now().unix_timestamp_nanos() / 1_000_000).unwrap_or(0),
            )
            .expect("the authorization pass runs");
            match outcome {
                AuthorizationOutcome::Authorized(_) => {
                    panic!("an R3 dispatch without an approval must never authorize")
                }
                AuthorizationOutcome::Rejected(rejection) => rejection,
            }
        };
        assert!(
            matches!(
                rejection,
                odin_kernel::AuthorizationRejection::NeedsApproval { .. }
            ),
            "the first dispatch must demand the operator approval, got {rejection:?}"
        );
        // The retry form: the durable arguments embed the exact approval
        // they authorize, the scope digest covers that whole object, and
        // the command row carries the same digest — so the consumption
        // seam and the question renderer both re-derive the scope from
        // durable rows alone.
        let retry_arguments = {
            let mut retry = arguments;
            retry["approvalId"] = Value::String(approval_id.to_string());
            retry
        };
        let scope = ApprovalScope {
            target_kind: "run".to_owned(),
            target_id: format!("run:live:{session}"),
            capability_id: odin_domain::CapabilityId::new(CAP_EFFECT).unwrap(),
            arguments_digest: odin_kernel::arguments_digest(&retry_arguments),
        };
        let spec = CommandSpec {
            id: command_id.clone(),
            idempotency_key: effect_key.to_owned(),
            correlation_id: "correlation:vault-seal-1".to_owned(),
            causation_id: None,
            issuer: SEAT.to_owned(),
            approval_id: Some(approval_id.clone()),
            target_kind: "run".to_owned(),
            target_id: format!("run:live:{session}"),
            capability_id: odin_domain::CapabilityId::new(CAP_EFFECT).unwrap(),
            capability_version: 1,
            arguments_hash: scope.arguments_digest,
            arguments: retry_arguments,
            expected_desired_revision: None,
            issued_at: now(),
            expires_at: now() + time::Duration::hours(1),
        };
        guard.record_command(&spec).unwrap().into_recorded();
        let requested = ApprovalGate::new(&mut guard)
            .request(NewApproval {
                approval_id: approval_id.clone(),
                issuer: SEAT.to_owned(),
                scope,
                requested_at: now(),
                expires_at: now() + time::Duration::hours(1),
            })
            .expect("the kernel gate journals the demand");
        assert_eq!(requested.status, ApprovalStatus::Requested);
    }
    stage("gate journaled: kernel demand requested");
    plane.gate_open.notify_one();
    let settled = reconciler.await.unwrap();
    stage("reconciler settled");
    assert_eq!(settled, 1, "the intent settles exactly once");

    // Link 6: the question the owner must answer is the one actually
    // delivered to the paired conversation.
    {
        let captured = captured.lock();
        assert_eq!(captured.len(), 1, "exactly one question posted");
        assert_eq!(captured[0].channel_id, CHANNEL);
        assert_eq!(
            captured[0].authorization, "Bot fixture-bot-secret",
            "the delivery must be an authenticated transport post"
        );
        let body = captured[0].body["content"].as_str().unwrap().to_owned();
        assert!(
            body.starts_with("May I seal the requested vault ledger copy"),
            "the wording must come from the published declaration: {body}"
        );
        assert!(
            !body.contains(&approval_id.to_string()) && !body.contains("blake3"),
            "no machinery in the question: {body}"
        );
    }
    let intent_command = {
        let guard = approval_handle.lock();
        guard
            .commands()
            .unwrap()
            .into_iter()
            .find(|command| command.capability_id.as_str() == CAP_INTAKE)
            .expect("the intent row is durable")
    };
    assert_eq!(
        intent_command.terminal_status,
        Some(CommandTerminalStatus::Completed)
    );
    let intent_result = intent_command.terminal_result.expect("the intent settled");
    assert_eq!(intent_result["outcome"]["waitingOnApproval"], true);
    assert_eq!(intent_result["outcome"]["answer"], "");

    // A message from any other author never reaches the decision path.
    let stranger = runtime
        .admit_message(&DiscordMessage {
            id: "3000000000000000002".to_owned(),
            channel_id: CHANNEL.to_owned(),
            author_id: "999999999999999999".to_owned(),
            guild_id: None,
            content: "yes".to_owned(),
            attachments: Vec::new(),
        })
        .unwrap();
    assert_eq!(stranger["status"], "unauthorized");

    // Link 7: the paired owner's reply settles the EXACT delivered request
    // through the kernel gate; the reply is causally ordered after the
    // transport's own posted question id.
    let asked_revision = {
        let guard = approval_handle.lock();
        let approval = guard.approval(&approval_id).unwrap().expect("requested");
        assert_eq!(approval.status, ApprovalStatus::Requested);
        let proofs: Vec<_> = guard
            .audit_events_after(0, 100)
            .unwrap()
            .into_iter()
            .filter(|event| event.kind == APPROVAL_DELIVERY_AUDIT_KIND)
            .collect();
        assert_eq!(proofs.len(), 1, "one durable delivery proof");
        assert_eq!(proofs[0].payload["channelId"], CHANNEL);
        assert_eq!(proofs[0].payload["ownerUserId"], OWNER);
        assert_eq!(proofs[0].payload["session"], format!("run:live:{session}"));
        assert_eq!(proofs[0].payload["capabilityId"], CAP_EFFECT);
        approval.revision
    };
    // Repeated polling must not repost; run off-thread because the loopback transport is blocking.
    let again = {
        let approvals = DaemonKernelApprovals {
            runtime: Arc::downgrade(&runtime),
            ledger: Arc::clone(&approval_handle),
            delegation_links: None,
        };
        let handle = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            handle.block_on(approvals.deliver_session_questions(&session, CHANNEL, OWNER, now()))
        })
        .await
        .unwrap()
        .unwrap()
    };
    assert!(
        again.is_empty(),
        "an asked question is not asked again: {again:?}"
    );
    assert_eq!(captured.lock().len(), 1, "the question is posted once");
    // A moved question is reposted for its new revision without ending the current turn.
    approval_handle
        .lock()
        .follow_approval_target(
            "run",
            &format!("run:live:{session}"),
            &format!("run:live:{session}"),
            now(),
        )
        .unwrap();
    let followed = {
        let approvals = DaemonKernelApprovals {
            runtime: Arc::downgrade(&runtime),
            ledger: Arc::clone(&approval_handle),
            delegation_links: None,
        };
        let handle = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            handle.block_on(approvals.deliver_session_questions(&session, CHANNEL, OWNER, now()))
        })
        .await
        .unwrap()
        .unwrap()
    };
    assert!(
        followed.is_empty(),
        "a followed question is not a new question: {followed:?}"
    );
    assert_eq!(
        captured.lock().len(),
        2,
        "re-posted once at its new revision"
    );
    let decision_revision = approval_handle
        .lock()
        .approval(&approval_id)
        .unwrap()
        .expect("requested")
        .revision;
    assert_eq!(decision_revision, asked_revision + 1);
    // Recheck owner, channel, message ordering, and revision off the async runtime thread.
    let decision_runtime = Arc::clone(&runtime);
    let decision_ledger = Arc::clone(&approval_handle);
    let decision_approval_id = approval_id.clone();
    let decision_outcome = tokio::task::spawn_blocking(move || {
        decision_runtime
            .decide_delivered_approval(
                &decision_ledger,
                &AuthenticatedOwnerMessage {
                    owner_user_id: OWNER.to_owned(),
                    channel_id: CHANNEL.to_owned(),
                    message_id: "3900000000000000000".to_owned(),
                    seat: SeatId::new(SEAT).unwrap(),
                    project: ProjectId::new(PROJECT).unwrap(),
                    content: "yes".to_owned(),
                },
                &decision_approval_id,
                decision_revision,
                OwnerDecision::AllowOnce,
                now(),
            )
            .expect("the authenticated owner decision settles")
    })
    .await
    .unwrap();
    stage("decision admitted: authenticated owner reply");
    assert!(matches!(
        decision_outcome,
        odin_kernel::DecisionOutcome::Approved(_)
    ));

    // Link 8: the consumed decision authorizes exactly one confined
    // temporary effect. The retry dispatch is re-derived from the durable
    // command row and consumed by the kernel's own R3 authorization pass at
    // the decided revision; a replay of the same retry is refused. The write
    // happens inside a sealed 0700 capsule through the real confinement
    // owner.
    {
        let mut guard = approval_handle.lock();
        let (fresh, context) = fresh_owner_authority(&published, &lane, session);
        let schemas = FileSchemas {
            root: published.root.path().to_path_buf(),
        };
        let now_ms = u64::try_from(now().unix_timestamp_nanos() / 1_000_000).unwrap_or(0);
        let listing = list_capabilities(
            fresh.get(),
            &context,
            &published.contracts,
            &schemas,
            now_ms,
        )
        .expect("kernel lists the published capabilities");
        let recorded = guard
            .command(&command_id)
            .unwrap()
            .expect("the retry-form command row is durable");
        let approved_revision = guard
            .approval(&approval_id)
            .unwrap()
            .expect("decided approval")
            .revision;
        let retry = ToolInvocation {
            command_id: command_id.clone(),
            capability_id: recorded.capability_id.clone(),
            capability_version: 1,
            listing_digest: listing.digest,
            arguments: recorded.arguments.clone(),
            arguments_digest: odin_kernel::arguments_digest(&recorded.arguments),
            target: InvocationTarget {
                kind: recorded.target_kind.clone(),
                id: recorded.target_id.clone(),
            },
            executor_binding: None,
            expected_revision: Some(approved_revision),
            plan_id: Some(PlanId::new(format!("plan:live:{session}")).unwrap()),
            approval_id: Some(approval_id.clone()),
            resource: None,
        };
        for attempt in 0..2 {
            let outcome = authorize(
                AuthorizationEnvironment {
                    authority: fresh.get(),
                    policy: &context,
                    contracts: &published.contracts,
                    schemas: &schemas,
                    listing: &listing,
                },
                &retry,
                PlanGate::Accepted,
                &mut ApprovalGate::new(&mut guard),
                now_ms,
            )
            .expect("the authorization pass runs");
            match (attempt, outcome) {
                (0, AuthorizationOutcome::Authorized(_)) => {}
                // The exact replay presents the revision its consumption
                // already advanced past; nothing is consumed twice.
                (
                    1,
                    AuthorizationOutcome::Rejected(
                        odin_kernel::AuthorizationRejection::StaleRevision { .. },
                    ),
                ) => {}
                (attempt, other) => panic!("consumes exactly once; attempt {attempt}: {other:?}"),
            }
        }
    }
    stage("approval consumed exactly once");
    let capsule_root = dir.path().join("capsule");
    std::fs::create_dir(&capsule_root).unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&capsule_root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    // The declared `ledger` component is capsule preparation before the
    // seal; the effect itself only ever writes the leaf file through the
    // confined capability.
    std::fs::create_dir_all(capsule_root.join("ledger")).unwrap();
    let capsule =
        odin_confined_fs::PrivateCapability::seal(&capsule_root).expect("the capsule seals");
    let artifact_rel = Path::new("ledger/vault-copy.txt");
    let payload = {
        let guard = approval_handle.lock();
        let command = guard
            .command(&command_id)
            .unwrap()
            .expect("recorded command");
        command
            .arguments
            .get("content")
            .and_then(Value::as_str)
            .expect("the approved payload travels in the durable row")
            .to_owned()
    };
    capsule
        .create_atomic(artifact_rel, payload.as_bytes(), 0o600)
        .expect("the confined effect writes");
    let mut written = String::new();
    {
        use std::io::Read as _;
        capsule
            .open_read(artifact_rel)
            .expect("the artifact reads back")
            .read_to_string(&mut written)
            .unwrap();
    }
    assert_eq!(written, EFFECT_PAYLOAD, "the effect is byte-exact");
    // The confinement is real: escapes refuse typed.
    assert!(matches!(
        capsule.open_read(Path::new("../escape")),
        Err(odin_confined_fs::ConfinedError::DotDotSegment)
    ));
    assert!(matches!(
        capsule.open_read(Path::new("/etc/passwd")),
        Err(odin_confined_fs::ConfinedError::AbsolutePath)
    ));

    // Link 9: finalization through the real command lifecycle. The
    // re-record is the idempotent retry row: the SAME durable arguments
    // and digest the approval scope pins.
    let artifact_digest = {
        let mut guard = approval_handle.lock();
        let mut arguments = json!({
            "path": "ledger/vault-copy.txt",
            "content": EFFECT_PAYLOAD,
            "preimage_sha256": Value::Null,
        });
        arguments["approvalId"] = Value::String(approval_id.to_string());
        let spec = CommandSpec {
            id: command_id.clone(),
            idempotency_key: effect_key.to_owned(),
            correlation_id: "correlation:vault-seal-1".to_owned(),
            causation_id: None,
            issuer: SEAT.to_owned(),
            approval_id: Some(approval_id.clone()),
            target_kind: "run".to_owned(),
            target_id: format!("run:live:{session}"),
            capability_id: odin_domain::CapabilityId::new(CAP_EFFECT).unwrap(),
            capability_version: 1,
            arguments_hash: odin_kernel::arguments_digest(&arguments),
            arguments,
            expected_desired_revision: None,
            issued_at: now(),
            expires_at: now() + time::Duration::hours(1),
        };
        let recorded = guard.record_command(&spec).unwrap().into_recorded();
        let revision = recorded.command().revision;
        let accepted = guard.accept_command(&recorded, revision, now()).unwrap();
        let accepted_revision = accepted.command().revision;
        let digest = Digest::hash(payload.as_bytes()).to_string();
        guard
            .complete_command(
                &accepted,
                &CommandOutcome {
                    status: CommandTerminalStatus::Completed,
                    result: json!({
                        "artifact": "ledger/vault-copy.txt",
                        "digest": digest,
                        "approval": approval_id.to_string(),
                    }),
                },
                accepted_revision,
                now(),
            )
            .unwrap();
        digest
    };
    // Quiesce the conversation's own continuation tasks.
    root.join_background(StdDuration::ZERO).await;
    stage("finalized: command completed");

    // Link 10: DB reopen. Every durable invariant is re-read from a fresh
    // handle.
    let reopened = Ledger::open(&ledger_path).unwrap();
    let settled_approval = reopened
        .approval(&approval_id)
        .unwrap()
        .expect("durable approval");
    assert_eq!(settled_approval.status, ApprovalStatus::Consumed);
    assert_eq!(
        settled_approval.consumed_by_command_id,
        Some(command_id.clone())
    );
    assert_eq!(
        settled_approval.decided_by.as_deref(),
        Some("discord-owner:444400000000000001")
    );
    assert!(
        settled_approval
            .decision_evidence_ref
            .as_deref()
            .unwrap_or_default()
            .starts_with("delivery:event:hermes-delivery:"),
        "the decision must name its delivery proof"
    );
    let finalized = reopened
        .command(&command_id)
        .unwrap()
        .expect("durable command");
    assert_eq!(
        finalized.terminal_status,
        Some(CommandTerminalStatus::Completed)
    );
    assert_eq!(
        finalized.terminal_result.unwrap()["digest"],
        artifact_digest
    );
    let reopened_intent = reopened
        .commands()
        .unwrap()
        .into_iter()
        .find(|command| command.capability_id.as_str() == CAP_INTAKE)
        .unwrap();
    assert_eq!(
        reopened_intent.terminal_status,
        Some(CommandTerminalStatus::Completed)
    );
    let run = read_run(reopened.connection(), &run_id)
        .unwrap()
        .expect("bridge run survives");
    assert_eq!(run.lane_id, lane);
    let proofs: Vec<_> = reopened
        .audit_events_after(0, 100)
        .unwrap()
        .into_iter()
        .filter(|event| event.kind == APPROVAL_DELIVERY_AUDIT_KIND)
        .collect();
    assert_eq!(
        proofs.len(),
        2,
        "both delivery proofs (asked, then followed) survive the reopen"
    );
    assert!(
        capsule.open_read(artifact_rel).is_ok(),
        "the confined artifact is durable on disk"
    );
    // The consumed reply intake is spent at the ledger layer, across the
    // reopen.
    {
        let mut guard = reopened;
        let current_revision = guard
            .approval(&approval_id)
            .unwrap()
            .expect("durable approval")
            .revision;
        let replay = guard
            .decide_approval_consuming_intake(
                &approval_id,
                ApprovalDecision::Approve { evidence_ref: None },
                "discord-owner:444400000000000001",
                now(),
                current_revision,
                &DecisionIntake {
                    consumer_id: format!("discord-owner:{OWNER}"),
                    message_id: "3900000000000000000".to_owned(),
                },
                false,
            )
            .unwrap();
        assert!(
            replay.is_none(),
            "the same reply must stay consumed across the reopen"
        );
    }
    stage("reopen invariants verified");

    // The composed surface refuses the replay too: the approval is no
    // longer open, so a redelivered yes can authorize nothing.
    let runtime2_ledger = Arc::new(Mutex::new(Ledger::open(&ledger_path).unwrap()));
    let runtime2 = HermesRuntime::open(
        HermesSettings::new(
            state_dir.clone(),
            Some(discord_settings()),
            None,
            None,
            Vec::new(),
        )
        .unwrap(),
        HermesLedgers {
            conversation: Ledger::open(&ledger_path).unwrap(),
            adapter: Arc::new(Mutex::new(Ledger::open_in_memory().unwrap())),
            purchase: Arc::new(std::sync::Mutex::new(Ledger::open_in_memory().unwrap())),
        },
        &published.contracts,
        None,
        8_192,
        BTreeMap::from([(
            SeatId::new(SEAT).unwrap(),
            BTreeSet::from([ProjectId::new(PROJECT).unwrap()]),
        )]),
        Some(ConversationOwnership {
            seat: SeatId::new(SEAT).unwrap(),
            project: ProjectId::new(PROJECT).unwrap(),
            ask_capability: odin_domain::CapabilityId::new(CAP_ASK).unwrap(),
        }),
    )
    .unwrap();
    runtime2
        .bind_notify_sink(Arc::new(DiscordEgressSink::new(Arc::new(transport_to(
            &api_base,
        )))))
        .unwrap();
    let replay = {
        let runtime2 = Arc::clone(&runtime2);
        let runtime2_ledger = Arc::clone(&runtime2_ledger);
        tokio::task::spawn_blocking(move || {
            runtime2.decide_delivered_approval(
                &runtime2_ledger,
                &AuthenticatedOwnerMessage {
                    owner_user_id: OWNER.to_owned(),
                    channel_id: CHANNEL.to_owned(),
                    message_id: "3900000000000000000".to_owned(),
                    seat: SeatId::new(SEAT).unwrap(),
                    project: ProjectId::new(PROJECT).unwrap(),
                    content: "yes".to_owned(),
                },
                &approval_id,
                decision_revision,
                OwnerDecision::AllowOnce,
                now(),
            )
        })
        .await
        .unwrap()
    };
    assert!(matches!(
        replay,
        Err(odin_hermes::runtime::DecisionRefusal::NotOpen(_))
    ));
    stage("replay refused on the composed surface");
}

// ---------------------------------------------------------------------------
// Private helpers, one file: the declaration publish, the session authority,
// the scripted bridge plane, the bounded-context compiler, and the loopback
// capture transport. Private items over public production APIs only.
// ---------------------------------------------------------------------------

/// Fixture identities are independent of deployment; capability ids must match admitted schema stems.
const SEAT: &str = "warden";
const PROJECT: &str = "harbor";
const SLICE: &str = "warden-watch";
const LANE: &str = "warden-harbor";
const CAP_INTAKE: &str = "task.read";
const CAP_ASK: &str = "seat.ask.warden";
const CAP_EFFECT: &str = "capsule.file.edit";
const OWNER: &str = "444400000000000001";
const CHANNEL: &str = "910000000000000001";
const NODE: &str = "node-harbor";
const PROVIDER: &str = "seal-provider";
const MODEL: &str = "warden-mini";
const KEY: &[u8] = b"integrated-path fixture signing key";
/// The exact bytes the approved effect writes into the sealed capsule.
const EFFECT_PAYLOAD: &str = "sealed ledger copy: fixture line\n";
const INTENT_TEXT: &str = "please seal the vault ledger copy for me";

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

// ---------------------------------------------------------------------------
// Link 1: declaration publish (real registry validators + production
// contract conversion).
// ---------------------------------------------------------------------------

fn dir_singular(dir: &str) -> &'static str {
    match dir {
        "capabilities" => "capability",
        "containers" => "container",
        "hosts" => "host",
        "lanes" => "lane",
        "nodes" => "node",
        "projects" => "project",
        "providers" => "provider",
        "seats" => "seat",
        "slices" => "slice",
        "context-profiles" => "context-profile",
        other => unreachable!("unknown registry kind dir {other}"),
    }
}

/// Writes the temporary declaration tree: nine kind directories, five
/// objects, the seat's four transport lanes plus the session lane, the
/// seat's standing conversation declaration, and the dedicated capability
/// schema files the relational validator stats on disk.
fn write_registry(root: &Path) {
    for kind in odin_registry::RegistryKind::ALL.map(odin_registry::RegistryKind::directory) {
        std::fs::create_dir_all(root.join("registry").join(kind)).unwrap();
        // Git does not track empty directories: every committed registry
        // kind carries a placeholder so provenance validation sees it.
        std::fs::write(root.join("registry").join(kind).join(".gitkeep"), b"").unwrap();
    }
    std::fs::create_dir_all(root.join("schemas").join("capability")).unwrap();
    // Every declared schema is the repo's real bytes: the seat_ask
    // primitive's schema paths are part of its reserved identity, the
    // kernel authorization pass validates the effect payload against the
    // capsule.file.edit bytes, and the admission tuples name these exact
    // files.
    for name in [
        "capsule.file.edit.input.json",
        "capsule.file.edit.output.json",
        "seat.ask.input.json",
        "seat.ask.output.json",
        "task.read.input.json",
        "task.read.output.json",
    ] {
        std::fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../schemas/capability")
                .join(name),
            root.join("schemas").join("capability").join(name),
        )
        .expect("the repo schema copies into the fixture");
    }
    let object = |dir: &str, id: &str, body: String| {
        let dir_path = root.join("registry").join(dir).join(id);
        std::fs::create_dir_all(&dir_path).unwrap();
        std::fs::write(dir_path.join(format!("{}.toml", dir_singular(dir))), body).unwrap();
    };
    for name in ["hosts", "nodes", "providers"] {
        std::fs::create_dir_all(root.join("registry").join(name)).unwrap();
    }
    object(
        "hosts",
        "harbor-laptop",
        "schema = \"odin.registry.v1\"\nkind = \"host\"\nenabled = true\n\
         description = \"Enrolled fixture deployment host.\"\n\
         hardware = \"fixture x86_64 host\"\nrole = \"control\"\n\
         tailscale = \"harbor-laptop\"\nenrolled = true\n"
            .to_owned(),
    );
    object(
        "nodes",
        NODE,
        "schema = \"odin.registry.v1\"\nkind = \"node\"\nenabled = true\n\
         description = \"The fixture's authoritative control node.\"\n\
         host = \"harbor-laptop\"\nrole = \"control\"\n\
         capabilities = [\"control\"]\nallow_workloads = true\n\
         gateway_endpoint = \"http://harbor-laptop:14000/v1\"\n\
         authoritative_state = true\n"
            .to_owned(),
    );
    object(
        "containers",
        "container-harbor",
        "schema = \"odin.registry.v1\"\nkind = \"container\"\nenabled = true\n\
         description = \"Native OMP process container for warden live sessions on the \
         fixture control node.\"\npurpose = \"warden-native\"\nbase = \"native-process\"\n\
         seats_offered = [\"warden\"]\nscripts = []\nwatchdogs = []\n\
         identity_fields = [\"purpose\", \"base\", \"contents.kind\"]\ntunables = {}\n\
         surface = [\"status\"]\ncontents = { kind = \"odin_env\" }\nmonitoring = \"none\"\n"
            .to_owned(),
    );
    object(
        "providers",
        "gateway-harbor",
        "schema = \"odin.registry.v1\"\nkind = \"provider\"\nenabled = true\n\
         description = \"Fixture model gateway provider.\"\nadapter = \"gateway\"\n\
         [policy]\nroutes = []\n\
         [recovery]\n\
         allowed_rungs = [\"retry\", \"restart_worker\", \"checkpoint\", \"rehome\", \"escalate\"]\n\
         blocked_missing_decision = \"operator must choose\"\n\
         [recovery.max_attempts]\nretry = 2\nrestart_worker = 1\ncheckpoint = 1\n\
         rehome = 1\nescalate = 1\n\
         [recovery.cooldown_seconds]\nretry = 30\nrestart_worker = 30\n\
         checkpoint = 30\nrehome = 60\nescalate = 0\n"
            .to_owned(),
    );
    object(
        "projects",
        PROJECT,
        format!(
            "schema = \"odin.registry.v1\"\nkind = \"project\"\nenabled = true\n\
             description = \"Fixture harbor project.\"\nsource_root = \".\"\n\
             default_seat = \"{SEAT}\"\nmemory_namespaces = [\"atlas.code\"]\n\
             artifact_policy = \"standard\"\n"
        ),
    );
    for (lane, direction, payload) in [
        (LANE, None, None),
        ("warden-file-in", Some("ingress"), Some("file")),
        ("warden-file-out", Some("egress"), Some("file")),
        ("warden-render-in", Some("ingress"), Some("render")),
        ("warden-render-out", Some("egress"), Some("render")),
    ] {
        let mut body = format!(
            "schema = \"odin.registry.v1\"\nkind = \"lane\"\nenabled = true\n\
             description = \"Fixture lane {lane}.\"\nproject = \"{PROJECT}\"\n\
             family = \"engine\"\ndefault_seat = \"{SEAT}\"\nqueue = \"interactive\"\n\
             requires_independent_review = false\n"
        );
        if let (Some(direction), Some(payload)) = (direction, payload) {
            body.push_str(&format!(
                "direction = \"{direction}\"\npayload_kind = \"{payload}\"\n"
            ));
        }
        object("lanes", lane, body);
    }
    object(
        "context-profiles",
        "fixture",
        "schema = \"odin.registry.v1\"\nkind = \"context-profile\"\nenabled = true\ndescription = \"Fixture context profile.\"\ncore_tokens = 2048\ninject_tokens = 4096\ninject_k = 8\n".to_owned(),
    );
    object(
        "seats",
        SEAT,
        format!(
            "schema = \"odin.registry.v1\"\nkind = \"seat\"\nenabled = true\n\
             description = \"Fixture coordinator seat.\"\ncategories = [\"coordinator\"]\n\
             tool_refs = [\"{CAP_INTAKE}\", \"{CAP_ASK}\", \"{CAP_EFFECT}\"]\n\
             project_scope = [\"{PROJECT}\"]\nbrain_scope = []\n\
             [approval_defaults]\nr0 = \"auto\"\nr1 = \"auto\"\nr2 = \"auto\"\nr3 = \"approval\"\n\
             [limits]\nmax_parallel_runs = 2\nmax_sessions = 2\n\
             budget = {{ usd_micros = 1_000_000, window = {{ duration_seconds = 2_592_000 }} }}\n\
             [live]\nmax_sessions = 2\nfile_ingress_lane = \"warden-file-in\"\n\
             file_egress_lane = \"warden-file-out\"\nrender_ingress_lane = \"warden-render-in\"\n\
             render_egress_lane = \"warden-render-out\"\n\
             [context]\nmax_bundle_tokens = 24_576\nprofile = \"fixture\"\n\
             [conversation]\nproject = \"{PROJECT}\"\nask_capability = \"{CAP_ASK}\"\n\
             guidance = \"Plain, short conversation style for the fixture seat.\"\n\
             answer_timeout_seconds = 10\n"
        ),
    );
    object(
        "slices",
        SLICE,
        format!(
            "schema = \"odin.registry.v1\"\nkind = \"slice\"\nenabled = true\n\
             description = \"Fixture slice admitting exactly the declared capabilities.\"\n\
             capabilities = [\"{CAP_INTAKE}\", \"{CAP_ASK}\", \"{CAP_EFFECT}\"]\n\
             variables = {{}}\n[redirects]\nout_of_scope = \"NeedsPlan\"\n\
             [context]\nmax_bundle_tokens = 24_576\nreserve_output_tokens = 4_096\n\
             control_tokens = 4_096\nhistory_tokens = 8_192\ncore_tokens = 2_048\nprefetch_tokens = 4_096\n\
             tool_result_tokens = 4_096\ntool_schema_tokens = 2_048\nmax_item_tokens = 4_096\n"
        ),
    );
    // Every enabled capability binds one compiled production admission
    // tuple exactly (version, schemas, handler, extractor): the intake
    // task-read route, the delegating seat_ask primitive, and the
    // confined file-edit route carrying the R3 operator gate.
    object(
        "capabilities",
        CAP_INTAKE,
        "schema = \"odin.registry.v1\"\nkind = \"capability\"\nenabled = true\n\
         implementation = \"builtin\"\nversion = 1\n\
         description = \"Record the owner-paired harbor intake as a durable task.\"\n\
         handler = { id = \"odin_task.read\" }\n\
         input_schema = \"schemas/capability/task.read.input.json\"\n\
         output_schema = \"schemas/capability/task.read.output.json\"\n\
         effect_class = \"R1\"\nseat_tags = [\"coordinator\"]\ntimeout_seconds = 30\n\
         idempotency = \"required\"\nretry = { max_attempts = 1 }\n\
         approval_policy = \"none\"\n\
         evidence_extractor = { id = \"odin_task.read_evidence\" }\n"
            .to_owned(),
    );
    object(
        "capabilities",
        CAP_ASK,
        format!(
            "schema = \"odin.registry.v1\"\nkind = \"capability\"\nenabled = true\n\
             implementation = \"builtin\"\nversion = 1\n\
             description = \"Ask the warden seat for one governed decision.\"\n\
             handler = {{ id = \"seat_ask\" }}\ndelegate_to = \"{SEAT}\"\n\
             input_schema = \"schemas/capability/seat.ask.input.json\"\n\
             output_schema = \"schemas/capability/seat.ask.output.json\"\n\
             effect_class = \"R3\"\nseat_tags = [\"coordinator\"]\ntimeout_seconds = 30\n\
             idempotency = \"required\"\nretry = {{ max_attempts = 0 }}\n\
             approval_policy = \"operator\"\n\
             evidence_extractor = {{ id = \"odin_hermes_seat_ask_evidence\" }}\n"
        ),
    );
    object(
        "capabilities",
        CAP_EFFECT,
        "schema = \"odin.registry.v1\"\nkind = \"capability\"\nenabled = true\n\
         implementation = \"builtin\"\nversion = 1\n\
         description = \"Seal the requested vault ledger copy into the declared capsule, \
         byte-exact and confined.\"\nhandler = { id = \"odin_file.edit\" }\n\
         input_schema = \"schemas/capability/capsule.file.edit.input.json\"\n\
         output_schema = \"schemas/capability/capsule.file.edit.output.json\"\n\
         effect_class = \"R3\"\nseat_tags = [\"coordinator\"]\ntimeout_seconds = 30\n\
         idempotency = \"required\"\nretry = { max_attempts = 1 }\n\
         approval_policy = \"operator\"\n\
         evidence_extractor = { id = \"odin_file.edit_evidence\" }\n"
            .to_owned(),
    );
}

/// The production publication loop (`operation_contracts`): every enabled
/// capability converts through the kernel's registry binding rules against
/// its declared admitted tuple.
fn operation_contracts(
    registry: &[RegistryObject],
) -> Result<BTreeMap<odin_domain::CapabilityId, CapabilityContract>, String> {
    let mut contracts = BTreeMap::new();
    for object in registry {
        if object.kind() != RegistryKind::Capability || !object.enabled() {
            continue;
        }
        let ObjectConfig::Capability(capability) = &object.config else {
            return Err(format!("registry object {} is not a capability", object.id));
        };
        let admitted = odin_registry::relational::declared_admitted_binding(capability)
            .ok_or_else(|| format!("enabled capability {} has no admitted binding", object.id))?;
        let contract = CapabilityContract::try_from_registry(object, &admitted)
            .map_err(|error| format!("capability {} contract failed: {error}", object.id))?;
        if contracts.insert(contract.id.clone(), contract).is_some() {
            return Err(format!("capability {} is declared twice", object.id));
        }
    }
    Ok(contracts)
}

struct Published {
    root: tempfile::TempDir,
    registry: Vec<RegistryObject>,
    contracts: BTreeMap<odin_domain::CapabilityId, CapabilityContract>,
    seat_revision: Digest,
    slice_revision: Digest,
    capability_policy_digest: Digest,
}

fn digest_of(registry: &[RegistryObject], kind: RegistryKind, id: &str) -> Digest {
    let object = registry
        .iter()
        .find(|object| object.kind() == kind && object.id == id)
        .unwrap_or_else(|| panic!("declared {id} admitted"));
    Digest::hash(&object.canonical_bytes().expect("canonical serialization"))
}

/// The git seams the publication requires: a real commit of the
/// declaration tree as the Odin test identity, signing disabled.
fn git(worktree: &Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args(args)
        .output()
        .expect("spawn git");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("git output is UTF-8")
        .trim_end()
        .to_owned()
}

fn commit_all(worktree: &Path, message: &str) -> String {
    git(worktree, &["init", "-q"]);
    git(worktree, &["add", "-A"]);
    git(
        worktree,
        &[
            "-c",
            "user.name=Odin Test",
            "-c",
            "user.email=odin-test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            message,
        ],
    );
    git(worktree, &["rev-parse", "HEAD"])
}

/// Publishes the declarations the way production does: the declaration
/// tree is committed, the committed-worktree candidate is validated
/// against the compiled production admission set, one snapshot revision
/// is published, and the consumer reopens the published snapshot through
/// the store handle before the contract conversion.
fn publish() -> Published {
    let root = tempfile::tempdir().unwrap();
    write_registry(root.path());
    let discovery = walk(root.path().join("registry"));
    assert!(
        discovery.findings.is_empty(),
        "discovery rejected the declarations: {:?}",
        discovery.findings
    );
    let parsed = parse_objects(&discovery.objects);
    assert!(
        parsed.findings.is_empty(),
        "parse rejected the declarations: {:?}",
        parsed.findings
    );
    let findings = validate_relations(&parsed.objects, &RelationContext::new(root.path()));
    assert!(
        findings.is_empty(),
        "relational admission rejected the declarations: {findings:?}"
    );
    let commit = commit_all(root.path(), "integrated-path fixture registry");
    let candidate = ValidatedSnapshotCandidate::from_committed_worktree(
        root.path(),
        &commit,
        odin_omp::host_tools::production_bindings()
            .iter()
            .map(|binding| binding.to_admitted_binding()),
    )
    .expect("the committed declarations satisfy production admission");
    let snapshot_path = root.path().join("state/registry/snapshot.json");
    SnapshotStore::new(&snapshot_path)
        .publish_committed(&candidate, 1)
        .expect("the snapshot publishes");
    let snapshot = SnapshotHandle::open(SnapshotStore::new(&snapshot_path))
        .expect("the snapshot store reopens")
        .current();
    snapshot.verify().expect("the published snapshot verifies");
    let contracts = operation_contracts(&snapshot.objects).unwrap();
    assert_eq!(contracts.len(), 3, "every enabled capability published");
    Published {
        seat_revision: digest_of(&snapshot.objects, RegistryKind::Seat, SEAT),
        slice_revision: digest_of(&snapshot.objects, RegistryKind::Slice, SLICE),
        capability_policy_digest: digest_of(&snapshot.objects, RegistryKind::Slice, SLICE),
        registry: snapshot.objects.clone(),
        contracts,
        root,
    }
}

// ---------------------------------------------------------------------------
// Reproduce the daemon wrapper's token mint/verify sequence because this crate cannot depend on odin-cli.
// ---------------------------------------------------------------------------

type LiveTokens = Arc<Mutex<BTreeMap<String, odin_domain::SeatTokenId>>>;

struct DeclaredAuthority {
    seat: SeatId,
    slice: SliceId,
    lane: LaneId,
    seat_revision: Digest,
    slice_revision: Digest,
    capability_policy_digest: Digest,
    context_policy_digest: Digest,
    live_tokens: LiveTokens,
}

impl DeclaredAuthority {
    fn new(published: &Published, lane: &LaneId, live_tokens: LiveTokens) -> Self {
        Self {
            seat: SeatId::new(SEAT).unwrap(),
            slice: SliceId::new(SLICE).unwrap(),
            lane: lane.clone(),
            seat_revision: published.seat_revision,
            slice_revision: published.slice_revision,
            capability_policy_digest: published.capability_policy_digest,
            context_policy_digest: context_policy_digest(
                SEAT,
                SLICE,
                lane.as_str(),
                published.seat_revision,
                published.slice_revision,
            ),
            live_tokens,
        }
    }
}

#[async_trait::async_trait]
impl ConversationAuthority for DeclaredAuthority {
    async fn ensure(
        &self,
        command_id: &CommandId,
        session_id: LiveSessionId,
    ) -> Result<odin_hermes::conversation::EnsuredGeneration, String> {
        let session = SessionId::new(session_id.to_string())
            .map_err(|error| format!("session identity rejected: {error}"))?;
        let issued_at_ms = u64::try_from(now().unix_timestamp_nanos() / 1_000_000).unwrap_or(0);
        let expires_at_ms = issued_at_ms + 3_600_000;
        let issuer = TokenIssuer::new(KEY.to_vec()).map_err(|error| error.to_string())?;
        let token = issuer
            .mint(MintRequest {
                seat: self.seat.clone(),
                slice: self.slice.clone(),
                lane: self.lane.clone(),
                session,
                seat_revision: self.seat_revision,
                slice_revision: self.slice_revision,
                capability_policy_digest: self.capability_policy_digest,
                context_policy_digest: self.context_policy_digest,
                issued_at_ms,
                expires_at_ms,
                entropy: command_id.as_str().as_bytes(),
            })
            .map_err(|error| error.to_string())?;
        let verified_session =
            SessionId::new(session_id.to_string()).map_err(|error| error.to_string())?;
        FreshAuthority::verify(
            &token,
            ExpectedBindings {
                seat: &self.seat,
                slice: &self.slice,
                lane: &self.lane,
                session: &verified_session,
                seat_revision: self.seat_revision,
                slice_revision: self.slice_revision,
                capability_policy_digest: self.capability_policy_digest,
                context_policy_digest: self.context_policy_digest,
            },
            KEY.to_vec(),
            MemoryRevocations::new(),
            issued_at_ms,
        )
        .map_err(|error| format!("published authority is unusable for this session: {error}"))?;
        self.live_tokens
            .lock()
            .insert(SEAT.to_owned(), token.token_id.clone());
        Ok(odin_hermes::conversation::EnsuredGeneration {
            bound: 1,
            current: 1,
            composition: None,
        })
    }
}

/// The durable intake-authority facts: the same readings the daemon binds —
/// the seat's live token must exist and be unrevoked in the shared ledger,
/// and the correlation identity must have no durable stop row. Unreadable
/// state reports revoked/stopped, never admits blindly.
struct LedgerAuthorityFacts {
    ledger: Arc<Mutex<Ledger>>,
    live_tokens: LiveTokens,
}

impl IntakeAuthorityFacts for LedgerAuthorityFacts {
    fn seat_token_revoked(&self, seat: &str) -> bool {
        let Some(token_id) = self.live_tokens.lock().get(seat).cloned() else {
            return true;
        };
        let guard = self.ledger.lock();
        LedgerRevocations::new(&guard)
            .is_revoked(&token_id)
            .unwrap_or(true)
    }

    fn stopped(&self, identity: &str) -> bool {
        let guard = self.ledger.lock();
        odin_ledger::operation::stop_row(guard.connection(), identity)
            .map(|row| row.is_some())
            .unwrap_or(true)
    }
}

// ---------------------------------------------------------------------------
// The conversation plane: the real FsLiveLedger journal, real command
// admission, and the real shared-ledger durable rows the production bridge
// writes on session open (session lane, bridge run, live-session row). Only
// the child actor's replies are scripted.
// ---------------------------------------------------------------------------

struct BridgePlane {
    ledger: FsLiveLedger,
    bridge_ledger: PathBuf,
    lane: LaneId,
    sessions: Mutex<BTreeMap<String, (LiveSessionState, u64, bool)>>,
    prompt_admitted: tokio::sync::Notify,
    gate_armed: std::sync::atomic::AtomicBool,
    gate_open: tokio::sync::Notify,
    history_changed: tokio::sync::Notify,
    prompts: Mutex<Vec<String>>,
}

impl BridgePlane {
    async fn new(live_root: &Path, bridge_ledger: PathBuf, lane: LaneId) -> Self {
        let plane = Self {
            ledger: FsLiveLedger::open(live_root.join("live")).expect("live ledger opens"),
            bridge_ledger,
            lane,
            sessions: Mutex::new(BTreeMap::new()),
            prompt_admitted: tokio::sync::Notify::new(),
            gate_armed: std::sync::atomic::AtomicBool::new(false),
            gate_open: tokio::sync::Notify::new(),
            history_changed: tokio::sync::Notify::new(),
            prompts: Mutex::new(Vec::new()),
        };
        // A fresh daemon over the same live root discovers the durable
        // sessions parked: no live actor anywhere.
        for persisted in plane.ledger.sessions().await.expect("durable sessions") {
            plane
                .sessions
                .lock()
                .entry(persisted.manifest.session_id.to_string())
                .or_insert((LiveSessionState::Idle, persisted.epoch.get(), false));
        }
        plane
    }

    fn manifest(&self, session: LiveSessionId) -> SessionManifest {
        SessionManifest {
            session_id: session,
            seat_id: SeatId::new(SEAT).unwrap(),
            slice_id: SliceId::new(SLICE).unwrap(),
            project_id: ProjectId::new(PROJECT).unwrap(),
            provider: ProviderName::new(PROVIDER).unwrap(),
            model: ModelName::new(MODEL).unwrap(),
            title: None,
            target_node: NodeId::new(NODE).unwrap(),
            open_tab: false,
            workload: None,
            served_revision: None,
            harness: None,
        }
    }

    /// The production bridge's first durable acts for a live session,
    /// mirrored exactly through the public ledger APIs: the session lane,
    /// the `run:live:<session>` bridge run, and the live-session row.
    fn ensure_shared_rows(&self, session: LiveSessionId) {
        let manifest = self.manifest(session);
        let input_hash =
            Digest::hash(&serde_json::to_vec(&manifest).expect("manifest serializes")).to_string();
        let mut ledger = Ledger::open(&self.bridge_ledger).expect("shared ledger opens");
        if read_lane(ledger.connection(), &self.lane)
            .expect("lane readable")
            .is_none()
        {
            create_lane(
                ledger.connection(),
                &NewLane {
                    lane_id: self.lane.clone(),
                    seat_id: SeatId::new(SEAT).unwrap(),
                    project_id: Some(ProjectId::new(PROJECT).unwrap()),
                    template_id: "default".to_owned(),
                    backend: "local_omp".to_owned(),
                    created_by: "live-session".to_owned(),
                    created_at: now(),
                    retained: false,
                },
            )
            .expect("session lane created");
        }
        let run_id = RunId::new(format!("run:live:{session}")).expect("run id");
        if read_run(ledger.connection(), &run_id)
            .expect("run readable")
            .is_none()
        {
            let attempt_number: i64 = ledger
                .connection()
                .query_row(
                    "SELECT COALESCE(MAX(attempt_number), 0) + 1 FROM runs WHERE lane_id = ?1",
                    [self.lane.to_string()],
                    |row| row.get(0),
                )
                .expect("attempt number readable");
            create_run(
                ledger.connection(),
                &NewRun {
                    run_id: run_id.clone(),
                    lane_id: self.lane.clone(),
                    attempt_number,
                    workflow_id: Some(format!("live:{SLICE}")),
                    workflow_version: Some(1),
                    input_hash,
                    accepted_capability_revision: None,
                    lease_id: None,
                    absolute_deadline: None,
                    retry_budget: 0,
                    created_at: now(),
                },
            )
            .expect("bridge run created");
        }
        let session_key = SessionId::new(session.to_string()).expect("session key");
        match ledger.live_session(&session_key) {
            Ok(existing) => {
                ledger
                    .reclaim_live_session(&session_key, existing.epoch, now())
                    .expect("live row reclaimed");
            }
            Err(LedgerError::NotFound { .. }) => {
                ledger
                    .create_live_session(&NewLiveSession {
                        session_id: session_key,
                        seat_id: SEAT.to_owned(),
                        project_id: PROJECT.to_owned(),
                        slice_id: SLICE.to_owned(),
                        lane_id: self.lane.to_string(),
                        target_node_id: NODE.to_owned(),
                        provider: PROVIDER.to_owned(),
                        model: MODEL.to_owned(),
                        title: None,
                        manifest: serde_json::to_value(&manifest).expect("manifest value"),
                        open_tab: false,
                        state: "ready".to_owned(),
                        created_at: now(),
                    })
                    .expect("live row created");
            }
            Err(error) => panic!("live row unreadable: {error}"),
        }
    }

    async fn push_event(&self, session: &LiveSessionId, body: LiveEventBody) {
        let epoch = self
            .sessions
            .lock()
            .get(&session.to_string())
            .copied()
            .expect("known session")
            .1;
        let sequence = self
            .ledger
            .head(*session)
            .await
            .map_err(live_error)
            .expect("head readable")
            .get()
            + 1;
        self.ledger
            .append(
                SessionEpoch::new(epoch),
                NewLiveEvent {
                    session_id: *session,
                    event_id: EventId::new(format!("event-{sequence}")).expect("event id"),
                    occurred_at: now(),
                    body,
                },
            )
            .await
            .map_err(live_error)
            .expect("event appended");
        self.history_changed.notify_waiters();
    }

    fn summary(&self, session: &LiveSessionId, head: EventSeq) -> LiveSessionSummary {
        let (state, epoch, _) = self
            .sessions
            .lock()
            .get(&session.to_string())
            .copied()
            .expect("known session");
        LiveSessionSummary {
            session_id: *session,
            epoch: SessionEpoch::new(epoch),
            seat_id: SeatId::new(SEAT).unwrap(),
            provider: ProviderName::new(PROVIDER).unwrap(),
            model: ModelName::new(MODEL).unwrap(),
            title: None,
            state,
            started_at: now(),
            updated_at: now(),
            failed_at: None,
            event_head: head,
            terminal_head: TerminalSeq::new(0),
            pending_permission_count: 0,
        }
    }
}

#[async_trait::async_trait]
impl ConversationPlane for BridgePlane {
    async fn sessions(&self, query: SessionListQuery) -> Result<SessionListPage, LiveError> {
        let entries: Vec<_> = self
            .sessions
            .lock()
            .iter()
            .map(|(id, (state, _, _))| (id.clone(), *state))
            .collect();
        let mut listed = Vec::new();
        for (id, state) in entries {
            if !query.include_ended
                && matches!(state, LiveSessionState::Ended | LiveSessionState::Failed)
            {
                continue;
            }
            let session = LiveSessionId::parse(&id).expect("session id");
            let head = self.ledger.head(session).await.map_err(live_error)?;
            let mut summary = self.summary(&session, head);
            summary.state = state;
            listed.push(summary);
        }
        Ok(SessionListPage::new(listed, None))
    }

    async fn open_session(
        &self,
        request: OpenSessionRequest,
    ) -> Result<LiveSessionSummary, LiveError> {
        let session = session_id_for(&request.command_id)?;
        self.ledger
            .create_session(self.manifest(session))
            .await
            .ok();
        self.ensure_shared_rows(session);
        let head = self.ledger.head(session).await.map_err(live_error)?;
        {
            let mut sessions = self.sessions.lock();
            let slot =
                sessions
                    .entry(session.to_string())
                    .or_insert((LiveSessionState::Idle, 1, true));
            slot.0 = LiveSessionState::Idle;
            slot.2 = true;
        }
        Ok(self.summary(&session, head))
    }

    async fn command(&self, command: LiveCommand) -> Result<CommandReceipt, LiveError> {
        // REAL journal lookup first: an admitted id replays its stored
        // receipt and never re-executes.
        if let Some(entry) = self.ledger.command(&command).await.map_err(live_error)? {
            return Ok(entry.receipt);
        }
        let parked = !self
            .sessions
            .lock()
            .get(&command.session_id.to_string())
            .map(|(_, _, live)| *live)
            .unwrap_or(false);
        if parked {
            return Err(LiveError::Conflict {
                code: "session_parked".to_owned(),
                message: "the session is parked after a daemon restart".to_owned(),
            });
        }
        let current_epoch = self
            .sessions
            .lock()
            .get(&command.session_id.to_string())
            .map(|(_, epoch, _)| *epoch)
            .unwrap_or(1);
        if command.expected_epoch.get() != current_epoch {
            return Ok(CommandReceipt::Rejected {
                command_id: command.command_id.clone(),
                reason: CommandRejection::EpochMismatch {
                    expected: command.expected_epoch,
                    actual: SessionEpoch::new(current_epoch),
                },
            });
        }
        self.ledger
            .append_command(&command)
            .await
            .map_err(live_error)?;
        let is_prompt = matches!(command.body, LiveCommandBody::Prompt { .. });
        if is_prompt {
            self.prompts.lock().push(command.command_id.to_string());
            self.prompt_admitted.notify_one();
        }
        if let LiveCommandBody::Prompt { message } = command.body {
            self.push_event(&command.session_id, LiveEventBody::UserMessage(message))
                .await;
            // The scripted actor holds its answer until the R3 gate request
            // is on the ledger, exactly as a real turn stays open behind a
            // gate.
            if self
                .gate_armed
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                self.gate_open.notified().await;
            }
            let answer = "I need your approval before sealing anything.".to_owned();
            self.push_event(
                &command.session_id,
                LiveEventBody::AssistantMessage(text_message(&answer)),
            )
            .await;
            self.push_event(
                &command.session_id,
                LiveEventBody::SessionStateChanged(odin_domain::huginn::SessionStateChanged {
                    previous: LiveSessionState::Running,
                    current: LiveSessionState::Idle,
                    reason: None,
                }),
            )
            .await;
            self.sessions
                .lock()
                .get_mut(&command.session_id.to_string())
                .expect("known session")
                .0 = LiveSessionState::Idle;
        }
        Ok(CommandReceipt::Accepted {
            command_id: command.command_id.clone(),
        })
    }

    async fn history(&self, query: HistoryQuery) -> Result<HistoryPage, LiveError> {
        self.ledger.history(query).await.map_err(live_error)
    }

    async fn wait_for_history(
        &self,
        session_id: LiveSessionId,
        after: EventSeq,
    ) -> Result<(), LiveError> {
        loop {
            let notified = self.history_changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.ledger.head(session_id).await.map_err(live_error)? > after {
                return Ok(());
            }
            notified.await;
        }
    }

    async fn recover_session(
        &self,
        session_id: LiveSessionId,
    ) -> Result<LiveSessionSummary, LiveError> {
        let ended = self
            .sessions
            .lock()
            .get(&session_id.to_string())
            .map(|(state, _, _)| *state == LiveSessionState::Ended)
            .unwrap_or(false);
        if ended {
            return Err(LiveError::Conflict {
                code: "session_ended".to_owned(),
                message: "the session is truthfully ended".to_owned(),
            });
        }
        let epoch = self.ledger.reclaim(session_id).await.map_err(live_error)?;
        let head = self
            .ledger
            .head(session_id)
            .await
            .map_err(live_error)
            .unwrap_or(EventSeq::new(0));
        self.ensure_shared_rows(session_id);
        {
            let mut sessions = self.sessions.lock();
            let slot = sessions.entry(session_id.to_string()).or_insert((
                LiveSessionState::Idle,
                epoch.get(),
                true,
            ));
            slot.0 = LiveSessionState::Idle;
            slot.1 = epoch.get();
            slot.2 = true;
        }
        Ok(self.summary(&session_id, head))
    }

    async fn command_entry(
        &self,
        command: &LiveCommand,
    ) -> Result<Option<odin_omp::live::ledger::CommandJournalEntry>, LiveError> {
        self.ledger.command(command).await.map_err(live_error)
    }

    async fn session_manifest_present(&self, session_id: LiveSessionId) -> Result<bool, LiveError> {
        Ok(self.ledger.session(session_id).await.is_ok())
    }
}

fn text_message(text: &str) -> LiveMessage {
    LiveMessage::new(vec![LiveContentBlock::Text(text.to_owned())]).expect("message")
}

// ---------------------------------------------------------------------------
// Link 4: bounded context. The real brain service compiles the vehicle
// session's turn from the published [context] declarations, with the kernel
// listing minted from a verified session authority over the published
// contracts and the on-disk declared schemas.
// ---------------------------------------------------------------------------

struct FileSchemas {
    root: PathBuf,
}

impl SchemaCatalog for FileSchemas {
    fn schema(&self, reference: &str) -> Result<ToolSchema, KernelError> {
        let bytes = std::fs::read(self.root.join(reference))
            .map_err(|error| KernelError::Registry(format!("{reference}: {error}")))?;
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|error| KernelError::Schema(error.to_string()))?;
        ToolSchema::from_value(value).map_err(|error| KernelError::Schema(error.to_string()))
    }
}

/// The fixture's ONE owner identity: a fresh kernel token minted and
/// verified for the exact session against the published revisions, plus
/// the policy context admitting exactly the published contracts. Every
/// kernel call in this test presents this authority.
fn fresh_owner_authority(
    published: &Published,
    lane: &LaneId,
    session: LiveSessionId,
) -> (FreshAuthority, PolicyContext) {
    let context_digest = context_policy_digest(
        SEAT,
        SLICE,
        lane.as_str(),
        published.seat_revision,
        published.slice_revision,
    );
    let issued_at_ms = u64::try_from(now().unix_timestamp_nanos() / 1_000_000).unwrap_or(0);
    let issuer = TokenIssuer::new(KEY.to_vec()).unwrap();
    let token = issuer
        .mint(MintRequest {
            seat: SeatId::new(SEAT).unwrap(),
            slice: SliceId::new(SLICE).unwrap(),
            lane: lane.clone(),
            session: SessionId::new(session.to_string()).unwrap(),
            seat_revision: published.seat_revision,
            slice_revision: published.slice_revision,
            capability_policy_digest: published.capability_policy_digest,
            context_policy_digest: context_digest,
            issued_at_ms,
            expires_at_ms: issued_at_ms + 3_600_000,
            entropy: b"integrated-path",
        })
        .unwrap();
    let fresh = FreshAuthority::verify(
        &token,
        ExpectedBindings {
            seat: &SeatId::new(SEAT).unwrap(),
            slice: &SliceId::new(SLICE).unwrap(),
            lane,
            session: &SessionId::new(session.to_string()).unwrap(),
            seat_revision: published.seat_revision,
            slice_revision: published.slice_revision,
            capability_policy_digest: published.capability_policy_digest,
            context_policy_digest: context_digest,
        },
        KEY.to_vec(),
        MemoryRevocations::new(),
        issued_at_ms,
    )
    .unwrap();
    let allowed: BTreeSet<odin_domain::CapabilityId> =
        published.contracts.keys().cloned().collect();
    let context = PolicyContext {
        seat_id: SeatId::new(SEAT).unwrap(),
        slice_id: SliceId::new(SLICE).unwrap(),
        lane_id: lane.clone(),
        seat_revision: published.seat_revision,
        slice_revision: published.slice_revision,
        capability_policy_digest: published.capability_policy_digest,
        seat_tool_refs: allowed.clone(),
        slice_capabilities: allowed.clone(),
        project_capabilities: allowed.clone(),
        lane_capabilities: allowed,
        denied_capabilities: BTreeSet::new(),
        denied_tools: BTreeSet::new(),
        seat_categories: BTreeSet::from(["coordinator".to_owned()]),
        adapter_health: odin_kernel::AdapterHealth::default(),
        resource_constraints: BTreeMap::new(),
        seat_hints: BTreeMap::new(),
    };
    (fresh, context)
}

fn compose_session_brain(published: &Published, store_root: &Path, session: LiveSessionId) {
    let slice = published
        .registry
        .iter()
        .find_map(|object| match &object.config {
            ObjectConfig::Slice(slice) if object.id == SLICE => Some(slice.clone()),
            _ => None,
        })
        .expect("declared slice");
    let seat = published
        .registry
        .iter()
        .find_map(|object| match &object.config {
            ObjectConfig::Seat(seat) if object.id == SEAT => Some(seat.clone()),
            _ => None,
        })
        .expect("declared seat");
    let model = ModelDescriptor {
        name: ModelName::new(MODEL).unwrap(),
        tokenizer: PinnedTokenizer::id().unwrap(),
        context_window_tokens: NonZeroU32::new(32_768).unwrap(),
    };
    let harbor = published
        .registry
        .iter()
        .find_map(|object| match &object.config {
            ObjectConfig::Project(project) if object.id == PROJECT => {
                Some(project.as_ref().clone())
            }
            _ => None,
        })
        .expect("declared project");
    let projects = std::collections::BTreeMap::from([(PROJECT, &harbor)]);
    let policy = EffectiveBrainPolicy::resolve(
        1,
        &slice,
        &seat,
        &projects,
        &odin_registry::context_profiles(&published.registry),
        &model,
    )
    .expect("published policy resolves");
    let _context_policy = policy.context.clone().expect("the declared context policy");
    let _service = BrainService::open(
        BrainServiceConfig {
            store_root: store_root.to_path_buf(),
            sources: BTreeMap::new(),
            embedding_available: false,
            embedding_model: None,
            archive_ingest_gate: None,
            postgres: None,
        },
        policy,
        Arc::new(std::sync::Mutex::new(Ledger::open_in_memory().unwrap())),
    )
    .expect("brain service opens");
    let lane = LaneId::new(LANE).unwrap();
    let (fresh, context) = fresh_owner_authority(published, &lane, session);
    let issued_at_ms = u64::try_from(now().unix_timestamp_nanos() / 1_000_000).unwrap_or(0);
    let listing = list_capabilities(
        fresh.get(),
        &context,
        &published.contracts,
        &FileSchemas {
            root: published.root.path().to_path_buf(),
        },
        issued_at_ms,
    )
    .expect("kernel lists the published capabilities");
    let tool_names: Vec<String> = listing
        .tools
        .iter()
        .map(|tool| tool.tool_name.to_string())
        .collect();
    for expected in ["task_read", "seat_ask_warden", "capsule_file_edit"] {
        assert!(
            tool_names.iter().any(|name| *name == expected),
            "the published capability {expected} must surface in the model listing: {tool_names:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// The one connected path.
// ---------------------------------------------------------------------------

fn hermes_ledgers_in_memory() -> HermesLedgers {
    HermesLedgers {
        conversation: Ledger::open_in_memory().unwrap(),
        adapter: Arc::new(Mutex::new(Ledger::open_in_memory().unwrap())),
        purchase: Arc::new(std::sync::Mutex::new(Ledger::open_in_memory().unwrap())),
    }
}

fn discord_settings() -> DiscordSettings {
    DiscordSettings::new(
        SEAT,
        PROJECT,
        OWNER,
        CHANNEL,
        CAP_INTAKE,
        4,
        4096,
        "discord-bot-token",
        BTreeSet::new(),
        3600,
    )
    .unwrap()
}

fn transport_to(api_base: &str) -> DiscordRestTransport {
    DiscordRestTransport::with_api_base(
        DiscordCredential::token(
            odin_domain::huginn::OpaqueCredentialHandle::new("cred:discord.bot").unwrap(),
            SecretToken::new("fixture-bot-secret").unwrap(),
        ),
        reqwest::Client::new(),
        api_base.to_owned(),
    )
    .unwrap()
}

struct CapturedRequest {
    channel_id: String,
    authorization: String,
    body: Value,
}

/// The loopback stand-in for the pinned Discord REST endpoint: it records
/// every authenticated post and answers with a real, strictly increasing
/// posted-message id, so the decision path's causal ordering runs against
/// honest transport identities.
async fn spawn_capture_server() -> (String, Arc<Mutex<Vec<CapturedRequest>>>) {
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
    let captured: Arc<Mutex<Vec<CapturedRequest>>> = Arc::new(Mutex::new(Vec::new()));
    let state = captured.clone();
    let next_id = Arc::new(AtomicU64::new(3_000_000_000_000_000_000));
    let app = axum::Router::new().route(
        "/channels/{channel_id}/messages",
        axum::routing::post(
            move |axum::extract::Path(channel_id): axum::extract::Path<String>,
                  headers: axum::http::HeaderMap,
                  axum::Json(body): axum::Json<Value>| {
                let state = state.clone();
                let next_id = next_id.clone();
                async move {
                    let id = next_id.fetch_add(1, AtomicOrdering::SeqCst).to_string();
                    state.lock().push(CapturedRequest {
                        channel_id: channel_id.clone(),
                        authorization: headers
                            .get("authorization")
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or_default()
                            .to_owned(),
                        body,
                    });
                    axum::Json(json!({ "id": id, "channel_id": channel_id }))
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    (format!("http://{address}"), captured)
}
