use super::*;
use parking_lot::Mutex;

// Route effects are invoked inside the real kernel dispatch boundary; no
// PreparedEffect constructor or authorization bypass is exposed for tests.
fn dispatch_effect<F>(action: F) -> Result<ClaudeSessionRecord, HostToolError>
where
    F: FnOnce(&odin_kernel::PreparedEffect) -> Result<ClaudeSessionRecord, HostToolError>
        + Send
        + 'static,
{
    use odin_domain::knowledge::{ToolName, ToolSchema};
    use odin_domain::{
        CapabilityId, CommandId, Digest, EffectClass, LaneId, PlanId, SeatId, SessionId, SliceId,
    };
    use odin_kernel::token::{
        ExpectedBindings, FreshAuthority, MemoryRevocations, MintRequest, TokenIssuer,
    };
    use odin_kernel::*;
    use std::collections::BTreeSet;
    use std::num::NonZeroU32;

    struct Catalog(AdmittedCapability);
    impl OperationCatalog for Catalog {
        fn admitted(&self, id: &CapabilityId) -> Option<AdmittedCapability> {
            (id == &self.0.contract.id).then(|| self.0.clone())
        }
        fn resolves(&self, binding: &HandlerBinding) -> bool {
            matches!(binding, HandlerBinding::Builtin { name } if name == "route_test")
        }
    }
    struct Schemas(ToolSchema);
    impl SchemaCatalog for Schemas {
        fn schema(&self, _: &str) -> KernelResult<ToolSchema> {
            Ok(self.0.clone())
        }
    }
    struct Executor<F> {
        action: Mutex<Option<F>>,
        result: Mutex<Option<Result<ClaudeSessionRecord, HostToolError>>>,
    }
    impl<F> OperationExecutor for Executor<F>
    where
        F: FnOnce(&PreparedEffect) -> Result<ClaudeSessionRecord, HostToolError> + Send,
    {
        fn id(&self) -> &'static str {
            PreparedEffect::OMP_HOST_EXECUTOR
        }
        fn declared_pre_world(
            &self,
            _: &CapabilityContract,
            _: &Payload,
        ) -> Result<Option<PreWorld>, ExecutorFault> {
            Ok(Some(PreWorld::Absent))
        }
        fn observe(&self, _: &CapabilityContract, _: &Payload) -> Result<PreWorld, ExecutorFault> {
            Ok(PreWorld::Absent)
        }
        fn expected_post_world(
            &self,
            _: &CapabilityContract,
            _: &Payload,
        ) -> Result<Option<Digest>, ExecutorFault> {
            Ok(None)
        }
        fn execute(&self, effect: PreparedEffect) -> Result<EffectOutcome, ExecutorFault> {
            let result = self.action.lock().take().unwrap()(&effect);
            let digest = Digest::hash(format!("{result:?}").as_bytes());
            let succeeded = result.is_ok();
            *self.result.lock() = Some(result);
            if succeeded {
                Ok(EffectOutcome {
                    post_world: None,
                    evidence_digest: digest,
                    stop: None,
                })
            } else {
                Err(ExecutorFault::Uncertain {
                    detail: "route result retained by test executor".into(),
                })
            }
        }
    }
    let contract = CapabilityContract {
        id: CapabilityId::new("test.claude_route").unwrap(),
        toolset: None,
        op: None,
        expose: None,
        seat_ops: Default::default(),
        delegate_to: None,
        version: 1,
        tool_name: ToolName::new("test_claude_route").unwrap(),
        description: "Route lifecycle fixture".into(),
        handler: HandlerBinding::Builtin {
            name: "route_test".into(),
        },
        input_schema_ref: "schemas/capability/test.input.json".into(),
        output_schema_ref: "schemas/capability/test.output.json".into(),
        effect_class: EffectClass::R1,
        seat_tags: BTreeSet::from(["builder".into()]),
        timeout_seconds: NonZeroU32::new(5).unwrap(),
        idempotency: IdempotencyPolicy::Required,
        retry: RetryPolicy { max_attempts: 1 },
        approval: ApprovalRequirement::None,
        evidence_extractor: HandlerBinding::Builtin {
            name: "route_test".into(),
        },
        adapter: None,
        preview: None,
        batchable: false,
        batch: None,
    };
    let seat = SeatId::new("seat.test").unwrap();
    let slice = SliceId::new("slice.test").unwrap();
    let lane = LaneId::new("lane.test").unwrap();
    let session = SessionId::new("00000000-0000-4000-8000-000000000001").unwrap();
    let bindings = ExpectedBindings {
        seat: &seat,
        slice: &slice,
        lane: &lane,
        session: &session,
        seat_revision: Digest::hash(b"seat"),
        slice_revision: Digest::hash(b"slice"),
        capability_policy_digest: Digest::hash(b"policy"),
        context_policy_digest: Digest::hash(b"context"),
    };
    let key = b"route regression signing key".to_vec();
    let token = TokenIssuer::new(key.clone())
        .unwrap()
        .mint(MintRequest {
            seat: seat.clone(),
            slice: slice.clone(),
            lane: lane.clone(),
            session: session.clone(),
            seat_revision: bindings.seat_revision,
            slice_revision: bindings.slice_revision,
            capability_policy_digest: bindings.capability_policy_digest,
            context_policy_digest: bindings.context_policy_digest,
            issued_at_ms: 0,
            expires_at_ms: 1_000,
            entropy: b"route-test",
        })
        .unwrap();
    let allowed = BTreeSet::from([contract.id.clone()]);
    let context = PolicyContext {
        seat_id: seat.clone(),
        slice_id: slice.clone(),
        lane_id: lane.clone(),
        seat_revision: bindings.seat_revision,
        slice_revision: bindings.slice_revision,
        capability_policy_digest: bindings.capability_policy_digest,
        seat_tool_refs: allowed.clone(),
        slice_capabilities: allowed.clone(),
        project_capabilities: allowed.clone(),
        lane_capabilities: allowed,
        denied_capabilities: BTreeSet::new(),
        denied_tools: BTreeSet::new(),
        seat_categories: BTreeSet::from(["builder".into()]),
        adapter_health: AdapterHealth::default(),
        resource_constraints: BTreeMap::new(),
        seat_hints: BTreeMap::new(),
    };
    let fresh =
        FreshAuthority::verify(&token, bindings, key, MemoryRevocations::new(), 20).unwrap();
    let contracts = BTreeMap::from([(contract.id.clone(), contract.clone())]);
    let schemas = Arc::new(Schemas(
        ToolSchema::from_value(json!({"type":"object", "additionalProperties": false})).unwrap(),
    ));
    let listing =
        list_capabilities(fresh.get(), &context, &contracts, schemas.as_ref(), 20).unwrap();
    let arguments = json!({});
    let invocation = ToolInvocation {
        command_id: CommandId::new("command.route").unwrap(),
        capability_id: contract.id.clone(),
        capability_version: contract.version,
        listing_digest: listing.digest,
        arguments: arguments.clone(),
        arguments_digest: arguments_digest(&arguments),
        target: InvocationTarget {
            kind: "capsule".into(),
            id: "capsule-test".into(),
        },
        executor_binding: None,
        expected_revision: None,
        plan_id: Some(PlanId::new("plan.route").unwrap()),
        approval_id: None,
        resource: None,
    };
    let mut approvals = odin_ledger::Ledger::open_in_memory().unwrap();
    let authorized = match authorize(
        policy::AuthorizationEnvironment {
            authority: fresh.get(),
            policy: &context,
            contracts: &contracts,
            schemas: schemas.as_ref(),
            listing: &listing,
        },
        &invocation,
        PlanGate::Accepted,
        &mut ApprovalGate::new(&mut approvals),
        20,
    )
    .unwrap()
    {
        AuthorizationOutcome::Authorized(value) => *value,
        AuthorizationOutcome::Rejected(reason) => panic!("test authority refused: {reason:?}"),
    };
    let executor = Arc::new(Executor {
        action: Mutex::new(Some(action)),
        result: Mutex::new(None),
    });
    let authority = OperationAuthority::new(
        Arc::new(Catalog(AdmittedCapability {
            contract,
            snapshot_revision: 1,
            snapshot_digest: Digest::hash(b"policy"),
        })),
        schemas,
        executor.clone(),
        odin_domain::operation::Limits::new(10, 10, 10_000),
        Arc::new(|| 20),
        Arc::new(std::sync::Mutex::new(
            odin_ledger::Ledger::open_in_memory().unwrap(),
        )),
    );
    let _decision = authority.invoke_authorized(
        authorized,
        &InvokeRequest {
            capsule_id: odin_types::CapsuleId::new("capsule-test").unwrap(),
            correlation_id: odin_types::CorrelationId::new("00000000000000000000000000000001")
                .unwrap(),
            requested_ceiling: odin_domain::operation::RequestCost {
                requests: 1,
                stops: 0,
                spend: 0,
            },
        },
    );
    let result = executor
        .result
        .lock()
        .take()
        .expect("real kernel dispatch must execute route fixture");
    result
}

#[derive(Default)]
struct FakeState {
    opens: Vec<ClaudeSessionRecord>,
    stops: Vec<(ClaudeSessionRecord, bool)>,
    prompts: usize,
    reads: usize,
    transcript_reads: usize,
    uncertain_open: bool,
    uncertain_stop: bool,
    unpushed: bool,
    events: Vec<Value>,
    presence: CarrierPresence,
    read_error: Option<String>,
}

/// A test-only backend with a per-UUID journal independent of the route store.
/// Partial failures leave that journal recoverable by a fresh backend instance.
struct FakeBackend {
    root: PathBuf,
    state: Mutex<FakeState>,
}

impl FakeBackend {
    fn new(root: PathBuf) -> Arc<Self> {
        fs::create_dir_all(&root).unwrap();
        Arc::new(Self {
            root,
            state: Mutex::new(FakeState::default()),
        })
    }

    fn journal(&self, id: &str) -> PathBuf {
        self.root.join(format!("{id}.json"))
    }

    fn resource(id: &str) -> Value {
        json!({"journal_session": id, "pod_uid": format!("fake-pod-{id}")})
    }
}

impl ClaudeSessionBackend for FakeBackend {
    fn preflight(&self, _: &ClaudeOpenRequest) -> Result<(), HostToolError> {
        Ok(())
    }

    fn resolve(&self, request: &ClaudeOpenRequest) -> Result<ClaudeOpenRequest, HostToolError> {
        let mut request = request.clone();
        if request.preset.as_deref() == Some("normal") {
            request.placement = Some(ClaudePlacement::HostTab);
            request.skip_permissions = Some(true);
            if request.account.is_empty() {
                request.account = "test-default-account".into();
            }
        } else {
            request.placement = Some(request.placement.unwrap_or_default());
            request.skip_permissions = Some(request.skip_permissions.unwrap_or(false));
        }
        Ok(request)
    }

    fn open(
        &self,
        _: &odin_kernel::PreparedEffect,
        session: &ClaudeSessionRecord,
    ) -> Result<ClaudeBackendOutcome, HostToolError> {
        let mut state = self.state.lock();
        state.opens.push(session.clone());
        assert_eq!(session.state, ClaudeSessionState::Opening);
        assert!(
            !self.journal(&session.session).exists(),
            "launch must not replay"
        );
        let resource = Self::resource(&session.session);
        fs::write(
            self.journal(&session.session),
            serde_json::to_vec(&resource).unwrap(),
        )
        .unwrap();
        if std::mem::take(&mut state.uncertain_open) {
            return Err(uncertain("fake launch receipt lost after journal creation"));
        }
        Ok(ClaudeBackendOutcome {
            resource: Some(resource),
            ..Default::default()
        })
    }

    fn prompt(
        &self,
        _: &odin_kernel::PreparedEffect,
        _: &ClaudeSessionRecord,
        _: &str,
    ) -> Result<ClaudeBackendOutcome, HostToolError> {
        self.state.lock().prompts += 1;
        Ok(ClaudeBackendOutcome::default())
    }

    fn read(&self, _: &ClaudeSessionRecord) -> Result<ClaudeBackendOutcome, HostToolError> {
        let mut state = self.state.lock();
        state.reads += 1;
        if let Some(error) = state.read_error.clone() {
            return Err(uncertain(error));
        }
        Ok(ClaudeBackendOutcome {
            events: state.events.clone(),
            ..Default::default()
        })
    }

    fn read_transcript(
        &self,
        session: &ClaudeSessionRecord,
    ) -> Result<ClaudeBackendOutcome, HostToolError> {
        self.state.lock().transcript_reads += 1;
        self.read(session)
    }

    fn stop(
        &self,
        _: &odin_kernel::PreparedEffect,
        session: &ClaudeSessionRecord,
        discard: bool,
    ) -> Result<ClaudeBackendOutcome, HostToolError> {
        let mut state = self.state.lock();
        state.stops.push((session.clone(), discard));
        assert_eq!(session.state, ClaudeSessionState::Stopping);
        let path = self.journal(&session.session);
        if !path.exists() {
            assert!(
                session.resource.is_none(),
                "missing journal cannot disprove a received resource"
            );
            return Ok(ClaudeBackendOutcome {
                events: vec![json!({"no_effect": true, "journal_session": session.session})],
                ..Default::default()
            });
        }
        let resource: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(resource, Self::resource(&session.session));
        if let Some(receipt) = &session.resource {
            assert_eq!(
                receipt, &resource,
                "stop must use the exact journal identity"
            );
        }
        if state.unpushed && !discard {
            return Err(refused("fake backend has unpushed commits"));
        }
        if std::mem::take(&mut state.uncertain_stop) {
            return Err(uncertain("fake stop acknowledgement lost"));
        }
        fs::remove_file(path).unwrap();
        Ok(ClaudeBackendOutcome {
            resource: Some(resource),
            ..Default::default()
        })
    }

    fn carrier_presence(&self, _: &ClaudeSessionRecord) -> CarrierPresence {
        self.state.lock().presence
    }
}

fn scope(run: &str) -> Scope {
    Scope {
        run: Some(odin_domain::RunId::new(run).unwrap()),
        project: Some(odin_domain::ProjectId::new("rig").unwrap()),
        seat: Some("gungnir".parse().unwrap()),
        lane: Some("gungnir-rig".parse().unwrap()),
        ..Scope::default()
    }
}

fn request() -> ClaudeOpenRequest {
    ClaudeOpenRequest {
        model: None,
        account: "test-account".into(),
        project: "rig".into(),
        placement: None,
        mcp: Vec::new(),
        name: Some("regression".into()),
        host: None,
        skip_permissions: None,
        preset: None,
        dir: None,
    }
}

struct TestRoute(Arc<DaemonClaudeSessionRoute>);

impl std::ops::Deref for TestRoute {
    type Target = DaemonClaudeSessionRoute;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TestRoute {
    fn open(
        &self,
        scope: Scope,
        request: ClaudeOpenRequest,
    ) -> Result<ClaudeSessionRecord, HostToolError> {
        let route = self.0.clone();
        dispatch_effect(move |effect| route.open(effect, scope, request))
    }
    fn prompt(
        &self,
        scope: Scope,
        request: ClaudePromptRequest,
    ) -> Result<ClaudeSessionRecord, HostToolError> {
        let route = self.0.clone();
        dispatch_effect(move |effect| route.prompt(effect, scope, request))
    }
    fn stop(
        &self,
        scope: Scope,
        request: ClaudeStopRequest,
    ) -> Result<ClaudeSessionRecord, HostToolError> {
        let route = self.0.clone();
        dispatch_effect(move |effect| route.stop(effect, scope, request))
    }
}

// Publish copied declarations using the existing committed-worktree fixture
// path; admission tests therefore exercise real seat/lane/project semantics.
pub(crate) fn registry_pin(root: &Path) -> Arc<odin_registry::SnapshotHandle> {
    let store = odin_registry::SnapshotStore::new(root.join("registry-snapshot.json"));
    if !root.join("registry-snapshot.json").exists() {
        let repository = root.join("registry-fixture");
        fs::create_dir_all(&repository).unwrap();
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for tree in ["registry", "schemas"] {
            crate::test_fixture::copy_tree(&source.join(tree), &repository.join(tree));
        }
        crate::test_support::git(
            &repository,
            &["-c", "init.defaultBranch=main", "init", "--quiet"],
        );
        let commit =
            crate::test_support::commit_all(&repository, "Claude session registry fixture");
        let candidate = odin_registry::ValidatedSnapshotCandidate::from_committed_worktree(
            &repository,
            &commit,
            odin_cli::runtime_bindings::admitted_registry_bindings(),
        )
        .unwrap();
        store.publish_committed(&candidate, 1).unwrap();
    }
    Arc::new(odin_registry::SnapshotHandle::open(store).unwrap())
}

fn route(root: &Path, backend: &Arc<FakeBackend>) -> TestRoute {
    TestRoute(Arc::new(
        DaemonClaudeSessionRoute::new(
            root,
            backend.clone(),
            backend.clone(),
            Arc::new(MaterializedReadModel::new(
                32,
                time::OffsetDateTime::UNIX_EPOCH,
            )),
            registry_pin(root),
            None,
        )
        .unwrap(),
    ))
}

fn stored(route: &DaemonClaudeSessionRoute, id: &str) -> StoredSession {
    serde_json::from_slice(&fs::read(route.root.join(format!("{id}.json"))).unwrap()).unwrap()
}

fn read_request(id: &str, since: Option<u64>) -> ClaudeReadRequest {
    ClaudeReadRequest {
        session: id.into(),
        since,
    }
}

fn stop_request(id: &str, discard: bool) -> ClaudeStopRequest {
    ClaudeStopRequest {
        session: id.into(),
        discard_unpushed: discard,
    }
}

#[test]
fn cross_project_open_is_refused_before_launch_or_durable_intent() {
    let dir = tempfile::tempdir().unwrap();
    let backend = FakeBackend::new(dir.path().join("backend"));
    let route = route(dir.path(), &backend);
    let mut cross_project = request();
    cross_project.project = "odin".into();
    assert!(route
        .preflight_open(&scope("owner-run"), &cross_project)
        .is_err());
    assert!(route.open(scope("owner-run"), cross_project).is_err());
    assert!(backend.state.lock().opens.is_empty());
    assert_eq!(fs::read_dir(&route.root).unwrap().count(), 0);
}

#[test]
fn restart_preserves_owner_and_refuses_other_callers_before_backend_effects() {
    let dir = tempfile::tempdir().unwrap();
    let backend = FakeBackend::new(dir.path().join("backend"));
    let first = route(dir.path(), &backend);
    let opened = first.open(scope("owner-run"), request()).unwrap();
    drop(first);
    let restarted = route(dir.path(), &backend);
    let intruder = scope("other-run");
    assert!(matches!(
        restarted.read(intruder.clone(), read_request(&opened.session, None)),
        Err(HostToolError::Scope { .. })
    ));
    assert!(matches!(
        restarted.prompt(
            intruder.clone(),
            ClaudePromptRequest {
                session: opened.session.clone(),
                text: "do work".into()
            }
        ),
        Err(HostToolError::Scope { .. })
    ));
    assert!(matches!(
        restarted.stop(intruder, stop_request(&opened.session, true)),
        Err(HostToolError::Scope { .. })
    ));
    assert!(matches!(
        restarted.read(Scope::default(), read_request(&opened.session, None)),
        Err(HostToolError::Scope { .. })
    ));
    assert_eq!(stored(&restarted, &opened.session).session, opened);
    let state = backend.state.lock();
    assert_eq!(state.opens.len(), 1);
    assert_eq!(state.reads, 0);
    assert_eq!(state.prompts, 0);
    assert!(state.stops.is_empty());
}

#[test]
fn duplicate_open_uses_same_receipt_before_and_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let backend = FakeBackend::new(dir.path().join("backend"));
    let first = route(dir.path(), &backend);
    let opened = first.open(scope("owner-run"), request()).unwrap();
    assert_eq!(first.open(scope("owner-run"), request()).unwrap(), opened);
    drop(first);
    let restarted = route(dir.path(), &backend);
    let mut explicit = request();
    explicit.placement = Some(ClaudePlacement::Pod);
    assert_eq!(
        restarted.open(scope("owner-run"), explicit).unwrap(),
        opened
    );
    assert_eq!(backend.state.lock().opens.len(), 1);
}

#[test]
fn partial_open_survives_restart_without_relaunch_and_stop_recovers_journal() {
    let dir = tempfile::tempdir().unwrap();
    let journal_root = dir.path().join("backend");
    let backend = FakeBackend::new(journal_root.clone());
    backend.state.lock().uncertain_open = true;
    let first = route(dir.path(), &backend);
    assert!(matches!(
        first.open(scope("owner-run"), request()),
        Err(HostToolError::Uncertain { .. })
    ));
    let id = backend.state.lock().opens[0].session.clone();
    let partial = stored(&first, &id).session;
    assert_eq!(partial.state, ClaudeSessionState::InDoubt);
    assert!(partial.resource.is_none());
    assert!(partial.last_error.is_some());
    assert!(backend.journal(&id).exists());
    drop(first);
    drop(backend);
    let backend = FakeBackend::new(journal_root);
    let restarted = route(dir.path(), &backend);
    assert_eq!(stored(&restarted, &id).session, partial);
    assert!(matches!(
        restarted.open(scope("owner-run"), request()),
        Err(HostToolError::Uncertain { .. })
    ));
    assert!(backend.state.lock().opens.is_empty());
    let stopped = restarted
        .stop(scope("owner-run"), stop_request(&id, false))
        .unwrap();
    assert_eq!(stopped.session, id);
    assert_eq!(stopped.state, ClaudeSessionState::Stopped);
    assert_eq!(stopped.resource, Some(FakeBackend::resource(&id)));
    assert!(!backend.journal(&id).exists());
    let state = backend.state.lock();
    assert_eq!(state.stops.len(), 1);
    assert_eq!(state.stops[0].0.session, id);
    assert!(state.stops[0].0.resource.is_none());
}

#[test]
fn unpushed_refusal_preserves_running_resource_until_explicit_override() {
    let dir = tempfile::tempdir().unwrap();
    let backend = FakeBackend::new(dir.path().join("backend"));
    let first = route(dir.path(), &backend);
    let opened = first.open(scope("owner-run"), request()).unwrap();
    backend.state.lock().unpushed = true;
    assert!(matches!(
        first.stop(scope("owner-run"), stop_request(&opened.session, false)),
        Err(HostToolError::Arguments { .. })
    ));
    let refused = stored(&first, &opened.session).session;
    assert_eq!(refused.state, ClaudeSessionState::Running);
    assert_eq!(refused.resource, opened.resource);
    assert!(backend.journal(&opened.session).exists());
    drop(first);
    let restarted = route(dir.path(), &backend);
    assert_eq!(stored(&restarted, &opened.session).session, refused);
    let stopped = restarted
        .stop(scope("owner-run"), stop_request(&opened.session, true))
        .unwrap();
    assert_eq!(stopped.state, ClaudeSessionState::Stopped);
    assert_eq!(stopped.resource, opened.resource);
    assert!(!backend.journal(&opened.session).exists());
    let state = backend.state.lock();
    assert_eq!(state.stops.len(), 2);
    assert!(!state.stops[0].1);
    assert!(state.stops[1].1);
}

#[test]
fn a_prompt_reaches_the_running_pod_once_and_an_empty_one_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let backend = FakeBackend::new(dir.path().join("backend"));
    let route = route(dir.path(), &backend);
    let opened = route.open(scope("owner-run"), request()).unwrap();
    let prompt = |text: &str| ClaudePromptRequest {
        session: opened.session.clone(),
        text: text.into(),
    };
    assert!(matches!(
        route.prompt(scope("owner-run"), prompt("  ")),
        Err(HostToolError::Arguments { .. })
    ));
    assert_eq!(
        backend.state.lock().prompts,
        0,
        "an empty prompt is never sent"
    );
    let prompted = route
        .prompt(scope("owner-run"), prompt("do the work"))
        .unwrap();
    assert_eq!(prompted.state, ClaudeSessionState::Running);
    assert_eq!(backend.state.lock().prompts, 1);
}

#[test]
fn host_prompt_refusal_does_not_mutate_session_or_call_backend() {
    let dir = tempfile::tempdir().unwrap();
    let backend = FakeBackend::new(dir.path().join("backend"));
    let route = route(dir.path(), &backend);
    let mut request = request();
    request.placement = Some(ClaudePlacement::HostTab);
    request.host = Some("declared-host".into());
    let opened = route.open(scope("owner-run"), request).unwrap();
    let prompt = ClaudePromptRequest {
        session: opened.session.clone(),
        text: "do not type this".into(),
    };
    assert!(matches!(
        route.preflight_prompt(&scope("owner-run"), &prompt),
        Err(HostToolError::Arguments { .. })
    ));
    assert!(matches!(
        route.prompt(scope("owner-run"), prompt),
        Err(HostToolError::Arguments { .. })
    ));
    assert_eq!(stored(&route, &opened.session).session, opened);
    assert_eq!(backend.state.lock().prompts, 0);
}

#[test]
fn crash_after_open_intent_before_backend_is_reconciled_then_reopened() {
    let dir = tempfile::tempdir().unwrap();
    let backend = FakeBackend::new(dir.path().join("backend"));
    let first = route(dir.path(), &backend);
    let id = uuid::Uuid::new_v4().to_string();
    let mut intent = StoredSession {
        session: ClaudeSessionRecord {
            session: id.clone(),
            request: backend.resolve(&request()).unwrap(),
            owner_run: "owner-run".into(),
            seat: None,
            lane: None,
            state: ClaudeSessionState::Opening,
            resource: None,
            claude_session_id: None,
            remote_control: None,
            cursor: 0,
            last_error: None,
            last_driver_cursor: None,
            last_publication_cursor: None,
        },
        events: Vec::new(),
        observed_at: time::OffsetDateTime::now_utc(),
        ended_at: None,
        needs_persist: false,
    };
    intent.event("opening", json!({})).unwrap();
    first.persist(&mut intent).unwrap();
    drop(first);
    let restarted = route(dir.path(), &backend);
    assert_eq!(
        stored(&restarted, &id).session.state,
        ClaudeSessionState::InDoubt
    );
    assert!(matches!(
        restarted.open(scope("owner-run"), request()),
        Err(HostToolError::Uncertain { .. })
    ));
    assert!(backend.state.lock().opens.is_empty());
    let stopped = restarted
        .stop(scope("owner-run"), stop_request(&id, false))
        .unwrap();
    assert_eq!(stopped.state, ClaudeSessionState::Stopped);
    assert!(stopped.resource.is_none());
    let reopened = restarted.open(scope("owner-run"), request()).unwrap();
    assert_ne!(reopened.session, id);
    assert_eq!(reopened.state, ClaudeSessionState::Running);
    assert_eq!(backend.state.lock().opens.len(), 1);
}

#[test]
fn owner_transcript_uses_the_existing_projection_and_agent_reads_remain_scoped() {
    let dir = tempfile::tempdir().unwrap();
    let backend = FakeBackend::new(dir.path().join("backend"));
    let route = route(dir.path(), &backend);
    let session = route.open(scope("owner-run"), request()).unwrap();
    backend.state.lock().events = vec![json!({
        "type":"assistant", "driver_cursor":100,
        "message":{"role":"assistant","content":"verified transcript"}
    })];
    route.refresh_observations().unwrap();
    assert_eq!(backend.state.lock().transcript_reads, 0);
    let page = route
        .read_owner(ClaudeReadRequest {
            session: session.session.clone(),
            since: None,
        })
        .unwrap();
    assert_eq!(backend.state.lock().transcript_reads, 1);
    assert!(page
        .events
        .iter()
        .any(|event| event.payload.get("driver_cursor") == Some(&json!(100))));
    let next = route
        .read_owner(ClaudeReadRequest {
            session: session.session.clone(),
            since: Some(page.next_cursor),
        })
        .unwrap();
    assert!(
        next.events.is_empty(),
        "the durable driver cursor deduplicates a repeated host page"
    );
    let mut other = scope("other-run");
    other.seat = Some("reginn".parse().unwrap());
    assert!(route
        .read(
            other,
            ClaudeReadRequest {
                session: session.session.clone(),
                since: None
            }
        )
        .is_err());
    assert!(route
        .read_owner(ClaudeReadRequest {
            session: session.session,
            since: Some(u64::MAX)
        })
        .is_err());
    assert!(route
        .read_owner(ClaudeReadRequest {
            session: "unknown".into(),
            since: None
        })
        .is_err());
}

#[test]
fn successful_stop_allows_fresh_open_with_new_identity() {
    let dir = tempfile::tempdir().unwrap();
    let backend = FakeBackend::new(dir.path().join("backend"));
    let route = route(dir.path(), &backend);
    let first = route.open(scope("owner-run"), request()).unwrap();
    route
        .stop(scope("owner-run"), stop_request(&first.session, false))
        .unwrap();
    let second = route.open(scope("owner-run"), request()).unwrap();
    assert_ne!(second.session, first.session);
    assert_eq!(second.state, ClaudeSessionState::Running);
    assert_eq!(backend.state.lock().opens.len(), 2);
}
