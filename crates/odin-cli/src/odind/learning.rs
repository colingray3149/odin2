//! The odind brain ports: the pre-IO vault scoping gate and the delegated
//! task review hook. Each is a daemon-owned port over the per-seat brain
//! services and the live-session manifests; live.rs composes them.

use std::collections::BTreeMap;
use std::sync::Arc;

use odin_domain::{SeatId, SessionId};

/// The pre-write vault scoping gate composed by the daemon: the per-seat
/// brain services plus the durable live-session manifests it resolves the
/// writing session's declared project against.
pub(crate) struct FactoryVaultWriteGate {
    brains: BTreeMap<SeatId, Arc<odin_brain::service::BrainService>>,
    live_ledger: Arc<dyn odin_omp::live::ledger::LiveLedger>,
    generated_namespace: Option<String>,
}

impl FactoryVaultWriteGate {
    pub(crate) fn new(
        brains: BTreeMap<SeatId, Arc<odin_brain::service::BrainService>>,
        live_ledger: Arc<dyn odin_omp::live::ledger::LiveLedger>,
        generated_namespace: Option<String>,
    ) -> Self {
        Self {
            brains,
            live_ledger,
            generated_namespace,
        }
    }
}

/// Before vault IO, require exactly one reachable memory namespace for the
/// session's project and require the destination source id to match it.
impl odin_hermes::vault::VaultWriteGate for FactoryVaultWriteGate {
    fn gate_generated_write(
        &self,
        seat: &SeatId,
        session: &SessionId,
        source_id: &str,
        page_name: &str,
    ) -> Result<(), odin_brain::error::BrainError> {
        let brain =
            self.brains
                .get(seat)
                .ok_or_else(|| odin_brain::error::BrainError::Unavailable {
                    component: "learning",
                    reason: format!(
                        "seat {} serves no brain service; nothing is declared to write",
                        seat.as_str()
                    ),
                })?;
        let live_session = odin_domain::huginn::ids::LiveSessionId::parse(&session.to_string())
            .map_err(|error| odin_brain::error::BrainError::InvalidRequest(error.to_string()))?;
        let project = {
            let resolve = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| {
                    odin_brain::error::BrainError::InvalidRequest(error.to_string())
                })?;
            resolve.block_on(async {
                self.live_ledger
                    .session(live_session)
                    .await
                    .map_err(|error| {
                        odin_brain::error::BrainError::InvalidRequest(error.to_string())
                    })
                    .and_then(|record| {
                        if record.manifest.seat_id != *seat {
                            return Err(odin_brain::error::BrainError::InvalidRequest(
                                "vault write seat does not match the durable session".into(),
                            ));
                        }
                        Ok(record.manifest.project_id)
                    })
            })?
        };
        let generated = self.generated_namespace.as_ref().ok_or_else(|| {
            odin_brain::error::BrainError::InvalidRequest(
                "vault generated namespace is not composed".into(),
            )
        })?;
        let projection_root = format!(
            "{generated}/{}/",
            odin_brain::source::silverbullet::RESERVED_KNOWLEDGE_SEGMENT,
        );
        if page_name.starts_with(&projection_root) {
            return Err(odin_brain::error::BrainError::InvalidRequest(
                "generated knowledge pages are owned by the source projection writer".into(),
            ));
        }
        let reserved = format!(
            "{generated}/{}/",
            odin_brain::source::silverbullet::RESERVED_MEMORY_SEGMENT,
        );
        if let Some(relative) = page_name.strip_prefix(&reserved) {
            // A reserved memory write lands in `memories/<name>/`, where
            // `memory.<name>` is the bound seat's own memory or a memory
            // namespace the session's project declares — and either way one
            // the session's project scope actually serves.
            let name = relative.split('/').next().unwrap_or_default();
            let source = odin_domain::knowledge::AtlasId::new(format!("memory.{name}")).map_err(
                |error| odin_brain::error::BrainError::InvalidRequest(error.to_string()),
            )?;
            let policy = brain.policy();
            let own = name == seat.as_str();
            let project_declared = policy
                .project_memory(&project)
                .is_some_and(|declared| declared.contains(&source));
            if !(own || project_declared)
                || !policy
                    .project_serving_scope(Some(&project))
                    .contains(&source)
            {
                return Err(odin_brain::error::BrainError::InvalidRequest(
                    "reserved memory writes require the bound seat's own memory or the \
                     session project's declared memory source"
                        .into(),
                ));
            }
            return Ok(());
        }
        let declared = brain.policy().project_memory(&project);
        let mut namespaces = declared.iter().flat_map(|set| set.iter());
        match (namespaces.next(), namespaces.next()) {
            // The actual write destination must BE the declared memory: a
            // generated note is confined only when the source it lands in
            // is the one namespace the project declared. A different or
            // ambiguous destination refuses before any IO.
            (Some(namespace), None) if namespace.as_str() == source_id => Ok(()),
            _ => Err(odin_brain::error::BrainError::InvalidRequest(format!(
                "the session's bound project does not declare the actual write source \
                 {source_id:?} as its single reachable project memory namespace"
            ))),
        }
    }

    fn generated_written(
        &self,
        seat: &SeatId,
        session: &SessionId,
        source_id: &str,
        page_name: &str,
    ) -> Result<(), odin_brain::error::BrainError> {
        self.gate_generated_write(seat, session, source_id, page_name)?;
        let generated = self.generated_namespace.as_ref().ok_or_else(|| {
            odin_brain::error::BrainError::InvalidRequest("vault namespace is absent".into())
        })?;
        let own_prefix = format!(
            "{}/",
            odin_brain::source::silverbullet::memory_namespace(generated, seat.as_str())?,
        );
        if page_name.starts_with(&own_prefix) {
            let source = odin_domain::knowledge::AtlasId::new(format!("memory.{seat}")).map_err(
                |error| odin_brain::error::BrainError::InvalidRequest(error.to_string()),
            )?;
            // Shared readers of this explicitly declared source refresh as well.
            for brain in self.brains.values() {
                if brain
                    .policy()
                    .knowledge
                    .as_ref()
                    .is_some_and(|policy| policy.atlas_sources.contains(&source))
                {
                    brain.ensure_source_generation(&source)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/live.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/continuity.rs"]
mod continuity_tests;

/// Reviews a completed delegated task into the child seat's brain.
pub(crate) struct FactoryTaskLearningCapture {
    runtime: Arc<std::sync::OnceLock<Arc<odin_hermes::runtime::HermesRuntime>>>,
    /// The durable live-session manifests: the child's seat, project and
    /// task title.
    live_ledger: Arc<dyn odin_omp::live::ledger::LiveLedger>,
}

impl FactoryTaskLearningCapture {
    pub(crate) fn new(
        runtime: Arc<std::sync::OnceLock<Arc<odin_hermes::runtime::HermesRuntime>>>,
        live_ledger: Arc<dyn odin_omp::live::ledger::LiveLedger>,
    ) -> Self {
        Self {
            runtime,
            live_ledger,
        }
    }
}

/// A completed delegated task is reviewed for the CHILD seat that did the
/// work (Gungnir learns the repo's test command, not its caller). Summary and
/// manifest failures remain retryable without accepting a review obligation.
/// The exact child's task/Result receipt must settle durably before capture is
/// acknowledged. Reopen/retry skips successful receipts; uncertain prior effects
/// remain pending rather than reapplying learning.
impl odin_omp::host_tools::delegation::TaskLearningCapture for FactoryTaskLearningCapture {
    fn capture_task_completion(
        &self,
        facts: &odin_omp::host_tools::delegation::TaskCompletionFacts,
    ) -> Result<(), String> {
        let runtime = self.runtime.get().ok_or_else(|| {
            "the Hermes runtime is not composed; nothing reviews tasks".to_owned()
        })?;
        let summary = facts
            .result
            .summary
            .clone()
            .filter(|summary| !summary.trim().is_empty())
            .ok_or_else(|| "the task result carries no summary to learn from".to_owned())?;
        let child = facts.child;
        let manifest = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| error.to_string())?
            .block_on(self.live_ledger.session(child))
            .map(|session| session.manifest)
            .map_err(|error| format!("the child session manifest is unreadable: {error}"))?;
        runtime
            .review_task_completion(odin_hermes::runtime::review::Exchange {
                seat: manifest.seat_id.clone(),
                session: child.to_string(),
                parent_session: Some(facts.parent_session.to_string()),
                project: Some(manifest.project_id.clone()),
                turn_keys: Vec::new(),
                sequence: Some(facts.result.event_sequence),
                trigger: "task",
                asked: manifest
                    .title
                    .clone()
                    .unwrap_or_else(|| "(delegated task)".to_owned()),
                answered: summary,
            })
            .map_err(|error| {
                format!(
                    "task learning child={} parent={} result={}: {error}",
                    facts.child, facts.parent_session, facts.result.event_sequence,
                )
            })
    }
}

/// The live session actor's Result hook: a delegated child goes to the task
/// owner (reviewed once as a task); any other seat session's finished turn
/// (an OMP terminal, Zed over ACP) is reviewed as a turn. Conversation
/// vehicles are reviewed by the conversation itself, pods not at all.
pub(crate) struct SessionTurnReview {
    pub(crate) owner: Option<Arc<dyn odin_omp::host_tools::delegation::CompletionEventObserver>>,
    pub(crate) links: odin_omp::host_tools::delegation::DelegationLinkLedger,
    pub(crate) runtime: Arc<std::sync::OnceLock<Arc<odin_hermes::runtime::HermesRuntime>>>,
    pub(crate) live_ledger: Arc<dyn odin_omp::live::ledger::LiveLedger>,
}

impl odin_omp::host_tools::delegation::CompletionEventObserver for SessionTurnReview {
    fn result_persisted(&self, session: odin_domain::huginn::ids::LiveSessionId, sequence: u64) {
        let Some(runtime) = self.runtime.get().cloned() else {
            if let Some(owner) = &self.owner {
                owner.result_persisted(session, sequence);
            }
            return;
        };
        // Accept before either the synchronous task owner or asynchronous
        // exchange lookup can begin: a cleanup observer must never see the
        // completed result without its pending review obligation.
        let review = runtime.register_review(
            session.to_string(),
            "result",
            Some(sequence),
            Vec::new(),
            None,
        );
        if let Some(owner) = &self.owner {
            owner.result_persisted(session, sequence);
        }
        let review = match review {
            Ok(review) => review,
            Err(error) => {
                tracing::error!("turn review registration failed session={session} reason={error}");
                return;
            }
        };
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            review.complete(odin_hermes::runtime::review::ReviewOutcome::Skipped(
                "no async runtime".into(),
            ));
            return;
        };
        let links = self.links.clone();
        let ledger = Arc::clone(&self.live_ledger);
        handle.spawn(async move {
            use odin_hermes::runtime::review::ReviewOutcome;
            match turn_exchange(ledger.as_ref(), &links, session, sequence).await {
                Ok(Some(exchange)) => runtime.review_registered(exchange, review),
                Ok(None) => review.complete(ReviewOutcome::Skipped(
                    "not a direct reviewable turn".into(),
                )),
                Err(error) => review.complete(ReviewOutcome::Failed(error)),
            }
        });
    }
}

/// The finished turn ending at `sequence` as a reviewable exchange, or
/// `None` when the session is not a direct seat session or the turn has no
/// owner prompt and answer (a local slash command, an empty result).
pub(crate) async fn turn_exchange(
    ledger: &dyn odin_omp::live::ledger::LiveLedger,
    links: &odin_omp::host_tools::delegation::DelegationLinkLedger,
    session: odin_domain::huginn::ids::LiveSessionId,
    sequence: u64,
) -> Result<Option<odin_hermes::runtime::review::Exchange>, String> {
    use odin_domain::huginn::{EventSeq, HistoryQuery, LiveContentBlock, LiveEventBody};
    const WINDOW: u64 = 256;
    if links.load(&session)?.is_some() {
        return Ok(None);
    }
    let manifest = ledger
        .session(session)
        .await
        .map_err(|error| format!("the session manifest is unreadable: {error}"))?
        .manifest;
    if manifest.workload.is_some()
        || manifest
            .title
            .as_deref()
            .is_some_and(|title| title.starts_with(odin_hermes::conversation::VEHICLE_TITLE_PREFIX))
    {
        return Ok(None);
    }
    let page = ledger
        .history(HistoryQuery {
            session_id: session,
            after: EventSeq::new(sequence.saturating_sub(WINDOW)),
            limit: std::num::NonZeroU16::new(WINDOW as u16).expect("non-zero window"),
        })
        .await
        .map_err(|error| format!("the session history is unreadable: {error}"))?;
    let mut asked = None;
    let mut answered = None;
    for event in page.events {
        if event.sequence.get() > sequence {
            break;
        }
        match event.body {
            LiveEventBody::UserMessage(message) => {
                asked = Some(
                    message
                        .content
                        .iter()
                        .filter_map(|block| match block {
                            LiveContentBlock::Text(text) => Some(text.as_str()),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                        .join("\n"),
                );
            }
            LiveEventBody::Result(result) if event.sequence.get() == sequence => {
                answered = result.summary;
            }
            _ => {}
        }
    }
    let (Some(asked), Some(answered)) = (
        asked.filter(|text| !text.trim().is_empty() && !text.trim_start().starts_with('/')),
        answered.filter(|text| !text.trim().is_empty()),
    ) else {
        return Ok(None);
    };
    Ok(Some(odin_hermes::runtime::review::Exchange {
        seat: manifest.seat_id,
        session: session.to_string(),
        parent_session: None,
        project: Some(manifest.project_id),
        turn_keys: Vec::new(),
        sequence: Some(sequence),
        trigger: "turn",
        asked,
        answered,
    }))
}

#[cfg(test)]
mod turn_review_tests {
    use odin_domain::huginn::{
        LiveContentBlock, LiveEventBody, LiveMessage, LiveSessionId, ModelName, ProviderName,
        SessionEpoch, SessionManifest, SessionResult, WorkloadSessionBinding,
    };
    use odin_domain::{
        CommandId, Digest, EventId, NodeId, ProjectId, RunId, SeatId, SessionId, SliceId,
    };
    use odin_omp::host_tools::delegation::{
        DelegationLink, DelegationLinkLedger, DelegationPhase, GovernedTaskOwner,
        DELEGATION_LINK_SCHEMA,
    };
    use odin_omp::live::ledger::fs::FsLiveLedger;
    use odin_omp::live::ledger::{LiveLedger, NewLiveEvent};

    async fn session(
        ledger: &FsLiveLedger,
        id: &str,
        title: Option<&str>,
        asked: &str,
        answered: &str,
    ) -> (LiveSessionId, u64) {
        session_with(ledger, id, title, asked, answered, None).await
    }

    async fn session_with(
        ledger: &FsLiveLedger,
        id: &str,
        title: Option<&str>,
        asked: &str,
        answered: &str,
        workload: Option<WorkloadSessionBinding>,
    ) -> (LiveSessionId, u64) {
        let session = LiveSessionId::parse(id).unwrap();
        ledger
            .create_session(SessionManifest {
                session_id: session,
                seat_id: SeatId::new("gungnir").unwrap(),
                slice_id: SliceId::new("gungnir-build").unwrap(),
                project_id: ProjectId::new("surtr").unwrap(),
                provider: ProviderName::new("gateway").unwrap(),
                model: ModelName::new("zai-glm").unwrap(),
                title: title.map(str::to_owned),
                target_node: NodeId::new("mini").unwrap(),
                open_tab: true,
                workload,
                served_revision: None,
                harness: None,
            })
            .await
            .unwrap();
        let mut last = 0;
        for (index, body) in [
            LiveEventBody::UserMessage(LiveMessage {
                content: vec![LiveContentBlock::Text(asked.to_owned())],
            }),
            LiveEventBody::Result(SessionResult {
                summary: Some(answered.to_owned()),
                artifacts: Vec::new(),
            }),
        ]
        .into_iter()
        .enumerate()
        {
            last = ledger
                .append(
                    SessionEpoch::new(1),
                    NewLiveEvent {
                        session_id: session,
                        event_id: EventId::new(format!("turn-review:{id}:{index}")).unwrap(),
                        occurred_at: time::OffsetDateTime::now_utc(),
                        body,
                    },
                )
                .await
                .unwrap()
                .sequence
                .get();
        }
        (session, last)
    }

    #[test]
    fn task_prerequisite_failures_leave_no_obligation_and_retry_can_finish() {
        use std::collections::BTreeMap;
        use std::sync::{Arc, Mutex, OnceLock};

        use odin_hermes::runtime::review::{
            REVIEW_COMPLETED_AUDIT_KIND, REVIEW_PENDING_AUDIT_KIND,
        };
        use odin_ledger::Ledger;
        use odin_omp::host_tools::delegation::{
            TaskCompletionFacts, TaskLearningCapture, TaskResultReport,
        };

        let root = tempfile::tempdir().unwrap();
        let ledger = Arc::new(FsLiveLedger::open(root.path().join("live")).unwrap());
        let audit = Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()));
        let runtime = odin_hermes::runtime::HermesRuntime::open(
            odin_hermes::config::HermesSettings::new(
                root.path().join("hermes"),
                None,
                None,
                None,
                vec![],
            )
            .unwrap(),
            odin_hermes::runtime::HermesLedgers {
                conversation: Ledger::open_in_memory().unwrap(),
                adapter: Arc::new(parking_lot::Mutex::new(Ledger::open_in_memory().unwrap())),
                purchase: Arc::clone(&audit),
            },
            &BTreeMap::new(),
            None,
            8192,
            BTreeMap::new(),
            None,
        )
        .unwrap();
        let runtime_slot = Arc::new(OnceLock::new());
        assert!(runtime_slot.set(runtime).is_ok());
        let capture = super::FactoryTaskLearningCapture::new(runtime_slot, ledger.clone());
        let id = "00000000-0000-4000-8000-0000000000d7";
        let mut facts = TaskCompletionFacts {
            parent_seat: SeatId::new("architect").unwrap(),
            parent_session: SessionId::new("00000000-0000-4000-8000-0000000000a1").unwrap(),
            child: LiveSessionId::parse(id).unwrap(),
            result: TaskResultReport {
                summary: None,
                artifacts: Vec::new(),
                event_sequence: 2,
            },
        };
        let lifecycle = || {
            audit
                .lock()
                .unwrap()
                .audit_events_after(0, 64)
                .unwrap()
                .into_iter()
                .filter(|event| {
                    event.kind == REVIEW_PENDING_AUDIT_KIND
                        || event.kind == REVIEW_COMPLETED_AUDIT_KIND
                })
                .collect::<Vec<_>>()
        };

        for summary in [None, Some(" \n ".to_owned())] {
            facts.result.summary = summary;
            assert!(capture
                .capture_task_completion(&facts)
                .unwrap_err()
                .contains("no summary"));
            assert!(lifecycle().is_empty(), "invalid summary accepted no review");
        }
        facts.result.summary = Some("nix flake check runs them".to_owned());
        assert!(capture
            .capture_task_completion(&facts)
            .unwrap_err()
            .contains("child session manifest is unreadable"));
        assert!(
            lifecycle().is_empty(),
            "a retryable manifest failure must not leave a failed obligation"
        );

        // Make the same child's manifest readable, then retry the same result.
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (child, sequence) = executor.block_on(session(
            ledger.as_ref(),
            id,
            Some("surtr tests"),
            "how do I run surtr's tests?",
            facts.result.summary.as_deref().unwrap(),
        ));
        assert_eq!(child, facts.child);
        assert_eq!(sequence, facts.result.event_sequence);
        let parent = facts.parent_session.to_string();
        executor.block_on(async move {
            tokio::task::spawn_blocking(move || capture.capture_task_completion(&facts))
                .await
                .unwrap()
                .unwrap();
        });
        // Runtime shutdown joins the review's blocking worker, without polling.
        drop(executor);
        let events = lifecycle();
        assert_eq!(
            events.len(),
            2,
            "only the successful retry accepted a review"
        );
        assert_eq!(events[0].kind, REVIEW_PENDING_AUDIT_KIND);
        assert_eq!(events[1].kind, REVIEW_COMPLETED_AUDIT_KIND);
        assert_eq!(events[0].payload["reviewId"], events[1].payload["reviewId"]);
        for event in &events {
            assert_eq!(event.payload["session"], child.to_string());
            assert_eq!(event.payload["parentSession"], parent);
            assert_eq!(event.payload["sequence"], sequence);
            assert_eq!(event.payload["trigger"], "task");
        }
        assert_eq!(events[0].payload["status"], "pending");
        assert_eq!(events[1].payload["status"], "skipped");
        assert_eq!(events[1].payload["reason"], "seat declares no review lane");
    }

    #[tokio::test]
    async fn a_direct_seat_turn_is_reviewed_and_vehicles_and_commands_are_not() {
        let root = tempfile::tempdir().unwrap();
        let ledger = FsLiveLedger::open(root.path().join("live")).unwrap();
        let links = DelegationLinkLedger::open(root.path().join("links")).unwrap();
        let ledger_ref: &dyn LiveLedger = &ledger;

        let (direct, at) = session(
            &ledger,
            "00000000-0000-4000-8000-0000000000d1",
            Some("surtr refactor"),
            "how do I run surtr's tests?",
            "nix flake check runs them",
        )
        .await;
        let exchange = super::turn_exchange(ledger_ref, &links, direct, at)
            .await
            .unwrap()
            .expect("a direct seat turn is reviewed");
        assert_eq!(exchange.seat.as_str(), "gungnir");
        assert_eq!(exchange.trigger, "turn");
        assert_eq!(exchange.asked, "how do I run surtr's tests?");
        assert_eq!(exchange.answered, "nix flake check runs them");

        let title = format!("{}c1", odin_hermes::conversation::VEHICLE_TITLE_PREFIX);
        let (vehicle, at) = session(
            &ledger,
            "00000000-0000-4000-8000-0000000000d2",
            Some(&title),
            "hi",
            "hello",
        )
        .await;
        assert!(super::turn_exchange(ledger_ref, &links, vehicle, at)
            .await
            .unwrap()
            .is_none());

        let (command, at) = session(
            &ledger,
            "00000000-0000-4000-8000-0000000000d3",
            None,
            "/status",
            "idle",
        )
        .await;
        assert!(super::turn_exchange(ledger_ref, &links, command, at)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn workload_and_linked_child_skip_turn_review() {
        let root = tempfile::tempdir().unwrap();
        let ledger = FsLiveLedger::open(root.path().join("live")).unwrap();
        let links = DelegationLinkLedger::open(root.path().join("links")).unwrap();
        let ledger_ref: &dyn LiveLedger = &ledger;

        let (direct, at) = session(
            &ledger,
            "00000000-0000-4000-8000-0000000000d4",
            Some("surtr refactor"),
            "how do I run surtr's tests?",
            "nix flake check runs them",
        )
        .await;
        let exchange = super::turn_exchange(ledger_ref, &links, direct, at)
            .await
            .unwrap()
            .expect("a direct seat turn is reviewed");
        assert_eq!(exchange.project, Some(ProjectId::new("surtr").unwrap()));
        assert_eq!(exchange.session, direct.to_string());

        links
            .persist(&DelegationLink {
                schema: DELEGATION_LINK_SCHEMA.to_owned(),
                child: direct,
                parent: SessionId::new("00000000-0000-4000-8000-0000000000a1").unwrap(),
                parent_seat: Some(SeatId::new("gungnir").unwrap()),
                parent_run: RunId::new("run:turn-review-parent").unwrap(),
                child_run: GovernedTaskOwner::child_run_for(&direct).unwrap(),
                command: CommandId::new("odin.task.create:turn-review").unwrap(),
                project: ProjectId::new("surtr").unwrap(),
                provider: "gateway".to_owned(),
                model: "glm-flash".to_owned(),
                prompt_digest: Digest::hash(b"prompt"),
                depth: 1,
                phase: DelegationPhase::Provisioning,
                created_at_ms: 1,
                learning_capture_sequence: None,
                escalated_to: None,
                escalation_open: false,
                learning_result_sequence: None,
                learning_proposal_id: None,
                stall_retries: 0,
                stalls: Vec::new(),
                switched_to: None,
                handled_stall_event: None,
                refusals: Vec::new(),
                gateway_fallbacks: Vec::new(),
                reported_answer: None,
                assignment: String::new(),
                rollover_admissions: 0,
                pending_report: None,
            })
            .unwrap();
        assert!(super::turn_exchange(ledger_ref, &links, direct, at)
            .await
            .unwrap()
            .is_none());

        let (pod, at) = session_with(
            &ledger,
            "00000000-0000-4000-8000-0000000000d5",
            None,
            "run the pod",
            "pod finished",
            Some(WorkloadSessionBinding {
                profile: "pod".to_owned(),
                snapshot_revision: 1,
                operation: "run".to_owned(),
                inputs: Vec::new(),
                launching_run: None,
            }),
        )
        .await;
        assert!(super::turn_exchange(ledger_ref, &links, pod, at)
            .await
            .unwrap()
            .is_none());

        let (empty, at) = session(
            &ledger,
            "00000000-0000-4000-8000-0000000000d6",
            None,
            "how do I run surtr's tests?",
            "",
        )
        .await;
        assert!(super::turn_exchange(ledger_ref, &links, empty, at)
            .await
            .unwrap()
            .is_none());
    }
}

#[cfg(test)]
mod feeds_provisioning_tests {
    use crate::live::ensure_feeds_dir;

    #[test]
    fn fresh_root_gets_a_private_feeds_directory_and_pump_cursor_persists() {
        let root = tempfile::tempdir().expect("fresh root");
        let huginn_root = root.path().join("huginn");
        assert!(
            !huginn_root.join("feeds").exists(),
            "fresh root has no feeds dir"
        );
        ensure_feeds_dir(&huginn_root).expect("provision feeds on fresh root");
        let feeds = huginn_root.join("feeds");
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&feeds)
            .expect("feeds dir exists")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "feeds dir is private");
        // Idempotent: the composition may run again over an existing root.
        ensure_feeds_dir(&huginn_root).expect("re-provision is idempotent");
        // The real pump's cursor persist lands in the provisioned parent:
        // the exact write the composition enables on a fresh root.
        let cursor = feeds.join("change-cursor");
        std::fs::write(&cursor, "1").expect("cursor ordinal persists");
        assert_eq!(
            std::fs::read_to_string(&cursor).expect("cursor readable"),
            "1"
        );
    }
}
