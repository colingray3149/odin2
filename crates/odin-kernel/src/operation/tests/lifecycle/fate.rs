//! Cross execution outcomes with settlement paths and check persistence without re-execution.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fate {
    CommittedClean,
    /// Pre-output uncertainty: in-doubt, nothing landed, no evidence.
    UncertainNoOutput,
    /// Post-output uncertainty: in-doubt, effect landed, receipt captured.
    UncertainPostOutput,
    PreparedNeverDispatched,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Settle {
    /// Public resume by the exact prepare-time authority.
    Resume,
    /// Resume by the lease's ROTATED generation: a newer token never
    /// inherits an older row — authority does not widen.
    ResumeRotatedToken,
    Reconcile,
    /// Exact replay of the original correlation.
    Replay,
    StopTargeted,
    StopWide,
    CloseDrain,
    CloseAbort,
}

impl Fate {
    fn tag(self) -> &'static str {
        match self {
            Fate::CommittedClean => "committed",
            Fate::UncertainNoOutput => "uncertain-no-output",
            Fate::UncertainPostOutput => "uncertain-post-output",
            Fate::PreparedNeverDispatched => "prepared",
        }
    }

    fn landed(self) -> bool {
        matches!(self, Fate::CommittedClean | Fate::UncertainPostOutput)
    }
}

impl Settle {
    fn tag(self) -> &'static str {
        match self {
            Settle::Resume => "resume",
            Settle::ResumeRotatedToken => "resume-rotated",
            Settle::Reconcile => "reconcile",
            Settle::Replay => "replay",
            Settle::StopTargeted => "stop-targeted",
            Settle::StopWide => "stop-wide",
            Settle::CloseDrain => "close-drain",
            Settle::CloseAbort => "close-abort",
        }
    }
}

/// Cover four outcomes across eight settlement paths, including reopen and replay.
#[test]
fn unknown_fate_retains_identity_across_every_settle_path() {
    for fate in [
        Fate::CommittedClean,
        Fate::UncertainNoOutput,
        Fate::UncertainPostOutput,
        Fate::PreparedNeverDispatched,
    ] {
        for settle in [
            Settle::Resume,
            Settle::ResumeRotatedToken,
            Settle::Reconcile,
            Settle::Replay,
            Settle::StopTargeted,
            Settle::StopWide,
            Settle::CloseDrain,
            Settle::CloseAbort,
        ] {
            lc_run_fate_settle(fate, settle);
        }
    }
}

fn lc_run_fate_settle(fate: Fate, settle: Settle) {
    let tag = format!("lc-fate-{}-{}", fate.tag(), settle.tag());
    let ledger_path = lease_ledger_path(&tag);
    let world = Arc::new(World::default());
    let ledger = Arc::new(Mutex::new(
        Ledger::open(&ledger_path).expect("file-backed ledger"),
    ));
    let fixture = fixture_with(
        Arc::clone(&world),
        Arc::new(Executor(Arc::clone(&world))),
        ledger,
    );
    let label = format!("fate {} settle {}", fate.tag(), settle.tag());
    let capsule_id = CapsuleId::new(CAPSULE).unwrap();
    let owner = Presenter::Owner(100);
    let correlation_id = correlation("lc-fate-row");
    let stop_correlation_id = correlation("lc-fate-stop");
    let path = "docs/lc-fate.md";
    let content = "lc-fate-content";

    let mut model = Model::default();
    let operation_id = match fate {
        Fate::CommittedClean => {
            let expected = model.apply_invoke(owner, correlation_id.as_str(), path, content);
            let outcome = lc_invoke(&fixture, owner, &correlation_id, path, content);
            lc_expect_decided(expected, &outcome, &label);
            outcome.expect("decision available").operation_id
        }
        Fate::UncertainNoOutput => {
            fixture.world.uncertain.store(true, Ordering::SeqCst);
            let outcome = lc_invoke(&fixture, owner, &correlation_id, path, content);
            fixture.world.uncertain.store(false, Ordering::SeqCst);
            assert!(
                matches!(
                    &outcome,
                    Err(OperationRejection::Executor(
                        ExecutorFault::Uncertain { .. }
                    ))
                ),
                "{label}: pre-output uncertainty must record in-doubt, got {outcome:?}"
            );
            model.lease = LeaseModel::Open { bound: owner };
            model.record_row(
                correlation_id.as_str(),
                ModelRow {
                    creator: owner,
                    state: EffectState::InDoubt,
                    evidence: None,
                    landed: false,
                },
            );
            fixture.operation_id(correlation_id.as_str())
        }
        Fate::UncertainPostOutput => {
            fixture
                .world
                .post_effect_uncertain
                .store(true, Ordering::SeqCst);
            let outcome = lc_invoke(&fixture, owner, &correlation_id, path, content);
            fixture
                .world
                .post_effect_uncertain
                .store(false, Ordering::SeqCst);
            assert!(
                matches!(
                    &outcome,
                    Err(OperationRejection::Executor(
                        ExecutorFault::PostEffectUncertain { evidence_digest, .. }
                    )) if *evidence_digest == receipt_digest(content)
                ),
                "{label}: post-output uncertainty must bind the captured receipt, got {outcome:?}"
            );
            model.lease = LeaseModel::Open { bound: owner };
            model.files.insert(path.to_owned(), content.to_owned());
            model.record_row(
                correlation_id.as_str(),
                ModelRow {
                    creator: owner,
                    state: EffectState::InDoubt,
                    evidence: Some(receipt_digest(content).to_string()),
                    landed: true,
                },
            );
            fixture.operation_id(correlation_id.as_str())
        }
        Fate::PreparedNeverDispatched => {
            let authorized = fixture.authorize_with(
                lc_owner_proof(100),
                &arguments_at(path, content),
                LC_VERIFY_NOW,
            );
            fixture.open_test_lease(&authorized, CAPSULE, 19);
            let seeded =
                fixture.seed_in_flight_operation(&correlation_id, &capsule_id, &authorized);
            model.lease = LeaseModel::Open { bound: owner };
            model.record_row(
                correlation_id.as_str(),
                ModelRow {
                    creator: owner,
                    state: EffectState::Prepared,
                    evidence: None,
                    landed: false,
                },
            );
            seeded
        }
    };
    let mut shadow = Shadow::default();
    lc_verify(&fixture, &model, &mut shadow, &format!("{label}: fate set"));

    match settle {
        Settle::Resume | Settle::Reconcile | Settle::Replay => {
            let expected_next = {
                let row = &model.rows[correlation_id.as_str()];
                lc_settle_law(row.state, row.landed)
            };
            if settle == Settle::Replay {
                let outcome = lc_invoke(&fixture, owner, &correlation_id, path, content);
                lc_expect_decided(
                    InvokeModel::Decided {
                        state: expected_next,
                        replay: true,
                    },
                    &outcome,
                    &label,
                );
                assert_eq!(
                    outcome.expect("decision available").operation_id,
                    operation_id,
                    "{label}: replay keeps the operation identity"
                );
            } else {
                let fresh = lc_owner_proof(100);
                if settle == Settle::Resume {
                    let decision = fixture
                        .authority
                        .resume(fresh, &capsule_id, &correlation_id, &operation_id)
                        .unwrap_or_else(|error| panic!("{label}: resume settles: {error:?}"));
                    assert!(decision.replay, "{label}: resume never re-executes");
                    assert_eq!(decision.state, expected_next, "{label}: settled state");
                } else {
                    let outcome = fixture
                        .authority
                        .reconcile(fresh, &capsule_id, &correlation_id, &operation_id)
                        .unwrap_or_else(|error| panic!("{label}: reconcile settles: {error:?}"));
                    assert!(
                        outcome.decision.replay,
                        "{label}: reconcile never re-executes"
                    );
                    assert_eq!(
                        outcome.decision.state, expected_next,
                        "{label}: settled state"
                    );
                    // The observation is the executor's real view of the
                    // world, independently computed here.
                    let expected_observed = if fate.landed() {
                        PreWorld::Digest(Digest::hash(content.as_bytes()))
                    } else {
                        PreWorld::Absent
                    };
                    assert_eq!(outcome.observed, expected_observed, "{label}: observation");
                }
            }
            model.rows.get_mut(correlation_id.as_str()).unwrap().state = expected_next;
        }
        Settle::ResumeRotatedToken => {
            let refused = fixture.authority.resume(
                lc_owner_proof(200),
                &capsule_id,
                &correlation_id,
                &operation_id,
            );
            assert!(
                matches!(&refused, Err(OperationRejection::AuthorityMismatch { .. })),
                "{label}: a rotated generation never inherits the older row, got {refused:?}"
            );
        }
        Settle::StopTargeted | Settle::StopWide => {
            let targeted = settle == Settle::StopTargeted;
            let outcome = fixture
                .authority
                .stop_intent(
                    lc_owner_proof(100),
                    &capsule_id,
                    &stop_correlation_id,
                    targeted.then(|| operation_id.clone()),
                )
                .unwrap_or_else(|error| {
                    panic!("{label}: the bound authority records cancel: {error:?}")
                });
            assert_eq!(
                outcome.state, "requested",
                "{label}: cancel stays requested"
            );
            assert!(!outcome.replay, "{label}: the first cancel is fresh");
            assert_eq!(
                outcome.operation_id,
                targeted.then(|| operation_id.clone()),
                "{label}: cancel operation binding"
            );
            // Cancel never invents a verdict: the row is untouched.
            model
                .stops
                .insert(stop_correlation_id.as_str().to_owned(), "requested");
            let entry = model.usage.entry(owner.session()).or_insert((0, 0, 0));
            entry.1 += 1;
        }
        Settle::CloseDrain | Settle::CloseAbort => {
            let mode = if settle == Settle::CloseDrain {
                CloseMode::Drain
            } else {
                CloseMode::Abort
            };
            let row = &model.rows[correlation_id.as_str()];
            let nonterminal = row.state.is_nonterminal();
            if settle == Settle::CloseAbort && nonterminal && row.landed {
                // A landed effect can never be aborted: the close reports
                // the block and the capsule stays open, unresolved.
                let blocked = fixture.authority.close_capsule(
                    lc_owner_proof(100),
                    &capsule_id,
                    &correlation("lc-fate-close"),
                    mode,
                );
                assert!(
                    matches!(
                        &blocked,
                        Err(OperationRejection::CapsuleBlocked { blocked: 1, .. })
                    ),
                    "{label}: abort must refuse the landed effect, got {blocked:?}"
                );
            } else {
                let closed = fixture
                    .authority
                    .close_capsule(
                        lc_owner_proof(100),
                        &capsule_id,
                        &correlation("lc-fate-close"),
                        mode,
                    )
                    .unwrap_or_else(|error| panic!("{label}: close settles: {error:?}"));
                assert!(!closed.replay, "{label}: the first close is fresh");
                assert_eq!(
                    closed.drained,
                    u64::from(nonterminal),
                    "{label}: drained count"
                );
                if nonterminal {
                    let row = model.rows.get_mut(correlation_id.as_str()).unwrap();
                    row.state = lc_settle_law(row.state, row.landed);
                }
                model.lease = LeaseModel::Closed {
                    close_mode: mode.as_str(),
                };
            }
        }
    }
    lc_verify(
        &fixture,
        &model,
        &mut shadow,
        &format!("{label}: after settle"),
    );

    // The original authority can resume the recorded operation after cancellation or capsule closure.
    let next = {
        let row = &model.rows[correlation_id.as_str()];
        lc_settle_law(row.state, row.landed)
    };
    let decision = fixture
        .authority
        .resume(
            lc_owner_proof(100),
            &capsule_id,
            &correlation_id,
            &operation_id,
        )
        .unwrap_or_else(|error| panic!("{label}: resume settles durable truth: {error:?}"));
    assert!(
        decision.replay,
        "{label}: the second settle never re-executes"
    );
    assert_eq!(decision.state, next, "{label}: second settle state");
    assert_eq!(
        decision.operation_id, operation_id,
        "{label}: identity survives every settle path"
    );
    model.rows.get_mut(correlation_id.as_str()).unwrap().state = next;
    lc_verify(
        &fixture,
        &model,
        &mut shadow,
        &format!("{label}: after resume"),
    );

    // Reopen: identical durable state; the terminal row replays.
    let final_state = model.rows[correlation_id.as_str()].state;
    drop(fixture);
    let reopened_ledger = Arc::new(Mutex::new(
        Ledger::open(&ledger_path).expect("reopen ledger"),
    ));
    let reopened = fixture_with(
        Arc::clone(&world),
        Arc::new(Executor(Arc::clone(&world))),
        reopened_ledger,
    );
    lc_verify(
        &reopened,
        &model,
        &mut shadow,
        &format!("{label}: reopened"),
    );
    let replayed = reopened
        .authority
        .resume(
            lc_owner_proof(100),
            &capsule_id,
            &correlation_id,
            &operation_id,
        )
        .unwrap_or_else(|error| panic!("{label}: reopened resume replays: {error:?}"));
    assert!(replayed.replay, "{label}: reopen replays the terminal row");
    assert_eq!(replayed.state, final_state, "{label}: reopened state");
    assert_eq!(
        reopened.world.executions.load(Ordering::SeqCst),
        model.executions,
        "{label}: nothing re-executes after reopen"
    );
    drop(reopened);
    discard_ledger(&ledger_path);
}
