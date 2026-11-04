//! Closure is immutable: foreign authorities, mismatched modes, and late cancellation
//! cannot change a closed capsule.

use super::*;

#[test]
fn closure_record_is_immutable_and_late_foreign_close_and_cancel_are_refused() {
    let fixture = fixture();
    let capsule_id = CapsuleId::new(CAPSULE).unwrap();
    let owner = Presenter::Owner(100);
    let correlation_id = correlation("lc-closure-row");
    let stop_correlation_id = correlation("lc-closure-stop");
    let path = "docs/lc-closure.md";
    let content = "lc-closure-content";

    // One committed operation: the capsule holds a terminal row.
    let mut model = Model::default();
    let expected = model.apply_invoke(owner, correlation_id.as_str(), path, content);
    let outcome = lc_invoke(&fixture, owner, &correlation_id, path, content);
    lc_expect_decided(expected, &outcome, "closure: dispatch");
    let operation_id = outcome.expect("decision available").operation_id;
    let mut shadow = Shadow::default();

    // A foreign seat cannot close an open capsule, and commits nothing.
    let foreign = lc_close(
        &fixture,
        Presenter::ForeignSeat,
        &capsule_id,
        "lc-closure-foreign-open",
        CloseMode::Abort,
    );
    assert!(
        matches!(&foreign, Err(OperationRejection::AuthorityMismatch { .. })),
        "closure: a foreign seat cannot close an open capsule, got {foreign:?}"
    );
    lc_verify(
        &fixture,
        &model,
        &mut shadow,
        "closure: foreign close on open refused",
    );

    // Drain leaves the terminal row untouched.
    let closed = lc_close(
        &fixture,
        owner,
        &capsule_id,
        "lc-closure-close",
        CloseMode::Drain,
    )
    .unwrap_or_else(|error| panic!("closure: bound drain close settles: {error:?}"));
    assert!(!closed.replay, "closure: the first close is fresh");
    assert_eq!(closed.drained, 0, "closure: a terminal row drains nothing");
    model.lease = LeaseModel::Closed {
        close_mode: CloseMode::Drain.as_str(),
    };
    lc_verify(&fixture, &model, &mut shadow, "closure: closed");

    // A mode-mismatched second close replays and the record stays drain.
    let replayed = lc_close(
        &fixture,
        owner,
        &capsule_id,
        "lc-closure-replay",
        CloseMode::Abort,
    )
    .unwrap_or_else(|error| panic!("closure: closed capsule replays: {error:?}"));
    assert!(replayed.replay, "closure: the second close is a replay");
    assert_eq!(replayed.drained, 0, "closure: a replay drains nothing");
    lc_verify(
        &fixture,
        &model,
        &mut shadow,
        "closure: mode-mismatched replay",
    );

    // A foreign seat still cannot reach the closed capsule.
    let foreign_closed = lc_close(
        &fixture,
        Presenter::ForeignSeat,
        &capsule_id,
        "lc-closure-foreign-closed",
        CloseMode::Drain,
    );
    assert!(
        matches!(
            &foreign_closed,
            Err(OperationRejection::AuthorityMismatch { .. })
        ),
        "closure: a foreign seat cannot close a closed capsule, got {foreign_closed:?}"
    );
    lc_verify(
        &fixture,
        &model,
        &mut shadow,
        "closure: foreign close on closed refused",
    );

    // Cancel can never touch a closed capsule: typed refusal, no durable
    // intent, no charge, no revival of the terminal lifecycle.
    let stopped = fixture.authority.stop_intent(
        lc_owner_proof(100),
        &capsule_id,
        &stop_correlation_id,
        Some(operation_id),
    );
    assert!(
        matches!(&stopped, Err(OperationRejection::CapsuleClosed { .. })),
        "closure: cancel cannot touch a closed capsule, got {stopped:?}"
    );
    {
        let ledger = fixture.authority.lock_store().expect("ledger lock");
        assert!(
            store::stop_row(ledger.connection(), stop_correlation_id.as_str())
                .expect("stop row read")
                .is_none(),
            "closure: the refused cancel must not record an intent"
        );
    }
    lc_verify(
        &fixture,
        &model,
        &mut shadow,
        "closure: late cancel refused",
    );
}

fn lc_close(
    fixture: &Fixture,
    presenter: Presenter,
    capsule_id: &CapsuleId,
    tag: &str,
    mode: CloseMode,
) -> Result<CapsuleOutcome, OperationRejection> {
    fixture.authority.close_capsule(
        proof_with(
            presenter.seat(),
            presenter.session(),
            b"policy",
            presenter.generation(),
            LC_VERIFY_NOW,
        ),
        capsule_id,
        &correlation(tag),
        mode,
    )
}
