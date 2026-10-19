//! Check persisted lease authority after every presentation sequence of length one through four.

use super::*;

/// Partition the 340 authority sequences by first presentation: 85 per test,
/// checking persisted state after every step.
fn authority_sequences_starting_with(first: Presenter) {
    const PRESENTATIONS: [Presenter; 4] = [
        Presenter::Owner(100),
        Presenter::Owner(200),
        Presenter::ForeignSeat,
        Presenter::ForeignSession,
    ];
    for length in 1..=4usize {
        let total = PRESENTATIONS.len().pow((length - 1) as u32);
        for code in 0..total {
            let mut steps = [first; 4];
            let mut remainder = code;
            for step in &mut steps[1..length] {
                *step = PRESENTATIONS[remainder % PRESENTATIONS.len()];
                remainder /= PRESENTATIONS.len();
            }
            lc_run_authority_sequence(&steps[..length]);
        }
    }
}

#[test]
fn generated_authority_sequences_from_owner_100_keep_the_lease_law_exact() {
    authority_sequences_starting_with(Presenter::Owner(100));
}

#[test]
fn generated_authority_sequences_from_owner_200_keep_the_lease_law_exact() {
    authority_sequences_starting_with(Presenter::Owner(200));
}

#[test]
fn generated_authority_sequences_from_foreign_seat_keep_the_lease_law_exact() {
    authority_sequences_starting_with(Presenter::ForeignSeat);
}

#[test]
fn generated_authority_sequences_from_foreign_session_keep_the_lease_law_exact() {
    authority_sequences_starting_with(Presenter::ForeignSession);
}

#[test]
fn uncertain_row_blocks_rotation_until_settled() {
    let fixture = fixture();
    let mut model = Model::default();
    let mut shadow = Shadow::default();

    // Owner@100 dispatches into pre-output uncertainty: a nonterminal
    // in-doubt row with no evidence and nothing in the world.
    fixture.world.uncertain.store(true, Ordering::SeqCst);
    let correlation_id = correlation("lc-block-uncertain");
    let outcome = lc_invoke(
        &fixture,
        Presenter::Owner(100),
        &correlation_id,
        "docs/lc-block.md",
        "lc-block-content",
    );
    fixture.world.uncertain.store(false, Ordering::SeqCst);
    assert!(
        matches!(
            &outcome,
            Err(OperationRejection::Executor(
                ExecutorFault::Uncertain { .. }
            ))
        ),
        "expected pre-output uncertainty, got {outcome:?}"
    );
    model.lease = LeaseModel::Open {
        bound: Presenter::Owner(100),
    };
    model.record_row(
        correlation_id.as_str(),
        ModelRow {
            creator: Presenter::Owner(100),
            state: EffectState::InDoubt,
            evidence: None,
            landed: false,
        },
    );
    lc_verify(&fixture, &model, &mut shadow, "uncertain block: fate set");

    // The strictly newer owner@200 generation may not rotate past the
    // unresolved row: typed refusal, nothing moves, nothing is charged.
    let rotation = correlation("lc-block-rotation");
    let expected = model.apply_invoke(
        Presenter::Owner(200),
        rotation.as_str(),
        "docs/lc-block-rotation.md",
        "lc-block-rotation",
    );
    let outcome = lc_invoke(
        &fixture,
        Presenter::Owner(200),
        &rotation,
        "docs/lc-block-rotation.md",
        "lc-block-rotation",
    );
    lc_expect_err(expected, &outcome, "uncertain block: rotation refused");
    lc_verify(
        &fixture,
        &model,
        &mut shadow,
        "uncertain block: rotation refused",
    );

    // The exact replay settles the row from the world alone: nothing
    // landed, so it aborts and the capsule is rotatable again.
    let expected = model.apply_invoke(
        Presenter::Owner(100),
        correlation_id.as_str(),
        "docs/lc-block.md",
        "lc-block-content",
    );
    let outcome = lc_invoke(
        &fixture,
        Presenter::Owner(100),
        &correlation_id,
        "docs/lc-block.md",
        "lc-block-content",
    );
    lc_expect_decided(expected, &outcome, "uncertain block: replay settles");
    lc_verify(
        &fixture,
        &model,
        &mut shadow,
        "uncertain block: replay settles",
    );

    // The rotation now proceeds under exactly one durable rebind event.
    let rotated = correlation("lc-block-rotated");
    let expected = model.apply_invoke(
        Presenter::Owner(200),
        rotated.as_str(),
        "docs/lc-block-rotated.md",
        "lc-block-rotated",
    );
    let outcome = lc_invoke(
        &fixture,
        Presenter::Owner(200),
        &rotated,
        "docs/lc-block-rotated.md",
        "lc-block-rotated",
    );
    lc_expect_decided(expected, &outcome, "uncertain block: rotation proceeds");
    lc_verify(
        &fixture,
        &model,
        &mut shadow,
        "uncertain block: rotation proceeds",
    );
}

fn lc_run_authority_sequence(steps: &[Presenter]) {
    let fixture = fixture();
    let mut model = Model::default();
    let mut shadow = Shadow::default();
    let sequence: Vec<String> = steps.iter().map(|step| step.tag()).collect();
    let base = format!("authority sequence [{}]", sequence.join(", "));
    for (position, presenter) in steps.iter().enumerate() {
        let label = format!("{base} step {position} ({})", presenter.tag());
        let correlation_id = correlation(&format!("lc-authority-{position}"));
        let path = format!("docs/lc-authority-{position}.md");
        let content = format!("content-{position}");
        let expected = model.apply_invoke(*presenter, correlation_id.as_str(), &path, &content);
        let outcome = lc_invoke(&fixture, *presenter, &correlation_id, &path, &content);
        match expected {
            InvokeModel::Decided { .. } => lc_expect_decided(expected, &outcome, &label),
            _ => lc_expect_err(expected, &outcome, &label),
        }
        lc_verify(&fixture, &model, &mut shadow, &label);
    }
}
