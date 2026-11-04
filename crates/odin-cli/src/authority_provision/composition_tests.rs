use super::*;
use std::fs;

use crate::authority_provision::fixture::{command, fixture};
use crate::authority_provision::{ensure_session_token, init, TokenRenewalPolicy};

/// The fixture seat's declared launch options, in declaration order. The
/// selection tests deliberately open the SECOND option: declaration order is
/// not a default, so selecting an option that is not first must be honoured.
const DECLARED_PROVIDER: &str = "gateway";
const FIRST_DECLARED_MODEL: &str = "zai-glm";
const SECOND_DECLARED_MODEL: &str = "glm-flash";

#[test]
fn compose_rejects_unknown_seats_and_projects() {
    let fixture = fixture();
    let error = compose(
        &fixture.config,
        "gungnir",
        "odin",
        &command("command:unknown-seat"),
        LaunchSelection::new(DECLARED_PROVIDER, FIRST_DECLARED_MODEL),
    )
    .expect_err("unknown seat is rejected");
    assert!(error.contains("gungnir"), "unexpected error: {error}");
    let error = compose(
        &fixture.config,
        "architect",
        "research",
        &command("command:unknown-project"),
        LaunchSelection::new(DECLARED_PROVIDER, FIRST_DECLARED_MODEL),
    )
    .expect_err("project outside the seat scope is rejected");
    assert!(
        error.contains("no configured session lane"),
        "unexpected error: {error}"
    );
    let mut mismatched = fixture.config.clone();
    mismatched.seats[0].slice = odin_domain::SliceId::new("missing-slice").unwrap();
    let error = compose(
        &mismatched,
        "architect",
        "odin",
        &command("command:mismatched-snapshot"),
        LaunchSelection::new(DECLARED_PROVIDER, FIRST_DECLARED_MODEL),
    )
    .expect_err("configuration claims absent from the snapshot are rejected");
    assert!(
        error.contains("slice missing-slice is not enabled"),
        "unexpected error: {error}"
    );
}

#[test]
fn pinned_durable_composition_binds_the_exact_session_the_command_never_hashes_to() {
    let fixture = fixture();
    init(&fixture.config).expect("authority initialized");
    // The durable session exists: its identity was derived when the
    // session first opened and it lives in durable state.
    let open_command = command("command:durable-open");
    let opened = compose(
        &fixture.config,
        "architect",
        "odin",
        &open_command,
        LaunchSelection::new(DECLARED_PROVIDER, FIRST_DECLARED_MODEL),
    )
    .expect("the open");
    let durable_session = opened.live_session;

    // A later recovery composes from a fresh per-turn command id but
    // pins the durable identity and the durable session's OWN launch pair:
    // the token must bind the EXACT session, and the model must never
    // silently change on recovery.
    let recovery_command = command("command:recovery-turn");
    let pinned = compose_for_session(
        &fixture.config,
        "architect",
        "odin",
        &recovery_command,
        durable_session,
        LaunchSelection::new(opened.provider.as_str(), opened.model.as_str()),
    )
    .expect("the pinned composition");
    assert_eq!(pinned.live_session, durable_session);
    assert_eq!(pinned.session, opened.session);
    assert_eq!(pinned.command_id, recovery_command);
    assert_eq!(pinned.provider, opened.provider);
    assert_eq!(pinned.model, opened.model);

    // A persisted session whose pair is no longer declared refuses typed —
    // it is never silently recomposed under the seat's first declaration.
    let error = compose_for_session(
        &fixture.config,
        "architect",
        "odin",
        &recovery_command,
        durable_session,
        LaunchSelection::new(DECLARED_PROVIDER, "removed-model"),
    )
    .expect_err("an undeclared persisted pair never silently changes model");
    assert!(
        error.contains("does not declare the selected launch"),
        "unexpected error: {error}"
    );

    // The same command WITHOUT the pin derives a different session: a
    // command id never hashes to the durable session, and the seam
    // never pretends otherwise.
    let derived = compose(
        &fixture.config,
        "architect",
        "odin",
        &recovery_command,
        LaunchSelection::new(DECLARED_PROVIDER, SECOND_DECLARED_MODEL),
    )
    .expect("the derived composition");
    assert_ne!(derived.session, pinned.session);
    assert_ne!(derived.live_session, pinned.live_session);
    // A different explicit selection is a different launch, not a reorder.
    assert_ne!(derived.model, pinned.model);

    // Only the identity is pinned: one published-policy digest proves
    // the rest of the derivation matches the fresh-open composition.
    assert_eq!(
        pinned.policy.policy.capability_policy_digest,
        derived.policy.policy.capability_policy_digest
    );

    // The ensured token binds the durable identity and is filed under it.
    let report = ensure_session_token(
        &fixture.config,
        &pinned,
        3_600,
        TokenRenewalPolicy::BoundedSameSession,
    )
    .expect("the pinned session is provisioned");
    assert!(!report.renewed);
    assert_eq!(report.session, opened.session.to_string());
    assert_eq!(
        report.token_path,
        fixture
            .config
            .paths
            .authority_token_root
            .join(format!("{}.json", durable_session))
    );
    let token: odin_domain::SeatToken =
        serde_json::from_slice(&fs::read(&report.token_path).expect("token readable"))
            .expect("token parses");
    assert_eq!(token.session, opened.session);
}
