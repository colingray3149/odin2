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
fn compose_selects_the_named_declared_launch_and_refuses_undeclared_pairs() {
    let fixture = fixture();
    // The named pair is honoured even when it is NOT the first declared
    // option: selection is explicit, never positional.
    let selected = compose(
        &fixture.config,
        "architect",
        "odin",
        &command("command:explicit-second-option"),
        LaunchSelection::new(DECLARED_PROVIDER, SECOND_DECLARED_MODEL),
    )
    .expect("the declared second option is selectable");
    assert_eq!(selected.provider.as_str(), DECLARED_PROVIDER);
    assert_eq!(selected.model.as_str(), SECOND_DECLARED_MODEL);
    let first = compose(
        &fixture.config,
        "architect",
        "odin",
        &command("command:explicit-first-option"),
        LaunchSelection::new(DECLARED_PROVIDER, FIRST_DECLARED_MODEL),
    )
    .expect("the declared first option is selectable");
    assert_eq!(first.model.as_str(), FIRST_DECLARED_MODEL);
    assert_ne!(selected.model, first.model);

    // A pair the seat does not declare refuses typed, naming the declared
    // options — through the SAME predicate the supervisor's open admission
    // enforces, so no authority can be composed for an open that refuses.
    for model in ["undeclared-model", "gpt-6-astra"] {
        let error = compose(
            &fixture.config,
            "architect",
            "odin",
            &command("command:undeclared-pair"),
            LaunchSelection::new(DECLARED_PROVIDER, model),
        )
        .expect_err("an undeclared pair is refused");
        assert!(
            error.contains("does not declare the selected launch"),
            "unexpected error: {error}"
        );
        assert!(
            error.contains(&format!("{DECLARED_PROVIDER}/{FIRST_DECLARED_MODEL}"))
                && error.contains(&format!("{DECLARED_PROVIDER}/{SECOND_DECLARED_MODEL}")),
            "the refusal must name every declared option: {error}"
        );
    }
    let error = compose(
        &fixture.config,
        "architect",
        "odin",
        &command("command:undeclared-provider"),
        LaunchSelection::new("openai-codex", FIRST_DECLARED_MODEL),
    )
    .expect_err("an undeclared provider is refused");
    assert!(
        error.contains("does not declare the selected launch"),
        "unexpected error: {error}"
    );

    // Preflight rejects the undeclared pair before approval.
    let error = preflight_compose(
        &fixture.config,
        "architect",
        "odin",
        LaunchSelection::new(DECLARED_PROVIDER, "undeclared-model"),
    )
    .expect_err("preflight refuses the undeclared pair");
    assert!(
        error.contains("does not declare the selected launch"),
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

#[test]
fn preflight_compose_runs_the_derivation_law_read_only() {
    let fixture = fixture();
    // Unknown seat: the same derivation refusal `compose` produces.
    let error = preflight_compose(
        &fixture.config,
        "gungnir",
        "odin",
        LaunchSelection::new(DECLARED_PROVIDER, FIRST_DECLARED_MODEL),
    )
    .expect_err("an unknown seat refuses the derivation law");
    assert!(error.contains("gungnir"), "unexpected error: {error}");
    // Unknown project: the same session-lane refusal `compose` produces.
    let error = preflight_compose(
        &fixture.config,
        "architect",
        "research",
        LaunchSelection::new(DECLARED_PROVIDER, FIRST_DECLARED_MODEL),
    )
    .expect_err("an unbound project refuses the derivation law");
    assert!(
        error.contains("no configured session lane"),
        "unexpected error: {error}"
    );
    let readiness = preflight_compose(
        &fixture.config,
        "architect",
        "odin",
        LaunchSelection::new(DECLARED_PROVIDER, SECOND_DECLARED_MODEL),
    )
    .expect("the declared seat and project derive");
    let composed = compose(
        &fixture.config,
        "architect",
        "odin",
        &command("command:preflight-compose"),
        LaunchSelection::new(DECLARED_PROVIDER, SECOND_DECLARED_MODEL),
    )
    .expect("compose");
    assert_eq!(readiness.provider, composed.provider);
    assert_eq!(readiness.model, composed.model);
    assert_eq!(readiness.lane, composed.lane);
    assert_eq!(readiness.project_root, composed.project_root);
    // Read-only: the derivation mints nothing — the authority token root
    // stays exactly as it was.
    let token_root = fixture.config.paths.authority_token_root.clone();
    let before = file_list(&token_root);
    preflight_compose(
        &fixture.config,
        "architect",
        "odin",
        LaunchSelection::new(DECLARED_PROVIDER, FIRST_DECLARED_MODEL),
    )
    .expect("ready");
    assert_eq!(file_list(&token_root), before, "preflight writes nothing");
}

fn file_list(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        if let Ok(entries) = std::fs::read_dir(&directory) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    pending.push(path);
                } else {
                    files.push(path);
                }
            }
        }
    }
    files.sort();
    files
}
