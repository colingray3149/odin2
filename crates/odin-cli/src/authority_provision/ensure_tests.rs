use super::*;

use crate::authority_provision::entropy::os_random_bytes;
use crate::authority_provision::fixture::{command, fixture, write_object, SEAT_TOML};
use crate::authority_provision::token::MINT_ENTROPY_BYTES;
use crate::authority_provision::{
    compose, compose_for_session, init, mint_for_composition, LaunchSelection,
};
use crate::test_support::commit_all;
use odin_kernel::{MemoryRevocations, MintRequest, TokenIssuer};
use odin_registry::SnapshotStore;

/// The fixture seat's first declared launch option, named explicitly on
/// every composition: the launch is a selection, never a positional default.
const DECLARED_PROVIDER: &str = "gateway";
const DECLARED_MODEL: &str = "zai-glm";

#[test]
fn same_command_reuses_verified_token_but_revocation_never_auto_renews() {
    use odin_kernel::RevocationStore as _;

    let fixture = fixture();
    init(&fixture.config).expect("authority initialized");
    let command_id = command("command:reuse");
    let composition = compose(
        &fixture.config,
        "architect",
        "odin",
        &command_id,
        LaunchSelection::new(DECLARED_PROVIDER, DECLARED_MODEL),
    )
    .expect("composition");
    let first = mint_for_composition(&fixture.config, &composition, 3_600, false)
        .expect("initial token minted");
    let original_bytes = fs::read(&first.token_path).expect("token readable");

    // Valid tokens are reused byte-for-byte under both renewal policies.
    for renewal in [
        TokenRenewalPolicy::OperatorOnly,
        TokenRenewalPolicy::BoundedSameSession,
    ] {
        let reused = ensure_session_token(&fixture.config, &composition, 3_600, renewal)
            .expect("same command reuses valid authority");
        assert!(reused.reused_existing);
        assert!(!reused.renewed);
        assert_eq!(reused.renewal_reason, None);
        assert_eq!(reused.session, first.session);
        assert_eq!(reused.token_id, first.token_id);
        assert_eq!(
            odin_domain::Digest::hash(&fs::read(&reused.token_path).unwrap()),
            odin_domain::Digest::hash(&original_bytes)
        );
    }

    let token: odin_domain::SeatToken =
        serde_json::from_slice(&original_bytes).expect("token parses");
    let ledger = Ledger::open(fixture.config.paths.state_root.join("ledger.sqlite3"))
        .expect("revocation ledger");
    LedgerRevocations::new(&ledger)
        .revoke(&token.token_id, first.issued_at_ms.saturating_add(1))
        .expect("revoke token");

    // Neither renewal policy may bypass revocation.
    for renewal in [
        TokenRenewalPolicy::OperatorOnly,
        TokenRenewalPolicy::BoundedSameSession,
    ] {
        let error = ensure_session_token(&fixture.config, &composition, 3_600, renewal)
            .expect_err("revoked authority is never auto-renewed");
        match error {
            EnsureSessionTokenError::Revoked { token_id } => {
                assert_eq!(token_id, token.token_id.to_string());
            }
            other => panic!("expected the typed revoked refusal, got: {other}"),
        }
    }
    assert_eq!(
        odin_domain::Digest::hash(
            &fs::read(&first.token_path).expect("revoked token remains installed"),
        ),
        odin_domain::Digest::hash(&original_bytes),
        "failed reuse must not change the token file"
    );

    let replacement = mint_for_composition(&fixture.config, &composition, 60, true)
        .expect("explicit operator renewal succeeds");
    assert!(replacement.renewed);
    assert!(!replacement.reused_existing);
    assert_eq!(replacement.renewal_reason, None);
    assert_ne!(replacement.token_id, first.token_id);
}

#[test]
fn renewal_retains_the_bound_generation_across_a_new_publication_and_closed_never_revives() {
    let fixture = fixture();
    init(&fixture.config).expect("authority initialized");
    let command_id = command("command:drift");
    let composition = compose(
        &fixture.config,
        "architect",
        "odin",
        &command_id,
        LaunchSelection::new(DECLARED_PROVIDER, DECLARED_MODEL),
    )
    .expect("composition");
    let durable_session = composition.live_session;
    let first = ensure_session_token(
        &fixture.config,
        &composition,
        1,
        TokenRenewalPolicy::OperatorOnly,
    )
    .expect("revision-one authority provisioned (one-second bound)");
    let first_bytes = fs::read(&first.token_path).expect("token readable");
    let first_token: odin_domain::SeatToken =
        serde_json::from_slice(&first_bytes).expect("token parses");
    assert_eq!(first_token.served_revision, Some(1));

    // The roll: the seat declaration changes and a new registry revision
    // is published — exactly what a deploy does.
    let worktree = fixture._temporary.path().join("authoring");
    write_object(
        &worktree,
        "seats",
        "architect",
        "seat.toml",
        &SEAT_TOML.replace(
            "categories = [\"builder\", \"coordinator\"]",
            "categories = [\"builder\", \"coordinator\", \"reviewer\"]",
        ),
    );
    let commit = commit_all(&worktree, "authority fixture registry roll");
    let candidate = odin_registry::ValidatedSnapshotCandidate::from_committed_worktree(
        &worktree,
        &commit,
        odin_omp::host_tools::PRE_ADMITTED_BINDINGS
            .iter()
            .map(|binding| binding.to_admitted_binding()),
    )
    .expect("rolled authority fixture candidate");
    SnapshotStore::new(&fixture.config.paths.registry_snapshot)
        .publish_committed(&candidate, 2)
        .expect("publish rolled authority fixture snapshot");

    // The pinned durable composition reads the ROLLED snapshot, under the
    // durable session's own persisted launch pair.
    let rolled = compose_for_session(
        &fixture.config,
        "architect",
        "odin",
        &command_id,
        durable_session,
        LaunchSelection::new(composition.provider.as_str(), composition.model.as_str()),
    )
    .expect("rolled composition");
    assert_eq!(rolled.snapshot_revision, 2);

    // Expire the one-second token before exercising renewal.
    std::thread::sleep(std::time::Duration::from_millis(1_200));

    // Renewal retains the session's publication and advances its issuance time.
    let renewed = ensure_session_token(
        &fixture.config,
        &rolled,
        3_600,
        TokenRenewalPolicy::BoundedSameSession,
    )
    .expect("the expired bound session renews its OWN generation");
    assert!(renewed.renewed);
    assert!(!renewed.reused_existing);
    assert_eq!(renewed.session, first.session, "identity is preserved");
    let renewed_token: odin_domain::SeatToken =
        serde_json::from_slice(&fs::read(&renewed.token_path).expect("renewed readable"))
            .expect("renewed token parses");
    assert_eq!(
        renewed_token.served_revision,
        Some(1),
        "renewal retains the session's bound generation"
    );
    assert_eq!(
        renewed_token.seat_revision, first_token.seat_revision,
        "renewal recomposes the retained seat material, never the roll"
    );
    assert_eq!(
        renewed_token.capability_policy_digest, first_token.capability_policy_digest,
        "renewal recomposes the retained admission material"
    );
    assert_ne!(renewed.token_id, first.token_id);
    assert!(
        renewed.issued_at_ms > first.issued_at_ms,
        "renewal issuance is strictly monotonic for the lease gate"
    );

    // The renewed token now verifies against its retained generation: the
    // same call reuses it byte-for-byte even though the registry head is
    // at revision 2.
    let reused = ensure_session_token(
        &fixture.config,
        &rolled,
        3_600,
        TokenRenewalPolicy::BoundedSameSession,
    )
    .expect("the renewed token is current for its own generation");
    assert!(reused.reused_existing);
    assert!(!reused.renewed);

    // A closed token can never revive: revoking the renewed identity
    // refuses the next ensure typed and leaves the file untouched.
    let ledger = Ledger::open(fixture.config.paths.state_root.join("ledger.sqlite3"))
        .expect("revocation ledger");
    LedgerRevocations::new(&ledger)
        .revoke(
            &renewed_token.token_id,
            renewed.issued_at_ms.saturating_add(1),
        )
        .expect("revoke renewed token");
    let revived = ensure_session_token(
        &fixture.config,
        &rolled,
        3_600,
        TokenRenewalPolicy::BoundedSameSession,
    );
    match revived {
        Err(EnsureSessionTokenError::Revoked { token_id }) => {
            assert_eq!(token_id, renewed_token.token_id.to_string());
        }
        other => panic!("revoked authority can never revive: {other:?}"),
    }
}

#[test]
fn expired_is_eligible_but_unauthentic_or_foreign_authority_is_never_renewed() {
    let fixture = fixture();
    init(&fixture.config).expect("authority initialized");
    let command_id = command("command:expiry");
    let composition = compose(
        &fixture.config,
        "architect",
        "odin",
        &command_id,
        LaunchSelection::new(DECLARED_PROVIDER, DECLARED_MODEL),
    )
    .expect("composition");
    let token_path = fixture
        .config
        .paths
        .authority_token_root
        .join(format!("{}.json", composition.session.as_str()));
    let signing_key = load_signing_key(&fixture.config).expect("key loads");
    let now = unix_millis().expect("clock");

    // An already-expired token that otherwise authenticates: signed with
    // the real key and bound to the exact composition identity/policy.
    let entropy = os_random_bytes(MINT_ENTROPY_BYTES).expect("entropy");
    let expired_token = TokenIssuer::new(signing_key.clone())
        .expect("issuer")
        .mint(MintRequest {
            seat: composition.seat.clone(),
            slice: composition.slice.clone(),
            lane: composition.lane.clone(),
            session: composition.session.clone(),
            seat_revision: composition.policy.policy.seat_revision,
            slice_revision: composition.policy.policy.slice_revision,
            capability_policy_digest: composition.policy.policy.capability_policy_digest,
            context_policy_digest: composition.policy.context_policy_digest,
            issued_at_ms: now.saturating_sub(7_200_000),
            expires_at_ms: now.saturating_sub(3_600_000),
            entropy: &entropy,
        })
        .expect("expired token mints");
    fs::write(
        &token_path,
        serde_json::to_vec_pretty(&expired_token).expect("serializes"),
    )
    .expect("install expired token");
    fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).expect("protect");

    let error = ensure_session_token(
        &fixture.config,
        &composition,
        3_600,
        TokenRenewalPolicy::OperatorOnly,
    )
    .expect_err("the operator law refuses expiry");
    assert!(
        matches!(
            error,
            EnsureSessionTokenError::RenewalNotPermitted {
                reason: TokenReissueReason::Expired { .. },
                ..
            }
        ),
        "unexpected refusal: {error}"
    );

    // Same-session renewal must advance issuance and match the composition.
    let renewed = ensure_session_token(
        &fixture.config,
        &composition,
        3_600,
        TokenRenewalPolicy::BoundedSameSession,
    )
    .expect("expiry is renewal-eligible under the bounded law");
    assert!(renewed.renewed);
    match &renewed.renewal_reason {
        Some(TokenReissueReason::Expired { expires_at_ms, .. }) => {
            assert_eq!(*expires_at_ms, expired_token.expires_at_ms);
        }
        other => panic!("expected the typed expiry reason, got: {other:?}"),
    }
    assert!(renewed.issued_at_ms > expired_token.issued_at_ms);
    let renewed_token: odin_domain::SeatToken =
        serde_json::from_slice(&fs::read(&renewed.token_path).expect("renewed readable"))
            .expect("renewed token parses");
    FreshAuthority::verify(
        &renewed_token,
        expected_bindings(&composition),
        signing_key.clone(),
        MemoryRevocations::default(),
        unix_millis().expect("clock"),
    )
    .expect("the renewed token verifies against the composition");

    // A MALFORMED file is never renewed: garbage proves no identity.
    fs::write(&token_path, b"{ not json").expect("install garbage");
    fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).expect("protect");
    let garbage_digest = odin_domain::Digest::hash(&fs::read(&token_path).unwrap());
    for renewal in [
        TokenRenewalPolicy::OperatorOnly,
        TokenRenewalPolicy::BoundedSameSession,
    ] {
        let error = ensure_session_token(&fixture.config, &composition, 3_600, renewal)
            .expect_err("malformed authority is never renewed");
        assert!(
            matches!(error, EnsureSessionTokenError::MalformedJson { .. }),
            "unexpected refusal: {error}"
        );
    }
    assert_eq!(
        odin_domain::Digest::hash(&fs::read(&token_path).unwrap()),
        garbage_digest
    );

    // A validly signed token for a DIFFERENT session is foreign
    // authority for this seam and is never renewed — not even when it is
    // also expired: identity authentication precedes every eligibility.
    let foreign_entropy = os_random_bytes(MINT_ENTROPY_BYTES).expect("entropy");
    let foreign_session =
        odin_domain::SessionId::parse("00000000-0000-4000-8000-0000000000be").unwrap();
    let foreign = TokenIssuer::new(signing_key.clone())
        .expect("issuer")
        .mint(MintRequest {
            seat: composition.seat.clone(),
            slice: composition.slice.clone(),
            lane: composition.lane.clone(),
            session: foreign_session.clone(),
            seat_revision: composition.policy.policy.seat_revision,
            slice_revision: composition.policy.policy.slice_revision,
            capability_policy_digest: composition.policy.policy.capability_policy_digest,
            context_policy_digest: composition.policy.context_policy_digest,
            issued_at_ms: now.saturating_sub(7_200_000),
            expires_at_ms: now.saturating_sub(3_600_000),
            entropy: &foreign_entropy,
        })
        .expect("foreign token mints");
    fs::write(
        &token_path,
        serde_json::to_vec_pretty(&foreign).expect("serializes"),
    )
    .expect("install foreign token");
    fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).expect("protect");
    let foreign_digest = odin_domain::Digest::hash(&fs::read(&token_path).unwrap());
    for renewal in [
        TokenRenewalPolicy::OperatorOnly,
        TokenRenewalPolicy::BoundedSameSession,
    ] {
        let error = ensure_session_token(&fixture.config, &composition, 3_600, renewal)
            .expect_err("foreign authority is never renewed");
        match error {
            EnsureSessionTokenError::ForeignBinding {
                field,
                expected,
                actual,
            } => {
                assert_eq!(field, "session");
                assert_eq!(expected, composition.session.as_str());
                assert_eq!(actual, foreign_session.as_str());
            }
            other => panic!("expected the typed foreign refusal, got: {other}"),
        }
    }
    assert_eq!(
        odin_domain::Digest::hash(&fs::read(&token_path).unwrap()),
        foreign_digest
    );
}

#[test]
fn legacy_authority_is_admitted_only_through_one_proven_retained_generation() {
    use odin_omp::host_tools::operations::RevisionMaterialSource as _;

    let fixture = fixture();
    init(&fixture.config).expect("authority initialized");
    let command_id = command("command:legacy");
    let composition = compose(
        &fixture.config,
        "architect",
        "odin",
        &command_id,
        LaunchSelection::new(DECLARED_PROVIDER, DECLARED_MODEL),
    )
    .expect("composition");
    let token_path = fixture
        .config
        .paths
        .authority_token_root
        .join(format!("{}.json", composition.session.as_str()));
    let signing_key = load_signing_key(&fixture.config).expect("key loads");
    let now = unix_millis().expect("clock");

    // The pre-revision-binding shape: the exact v2 claims the retained
    // publication's composition derives, minted with NO served_revision.
    let entropy = os_random_bytes(MINT_ENTROPY_BYTES).expect("entropy");
    let legacy = TokenIssuer::new(signing_key.clone())
        .expect("issuer")
        .mint(MintRequest {
            seat: composition.seat.clone(),
            slice: composition.slice.clone(),
            lane: composition.lane.clone(),
            session: composition.session.clone(),
            seat_revision: composition.policy.policy.seat_revision,
            slice_revision: composition.policy.policy.slice_revision,
            capability_policy_digest: composition.policy.policy.capability_policy_digest,
            context_policy_digest: composition.policy.context_policy_digest,
            issued_at_ms: now.saturating_sub(1_000),
            expires_at_ms: now.saturating_add(3_600_000),
            entropy: &entropy,
        })
        .expect("legacy token mints");
    assert_eq!(legacy.served_revision, None);

    // Exactly one retained publication matches the legacy token's digests.
    let source = crate::runtime_bindings::StoreRevisionMaterial::new(
        SnapshotStore::new(&fixture.config.paths.registry_snapshot),
        fixture.config.clone(),
    );
    assert_eq!(
        source
            .resolve_legacy(&legacy)
            .expect("one retained publication proves the generation"),
        1
    );

    // The admission: ensure reuses the proven legacy authority
    // byte-for-byte — never re-minting it, never moving it to current.
    fs::write(
        &token_path,
        serde_json::to_vec_pretty(&legacy).expect("serializes"),
    )
    .expect("install legacy token");
    fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).expect("protect");
    let installed_digest = odin_domain::Digest::hash(&fs::read(&token_path).unwrap());
    let reused = ensure_session_token(
        &fixture.config,
        &composition,
        3_600,
        TokenRenewalPolicy::OperatorOnly,
    )
    .expect("proven legacy authority is reused");
    assert!(reused.reused_existing);
    assert!(!reused.renewed);
    assert_eq!(
        odin_domain::Digest::hash(&fs::read(&token_path).unwrap()),
        installed_digest
    );

    // UNPROVEN authority refuses typed: the same legacy shape carrying a
    // capability digest no retained publication admits proves nothing and
    // admits nothing — there is no current or zero default.
    let unproven_entropy = os_random_bytes(MINT_ENTROPY_BYTES).expect("entropy");
    let unproven = TokenIssuer::new(signing_key)
        .expect("issuer")
        .mint(MintRequest {
            seat: composition.seat.clone(),
            slice: composition.slice.clone(),
            lane: composition.lane.clone(),
            session: composition.session.clone(),
            seat_revision: composition.policy.policy.seat_revision,
            slice_revision: composition.policy.policy.slice_revision,
            capability_policy_digest: odin_domain::Digest::hash(b"never admitted"),
            context_policy_digest: composition.policy.context_policy_digest,
            issued_at_ms: now.saturating_sub(1_000),
            expires_at_ms: now.saturating_add(3_600_000),
            entropy: &unproven_entropy,
        })
        .expect("unproven token mints");
    let error = source
        .resolve_legacy(&unproven)
        .expect_err("unproven legacy digests must refuse");
    assert!(
        error.contains("no retained publication"),
        "unexpected refusal: {error}"
    );
}

// Include the retained revision in refusal so callers can open a successor session.
#[test]
fn an_unrecomposable_bound_generation_refuses_typed_with_its_revision() {
    let fixture = fixture();
    init(&fixture.config).expect("authority initialized");
    let command_id = command("unrecomposable-bound");
    let composition = compose(
        &fixture.config,
        "architect",
        "odin",
        &command_id,
        LaunchSelection::new(DECLARED_PROVIDER, DECLARED_MODEL),
    )
    .expect("composition");
    ensure_session_token(
        &fixture.config,
        &composition,
        1,
        TokenRenewalPolicy::OperatorOnly,
    )
    .expect("revision-one authority provisioned");
    let worktree = fixture._temporary.path().join("authoring");
    write_object(
        &worktree,
        "seats",
        "architect",
        "seat.toml",
        &SEAT_TOML.replace(
            "categories = [\"builder\", \"coordinator\"]",
            "categories = [\"builder\", \"coordinator\", \"reviewer\"]",
        ),
    );
    let commit = commit_all(&worktree, "authority fixture registry roll");
    let candidate = odin_registry::ValidatedSnapshotCandidate::from_committed_worktree(
        &worktree,
        &commit,
        odin_omp::host_tools::PRE_ADMITTED_BINDINGS
            .iter()
            .map(|binding| binding.to_admitted_binding()),
    )
    .expect("rolled authority fixture candidate");
    SnapshotStore::new(&fixture.config.paths.registry_snapshot)
        .publish_committed(&candidate, 2)
        .expect("publish rolled authority fixture snapshot");
    // The bound generation's material is gone from the retained store.
    let snapshot = &fixture.config.paths.registry_snapshot;
    let retained = snapshot
        .parent()
        .expect("snapshot directory")
        .join("revisions")
        .join(format!("{:020}.snapshot.json", 1));
    fs::remove_file(&retained).expect("retained revision one removed");
    let rolled = compose_for_session(
        &fixture.config,
        "architect",
        "odin",
        &command_id,
        composition.live_session,
        LaunchSelection::new(composition.provider.as_str(), composition.model.as_str()),
    )
    .expect("rolled composition");
    assert!(matches!(
        ensure_session_token(
            &fixture.config,
            &rolled,
            60,
            TokenRenewalPolicy::BoundedSameSession
        ),
        Err(EnsureSessionTokenError::BoundGenerationUnavailable { bound: 1, .. })
    ));
}
