use super::*;

use crate::authority_provision::entropy::os_random_bytes;
use crate::authority_provision::fixture::{command, fixture};
use crate::authority_provision::private_fs::write_private_atomic;
use crate::authority_provision::token::MINT_ENTROPY_BYTES;
use crate::authority_provision::{compose, init, mint_for_composition, LaunchSelection};
use odin_kernel::{MemoryRevocations, MintRequest, TokenIssuer};

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
fn a_token_living_past_the_ceiling_is_refused_and_left_alone() {
    let fixture = fixture();
    init(&fixture.config).expect("authority initialized");
    let composition = compose(
        &fixture.config,
        "architect",
        "odin",
        &command("command:overlong"),
        LaunchSelection::new(DECLARED_PROVIDER, DECLARED_MODEL),
    )
    .expect("composition");
    let now = unix_millis().expect("clock");
    let entropy = os_random_bytes(MINT_ENTROPY_BYTES).expect("entropy");
    let token = TokenIssuer::new(load_signing_key(&fixture.config).expect("key loads"))
        .expect("issuer")
        .mint_bound(
            MintRequest {
                seat: composition.seat.clone(),
                slice: composition.slice.clone(),
                lane: composition.lane.clone(),
                session: composition.session.clone(),
                seat_revision: composition.policy.policy.seat_revision,
                slice_revision: composition.policy.policy.slice_revision,
                capability_policy_digest: composition.policy.policy.capability_policy_digest,
                context_policy_digest: composition.policy.context_policy_digest,
                issued_at_ms: now,
                expires_at_ms: now + (MAX_TOKEN_TTL_SECONDS + 1) * 1_000,
                entropy: &entropy,
            },
            composition.snapshot_revision,
        )
        .expect("overlong token mints");
    let token_path = fixture
        .config
        .paths
        .authority_token_root
        .join(format!("{}.json", composition.session.as_str()));
    let bytes = serde_json::to_vec_pretty(&token).expect("serializes");
    write_private_atomic(&token_path, &bytes).expect("install overlong token");

    for renewal in [
        TokenRenewalPolicy::OperatorOnly,
        TokenRenewalPolicy::BoundedSameSession,
    ] {
        let error = ensure_session_token(&fixture.config, &composition, 3_600, renewal)
            .expect_err("an overlong token is never reused or renewed");
        assert!(
            matches!(error, EnsureSessionTokenError::Overlong { .. }),
            "unexpected refusal: {error}"
        );
    }
    assert_eq!(fs::read(&token_path).expect("token readable"), bytes);
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
