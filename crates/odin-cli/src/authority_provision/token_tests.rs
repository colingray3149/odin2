use super::*;

use crate::authority_provision::dir_mode;
use crate::authority_provision::fixture::{command, fixture};
use crate::authority_provision::init;
use odin_domain::SeatId;
use odin_omp::live::supervisor::session_id_for;

/// The fixture seat's first declared launch option, named explicitly on
/// every mint: the launch is a selection, never a positional default.
const DECLARED_PROVIDER: &str = "gateway";
const DECLARED_MODEL: &str = "zai-glm";

#[test]
fn mint_binds_the_exact_supervisor_session_identity_and_bounds_ttl() {
    let fixture = fixture();
    init(&fixture.config).expect("authority initialized");
    let expected = session_id_for(&command("command:fixed")).expect("session id derives");
    for ttl in [0, MAX_TOKEN_TTL_SECONDS + 1] {
        let error = mint(
            &fixture.config,
            "architect",
            "odin",
            &command("command:fixed"),
            LaunchSelection::new(DECLARED_PROVIDER, DECLARED_MODEL),
            ttl,
            false,
        )
        .expect_err("out-of-bounds ttl is rejected");
        assert!(
            error.contains("ttl-seconds"),
            "unexpected error for {ttl}: {error}"
        );
    }
    let report = mint(
        &fixture.config,
        "architect",
        "odin",
        &command("command:fixed"),
        LaunchSelection::new(DECLARED_PROVIDER, DECLARED_MODEL),
        MAX_TOKEN_TTL_SECONDS,
        false,
    )
    .expect("bounded mint succeeds");
    assert_eq!(report.ttl_seconds, MAX_TOKEN_TTL_SECONDS);
    assert_eq!(
        report.expires_at_ms - report.issued_at_ms,
        MAX_TOKEN_TTL_SECONDS * 1_000
    );
    assert_eq!(report.session, expected.to_string());
    assert_eq!(
        report.token_path,
        fixture
            .config
            .paths
            .authority_token_root
            .join(format!("{}.json", expected))
    );
    assert_eq!(dir_mode(&report.token_path), 0o600);
    let token_bytes = fs::read(&report.token_path).expect("token readable");
    let token: odin_domain::SeatToken =
        serde_json::from_slice(&token_bytes).expect("token JSON parses");
    assert_eq!(token.token_id.to_string(), report.token_id);
    assert_eq!(token.seat, SeatId::new("architect").unwrap());
    assert_eq!(
        token.session,
        odin_domain::SessionId::parse(&expected.to_string()).unwrap()
    );
    assert!(!report.renewed);

    // A same-session mint is refused without the explicit renewal choice.
    let error = mint(
        &fixture.config,
        "architect",
        "odin",
        &command("command:fixed"),
        LaunchSelection::new(DECLARED_PROVIDER, DECLARED_MODEL),
        MAX_TOKEN_TTL_SECONDS,
        false,
    )
    .expect_err("same-session mint without --renew is refused");
    assert!(error.contains("--renew"), "unexpected error: {error}");

    // Explicit renewal replaces the token atomically under a new identity.
    let renewed = mint(
        &fixture.config,
        "architect",
        "odin",
        &command("command:fixed"),
        LaunchSelection::new(DECLARED_PROVIDER, DECLARED_MODEL),
        60,
        true,
    )
    .expect("explicit renewal succeeds");
    assert!(renewed.renewed);
    assert_ne!(
        renewed.token_id, report.token_id,
        "renewal mints a new identity"
    );
    assert_eq!(renewed.token_path, report.token_path);
    let replaced = fs::read(&renewed.token_path).expect("replaced token readable");
    assert_ne!(
        odin_domain::Digest::hash(&replaced),
        odin_domain::Digest::hash(&token_bytes),
        "renewal must replace the file content, not keep the old token"
    );
    let replaced_token: odin_domain::SeatToken =
        serde_json::from_slice(&replaced).expect("replaced token parses");
    assert_eq!(
        replaced_token.token_id.to_string(),
        renewed.token_id,
        "the installed file carries exactly the renewed identity"
    );
}

#[test]
fn mint_fails_closed_without_the_key_or_the_pinned_snapshot() {
    let fixture = fixture();
    // Missing snapshot: composition fails before any key is touched.
    let mut broken =
        OdindConfig::load(fixture._temporary.path().join("odind.toml")).expect("config reloads");
    broken.paths.registry_snapshot = fixture
        .config
        .paths
        .state_root
        .join("missing/snapshot.json");
    let error = mint(
        &broken,
        "architect",
        "odin",
        &command("command:no-snapshot"),
        LaunchSelection::new(DECLARED_PROVIDER, DECLARED_MODEL),
        60,
        false,
    )
    .expect_err("missing snapshot is rejected");
    assert!(error.contains("snapshot"), "unexpected error: {error}");

    // Missing key: minting fails honestly and directs at `authority init`.
    let fixture = self::fixture();
    let error = mint(
        &fixture.config,
        "architect",
        "odin",
        &command("command:no-key"),
        LaunchSelection::new(DECLARED_PROVIDER, DECLARED_MODEL),
        60,
        false,
    )
    .expect_err("unprovisioned key path is rejected");
    assert!(
        error.contains("not provisioned yet"),
        "unexpected error: {error}"
    );
}

#[test]
fn rollback_never_unlinks_symlink_or_hardlinked_tokens() {
    let fixture = fixture();
    init(&fixture.config).expect("authority initialized");
    let report = mint(
        &fixture.config,
        "architect",
        "odin",
        &command("command:rollback-links"),
        LaunchSelection::new(DECLARED_PROVIDER, DECLARED_MODEL),
        60,
        false,
    )
    .unwrap();
    let bytes = fs::read(&report.token_path).unwrap();
    let token: SeatToken = serde_json::from_slice(&bytes).unwrap();
    let target = report.token_path.with_extension("saved");
    fs::hard_link(&report.token_path, &target).unwrap();
    assert!(!remove_session_token_if_owned(&report.token_path, &token.token_id).unwrap());
    assert_eq!(fs::read(&report.token_path).unwrap(), bytes);
    fs::remove_file(&report.token_path).unwrap();
    std::os::unix::fs::symlink(&target, &report.token_path).unwrap();
    assert!(!remove_session_token_if_owned(&report.token_path, &token.token_id).unwrap());
    assert!(fs::symlink_metadata(&report.token_path)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read(target).unwrap(), bytes);
}
