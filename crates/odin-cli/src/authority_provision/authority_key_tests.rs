use super::*;

use crate::authority_provision::dir_mode;
use crate::authority_provision::fixture::fixture;

#[test]
fn init_creates_private_roots_and_is_idempotent() {
    let fixture = fixture();
    let report = init(&fixture.config).expect("init provisions");
    let token_root = &report.token_root;
    let key_file = &report.verification_key_file;
    let state_root = &report.state_root;
    assert!(
        !report.state_root_created,
        "snapshot publication created the fixture state root first"
    );
    assert!(report.token_root_created);
    assert!(report.key_created);
    assert_eq!(report.key_bytes, 48);
    assert_eq!(dir_mode(state_root), 0o700);
    assert_eq!(dir_mode(token_root), 0o700);
    assert_eq!(dir_mode(key_file), 0o600);
    let key_before = fs::read(key_file).expect("key readable");
    let key_before_digest = odin_domain::Digest::hash(&key_before);
    assert_eq!(key_before.len(), 48);

    let again = init(&fixture.config).expect("second init is idempotent");
    assert!(!again.token_root_created);
    assert!(!again.state_root_created);
    assert!(!again.key_created);
    let key_after = fs::read(key_file).expect("key readable");
    assert_eq!(
        odin_domain::Digest::hash(&key_after),
        key_before_digest,
        "existing keys are preserved byte-for-byte"
    );
}

#[test]
fn a_loose_key_is_refused_for_use_and_tightened_by_init_without_changing_its_bytes() {
    let fixture = fixture();
    init(&fixture.config).expect("authority initialized");
    let key_file = fixture.config.paths.authority_verification_key_file.clone();
    let key = fs::read(&key_file).expect("key readable");
    fs::set_permissions(&key_file, fs::Permissions::from_mode(0o644)).expect("loosen key");
    let error = load_signing_key(&fixture.config).expect_err("a loose key is not used");
    assert!(error.contains("0600"), "unexpected error: {error}");

    let report = init(&fixture.config).expect("init tightens an owned loose key");
    assert!(!report.key_created);
    assert_eq!(dir_mode(&key_file), 0o600);
    assert_eq!(fs::read(&key_file).expect("key readable"), key);
    load_signing_key(&fixture.config).expect("the tightened key loads");
}
