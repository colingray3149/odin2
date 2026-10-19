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
fn init_rejects_symlinked_roots_and_never_resets_an_existing_key() {
    let fixture = fixture();
    let token_root = fixture.config.paths.authority_token_root.clone();
    fs::create_dir_all(token_root.parent().unwrap()).expect("parent");
    let elsewhere = fixture.config.paths.state_root.join("elsewhere");
    fs::create_dir_all(&elsewhere).expect("elsewhere");
    std::os::unix::fs::symlink(&elsewhere, &token_root).expect("symlink token root");
    let error = init(&fixture.config).expect_err("symlinked token root is rejected");
    assert!(error.contains("symlink"), "unexpected error: {error}");

    // An owned world-readable token root is tightened, never refused.
    let fixture = self::fixture();
    let token_root = fixture.config.paths.authority_token_root.clone();
    fs::create_dir_all(&token_root).expect("loose token root");
    fs::set_permissions(&token_root, fs::Permissions::from_mode(0o755)).expect("loosen");
    let report = init(&fixture.config).expect("init tightens an owned loose root");
    assert_eq!(dir_mode(&report.token_root), 0o700);

    // A symlinked key file and a short existing key both fail closed with
    // the key preserved: there is no hidden reset.
    let fixture = self::fixture();
    let key_file = fixture.config.paths.authority_verification_key_file.clone();
    fs::create_dir_all(key_file.parent().unwrap()).expect("key parent");
    std::os::unix::fs::symlink(
        fixture.config.paths.state_root.join("elsewhere.key"),
        &key_file,
    )
    .expect("symlink key");
    let error = init(&fixture.config).expect_err("symlinked key is rejected");
    assert!(error.contains("symlink"), "unexpected error: {error}");

    let fixture = self::fixture();
    let key_file = fixture.config.paths.authority_verification_key_file.clone();
    fs::create_dir_all(key_file.parent().unwrap()).expect("key parent");
    fs::write(&key_file, b"too-short").expect("short key");
    let error = init(&fixture.config).expect_err("short key is rejected");
    assert!(
        error.contains("replace it explicitly"),
        "unexpected error: {error}"
    );
    assert_eq!(
        odin_domain::Digest::hash(&fs::read(&key_file).expect("short key preserved")),
        odin_domain::Digest::hash(b"too-short")
    );

    let fixture = self::fixture();
    let mut hard_linked = fixture.config.clone();
    let key_file = hard_linked.paths.authority_verification_key_file.clone();
    fs::create_dir_all(key_file.parent().unwrap()).expect("key parent");
    fs::write(
        &key_file,
        os_random_bytes(GENERATED_KEY_BYTES).expect("fixture key entropy"),
    )
    .expect("existing key");
    fs::hard_link(
        &key_file,
        fixture.config.paths.state_root.join("exposed.key"),
    )
    .expect("hard-link key");
    let error = init(&hard_linked).expect_err("hard-linked key is rejected");
    assert!(
        error.contains("multiple hard links"),
        "unexpected error: {error}"
    );
    let git_root = fixture.config.paths.state_root.join("authoring");
    fs::create_dir_all(&git_root).expect("create nested git root");
    crate::test_support::git(&git_root, &["-c", "init.defaultBranch=main", "init"]);
    hard_linked.paths.authority_token_root = git_root.join("private-authority/tokens");
    hard_linked.paths.authority_verification_key_file = fixture
        ._temporary
        .path()
        .join("authoring/private-authority/verification.key");
    let error = init(&hard_linked).expect_err("Git-contained roots are rejected");
    assert!(error.contains("Git worktree"), "unexpected error: {error}");
}
