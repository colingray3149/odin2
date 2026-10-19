use super::*;

use std::fs;
use std::path::{Path, PathBuf};

use odin_registry::SnapshotHandle;

use crate::test_fixture::{fixture_config_text, manifest_identity_fixture, PublishedStore};

#[test]
fn isolated_payload_config_must_match_manifest_identity() {
    let configured = PathBuf::from("/nix/store/scanner/bin/scanner");
    let manifest = manifest_identity_fixture("scanner", &configured);
    bound_manifest_identity(&manifest, "scanner", &configured).expect("bound identity");
    let error = bound_manifest_identity(&manifest, "scanner", Path::new("/usr/bin/scanner"))
        .expect_err("drifted scanner config is rejected");
    assert!(
        error.contains("does not match configured executable"),
        "unexpected error: {error}"
    );
    let error = bound_manifest_identity(&manifest, "xvfb", &configured)
        .expect_err("missing manifest identity is rejected");
    assert!(
        error.contains("runtime manifest xvfb"),
        "unexpected error: {error}"
    );
}

#[test]
fn extension_policy_binds_pinned_snapshot_without_deleting() {
    let fixture = PublishedStore::new("laptop", true);
    let root = fixture.temporary.path();
    let extension = root.join("index.ts");
    fs::write(&extension, b"export const gungnir = true;\n").expect("extension");
    fs::create_dir_all(root.join("state")).expect("state");
    let text = fixture_config_text(root, &fixture.snapshot_path);
    let mut config = OdindConfig::parse(&text).expect("fixture config parses");
    config.executables.extension = extension.clone();
    config.validate().expect("fixture config validates");

    let snapshot = SnapshotHandle::open(fixture.store())
        .expect("open verified store")
        .current();
    let binding = produce_extension_policy(&config, &snapshot).expect("policy produced");
    assert!(binding
        .path
        .starts_with(root.join("state/huginn/extension-policy")));
    let loaded = binding.load().expect("binding loads");
    assert_eq!(loaded.snapshot_revision, snapshot.revision);
    assert_eq!(loaded.config_revision, 1);
    loaded
        .verify_extension_artifact(&extension)
        .expect("extension artifact binds");

    let again = produce_extension_policy(&config, &snapshot).expect("reuse existing");
    assert_eq!(again.path, binding.path);
    assert_eq!(again.digest, binding.digest);
}
