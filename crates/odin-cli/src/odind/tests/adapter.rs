use super::*;

use crate::test_fixture::{fixture_config_text, manifest_identity_fixture, PublishedStore};

#[test]
fn a_declared_backend_needs_its_manifest_executable() {
    let fixture = PublishedStore::new("laptop", true);
    let root = fixture.temporary.path();
    let manifest = manifest_identity_fixture("adapter.other", &root.join("adapter-other"));

    let none = OdindConfig::parse(&fixture_config_text(root, &fixture.snapshot_path))
        .expect("fixture config parses");
    let backends = declared_adapter_backends(&none, &manifest).expect("no backend declared");
    assert_eq!(backends.ids().count(), 0);

    let declared = format!(
        "{}[adapter_backends.mcp-time]\nargv = ['--adapter', 'mcp-time']\n",
        fixture_config_text(root, &fixture.snapshot_path)
    );
    let declared = OdindConfig::parse(&declared).expect("declared fixture config parses");
    declared
        .validate()
        .expect("declared fixture config validates");
    let error = match declared_adapter_backends(&declared, &manifest) {
        Err(error) => error,
        Ok(_) => panic!("a backend without its manifest executable must be refused"),
    };
    assert!(
        error.contains("mcp-time") && error.contains("adapter.mcp-time"),
        "the refusal names the adapter and its manifest key: {error}"
    );
}
