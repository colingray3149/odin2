//! The capabilities a person must approve are a declaration fact, not a
//! hardcoded match. This pins the operator capabilities whose decider is the
//! owner.

use std::fs;
use std::path::PathBuf;

use odin_registry::schema::{
    parse_object_toml, ApprovalDeciderToml, CapabilityApprovalToml, ObjectConfig,
};
use odin_registry::RegistryKind;

#[test]
fn owner_gated_operator_capabilities_are_exactly_the_human_gates() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../registry/capabilities");
    let mut owners = Vec::new();
    let entries = fs::read_dir(&root)
        .unwrap_or_else(|error| panic!("read capability declarations {}: {error}", root.display()));
    for entry in entries {
        let entry = entry.unwrap_or_else(|error| panic!("read capability entry: {error}"));
        let path = entry.path().join("capability.toml");
        if !path.is_file() {
            continue;
        }
        let id = entry.file_name().to_string_lossy().into_owned();
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        let object = parse_object_toml(
            RegistryKind::Capability,
            &id,
            format!("registry/capabilities/{id}/capability.toml"),
            &source,
        )
        .unwrap_or_else(|finding| panic!("parse {id}: {finding:?}"));
        let ObjectConfig::Capability(capability) = object.config else {
            panic!("{id} did not parse as a capability");
        };
        if capability.approval_policy == CapabilityApprovalToml::Operator
            && capability.approval_decider == ApprovalDeciderToml::Owner
        {
            owners.push(id);
        }
    }
    owners.sort();
    assert_eq!(
        owners,
        [
            "browser.consequential",
            "email.send",
            "purchase.submit",
            "task.grant",
        ]
    );
}
