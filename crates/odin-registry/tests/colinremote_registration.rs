//! The shipped registry passes the production admission validators: no
//! declaration in `registry/` carries a failing finding.

use std::path::Path;

use odin_registry::{parse_objects, validate_relations, walk, RelationContext};

#[test]
fn colinremote_registration_is_present_and_passes_admission() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let declarations = [
        "registry/projects/colinremote/project.toml",
        "registry/lanes/architect-colinremote/lane.toml",
        "registry/slices/colinremote-engine/slice.toml",
        "registry/containers/colinremote-native/container.toml",
        "registry/seats/architect/seat.toml",
    ];
    let discovery = walk(root.join("registry"));
    let parsed = parse_objects(&discovery.objects);
    for path in declarations {
        assert!(
            parsed
                .objects
                .iter()
                .any(|object| object.relative_config.ends_with(path)),
            "registration declaration was not admitted: {path}"
        );
    }
    let mut findings = discovery.findings;
    findings.extend(parsed.findings);
    findings.extend(validate_relations(
        &parsed.objects,
        &RelationContext::new(&root),
    ));
    let rejected: Vec<_> = findings
        .iter()
        .filter(|finding| finding.severity == odin_registry::FindingSeverity::Fail)
        .collect();
    assert!(
        rejected.is_empty(),
        "tenant registration rejected: {rejected:?}"
    );
}
