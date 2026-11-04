use super::*;

use std::fs;
use std::path::{Path, PathBuf};

use crate::test_fixture::{fixture_config_text, PublishedStore};

#[test]
fn operator_context_never_serves_a_protected_root_or_the_whole_home() {
    let fixture = PublishedStore::new("laptop", true);
    let root = fixture.temporary.path();
    let state = root.join("state");
    fs::create_dir_all(&state).expect("state");
    let sibling = root.join("context");
    fs::create_dir_all(&sibling).expect("context");
    let config_with = |context: &Path| {
        let mut config = OdindConfig::parse(&fixture_config_text(root, &fixture.snapshot_path))
            .expect("fixture config parses");
        config.paths.operator_context_root = Some(context.to_owned());
        config
    };
    let none = BTreeMap::new();

    let served = context_read_runtime_config(&config_with(&sibling), &none, 4096)
        .expect("a sibling directory is served")
        .expect("configured");
    assert_eq!(served.root, sibling.canonicalize().unwrap());

    let refusal = |context: &Path| {
        context_read_runtime_config(&config_with(context), &none, 4096)
            .err()
            .expect("the root is refused")
    };
    let overlaps_state = refusal(&state);
    assert!(overlaps_state.contains("overlaps"), "{overlaps_state}");
    let contains_state = refusal(root);
    assert!(contains_state.contains("overlaps"), "{contains_state}");

    let home = std::env::var_os("HOME").map(PathBuf::from).expect("HOME");
    let whole_home = refusal(&home);
    assert!(whole_home.contains("home directory"), "{whole_home}");
}

#[test]
fn children_inherit_the_declared_environment_and_no_interpreter_switches() {
    std::env::set_var("PI_PYTHON_BIN", "/usr/bin/python3");
    std::env::set_var("PI_NODE_BIN", "/usr/bin/node");
    let names: Vec<String> = child_environment()
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    assert!(names.iter().any(|name| name == "PATH"), "{names:?}");
    assert!(
        !names.iter().any(|name| name.starts_with("PI_")),
        "{names:?}"
    );
}
