use std::process::Command;

#[test]
fn invalid_workspace_is_an_honest_failure() {
    let root = tempfile::tempdir().expect("empty directory");
    let output = Command::new(env!("CARGO_BIN_EXE_sweep"))
        .arg("--root")
        .arg(root.path())
        .output()
        .expect("sweep workspace validation");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a Cargo workspace"));
}
