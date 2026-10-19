use std::process::Command;

#[test]
fn help_exposes_only_the_direct_execution_modes() {
    let output = Command::new(env!("CARGO_BIN_EXE_sweep"))
        .arg("--help")
        .output()
        .expect("sweep help");
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).expect("UTF-8 help");
    assert!(text.contains("--system"));
    assert!(text.contains("--integration"));
    assert!(!text.contains("--grader"));
    assert!(!text.contains("--profile"));
}

#[test]
fn conflicting_modes_fail_before_any_checks_run() {
    let output = Command::new(env!("CARGO_BIN_EXE_sweep"))
        .args(["--system", "--integration"])
        .output()
        .expect("sweep arguments");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}

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
