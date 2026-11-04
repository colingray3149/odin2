//! Stream write failures must not replace the CLI's exit status with a panic.

use std::fs::OpenOptions;
use std::process::{Command, Stdio};

// `/dev/full` fails every write deterministically, like a reader that went away.
#[test]
fn an_error_exit_with_an_unwritable_stderr_is_a_plain_failure() {
    let full = || {
        OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .expect("/dev/full opens")
    };
    let state = tempfile::tempdir().expect("temp state root");
    let status = Command::new(env!("CARGO_BIN_EXE_odin"))
        .args([
            "huginn",
            "--endpoint",
            "https://127.0.0.1:9",
            "--state-root",
        ])
        .arg(state.path())
        .arg("status")
        .stdin(Stdio::null())
        .stdout(Stdio::from(full()))
        .stderr(Stdio::from(full()))
        .status()
        .expect("odin runs");
    assert_eq!(
        status.code(),
        Some(1),
        "a plain failure exit, not an abort: {status:?}"
    );
}
