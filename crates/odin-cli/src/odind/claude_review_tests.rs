use super::*;
fn profile(binary: String) -> ClaudeReviewToml {
    let mut p: ClaudeReviewToml = toml::from_str::<odin_registry::ClaudeCodeToml>(include_str!(
        "../../../../registry/workloads/claude-review/profile.toml"
    ))
    .unwrap()
    .review
    .unwrap();
    p.binary = binary;
    p
}
#[test]
fn real_bwrap_keeps_bundle_readonly_and_secrets_off_argv_and_env() {
    use std::os::unix::fs::PermissionsExt;
    let bwrap = std::env::var_os("ODIN_TEST_BWRAP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/current-system/sw/bin/bwrap"));
    if !bwrap.exists() {
        panic!(
            "bwrap missing at {}: run inside nix develop (ODIN_TEST_BWRAP)",
            bwrap.display()
        );
    }
    let root = tempfile::tempdir().unwrap();
    let run = root.path();
    fs::create_dir(run.join("bundle")).unwrap();
    fs::write(run.join("bundle/plan.txt"), "PRIVATE-BUNDLE").unwrap();
    fs::write(run.join("credentials"), "PRIVATE-LOGIN").unwrap();
    let sh = fs::canonicalize("/bin/sh").unwrap();
    let stub = run.join("claude");
    fs::write(
        &stub,
        format!(
            r#"#!{}
for arg in "$@"; do printf '%s\n' "$arg" >&2; done
export -p >&2
while IFS= read -r line || [ -n "$line" ]; do printf '%s\n' "$line" >&2; done
if printf bad > /review/input/plan.txt 2>/dev/null; then exit 3; fi
printf '{{"result":"readonly","usage":{{"input_tokens":1,"output_tokens":1}}}}'
"#,
            sh.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&stub, fs::Permissions::from_mode(0o700)).unwrap();
    let result = invoke(
        &bwrap,
        &profile(stub.to_string_lossy().into_owned()),
        &run.join("credentials"),
        run,
        "Review this plan",
        Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(result["result"], "readonly");
    let seen = fs::read_to_string(run.join("launch/stderr")).unwrap();
    assert!(seen.contains("Read,Grep,Glob") && seen.contains("Question: Review this plan"));
    assert!(!seen.contains("PRIVATE-LOGIN") && !seen.contains("PRIVATE-BUNDLE"));
    // `--tools` and `--allowedTools` carry one comma-joined value, so look inside each argument.
    assert!(!seen
        .lines()
        .flat_map(|line| line.split(','))
        .any(|tool| ["Bash", "Write", "Edit"].contains(&tool)));
    assert_eq!(
        fs::read_to_string(run.join("bundle/plan.txt")).unwrap(),
        "PRIVATE-BUNDLE"
    );
}
