use super::*;

fn card(
    route: &str,
    served: Option<&str>,
    thinking_default: Option<&str>,
) -> odin_registry::schema::ModelCardToml {
    odin_registry::schema::ModelCardToml {
        order: None,
        schema: "odin.registry.v1".to_owned(),
        kind: RegistryKind::Model,
        enabled: true,
        description: "fixture".to_owned(),
        id: match route {
            GATEWAY_ROUTE => "gateway/astra".to_owned(),
            CLAUDE_ROUTE => "claude/claude-opus-5-5".to_owned(),
            _ => "antigravity/gemini-3-pro".to_owned(),
        },
        served: served.map(str::to_owned),
        route: route.to_owned(),
        capability: "chat".to_owned(),
        tier: Some("frontier".to_owned()),
        account: None,
        strengths: "fixture strengths".to_owned(),
        fallbacks: Vec::new(),
        seats: false,
        family: false,
        brain_serving: false,
        brain_review: false,
        replay_reasoning: true,
        reasoning_effort: true,
        window: None,
        thinking: thinking_default.map(|default| odin_registry::schema::ModelThinkingToml {
            default: Some(default.to_owned()),
            levels: Vec::new(),
            temperature: None,
        }),
        image: None,
        wire: None,
        strict: None,
        tokenizer: None,
    }
}

#[test]
fn official_models_take_the_served_identity_verbatim_for_agy_and_stripped_for_claude() {
    assert_eq!(
        official_model(&card(AGY_ROUTE, Some("gemini-3-pro"), None)),
        Some("gemini-3-pro")
    );
    assert_eq!(
        official_model(&card(
            CLAUDE_ROUTE,
            Some("claude-code/claude-opus-5-5"),
            None
        )),
        Some("claude-opus-5-5")
    );
    assert_eq!(official_model(&card(GATEWAY_ROUTE, None, None)), None);
}

#[test]
fn claude_consult_is_one_question_with_no_tools_and_persisted_sessions() {
    let run = std::env::temp_dir().join("odin-consult-argv-fixture");
    let argv = claude_consult_argv("claude-opus-5-5", "high", &run);
    let value_of = |flag: &str| {
        let at = argv.iter().position(|arg| arg == flag).expect(flag);
        argv[at + 1].as_str()
    };
    assert_eq!(value_of("--model"), "claude-opus-5-5");
    assert_eq!(value_of("--effort"), "high");
    assert_eq!(value_of("--tools"), "", "no tools");
    assert_eq!(value_of("--allowedTools"), "", "no allowed tools");
    assert_eq!(value_of("--output-format"), "json");
    assert!(
        !argv.iter().any(|arg| arg == "--no-session-persistence"),
        "sessions persist so ccusage attributes the spend: {argv:?}"
    );
    assert!(
        !argv
            .iter()
            .any(|arg| arg == "--dangerously-skip-permissions"),
        "{argv:?}"
    );
    assert!(argv.contains(&CONSULT_SYSTEM.to_owned()));
}

/// Writes an executable shell script and returns its absolute path.
fn script(root: &Path, name: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = root.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::canonicalize(&path).unwrap()
}

/// A minimal pinned snapshot, the way the daemon binds one.
fn pinned() -> Arc<SnapshotHandle> {
    let root = tempfile::tempdir().unwrap().keep();
    let snapshot = odin_registry::Snapshot::build(1, Vec::new()).unwrap();
    let mut bytes = serde_json::to_vec_pretty(&snapshot).unwrap();
    bytes.push(b'\n');
    let revisions = root.join("revisions");
    std::fs::create_dir_all(&revisions).unwrap();
    std::fs::write(root.join("snapshot.json"), &bytes).unwrap();
    std::fs::write(revisions.join("00000000000000000001.snapshot.json"), &bytes).unwrap();
    let receipt = json!({
        "schema": odin_registry::PUBLICATION_RECEIPT_SCHEMA,
        "outcome": "published",
        "revision": 1,
        "previous_revision": null,
        "commit": "commit-1",
        "tree": "tree-1",
        "snapshot_hash": snapshot.hash,
    });
    std::fs::write(
        revisions.join("00000000000000000001.receipt.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
    Arc::new(
        SnapshotHandle::open(odin_registry::SnapshotStore::new(
            root.join("snapshot.json"),
        ))
        .unwrap(),
    )
}

#[test]
fn agy_refuses_when_another_profile_is_active_and_never_switches() {
    let root = tempfile::tempdir().unwrap();
    let aisw = script(
        root.path(),
        "aisw",
        r#"echo "$@" >> "$0.calls"; echo '{"agy":{"active":"other-account","profiles":[]},"claude":{}}'"#,
    );
    let calls = aisw.with_extension("calls");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).unwrap();
    let route = DaemonConsultRoute {
        pin: pinned(),
        state_root: state,
        agy: Some(OdindConsultAgyConfig {
            profile: "google-ai-pro".to_owned(),
            binary: root.path().join("agy"),
            aisw,
        }),
    };
    let model = OfficialConsultModel {
        id: "antigravity/gemini-3-pro".to_owned(),
        route: "agy".to_owned(),
        model: "gemini-3-pro".to_owned(),
        effort: "high".to_owned(),
        strengths: String::new(),
    };
    let error = route
        .consult_agy(&model, "q", None)
        .expect_err("must refuse");
    assert!(
        error.contains("aisw use antigravity google-ai-pro")
            && error.contains("other-account")
            && error.contains("google-ai-pro"),
        "{error}"
    );
    assert_eq!(
        std::fs::read_to_string(calls).unwrap().trim(),
        "list --json",
        "only the profile listing ran; the account was never switched"
    );
}

#[test]
fn run_bounded_returns_the_clients_json_and_names_non_json_answers() {
    let root = tempfile::tempdir().unwrap();
    let okay = script(
        root.path(),
        "agy-okay",
        r#"printf '%s' '{"status":"OK","response":"Fine.","duration_seconds":2,"usage":{"input_tokens":3,"output_tokens":5}}'"#,
    );
    let okay_command = Command::new(&okay);
    let value = run_bounded(okay_command, None, Duration::from_secs(10), "agy").unwrap();
    assert_eq!(value["response"], "Fine.");
    let broken = script(root.path(), "agy-broken", r#"printf 'not json at all'"#);
    let broken_command = Command::new(&broken);
    let error =
        run_bounded(broken_command, None, Duration::from_secs(10), "agy").expect_err("non-JSON");
    assert!(error.contains("answered without JSON"), "{error}");
}

#[test]
fn a_client_that_prints_nothing_is_killed_at_the_timeout() {
    let root = tempfile::tempdir().unwrap();
    let silent = script(root.path(), "claude-silent", "sleep 30");
    let command = Command::new(&silent);
    let started = Instant::now();
    let error = run_bounded(command, None, Duration::from_millis(300), "claude")
        .expect_err("a silent client outlives its timeout");
    assert!(error.contains("declared timeout"), "{error}");
    assert!(started.elapsed() < Duration::from_secs(10), "{error}");
}
