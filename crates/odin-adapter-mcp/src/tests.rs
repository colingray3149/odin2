use super::*;

fn config(read_only: &[&str], server: Vec<String>) -> BridgeConfig {
    BridgeConfig {
        adapter: "mcp-time".to_owned(),
        kind_prefix: "time".to_owned(),
        read_only: read_only.iter().map(|tool| (*tool).to_owned()).collect(),
        sequences: Vec::new(),
        expose: Vec::new(),
        load_check: None,
        window: None,
        pdf_text: None,
        server,
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn the_argv_declares_adapter_prefix_read_only_tools_and_server() {
    let parsed = BridgeConfig::parse(&strings(&[
        "--adapter",
        "mcp-time",
        "--kind-prefix",
        "time",
        "--read-only",
        "get_current_time",
        "--",
        "/nix/store/x-mcp-server-time/bin/mcp-server-time",
        "--local-timezone",
        "America/Los_Angeles",
    ]))
    .expect("a complete argv parses");
    assert_eq!(parsed.adapter, "mcp-time");
    assert_eq!(parsed.read_only, vec!["get_current_time"]);
    assert_eq!(parsed.server.len(), 3);
    for broken in [
        strings(&["--adapter", "a", "--kind-prefix", "time"]),
        strings(&["--adapter", "a", "--kind-prefix", "time", "--"]),
        strings(&["--adapter", "a", "--kind-prefix", "Time", "--", "x"]),
        strings(&["--kind-prefix", "time", "--", "x"]),
        strings(&[
            "--adapter",
            "a",
            "--kind-prefix",
            "time",
            "--bogus",
            "x",
            "--",
            "x",
        ]),
    ] {
        assert!(BridgeConfig::parse(&broken).is_err(), "{broken:?}");
    }
}

#[test]
fn read_only_tools_are_r0_pure_and_the_rest_ask_first() {
    let bridge = config(&["get_current_time"], strings(&["/bin/true"]));
    let descriptor = bridge
        .descriptor(&[
            json!({"name": "get_current_time"}),
            json!({"name": "convert_time", "annotations": {"readOnlyHint": true}}),
            json!({"name": "set_alarm"}),
            json!({"name": "Bad Name"}),
        ])
        .expect("descriptor builds");
    let parsed = odin_adapter_core::descriptor::AdapterDescriptor::from_wire(&descriptor)
        .expect("the descriptor passes the canonical schema");
    let classes: Vec<(String, String)> = parsed
        .operations()
        .iter()
        .map(|operation| {
            (
                operation.kind.as_str().to_owned(),
                format!("{:?}", operation.effect_class),
            )
        })
        .collect();
    assert_eq!(
        classes,
        vec![
            ("time.get_current_time".to_owned(), "R0".to_owned()),
            ("time.convert_time".to_owned(), "R0".to_owned()),
            ("time.set_alarm".to_owned(), "R3".to_owned()),
        ],
        "declared read-only and readOnlyHint tools are R0; others R3; unusable names are skipped"
    );
    assert_eq!(
        descriptor["operations"][0]["input_schema"],
        "schemas/capability/time.get_current_time.input.json"
    );
}

#[test]
fn a_new_server_binding_is_a_new_identity() {
    let first = config(&[], strings(&["/nix/store/a-mcp/bin/mcp"]));
    let second = config(&[], strings(&["/nix/store/b-mcp/bin/mcp"]));
    assert_ne!(first.binding_digest(), second.binding_digest());
    assert_eq!(first.binding_digest(), first.clone().binding_digest());
}

#[test]
fn a_tool_error_is_never_a_success() {
    assert!(call_result(
        json!({"content": [{"type": "text", "text": "bad zone"}], "isError": true})
    )
    .is_err());
    let ok = call_result(json!({
        "content": [{"type": "text", "text": "{\"datetime\":\"x\"}"}],
        "structuredContent": {"datetime": "x"},
    }))
    .expect("success");
    assert_eq!(ok["structuredContent"]["datetime"], "x");
}

/// A minimal stdio MCP server in POSIX sh: answers initialize, tools/list
/// and tools/call by echoing the request id; ignores notifications. A hung
/// call execs its sleep, so stopping the server ends it.
fn fake_server(directory: &std::path::Path, hang_on_call: bool) -> Vec<String> {
    let call = if hang_on_call {
        "exec sleep 30".to_owned()
    } else {
        r#"printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"12:00"}]}}\n' "$id""#
            .to_owned()
    };
    let script = format!(
        r#"while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  case "$line" in
    *'"initialize"'*) printf '{{"jsonrpc":"2.0","method":"notifications/message","params":{{}}}}\n'; printf '{{"jsonrpc":"2.0","id":%s,"result":{{"protocolVersion":"2025-06-18","capabilities":{{}},"serverInfo":{{"name":"fake","version":"1"}}}}}}\n' "$id" ;;
    *'"tools/list"'*) printf '{{"jsonrpc":"2.0","id":%s,"result":{{"tools":[{{"name":"get_current_time"}}]}}}}\n' "$id" ;;
    *'"tools/call"'*) {call} ;;
  esac
done
"#
    );
    let path = directory.join("fake-mcp.sh");
    std::fs::write(&path, script).expect("fake server written");
    vec!["/bin/sh".to_owned(), path.to_string_lossy().into_owned()]
}

#[test]
fn a_session_lists_and_calls_through_a_real_stdio_server() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = fake_server(directory.path(), false);
    let mut session = McpSession::open(&server, Duration::from_secs(10)).expect("handshake");
    let tools = session.tools().expect("tools/list");
    assert_eq!(tools[0]["name"], "get_current_time");
    let result = session
        .request(
            "tools/call",
            json!({"name": "get_current_time", "arguments": {}}),
        )
        .expect("tools/call");
    assert_eq!(call_result(result).unwrap()["content"][0]["text"], "12:00");
}

#[test]
fn a_hung_server_times_out_typed_and_a_missing_one_fails_to_spawn() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = fake_server(directory.path(), true);
    let mut session = McpSession::open(&server, Duration::from_secs(2)).expect("handshake");
    let started = Instant::now();
    let error = session
        .request(
            "tools/call",
            json!({"name": "get_current_time", "arguments": {}}),
        )
        .expect_err("a hung call is bounded");
    assert!(matches!(error, BridgeError::Timeout(_)), "{error:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
    let missing = McpSession::open(
        &strings(&["/nonexistent/mcp-server"]),
        Duration::from_secs(2),
    );
    assert!(matches!(missing, Err(BridgeError::Spawn(_))));
}

#[test]
fn a_server_that_dies_keeps_its_stderr_and_a_missing_one_names_the_spawn_error() {
    let directory = tempfile::tempdir().expect("tempdir");
    let script = directory.path().join("die.sh");
    std::fs::write(&script, "echo mcp-stderr-canary >&2\nexit 1\n").expect("script");
    let script = script.to_string_lossy().into_owned();
    let Err(error) = McpSession::open(&strings(&["/bin/sh", &script]), Duration::from_secs(2))
    else {
        panic!("a server that exits before initialize fails");
    };
    let shown = error.to_string();
    assert!(
        shown.contains("mcp-stderr-canary"),
        "stderr cause missing: {shown}"
    );
    assert!(
        !matches!(error, BridgeError::Spawn(_)),
        "a started server is not a spawn failure: {error:?}"
    );

    let Err(missing) = McpSession::open(
        &strings(&["/nonexistent/mcp-server-cause"]),
        Duration::from_secs(2),
    ) else {
        panic!("missing executable");
    };
    let BridgeError::Spawn(detail) = missing else {
        panic!("missing executable is a spawn failure: {missing:?}");
    };
    assert!(
        detail.contains("os error") || detail.contains("No such file"),
        "spawn cause missing: {detail}"
    );
    assert!(!detail.contains("mcp-stderr-canary"), "{detail}");
}

#[test]
fn a_failing_converter_keeps_its_stderr_and_drops_the_document_url() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = converter(
        directory.path(),
        "echo converter-cause-canary >&2\necho \"$1\" >&2\nexit 3",
    );
    let url = "https://example.invalid/secret-document.pdf";
    let error = super::read::pdf_text(&path, url, Instant::now() + Duration::from_secs(5))
        .expect_err("converter exit 3");
    let BridgeError::PdfText(detail) = error else {
        panic!("converter failure stays PdfText: {error:?}");
    };
    assert!(detail.contains("converter-cause-canary"), "{detail}");
    assert!(!detail.contains(url), "document URL leaked: {detail}");
    assert!(!detail.contains("secret-document"), "{detail}");
}

#[test]
fn a_repeated_long_converter_url_does_not_leak_at_the_tail_boundary() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = converter(
        directory.path(),
        "printf '%s\\n%s\\nconverter-tail-canary\\n' \"$1\" \"$1\" >&2\nexit 3",
    );
    let url = format!(
        "https://example.invalid/{}/private-boundary-canary",
        "x".repeat(super::NOTE_BYTES * 2),
    );
    let error = super::read::pdf_text(&path, &url, Instant::now() + Duration::from_secs(2))
        .expect_err("converter failure");
    let BridgeError::PdfText(detail) = error else {
        panic!("converter failure stays PdfText: {error:?}");
    };
    assert!(detail.contains("converter-tail-canary"), "{detail}");
    assert!(!detail.contains("private-boundary-canary"), "{detail}");
    assert!(!detail.contains(&url), "{detail}");
}

#[test]
fn a_later_server_exit_keeps_its_stderr() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = scripted_server(
        directory.path(),
        "",
        r#"    *'"tools/list"'*) printf 'later-stderr-canary\n' >&2; exit 3 ;;"#,
    );
    let mut session = McpSession::open(&server, Duration::from_secs(2)).expect("handshake");
    let error = session.tools().expect_err("server exited");
    assert!(matches!(error, BridgeError::Protocol(_)), "{error:?}");
    assert!(error.to_string().contains("later-stderr-canary"), "{error}");
}

#[test]
fn a_stderr_flooding_descendant_cannot_extend_the_session_deadline() {
    let directory = tempfile::tempdir().expect("tempdir");
    let script = directory.path().join("stderr-descendant.sh");
    std::fs::write(
        &script,
        "printf 'descendant-stderr-canary\\n' >&2\n(trap 'exit 0' PIPE; while :; do printf 'descendant-stderr-canary\\n' >&2 || exit; done) &\nexit 1\n",
    )
    .expect("script");
    let server = vec!["/bin/sh".to_owned(), script.to_string_lossy().into_owned()];
    let started = Instant::now();
    let Err(error) = McpSession::open(&server, Duration::from_millis(100)) else {
        panic!("server did not initialize");
    };
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(
        matches!(error, BridgeError::Timeout(_) | BridgeError::Protocol(_)),
        "{error:?}"
    );
    assert!(
        error.to_string().contains("descendant-stderr-canary"),
        "{error}"
    );
}

#[test]
fn an_expired_session_refuses_even_when_its_answer_is_already_buffered() {
    let root = tempfile::tempdir().expect("private server root");
    let ready_path = root.path().join("answer-queued");
    let mut server = scripted_server(
        root.path(),
        "",
        r#"    *'"notifications/initialized"'*)
      printf '{"jsonrpc":"2.0","id":2,"result":{"marker":"queued"}}\n'
      : > "$1" ;;"#,
    );
    server.push(ready_path.to_string_lossy().into_owned());
    let bound = Duration::from_secs(2);
    let mut session = McpSession::open(&server, bound).expect("handshake before the bound");
    let ready_deadline = Instant::now() + bound;
    while !ready_path.exists() {
        assert!(
            Instant::now() < ready_deadline,
            "the server never queued its answer"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    std::thread::sleep(bound);
    let error = session
        .request(
            "tools/call",
            json!({"name": "get_current_time", "arguments": {}}),
        )
        .expect_err("readable and writable pipes cannot extend an expired session");
    assert!(matches!(error, BridgeError::Timeout(_)), "{error:?}");
}

/// A stdio MCP server in POSIX sh speaking the protocol of [`fake_server`]
/// with builtins only, so no helper process outlives a write and stopping
/// the one shell ends every byte it produces. `prelude` runs once; `arms`
/// are further `case` arms over each request `$line`, its `$id` parsed;
/// the caller appends any script arguments to the returned argv.
fn scripted_server(directory: &std::path::Path, prelude: &str, arms: &str) -> Vec<String> {
    let script = format!(
        r#"{prelude}
while IFS= read -r line; do
  rest=${{line#*\"id\":}}; id=${{rest%%[!0-9]*}}
  case "$line" in
    *'"initialize"'*) printf '{{"jsonrpc":"2.0","id":%s,"result":{{"protocolVersion":"2025-06-18","capabilities":{{}},"serverInfo":{{"name":"fake","version":"1"}}}}}}\n' "$id" ;;
{arms}
  esac
done
"#
    );
    let path = directory.join("scripted-mcp.sh");
    std::fs::write(&path, script).expect("scripted server written");
    vec!["/bin/sh".to_owned(), path.to_string_lossy().into_owned()]
}

/// Builds `$chunk`, 64 KiB of `x`, with builtins.
const CHUNK: &str =
    r#"chunk=x; i=0; while [ "$i" -lt 16 ]; do chunk=$chunk$chunk; i=$((i+1)); done"#;

/// Reject oversized lines before consuming the server's full output, with or without a newline.
#[test]
fn an_unterminated_or_oversize_line_stops_at_the_line_bound() {
    for mode in ["unterminated", "oversize"] {
        let directory = tempfile::tempdir().expect("tempdir");
        let drained = directory.path().join("drained");
        let mut server = scripted_server(
            directory.path(),
            CHUNK,
            r#"    *'"tools/list"'*)
      n=0; while [ "$n" -lt 384 ]; do printf '%s' "$chunk"; n=$((n+1)); done
      : > "$2"
      if [ "$1" = oversize ]; then printf '\n{"jsonrpc":"2.0","id":%s,"result":{"tools":[]}}\n' "$id"; fi ;;"#,
        );
        server.extend([mode.to_owned(), drained.to_string_lossy().into_owned()]);
        let mut session = McpSession::open(&server, Duration::from_secs(10)).expect("handshake");
        let error = session.tools().expect_err(mode);
        assert!(
            matches!(error, BridgeError::Protocol(_)),
            "{mode}: {error:?}"
        );
        drop(session);
        assert!(
            !drained.exists(),
            "{mode}: the reader consumed the whole 24 MiB line"
        );
    }
}

/// Unsolicited notifications count against the next request's read limit.
#[test]
fn a_notification_flood_fails_the_next_answer_instead_of_queueing() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = scripted_server(
        directory.path(),
        CHUNK,
        r#"    *'"notifications/initialized"'*)
      n=0; while [ "$n" -lt 768 ]; do printf '{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"%s"}}\n' "$chunk"; n=$((n+1)); done ;;
    *'"tools/list"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"get_current_time"}]}}\n' "$id" ;;"#,
    );
    let mut session = McpSession::open(&server, Duration::from_secs(20)).expect("handshake");
    let error = session
        .tools()
        .expect_err("a 48 MiB flood is past the read bound of one answer");
    assert!(matches!(error, BridgeError::Protocol(_)), "{error:?}");
}

#[test]
fn a_server_that_stops_reading_times_out_the_write_at_the_session_deadline() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = scripted_server(
        directory.path(),
        "",
        r#"    *'"notifications/initialized"'*) exec sleep 20 ;;"#,
    );
    let mut session = McpSession::open(&server, Duration::from_secs(3)).expect("handshake");
    let started = Instant::now();
    let error = session
        .request(
            "tools/call",
            json!({"name": "get_current_time", "arguments": {"blob": "x".repeat(4 << 20)}}),
        )
        .expect_err("a write into a full pipe is bounded");
    assert!(matches!(error, BridgeError::Timeout(_)), "{error:?}");
    assert!(
        started.elapsed() < Duration::from_secs(12),
        "the server's exit, not the session deadline, ended the write"
    );
}

/// Cursor, item, and byte limits prevent endless pagination and unbounded buffering.
#[test]
fn a_listing_stops_at_a_repeated_cursor_and_at_its_item_and_byte_bound() {
    let directory = tempfile::tempdir().expect("tempdir");
    let prelude = r#"mode=$1; fresh=0
page() {
  if [ -n "$2" ]; then printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":%s,"nextCursor":"%s"}}\n' "$id" "$1" "$2"
  else printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":%s}}\n' "$id" "$1"; fi
}
if [ "$mode" = items ]; then
  a=; b=; i=0
  while [ "$i" -lt 2500 ]; do a="$a{\"name\":\"a$i\"},"; b="$b{\"name\":\"b$i\"},"; i=$((i+1)); done
  a="[${a%,}]"; b="[${b%,}]"
fi
if [ "$mode" = bytes ]; then
  d=x; i=0; while [ "$i" -lt 21 ]; do d=$d$d; i=$((i+1)); done
  big="[{\"name\":\"big\",\"description\":\"$d$d$d\"}]"
fi"#;
    let arms = r#"    *'"tools/list"'*)
      cursor=
      case "$line" in *'"cursor":"'*) rest=${line#*\"cursor\":\"}; cursor=${rest%%\"*} ;; esac
      case "$mode:$cursor" in
        pages:) page '[{"name":"a"}]' p2 ;;
        pages:p2) page '[{"name":"b"}]' p3 ;;
        pages:p3) page '[{"name":"c"}]' '' ;;
        cycle:) page '[{"name":"a"}]' A ;;
        cycle:A) page '[{"name":"b"}]' B ;;
        cycle:B) page '[{"name":"c"}]' A ;;
        fresh:*) fresh=$((fresh+1)); page '[]' "c$fresh" ;;
        items:) page "$a" p2 ;;
        items:p2) page "$b" '' ;;
        bytes:) page "$big" p2 ;;
        bytes:p2) page "$big" '' ;;
      esac ;;"#;
    let server = scripted_server(directory.path(), prelude, arms);
    let listing = |mode: &str| {
        let mut server = server.clone();
        server.push(mode.to_owned());
        McpSession::open(&server, Duration::from_secs(10))
            .expect("handshake")
            .tools()
    };
    let names: Vec<Value> = listing("pages")
        .expect("a paged listing")
        .iter()
        .map(|tool| tool["name"].clone())
        .collect();
    assert_eq!(names, vec![json!("a"), json!("b"), json!("c")]);
    for mode in ["cycle", "fresh", "items", "bytes"] {
        let error = listing(mode).expect_err(mode);
        assert!(
            matches!(error, BridgeError::Protocol(_)),
            "{mode}: {error:?}"
        );
    }
}

fn browser_bridge(server: Vec<String>) -> BridgeConfig {
    BridgeConfig::parse(
        &[
            strings(&[
                "--adapter",
                "obscura",
                "--kind-prefix",
                "web",
                "--read-only",
                "browser_navigate",
                "--read-only",
                "browser_markdown",
                "--sequence",
                "read=browser_navigate,browser_markdown",
                "--",
            ]),
            server,
        ]
        .concat(),
    )
    .expect("a sequence bridge parses")
}

fn browser_tools() -> Vec<Value> {
    vec![
        json!({"name": "browser_navigate", "inputSchema": {"properties": {"url": {}, "waitUntil": {}}}}),
        json!({"name": "browser_markdown", "inputSchema": {"properties": {"max_chars": {}}}}),
        json!({"name": "browser_click", "inputSchema": {"properties": {"selector": {}}}}),
    ]
}

#[test]
fn a_declared_sequence_is_the_only_operation_and_is_r0_when_every_step_reads() {
    let bridge = browser_bridge(strings(&["/bin/true"]));
    let descriptor = bridge.descriptor(&browser_tools()).expect("descriptor");
    let parsed = odin_adapter_core::descriptor::AdapterDescriptor::from_wire(&descriptor)
        .expect("canonical descriptor");
    let kinds: Vec<(String, String)> = parsed
        .operations()
        .iter()
        .map(|operation| {
            (
                operation.kind.as_str().to_owned(),
                format!("{:?}", operation.effect_class),
            )
        })
        .collect();
    assert_eq!(kinds, vec![("web.read".to_owned(), "R0".to_owned())]);
    assert_eq!(
        bridge.plan("web.read"),
        Some(strings(&["browser_navigate", "browser_markdown"]))
    );
    assert_eq!(bridge.plan("web.browser_click"), None);
    assert!(bridge.descriptor(&browser_tools()[1..]).is_err());
    assert!(BridgeConfig::parse(&strings(&[
        "--adapter",
        "a",
        "--kind-prefix",
        "web",
        "--sequence",
        "read",
        "--",
        "x"
    ]))
    .is_err());
}

#[test]
fn each_step_gets_the_fields_its_schema_names() {
    let input = json!({"url": "https://arxiv.org/abs/1706.03762", "max_chars": 2000});
    let tools = browser_tools();
    assert_eq!(
        step_arguments(&input, Some(&tools[0])),
        json!({"url": "https://arxiv.org/abs/1706.03762"})
    );
    assert_eq!(
        step_arguments(&input, Some(&tools[1])),
        json!({"max_chars": 2000})
    );
    assert_eq!(step_arguments(&input, None), json!({}));
}

#[test]
fn a_sequence_keeps_the_server_state_between_its_steps() {
    let directory = tempfile::tempdir().expect("tempdir");
    let script = r##"page=none
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  case "$line" in
    *'"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"fake","version":"1"}}}\n' "$id" ;;
    *'"tools/list"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"browser_navigate","inputSchema":{"properties":{"url":{}}}},{"name":"browser_markdown","inputSchema":{"properties":{"max_chars":{}}}}]}}\n' "$id" ;;
    *'"browser_navigate"'*'"max_chars"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"isError":true,"content":[{"type":"text","text":"unexpected field"}]}}\n' "$id" ;;
    *'"browser_navigate"'*) page=$(printf '%s' "$line" | sed -n 's/.*"url":"\([^"]*\)".*/\1/p'); printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"ok"}]}}\n' "$id" ;;
    *'"browser_markdown"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"# %s"}]}}\n' "$id" "$page" ;;
  esac
done
"##;
    let path = directory.path().join("fake-browser.sh");
    std::fs::write(&path, script).expect("fake browser written");
    let server = vec!["/bin/sh".to_owned(), path.to_string_lossy().into_owned()];
    let bridge = browser_bridge(server.clone());
    let plan = bridge.plan("web.read").expect("planned");
    let mut session = McpSession::open(&server, Duration::from_secs(10)).expect("handshake");
    let result = session
        .call_plan(
            &plan,
            &json!({"url": "https://arxiv.org/abs/1706.03762", "max_chars": 2000}),
            Rules::default(),
        )
        .expect("the sequence runs");
    assert_eq!(
        result["content"][0]["text"],
        "# https://arxiv.org/abs/1706.03762"
    );
}

/// HTTP error pages can navigate successfully; DNS and SSRF failures return `isError`.
/// The request log reports the document's status first.
fn obscura_like(directory: &std::path::Path) -> Vec<String> {
    let script = r##"page=none
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  case "$line" in
    *'"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"fake","version":"1"}}}\n' "$id" ;;
    *'"tools/list"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"browser_navigate","inputSchema":{"properties":{"url":{}}}},{"name":"browser_markdown","inputSchema":{"properties":{"max_chars":{}}}},{"name":"browser_network_requests","inputSchema":{"properties":{}}}]}}\n' "$id" ;;
    *unreachable*'"browser_navigate"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"isError":true,"content":[{"type":"text","text":"Error: Network error: https://unreachable.example/: error sending request"}]}}\n' "$id" ;;
    *'"browser_navigate"'*) page=$(printf '%s' "$line" | sed -n 's/.*"url":"\([^"]*\)".*/\1/p'); printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"Navigated to %s"}]}}\n' "$id" "$page" ;;
    *'"browser_network_requests"'*)
      case "$page" in
        *missing*) log="[404] GET $page (7229B)\\n[200] GET https://example.org/style.css (65992B)" ;;
        *blank*) log="" ;;
        *) log="[200] GET $page (41853B)" ;;
      esac
      printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"%s"}]}}\n' "$id" "$log" ;;
    *'"browser_markdown"'*)
      case "$page" in
        *empty*) text="  " ;;
        *) text="# $page" ;;
      esac
      printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"%s"}]}}\n' "$id" "$text" ;;
  esac
done
"##;
    let path = directory.join("obscura-like.sh");
    std::fs::write(&path, script).expect("fake browser written");
    vec!["/bin/sh".to_owned(), path.to_string_lossy().into_owned()]
}

fn read_page(server: &[String], url: &str) -> Result<Value, BridgeError> {
    let plan = strings(&["browser_navigate", "browser_markdown"]);
    McpSession::open(server, Duration::from_secs(10))
        .expect("handshake")
        .call_plan(
            &plan,
            &json!({"url": url}),
            Rules {
                load_check: Some("browser_network_requests"),
                ..Rules::default()
            },
        )
}

#[test]
fn a_page_that_did_not_load_is_a_typed_failure_never_content() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = obscura_like(directory.path());
    let read = read_page(&server, "https://arxiv.org/abs/1609.07625").expect("a loaded page reads");
    assert_eq!(
        read["content"][0]["text"],
        "# https://arxiv.org/abs/1609.07625"
    );
    for url in [
        "https://arxiv.org/abs/missing",
        "https://unreachable.example/",
        "about:blank",
        "https://example.org/empty",
    ] {
        let error = read_page(&server, url).expect_err(url);
        assert!(
            matches!(error, BridgeError::PageLoad(_)),
            "{url}: {error:?}"
        );
    }
}

#[test]
fn the_document_is_the_first_logged_request() {
    assert_eq!(
        loaded_document(
            "[200] GET https://a.example/x (10B)\n[404] GET https://a.example/y.css (0B)"
        ),
        Ok("https://a.example/x".to_owned())
    );
    assert!(matches!(
        loaded_document("[500] GET https://a.example/x (0B)"),
        Err(BridgeError::PageLoad(_))
    ));
    assert!(matches!(loaded_document(""), Err(BridgeError::PageLoad(_))));
}

#[test]
fn a_load_check_is_declared_listed_and_part_of_the_identity() {
    let mut bridge = browser_bridge(strings(&["/bin/true"]));
    let unchecked = bridge.binding_digest();
    bridge.load_check = Some("browser_network_requests".to_owned());
    assert_ne!(bridge.binding_digest(), unchecked);
    assert!(
        bridge.descriptor(&browser_tools()).is_err(),
        "a load check the server does not list refuses the descriptor"
    );
}

/// PDF navigation can succeed while Markdown contains raw PDF bytes and echoes `max_chars`.
fn pdf_browser(directory: &std::path::Path) -> Vec<String> {
    let script = r##"page=none
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  case "$line" in
    *'"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"fake","version":"1"}}}\n' "$id" ;;
    *'"tools/list"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"browser_navigate","inputSchema":{"properties":{"url":{}}}},{"name":"browser_markdown","inputSchema":{"properties":{"max_chars":{}}}},{"name":"browser_network_requests","inputSchema":{"properties":{}}}]}}\n' "$id" ;;
    *'"browser_navigate"'*) page=$(printf '%s' "$line" | sed -n 's/.*"url":"\([^"]*\)".*/\1/p'); printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"Navigated"}]}}\n' "$id" ;;
    *'"browser_network_requests"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"[200] GET %s (1134375B)"}]}}\n' "$id" "$page" ;;
    *'"browser_markdown"'*)
      asked=$(printf '%s' "$line" | sed -n 's/.*"max_chars":\([0-9]*\).*/\1/p')
      case "$page" in
        *pdf*) text="%PDF-1.7\\n%\\u00ef\\u00bf\\u00bd stream asked=$asked" ;;
        *) text="0123456789abcdefghij asked=$asked" ;;
      esac
      printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"%s"}]}}\n' "$id" "$text" ;;
  esac
done
"##;
    let path = directory.join("pdf-browser.sh");
    std::fs::write(&path, script).expect("fake browser written");
    vec!["/bin/sh".to_owned(), path.to_string_lossy().into_owned()]
}

fn converter(directory: &std::path::Path, body: &str) -> String {
    let path = directory.join("pdf-text.sh");
    let mut writer = std::fs::File::create(&path).expect("converter created");
    // An inherited writer keeps write access and this flock after the parent
    // closes; the read-only lock waits until those writers exit.
    rustix::fs::flock(&writer, rustix::fs::FlockOperation::LockExclusive).expect("converter lock");
    std::io::Write::write_all(&mut writer, format!("#!/bin/sh\n{body}\n").as_bytes())
        .expect("converter written");
    drop(writer);
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .expect("converter executable");
    let reader = std::fs::File::open(&path).expect("converter reopened");
    rustix::fs::flock(&reader, rustix::fs::FlockOperation::LockExclusive).expect("converter quiet");
    path.to_string_lossy().into_owned()
}

fn read_with(
    server: &[String],
    input: &Value,
    rules: Rules<'_>,
    bound: Duration,
) -> Result<Value, BridgeError> {
    McpSession::open(server, bound)
        .expect("handshake")
        .call_plan(
            &strings(&["browser_navigate", "browser_markdown"]),
            input,
            rules,
        )
}

#[test]
fn a_pdf_page_reads_as_the_converters_text_never_its_bytes() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = pdf_browser(directory.path());
    let input = json!({"url": "https://arxiv.org/pdf/2101.04749"});
    let unconverted = read_with(
        &server,
        &input,
        Rules {
            load_check: Some("browser_network_requests"),
            ..Rules::default()
        },
        Duration::from_secs(10),
    )
    .expect("a page without a converter reads as rendered");
    assert!(text_of(&unconverted).starts_with("%PDF-1.7"));
    let script = converter(
        directory.path(),
        r#"printf 'ChemNODE: A Neural Ordinary Differential Equations Framework\nfrom %s\n' "$1""#,
    );
    let rules = Rules {
        load_check: Some("browser_network_requests"),
        window: None,
        pdf_text: Some(&script),
    };
    let read = read_with(&server, &input, rules, Duration::from_secs(10)).expect("converted");
    assert_eq!(
        text_of(&read),
        "ChemNODE: A Neural Ordinary Differential Equations Framework\nfrom https://arxiv.org/pdf/2101.04749\n"
    );
    let html = read_with(
        &server,
        &json!({"url": "https://arxiv.org/abs/2101.04749"}),
        rules,
        Duration::from_secs(10),
    )
    .expect("an HTML page never runs the converter");
    assert!(text_of(&html).starts_with("0123456789"));
}

#[test]
fn a_converter_that_fails_or_hangs_is_a_typed_bounded_failure() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = pdf_browser(directory.path());
    let input = json!({"url": "https://arxiv.org/pdf/2101.04749"});
    let failing = converter(directory.path(), "echo partial; exit 3");
    let rules = Rules {
        load_check: Some("browser_network_requests"),
        window: None,
        pdf_text: Some(&failing),
    };
    let error = read_with(&server, &input, rules, Duration::from_secs(10)).expect_err("exit 3");
    assert!(matches!(error, BridgeError::PdfText(_)), "{error:?}");
    let blank_dir = tempfile::tempdir().expect("tempdir");
    let blank = converter(blank_dir.path(), "printf '\\n\\n'");
    let error = read_with(
        &server,
        &input,
        Rules {
            pdf_text: Some(&blank),
            ..rules
        },
        Duration::from_secs(10),
    )
    .expect_err("a scanned PDF has no text");
    assert!(matches!(error, BridgeError::PageLoad(_)), "{error:?}");
    let hang_dir = tempfile::tempdir().expect("tempdir");
    let hanging = converter(hang_dir.path(), "exec sleep 30");
    let started = Instant::now();
    let error = read_with(
        &server,
        &input,
        Rules {
            pdf_text: Some(&hanging),
            ..rules
        },
        Duration::from_secs(3),
    )
    .expect_err("a hung converter is bounded by the session");
    assert!(matches!(error, BridgeError::Timeout(_)), "{error:?}");
    assert!(started.elapsed() < Duration::from_secs(6));
}

#[test]
fn a_converter_printing_past_the_cap_is_rejected_not_truncated() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = pdf_browser(directory.path());
    let input = json!({"url": "https://arxiv.org/pdf/2101.04749"});
    let cap = 8 << 20;
    let overflowing = converter(
        directory.path(),
        &format!("head -c {} /dev/zero | tr '\\0' 'b'", cap + 1),
    );
    let error = read_with(
        &server,
        &input,
        Rules {
            load_check: Some("browser_network_requests"),
            window: None,
            pdf_text: Some(&overflowing),
        },
        Duration::from_secs(10),
    )
    .expect_err("past the cap the read is rejected, not truncated");
    assert!(matches!(error, BridgeError::PdfText(_)), "{error:?}");
}

/// A converter is read until it exits, not until every descendant that
/// inherited its output lets go: one that leaves a sleeper holding the
/// pipe still reads as the text it printed before exiting.
#[test]
fn a_converter_descendant_holding_its_output_does_not_hold_the_read() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = pdf_browser(directory.path());
    let lingering = converter(directory.path(), "sleep 8 &\nprintf 'converted text\\n'");
    let started = Instant::now();
    let read = read_with(
        &server,
        &json!({"url": "https://arxiv.org/pdf/2101.04749"}),
        Rules {
            load_check: Some("browser_network_requests"),
            window: None,
            pdf_text: Some(&lingering),
        },
        Duration::from_secs(4),
    )
    .expect("the converter's exit ends its output");
    assert!(started.elapsed() < Duration::from_secs(4));
    assert_eq!(text_of(&read), "converted text\n");
}

#[test]
fn the_cap_itself_is_accepted_in_full_and_still_needs_a_clean_exit() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = pdf_browser(directory.path());
    let input = json!({"url": "https://arxiv.org/pdf/2101.04749"});
    let cap = 8 << 20;
    let exact = converter(
        directory.path(),
        &format!("head -c {} /dev/zero | tr '\\0' 'a'", cap),
    );
    let rules = Rules {
        load_check: Some("browser_network_requests"),
        window: None,
        pdf_text: Some(&exact),
    };
    let read = read_with(&server, &input, rules, Duration::from_secs(10))
        .expect("the cap itself is not an overflow");
    let text = text_of(&read);
    assert_eq!(text.len(), cap);
    assert!(
        text.bytes().all(|byte| byte == b'a'),
        "the full cap arrives"
    );
    let failing = converter(
        directory.path(),
        &format!("head -c {} /dev/zero | tr '\\0' 'a'; exit 3", cap),
    );
    let error = read_with(
        &server,
        &input,
        Rules {
            pdf_text: Some(&failing),
            ..rules
        },
        Duration::from_secs(10),
    )
    .expect_err("at the cap a failed exit is still a rejection");
    assert!(matches!(error, BridgeError::PdfText(_)), "{error:?}");
}

#[test]
fn a_windowed_read_asks_for_the_whole_page_and_serves_it_from_offset() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = pdf_browser(directory.path());
    let rules = Rules {
        load_check: Some("browser_network_requests"),
        window: Some("max_chars"),
        pdf_text: None,
    };
    let url = "https://arxiv.org/abs/2101.04749";
    let first = read_with(
        &server,
        &json!({"url": url, "max_chars": 10}),
        rules,
        Duration::from_secs(10),
    )
    .expect("first window");
    assert_eq!(
        text_of(&first),
        "0123456789\n\n[characters 0-10 of 34; the rest follows from offset 10]"
    );
    let last = read_with(
        &server,
        &json!({"url": url, "max_chars": 500, "offset": 10}),
        rules,
        Duration::from_secs(10),
    )
    .expect("last window");
    assert_eq!(text_of(&last), "abcdefghij asked=2000000");
    let past = read_with(
        &server,
        &json!({"url": url, "offset": 34}),
        rules,
        Duration::from_secs(10),
    )
    .expect_err("past the end");
    assert_eq!(
        past,
        BridgeError::OffsetPastEnd {
            offset: 34,
            total: 34
        }
    );
}

#[test]
fn a_windowed_pdf_read_serves_the_converters_text_from_an_offset() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = pdf_browser(directory.path());
    let script = converter(directory.path(), "printf 'éééééééééé0123456789'");
    let rules = Rules {
        load_check: Some("browser_network_requests"),
        window: Some("max_chars"),
        pdf_text: Some(&script),
    };
    let first = read_with(
        &server,
        &json!({"url": "https://arxiv.org/pdf/2101.04749", "offset": 8, "max_chars": 4}),
        rules,
        Duration::from_secs(10),
    )
    .expect("first window of the converted text");
    assert_eq!(
        text_of(&first),
        "éé01\n\n[characters 8-12 of 20; the rest follows from offset 12]"
    );
    let rest = read_with(
        &server,
        &json!({"url": "https://arxiv.org/pdf/2101.04749", "offset": 12}),
        rules,
        Duration::from_secs(10),
    )
    .expect("the rest from the named offset");
    assert_eq!(text_of(&rest), "23456789");
}

#[test]
fn a_pdf_continuation_past_two_million_names_an_offset_the_schema_admits() {
    const URL: &str = "https://arxiv.org/pdf/2101.04749";
    const TAIL: &str = "; the rest follows from offset ";
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/capability/web.read.input.json"
    ))
    .expect("the committed web.read input schema parses");
    let validator = jsonschema::options()
        .build(&schema)
        .expect("the input schema compiles");
    let refusal = |input: serde_json::Value| {
        validator
            .iter_errors(&input)
            .next()
            .map(|error| error.to_string())
    };
    let text = "a".repeat(2_100_000);
    let mut offset = 2_000_000usize;
    let mut hops = 0;
    let tail = loop {
        hops += 1;
        assert!(hops < 10, "the advertised tail never ends");
        assert_eq!(
            refusal(json!({"url": URL, "offset": offset, "max_chars": 40_000})),
            None,
            "the schema must admit the read from {offset}"
        );
        let served = text_of(
            &crate::read::window(
                &text,
                &json!({"offset": offset, "max_chars": 40_000}),
                "max_chars",
            )
            .expect("the window the schema admits serves"),
        );
        match served.rfind(TAIL) {
            Some(marker) => {
                offset = served[marker + TAIL.len()..]
                    .trim_end_matches(']')
                    .parse()
                    .expect("the window names a numeric next offset");
            }
            None => break served,
        }
    };
    assert!(
        offset > 2_000_000,
        "a continuation was advertised past 2000000"
    );
    assert_eq!(tail, &text[offset..], "the last window ends the page");
    assert!(
        refusal(json!({"url": URL, "offset": 8_388_608, "max_chars": 40_000})).is_some(),
        "one position past the byte cap stays refused"
    );
    assert_eq!(
        refusal(json!({"url": URL, "offset": 8_388_607, "max_chars": 40_000})),
        None,
        "the last byte-cap position stays admitted"
    );
}

#[test]
fn a_window_counts_characters_and_defaults_to_four_thousand() {
    let text = "é".repeat(5_000);
    let served =
        crate::read::window(&text, &json!({"offset": 4_999}), "max_chars").expect("window");
    assert_eq!(text_of(&served), "é");
    let default = crate::read::window(&text, &json!({}), "max_chars").expect("window");
    assert!(text_of(&default).starts_with(&"é".repeat(4_000)));
    assert!(text_of(&default)
        .ends_with("[characters 0-4000 of 5000; the rest follows from offset 4000]"));
}

#[test]
fn window_and_converter_are_declared_and_part_of_the_identity() {
    let mut argv = strings(&[
        "--adapter",
        "obscura",
        "--kind-prefix",
        "web",
        "--sequence",
        "read=browser_navigate,browser_markdown",
    ]);
    let plain =
        BridgeConfig::parse(&[argv.clone(), strings(&["--", "x"])].concat()).expect("parses");
    argv.extend(strings(&[
        "--window",
        "max_chars",
        "--pdf-text",
        "/nix/store/x-pdf-text",
        "--",
        "x",
    ]));
    let declared = BridgeConfig::parse(&argv).expect("parses");
    assert_eq!(declared.rules().window, Some("max_chars"));
    assert_eq!(declared.rules().pdf_text, Some("/nix/store/x-pdf-text"));
    assert_ne!(declared.binding_digest(), plain.binding_digest());
}
