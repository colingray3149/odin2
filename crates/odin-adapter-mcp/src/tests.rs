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
        article_text: None,
        surface: PIN.to_owned(),
        server,
    }
}

/// Any 64 lowercase hex digits parse as a pin; a test that lists tools pins what its server lists.
const PIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn pinned(mut config: BridgeConfig, tools: &[Value]) -> BridgeConfig {
    config.surface = config
        .surface_digest(tools)
        .expect("the tools canonicalize");
    config
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn a_tool_error_names_its_cause_and_drops_the_url() {
    for (said, cause) in [
        (
            "Error: Network error: https://secret.example/: client error (Connect) \
             (source: Some(ConnectError(\"dns error\")))",
            "the site's name did not resolve",
        ),
        (
            "Error: Access to private/internal IP address https://10.0.0.1/",
            "its address is private, and private networks are blocked",
        ),
        (
            "Error: the document answered HTTP 403 for https://secret.example/",
            "the document answered HTTP 403",
        ),
        (
            "Error: unsupported content encoding from https://secret.example/document",
            "the site used an unsupported content encoding",
        ),
    ] {
        let error =
            call_result(json!({"content": [{"type": "text", "text": said}], "isError": true}))
                .expect_err(cause);
        assert_eq!(error, BridgeError::Tool(cause.to_owned()), "{said}");
        let shown = error.to_string();
        assert!(
            !shown.contains("secret.example") && !shown.contains("10.0.0.1"),
            "{shown}"
        );
    }
    let timed_out = "Error: Network error: https://secret.example/path: error sending request \
                     (source: Some(TimedOut))";
    let error =
        call_result(json!({"content": [{"type": "text", "text": timed_out}], "isError": true}))
            .expect_err("a time-out is refused");
    assert_eq!(
        error,
        BridgeError::Refused("the site did not answer in time".to_owned())
    );
    assert_eq!(error.to_string(), "the site did not answer in time");
    for (said, cause) in [
        (
            "{\"error\":\"project not found: home-colin-x\"}",
            "the tool said: project not found: home-colin-x",
        ),
        (
            "\ngit diff exited with status 128\nfatal: bad revision",
            "the tool said: git diff exited with status 128",
        ),
        ("", "the tool reported an error with no text"),
    ] {
        let error =
            call_result(json!({"content": [{"type": "text", "text": said}], "isError": true}))
                .expect_err(cause);
        assert_eq!(error, BridgeError::Tool(cause.to_owned()), "{said}");
    }
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
fn a_hung_server_times_out_typed() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = fake_server(directory.path(), true);
    let mut session = McpSession::open(&server, Duration::from_millis(500)).expect("handshake");
    let started = Instant::now();
    let error = session
        .request(
            "tools/call",
            json!({"name": "get_current_time", "arguments": {}}),
        )
        .expect_err("a hung call is bounded");
    assert!(matches!(error, BridgeError::Timeout(_)), "{error:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
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
fn a_server_that_echoes_the_document_on_stderr_never_returns_it_in_a_failure() {
    let directory = tempfile::tempdir().expect("tempdir");
    let url = "https://example.invalid/private-document";
    let server = scripted_server(
        directory.path(),
        "",
        r#"    *'"tools/call"'*) printf 'fetching https://example.invalid/private-document\nstderr-canary\n' >&2; exec sleep 30 ;;"#,
    );
    let mut session =
        McpSession::open_redacting(&server, Duration::from_millis(800), url).expect("handshake");
    let error = session
        .request(
            "tools/call",
            json!({"name": "get_current_time", "arguments": {"url": url}}),
        )
        .expect_err("a hung call is bounded");
    let shown = error.to_string();
    assert!(matches!(error, BridgeError::Timeout(_)), "{error:?}");
    assert!(shown.contains("stderr-canary"), "{shown}");
    assert!(!shown.contains("private-document"), "{shown}");
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
                "--surface",
                PIN,
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
    let bridge = pinned(browser_bridge(strings(&["/bin/true"])), &browser_tools());
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
            None,
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
            None,
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
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let number = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = directory.join(format!("converter-{number}.sh"));
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
            None,
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
        article_text: None,
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
        article_text: None,
    };
    let error = read_with(&server, &input, rules, Duration::from_secs(10)).expect_err("exit 3");
    assert!(matches!(error, BridgeError::PdfText(_)), "{error:?}");
    let blocked_dir = tempfile::tempdir().expect("tempdir");
    let blocked = converter(
        blocked_dir.path(),
        "echo 'the site refused this exit (HTTP 403)' >&2; exit 67",
    );
    let error = read_with(
        &server,
        &input,
        Rules {
            pdf_text: Some(&blocked),
            ..rules
        },
        Duration::from_secs(10),
    )
    .expect_err("exit 67");
    assert!(matches!(error, BridgeError::Refused(_)), "{error:?}");
    let blank_dir = tempfile::tempdir().expect("tempdir");
    let blank = converter(blank_dir.path(), "printf '\\n\\n'");
    let error = read_with(
        &server,
        &input,
        Rules {
            pdf_text: Some(&blank),
            article_text: None,
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
            article_text: None,
            ..rules
        },
        Duration::from_millis(800),
    )
    .expect_err("a hung converter is bounded by the session");
    assert!(matches!(error, BridgeError::Timeout(_)), "{error:?}");
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn a_windowed_read_asks_for_the_whole_page_and_serves_it_from_offset() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = pdf_browser(directory.path());
    let rules = Rules {
        load_check: Some("browser_network_requests"),
        window: Some("max_chars"),
        pdf_text: None,
        article_text: None,
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
fn descriptor_refuses_a_drifted_surface_naming_both_digests() {
    let tools = [json!({"name": "get_current_time", "description": "now"})];
    let bridge = pinned(config(&[], strings(&["/bin/true"])), &tools);
    assert!(bridge.descriptor(&tools).is_ok());
    let drifted = [json!({"name": "get_current_time", "description": "now, plus a new duty"})];
    let message = bridge
        .descriptor(&drifted)
        .expect_err("drift refuses")
        .to_string();
    let served = bridge.surface_digest(&drifted).expect("digest");
    assert!(message.contains(&bridge.surface[..12]), "{message}");
    assert!(message.contains(&served[..12]), "{message}");
    assert!(
        message.contains(&format!("--surface {served}")),
        "{message}"
    );
}

#[test]
fn fallback_prefers_article_text_when_it_succeeds() {
    let directory = tempfile::tempdir().expect("scratch directory");
    let script = converter(directory.path(), "cat >/dev/null; echo ARTICLE");
    let deadline = Instant::now() + Duration::from_secs(5);
    let page = b"<html><nav>Menu</nav><article><p>Body</p></article></html>";
    let text = http_read::html_text(page, Some(&script), deadline).expect("converted");
    assert_eq!(text.trim(), "ARTICLE");
}

#[test]
fn a_blocked_page_retries_an_independent_engine_then_the_dated_archive() {
    use crate::read::{public_fallback, PageRead, ReadStop, StoppedRead};
    let stop = StoppedRead {
        stop: ReadStop::Challenged,
        cause: "HTTP 200 challenge".into(),
    };
    let page = "https://a.example/dated";
    let alternate = public_fallback(
        page,
        &stop,
        || {
            Some(PageRead {
                url: page.into(),
                text: "alternate body".into(),
            })
        },
        |_| panic!("a successful alternate read must not consult Wayback"),
    )
    .unwrap();
    assert!(alternate.text.contains("alternate plain-HTTP engine"));
    let order = std::cell::RefCell::new(Vec::new());
    let archived = public_fallback(
        page,
        &stop,
        || {
            order.borrow_mut().push("alternate");
            None
        },
        |url| {
            order.borrow_mut().push("archive");
            assert_eq!(url, "https://web.archive.org/web/2/https://a.example/dated");
            Some(PageRead {
                url: "https://web.archive.org/web/20240315010203id_/https://a.example/dated".into(),
                text: "archived body".into(),
            })
        },
    )
    .unwrap();
    assert_eq!(*order.borrow(), vec!["alternate", "archive"]);
    assert_eq!(
        archived.text,
        "Read the archived copy of https://a.example/dated from 2024-03-15.\n\narchived body"
    );
    let missing = public_fallback(page, &stop, || None, |_| None).unwrap_err();
    assert!(matches!(missing, BridgeError::Refused(_)), "{missing:?}");
    assert!(missing.to_string().contains("no archived copy was found"));
    let undated = public_fallback(
        page,
        &stop,
        || None,
        |_| {
            Some(PageRead {
                url: crate::read::archive_url(page),
                text: "not a snapshot".into(),
            })
        },
    )
    .unwrap_err();
    assert!(undated.to_string().contains("no archived copy was found"));
}
