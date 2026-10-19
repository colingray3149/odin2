use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use super::{KernelMcpServer, KernelSession, McpEndpoint, McpReply};
use crate::host_tools::operations::HostToolOperationError;
use crate::host_tools::{RpcHostToolDefinition, ToolLoadMode};

/// One seat's kernel: `check_run` succeeds, `seat_ask_kubert` is refused by
/// policy, `broken_tool` reports a tool error; nothing else is listed.
#[derive(Default)]
struct FakeKernel {
    calls: Mutex<Vec<(String, Value, String)>>,
}

impl KernelSession for FakeKernel {
    fn tools(&self) -> Result<Vec<RpcHostToolDefinition>, HostToolOperationError> {
        Ok(vec![RpcHostToolDefinition {
            name: "check_run".into(),
            label: "Check".into(),
            description: "Runs the project's declared checks.".into(),
            parameters: json!({"$schema": "https://json-schema.org/draft/2020-12/schema",
                "title": "check_run input", "description": "Host policy prose.",
                "type": "object", "properties": {}, "additionalProperties": false}),
            hidden: false,
            load_mode: ToolLoadMode::Essential,
        }])
    }

    fn call(
        &self,
        tool: &str,
        arguments: Value,
        request_id: &str,
    ) -> Result<Value, HostToolOperationError> {
        self.calls
            .lock()
            .expect("calls")
            .push((tool.to_owned(), arguments, request_id.to_owned()));
        match tool {
            "check_run" => Ok(json!({"passed": true})),
            "broken_tool" => Ok(json!({"isError": true, "message": "checks failed"})),
            "seat_ask_kubert" => Err(HostToolOperationError::Composition {
                detail: "approval required".to_owned(),
            }),
            name => Err(HostToolOperationError::UnknownTool {
                name: name.to_owned(),
            }),
        }
    }
}

const SESSION: &str = "4f6c2a10-0000-4000-8000-000000000001";

fn served() -> (
    Arc<KernelMcpServer>,
    Arc<FakeKernel>,
    super::McpRegistration,
) {
    let server = KernelMcpServer::new("http://127.0.0.1:18430/");
    let kernel = Arc::new(FakeKernel::default());
    let registration = server.register(
        SESSION,
        "class",
        Arc::clone(&kernel) as Arc<dyn KernelSession>,
        None,
    );
    (server, kernel, registration)
}

fn post(server: &KernelMcpServer, bearer: &str, message: Value) -> McpReply {
    server.handle(
        SESSION,
        Some(&format!("Bearer {bearer}")),
        &serde_json::to_vec(&message).expect("encode"),
    )
}

fn result(reply: &McpReply) -> &Value {
    assert_eq!(reply.status, 200, "{reply:?}");
    reply
        .body
        .as_ref()
        .and_then(|body| body.get("result"))
        .unwrap_or_else(|| panic!("a JSON-RPC result: {reply:?}"))
}

#[test]
fn the_endpoint_is_per_session_and_bearer_bound() {
    let (server, kernel, registration) = served();
    assert_eq!(
        registration.endpoint.url,
        format!("http://127.0.0.1:18430/mcp/{SESSION}")
    );
    let ping =
        serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 1, "method": "ping"})).expect("encode");
    let unknown = server.handle("other-session", None, &ping);
    assert_eq!(unknown.status, 404);
    assert_eq!(server.handle(SESSION, None, &ping).status, 401);
    assert_eq!(
        server
            .handle(SESSION, Some("Bearer 00112233"), &ping)
            .status,
        401
    );
    let other = server.register(
        "another",
        "class",
        Arc::clone(&kernel) as Arc<dyn KernelSession>,
        None,
    );
    assert_ne!(other.endpoint.bearer, registration.endpoint.bearer);
    assert_eq!(
        server
            .handle(
                SESSION,
                Some(&format!("Bearer {}", other.endpoint.bearer)),
                &ping
            )
            .status,
        401,
        "another session's token never opens this session"
    );
    let reply = post(
        &server,
        &registration.endpoint.bearer,
        json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
    );
    assert_eq!(result(&reply), &json!({}));
    assert!(kernel.calls.lock().expect("calls").is_empty());
}

#[test]
fn initialize_negotiates_and_notifications_are_accepted() {
    let (server, _kernel, registration) = served();
    let bearer = &registration.endpoint.bearer;
    let reply = post(
        &server,
        bearer,
        json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": {"name": "claude-code", "version": "2"}}}),
    );
    let init = result(&reply);
    assert_eq!(init["protocolVersion"], "2025-03-26");
    assert_eq!(init["serverInfo"]["name"], "odin");
    assert!(init["capabilities"]["tools"].is_object());
    let unknown_version = post(
        &server,
        bearer,
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"protocolVersion": "1999-01-01"}}),
    );
    assert_eq!(result(&unknown_version)["protocolVersion"], "2025-06-18");
    let notification = post(
        &server,
        bearer,
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );
    assert_eq!(
        notification,
        McpReply {
            status: 202,
            body: None
        }
    );
}

#[test]
fn tools_list_is_the_seats_admitted_definitions() {
    let (server, _kernel, registration) = served();
    let reply = post(
        &server,
        &registration.endpoint.bearer,
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    );
    assert_eq!(
        result(&reply)["tools"],
        json!([{
            "name": "check_run",
            "description": "Runs the project's declared checks.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
        }])
    );
}

#[test]
fn tools_call_dispatches_once_per_call_with_a_fresh_request_id() {
    let (server, kernel, registration) = served();
    let bearer = &registration.endpoint.bearer;
    let call = |id: u64| {
        post(
            &server,
            bearer,
            json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
                   "params": {"name": "check_run", "arguments": {"target": "all"}}}),
        )
    };
    let first = call(3);
    let answer = result(&first);
    assert_eq!(answer["isError"], false);
    assert_eq!(answer["content"][0]["type"], "text");
    assert_eq!(answer["content"][0]["text"], "{\"passed\":true}");
    let _ = call(3);
    let calls = kernel.calls.lock().expect("calls");
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].0, "check_run");
    assert_eq!(calls[0].1, json!({"target": "all"}));
    assert!(calls[0].2.starts_with("mcp-"));
    assert_ne!(
        calls[0].2, calls[1].2,
        "a reused JSON-RPC id never replays a journaled operation"
    );
}

#[test]
fn refusals_and_tool_errors_reach_the_model_as_error_results() {
    let (server, _kernel, registration) = served();
    let bearer = &registration.endpoint.bearer;
    let refused = post(
        &server,
        bearer,
        json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
               "params": {"name": "seat_ask_kubert", "arguments": {}}}),
    );
    let refused = result(&refused);
    assert_eq!(refused["isError"], true);
    assert!(refused["content"][0]["text"]
        .as_str()
        .is_some_and(|text| text.contains("approval required")));
    let failed = post(
        &server,
        bearer,
        json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
               "params": {"name": "broken_tool"}}),
    );
    assert_eq!(result(&failed)["isError"], true);
    let unknown = post(
        &server,
        bearer,
        json!({"jsonrpc": "2.0", "id": 6, "method": "tools/call",
               "params": {"name": "rm_rf", "arguments": {}}}),
    );
    assert_eq!(
        unknown.body.as_ref().expect("body")["error"]["code"],
        -32602
    );
    let bad_arguments = post(
        &server,
        bearer,
        json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
               "params": {"name": "check_run", "arguments": "all"}}),
    );
    assert_eq!(
        bad_arguments.body.as_ref().expect("body")["error"]["code"],
        -32602
    );
    let method = post(
        &server,
        bearer,
        json!({"jsonrpc": "2.0", "id": 8, "method": "resources/list"}),
    );
    assert_eq!(method.body.as_ref().expect("body")["error"]["code"], -32601);
}

#[test]
fn malformed_and_batched_bodies_are_refused_typed() {
    let (server, _kernel, registration) = served();
    let header = format!("Bearer {}", registration.endpoint.bearer);
    let malformed = server.handle(SESSION, Some(&header), b"{not json");
    assert_eq!(malformed.status, 400);
    assert_eq!(malformed.body.expect("body")["error"]["code"], -32700);
    let batch = server.handle(
        SESSION,
        Some(&header),
        br#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#,
    );
    assert_eq!(batch.status, 400);
    assert_eq!(batch.body.expect("body")["error"]["code"], -32600);
}

#[test]
fn a_dropped_registration_retires_only_its_own_entry() {
    let (server, kernel, first) = served();
    let ping = br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
    // A reclaim re-registers the session with the token its config carries.
    let second = server.register(
        SESSION,
        "class",
        Arc::clone(&kernel) as Arc<dyn KernelSession>,
        Some(first.endpoint.bearer.clone()),
    );
    assert_eq!(second.endpoint, first.endpoint);
    drop(first);
    let header = format!("Bearer {}", second.endpoint.bearer);
    assert_eq!(server.handle(SESSION, Some(&header), ping).status, 200);
    drop(second);
    assert_eq!(server.handle(SESSION, Some(&header), ping).status, 404);
}

#[test]
fn the_claude_config_is_owner_only_and_keeps_its_token() {
    let dir = std::env::temp_dir().join(format!("odin-mcp-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let path = dir.join("mcp.json");
    let endpoint = McpEndpoint {
        url: format!("http://127.0.0.1:18430/mcp/{SESSION}"),
        bearer: "ab".repeat(32),
    };
    endpoint.write_config(&path).expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let written: Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("json");
    assert_eq!(written["mcpServers"]["odin"]["type"], "http");
    assert_eq!(
        McpEndpoint::persisted_bearer(&path, &endpoint.url),
        Some(endpoint.bearer.clone())
    );
    assert_eq!(
        McpEndpoint::persisted_bearer(&path, "http://127.0.0.1:1/mcp/x"),
        None,
        "a config for another endpoint never lends its token"
    );
    assert_eq!(
        endpoint.acp_server()["headers"][0]["value"],
        format!("Bearer {}", endpoint.bearer)
    );
    let _ = std::fs::remove_dir_all(&dir);
}
