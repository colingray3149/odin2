//! `knowledge.*`: the compiled brain's tools. Every tool is one forward: the seat's name and session go to the knowledge service
//! on this host (`ODIN_KNOWLEDGE_URL`, loopback, declared by dotfiles modules/home/knowledge.nix) and its answer comes back verbatim.
//! The service owns access (`_system/access.toml`), search, reads and writes; odind holds no knowledge state of its own.
//! Install as odin:crates/odin-hermes/src/runtime/knowledge.rs (chapter 10, step 10-08).

use std::sync::Arc;
use std::time::Duration;

use odin_domain::Scope;
use odin_omp::capability_parameters;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode};
use serde_json::Value;

use super::tools::CapabilityTool;
use super::HermesRuntime;

const URL_ENV: &str = "ODIN_KNOWLEDGE_URL";
/// `knowledge.pull` may wait for a puller (the service waits at most 100 s); every other verb answers in seconds.
const TIMEOUT: Duration = Duration::from_secs(125);

/// One POST to `<url>/tool/<verb>`. The service answers `{"ok": true, "result": ..}` or `{"ok": false, "error": ".."}`;
/// a refusal is an arguments error carrying the service's own sentence, so the model reads the cause.
fn forward(
    tool: &'static str,
    verb: &str,
    base: &str,
    scope: &Scope,
    arguments: &Value,
) -> Result<Value, HostToolError> {
    let seat = scope.seat.as_ref().ok_or_else(|| HostToolError::Scope {
        tool,
        reason: "knowledge tools need the calling seat",
    })?;
    let client = reqwest::blocking::Client::builder()
        .timeout(TIMEOUT)
        .build()
        .map_err(|error| HostToolError::unavailable(tool, error))?;
    let mut request = client
        .post(format!("{}/tool/{verb}", base.trim_end_matches('/')))
        .header("X-Knowledge-Seat", seat.as_str())
        .json(arguments);
    if let Some(session) = scope.session.as_ref() {
        request = request.header("X-Knowledge-Session", session.as_str());
    }
    let response = request.send().map_err(|error| {
        HostToolError::unavailable(
            tool,
            format!("the knowledge service at {base} did not answer: {error}; systemctl --user status knowledge-service"),
        )
    })?;
    let status = response.status();
    let body: Value = response.json().map_err(|error| {
        HostToolError::unavailable(
            tool,
            format!("the knowledge service answered HTTP {status} with unreadable JSON: {error}"),
        )
    })?;
    match body.get("ok").and_then(Value::as_bool) {
        Some(true) => Ok(body.get("result").cloned().unwrap_or(Value::Null)),
        Some(false) if status.is_success() => Err(HostToolError::Arguments {
            tool,
            detail: body["error"].as_str().unwrap_or("refused").to_owned(),
        }),
        _ => Err(HostToolError::unavailable(
            tool,
            body["error"]
                .as_str()
                .unwrap_or("the knowledge service failed")
                .to_owned(),
        )),
    }
}

macro_rules! knowledge_tool {
    ($tools:expr, $runtime:expr, $id:literal, $tool:literal, $verb:literal, $label:literal, $description:literal) => {{
        let runtime = Arc::clone($runtime);
        let handler = move |scope: Scope, arguments: Value| {
            let _ = &runtime; // the runtime is kept alive for the tool's lifetime, like every sibling tool
            let base = std::env::var(URL_ENV).map_err(|_| {
                HostToolError::unavailable(
                    $tool,
                    format!("{URL_ENV} is unset; dotfiles modules/home/knowledge.nix declares it on the authority"),
                )
            })?;
            forward($tool, $verb, &base, &scope, &arguments)
        };
        $tools.push(Arc::new(CapabilityTool::plain_without_prerequisites(
            RpcHostToolDefinition {
                name: $tool.into(),
                label: $label.into(),
                description: $description.into(),
                parameters: capability_parameters!($id),
                hidden: false,
                load_mode: ToolLoadMode::Discoverable,
            },
            Box::new(handler),
        )));
    }};
}

// `knowledge_tools` itself is generated from the service's tool table (`knowledge_service.py export-capabilities`), so the model-facing
// descriptions, the schemas and the service never drift: one `knowledge_tool!` line per verb.
include!("knowledge_table.rs");

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// A one-shot HTTP server that records the request it gets and answers `reply`.
    fn serve_once(reply: &'static str) -> (String, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut seen = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                let n = stream.read(&mut buffer).unwrap();
                seen.extend_from_slice(&buffer[..n]);
                let text = String::from_utf8_lossy(&seen).to_string();
                if let Some(split) = text.find("\r\n\r\n") {
                    let length = text
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .and_then(|v| v.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if seen.len() >= split + 4 + length {
                        break;
                    }
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                reply.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            String::from_utf8_lossy(&seen).to_string()
        });
        (base, handle)
    }

    fn scope(seat: &str) -> Scope {
        Scope {
            seat: Some(seat.parse().unwrap()),
            project: None,
            lane: None,
            run: None,
            attempt: None,
            session: Some("session-abc123".parse().unwrap()),
            node: None,
        }
    }

    #[test]
    fn each_declared_knowledge_tool_forwards_its_arguments_and_the_seat() {
        let (base, seen) = serve_once(r#"{"ok":true,"result":{"hits":[]}}"#);
        let value = forward(
            "knowledge_search",
            "search",
            &base,
            &scope("architect"),
            &serde_json::json!({"query": "odin"}),
        )
        .unwrap();
        assert_eq!(value["hits"], serde_json::json!([]));
        let request = seen.join().unwrap();
        assert!(
            request.starts_with("POST /tool/search HTTP/1.1"),
            "{request}"
        );
        assert!(
            request
                .to_ascii_lowercase()
                .contains("x-knowledge-seat: architect"),
            "{request}"
        );
        assert!(
            request
                .to_ascii_lowercase()
                .contains("x-knowledge-session: session-abc123"),
            "{request}"
        );
        assert!(request.ends_with(r#"{"query":"odin"}"#), "{request}");
    }

    #[test]
    fn a_refusal_reaches_the_model_as_the_services_own_sentence() {
        let (base, seen) = serve_once(
            r#"{"ok":false,"error":"knowledge.delete is not granted to architect in _system/access.toml"}"#,
        );
        let error = forward(
            "knowledge_delete",
            "delete",
            &base,
            &scope("architect"),
            &serde_json::json!({"path": "x"}),
        )
        .unwrap_err();
        seen.join().unwrap();
        assert!(
            error.to_string().contains("is not granted to architect"),
            "{error}"
        );
    }

    #[test]
    fn a_call_without_a_seat_is_refused() {
        let mut anonymous = scope("architect");
        anonymous.seat = None;
        let error = forward(
            "knowledge_search",
            "search",
            "http://127.0.0.1:1",
            &anonymous,
            &serde_json::json!({}),
        )
        .unwrap_err();
        assert!(error.to_string().contains("calling seat"), "{error}");
    }
}
