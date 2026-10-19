//! Each framed adapter call uses one MCP session; stderr diagnostics must fit without host draining.

use std::io::{Read, Write};
use std::process::ExitCode;
use std::time::Duration;

use odin_adapter_core::descriptor::AdapterDescriptor;
use odin_adapter_core::status::AdapterStatusSnapshot;
use odin_adapter_core::transport::{
    decode_frame, encode_frame, AdapterErrorCode, JsonRpcOutcome, JsonRpcRequest, RpcMethod,
    MAX_FRAME_BYTES,
};
use odin_adapter_mcp::{bounded, BridgeConfig, BridgeError, McpSession};
use serde_json::{json, Value};

/// Leave time to return before the host's 20-second probe timeout.
const SESSION_BOUND: Duration = Duration::from_secs(15);

/// Page navigation and a separate PDF fetch need longer than a status probe.
const CALL_BOUND: Duration = Duration::from_secs(35);

const MESSAGE_BYTES: usize = 1024;

fn main() -> ExitCode {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .compact()
        .with_writer(std::io::stderr)
        .init();
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let request = match read_request() {
        Ok(request) => request,
        Err((id, code, message)) => {
            return write_frame(&json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": code.code(), "message": message},
            }))
        }
    };
    let outcome = match BridgeConfig::parse(&arguments) {
        Ok(config) => dispatch(&config, &request),
        Err(error) => failure(
            &request,
            AdapterErrorCode::InternalError,
            &error.to_string(),
        ),
    };
    let wire = outcome.to_wire();
    if encode_frame(&wire).is_ok() {
        return write_frame(&wire);
    }
    write_frame(&json!({
        "jsonrpc": "2.0",
        "id": outcome.id(),
        "error": {
            "code": AdapterErrorCode::InternalError.code(),
            "message": "adapter response exceeded the canonical frame bound",
        },
    }))
}

fn dispatch(config: &BridgeConfig, request: &JsonRpcRequest) -> JsonRpcOutcome {
    match &request.method {
        RpcMethod::Status => status(config, request),
        RpcMethod::Describe => describe(config, request),
        RpcMethod::Operation(kind) => operate(config, request, kind.as_str()),
    }
}

fn note(line: &str) {
    let _ = writeln!(
        std::io::stderr().lock(),
        "odin-adapter-mcp: {}",
        bounded(line, MESSAGE_BYTES)
    );
}

/// Failure details exclude document URLs and upstream content except for redacted stderr tails.
fn failure(request: &JsonRpcRequest, code: AdapterErrorCode, message: &str) -> JsonRpcOutcome {
    let message = bounded(message, MESSAGE_BYTES);
    note(&format!("{} failed: {message}", request.method));
    JsonRpcOutcome::Error {
        id: request.id.clone(),
        code,
        message: message.to_owned(),
        data: None,
    }
}

fn bridge_failure(request: &JsonRpcRequest, error: &BridgeError) -> JsonRpcOutcome {
    failure(request, code_of(error), &error.to_string())
}

fn code_of(error: &BridgeError) -> AdapterErrorCode {
    match error {
        BridgeError::Timeout(_) => AdapterErrorCode::Timeout,
        BridgeError::Spawn(_) => AdapterErrorCode::AccountUnavailable,
        BridgeError::Argv(_)
        | BridgeError::Protocol(_)
        | BridgeError::Tool(_)
        | BridgeError::PageLoad(_)
        | BridgeError::PdfText(_) => AdapterErrorCode::InternalError,
        BridgeError::OffsetPastEnd { .. } => AdapterErrorCode::InvalidParams,
    }
}

fn describe(config: &BridgeConfig, request: &JsonRpcRequest) -> JsonRpcOutcome {
    let descriptor = McpSession::open(&config.server, SESSION_BOUND)
        .and_then(|mut session| session.tools())
        .and_then(|tools| config.descriptor(&tools));
    match descriptor {
        Ok(wire) => match AdapterDescriptor::from_wire(&wire) {
            Ok(descriptor) => JsonRpcOutcome::Success {
                id: request.id.clone(),
                result: descriptor.to_wire(),
            },
            Err(_) => failure(
                request,
                AdapterErrorCode::InternalError,
                "the listed tools do not form a valid adapter descriptor",
            ),
        },
        Err(error) => bridge_failure(request, &error),
    }
}

/// Probe the server rather than reporting health from configuration alone.
fn status(config: &BridgeConfig, request: &JsonRpcRequest) -> JsonRpcOutcome {
    let probe =
        McpSession::open(&config.server, SESSION_BOUND).and_then(|mut session| session.tools());
    let (health, last_failure) = match &probe {
        Ok(_) => ("ready", Value::Null),
        Err(error) => {
            note(&format!("status probe failed: {error}"));
            (
                "unavailable",
                json!({"code": "mcp_server_unavailable", "retryable": true, "operation_id": null}),
            )
        }
    };
    let observed_at = match time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .ok()
        .and_then(|now| {
            now.format(&time::format_description::well_known::Rfc3339)
                .ok()
        }) {
        Some(stamp) => stamp,
        None => {
            return failure(
                request,
                AdapterErrorCode::InternalError,
                "the observation time could not be formatted",
            )
        }
    };
    let wire = json!({
        "schema": odin_adapter_core::ADAPTER_STATUS_SCHEMA_NAME,
        "adapter": config.identity(),
        "revision": 1u64,
        "health": health,
        "taint": "clean",
        "active_operations": 0u64,
        "observed_at": observed_at,
        "last_failure": last_failure,
        "evidence_refs": [],
    });
    match AdapterStatusSnapshot::from_wire(&wire) {
        Ok(snapshot) => JsonRpcOutcome::Success {
            id: request.id.clone(),
            result: snapshot.to_wire(),
        },
        Err(_) => failure(
            request,
            AdapterErrorCode::InternalError,
            "the status snapshot is not canonical",
        ),
    }
}

fn operate(config: &BridgeConfig, request: &JsonRpcRequest, kind: &str) -> JsonRpcOutcome {
    let Some(plan) = config.plan(kind) else {
        return failure(
            request,
            AdapterErrorCode::MethodNotFound,
            "the operation is not served by this bridge",
        );
    };
    let input = request
        .params
        .get("input")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let called = McpSession::open(&config.server, CALL_BOUND)
        .and_then(|mut session| session.call_plan(&plan, &input, config.rules()));
    match called {
        Ok(result) => {
            note(&format!(
                "tool call ok adapter={} kind={kind} tools={}",
                config.adapter,
                plan.join(",")
            ));
            JsonRpcOutcome::Success {
                id: request.id.clone(),
                result,
            }
        }
        Err(error) => bridge_failure(request, &error),
    }
}

fn read_request() -> Result<JsonRpcRequest, (Value, AdapterErrorCode, &'static str)> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_FRAME_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            (
                Value::Null,
                AdapterErrorCode::ParseError,
                "the request frame could not be read",
            )
        })?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err((
            Value::Null,
            AdapterErrorCode::ParseError,
            "request frame exceeds the transport bound",
        ));
    }
    let wire = decode_frame(&bytes).map_err(|_| {
        (
            Value::Null,
            AdapterErrorCode::ParseError,
            "the request frame is not one canonical frame",
        )
    })?;
    let id = wire.get("id").cloned().unwrap_or(Value::Null);
    JsonRpcRequest::from_wire(&wire).map_err(|_| {
        (
            id,
            AdapterErrorCode::InvalidRequest,
            "the request is not a valid adapter request",
        )
    })
}

fn write_frame(wire: &Value) -> ExitCode {
    match encode_frame(wire) {
        Ok(frame) => {
            let mut stdout = std::io::stdout().lock();
            match stdout.write_all(&frame).and_then(|()| stdout.flush()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => ExitCode::FAILURE,
            }
        }
        Err(_) => ExitCode::FAILURE,
    }
}
