//! One request per process keeps credential resolution fresh for every launch.

#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use odin_adapter_core::config::{AdapterBackendConfig, AdapterDeployment};
use odin_adapter_core::ids::{AdapterTaint, AdapterVersion, AdapterWireId, WireAdapterIdentity};
use odin_adapter_core::status::{AdapterHealthState, AdapterStatusSnapshot, StatusFailure};
use odin_adapter_core::transport::{
    decode_frame, encode_frame, AdapterErrorCode, JsonRpcOutcome, JsonRpcRequest, ProtocolError,
    RpcMethod, StatusParams, WebSearchParams, MAX_FRAME_BYTES, WEB_SEARCH_KIND,
};
use odin_adapter_web::credentials;
use serde_json::{json, Value};
use time::OffsetDateTime;

const CONFIG_MAX_BYTES: usize = 65_536;

/// Each process produces a fresh snapshot, so revisions restart at one.
const STATUS_REVISION: u64 = 1;

const CREDENTIAL_FAILURE_CODE: &str = "credentials_unavailable";

/// Static errors prevent malformed arguments and credential paths from leaking into replies.
const ARGV_UNAVAILABLE: &str =
    "backend deployment configuration unavailable: expected exactly --config PATH";

const CONFIG_UNAVAILABLE: &str = "backend deployment configuration unavailable";

/// The binary selects its adapter; deployment-specific values still come from configuration.
const WEB_SEARCH_ADAPTER_ID: &str = "web-search";

const RUNTIME_UNAVAILABLE: &str = "adapter async runtime unavailable";

const RESPONSE_OVERSIZED: &str = "adapter response exceeded the canonical frame bound";

struct ConfigFailure {
    code: AdapterErrorCode,
    message: &'static str,
}

struct FrameFailure {
    id: Option<String>,
    code: AdapterErrorCode,
    message: String,
}

fn main() -> ExitCode {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .compact()
        .with_writer(std::io::stderr)
        .init();
    let config = load_configuration();
    let request = match read_request() {
        Ok(request) => request,
        Err(failure) => return emit_raw_error(&failure),
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            return emit_outcome(&JsonRpcOutcome::Error {
                id: request.id.clone(),
                code: AdapterErrorCode::InternalError,
                message: RUNTIME_UNAVAILABLE.to_owned(),
                data: None,
            })
        }
    };
    let outcome = runtime.block_on(dispatch(&config, &request));
    emit_outcome(&outcome)
}

fn parse_config_path() -> Result<PathBuf, ConfigFailure> {
    let mut args = std::env::args_os();
    let _program = args.next();
    let rest: Vec<_> = args.collect();
    match rest.as_slice() {
        [flag, path] if flag == OsStr::new("--config") => Ok(PathBuf::from(path)),
        _ => Err(ConfigFailure {
            code: AdapterErrorCode::CredentialsUnavailable,
            message: ARGV_UNAVAILABLE,
        }),
    }
}

/// Callers sanitize I/O errors so file paths do not reach responses.
fn read_bounded(path: &Path, ceiling: usize) -> std::io::Result<Vec<u8>> {
    let mut file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4_096];
    loop {
        let read = file.read(&mut chunk)?;
        if read == 0 {
            return Ok(bytes);
        }
        if bytes.len() + read > ceiling {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bounded read ceiling exceeded",
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
}

fn load_configuration() -> Result<AdapterBackendConfig, ConfigFailure> {
    let path = parse_config_path()?;
    let bytes = read_bounded(&path, CONFIG_MAX_BYTES).map_err(|_| ConfigFailure {
        code: AdapterErrorCode::CredentialsUnavailable,
        message: CONFIG_UNAVAILABLE,
    })?;
    let config: AdapterBackendConfig =
        serde_json::from_slice(&bytes).map_err(|_| ConfigFailure {
            code: AdapterErrorCode::CredentialsUnavailable,
            message: CONFIG_UNAVAILABLE,
        })?;
    Ok(config)
}

fn read_request() -> Result<JsonRpcRequest, FrameFailure> {
    let mut bytes = Vec::new();
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut chunk = [0u8; 4_096];
    loop {
        match input.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                bytes.extend_from_slice(&chunk[..read]);
                if bytes.len() > MAX_FRAME_BYTES {
                    return Err(FrameFailure {
                        id: None,
                        code: AdapterErrorCode::ParseError,
                        message: "request frame exceeds the transport bound".to_owned(),
                    });
                }
            }
            Err(_) => {
                return Err(FrameFailure {
                    id: None,
                    code: AdapterErrorCode::ParseError,
                    message: "request frame could not be read from stdin".to_owned(),
                })
            }
        }
    }
    let wire = decode_frame(&bytes).map_err(|error| FrameFailure {
        id: None,
        code: AdapterErrorCode::ParseError,
        message: error.to_string(),
    })?;
    // Even a rejected envelope may carry an echoable string id.
    let id = wire.get("id").and_then(Value::as_str).map(str::to_owned);
    JsonRpcRequest::from_wire(&wire).map_err(|error| FrameFailure {
        id,
        code: envelope_code(&error),
        message: error.to_string(),
    })
}

fn envelope_code(error: &ProtocolError) -> AdapterErrorCode {
    match error {
        ProtocolError::UnknownMethod(_) => AdapterErrorCode::MethodNotFound,
        _ => AdapterErrorCode::InvalidRequest,
    }
}

async fn dispatch(
    config: &Result<AdapterBackendConfig, ConfigFailure>,
    request: &JsonRpcRequest,
) -> JsonRpcOutcome {
    let config = match config {
        Ok(config) => config,
        Err(failure) => {
            return JsonRpcOutcome::Error {
                id: request.id.clone(),
                code: failure.code,
                message: failure.message.to_owned(),
                data: None,
            }
        }
    };
    match &request.method {
        RpcMethod::Status => status(config, request),
        RpcMethod::Describe => describe(config, request),
        RpcMethod::Operation(kind) if kind.as_str() == WEB_SEARCH_KIND => {
            web_search(config, request).await
        }
        RpcMethod::Operation(_) => JsonRpcOutcome::Error {
            id: request.id.clone(),
            code: AdapterErrorCode::MethodNotFound,
            message: format!(
                "adapter operation kind {} is not admitted by this backend",
                request.method
            ),
            data: None,
        },
    }
}

fn web_search_deployment(
    config: &AdapterBackendConfig,
) -> Option<(&AdapterWireId, &AdapterDeployment)> {
    let key =
        AdapterWireId::new(WEB_SEARCH_ADAPTER_ID).expect("adapter key fits the wire id grammar");
    config.adapters().get_key_value(&key)
}

async fn web_search(config: &AdapterBackendConfig, request: &JsonRpcRequest) -> JsonRpcOutcome {
    let params = match WebSearchParams::from_wire(&request.params) {
        Ok(params) => params,
        Err(error) => {
            return JsonRpcOutcome::Error {
                id: request.id.clone(),
                code: AdapterErrorCode::InvalidParams,
                message: error.to_string(),
                data: None,
            }
        }
    };
    let Some((_, deployment)) = web_search_deployment(config) else {
        return JsonRpcOutcome::Error {
            id: request.id.clone(),
            code: AdapterErrorCode::CredentialsUnavailable,
            message: CONFIG_UNAVAILABLE.to_owned(),
            data: None,
        };
    };
    match odin_adapter_web::search(deployment, params.input()).await {
        Ok(result) => JsonRpcOutcome::Success {
            id: request.id.clone(),
            result,
        },
        Err(error) => JsonRpcOutcome::Error {
            id: request.id.clone(),
            code: error.code(),
            message: error.message().to_owned(),
            data: error.detail().map(|detail| json!({ "detail": detail })),
        },
    }
}

/// The handshake lets the host discover this backend's operations without compiling them in.
fn describe(config: &AdapterBackendConfig, request: &JsonRpcRequest) -> JsonRpcOutcome {
    let Some((adapter_id, deployment)) = web_search_deployment(config) else {
        return JsonRpcOutcome::Error {
            id: request.id.clone(),
            code: AdapterErrorCode::CredentialsUnavailable,
            message: CONFIG_UNAVAILABLE.to_owned(),
            data: None,
        };
    };
    JsonRpcOutcome::Success {
        id: request.id.clone(),
        result: json!({
            "schema": odin_adapter_core::ADAPTER_DESCRIPTOR_SCHEMA_NAME,
            "adapter": {
                "adapter_id": adapter_id.as_str(),
                "version": env!("CARGO_PKG_VERSION"),
                "binding_digest": deployment.binding_digest(),
            },
            "protocol_version": odin_adapter_core::descriptor::ADAPTER_PROTOCOL_VERSION,
            "operations": [{
                "kind": WEB_SEARCH_KIND,
                "input_schema": "schemas/capability/web.search.input.json",
                "output_schema": "schemas/capability/web.search.output.json",
                "effect_class": "R0",
                "idempotency": "pure",
                "evidence": [{
                    "kind": odin_adapter_core::ADAPTER_RECEIPT_EVIDENCE_KIND,
                    "schema": odin_adapter_core::ADAPTER_RECEIPT_EVIDENCE_SCHEMA_REF,
                    "required": true,
                }],
                "credential_handle": null,
                "taint_after": "credential_tainted",
            }],
            "credential_handles": [],
            "initial_taint": "credential_tainted",
        }),
    }
}

fn status(config: &AdapterBackendConfig, request: &JsonRpcRequest) -> JsonRpcOutcome {
    if let Err(error) = StatusParams::from_wire(&request.params) {
        return JsonRpcOutcome::Error {
            id: request.id.clone(),
            code: AdapterErrorCode::InvalidParams,
            message: error.to_string(),
            data: None,
        };
    }
    let Some((adapter_id, deployment)) = web_search_deployment(config) else {
        return JsonRpcOutcome::Error {
            id: request.id.clone(),
            code: AdapterErrorCode::CredentialsUnavailable,
            message: CONFIG_UNAVAILABLE.to_owned(),
            data: None,
        };
    };
    let resolved = deployment.credential().map(credentials::resolve);
    let (health, last_failure) = match resolved {
        // Keyless backends need no credential; status checks discard any resolved secret.
        None | Some(Ok(_)) => (AdapterHealthState::Ready, None),
        Some(Err(_error)) => (
            AdapterHealthState::Unavailable,
            Some(StatusFailure {
                code: AdapterWireId::new(CREDENTIAL_FAILURE_CODE)
                    .expect("failure code fits the wire id grammar"),
                retryable: true,
                operation_id: None,
            }),
        ),
    };
    let identity = WireAdapterIdentity {
        adapter_id: adapter_id.clone(),
        version: AdapterVersion::new(env!("CARGO_PKG_VERSION"))
            .expect("crate version fits the adapter version grammar"),
        binding_digest: deployment.binding_digest(),
    };
    // OffsetDateTime's default serde format is not the RFC 3339 string required by the schema.
    let observed_at =
        match OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339) {
            Ok(stamp) => Value::String(stamp),
            Err(_) => {
                return JsonRpcOutcome::Error {
                    id: request.id.clone(),
                    code: AdapterErrorCode::InternalError,
                    message: "status timestamp serialization failed".to_owned(),
                    data: None,
                }
            }
        };
    let wire = json!({
        "schema": odin_adapter_core::ADAPTER_STATUS_SCHEMA_NAME,
        "adapter": identity,
        "revision": STATUS_REVISION,
        "health": health,
        // Successful resolution does not remove credential taint or verify the upstream account.
        "taint": AdapterTaint::CredentialTainted,
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
        // Validation errors contain only public snapshot fields, not credential details.
        Err(error) => JsonRpcOutcome::Error {
            id: request.id.clone(),
            code: AdapterErrorCode::InternalError,
            message: "status snapshot failed canonical validation".to_owned(),
            data: Some(json!({ "detail": error.to_string() })),
        },
    }
}

fn emit_raw_error(failure: &FrameFailure) -> ExitCode {
    let id = match &failure.id {
        Some(id) => json!(id),
        None => Value::Null,
    };
    let wire = json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": failure.code.code(),
            "message": failure.message,
        },
    });
    write_frame(&wire)
}

/// Oversized results still need an error reply within the frame limit.
fn emit_outcome(outcome: &JsonRpcOutcome) -> ExitCode {
    let wire = outcome.to_wire();
    if encode_frame(&wire).is_ok() {
        return write_frame(&wire);
    }
    write_frame(&json!({
        "jsonrpc": "2.0",
        "id": outcome.id(),
        "error": {
            "code": AdapterErrorCode::InternalError.code(),
            "message": RESPONSE_OVERSIZED,
        },
    }))
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
        Err(_) => {
            let _ = writeln!(
                std::io::stderr(),
                "adapter backend could not encode one canonical response frame"
            );
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::num::{NonZeroU32, NonZeroU64};

    use odin_adapter_core::config::{AdapterCredential, AdapterEndpoint, SearchBackend};
    use odin_adapter_core::operation::IdempotencyKey;
    use odin_adapter_core::transport::{WebSearchInput, WebSearchParams};
    use odin_adapter_core::OpaqueCredentialHandle;

    /// A valid in-bounds deployment whose only variable is the credential
    /// path suffix, so distinct fixtures carry distinct binding digests.
    fn deployment(credential_suffix: &str) -> AdapterDeployment {
        AdapterDeployment::new(
            SearchBackend::Brave,
            AdapterEndpoint::parse("https://search.example.invalid/resolve")
                .expect("fixture endpoint parses"),
            Some(
                AdapterCredential::new(
                    OpaqueCredentialHandle::new("cred:web.search").expect("fixture handle parses"),
                    PathBuf::from(format!("/run/odin/secrets/{credential_suffix}")),
                )
                .expect("fixture credential parses"),
            ),
            NonZeroU64::new(5_000).expect("nonzero timeout"),
            NonZeroU32::new(5).expect("nonzero result bound"),
            NonZeroU64::new(65_536).expect("nonzero response bound"),
        )
        .expect("fixture deployment validates")
    }

    fn config_with(adapters: &[(&str, AdapterDeployment)]) -> AdapterBackendConfig {
        let map: BTreeMap<AdapterWireId, AdapterDeployment> = adapters
            .iter()
            .map(|(key, deployment)| {
                (
                    AdapterWireId::new(*key).expect("fixture key parses"),
                    deployment.clone(),
                )
            })
            .collect();
        AdapterBackendConfig::new(map).expect("fixture config validates")
    }

    fn web_search_request(operation_id: &str) -> JsonRpcRequest {
        JsonRpcRequest::web_search(
            "req-1",
            AdapterWireId::new(operation_id).expect("fixture operation id parses"),
            IdempotencyKey::new("fixture-idempotency-key").expect("fixture key parses"),
            WebSearchInput::new("adapter boundary", 3).expect("fixture input validates"),
        )
        .expect("fixture request validates")
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds")
    }

    /// Deployment selection is keyed by this binary's fixed `web-search`
    /// key alone: the request's authority-minted `operation_id` stays
    /// evidence metadata and never selects configuration, even when an
    /// adapter is compiled under exactly that operation id.
    #[test]
    fn deployment_selection_ignores_request_operation_id() {
        let config = config_with(&[
            ("web-search", deployment("primary")),
            ("other-operation", deployment("decoy")),
        ]);
        let request = web_search_request("other-operation");
        let params = WebSearchParams::from_wire(&request.params).expect("fixture params parse");
        let (selected_id, selected) =
            web_search_deployment(&config).expect("the fixed key resolves");
        assert_eq!(selected_id.as_str(), WEB_SEARCH_ADAPTER_ID);
        let by_operation_id = config
            .adapters()
            .get(params.operation_id())
            .expect("the decoy is compiled under the request operation_id");
        assert_ne!(
            selected.binding_digest(),
            by_operation_id.binding_digest(),
            "selection must follow the fixed web-search key, not the request operation_id"
        );
    }

    /// A config without the compiled `web-search` key answers
    /// `web.search` with the typed unavailable error — id echoed, no
    /// fallback deployment, no upstream attempt.
    #[test]
    fn missing_compiled_key_answers_typed_unavailable() {
        let config = config_with(&[("other-operation", deployment("decoy"))]);
        let request = web_search_request("other-operation");
        let outcome = runtime().block_on(web_search(&config, &request));
        match outcome {
            JsonRpcOutcome::Error {
                id,
                code,
                message,
                data,
            } => {
                assert_eq!(id, "req-1");
                assert_eq!(code, AdapterErrorCode::CredentialsUnavailable);
                assert_eq!(message, CONFIG_UNAVAILABLE);
                assert_eq!(data, None);
            }
            other => panic!("expected the typed unavailable error, got {other:?}"),
        }
    }

    /// A launch whose configuration never became available answers every
    /// dispatched method with the typed error and still echoes the id.
    #[test]
    fn unavailable_configuration_answers_typed_error_with_echoed_id() {
        let failure = ConfigFailure {
            code: AdapterErrorCode::CredentialsUnavailable,
            message: CONFIG_UNAVAILABLE,
        };
        let request = JsonRpcRequest::status("status-req-7");
        let outcome = runtime().block_on(dispatch(&Err(failure), &request));
        match outcome {
            JsonRpcOutcome::Error {
                id, code, message, ..
            } => {
                assert_eq!(id, "status-req-7");
                assert_eq!(code, AdapterErrorCode::CredentialsUnavailable);
                assert_eq!(message, CONFIG_UNAVAILABLE);
            }
            other => panic!("expected the typed config error, got {other:?}"),
        }
    }

    /// The credential-bearing adapter's snapshot never reports `clean`:
    /// a failed local resolve yields `unavailable` health with the typed
    /// failure while taint stays `credential_tainted` — monotonic, never
    /// reset by any later successful resolve, never implying upstream
    /// account standing.
    #[test]
    fn status_stays_credential_tainted_on_failed_local_resolve() {
        let config = config_with(&[("web-search", deployment("absent"))]);
        let request = JsonRpcRequest::status("status-req-1");
        let outcome = status(&config, &request);
        let JsonRpcOutcome::Success { id, result } = outcome else {
            panic!("a present config must serve a status snapshot");
        };
        assert_eq!(id, "status-req-1");
        assert_eq!(result["adapter"]["adapter_id"], "web-search");
        assert_eq!(result["health"], "unavailable");
        assert_eq!(result["taint"], "credential_tainted");
        assert_eq!(result["last_failure"]["code"], "credentials_unavailable");
    }
}
