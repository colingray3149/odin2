//! The kernel bridge for non-OMP harness sessions: supported agents call
//! their seat's Odin functions — `seat_ask_*`, `check_run`, … — through an
//! MCP server odind serves on loopback, and every call is governed exactly
//! like an OMP seat's. Claude workloads use the separate driver contract.
//!
//! Uses the OMP factory's operation binding, admitted definitions, and dispatch
//! checks rather than a separate policy path. Tools requiring OMP execution
//! context remain unavailable and are identified in their descriptions.
//!
//! Transport (MCP streamable HTTP, JSON responses only): one loopback
//! listener, `POST /mcp/<live-session-id>` with `Authorization: Bearer
//! <per-session random token>`. Methods: `initialize`, `ping`, `tools/list`,
//! `tools/call`; notifications and client responses are acknowledged `202`.
//! Anything else is refused typed ([`McpRefusal`]) with one structured log
//! line. [`KernelMcpServer::handle`] is transport-free so the protocol and
//! its refusals are tested without a socket; odind owns the listener.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex, Weak};

use odin_domain::{Scope, SessionId};
use serde_json::{json, Value};
use thiserror::Error;

use crate::host_tools::operations::{
    HostToolOperationError, HostToolOperations, SessionOperationBinding, SessionOperationContext,
};
use crate::host_tools::RpcHostToolDefinition;

/// The MCP protocol revisions this server speaks; the newest is offered
/// when the client asks for one it does not know.
pub const PROTOCOL_VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

/// The server name every harness config registers: Claude Code exposes its
/// tools as `mcp__odin__<tool>`.
pub const SERVER_NAME: &str = "odin";

/// One session's governed kernel surface.
pub trait KernelSession: Send + Sync {
    /// The model-visible definitions of the session's admitted tools.
    fn tools(&self) -> Result<Vec<RpcHostToolDefinition>, HostToolOperationError>;

    /// One governed call; `request_id` is unique per call.
    fn call(
        &self,
        tool: &str,
        arguments: Value,
        request_id: &str,
    ) -> Result<Value, HostToolOperationError>;
}

pub struct GovernedSession {
    operations: HostToolOperations,
    binding: SessionOperationBinding,
    session: SessionId,
    scope: Scope,
    admitted: BTreeSet<String>,
}

impl GovernedSession {
    pub(crate) fn new(
        operations: HostToolOperations,
        binding: SessionOperationBinding,
        session: SessionId,
        scope: Scope,
        admitted: BTreeSet<String>,
    ) -> Self {
        Self {
            operations,
            binding,
            session,
            scope,
            admitted,
        }
    }
}

impl KernelSession for GovernedSession {
    fn tools(&self) -> Result<Vec<RpcHostToolDefinition>, HostToolOperationError> {
        self.operations.admitted_definitions(&self.admitted, false)
    }

    fn call(
        &self,
        tool: &str,
        arguments: Value,
        request_id: &str,
    ) -> Result<Value, HostToolOperationError> {
        // The listed surface is the callable surface, exactly as the OMP
        // bridge registers it: an unlisted name never reaches dispatch.
        if !self.admitted.contains(tool) {
            return Err(HostToolOperationError::UnknownTool {
                name: tool.to_owned(),
            });
        }
        self.operations.dispatch_tool(
            SessionOperationContext {
                binding: &self.binding,
                session: &self.session,
                scope: &self.scope,
                // No OMP execution context is available; tools requiring it must refuse.
                execution: None,
            },
            tool,
            None,
            arguments,
            request_id,
        )
    }
}

/// Why a request was refused before any JSON-RPC method ran.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum McpRefusal {
    #[error("no kernel session is registered at this path")]
    UnknownSession,
    #[error("the bearer token is missing or does not match this session")]
    Unauthorized,
    #[error("the request body is not one JSON-RPC message")]
    Malformed,
    #[error("batched JSON-RPC messages are not served")]
    Batch,
}

impl McpRefusal {
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnknownSession => "unknown_session",
            Self::Unauthorized => "unauthorized",
            Self::Malformed => "malformed",
            Self::Batch => "batch",
        }
    }

    const fn status(self) -> u16 {
        match self {
            Self::UnknownSession => 404,
            Self::Unauthorized => 401,
            Self::Malformed | Self::Batch => 400,
        }
    }
}

/// One HTTP answer: `body` is `None` for `202 Accepted`.
#[derive(Debug, PartialEq)]
pub struct McpReply {
    pub status: u16,
    pub body: Option<Value>,
}

/// Where one session reaches its kernel bridge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpEndpoint {
    pub url: String,
    pub bearer: String,
}

impl McpEndpoint {
    /// Claude Code's `--mcp-config` document.
    pub fn claude_config(&self) -> Value {
        json!({"mcpServers": {SERVER_NAME: {
            "type": "http",
            "url": self.url,
            "headers": {"Authorization": format!("Bearer {}", self.bearer)},
        }}})
    }

    /// The ACP `mcpServers` entry (`session/new`, `session/load`).
    pub fn acp_server(&self) -> Value {
        json!({
            "type": "http",
            "name": SERVER_NAME,
            "url": self.url,
            "headers": [{"name": "Authorization", "value": format!("Bearer {}", self.bearer)}],
        })
    }

    /// Writes the Claude Code config, owner-only, replacing any older one.
    pub fn write_config(&self, path: &Path) -> std::io::Result<()> {
        use std::io::Write as _;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt as _;
        let staging = path.with_extension("json.tmp");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&staging)?;
        file.write_all(&serde_json::to_vec_pretty(&self.claude_config())?)?;
        file.sync_all()?;
        std::fs::rename(&staging, path)
    }

    /// The bearer a config written earlier for `url` carries: a terminal
    /// that outlived an odind restart keeps the token its agent read.
    pub fn persisted_bearer(path: &Path, url: &str) -> Option<String> {
        let config: Value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
        let server = config.pointer(&format!("/mcpServers/{SERVER_NAME}"))?;
        if server.get("url").and_then(Value::as_str) != Some(url) {
            return None;
        }
        let header = server.pointer("/headers/Authorization")?.as_str()?;
        let bearer = header.strip_prefix("Bearer ")?;
        valid_bearer(bearer).then(|| bearer.to_owned())
    }
}

fn valid_bearer(bearer: &str) -> bool {
    bearer.len() == 64 && bearer.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn fresh_bearer() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

fn bearer_digest(bearer: &str) -> [u8; 32] {
    *blake3::hash(bearer.as_bytes()).as_bytes()
}

struct Entry {
    generation: u64,
    seat: String,
    digest: [u8; 32],
    session: Arc<dyn KernelSession>,
}

/// The kernel bridge: one per daemon, one entry per open harness session.
pub struct KernelMcpServer {
    base_url: String,
    /// The node-reachable origin pods use: the node's declared pod-facing
    /// address, bearer-protected like loopback.
    node_base_url: Option<String>,
    sessions: Mutex<BTreeMap<String, Entry>>,
    generations: std::sync::atomic::AtomicU64,
}

/// A registered session; dropping it (the session's control is dropped when
/// the session ends) retires the endpoint.
pub struct McpRegistration {
    server: Weak<KernelMcpServer>,
    session: String,
    generation: u64,
    pub endpoint: McpEndpoint,
}

impl Drop for McpRegistration {
    fn drop(&mut self) {
        if let Some(server) = self.server.upgrade() {
            if let Ok(mut sessions) = server.sessions.lock() {
                // A reclaim re-registered the session: that entry is not ours.
                if sessions
                    .get(&self.session)
                    .is_some_and(|entry| entry.generation == self.generation)
                {
                    sessions.remove(&self.session);
                    tracing::info!("odind: mcp retired session={}", self.session);
                }
            }
        }
    }
}

impl std::fmt::Debug for McpRegistration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpRegistration")
            .field("session", &self.session)
            .field("url", &self.endpoint.url)
            .finish_non_exhaustive()
    }
}

fn rpc_error(id: &Value, code: i64, message: impl Into<String>) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message.into()}})
}

fn rpc_result(id: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

impl KernelMcpServer {
    /// `base_url` is the listener's origin, e.g. `http://127.0.0.1:18430`.
    pub fn new(base_url: impl Into<String>) -> Arc<Self> {
        Self::with_node(base_url, None)
    }

    /// [`Self::new`] with the node-reachable origin pods use.
    pub fn with_node(base_url: impl Into<String>, node_base_url: Option<String>) -> Arc<Self> {
        Arc::new(Self {
            node_base_url: node_base_url.map(|url| url.trim_end_matches('/').to_owned()),
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            sessions: Mutex::new(BTreeMap::new()),
            generations: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// The endpoint URL of one live session.
    pub fn url_for(&self, live_session: &str) -> String {
        format!("{}/mcp/{live_session}", self.base_url)
    }

    /// The endpoint URL a pod reaches one live session at, when the node
    /// serves one.
    pub fn node_url_for(&self, live_session: &str) -> Option<String> {
        self.node_base_url
            .as_ref()
            .map(|base| format!("{base}/mcp/{live_session}"))
    }

    /// [`Self::register`] at the node-reachable URL; `None` when this node
    /// serves pods no bridge.
    pub fn register_for_pod(
        self: &Arc<Self>,
        live_session: &str,
        seat: &str,
        session: Arc<dyn KernelSession>,
        bearer: Option<String>,
    ) -> Option<McpRegistration> {
        let url = self.node_url_for(live_session)?;
        let mut registration = self.register(live_session, seat, session, bearer);
        registration.endpoint.url = url;
        Some(registration)
    }

    /// Registers (or re-registers, on reclaim) one session. `bearer` reuses
    /// a token an earlier config carries; anything else gets a fresh one.
    pub fn register(
        self: &Arc<Self>,
        live_session: &str,
        seat: &str,
        session: Arc<dyn KernelSession>,
        bearer: Option<String>,
    ) -> McpRegistration {
        let bearer = bearer
            .filter(|bearer| valid_bearer(bearer))
            .unwrap_or_else(fresh_bearer);
        let generation = self
            .generations
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.insert(
                live_session.to_owned(),
                Entry {
                    generation,
                    seat: seat.to_owned(),
                    digest: bearer_digest(&bearer),
                    session,
                },
            );
        }
        let url = self.url_for(live_session);
        tracing::info!("odind: mcp registered session={live_session} seat={seat} url={url}");
        McpRegistration {
            server: Arc::downgrade(self),
            session: live_session.to_owned(),
            generation,
            endpoint: McpEndpoint { url, bearer },
        }
    }

    fn refuse(path_session: &str, refusal: McpRefusal) -> McpReply {
        tracing::error!(
            "odind: mcp refused session={path_session} reason={} detail=\"{refusal}\"",
            refusal.code()
        );
        let body = match refusal {
            McpRefusal::Malformed => Some(rpc_error(&Value::Null, -32700, refusal.to_string())),
            McpRefusal::Batch => Some(rpc_error(&Value::Null, -32600, refusal.to_string())),
            _ => Some(json!({"error": refusal.code(), "message": refusal.to_string()})),
        };
        McpReply {
            status: refusal.status(),
            body,
        }
    }

    /// Serves one `POST /mcp/<path_session>`. Blocking: a tool call runs
    /// the governed dispatch, so callers run this off the async runtime.
    pub fn handle(&self, path_session: &str, authorization: Option<&str>, body: &[u8]) -> McpReply {
        let (session, seat) = {
            let Ok(sessions) = self.sessions.lock() else {
                return McpReply {
                    status: 503,
                    body: Some(json!({"error": "unavailable"})),
                };
            };
            let Some(entry) = sessions.get(path_session) else {
                return Self::refuse(path_session, McpRefusal::UnknownSession);
            };
            let presented = authorization
                .and_then(|header| header.strip_prefix("Bearer "))
                .map(|bearer| bearer_digest(bearer.trim()));
            if presented != Some(entry.digest) {
                return Self::refuse(path_session, McpRefusal::Unauthorized);
            }
            (Arc::clone(&entry.session), entry.seat.clone())
        };
        let message: Value = match serde_json::from_slice(body) {
            Ok(message) => message,
            Err(_) => return Self::refuse(path_session, McpRefusal::Malformed),
        };
        if message.is_array() {
            return Self::refuse(path_session, McpRefusal::Batch);
        }
        let Some(object) = message.as_object() else {
            return Self::refuse(path_session, McpRefusal::Malformed);
        };
        let method = object.get("method").and_then(Value::as_str);
        let id = object.get("id").cloned();
        let (Some(method), Some(id)) = (method, id) else {
            // A notification (no id) or a client response (no method).
            return McpReply {
                status: 202,
                body: None,
            };
        };
        let params = object.get("params").cloned().unwrap_or_else(|| json!({}));
        let body = match method {
            "initialize" => {
                let asked = params.get("protocolVersion").and_then(Value::as_str);
                let version = asked
                    .filter(|asked| PROTOCOL_VERSIONS.contains(asked))
                    .unwrap_or(PROTOCOL_VERSIONS[0]);
                tracing::info!(
                    "odind: mcp initialize session={path_session} seat={seat} \
                     protocol={version}"
                );
                rpc_result(
                    &id,
                    json!({
                        "protocolVersion": version,
                        "capabilities": {"tools": {"listChanged": false}},
                        "serverInfo": {"name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION")},
                        "instructions": "Odin's functions for this seat. Odin governs every \
                            call exactly as for its own seats: a refusal or an approval wait \
                            is Odin's answer, not a fault.",
                    }),
                )
            }
            "ping" => rpc_result(&id, json!({})),
            "tools/list" => match session.tools() {
                Ok(definitions) => rpc_result(
                    &id,
                    json!({"tools": definitions.iter().map(|definition| json!({
                        "name": definition.name,
                        "description": definition.description,
                        "inputSchema": crate::host_tools::schema_compat::without_root_annotations(
                            &definition.parameters,
                        ),
                    })).collect::<Vec<_>>()}),
                ),
                Err(error) => {
                    tracing::error!(
                        "odind: mcp tools-list failed session={path_session} seat={seat} \
                         error=\"{error}\""
                    );
                    rpc_error(&id, -32603, error.to_string())
                }
            },
            "tools/call" => call(&*session, path_session, &seat, &id, &params),
            other => {
                tracing::error!(
                    "odind: mcp refused session={path_session} reason=unknown_method \
                     method={other}"
                );
                rpc_error(&id, -32601, format!("method {other} is not served"))
            }
        };
        McpReply {
            status: 200,
            body: Some(body),
        }
    }
}

fn call(
    session: &dyn KernelSession,
    path_session: &str,
    seat: &str,
    id: &Value,
    params: &Value,
) -> Value {
    let Some(tool) = params.get("name").and_then(Value::as_str) else {
        return rpc_error(id, -32602, "tools/call needs a tool name");
    };
    let arguments = match params.get("arguments") {
        None | Some(Value::Null) => json!({}),
        Some(arguments @ Value::Object(_)) => arguments.clone(),
        Some(_) => return rpc_error(id, -32602, "tools/call arguments must be an object"),
    };
    let request = format!("mcp-{}", uuid::Uuid::new_v4().simple());
    match session.call(tool, arguments, &request) {
        Ok(result) => {
            let failed = result
                .get("isError")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            tracing::info!(
                "odind: mcp call session={path_session} seat={seat} tool={tool} \
                 request={request} outcome={}",
                if failed { "tool_error" } else { "ok" }
            );
            let text = crate::bridge::model_tool_text(&result)
                .unwrap_or_else(|error| format!("result could not be rendered: {error}"));
            rpc_result(
                id,
                json!({"content": [{"type": "text", "text": text}], "isError": failed}),
            )
        }
        Err(HostToolOperationError::UnknownTool { name }) => {
            tracing::error!(
                "odind: mcp refused session={path_session} seat={seat} tool={name} \
                 reason=unknown_tool"
            );
            rpc_error(
                id,
                -32602,
                format!("{name} is not one of this seat's Odin tools"),
            )
        }
        Err(error) => {
            // A governed refusal (policy, approval, revoked token…) is the
            // tool's answer to the model, as on the OMP bridge.
            tracing::error!(
                "odind: mcp call session={path_session} seat={seat} tool={tool} \
                 request={request} outcome=refused"
            );
            rpc_result(
                id,
                json!({
                    "content": [{"type": "text", "text": crate::bridge::model_error_text(&error.to_string())}],
                    "isError": true
                }),
            )
        }
    }
}

#[cfg(test)]
mod tests;
