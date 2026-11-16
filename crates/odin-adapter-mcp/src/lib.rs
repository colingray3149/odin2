//! Sequence steps share an MCP session so stateful servers retain their state between calls.

use std::collections::BTreeSet;
use std::io::{ErrorKind, Read, Write};
use std::ops::Range;
use std::os::fd::AsFd;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};
use rustix::process::{kill_process, Pid, Signal};
use serde_json::{json, Value};

mod http_read;
pub mod read;

pub const MCP_PROTOCOL_VERSION: &str = "2025-06-18";

/// Allow the whole-page response used for windowed reads, including JSON escaping.
const LINE_BYTES: usize = 16 << 20;

const ANSWER_BYTES: usize = 32 << 20;

const LIST_PAGES: usize = 64;
const LIST_TOOLS: usize = 1024;
const LIST_BYTES: usize = 8 << 20;

const READ_CHUNK: usize = 64 << 10;

/// Keep diagnostics below a pipe buffer because the host does not drain stderr during calls.
pub const NOTE_BYTES: usize = 1024;
/// The most of a tool's own error text a failure carries as its cause.
const CAUSE_BYTES: usize = 400;

/// Fallback when a backend's argv declares no `--call-bound`: page navigation
/// and a separate PDF fetch need longer than a status probe.
pub const DEFAULT_CALL_BOUND: Duration = Duration::from_secs(35);
/// Sanity range only: a synchronous call longer than this belongs in the backend's own async job.
const MAX_CALL_BOUND_SECONDS: u64 = 300;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeConfig {
    pub adapter: String,
    pub kind_prefix: String,
    pub read_only: Vec<String>,
    pub r1: Vec<String>,
    pub sequences: Vec<Sequence>,
    pub expose: Vec<String>,
    pub load_check: Option<String>,
    pub window: Option<String>,
    pub pdf_text: Option<String>,
    pub article_text: Option<String>,
    /// The page fetch with a browser's network fingerprint, tried after the plain reader.
    pub fingerprint_fetch: Option<String>,
    /// How long one operation call may take, its MCP session included.
    pub call_bound: Duration,
    /// BLAKE3 pin (64 hex) of the served tools' names, descriptions and input schemas; empty only while printing it.
    pub surface: String,
    pub server: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sequence {
    pub name: String,
    pub tools: Vec<String>,
}

impl Sequence {
    /// `<name>=<tool>,<tool>...`.
    fn parse(value: &str) -> Result<Self, BridgeError> {
        let (name, tools) = value
            .split_once('=')
            .ok_or_else(|| BridgeError::Argv(format!("sequence {value:?} is not name=tool,...")))?;
        let tools: Vec<String> = tools.split(',').map(str::to_owned).collect();
        if !kind_segment(name) || tools.iter().any(|tool| tool.is_empty()) {
            return Err(BridgeError::Argv(format!(
                "sequence {value:?} needs a kind-segment name and named tools"
            )));
        }
        Ok(Self {
            name: name.to_owned(),
            tools,
        })
    }
}

fn kind_segment(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '-')
}

/// Each failure names a known cause without forwarding untrusted tool payloads.
#[derive(Debug, Eq, PartialEq)]
pub enum BridgeError {
    Argv(String),
    Spawn(String),
    Timeout(String),
    Protocol(String),
    Tool(String),
    PageLoad(String),
    PdfText(String),
    /// The site refused, challenged or never answered: a failure another network exit may not
    /// repeat. It reads as the failure it came from.
    Refused(String),
    OffsetPastEnd {
        offset: usize,
        total: usize,
    },
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Argv(detail) => write!(formatter, "bridge argv rejected: {detail}"),
            Self::Spawn(detail) => write!(formatter, "{detail}"),
            Self::Timeout(detail) => write!(formatter, "MCP server timed out: {detail}"),
            Self::Protocol(detail) => write!(formatter, "MCP server answered badly: {detail}"),
            Self::Tool(detail) | Self::Refused(detail) => write!(formatter, "{detail}"),
            Self::PageLoad(detail) => write!(formatter, "the page did not load: {detail}"),
            Self::PdfText(detail) => write!(formatter, "the PDF did not read as text: {detail}"),
            Self::OffsetPastEnd { offset, total } => write!(
                formatter,
                "offset {offset} is past the end of the page ({total} characters)"
            ),
        }
    }
}

impl BridgeError {
    /// This failure, marked as a refusal by the site; its prose is unchanged.
    pub(crate) fn refused(self) -> Self {
        Self::Refused(self.to_string())
    }
}

fn parse_call_bound(value: &str) -> Result<Duration, BridgeError> {
    match value.parse::<u64>() {
        Ok(seconds @ 1..=MAX_CALL_BOUND_SECONDS) => Ok(Duration::from_secs(seconds)),
        Ok(0) => Err(BridgeError::Argv("--call-bound 0 leaves no time for a call".into())),
        Ok(seconds) => Err(BridgeError::Argv(format!(
            "--call-bound {seconds} is over {MAX_CALL_BOUND_SECONDS} seconds; longer work belongs in an async job"
        ))),
        Err(_) => Err(BridgeError::Argv(format!(
            "--call-bound {value:?} is not a whole number of seconds"
        ))),
    }
}

impl BridgeConfig {
    /// `--adapter <id> --kind-prefix <prefix> [--read-only <tool>]... [--r1 <tool>]...
    /// [--sequence <name>=<tool>,...]... [--expose <tool>]... [--load-check <tool>]
    /// [--window <field>] [--pdf-text <executable>] [--article-text <executable>]
    /// [--fingerprint-fetch <executable>] [--call-bound <seconds>] --surface <64 hex> -- <server argv>`.
    pub fn parse(arguments: &[String]) -> Result<Self, BridgeError> {
        let config = Self::parse_unpinned(arguments)?;
        if config.surface.is_empty() {
            return Err(BridgeError::Argv(
                "--surface is required; print it with odin-adapter-mcp --print-surface <same flags> -- <server>"
                    .into(),
            ));
        }
        Ok(config)
    }

    /// The same argv with `--surface` optional, for printing the pin.
    pub fn parse_unpinned(arguments: &[String]) -> Result<Self, BridgeError> {
        let split = arguments
            .iter()
            .position(|argument| argument == "--")
            .ok_or_else(|| BridgeError::Argv("missing `--` before the MCP server argv".into()))?;
        let (own, server) = (&arguments[..split], &arguments[split + 1..]);
        if server.is_empty() {
            return Err(BridgeError::Argv("empty MCP server argv".into()));
        }
        let (mut adapter, mut kind_prefix, mut read_only) = (None, None, Vec::new());
        let mut r1 = Vec::new();
        let (mut sequences, mut expose, mut load_check) = (Vec::new(), Vec::new(), None);
        let (mut window, mut pdf_text, mut article_text) = (None, None, None);
        let (mut fingerprint_fetch, mut call_bound) = (None, DEFAULT_CALL_BOUND);
        let mut surface = None;
        let mut flags = own.iter();
        while let Some(flag) = flags.next() {
            let value = flags
                .next()
                .ok_or_else(|| BridgeError::Argv(format!("{flag} needs a value")))?
                .clone();
            match flag.as_str() {
                "--adapter" => adapter = Some(value),
                "--kind-prefix" => kind_prefix = Some(value),
                "--read-only" => read_only.push(value),
                "--r1" => r1.push(value),
                "--sequence" => sequences.push(Sequence::parse(&value)?),
                "--expose" => expose.push(value),
                "--load-check" => load_check = Some(value),
                "--window" => window = Some(value),
                "--pdf-text" => pdf_text = Some(value),
                "--article-text" => article_text = Some(value),
                "--fingerprint-fetch" => fingerprint_fetch = Some(value),
                "--call-bound" => call_bound = parse_call_bound(&value)?,
                "--surface" => surface = Some(value),
                other => return Err(BridgeError::Argv(format!("unknown flag {other}"))),
            }
        }
        let kind_prefix =
            kind_prefix.ok_or_else(|| BridgeError::Argv("--kind-prefix is required".into()))?;
        if !kind_prefix
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_lowercase())
            || !kind_prefix
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '-')
        {
            return Err(BridgeError::Argv(format!(
                "kind prefix {kind_prefix:?} must be one lowercase operation-kind segment"
            )));
        }
        if r1
            .iter()
            .any(|tool| !kind_segment(tool) || read_only.contains(tool))
        {
            return Err(BridgeError::Argv(
                "--r1 requires a valid tool name not declared --read-only".into(),
            ));
        }
        let surface = surface.unwrap_or_default();
        if !surface.is_empty()
            && (surface.len() != 64
                || !surface
                    .chars()
                    .all(|ch| ch.is_ascii_digit() || ('a'..='f').contains(&ch)))
        {
            return Err(BridgeError::Argv(
                "--surface must be 64 lowercase hex".into(),
            ));
        }
        Ok(Self {
            adapter: adapter.ok_or_else(|| BridgeError::Argv("--adapter is required".into()))?,
            kind_prefix,
            read_only,
            r1,
            sequences,
            expose,
            load_check,
            window,
            pdf_text,
            article_text,
            fingerprint_fetch,
            call_bound,
            surface,
            server: server.to_vec(),
        })
    }

    /// Invalid tool names cannot become operation-kind segments.
    pub fn kind_of(&self, tool: &str) -> Option<String> {
        kind_segment(tool).then(|| format!("{}.{tool}", self.kind_prefix))
    }

    fn serves_only_declared(&self) -> bool {
        !self.sequences.is_empty() || !self.expose.is_empty()
    }

    fn serves_tool(&self, tool: &str) -> bool {
        !self.serves_only_declared() || self.expose.iter().any(|exposed| exposed == tool)
    }

    pub fn plan(&self, kind: &str) -> Option<Vec<String>> {
        let name = kind.strip_prefix(&self.kind_prefix)?.strip_prefix('.')?;
        if let Some(sequence) = self.sequences.iter().find(|sequence| sequence.name == name) {
            return Some(sequence.tools.clone());
        }
        self.serves_tool(name).then(|| vec![name.to_owned()])
    }

    fn read_only(&self, tool: &Value) -> bool {
        let name = tool.get("name").and_then(Value::as_str).unwrap_or_default();
        self.read_only.iter().any(|listed| listed == name)
            || tool
                .pointer("/annotations/readOnlyHint")
                .and_then(Value::as_bool)
                == Some(true)
    }

    /// Include deployment settings so changed server configuration cannot reuse its identity.
    pub fn binding_digest(&self) -> String {
        let mut wire = json!({
            "adapter": self.adapter,
            "kind_prefix": self.kind_prefix,
            "read_only": self.read_only,
            "server": self.server,
        });
        if !self.r1.is_empty() {
            wire["r1"] = json!(self.r1);
        }
        if self.serves_only_declared() {
            let sequences: Vec<String> = self
                .sequences
                .iter()
                .map(|sequence| format!("{}={}", sequence.name, sequence.tools.join(",")))
                .collect();
            wire["sequences"] = json!(sequences);
            wire["expose"] = json!(self.expose);
        }
        for (field, value) in [
            ("load_check", &self.load_check),
            ("window", &self.window),
            ("pdf_text", &self.pdf_text),
            ("article_text", &self.article_text),
            ("fingerprint_fetch", &self.fingerprint_fetch),
        ] {
            if let Some(value) = value {
                wire[field] = json!(value);
            }
        }
        wire["surface"] = json!(self.surface);
        let canonical =
            odin_strict_json::canonicalize(&wire).expect("string-only JSON canonicalizes");
        odin_adapter_core::Digest::hash(&canonical).to_string()
    }

    /// The pin of what this bridge serves: the served tools sorted by name, each reduced to
    /// name, description and input schema, so a server that changes one is a different surface.
    pub fn surface_digest(&self, tools: &[Value]) -> Result<String, BridgeError> {
        let mut served: Vec<Value> = tools
            .iter()
            .filter(|tool| {
                let name = tool.get("name").and_then(Value::as_str).unwrap_or_default();
                self.covers_tool(name)
            })
            .map(canonical_tool)
            .collect();
        served.sort_by(|left, right| {
            left["name"]
                .as_str()
                .unwrap_or_default()
                .cmp(right["name"].as_str().unwrap_or_default())
        });
        let canonical = odin_strict_json::canonicalize(&served).map_err(|error| {
            BridgeError::Protocol(format!("the tool surface does not canonicalize: {error}"))
        })?;
        Ok(odin_adapter_core::Digest::hash(&canonical).hex())
    }

    /// A tool the pin must cover: one this bridge serves, or a sequence step or load check it calls.
    fn covers_tool(&self, name: &str) -> bool {
        self.serves_tool(name)
            || self
                .sequences
                .iter()
                .any(|sequence| sequence.tools.iter().any(|step| step == name))
            || self.load_check.as_deref() == Some(name)
    }

    /// Refuse a server whose tools differ from the pinned surface.
    pub fn check_surface(&self, tools: &[Value]) -> Result<(), BridgeError> {
        let served = self.surface_digest(tools)?;
        if served == self.surface {
            return Ok(());
        }
        let prefix = |digest: &str| digest.chars().take(12).collect::<String>();
        Err(BridgeError::Protocol(format!(
            "the {} MCP server's tool surface changed: pinned {}, served {}; read its tool descriptions, then set --surface {served} in its adapterBackends argv",
            self.adapter,
            prefix(&self.surface),
            prefix(&served)
        )))
    }

    pub fn descriptor(&self, tools: &[Value]) -> Result<Value, BridgeError> {
        self.check_surface(tools)?;
        let mut operations = Vec::new();
        let mut skipped = 0usize;
        for tool in tools {
            let name = tool
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| BridgeError::Protocol("a listed tool has no name".into()))?;
            if !self.serves_tool(name) {
                continue;
            }
            let Some(kind) = self.kind_of(name) else {
                skipped += 1;
                continue;
            };
            let read_only = self.read_only(tool);
            let r1 = self.r1.iter().any(|declared| declared == name);
            if r1 && read_only {
                return Err(BridgeError::Protocol(format!(
                    "tool {name} is declared R1 but marked read-only"
                )));
            }
            operations.push(operation(&kind, read_only, r1));
        }
        if skipped > 0 {
            note(&format!(
                "{skipped} listed tools skipped: their names are not kind segments"
            ));
        }
        for sequence in &self.sequences {
            let mut read_only = true;
            for step in sequence.tools.iter().chain(&self.load_check) {
                let tool = tools
                    .iter()
                    .find(|tool| tool.get("name").and_then(Value::as_str) == Some(step.as_str()))
                    .ok_or_else(|| {
                        BridgeError::Protocol(format!(
                            "sequence {} names {step}, which the server does not list",
                            sequence.name
                        ))
                    })?;
                read_only &= self.read_only(tool);
            }
            operations.push(operation(
                &format!("{}.{}", self.kind_prefix, sequence.name),
                read_only,
                false,
            ));
        }
        if operations.is_empty() {
            return Err(BridgeError::Protocol(
                "the server lists no usable tool".into(),
            ));
        }
        Ok(json!({
            "schema": odin_adapter_core::ADAPTER_DESCRIPTOR_SCHEMA_NAME,
            "adapter": self.identity(),
            "protocol_version": odin_adapter_core::descriptor::ADAPTER_PROTOCOL_VERSION,
            "operations": operations,
            "credential_handles": [],
            "initial_taint": "clean",
        }))
    }

    pub fn rules(&self) -> Rules<'_> {
        Rules {
            load_check: self.load_check.as_deref(),
            window: self.window.as_deref(),
            pdf_text: self.pdf_text.as_deref(),
            article_text: self.article_text.as_deref(),
            fingerprint_fetch: self.fingerprint_fetch.as_deref(),
        }
    }

    pub fn identity(&self) -> Value {
        json!({
            "adapter_id": self.adapter,
            "version": env!("CARGO_PKG_VERSION"),
            "binding_digest": self.binding_digest(),
        })
    }
}

fn operation(kind: &str, read_only: bool, r1: bool) -> Value {
    json!({
        "kind": kind,
        "input_schema": format!("schemas/capability/{kind}.input.json"),
        "output_schema": format!("schemas/capability/{kind}.output.json"),
        "effect_class": if read_only { "R0" } else if r1 { "R1" } else { "R3" },
        "idempotency": if read_only { "pure" } else { "required" },
        "evidence": [{
            "kind": odin_adapter_core::ADAPTER_RECEIPT_EVIDENCE_KIND,
            "schema": odin_adapter_core::ADAPTER_RECEIPT_EVIDENCE_SCHEMA_REF,
            "required": true,
        }],
        "credential_handle": null,
        "taint_after": "clean",
    })
}

/// A sequence step receives only fields declared by its own input schema.
pub fn step_arguments(input: &Value, tool: Option<&Value>) -> Value {
    let named = tool
        .and_then(|tool| tool.pointer("/inputSchema/properties"))
        .and_then(Value::as_object);
    let arguments: serde_json::Map<String, Value> = input
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(field, _)| named.is_some_and(|named| named.contains_key(*field)))
        .map(|(field, value)| (field.clone(), value.clone()))
        .collect();
    Value::Object(arguments)
}

/// The three fields a pin covers. Absent description or schema stay null, so a server that
/// drops one changes the digest; annotations and other fields do not.
fn canonical_tool(tool: &Value) -> Value {
    json!({
        "name": tool.get("name").cloned().unwrap_or(Value::Null),
        "description": tool.get("description").cloned().unwrap_or(Value::Null),
        "inputSchema": tool.get("inputSchema").cloned().unwrap_or(Value::Null),
    })
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Rules<'a> {
    pub load_check: Option<&'a str>,
    pub window: Option<&'a str>,
    pub pdf_text: Option<&'a str>,
    pub article_text: Option<&'a str>,
    pub fingerprint_fetch: Option<&'a str>,
}

// A cancellable reader prevents inherited stderr pipes from extending the session.
struct StderrTail {
    bytes: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    reader: Option<std::thread::JoinHandle<()>>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    secret: String,
}

fn capture_stderr(stderr: ChildStderr, secret: &str) -> std::io::Result<StderrTail> {
    nonblocking(&stderr)?;
    let bytes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let tail = std::sync::Arc::clone(&bytes);
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cancel = std::sync::Arc::clone(&stop);
    // Retain URL overlap so a tail cut cannot hide a redaction match.
    let retain = NOTE_BYTES.saturating_add(secret.len());
    let reader = std::thread::Builder::new()
        .name("mcp-stderr".into())
        .spawn(move || drain_stderr(stderr, tail, cancel, retain))?;
    Ok(StderrTail {
        bytes,
        reader: Some(reader),
        stop,
        secret: secret.to_owned(),
    })
}

fn drain_stderr(
    mut stderr: ChildStderr,
    tail: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    retain: usize,
) {
    let mut chunk = [0u8; 256];
    loop {
        if stop.load(std::sync::atomic::Ordering::Relaxed) {
            drain_ready(&mut stderr, &tail, retain);
            break;
        }
        match stderr.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => append_tail(&tail, &chunk[..count], retain),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                let slice = Instant::now() + Duration::from_millis(20);
                match ready(&stderr, PollFlags::IN, slice) {
                    Ok(true) => {}
                    Ok(false) => {}
                    Err(error) => {
                        tracing::warn!(%error, "polling MCP stderr failed");
                        drain_ready(&mut stderr, &tail, retain);
                        break;
                    }
                }
            }
            Err(error) => {
                tracing::warn!(%error, "reading MCP stderr failed");
                break;
            }
        }
    }
}

// A descendant may keep writing after cancellation, so draining must also stop.
fn drain_ready(stderr: &mut ChildStderr, tail: &std::sync::Mutex<Vec<u8>>, retain: usize) {
    let mut chunk = [0u8; 256];
    let deadline = Instant::now() + Duration::from_millis(20);
    while Instant::now() < deadline {
        match stderr.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => append_tail(tail, &chunk[..count], retain),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => break,
            Err(error) => {
                tracing::warn!(%error, "draining MCP stderr failed");
                break;
            }
        }
    }
}

fn append_tail(tail: &std::sync::Mutex<Vec<u8>>, chunk: &[u8], retain: usize) {
    let mut bytes = tail.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    bytes.extend_from_slice(chunk);
    if bytes.len() > retain {
        let drop = bytes.len() - retain;
        bytes.drain(..drop);
    }
}

impl StderrTail {
    fn finish(&mut self) -> String {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(reader) = self.reader.take() {
            if let Err(payload) = reader.join() {
                let error = payload
                    .downcast_ref::<&str>()
                    .copied()
                    .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                    .unwrap_or("non-string panic payload");
                tracing::error!(error, "MCP stderr reader panicked");
            }
        }
        let mut bytes = std::mem::take(
            &mut *self
                .bytes
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        if !self.secret.is_empty() {
            redact_bytes(&mut bytes, self.secret.as_bytes());
        }
        let raw_start = bytes.len().saturating_sub(NOTE_BYTES);
        let text = String::from_utf8_lossy(&bytes[raw_start..]);
        let mut start = text.len().saturating_sub(NOTE_BYTES);
        while !text.is_char_boundary(start) {
            start += 1;
        }
        text[start..].trim().to_owned()
    }
}

fn with_stderr(error: BridgeError, note: &str) -> BridgeError {
    let note = note.trim();
    if note.is_empty() {
        return error;
    }
    let attach = |detail: String| format!("{detail}; stderr: {note}");
    match error {
        BridgeError::Spawn(detail) => BridgeError::Spawn(attach(detail)),
        BridgeError::Protocol(detail) => BridgeError::Protocol(attach(detail)),
        BridgeError::Timeout(detail) => BridgeError::Timeout(attach(detail)),
        BridgeError::PdfText(detail) => BridgeError::PdfText(attach(detail)),
        other => other,
    }
}

// Equal-length masking cannot expose an earlier partial URL when the tail is cut.
fn redact_bytes(bytes: &mut [u8], secret: &[u8]) {
    if secret.is_empty() {
        return;
    }
    let mut masked_until = 0;
    for start in 0..bytes.len() {
        if bytes[start..].starts_with(secret) {
            masked_until = start + secret.len();
        }
        if start < masked_until {
            bytes[start] = b'*';
        }
    }
}

/// Stops a session's server from another thread. The session clears it before reaping the
/// server, so a late stop never reaches a reused pid.
#[derive(Clone)]
pub(crate) struct Stopper(Arc<Mutex<Option<Pid>>>);

impl Stopper {
    pub(crate) fn stop(&self) {
        if let Some(pid) = *self.server() {
            let _ = kill_process(pid, Signal::KILL);
        }
    }

    fn clear(&self) {
        self.server().take();
    }

    fn server(&self) -> MutexGuard<'_, Option<Pid>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Reuse unread bytes and compact only when reading again to avoid copying every parsed line.
pub struct McpSession {
    child: Child,
    stopper: Stopper,
    stdin: ChildStdin,
    stdout: ChildStdout,
    stderr: StderrTail,
    pending: Vec<u8>,
    consumed: usize,
    searched: usize,
    /// Buffered output must not let a productive peer extend the session.
    deadline: Instant,
    next_id: u64,
    /// Partial writes or unread responses make a failed exchange unsafe to resume.
    failed: bool,
}

impl McpSession {
    pub fn open(server: &[String], bound: Duration) -> Result<Self, BridgeError> {
        Self::open_redacting(server, bound, "")
    }

    /// Like [`Self::open`], with every `secret` (the document URL) masked out of the server's
    /// stderr tail that failures carry back.
    pub fn open_redacting(
        server: &[String],
        bound: Duration,
        secret: &str,
    ) -> Result<Self, BridgeError> {
        let (program, arguments) = server
            .split_first()
            .ok_or_else(|| BridgeError::Argv("empty MCP server argv".into()))?;
        let mut child = Command::new(program)
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                BridgeError::Spawn(format!("the declared server could not be started: {error}"))
            })?;
        let stderr = child.stderr.take().expect("piped stderr");
        let stderr = match capture_stderr(stderr, secret) {
            Ok(stderr) => stderr,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(BridgeError::Spawn(format!(
                    "the server's stderr could not be captured: {error}"
                )));
            }
        };
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let stopper = Stopper(Arc::new(Mutex::new(Some(Pid::from_child(&child)))));
        let mut session = Self {
            child,
            stopper,
            stdin,
            stdout,
            stderr,
            pending: Vec::new(),
            consumed: 0,
            searched: 0,
            deadline: Instant::now() + bound,
            next_id: 1,
            failed: false,
        };
        if let Err(error) = nonblocking(&session.stdin).and_then(|()| nonblocking(&session.stdout))
        {
            return Err(session.fail(BridgeError::Protocol(format!(
                "the server's pipes could not be owned: {error}"
            ))));
        }
        if let Err(error) = session.request(
            "initialize",
            json!({
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "odin-adapter-mcp", "version": env!("CARGO_PKG_VERSION")},
            }),
        ) {
            return Err(session.fail(error));
        }
        session.failed = true;
        if let Err(error) =
            session.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        {
            return Err(session.fail(error));
        }
        session.failed = false;
        Ok(session)
    }

    // A failed pipe cannot be reused, and its process may have final diagnostics.
    fn fail(&mut self, error: BridgeError) -> BridgeError {
        self.failed = true;
        self.stopper.clear();
        let _ = self.child.kill();
        let _ = self.child.wait();
        let note = self.stderr.finish();
        with_stderr(error, &note)
    }

    fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// Check after writing as well so completion cannot conceal an expired deadline.
    fn send(&mut self, message: &Value) -> Result<(), BridgeError> {
        let untaken = || BridgeError::Timeout("the server did not take the request".into());
        let mut line = serde_json::to_vec(message).expect("JSON serializes");
        line.push(b'\n');
        let mut written = 0;
        while written < line.len() {
            if self.expired() {
                return Err(self.fail(untaken()));
            }
            match self.stdin.write(&line[written..]) {
                Ok(0) => {
                    return Err(self.fail(BridgeError::Protocol(
                        "the server stopped taking input".into(),
                    )))
                }
                Ok(count) => written += count,
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    match ready(&self.stdin, PollFlags::OUT, self.deadline) {
                        Ok(true) => {}
                        Ok(false) => return Err(self.fail(untaken())),
                        Err(error) => {
                            return Err(self.fail(BridgeError::Protocol(format!(
                                "waiting to write to the server failed: {error}"
                            ))))
                        }
                    }
                }
                Err(error) => {
                    return Err(self.fail(BridgeError::Protocol(format!(
                        "the server stopped reading its input: {error}"
                    ))))
                }
            }
        }
        if self.expired() {
            return Err(self.fail(untaken()));
        }
        Ok(())
    }

    /// Compact only when no complete unread line remains.
    fn fill(&mut self, method: &str) -> Result<(), BridgeError> {
        if self.consumed > 0 {
            self.pending.drain(..self.consumed);
            self.searched -= self.consumed;
            self.consumed = 0;
        }
        let mut chunk = [0u8; READ_CHUNK];
        loop {
            if self.expired() {
                return Err(self.fail(BridgeError::Timeout(format!("no answer to {method}"))));
            }
            match self.stdout.read(&mut chunk) {
                Ok(0) => {
                    return Err(self.fail(BridgeError::Protocol(format!(
                        "the server exited before answering {method}"
                    ))))
                }
                Ok(count) => {
                    self.pending.extend_from_slice(&chunk[..count]);
                    return Ok(());
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    match ready(&self.stdout, PollFlags::IN, self.deadline) {
                        Ok(true) => {}
                        Ok(false) => {
                            return Err(
                                self.fail(BridgeError::Timeout(format!("no answer to {method}")))
                            )
                        }
                        Err(error) => {
                            return Err(self.fail(BridgeError::Protocol(format!(
                                "waiting for the answer to {method} failed: {error}"
                            ))))
                        }
                    }
                }
                Err(error) => {
                    return Err(self.fail(BridgeError::Protocol(format!(
                        "reading the answer to {method} failed: {error}"
                    ))))
                }
            }
        }
    }

    /// The returned range stays valid until the next call; its newline counts toward the budget.
    fn line(&mut self, budget: &mut usize, method: &str) -> Result<Range<usize>, BridgeError> {
        loop {
            if self.expired() {
                return Err(self.fail(BridgeError::Timeout(format!("no answer to {method}"))));
            }
            if let Some(offset) = self.pending[self.searched..]
                .iter()
                .position(|byte| *byte == b'\n')
            {
                let start = self.consumed;
                let end = self.searched + offset;
                if end - start > LINE_BYTES {
                    return Err(oversize_line());
                }
                if end - start >= *budget {
                    return Err(over_budget(method));
                }
                *budget -= end - start + 1;
                self.consumed = end + 1;
                self.searched = self.consumed;
                return Ok(start..end);
            }
            self.searched = self.pending.len();
            let unread = self.pending.len() - self.consumed;
            if unread > LINE_BYTES {
                return Err(oversize_line());
            }
            // Reserve room for the newline that will complete this line.
            if unread >= *budget {
                return Err(over_budget(method));
            }
            self.fill(method)?;
        }
    }

    /// Notifications and unrelated requests count toward the answer's byte and time limits.
    fn exchange(&mut self, method: &str, params: Value) -> Result<(Value, usize), BridgeError> {
        if self.failed {
            return Err(BridgeError::Protocol(format!(
                "the session failed before {method}"
            )));
        }
        self.failed = true;
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))?;
        let mut budget = ANSWER_BYTES;
        loop {
            let line = self.line(&mut budget, method)?;
            let length = line.len();
            let Ok(mut message) = serde_json::from_slice::<Value>(&self.pending[line]) else {
                continue;
            };
            if message.get("id").and_then(Value::as_u64) != Some(id)
                || message.get("method").is_some()
            {
                continue;
            }
            if message.get("error").is_some() {
                return Err(BridgeError::Protocol(format!(
                    "{method} answered with an error"
                )));
            }
            let result = match message.get_mut("result") {
                Some(result) => result.take(),
                None => return Err(BridgeError::Protocol(format!("{method} had no result"))),
            };
            if self.expired() {
                return Err(self.fail(BridgeError::Timeout(format!("no answer to {method}"))));
            }
            self.failed = false;
            return Ok((result, length));
        }
    }

    pub fn request(&mut self, method: &str, params: Value) -> Result<Value, BridgeError> {
        self.exchange(method, params).map(|(result, _)| result)
    }

    /// Reject repeated cursors and excessive listings to prevent unending pagination.
    pub fn tools(&mut self) -> Result<Vec<Value>, BridgeError> {
        let mut tools = Vec::new();
        let mut seen = BTreeSet::new();
        let mut listed = 0usize;
        let mut cursor: Option<String> = None;
        for _ in 0..LIST_PAGES {
            let params = match &cursor {
                Some(cursor) => json!({"cursor": cursor}),
                None => json!({}),
            };
            let (mut page, bytes) = self.exchange("tools/list", params)?;
            listed += bytes;
            if listed > LIST_BYTES {
                return Err(BridgeError::Protocol(
                    "the tool listing exceeds its byte bound".into(),
                ));
            }
            if let Some(Value::Array(listed_tools)) = page.get_mut("tools").map(Value::take) {
                if tools.len() + listed_tools.len() > LIST_TOOLS {
                    return Err(BridgeError::Protocol(
                        "the tool listing exceeds its tool bound".into(),
                    ));
                }
                tools.extend(listed_tools);
            }
            match page.get("nextCursor").and_then(Value::as_str) {
                Some(next) if !next.is_empty() => {
                    if !seen.insert(next.to_owned()) {
                        return Err(BridgeError::Protocol(
                            "the tool listing repeated a cursor".into(),
                        ));
                    }
                    cursor = Some(next.to_owned());
                }
                _ => return Ok(tools),
            }
        }
        Err(BridgeError::Protocol(
            "the tool listing exceeds its page bound".into(),
        ))
    }
}

fn oversize_line() -> BridgeError {
    BridgeError::Protocol("a line from the server exceeds the line bound".into())
}

fn over_budget(method: &str) -> BridgeError {
    BridgeError::Protocol(format!(
        "the server sent more than one answer to {method} may hold"
    ))
}

fn nonblocking(pipe: &impl AsFd) -> std::io::Result<()> {
    let flags = fcntl_getfl(pipe)?;
    fcntl_setfl(pipe, flags | OFlags::NONBLOCK)?;
    Ok(())
}

/// Treat hangups and errors as ready so the next read or write can report the cause.
fn ready(pipe: &impl AsFd, events: PollFlags, deadline: Instant) -> std::io::Result<bool> {
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok(false);
        }
        let timeout = Timespec {
            tv_sec: left.as_secs().try_into().unwrap_or(i64::MAX),
            tv_nsec: left.subsec_nanos() as _,
        };
        let mut polled = [PollFd::new(pipe, events)];
        match poll(&mut polled, Some(&timeout)) {
            Ok(0) => {}
            Ok(_) => return Ok(true),
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) => return Err(error.into()),
        }
    }
}

/// One bounded diagnostic line on this process's stderr.
pub fn note(line: &str) {
    let _ = writeln!(
        std::io::stderr().lock(),
        "odin-adapter-mcp: {}",
        bounded(line, NOTE_BYTES)
    );
}

/// Preserve UTF-8 boundaries when truncating diagnostic text.
pub fn bounded(text: &str, bytes: usize) -> &str {
    if text.len() <= bytes {
        return text;
    }
    let mut end = bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

impl McpSession {
    /// `surface` re-checks the listing a sequence takes before its first step. A single tool
    /// call uses the listing `operate` already checked and does not list again. A page read
    /// races the plain reader against the browser: the first good page wins.
    pub fn call_plan(
        &mut self,
        plan: &[String],
        input: &Value,
        rules: Rules<'_>,
        surface: Option<&BridgeConfig>,
    ) -> Result<Value, BridgeError> {
        let sequence = plan.len() > 1;
        if !sequence {
            let step = plan
                .first()
                .ok_or_else(|| BridgeError::Argv("an empty plan".into()))?;
            let result = self.request("tools/call", json!({"name": step, "arguments": input}))?;
            return call_result(result);
        }
        let listed = self.tools()?;
        if let Some(config) = surface {
            config.check_surface(&listed)?;
        }
        let url = input.get("url").and_then(Value::as_str);
        let mut plain = rules.load_check.zip(url).map(|(_, url)| {
            http_read::PlainRead::start(
                url,
                self.deadline,
                rules.article_text,
                rules
                    .window
                    .and_then(|field| read::first_window(input, field)),
                self.stopper.clone(),
            )
        });
        match self.browse(&listed, plan, input, rules, &mut plain) {
            Ok(read) => Ok(read),
            // A browser the plain reader stopped ends here too, as a failed exchange.
            Err(error) => match plain.and_then(|plain| plain.winner(self.deadline)) {
                Some(page) => served(
                    rules,
                    input,
                    &read::with_alternate_note(page).text,
                    true,
                    false,
                    json!({ "content": [] }),
                ),
                None => Err(error),
            },
        }
    }

    /// The sequence's steps through the browser; a stopped page falls back to `plain`'s page.
    fn browse(
        &mut self,
        listed: &[Value],
        plan: &[String],
        input: &Value,
        rules: Rules<'_>,
        plain: &mut Option<http_read::PlainRead>,
    ) -> Result<Value, BridgeError> {
        let mut last = json!({ "content": [] });
        let mut document = None;
        let mut stopped: Option<read::StoppedRead> = None;
        for (index, step) in plan.iter().enumerate() {
            let outcome = self.tool_call(listed, step, input, rules, index + 1 == plan.len())?;
            last = match (index, rules.load_check) {
                (0, Some(check)) => {
                    let navigated = outcome.map_err(|error| match error {
                        BridgeError::Tool(said) => BridgeError::PageLoad(said),
                        BridgeError::Refused(said) => BridgeError::PageLoad(said).refused(),
                        other => other,
                    })?;
                    let log = self.tool_call(listed, check, input, rules, false)??;
                    // The body is not read yet, so a 200 challenge is caught
                    // again after the read tool returns its text.
                    match read::document_verdict(&text_of(&log), "") {
                        read::DocumentVerdict::Loaded(url) => document = Some(url),
                        read::DocumentVerdict::Stopped(stop) => stopped = Some(stop),
                        read::DocumentVerdict::Failed(detail) => {
                            return Err(BridgeError::PageLoad(detail));
                        }
                    }
                    navigated
                }
                _ => outcome?,
            };
            if stopped.is_some() {
                break;
            }
        }
        let mut text = text_of(&last);
        if stopped.is_none() {
            if let Some(url) = document.clone() {
                if let read::DocumentVerdict::Stopped(stop) =
                    read::document_verdict(&format!("[200] GET {url}"), &text)
                {
                    stopped = Some(stop);
                }
            }
        }
        if let Some(stop) = stopped {
            return self.fallback_read(listed, plan, input, rules, stop, plain.take());
        }
        let converter = rules
            .pdf_text
            .filter(|_| text.trim_start().starts_with("%PDF-"));
        if let Some(converter) = converter {
            let url = document
                .clone()
                .or_else(|| input.get("url").and_then(Value::as_str).map(str::to_owned))
                .ok_or_else(|| BridgeError::PdfText("the read names no URL".into()))?;
            text = read::pdf_text(converter, &url, self.deadline)?;
        }
        if document.is_some() && text.trim().is_empty() {
            return Err(BridgeError::PageLoad(
                "the page has no readable text".into(),
            ));
        }
        served(
            rules,
            input,
            &text,
            document.is_some(),
            converter.is_some(),
            last,
        )
    }

    /// Take the independent public-only HTTP reader's page while this MCP
    /// session stays open, then navigate Obscura to Wayback in the same session.
    fn fallback_read(
        &mut self,
        listed: &[Value],
        plan: &[String],
        input: &Value,
        rules: Rules<'_>,
        stop: read::StoppedRead,
        plain: Option<http_read::PlainRead>,
    ) -> Result<Value, BridgeError> {
        let original = input
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| BridgeError::PageLoad(read::no_archive(&stop)))?
            .to_owned();
        let (Some(engine), Some(read_with), Some(check)) =
            (plan.first(), plan.last(), rules.load_check)
        else {
            return Err(BridgeError::PageLoad(read::no_archive(&stop)));
        };
        let deadline = self.deadline;
        let read = read::public_fallback(
            &original,
            &stop,
            || {
                plain.and_then(|plain| plain.page(deadline)).or_else(|| {
                    rules.fingerprint_fetch.and_then(|fetch| {
                        http_read::fingerprinted(fetch, &original, deadline, rules.article_text)
                    })
                })
            },
            |archive_url| {
                let mut archived = input.clone();
                archived["url"] = json!(archive_url);
                self.engine_read(listed, engine, read_with, check, &archived, rules)
            },
        )?;
        // A fallback that fetched a PDF holds its raw bytes: the declared converter reads its text.
        let (note, body) = read.text.split_once("\n\n").unwrap_or(("", &read.text));
        let converter = rules
            .pdf_text
            .filter(|_| body.trim_start().starts_with("%PDF-"));
        let text = match converter {
            Some(converter) => format!(
                "{note}\n\n{}",
                read::pdf_text(converter, &read.url, self.deadline)?
            ),
            None => read.text.clone(),
        };
        served(
            rules,
            input,
            &text,
            true,
            converter.is_some(),
            json!({ "content": [] }),
        )
    }

    /// Navigate with one engine and read that page back. `None` is a failed
    /// attempt, including a challenge page the archive itself served: a
    /// fallback that returns the block is not a read.
    fn engine_read(
        &mut self,
        listed: &[Value],
        engine: &str,
        read_with: &str,
        check: &str,
        input: &Value,
        rules: Rules<'_>,
    ) -> Option<read::PageRead> {
        self.tool_call(listed, engine, input, rules, false)
            .ok()?
            .ok()?;
        let log = text_of(
            &self
                .tool_call(listed, check, input, rules, false)
                .ok()?
                .ok()?,
        );
        let text = text_of(
            &self
                .tool_call(listed, read_with, input, rules, true)
                .ok()?
                .ok()?,
        );
        match read::document_verdict(&log, &text) {
            read::DocumentVerdict::Loaded(url) if !text.trim().is_empty() => {
                Some(read::PageRead { url, text })
            }
            _ => None,
        }
    }

    /// One listed tool, with only the fields that tool declares. A page read asks
    /// for the text through the caller's window; the window is cut here, not upstream.
    fn tool_call(
        &mut self,
        listed: &[Value],
        step: &str,
        input: &Value,
        rules: Rules<'_>,
        page: bool,
    ) -> Result<Result<Value, BridgeError>, BridgeError> {
        let tool = listed
            .iter()
            .find(|tool| tool.get("name").and_then(Value::as_str) == Some(step));
        let mut arguments = step_arguments(input, tool);
        if let Some(field) = rules.window.filter(|_| page) {
            arguments[field] = json!(read::asked_chars(input, field));
        }
        let result = self.request("tools/call", json!({"name": step, "arguments": arguments}))?;
        Ok(call_result(result))
    }
}

fn served(
    rules: Rules<'_>,
    input: &Value,
    text: &str,
    checked: bool,
    converted: bool,
    last: Value,
) -> Result<Value, BridgeError> {
    match rules.window {
        Some(field) => read::window(text, input, field),
        None if converted || checked => Ok(json!({"content": [{"type": "text", "text": text}]})),
        None => Ok(last),
    }
}

pub(crate) fn text_of(result: &Value) -> String {
    result
        .get("content")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|block| block.get("text").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The worker stops descendants; this session stops only the server it spawned.
impl Drop for McpSession {
    fn drop(&mut self) {
        self.stopper.clear();
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = self.stderr.finish();
    }
}

/// Markers in a web reader's error, the cause a failure names, and whether the marker means the
/// site refused or never answered (another network exit may be let in). That text can hold the
/// URL, so it never leaves the bridge.
const TOOL_ERROR_CAUSES: [(&str, &str, bool); 10] = [
    ("dns error", "the site's name did not resolve", false),
    (
        "private/internal",
        "its address is private, and private networks are blocked",
        false,
    ),
    ("code: ssl", "the site's TLS connection failed", false),
    (
        "certificate",
        "the site's TLS certificate was rejected",
        false,
    ),
    ("(timedout)", "the site did not answer in time", true),
    ("timed out", "the site did not answer in time", true),
    ("(connect)", "the site refused the connection", true),
    (
        "cdn-cgi/challenge-platform",
        "the site blocked this reader with its bot check (Cloudflare)",
        true,
    ),
    (
        "unsupported content encoding",
        "the site used an unsupported content encoding",
        false,
    ),
    ("network error", "the upstream network request failed", true),
];

/// Upstream tool errors are failures that name their cause.
pub fn call_result(mut result: Value) -> Result<Value, BridgeError> {
    if result.get("isError").and_then(Value::as_bool) == Some(true) {
        let (cause, refused) = tool_cause(&text_of(&result));
        return Err(if refused {
            BridgeError::Refused(cause)
        } else {
            BridgeError::Tool(cause)
        });
    }
    let content = result
        .get_mut("content")
        .map(Value::take)
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let mut out = serde_json::Map::new();
    out.insert("content".to_owned(), content);
    if let Some(structured) = result.get_mut("structuredContent") {
        out.insert("structuredContent".to_owned(), structured.take());
    }
    Ok(Value::Object(out))
}

/// A known web failure names its cause without the URL; any other error is the tool's own
/// words: its JSON `error` field, else its first line, bounded. The flag says a refusal.
fn tool_cause(text: &str) -> (String, bool) {
    let said = text.to_ascii_lowercase();
    if let Some(status) = http_status(&said) {
        return (format!("the document answered HTTP {status}"), false);
    }
    if let Some((_, cause, refused)) = TOOL_ERROR_CAUSES
        .iter()
        .find(|(marker, ..)| said.contains(marker))
    {
        return ((*cause).to_owned(), *refused);
    }
    let field = serde_json::from_str::<Value>(text).ok().and_then(|value| {
        value
            .get("error")
            .and_then(Value::as_str)
            .map(str::to_owned)
    });
    let own = field.as_deref().unwrap_or(text).trim();
    let own = own.lines().next().unwrap_or_default();
    if own.is_empty() {
        return ("the tool reported an error with no text".to_owned(), false);
    }
    (
        format!("the tool said: {}", bounded(own, CAUSE_BYTES)),
        false,
    )
}

/// The first `HTTP 403`-shaped status in upstream text, if it names one.
fn http_status(said: &str) -> Option<u16> {
    let rest = said.split("http ").nth(1)?;
    let status = rest
        .split(|ch: char| !ch.is_ascii_digit())
        .next()?
        .parse()
        .ok()?;
    (100..600).contains(&status).then_some(status)
}

#[cfg(test)]
mod tests;
