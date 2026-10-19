//! Sequence steps share an MCP session so stateful servers retain their state between calls.

use std::collections::BTreeSet;
use std::io::{ErrorKind, Read, Write};
use std::ops::Range;
use std::os::fd::AsFd;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};
use serde_json::{json, Value};

mod read;

pub const MCP_PROTOCOL_VERSION: &str = "2025-06-18";

/// Allow the whole-page response used for windowed reads, including JSON escaping.
const LINE_BYTES: usize = 16 << 20;

const ANSWER_BYTES: usize = 32 << 20;

const LIST_PAGES: usize = 64;
const LIST_TOOLS: usize = 1024;
const LIST_BYTES: usize = 8 << 20;

const READ_CHUNK: usize = 64 << 10;

/// Keep diagnostics below a pipe buffer because the host does not drain stderr during calls.
const NOTE_BYTES: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeConfig {
    pub adapter: String,
    pub kind_prefix: String,
    pub read_only: Vec<String>,
    pub sequences: Vec<Sequence>,
    pub expose: Vec<String>,
    pub load_check: Option<String>,
    pub window: Option<String>,
    pub pdf_text: Option<String>,
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

/// Only redacted stderr tails may contain upstream failure text; tool and page errors stay local.
#[derive(Debug, Eq, PartialEq)]
pub enum BridgeError {
    Argv(String),
    Spawn(String),
    Timeout(String),
    Protocol(String),
    Tool(String),
    PageLoad(String),
    PdfText(String),
    OffsetPastEnd { offset: usize, total: usize },
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Argv(detail) => write!(formatter, "bridge argv rejected: {detail}"),
            Self::Spawn(detail) => write!(formatter, "{detail}"),
            Self::Timeout(detail) => write!(formatter, "MCP server timed out: {detail}"),
            Self::Protocol(detail) => write!(formatter, "MCP server answered badly: {detail}"),
            Self::Tool(detail) => write!(formatter, "{detail}"),
            Self::PageLoad(detail) => write!(formatter, "the page did not load: {detail}"),
            Self::PdfText(detail) => write!(formatter, "the PDF did not read as text: {detail}"),
            Self::OffsetPastEnd { offset, total } => write!(
                formatter,
                "offset {offset} is past the end of the page ({total} characters)"
            ),
        }
    }
}

impl BridgeConfig {
    /// `--adapter <id> --kind-prefix <prefix> [--read-only <tool>]...
    /// [--sequence <name>=<tool>,...]... [--expose <tool>]... [--load-check <tool>]
    /// [--window <field>] [--pdf-text <executable>] -- <server argv>`.
    pub fn parse(arguments: &[String]) -> Result<Self, BridgeError> {
        let split = arguments
            .iter()
            .position(|argument| argument == "--")
            .ok_or_else(|| BridgeError::Argv("missing `--` before the MCP server argv".into()))?;
        let (own, server) = (&arguments[..split], &arguments[split + 1..]);
        if server.is_empty() {
            return Err(BridgeError::Argv("empty MCP server argv".into()));
        }
        let (mut adapter, mut kind_prefix, mut read_only) = (None, None, Vec::new());
        let (mut sequences, mut expose, mut load_check) = (Vec::new(), Vec::new(), None);
        let (mut window, mut pdf_text) = (None, None);
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
                "--sequence" => sequences.push(Sequence::parse(&value)?),
                "--expose" => expose.push(value),
                "--load-check" => load_check = Some(value),
                "--window" => window = Some(value),
                "--pdf-text" => pdf_text = Some(value),
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
        Ok(Self {
            adapter: adapter.ok_or_else(|| BridgeError::Argv("--adapter is required".into()))?,
            kind_prefix,
            read_only,
            sequences,
            expose,
            load_check,
            window,
            pdf_text,
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
        ] {
            if let Some(value) = value {
                wire[field] = json!(value);
            }
        }
        let canonical =
            odin_strict_json::canonicalize(&wire).expect("string-only JSON canonicalizes");
        odin_adapter_core::Digest::hash(&canonical).to_string()
    }

    pub fn descriptor(&self, tools: &[Value]) -> Result<Value, BridgeError> {
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
            operations.push(operation(&kind, self.read_only(tool)));
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

fn operation(kind: &str, read_only: bool) -> Value {
    json!({
        "kind": kind,
        "input_schema": format!("schemas/capability/{kind}.input.json"),
        "output_schema": format!("schemas/capability/{kind}.output.json"),
        "effect_class": if read_only { "R0" } else { "R3" },
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

#[derive(Clone, Copy, Debug, Default)]
pub struct Rules<'a> {
    pub load_check: Option<&'a str>,
    pub window: Option<&'a str>,
    pub pdf_text: Option<&'a str>,
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

/// Reuse unread bytes and compact only when reading again to avoid copying every parsed line.
pub struct McpSession {
    child: Child,
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
        let stderr = match capture_stderr(stderr, "") {
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
        let mut session = Self {
            child,
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

fn note(line: &str) {
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
    /// Stop at the first failed step so later steps cannot consume an invalid page.
    pub fn call_plan(
        &mut self,
        plan: &[String],
        input: &Value,
        rules: Rules<'_>,
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
        let mut call =
            |step: &str, page: bool| -> Result<Result<Value, BridgeError>, BridgeError> {
                let tool = listed
                    .iter()
                    .find(|tool| tool.get("name").and_then(Value::as_str) == Some(step));
                let mut arguments = step_arguments(input, tool);
                if let Some(field) = rules.window.filter(|_| page) {
                    arguments[field] = json!(read::PAGE_CHARS);
                }
                let result =
                    self.request("tools/call", json!({"name": step, "arguments": arguments}))?;
                Ok(call_result(result))
            };
        let mut last = json!({ "content": [] });
        let mut document = None;
        for (index, step) in plan.iter().enumerate() {
            let outcome = call(step, index + 1 == plan.len())?;
            last = match (index, rules.load_check) {
                (0, Some(check)) => {
                    let navigated = outcome.map_err(|_| {
                        BridgeError::PageLoad("the navigation reported an error".into())
                    })?;
                    let log = call(check, false)??;
                    document = Some(loaded_document(&text_of(&log))?);
                    navigated
                }
                _ => outcome?,
            };
        }
        let mut text = text_of(&last);
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
        match rules.window {
            Some(field) => read::window(&text, input, field),
            None if converter.is_some() => Ok(json!({"content": [{"type": "text", "text": text}]})),
            None => Ok(last),
        }
    }
}

fn text_of(result: &Value) -> String {
    result
        .get("content")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|block| block.get("text").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The first request-log entry is the document; errors include its status but not its URL.
pub fn loaded_document(log: &str) -> Result<String, BridgeError> {
    let entry = log.lines().find_map(|line| {
        let (status, rest) = line.strip_prefix('[')?.split_once("] ")?;
        let url = rest.split_whitespace().nth(1)?;
        Some((status.parse::<u16>().ok()?, url.to_owned()))
    });
    match entry {
        None => Err(BridgeError::PageLoad("no document was fetched".to_owned())),
        Some((status, _)) if !(200..400).contains(&status) => Err(BridgeError::PageLoad(format!(
            "the document answered HTTP {status}"
        ))),
        Some((_, url)) => Ok(url),
    }
}

/// The worker stops descendants; this session stops only the server it spawned.
impl Drop for McpSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = self.stderr.finish();
    }
}

/// Upstream tool errors are failures, and their text must not enter adapter error messages.
pub fn call_result(mut result: Value) -> Result<Value, BridgeError> {
    if result.get("isError").and_then(Value::as_bool) == Some(true) {
        return Err(BridgeError::Tool("the tool reported an error".to_owned()));
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

#[cfg(test)]
mod tests;
