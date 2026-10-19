//! Protocol v1/v2 JSONL frame decoding for the OMP RPC bridge.
//!
//! The transport is newline-delimited JSON: one physical frame per line, at most
//! [`MAX_FRAME_BYTES`] bytes including the terminating newline.
//! [`RpcFrameDecoder::push_physical_line`] takes the exact stdout bytes of one
//! physical line — one required trailing `\n`, no newline before it, and the
//! physical ceiling enforced over those exact bytes before any decoding — so a
//! process reader passes raw bytes without lossy text conversion. Protocol v2
//! carries logical frames that exceed the physical ceiling as ordered `rpc_chunk`
//! trains — at most [`CHUNK_PAYLOAD_BYTES`] decoded payload per physical line —
//! that reassemble to at most [`MAX_REASSEMBLED_BYTES`] bytes of logical JSON.
//! Chunk handling mirrors the pinned OMP `RpcFrameDecoder` (omp @ eab72e8,
//! `src/modes/rpc/rpc-frame.ts`), including validation order.
//!
//! Decoding never discards evidence. A successful decode yields a
//! [`DecodedRpcFrame`] with the parsed value, the exact logical UTF-8 bytes
//! (transport newlines excluded), and every physical line — exact bytes including
//! newlines — that produced it; unknown future frame `type` values are successful
//! frames like any other object. Any violation yields an [`RpcFrameError`]
//! retaining the exact physical bytes received for the failing frame — except
//! an over-ceiling line, which retains only its in-ceiling prefix so the copy
//! stays bounded no matter the input size. The interrupted sequence state is
//! dropped so the decoder stays usable only for a fresh stream.

use std::fmt;
use std::str;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use serde_json::Value;

/// Maximum byte size of one physical newline-delimited RPC frame, including the newline.
pub const MAX_FRAME_BYTES: usize = 1_048_576;
/// Maximum byte size of one logical frame reassembled by protocol v2.
pub const MAX_REASSEMBLED_BYTES: usize = 67_108_864;
/// Maximum decoded payload carried by a single `rpc_chunk` physical line.
pub const CHUNK_PAYLOAD_BYTES: usize = 262_144;
pub const MAX_CHUNK_COUNT: usize = MAX_REASSEMBLED_BYTES.div_ceil(CHUNK_PAYLOAD_BYTES);

const CHUNK_TYPE: &str = "rpc_chunk";
/// Pinned bound on the `chunkId` string length, measured in UTF-16 code
/// units exactly like the JavaScript `length` the pinned decoder checks.
const MAX_CHUNK_ID_CHARS: usize = 128;

/// RPC wire protocol generation, negotiated through `negotiate_protocol`.
///
/// v1 never sees chunk frames; a chunk arriving under v1 is a protocol
/// violation, exactly as in the pinned client, which enables v2 only after a
/// successful negotiation round-trip.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum RpcProtocolVersion {
    /// Chunkless baseline protocol.
    #[default]
    V1,
    /// Chunked protocol for logical frames beyond [`MAX_FRAME_BYTES`].
    V2,
}

impl RpcProtocolVersion {
    pub fn number(self) -> u64 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
        }
    }
}

/// One fully decoded logical frame with its complete physical evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedRpcFrame {
    value: Arc<Value>,
    /// `None` when the logical bytes are the first physical line without its
    /// terminating newline. A reassembled chunk train stores the concatenated
    /// payload here; it is not a reserialization.
    raw: Option<Arc<[u8]>>,
    lines: Arc<[Vec<u8>]>,
}

impl DecodedRpcFrame {
    /// A frame Odin itself composed from a non-OMP harness's output: the
    /// canonical session-event vocabulary, serialized once as its evidence.
    pub(crate) fn synthesized(value: Value) -> Self {
        let mut line = serde_json::to_vec(&value).unwrap_or_default();
        line.push(b'\n');
        Self::single(value, line)
    }

    /// One physical line, including its terminating newline. Logical bytes are
    /// that line without the newline — no second copy.
    fn single(value: Value, line: Vec<u8>) -> Self {
        debug_assert_eq!(line.last().copied(), Some(b'\n'));
        Self {
            value: Arc::new(value),
            raw: None,
            lines: Arc::from(vec![line]),
        }
    }

    fn reassembled(value: Value, raw: Vec<u8>, lines: Vec<Vec<u8>>) -> Self {
        Self {
            value: Arc::new(value),
            raw: Some(Arc::from(raw)),
            lines: Arc::from(lines),
        }
    }

    /// The parsed logical frame. Object-only: decoding rejects anything else.
    pub fn value(&self) -> &Value {
        self.value.as_ref()
    }

    /// The exact logical UTF-8 JSON bytes. For a single-line frame these are the
    /// received line bytes without the transport newline; for a reassembled frame
    /// the concatenated chunk payloads — never a reserialization.
    pub fn raw(&self) -> &[u8] {
        match &self.raw {
            Some(raw) => raw.as_ref(),
            None => {
                let line = &self.lines[0];
                &line[..line.len() - 1]
            }
        }
    }

    /// Every physical line that produced this frame, exact bytes including the
    /// terminating newline, in arrival order.
    pub fn lines(&self) -> &[Vec<u8>] {
        self.lines.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RpcFrameErrorKind {
    /// The input does not end with exactly one terminating newline.
    MissingNewline,
    /// A newline occurs inside the physical line, before its terminator.
    EmbeddedNewline,
    /// The exact physical line bytes including the newline exceed
    /// [`MAX_FRAME_BYTES`].
    FrameTooLarge {
        /// Physical size including the newline.
        size: usize,
    },
    /// The physical line content before the newline is not valid UTF-8.
    InvalidLineUtf8,
    /// A `rpc_chunk` arrived while protocol v1 is negotiated.
    ChunkBeforeNegotiation,
    /// The physical line is not valid JSON.
    MalformedLine { detail: String },
    /// The logical frame is valid JSON but not an object.
    NotAnObject,
    /// Chunk metadata is missing, mistyped, or outside the pinned ranges.
    InvalidChunkMetadata,
    /// Chunk `data` is not non-empty canonical standard base64.
    InvalidChunkData,
    /// The decoded chunk payload exceeds [`CHUNK_PAYLOAD_BYTES`].
    ChunkPayloadTooLarge {
        /// Decoded payload size in bytes.
        size: usize,
    },
    /// The first chunk of a sequence carried a nonzero index.
    ChunkSequenceStart {
        /// The rejected starting index.
        index: u64,
    },
    /// Chunk id, count, declared length, or index disagrees with the active sequence.
    ChunkSequenceMismatch,
    /// Accumulated bytes exceed the declared logical length.
    ChunkSequenceOverflow {
        /// Bytes received so far.
        received: u64,
        /// Declared logical length.
        declared: u64,
    },
    /// The final chunk arrived but the total does not equal the declared length.
    ChunkSequenceLengthMismatch {
        /// Bytes received in total.
        received: u64,
        /// Declared logical length.
        declared: u64,
    },
    /// A non-chunk frame arrived while a chunk sequence was active.
    ChunkSequenceInterrupted,
    /// The reassembled logical bytes are not valid UTF-8.
    InvalidFrameUtf8,
    /// The reassembled logical bytes are valid UTF-8 but not valid JSON.
    MalformedFrame { detail: String },
    /// The stream ended with a chunk sequence still active.
    UnfinishedChunkSequence {
        chunk_id: String,
        /// Next expected chunk index.
        next_index: u64,
        count: u64,
        /// Bytes received so far.
        received: u64,
        /// Declared logical length.
        declared: u64,
    },
}

impl fmt::Display for RpcFrameErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingNewline => write!(f, "physical rpc line is missing its terminating newline"),
            Self::EmbeddedNewline => write!(f, "physical rpc line contains an embedded newline"),
            Self::FrameTooLarge { size } => write!(
                f,
                "physical rpc frame of {size} bytes exceeds the {MAX_FRAME_BYTES}-byte transport limit including the newline"
            ),
            Self::InvalidLineUtf8 => write!(f, "physical rpc line is not valid utf-8"),
            Self::ChunkBeforeNegotiation => write!(f, "rpc chunk received before protocol negotiation"),
            Self::MalformedLine { detail } => write!(f, "physical rpc line is not valid json: {detail}"),
            Self::NotAnObject => write!(f, "rpc frame must be an object"),
            Self::InvalidChunkMetadata => write!(f, "invalid rpc chunk metadata"),
            Self::InvalidChunkData => write!(f, "invalid rpc chunk data"),
            Self::ChunkPayloadTooLarge { size } => write!(
                f,
                "rpc chunk payload of {size} bytes exceeds the {CHUNK_PAYLOAD_BYTES}-byte transport limit"
            ),
            Self::ChunkSequenceStart { index } => write!(f, "rpc chunk sequence must start at index 0, got {index}"),
            Self::ChunkSequenceMismatch => write!(f, "rpc chunk sequence mismatch"),
            Self::ChunkSequenceOverflow { received, declared } => {
                write!(f, "rpc chunk sequence exceeds declared length: {received} > {declared}")
            }
            Self::ChunkSequenceLengthMismatch { received, declared } => {
                write!(f, "rpc chunk sequence length mismatch: {received} != {declared}")
            }
            Self::ChunkSequenceInterrupted => write!(f, "rpc chunk sequence interrupted"),
            Self::InvalidFrameUtf8 => write!(f, "reassembled rpc frame is not valid utf-8"),
            Self::MalformedFrame { detail } => write!(f, "reassembled rpc frame is not valid json: {detail}"),
            Self::UnfinishedChunkSequence {
                chunk_id,
                next_index,
                count,
                received,
                declared,
            } => write!(
                f,
                "rpc chunk sequence {chunk_id} unfinished at end of stream: chunk {next_index}/{count}, {received}/{declared} bytes"
            ),
        }
    }
}

/// A rejected frame together with the physical inputs received for it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpcFrameError {
    kind: RpcFrameErrorKind,
    evidence: Vec<Vec<u8>>,
}

impl RpcFrameError {
    fn new(kind: RpcFrameErrorKind, evidence: Vec<Vec<u8>>) -> Self {
        Self { kind, evidence }
    }
    /// Builds the bounded evidence carried by an oversized physical line read
    /// at the process boundary. `prefix` is the exact in-ceiling prefix; the
    /// reader counts but never retains bytes beyond that bound.
    pub(crate) fn oversized(size: usize, prefix: Vec<u8>) -> Self {
        debug_assert!(size > MAX_FRAME_BYTES);
        debug_assert!(prefix.len() <= MAX_FRAME_BYTES);
        Self::new(RpcFrameErrorKind::FrameTooLarge { size }, vec![prefix])
    }

    pub fn kind(&self) -> &RpcFrameErrorKind {
        &self.kind
    }

    /// Every physical line received for the failing frame, exact bytes including
    /// the terminating newline, in arrival order. An over-ceiling line retains
    /// only its in-ceiling prefix so the copy stays bounded.
    pub fn evidence(&self) -> &[Vec<u8>] {
        &self.evidence
    }
}

impl fmt::Display for RpcFrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}; {} physical line(s) retained",
            self.kind,
            self.evidence.len()
        )
    }
}

impl std::error::Error for RpcFrameError {}

/// In-progress protocol v2 chunk sequence.
#[derive(Clone, Debug)]
struct PendingSequence {
    chunk_id: String,
    count: u64,
    byte_length: u64,
    next_index: u64,
    received: u64,
    bytes: Vec<u8>,
    lines: Vec<Vec<u8>>,
}

impl PendingSequence {
    fn new(chunk_id: String, count: u64, byte_length: u64) -> Self {
        Self {
            chunk_id,
            count,
            byte_length,
            next_index: 0,
            received: 0,
            bytes: Vec::new(),
            lines: Vec::new(),
        }
    }
}

/// Stateful decoder for one OMP RPC output stream.
///
/// Created under protocol v1 and upgraded through [`RpcFrameDecoder::set_protocol`]
/// once `negotiate_protocol` succeeds. Fed one physical JSONL line — exact bytes
/// including its terminating newline — at a time.
#[derive(Clone, Debug, Default)]
pub struct RpcFrameDecoder {
    protocol: RpcProtocolVersion,
    pending: Option<PendingSequence>,
}

impl RpcFrameDecoder {
    /// A decoder for `protocol`; the stream is expected to start in v1.
    pub fn new(protocol: RpcProtocolVersion) -> Self {
        Self {
            protocol,
            pending: None,
        }
    }

    pub fn protocol(&self) -> RpcProtocolVersion {
        self.protocol
    }

    /// Applies the negotiated protocol version. Chunks are only accepted under v2.
    pub fn set_protocol(&mut self, protocol: RpcProtocolVersion) {
        self.protocol = protocol;
    }

    /// Feeds one physical JSONL line: the exact stdout bytes including its single
    /// terminating newline.
    ///
    /// The line must end in exactly one `\n`; no further newline may occur
    /// before it and a missing terminator is a typed error, so callers pass raw
    /// process output without text reinterpretation. The physical ceiling is
    /// enforced over those exact bytes before any other check — an over-ceiling
    /// line is rejected with only its in-ceiling prefix retained, so no
    /// rejection path can allocate proportionally to oversized input — then
    /// UTF-8 and JSON parsing, and invalid UTF-8 content is a typed error
    /// retaining the bytes.
    ///
    /// Returns `Ok(Some(_))` when the line completed a logical frame, `Ok(None)`
    /// when the line extended an active v2 chunk sequence or was blank, and an
    /// [`RpcFrameError`] retaining the exact physical bytes of every line
    /// received for the failing frame. A violation inside an active sequence
    /// drops that broken sequence state.
    pub fn push_physical_line(
        &mut self,
        line: &[u8],
    ) -> Result<Option<DecodedRpcFrame>, RpcFrameError> {
        // The byte ceiling gates first: every other rejection copies the
        // line into evidence, so oversized input must never reach them.
        if line.len() > MAX_FRAME_BYTES {
            return Err(self.rejected_oversized_line(line));
        }
        self.finish_line(classify_physical_line(line), line.to_vec())
    }

    /// Same classification as [`Self::push_physical_line`], taking ownership
    /// of a line the reader already accumulated. A completed single-line frame
    /// keeps that buffer; logical bytes are a slice of it.
    pub(crate) fn push_owned_line(
        &mut self,
        line: Vec<u8>,
    ) -> Result<Option<DecodedRpcFrame>, RpcFrameError> {
        if line.len() > MAX_FRAME_BYTES {
            return Err(self.rejected_oversized_owned(line));
        }
        let decision = classify_physical_line(&line);
        self.finish_line(decision, line)
    }

    fn finish_line(
        &mut self,
        decision: LineDecision,
        line: Vec<u8>,
    ) -> Result<Option<DecodedRpcFrame>, RpcFrameError> {
        match decision {
            LineDecision::Blank => Ok(None),
            LineDecision::Reject(kind) => Err(self.rejected_owned(kind, line)),
            LineDecision::Parsed(frame) => {
                if !is_chunk_frame(&frame) {
                    if self.pending.is_some() {
                        return Err(
                            self.rejected_owned(RpcFrameErrorKind::ChunkSequenceInterrupted, line)
                        );
                    }
                    if !frame.is_object() {
                        return Err(self.rejected_owned(RpcFrameErrorKind::NotAnObject, line));
                    }
                    return Ok(Some(DecodedRpcFrame::single(frame, line)));
                }
                if self.protocol == RpcProtocolVersion::V1 {
                    return Err(
                        self.rejected_owned(RpcFrameErrorKind::ChunkBeforeNegotiation, line)
                    );
                }
                self.accept_chunk(&frame, line)
            }
        }
    }

    /// Ends the stream. An active chunk sequence is a protocol violation;
    /// its pending state is taken, so the decoder stays usable afterwards.
    pub fn finish(&mut self) -> Result<(), RpcFrameError> {
        match self.pending.take() {
            None => Ok(()),
            Some(pending) => Err(RpcFrameError::new(
                RpcFrameErrorKind::UnfinishedChunkSequence {
                    chunk_id: pending.chunk_id,
                    next_index: pending.next_index,
                    count: pending.count,
                    received: pending.received,
                    declared: pending.byte_length,
                },
                pending.lines,
            )),
        }
    }

    /// Validates and absorbs one `rpc_chunk` frame. Validation order matches the
    /// pinned decoder: metadata, base64 canonicality, payload ceiling, then
    /// sequence state; the reassembly ceiling is enforced on accumulated byte
    /// counts before any full-payload allocation.
    fn accept_chunk(
        &mut self,
        frame: &Value,
        line: Vec<u8>,
    ) -> Result<Option<DecodedRpcFrame>, RpcFrameError> {
        let object = frame.as_object().expect("chunk frames are objects");
        let chunk_id = object.get("chunkId").and_then(Value::as_str);
        let index = object.get("index").and_then(Value::as_u64);
        let count = object.get("count").and_then(Value::as_u64);
        let byte_length = object.get("byteLength").and_then(Value::as_u64);
        let (chunk_id, index, count, byte_length) = match (chunk_id, index, count, byte_length) {
            (Some(chunk_id), Some(index), Some(count), Some(byte_length)) => {
                (chunk_id, index, count, byte_length)
            }
            _ => return Err(self.rejected_owned(RpcFrameErrorKind::InvalidChunkMetadata, line)),
        };
        if chunk_id.is_empty()
            // The pin checks `chunkId.length`, a UTF-16 code-unit count where
            // astral characters count double; stop counting past the bound.
            || chunk_id.encode_utf16().nth(MAX_CHUNK_ID_CHARS).is_some()
            || index >= count
            || !(2..=MAX_CHUNK_COUNT as u64).contains(&count)
            || !(MAX_FRAME_BYTES as u64..=MAX_REASSEMBLED_BYTES as u64).contains(&byte_length)
        {
            return Err(self.rejected_owned(RpcFrameErrorKind::InvalidChunkMetadata, line));
        }
        let Some(bytes) = object
            .get("data")
            .and_then(Value::as_str)
            .and_then(decode_canonical_base64)
        else {
            return Err(self.rejected_owned(RpcFrameErrorKind::InvalidChunkData, line));
        };
        if bytes.len() > CHUNK_PAYLOAD_BYTES {
            let size = bytes.len();
            return Err(self.rejected_owned(RpcFrameErrorKind::ChunkPayloadTooLarge { size }, line));
        }

        let mismatched = match self.pending.as_ref() {
            Some(pending) => {
                pending.chunk_id != chunk_id
                    || pending.count != count
                    || pending.byte_length != byte_length
                    || pending.next_index != index
            }
            None => false,
        };
        if mismatched {
            return Err(self.rejected_owned(RpcFrameErrorKind::ChunkSequenceMismatch, line));
        }
        if self.pending.is_none() {
            if index != 0 {
                return Err(
                    self.rejected_owned(RpcFrameErrorKind::ChunkSequenceStart { index }, line)
                );
            }
            self.pending = Some(PendingSequence::new(
                chunk_id.to_owned(),
                count,
                byte_length,
            ));
        }
        let mut pending = self
            .pending
            .take()
            .expect("chunk sequence pending after start and match gates");
        let payload_bytes = bytes.len();
        pending.bytes.extend_from_slice(&bytes);
        pending.lines.push(line);
        pending.received += payload_bytes as u64;
        pending.next_index += 1;
        if pending.received > pending.byte_length {
            return Err(RpcFrameError::new(
                RpcFrameErrorKind::ChunkSequenceOverflow {
                    received: pending.received,
                    declared: pending.byte_length,
                },
                pending.lines,
            ));
        }
        if pending.next_index < pending.count {
            self.pending = Some(pending);
            return Ok(None);
        }
        if pending.received != pending.byte_length {
            return Err(RpcFrameError::new(
                RpcFrameErrorKind::ChunkSequenceLengthMismatch {
                    received: pending.received,
                    declared: pending.byte_length,
                },
                pending.lines,
            ));
        }

        let raw = pending.bytes;
        let Ok(text) = str::from_utf8(&raw) else {
            return Err(RpcFrameError::new(
                RpcFrameErrorKind::InvalidFrameUtf8,
                pending.lines,
            ));
        };
        let value: Value = match serde_json::from_str(text) {
            Ok(value) => value,
            Err(error) => {
                return Err(RpcFrameError::new(
                    RpcFrameErrorKind::MalformedFrame {
                        detail: error.to_string(),
                    },
                    pending.lines,
                ));
            }
        };
        if !value.is_object() {
            return Err(RpcFrameError::new(
                RpcFrameErrorKind::NotAnObject,
                pending.lines,
            ));
        }
        Ok(Some(DecodedRpcFrame::reassembled(
            value,
            raw,
            pending.lines,
        )))
    }

    /// Builds an error for one rejected physical line: the active sequence's
    /// lines, if any, are retained as evidence and the broken sequence state is
    /// dropped.
    fn rejected_owned(&mut self, kind: RpcFrameErrorKind, line: Vec<u8>) -> RpcFrameError {
        let mut evidence = self
            .pending
            .take()
            .map(|pending| pending.lines)
            .unwrap_or_default();
        evidence.push(line);
        RpcFrameError::new(kind, evidence)
    }

    /// Builds an over-ceiling error for one physical line: the active
    /// sequence's lines, if any, are retained as evidence and the broken
    /// sequence state is dropped. Only the in-ceiling prefix of the line
    /// itself is retained, so the allocation stays bounded by
    /// [`MAX_FRAME_BYTES`] no matter how large the caller's input was.
    fn rejected_oversized_line(&mut self, line: &[u8]) -> RpcFrameError {
        debug_assert!(line.len() > MAX_FRAME_BYTES);
        let mut evidence = self
            .pending
            .take()
            .map(|pending| pending.lines)
            .unwrap_or_default();
        evidence.push(line[..MAX_FRAME_BYTES].to_vec());
        RpcFrameError::new(
            RpcFrameErrorKind::FrameTooLarge { size: line.len() },
            evidence,
        )
    }

    fn rejected_oversized_owned(&mut self, mut line: Vec<u8>) -> RpcFrameError {
        debug_assert!(line.len() > MAX_FRAME_BYTES);
        let size = line.len();
        line.truncate(MAX_FRAME_BYTES);
        self.rejected_owned(RpcFrameErrorKind::FrameTooLarge { size }, line)
    }
}

fn is_chunk_frame(frame: &Value) -> bool {
    frame.get("type").and_then(Value::as_str) == Some(CHUNK_TYPE)
}

enum LineDecision {
    Blank,
    Reject(RpcFrameErrorKind),
    Parsed(Value),
}

/// Classifies one in-ceiling physical line. Decoder state (an active chunk
/// sequence, the negotiated protocol) is applied by the caller so this stays
/// a pure function of the bytes.
fn classify_physical_line(line: &[u8]) -> LineDecision {
    let Some((last, content)) = line.split_last() else {
        return LineDecision::Reject(RpcFrameErrorKind::MissingNewline);
    };
    if *last != b'\n' {
        return LineDecision::Reject(RpcFrameErrorKind::MissingNewline);
    }
    if content.contains(&b'\n') {
        return LineDecision::Reject(RpcFrameErrorKind::EmbeddedNewline);
    }
    let Ok(text) = str::from_utf8(content) else {
        return LineDecision::Reject(RpcFrameErrorKind::InvalidLineUtf8);
    };
    if text.trim().is_empty() {
        return LineDecision::Blank;
    }
    match serde_json::from_str::<Value>(text) {
        Ok(frame) => LineDecision::Parsed(frame),
        Err(error) => LineDecision::Reject(RpcFrameErrorKind::MalformedLine {
            detail: error.to_string(),
        }),
    }
}

/// Decodes standard padded base64, accepting only the canonical form: the
/// engine's standard alphabet, required canonical padding, and zero-discarded-
/// bits check together reproduce the pinned alphabet-regex plus roundtrip
/// equality — empty input, stray padding, non-alphabet bytes, and nonzero
/// discarded bits are all rejected.
fn decode_canonical_base64(data: &str) -> Option<Vec<u8>> {
    if data.is_empty() {
        return None;
    }
    let bytes = BASE64_STANDARD.decode(data).ok()?;
    (BASE64_STANDARD.encode(&bytes) == data).then_some(bytes)
}

#[cfg(test)]
mod tests;
