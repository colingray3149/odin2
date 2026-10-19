//! Kernel-lease-governed embedding execution for vector/hybrid retrieval.
//!
//! Embedding execution is provider-governed: vector/hybrid retrieval may run
//! only against a provider an active kernel lease explicitly authorizes.
//! Receipt projection alone is not authorization. The executor below never
//! mints, accepts, or synthesizes a permit: the only entry into a provider
//! call is [`ProviderLeaseCoordinator::begin_request`], whose
//! [`RequestBinding`] is the kernel-minted, ledger-persisted lease binding.
//! A binding whose provider is not the executor's composed provider id
//! does not authorize the brain embedding backend and yields the typed
//! [`BrainError::EmbeddingUnavailable`] — never fabricated embeddings, never
//! a silent downgrade to lexical candidates.
//!
//! The kernel provider model is deliberately credential-free and
//! transport-free: registry `auth` references, base URLs, and adapter
//! details never enter [`RequestBinding`]. The network hop therefore runs
//! through the [`GatewayTransport`] seam: the in-crate
//! [`PrivateGatewayTransport`] private-interface HTTP adapter posts to an
//! endpoint supplied by deployment wiring; the executor itself owns
//! lease governance, request lifecycle, and response contract enforcement.
//!
//! When the composed provider declares an embedding protocol
//! (`[protocol]` in its registry declaration), this transport seam is the
//! protocol's single application point: inputs are prefix-truncated to the
//! declared pinned-token bound and framed exactly as declared (no client
//! EOS, no trailing newline), and returned vectors are L2-normalized with
//! a typed zero-norm refusal. The protocol's identity composes the
//! effective embedding model id (`{wire_model}:{protocol}`) at the
//! projection seam, so index generations, backfill gating, and serve-time
//! authority all bind to wire model and protocol together. Absent a
//! declaration, the raw wire behavior and the unsuffixed identity stand.

use odin_domain::{LaneId, ProviderId};
use odin_kernel::provider::{
    ProviderCoordinatorTemplate, ProviderError, ProviderLeaseCoordinator, RequestBinding,
};
use odin_ledger::Ledger;
use odin_registry::{EmbeddingFramingToml, EmbeddingProtocolToml};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use time::OffsetDateTime;

use super::{LaneEmbeddingProvider, QueryEmbedder};
use crate::context::tokenizer::byte_fit_prefix;
use crate::error::{BrainError, BrainResult};
use zeroize::Zeroizing;

/// The typed failure for vector/hybrid retrieval when no active kernel
/// lease authorizes the composed embedding provider. `reason` states what
/// is missing; the result is unavailable, not lexical.
pub fn unauthorized(provider: impl Into<String>, reason: impl Into<String>) -> BrainError {
    BrainError::EmbeddingUnavailable {
        provider: provider.into(),
        reason: reason.into(),
    }
}

/// One embedding: dense vector as produced by the authorized provider model.
#[derive(Clone, Debug, PartialEq)]
pub struct EmbeddingVector {
    dims: Vec<f32>,
}

impl EmbeddingVector {
    /// Rejects empty vectors and non-finite dimensions.
    pub fn from_dims(dims: Vec<f32>) -> BrainResult<Self> {
        if dims.is_empty() {
            return Err(BrainError::InvalidRequest(
                "embedding vector must have at least one dimension".to_owned(),
            ));
        }
        if dims.iter().any(|dim| !dim.is_finite()) {
            return Err(BrainError::InvalidRequest(
                "embedding vector must contain only finite dimensions".to_owned(),
            ));
        }
        Ok(Self { dims })
    }

    pub fn dims(&self) -> &[f32] {
        &self.dims
    }

    /// Cosine similarity against another embedding, in `[-1, 1]`.
    ///
    /// Dimension mismatch or a zero-norm operand is a contract violation of
    /// the embedding space, not an availability event.
    pub fn cosine_similarity(&self, other: &EmbeddingVector) -> BrainResult<f64> {
        if self.dims.len() != other.dims.len() {
            return Err(BrainError::InvalidRequest(format!(
                "embedding dimension mismatch: {} vs {}",
                self.dims.len(),
                other.dims.len()
            )));
        }
        let mut dot = 0.0f64;
        let mut norm_self = 0.0f64;
        let mut norm_other = 0.0f64;
        for (a, b) in self.dims.iter().zip(other.dims.iter()) {
            let a = f64::from(*a);
            let b = f64::from(*b);
            dot += a * b;
            norm_self += a * a;
            norm_other += b * b;
        }
        if norm_self == 0.0 || norm_other == 0.0 {
            return Err(BrainError::InvalidRequest(
                "cosine similarity is undefined for a zero-norm embedding".to_owned(),
            ));
        }
        Ok(dot / (norm_self.sqrt() * norm_other.sqrt()))
    }
}

/// The completed outcome of one lease-governed embedding batch.
///
/// `binding` is the kernel binding this execution ran under, finished
/// through [`ProviderLeaseCoordinator::finish_request`]; it is provenance,
/// not a reusable permit.
#[derive(Clone, Debug, PartialEq)]
pub struct EmbeddingOutput {
    pub binding: RequestBinding,
    pub vectors: Vec<EmbeddingVector>,
}

/// The network hop to the deployed gateway: one embeddings call for the
/// bound account/model, given the kernel-minted binding as its only
/// authorization context.
///
/// This seam exists because the kernel provider model carries no base URL
/// and no credentials by construction; deployment wiring supplies the
/// endpoint to the private-interface adapter, [`PrivateGatewayTransport`]. It is
/// plumbing, never a permit: every call here already runs under a binding
/// minted by the coordinator.
pub trait GatewayTransport {
    fn embeddings(
        &mut self,
        binding: &RequestBinding,
        inputs: &[String],
    ) -> BrainResult<Vec<Vec<f32>>>;
}

/// Private-interface HTTP adapter for the [`GatewayTransport`] seam.
///
/// Deployment wiring supplies the endpoint explicitly (for example
/// `"http://127.0.0.1:4000"` or a declared tailscale embedding host); every
/// call posts an OpenAI-compatible embeddings request to
/// `<endpoint>/v1/embeddings`. Plain HTTP over [`std::net`] only — the
/// gateway is reached only over loopback or the encrypted tailscale overlay,
/// so TLS is neither supported nor required — with redirects refused, header
/// and body sizes bounded, and the genuine JSON embeddings response shape
/// enforced. An optional bearer is written only into requests on this one
/// pinned connection: the resolved addresses are fixed at construction and
/// redirects are refused rather than followed, so the credential can never
/// leave the process toward an unpinned destination. Plumbing under an
/// already-minted binding: no authority strings, no permits.
#[derive(Debug)]
pub struct PrivateGatewayTransport {
    /// Caller-supplied authority, echoed as the HTTP `Host` header.
    endpoint: String,
    /// Resolved admissible addresses, fixed at construction so a later DNS
    /// change can never smuggle the batch off the private interface.
    addresses: Vec<SocketAddr>,
    /// Gateway credential resolved from the route's configured credential handle.
    bearer: Option<GatewayBearer>,
}

/// One gateway credential value for the private-interface hop: a nonempty
/// RFC 6750 `b64token`, held in owned zeroizing storage that is cleared when
/// the value is dropped or rejected. `Debug` is redacted; the value is
/// never logged, never enters error text, and is written only into the
/// Authorization header of requests to the transport's
/// construction-pinned addresses.
pub struct GatewayBearer(Zeroizing<Vec<u8>>);

impl GatewayBearer {
    /// Wraps bytes before validation so rejected credentials are zeroized too.
    pub fn new(bytes: Vec<u8>) -> BrainResult<Self> {
        let bytes = Zeroizing::new(bytes);
        if !is_valid_bearer_token(&bytes) {
            return Err(gateway_unavailable(
                "gateway credential rejected: not a valid RFC 6750 bearer token",
            ));
        }
        Ok(Self(bytes))
    }

    /// The validated token bytes, borrowed for the one Authorization header
    /// write; never copied into a formatted string.
    fn token(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for GatewayBearer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("GatewayBearer([redacted])")
    }
}

/// RFC 6750 requires nonempty token bytes with `=` padding only at the end.
fn is_valid_bearer_token(bytes: &[u8]) -> bool {
    let Some(first_padding) = bytes.iter().position(|byte| *byte == b'=') else {
        return !bytes.is_empty() && bytes.iter().all(is_b64_token_byte);
    };
    first_padding > 0
        && bytes[..first_padding].iter().all(is_b64_token_byte)
        && bytes[first_padding..].iter().all(|byte| *byte == b'=')
}

/// One RFC 6750 `b64token` symbol outside the padding position.
fn is_b64_token_byte(byte: &u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
}

/// Upper bounds for the gateway hop; a gateway that exceeds them is broken
/// or hostile and fails as unavailable, never by ballooning memory.
const MAX_REQUEST_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_RESPONSE_BODY_BYTES: usize = 128 * 1024 * 1024;
const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Path every private-interface embeddings call is posted to.
const EMBEDDINGS_PATH: &str = "/v1/embeddings";

/// Restricts connections to loopback or the tailnet ranges `100.64.0.0/10`
/// and `fd7a:115c:a1e0::/48`, excluding other routable interfaces.
fn is_admissible_gateway_address(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || is_tailnet_ipv4(*v4),
        IpAddr::V6(v6) => v6.is_loopback() || is_tailnet_ipv6(*v6),
    }
}

/// Tailscale IPv4 overlay range: `100.64.0.0/10` (shared CGNAT block the
/// tailnet allocates node addresses from).
fn is_tailnet_ipv4(v4: Ipv4Addr) -> bool {
    let octets = v4.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

/// Tailscale IPv6 overlay range: the ULA prefix `fd7a:115c:a1e0::/48`.
fn is_tailnet_ipv6(v6: Ipv6Addr) -> bool {
    v6.octets()[..6] == [0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0]
}

impl PrivateGatewayTransport {
    /// Builds the adapter from an explicit gateway endpoint, either
    /// `host:port` or `http://host:port`. `https` is rejected, and the host
    /// must resolve to private-interface addresses only (loopback or the
    /// tailscale overlay, `is_admissible_gateway_address`) — the
    /// enforcement is on the resolved IP, not the scheme text, and the
    /// resolved set is fixed at construction.
    pub fn new(endpoint: impl Into<String>) -> BrainResult<Self> {
        let endpoint = endpoint.into();
        let trimmed = endpoint.trim();
        let bytes = trimmed.as_bytes();
        let authority = if bytes.len() >= 7 && bytes[..7].eq_ignore_ascii_case(b"http://") {
            &trimmed[7..]
        } else {
            if bytes.len() >= 8 && bytes[..8].eq_ignore_ascii_case(b"https://") {
                return Err(BrainError::InvalidRequest(format!(
                    "embedding gateway endpoint must be plain http, got {trimmed}"
                )));
            }
            trimmed
        };
        let authority = authority.trim_end_matches('/');
        if authority.is_empty() {
            return Err(BrainError::InvalidRequest(
                "embedding gateway endpoint must name host:port".to_owned(),
            ));
        }
        let (host, port) = split_host_port(authority)?;
        let addresses = (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|error| {
                BrainError::InvalidRequest(format!(
                    "embedding gateway endpoint '{authority}' does not resolve: {error}"
                ))
            })?
            .collect::<Vec<_>>();
        if addresses.is_empty() {
            return Err(BrainError::InvalidRequest(format!(
                "embedding gateway endpoint '{authority}' resolves to no addresses"
            )));
        }
        for address in &addresses {
            if !is_admissible_gateway_address(&address.ip()) {
                return Err(BrainError::InvalidRequest(format!(
                    "embedding gateway endpoint '{authority}' resolves to {address}, which \
                     is neither a loopback nor a tailscale-overlay address"
                )));
            }
        }
        Ok(Self {
            endpoint: authority.to_owned(),
            addresses,
            bearer: None,
        })
    }

    /// Applies [`Self::new`]'s address restrictions and sends the credential
    /// only in this transport's requests, never logs or errors.
    pub fn with_bearer(endpoint: impl Into<String>, bearer: GatewayBearer) -> BrainResult<Self> {
        let mut transport = Self::new(endpoint)?;
        transport.bearer = Some(bearer);
        Ok(transport)
    }

    /// Opens the gateway connection under a bounded connect timeout, trying
    /// every resolved address; total failure is the typed absent-backend
    /// error, not a panic.
    fn connect(&self) -> BrainResult<TcpStream> {
        let mut last_error = "no resolved gateway addresses".to_owned();
        for address in &self.addresses {
            match TcpStream::connect_timeout(address, CONNECT_TIMEOUT) {
                Ok(stream) => {
                    stream
                        .set_read_timeout(Some(IO_TIMEOUT))
                        .map_err(|error| io_unavailable("preparing the socket", error))?;
                    stream
                        .set_write_timeout(Some(IO_TIMEOUT))
                        .map_err(|error| io_unavailable("preparing the socket", error))?;
                    return Ok(stream);
                }
                Err(error) => last_error = format!("{address}: {error}"),
            }
        }
        Err(gateway_unavailable(format!(
            "embedding gateway at {} is unreachable: {last_error}",
            self.endpoint
        )))
    }
}

impl GatewayTransport for PrivateGatewayTransport {
    fn embeddings(
        &mut self,
        binding: &RequestBinding,
        inputs: &[String],
    ) -> BrainResult<Vec<Vec<f32>>> {
        let request = serde_json::json!({
            "model": binding.model.to_string(),
            "input": inputs,
        });
        let body = serde_json::to_vec(&request).map_err(|error| {
            gateway_unavailable(format!("embedding request failed to serialize: {error}"))
        })?;
        if body.len() > MAX_REQUEST_BODY_BYTES {
            return Err(BrainError::InvalidRequest(format!(
                "embedding batch of {} bytes exceeds the {} byte gateway request bound",
                body.len(),
                MAX_REQUEST_BODY_BYTES
            )));
        }
        let mut stream = self.connect()?;
        // The Authorization line is written as fixed prefix, borrowed token
        // bytes, and CRLF: no secret-bearing String exists on this path.
        let head = format!(
            "POST {EMBEDDINGS_PATH} HTTP/1.1\r\nHost: {}\r\n",
            self.endpoint
        );
        let tail = format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .write_all(head.as_bytes())
            .and_then(|()| match &self.bearer {
                None => Ok(()),
                Some(bearer) => stream
                    .write_all(b"Authorization: Bearer ")
                    .and_then(|()| stream.write_all(bearer.token()))
                    .and_then(|()| stream.write_all(b"\r\n")),
            })
            .and_then(|()| stream.write_all(tail.as_bytes()))
            .and_then(|()| stream.write_all(&body))
            .map_err(|error| io_unavailable("writing the embeddings request", error))?;
        stream
            .flush()
            .map_err(|error| io_unavailable("writing the embeddings request", error))?;
        let (status, body) = read_response(&mut stream)?;
        if (300..400).contains(&status) {
            return Err(gateway_unavailable(format!(
                "embedding gateway answered HTTP {status}; the gateway transport refuses redirects"
            )));
        }
        if status != 200 {
            return Err(gateway_unavailable(format!(
                "embedding gateway answered HTTP {status} for {EMBEDDINGS_PATH}"
            )));
        }
        parse_embeddings(&body, inputs.len())
    }
}

/// Reads one bounded HTTP/1.1 response: status plus body under the declared
/// framing (`Content-Length`, chunked, or close-delimited).
fn read_response(stream: &mut TcpStream) -> BrainResult<(u16, Vec<u8>)> {
    let mut buffered: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    let head_end = loop {
        if let Some(position) = find_sub(&buffered, b"\r\n\r\n") {
            break position;
        }
        if buffered.len() > MAX_RESPONSE_HEADER_BYTES {
            return Err(gateway_unavailable(
                "embedding gateway response headers exceed the loopback bound",
            ));
        }
        let read = stream
            .read(&mut chunk)
            .map_err(|error| io_unavailable("reading response headers", error))?;
        if read == 0 {
            return Err(gateway_unavailable(
                "embedding gateway closed the connection before response headers",
            ));
        }
        buffered.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&buffered[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| {
            gateway_unavailable(format!(
                "embedding gateway sent an unreadable status line: {status_line}"
            ))
        })?;
    let mut headers = Vec::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
    }
    let header = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };
    let chunked = header("transfer-encoding")
        .map(|value| value.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false);
    let content_length = header("content-length").and_then(|value| value.parse::<usize>().ok());
    let mut body = ResponseBody::new(stream, buffered.split_off(head_end + 4));
    let body_bytes = if chunked {
        body.read_chunked()?
    } else if let Some(length) = content_length {
        if length > MAX_RESPONSE_BODY_BYTES {
            return Err(gateway_unavailable(format!(
                "embedding gateway response of {length} bytes exceeds the {} byte loopback body bound",
                MAX_RESPONSE_BODY_BYTES
            )));
        }
        body.read_exact_bounded(length)?
    } else {
        body.read_to_end_bounded()?
    };
    Ok((status, body_bytes))
}

/// Bounded reader over the post-header bytes of one gateway response.
struct ResponseBody<'a> {
    stream: &'a mut TcpStream,
    buffered: Vec<u8>,
    consumed: usize,
}

impl<'a> ResponseBody<'a> {
    fn new(stream: &'a mut TcpStream, leftover: Vec<u8>) -> Self {
        Self {
            stream,
            buffered: leftover,
            consumed: 0,
        }
    }

    fn unconsumed(&self) -> &[u8] {
        &self.buffered[self.consumed..]
    }

    /// Pulls bytes from the socket until at least `want` unconsumed bytes are
    /// buffered; a socket closed mid-body is the typed absent-backend failure.
    fn fill(&mut self, want: usize) -> BrainResult<()> {
        while self.buffered.len() - self.consumed < want {
            let mut chunk = [0u8; 8192];
            let read = self
                .stream
                .read(&mut chunk)
                .map_err(|error| io_unavailable("reading the response body", error))?;
            if read == 0 {
                return Err(gateway_unavailable(
                    "embedding gateway closed the connection mid-response",
                ));
            }
            self.buffered.extend_from_slice(&chunk[..read]);
        }
        Ok(())
    }

    fn take(&mut self, count: usize) -> Vec<u8> {
        let out = self.buffered[self.consumed..self.consumed + count].to_vec();
        self.consumed += count;
        out
    }

    fn read_exact_bounded(&mut self, length: usize) -> BrainResult<Vec<u8>> {
        self.fill(length)?;
        Ok(self.take(length))
    }

    /// Reads one CRLF-terminated line (terminator stripped), bounded.
    fn read_line(&mut self, max: usize) -> BrainResult<String> {
        loop {
            if let Some(position) = find_sub(self.unconsumed(), b"\r\n") {
                let line = String::from_utf8_lossy(&self.unconsumed()[..position]).into_owned();
                self.consumed += position + 2;
                return Ok(line);
            }
            if self.unconsumed().len() > max {
                return Err(gateway_unavailable(
                    "embedding gateway sent an oversized chunked-encoding line",
                ));
            }
            let mut chunk = [0u8; 8192];
            let read = self
                .stream
                .read(&mut chunk)
                .map_err(|error| io_unavailable("reading the response body", error))?;
            if read == 0 {
                return Err(gateway_unavailable(
                    "embedding gateway closed the connection mid-response",
                ));
            }
            self.buffered.extend_from_slice(&chunk[..read]);
        }
    }

    /// Decodes a chunked body, rejecting any total beyond the loopback bound.
    fn read_chunked(&mut self) -> BrainResult<Vec<u8>> {
        let mut body = Vec::new();
        loop {
            let size_line = self.read_line(1024)?;
            let size_text = size_line.split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(size_text, 16).map_err(|_| {
                gateway_unavailable(format!(
                    "embedding gateway sent an unreadable chunk size: {size_line}"
                ))
            })?;
            if size == 0 {
                loop {
                    if self.read_line(8 * 1024)?.is_empty() {
                        break;
                    }
                }
                return Ok(body);
            }
            if body.len() + size > MAX_RESPONSE_BODY_BYTES {
                return Err(gateway_unavailable(format!(
                    "embedding gateway chunked response exceeds the {} byte loopback body bound",
                    MAX_RESPONSE_BODY_BYTES
                )));
            }
            body.extend(self.read_exact_bounded(size)?);
        }
    }

    /// Reads a close-delimited body under the loopback bound.
    fn read_to_end_bounded(&mut self) -> BrainResult<Vec<u8>> {
        let mut body = self.take(self.buffered.len() - self.consumed);
        let mut chunk = [0u8; 8192];
        loop {
            let read = self
                .stream
                .read(&mut chunk)
                .map_err(|error| io_unavailable("reading the response body", error))?;
            if read == 0 {
                return Ok(body);
            }
            if body.len() + read > MAX_RESPONSE_BODY_BYTES {
                return Err(gateway_unavailable(format!(
                    "embedding gateway response exceeds the {} byte loopback body bound",
                    MAX_RESPONSE_BODY_BYTES
                )));
            }
            body.extend_from_slice(&chunk[..read]);
        }
    }
}

/// Enforces the genuine gateway response contract: an OpenAI-compatible
/// `{ "data": [ { "index": n, "embedding": [numbers...] } ] }` payload whose
/// indices are exactly `0..expected`, placed by `index` rather than response
/// order, with one shared dimensionality across the batch. Missing or
/// duplicate indices, out-of-range indices, inconsistent dimensions, and
/// non-numeric or non-finite dimensions all fail as unavailable so no
/// fabricated vector can enter retrieval.
fn parse_embeddings(body: &[u8], expected: usize) -> BrainResult<Vec<Vec<f32>>> {
    let value: serde_json::Value = serde_json::from_slice(body).map_err(|error| {
        gateway_unavailable(format!(
            "embedding gateway returned malformed JSON: {error}"
        ))
    })?;
    let data = value
        .get("data")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            gateway_unavailable("embedding gateway response is missing the `data` array")
        })?;
    let mut slots: Vec<Option<Vec<f32>>> = vec![None; expected];
    for item in data {
        let index = item
            .get("index")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                gateway_unavailable("gateway embedding entry is missing its integer `index` field")
            })?;
        let index = usize::try_from(index).map_err(|_| {
            gateway_unavailable(format!("gateway embedding index {index} is out of range"))
        })?;
        if index >= expected {
            return Err(gateway_unavailable(format!(
                "gateway returned embedding index {index} beyond the batch of {expected} inputs"
            )));
        }
        if slots[index].is_some() {
            return Err(gateway_unavailable(format!(
                "gateway returned duplicate embedding index {index}"
            )));
        }
        let dims = item
            .get("embedding")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                gateway_unavailable(format!(
                    "embedding {index} in the gateway response is missing its `embedding` array"
                ))
            })?;
        slots[index] = Some(
            dims.iter()
                .map(|dim| {
                    let raw = dim.as_f64().ok_or_else(|| {
                        gateway_unavailable(format!(
                            "embedding {index} contains a non-numeric dimension"
                        ))
                    })?;
                    let dim = raw as f32;
                    if !dim.is_finite() {
                        return Err(gateway_unavailable(format!(
                            "embedding {index} contains a non-finite dimension"
                        )));
                    }
                    Ok(dim)
                })
                .collect::<BrainResult<Vec<f32>>>()?,
        );
    }
    let mut vectors = Vec::with_capacity(expected);
    let mut batch_dimension = None;
    for (index, slot) in slots.into_iter().enumerate() {
        let dims = slot.ok_or_else(|| {
            gateway_unavailable(format!(
                "gateway response is missing embedding index {index}"
            ))
        })?;
        match batch_dimension {
            None => batch_dimension = Some(dims.len()),
            Some(expected_dim) if expected_dim != dims.len() => {
                return Err(gateway_unavailable(format!(
                    "embedding {index} has {} dimensions but the batch established {expected_dim}",
                    dims.len()
                )));
            }
            _ => {}
        }
        vectors.push(dims);
    }
    Ok(vectors)
}

/// Splits a `host:port` authority, accepting `[ipv6]:port` brackets.
fn split_host_port(authority: &str) -> BrainResult<(String, u16)> {
    let invalid = |reason: &str| {
        BrainError::InvalidRequest(format!(
            "loopback embedding gateway endpoint '{authority}' is invalid: {reason}"
        ))
    };
    if let Some(rest) = authority.strip_prefix('[') {
        let close = rest
            .find(']')
            .ok_or_else(|| invalid("bracketed IPv6 host is missing ']'"))?;
        let port_text = rest[close + 1..]
            .strip_prefix(':')
            .ok_or_else(|| invalid("bracketed IPv6 host must be followed by :port"))?;
        let port = port_text
            .parse::<u16>()
            .map_err(|_| invalid("port is not a number in 0-65535"))?;
        return Ok((rest[..close].to_owned(), port));
    }
    let (host, port_text) = authority
        .rsplit_once(':')
        .ok_or_else(|| invalid("an explicit port is required"))?;
    if host.is_empty() || port_text.is_empty() {
        return Err(invalid("both host and port are required"));
    }
    let port = port_text
        .parse::<u16>()
        .map_err(|_| invalid("port is not a number in 0-65535"))?;
    Ok((host.to_owned(), port))
}

/// Transport-level failures: the gateway is absent, unreachable, or
/// answered something that is not a genuine embeddings payload. The
/// provider label is this seam's own infrastructure identity — the real
/// executor is kernel authority, never carried as a string here. Typed as
/// unavailable so retrieval degrades explicitly, never silently to lexical.
fn gateway_unavailable(reason: impl Into<String>) -> BrainError {
    BrainError::EmbeddingUnavailable {
        provider: "odin.brain.embedding-gateway".to_owned(),
        reason: reason.into(),
    }
}

/// Applies the declared protocol's framing to one already-truncated-or-not
/// input: prefix truncation under the crate's canonical pinned tokenizer
/// (`INDEX_TOKENIZER`: one token is one UTF-8 byte, so the declared token
/// bound is a conservative byte bound that never splits a character) runs
/// first, then the declared markers wrap the text exactly once — no client
/// EOS token is appended and no trailing newline follows the close marker.
fn framed_input(protocol: &EmbeddingProtocolToml, text: &str) -> String {
    let truncated = byte_fit_prefix(text, protocol.truncate_tokens);
    match protocol.framing {
        EmbeddingFramingToml::ImUserV1 => format!("<|im_start|>user\n{truncated}<|im_end|>"),
    }
}

/// Applies the declared protocol to one returned vector: L2 normalization
/// to unit Euclidean norm when declared, computed in `f64` over the exact
/// finite dimensions the response contract already enforced. A zero-norm
/// vector is directionless — cosine over it is NaN — so it is refused
/// typed as embedding-unavailable, never normalized, never stored.
fn normalized_dims(
    provider: &str,
    protocol: &EmbeddingProtocolToml,
    dims: Vec<f32>,
) -> BrainResult<Vec<f32>> {
    if !protocol.l2_normalize {
        return Ok(dims);
    }
    let norm_squared: f64 = dims
        .iter()
        .map(|dim| f64::from(*dim) * f64::from(*dim))
        .sum();
    if norm_squared == 0.0 {
        return Err(BrainError::EmbeddingUnavailable {
            provider: provider.to_owned(),
            reason: "the provider returned a zero-norm embedding under the declared L2 \
                     protocol; a directionless vector can never enter retrieval"
                .to_owned(),
        });
    }
    let norm = norm_squared.sqrt();
    Ok(dims
        .into_iter()
        .map(|dim| (f64::from(dim) / norm) as f32)
        .collect())
}

/// One embedding batch: the caller-owned request id, raw input texts, the
/// route's declared protocol (if any), and the ledger timestamp for the
/// lease request. Inputs are raw; the protocol is applied inside `embed`.
pub struct EmbedBatch<'a> {
    pub request_id: &'a str,
    pub inputs: &'a [String],
    pub protocol: Option<&'a EmbeddingProtocolToml>,
    pub now: OffsetDateTime,
}

/// Executes one embedding batch under an active kernel lane lease.
///
/// Flow, entirely kernel-governed:
/// 1. `coordinator.begin_request` binds the request to the lane's one
///    active lease (minting or reusing it in the ledger). Duplicate request
///    ids return the identical binding.
/// 2. The binding must name `expected_provider` — the executor's composed
///    provider identity, never a compiled constant; anything else means the
///    lane lease does not authorize the composed embedding backend.
/// 3. The transport executes against the bound account/model. The declared
///    protocol, when the composed route carries one, is applied exactly
///    once here — framing and prefix truncation on the way out, L2
///    normalization on the way back — so the serving executor and the
///    backfill lane share one implementation and no caller frames inputs
///    itself.
/// 4. The request finishes on both success and failure, releasing the
///    binding slot; fault recording against the candidate is left to the
///    caller, which owns typed retry policy.
pub fn embed(
    expected_provider: &ProviderId,
    coordinator: &mut ProviderLeaseCoordinator,
    ledger: &mut Ledger,
    batch: EmbedBatch<'_>,
    transport: &mut dyn GatewayTransport,
) -> BrainResult<EmbeddingOutput> {
    if batch.inputs.is_empty() {
        return Err(BrainError::InvalidRequest(
            "embedding batch must contain at least one input".to_owned(),
        ));
    }
    let binding = coordinator
        .begin_request(ledger, batch.request_id, batch.now)
        .map_err(provider_block)?;
    let result = run_bound(
        expected_provider,
        &binding,
        batch.inputs,
        batch.protocol,
        transport,
    );
    coordinator
        .finish_request(&binding.request_id)
        .map_err(provider_block)?;
    let vectors = result?;
    Ok(EmbeddingOutput { binding, vectors })
}

/// Runs the transport under an already-minted binding, enforcing the
/// composed-provider identity, the declared embedding protocol, and the
/// batch response contract: one non-empty vector per input, same order.
fn run_bound(
    expected_provider: &ProviderId,
    binding: &RequestBinding,
    inputs: &[String],
    protocol: Option<&EmbeddingProtocolToml>,
    transport: &mut dyn GatewayTransport,
) -> BrainResult<Vec<EmbeddingVector>> {
    if binding.provider.as_str() != expected_provider.as_str() {
        return Err(BrainError::EmbeddingUnavailable {
            provider: binding.provider.as_str().to_owned(),
            reason: format!(
                "lane lease {} binds provider {:?} model {}, but the composed \
                 embedding provider is {:?}",
                binding.lease_id,
                binding.provider.as_str(),
                binding.model,
                expected_provider.as_str()
            ),
        });
    }
    // One shared protocol application point: the query and backfill paths
    // both enter through this seam, so framing, truncation, and
    // normalization can never diverge between them.
    let prepared: Vec<String>;
    let wire_inputs: &[String] = match protocol {
        Some(protocol) => {
            prepared = inputs
                .iter()
                .map(|text| framed_input(protocol, text))
                .collect();
            &prepared
        }
        None => inputs,
    };
    let raw = transport.embeddings(binding, wire_inputs)?;
    if raw.len() != inputs.len() {
        return Err(BrainError::InvalidRequest(format!(
            "embedding transport returned {} vectors for {} inputs",
            raw.len(),
            inputs.len()
        )));
    }
    raw.into_iter()
        .map(|dims| {
            EmbeddingVector::from_dims(match protocol {
                Some(protocol) => normalized_dims(binding.provider.as_str(), protocol, dims)?,
                None => dims,
            })
        })
        .collect()
}

/// Maps coordinator refusal to the typed brain failure: an empty request id
/// is a caller bug, everything else is the provider plane saying no.
fn provider_block(error: ProviderError) -> BrainError {
    match error {
        ProviderError::EmptyRequestId => {
            BrainError::InvalidRequest("embedding request id must not be empty".to_owned())
        }
        error => BrainError::Unavailable {
            component: "provider",
            reason: error.to_string(),
        },
    }
}

/// Production executor composition: the resolved policy's provider
/// identity, the lane-independent kernel coordinator template, the ledger,
/// and the private-interface gateway transport, composed into per-lane
/// [`QueryEmbedder`] bindings the retriever consumes.
///
/// The executor owns no fixed gateway lane: runtime composition binds one
/// embedder per session through [`LaneEmbeddingProvider::bind_lane`], and
/// every query embedding enters through [`embed`] under that lane's
/// coordinator, so each one runs under a kernel-minted [`RequestBinding`]
/// whose provider must equal the composed identity, and finishes its lease
/// on both success and failure; no code path here can produce a vector
/// without the kernel lease and the gateway transport.
///
/// The executor carries the provider-declared embedding protocol and
/// applies it once inside [`embed`], so every binding it mints serves the
/// same declared wire contract.
pub struct KernelEmbeddingExecutor {
    provider: ProviderId,
    template: Arc<ProviderCoordinatorTemplate>,
    ledger: Mutex<Ledger>,
    transport: Mutex<PrivateGatewayTransport>,
    /// The provider-declared embedding protocol, applied once inside
    /// [`embed`]; `None` keeps the raw wire behavior.
    protocol: Option<EmbeddingProtocolToml>,
    requests: AtomicU64,
    /// Per-lane coordinators, weakly held: a live entry is owned by the
    /// bound embedders of that lane's session contexts, and every dead
    /// entry is reaped on the next bind, so retention is bounded by live
    /// sessions, never by bind history.
    coordinators: Mutex<BTreeMap<LaneId, Weak<Mutex<ProviderLeaseCoordinator>>>>,
}

/// One bound lane's lease coordinator: the per-lane authority every
/// embedder binding of that lane shares.
type LaneCoordinator = Mutex<ProviderLeaseCoordinator>;

impl KernelEmbeddingExecutor {
    /// Composes the executor from the resolved policy's provider identity,
    /// the lane-independent kernel selection template, the
    /// private-interface adapter resolved by deployment wiring, and the
    /// resolved route's declared embedding protocol (`None` keeps the raw
    /// wire behavior).
    pub fn new(
        provider: ProviderId,
        template: Arc<ProviderCoordinatorTemplate>,
        ledger: Ledger,
        transport: PrivateGatewayTransport,
        protocol: Option<EmbeddingProtocolToml>,
    ) -> Self {
        Self {
            provider,
            template,
            ledger: Mutex::new(ledger),
            transport: Mutex::new(transport),
            protocol,
            requests: AtomicU64::new(0),
            coordinators: Mutex::new(BTreeMap::new()),
        }
    }

    /// Builds the per-lane [`QueryEmbedder`]: one lease-governed request per
    /// batch of texts.
    ///
    /// Request ids are executor-unique (never content-derived) so overlapping
    /// identical queries bind distinct kernel requests instead of colliding
    /// on `begin_request` idempotency and racing `finish_request`.
    fn query_embedder(self: Arc<Self>, coordinator: Arc<LaneCoordinator>) -> Arc<QueryEmbedder> {
        Arc::new(move |texts: &[String]| {
            let request_id = format!(
                "{}-{}",
                self.provider.as_str(),
                self.requests.fetch_add(1, Ordering::Relaxed)
            );
            let mut coordinator = coordinator
                .lock()
                .map_err(|_| lock_poisoned("provider lease coordinator"))?;
            let mut ledger = self
                .ledger
                .lock()
                .map_err(|_| lock_poisoned("embedding ledger"))?;
            let mut transport = self
                .transport
                .lock()
                .map_err(|_| lock_poisoned("embedding gateway transport"))?;
            let output = embed(
                &self.provider,
                &mut coordinator,
                &mut ledger,
                EmbedBatch {
                    request_id: &request_id,
                    inputs: texts,
                    protocol: self.protocol.as_ref(),
                    now: OffsetDateTime::now_utc(),
                },
                &mut *transport,
            )?;
            Ok(output.vectors)
        })
    }
}

impl LaneEmbeddingProvider for KernelEmbeddingExecutor {
    /// Binds (or reuses) the lane coordinator and returns the embedder
    /// holding it strongly. The template performs the lane-independent
    /// validation at composition time, so a lane-dependent refusal here is
    /// the only failure before the first lease.
    fn bind_lane(self: Arc<Self>, lane: &LaneId) -> BrainResult<Arc<QueryEmbedder>> {
        let mut coordinators = self
            .coordinators
            .lock()
            .map_err(|_| lock_poisoned("lane coordinator registry"))?;
        // Reap every dead entry on every bind, not only the requested lane:
        // a lane whose sessions have all dropped disappears here.
        coordinators.retain(|_, weak| weak.strong_count() > 0);
        let lane = lane.clone();
        let coordinator = match coordinators.get(&lane).and_then(|weak| weak.upgrade()) {
            Some(coordinator) => coordinator,
            None => {
                let coordinator = Arc::new(Mutex::new(
                    self.template
                        .for_lane(lane.clone())
                        .map_err(provider_block)?,
                ));
                coordinators.insert(lane, Arc::downgrade(&coordinator));
                coordinator
            }
        };
        drop(coordinators);
        Ok(self.query_embedder(coordinator))
    }
}

/// Lock poisoning is an internal-invariant failure, surfaced typed rather
/// than unwrapped into a panic.
fn lock_poisoned(component: &'static str) -> BrainError {
    BrainError::Unavailable {
        component,
        reason: "internal lock poisoned; embedding executor state is inconsistent".to_owned(),
    }
}

fn io_unavailable(stage: &str, error: std::io::Error) -> BrainError {
    gateway_unavailable(format!("embedding gateway {stage}: {error}"))
}

/// First index of needle in haystack, if present.
fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod gateway_address_law_tests {
    use super::{is_admissible_gateway_address, PrivateGatewayTransport};
    use crate::error::BrainError;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn admits(value: IpAddr) -> bool {
        is_admissible_gateway_address(&value)
    }

    #[test]
    fn only_loopback_and_the_tailnet_overlay_are_admissible() {
        // Loopback, v4 and v6.
        assert!(admits(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(admits(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        // Tailscale CGNAT range 100.64.0.0/10: both boundary octets in,
        // one below and one above out.
        assert!(admits(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(admits(IpAddr::V4(Ipv4Addr::new(100, 127, 255, 254))));
        assert!(!admits(IpAddr::V4(Ipv4Addr::new(100, 63, 255, 255))));
        assert!(!admits(IpAddr::V4(Ipv4Addr::new(100, 128, 0, 0))));
        // Non-tailnet 100.x addresses stay out.
        assert!(!admits(IpAddr::V4(Ipv4Addr::new(100, 10, 0, 1))));
        // The tailnet ULA prefix fd7a:115c:a1e0::/48: in-prefix and a
        // neighboring ULA out.
        assert!(admits(IpAddr::V6(
            "fd7a:115c:a1e0:1234::1".parse().unwrap()
        )));
        assert!(!admits(IpAddr::V6("fd7a:115c:a1e1::1".parse().unwrap())));
        assert!(!admits(IpAddr::V6("fd00::1".parse().unwrap())));
        // LAN, public, link-local, wildcard: never.
        assert!(!admits(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))));
        assert!(!admits(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))));
        assert!(!admits(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!admits(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        assert!(!admits(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    }

    #[test]
    fn constructor_enforces_the_resolved_address_law() {
        assert!(PrivateGatewayTransport::new("http://127.0.0.1:4000").is_ok());
        assert!(PrivateGatewayTransport::new("100.64.0.11:8081").is_ok());
        assert!(PrivateGatewayTransport::new("[fd7a:115c:a1e0::1]:8081").is_ok());
        let refused = |endpoint: &str| {
            let error = PrivateGatewayTransport::new(endpoint).unwrap_err();
            assert!(
                matches!(error, BrainError::InvalidRequest(_)),
                "{endpoint} must refuse as invalid request, got {error:?}"
            );
        };
        // Resolved to a non-private interface: refused before any byte
        // moves; https is refused outright.
        refused("10.0.0.5:8081");
        refused("8.8.8.8:80");
        refused("https://127.0.0.1:4000");
    }
}

#[cfg(test)]
mod test_gateway {
    //! Shared loopback gateway stand-ins for the embedding transport tests.
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::net::TcpListener;
    use std::time::Duration;

    /// Serves exactly `count` sequential connections, answering each with
    /// `reply` only after the request head is read and the full declared
    /// body is drained; every socket runs under bounded deadlines. A short
    /// read or drain fails the fixture quietly — never a mid-request reply.
    pub(super) fn serve_n(count: usize, reply: Vec<u8>) -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback listener");
        let port = listener.local_addr().expect("listener address").port();
        std::thread::spawn(move || {
            for stream in listener.incoming().take(count) {
                let mut stream = stream.expect("gateway connection");
                let deadline = Some(Duration::from_secs(5));
                let _ = stream.set_read_timeout(deadline);
                let _ = stream.set_write_timeout(deadline);
                let mut reader = BufReader::new(stream.try_clone().expect("clone gateway stream"));
                let mut content_length = 0usize;
                loop {
                    let mut line = Vec::new();
                    if reader.read_until(b'\n', &mut line).unwrap_or(0) == 0 || line == b"\r\n" {
                        break;
                    }
                    if let Some((_, value)) = String::from_utf8_lossy(&line)
                        .split_once(':')
                        .filter(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
                    {
                        content_length = value.trim().parse().unwrap_or(0);
                    }
                }
                let mut remaining = content_length;
                while remaining > 0 {
                    let available = match reader.fill_buf() {
                        Ok(buffer) => buffer.len(),
                        Err(_) => return,
                    };
                    if available == 0 {
                        return;
                    }
                    let take = available.min(remaining);
                    reader.consume(take);
                    remaining -= take;
                }
                let _ = stream.write_all(&reply);
                let _ = stream.flush();
            }
        });
        port
    }

    /// Records drained request bodies verbatim, in connection order.
    pub(super) fn serve_n_capturing(
        count: usize,
        reply: Vec<u8>,
    ) -> (u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback listener");
        let port = listener.local_addr().expect("listener address").port();
        let bodies = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = std::sync::Arc::clone(&bodies);
        std::thread::spawn(move || {
            for stream in listener.incoming().take(count) {
                let mut stream = stream.expect("gateway connection");
                let deadline = Some(Duration::from_secs(5));
                let _ = stream.set_read_timeout(deadline);
                let _ = stream.set_write_timeout(deadline);
                let mut reader = BufReader::new(stream.try_clone().expect("clone gateway stream"));
                let mut content_length = 0usize;
                loop {
                    let mut line = Vec::new();
                    if reader.read_until(b'\n', &mut line).unwrap_or(0) == 0 || line == b"\r\n" {
                        break;
                    }
                    if let Some((_, value)) = String::from_utf8_lossy(&line)
                        .split_once(':')
                        .filter(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
                    {
                        content_length = value.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = Vec::new();
                let mut remaining = content_length;
                while remaining > 0 {
                    let available = match reader.fill_buf() {
                        Ok(buffer) => buffer.len(),
                        Err(_) => return,
                    };
                    if available == 0 {
                        return;
                    }
                    let take = available.min(remaining);
                    body.extend_from_slice(&reader.buffer()[..take]);
                    reader.consume(take);
                    remaining -= take;
                }
                if let Ok(mut slot) = recorded.lock() {
                    slot.push(String::from_utf8_lossy(&body).into_owned());
                }
                let _ = stream.write_all(&reply);
                let _ = stream.flush();
            }
        });
        (port, bodies)
    }

    /// The fixed relocation to `port`: the redirect-refusal fixture.
    pub(super) fn redirect_reply(port: u16) -> Vec<u8> {
        format!(
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/v1/embeddings\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .into_bytes()
    }
}

#[cfg(test)]
mod gateway_bearer_tests {
    use super::test_gateway;
    use super::{GatewayBearer, GatewayTransport, PrivateGatewayTransport};
    use crate::error::BrainError;
    use odin_domain::{Digest, LaneId, LeaseId, ProviderId};
    use odin_kernel::provider::RequestBinding;
    use std::net::TcpListener;
    use time::OffsetDateTime;

    /// A valid token exercising every admitted symbol class plus padding.
    const TOKEN: &[u8] = b"sk-test_token~+/9.abc==";

    fn test_binding() -> RequestBinding {
        RequestBinding {
            request_id: "request:1".to_owned(),
            lane: LaneId::new("lane:1").expect("valid lane id"),
            lease_id: LeaseId::new("lease:1").expect("valid lease id"),
            lease_revision: 1,
            provider: ProviderId::new("provider:1").expect("valid provider id"),
            account_handle: "account".to_owned(),
            model: "model".to_owned(),
            role: "embedding".to_owned(),
            affinity_key: "affinity".to_owned(),
            started_at: OffsetDateTime::UNIX_EPOCH,
            expires_at: None,
            registry_revision: 1,
            policy_digest: Digest::hash(b"policy"),
            projection_digest: Digest::hash(b"projection"),
        }
    }

    #[test]
    fn bearer_constructor_accepts_valid_rfc6750_tokens() {
        // Distinct boundaries: plain alphanumerics, every admitted symbol,
        // and trailing `=` padding after token bytes.
        let valid: [&[u8]; 3] = [b"abcXYZ019", b"-._~+/", b"token-9.abc=="];
        for token in valid {
            assert!(
                GatewayBearer::new(token.to_vec()).is_ok(),
                "{token:?} is a valid b64token"
            );
        }
    }

    #[test]
    fn bearer_constructor_rejects_malformed_tokens() {
        // Distinct boundaries: empty, whitespace, CR/LF header injection,
        // leading and interior `=` padding, and non-ASCII bytes.
        let malformed: [&[u8]; 7] = [
            b"",
            b" ",
            b"a\rb",
            b"a\nb",
            b"=abc",
            b"ab=cd",
            &[0xff, b'a'],
        ];
        for token in malformed {
            let error = GatewayBearer::new(token.to_vec()).unwrap_err();
            assert!(
                matches!(error, BrainError::EmbeddingUnavailable { .. }),
                "{token:?} must fail as embedding unavailable"
            );
        }
    }

    #[test]
    fn malformed_bearer_never_leaks_into_error_or_debug() {
        // One identifiable malformed secret: refusal and redaction are
        // asserted by absence of its `secret-marker` substring — Debug
        // escapes control bytes, so the raw CRLF sequence is not the probe.
        let marker = b"secret-marker\r\nX: injected";
        let needle: &[u8] = b"secret-marker";
        let error = GatewayBearer::new(marker.to_vec()).unwrap_err();
        for surface in [error.to_string(), format!("{error:?}")] {
            assert!(
                !surface
                    .as_bytes()
                    .windows(needle.len())
                    .any(|window| window == needle),
                "the malformed credential must never appear in {surface}"
            );
        }
    }

    #[test]
    fn bearer_debug_never_contains_the_token() {
        let bearer = GatewayBearer::new(TOKEN.to_vec()).expect("valid token");
        let debug = format!("{bearer:?}");
        assert!(
            !debug.as_bytes().windows(TOKEN.len()).any(|w| w == TOKEN),
            "bearer Debug must be redacted"
        );
    }

    #[test]
    fn credential_bearing_redirect_never_reaches_a_second_listener() {
        let second = TcpListener::bind(("127.0.0.1", 0)).expect("bind redirect listener");
        let second_port = second.local_addr().expect("listener address").port();
        second
            .set_nonblocking(true)
            .expect("nonblocking redirect listener");
        let port = test_gateway::serve_n(1, test_gateway::redirect_reply(second_port));
        let mut transport = PrivateGatewayTransport::with_bearer(
            format!("127.0.0.1:{port}"),
            GatewayBearer::new(TOKEN.to_vec()).expect("valid token"),
        )
        .expect("authenticated transport");
        let error = transport
            .embeddings(&test_binding(), &["hello".to_owned()])
            .unwrap_err();
        let reason = match &error {
            BrainError::EmbeddingUnavailable { reason, .. } => reason.as_str(),
            other => panic!("redirect must fail as embedding unavailable, got {other:?}"),
        };
        assert!(
            !reason.as_bytes().windows(TOKEN.len()).any(|w| w == TOKEN),
            "the refusal must never quote the credential"
        );
        // No thread, no counter: the synchronous call above has returned, so
        // any connection attempt would already be pending. WouldBlock proves
        // the redirect destination was never contacted.
        assert!(
            matches!(second.accept(), Err(accept) if accept.kind() == std::io::ErrorKind::WouldBlock),
            "the credential must never leave toward the redirect destination"
        );
    }
}

#[cfg(test)]
mod lane_binding_tests {
    use super::test_gateway;
    use super::{KernelEmbeddingExecutor, PrivateGatewayTransport};
    use crate::error::BrainError;
    use crate::retrieval::LaneEmbeddingProvider;
    use odin_domain::{LaneId, ProviderId, SeatId};
    use odin_kernel::provider::ProviderCoordinatorTemplate;
    use odin_ledger::lane_run::{create_lane, NewLane};
    use odin_ledger::Ledger;
    use odin_registry::schema::{
        parse_object_toml, RecoveryAttemptLimitsToml, RecoveryCooldownsToml, RecoveryPolicyToml,
        RecoveryRungToml, RegistryKind, RegistryObject, ResolvedProviderPolicy,
        ResolvedProviderRoute, ResolvedRecoveryPolicy,
    };
    use std::collections::BTreeSet;
    use std::net::TcpListener;
    use std::sync::Arc;
    use time::OffsetDateTime;

    const GATEWAY_TOML: &str = concat!(
        "schema = \"odin.registry.v1\"\n",
        "kind = \"provider\"\n",
        "enabled = true\n",
        "description = \"Loopback fixture gateway for lane-bound embedding tests.\"\n",
        "adapter = \"litellm-gateway\"\n",
        "policy = { routes = [{ gateway_lane_id = \"zai-glm\", gateway_model_id = \"openai/test-embedding\" }] }\n",
        "recovery = { allowed_rungs = [\"escalate\"], blocked_missing_decision = \"operator decision required\", max_attempts = { retry = 0, restart_worker = 0, checkpoint = 0, rehome = 0, escalate = 1 }, cooldown_seconds = { retry = 0, restart_worker = 0, checkpoint = 0, rehome = 0, escalate = 0 } }\n"
    );

    fn fixture_objects() -> Vec<RegistryObject> {
        vec![parse_object_toml(
            RegistryKind::Provider,
            "gateway",
            "registry/providers/gateway/provider.toml",
            GATEWAY_TOML,
        )
        .expect("fixture provider object")]
    }

    fn fixture_policy() -> ResolvedProviderPolicy {
        let recovery = RecoveryPolicyToml {
            max_attempts: RecoveryAttemptLimitsToml {
                retry: 0,
                restart_worker: 0,
                checkpoint: 0,
                rehome: 0,
                escalate: 1,
            },
            cooldown_seconds: RecoveryCooldownsToml {
                retry: 0,
                restart_worker: 0,
                checkpoint: 0,
                rehome: 0,
                escalate: 0,
            },
            allowed_rungs: BTreeSet::from([RecoveryRungToml::Escalate]),
            blocked_missing_decision: "operator decision required".to_owned(),
        };
        ResolvedProviderPolicy {
            budget: None,
            recovery: ResolvedRecoveryPolicy {
                registry_revision: 1,
                policy_digest: odin_domain::Digest::hash(b"recovery-policy"),
                filtered_rungs: vec![RecoveryRungToml::Escalate],
                policy: recovery,
            },
            provider_id: ProviderId::new("gateway").expect("provider id"),
            registry_revision: 1,
            policy_digest: odin_domain::Digest::hash(b"provider-policy"),
            projection_digest: odin_domain::Digest::hash(b"projection"),
            routes: vec![ResolvedProviderRoute {
                gateway_lane_id: "zai-glm".to_owned(),
                gateway_model_id: "openai/test-embedding".to_owned(),
                account_handle: "gateway-primary".to_owned(),
                endpoint: "http://127.0.0.1:4000".to_owned(),
                credential_handle: "litellm-master-key".to_owned(),
                role: "embedding".to_owned(),
                affinity_key: "skuld".to_owned(),
                priority: 0,
                protocol: None,
            }],
        }
    }

    fn fixture_executor(port: u16, ledger: Ledger) -> Arc<KernelEmbeddingExecutor> {
        let template = Arc::new(
            ProviderCoordinatorTemplate::from_resolved_policy(
                &fixture_objects(),
                None,
                &fixture_policy(),
            )
            .expect("template resolves"),
        );
        Arc::new(KernelEmbeddingExecutor::new(
            ProviderId::new("gateway").expect("provider id"),
            template,
            ledger,
            PrivateGatewayTransport::new(format!("127.0.0.1:{port}")).expect("loopback endpoint"),
            None,
        ))
    }

    fn seed_lane(ledger: &Ledger, lane: &LaneId) {
        create_lane(
            ledger.connection(),
            &NewLane {
                lane_id: lane.clone(),
                seat_id: SeatId::new("seat-a").expect("seat id"),
                project_id: None,
                template_id: "template-a".to_owned(),
                backend: "local_omp".to_owned(),
                created_by: "test".to_owned(),
                created_at: OffsetDateTime::UNIX_EPOCH,
                retained: false,
            },
        )
        .expect("seed lane row");
    }

    fn query() -> Vec<String> {
        vec!["hello retrieval".to_owned()]
    }

    /// One successful OpenAI-compatible single-embedding reply.
    fn embeddings_reply() -> Vec<u8> {
        let body = br#"{"data":[{"index":0,"embedding":[0.5,-0.25]}]}"#.to_vec();
        let mut reply =
            format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())
                .into_bytes();
        reply.extend_from_slice(&body);
        reply
    }

    #[test]
    fn same_lane_bindings_share_one_active_lease() {
        let lane = LaneId::new("lane-a").expect("lane id");
        let ledger = Ledger::open_in_memory().unwrap();
        seed_lane(&ledger, &lane);
        let port = test_gateway::serve_n(2, embeddings_reply());
        let executor = fixture_executor(port, ledger);
        let first = Arc::clone(&executor).bind_lane(&lane).expect("first bind");
        let second = Arc::clone(&executor).bind_lane(&lane).expect("second bind");
        first(&query()).expect("embedding under the first binding");
        second(&query()).expect("embedding under the second binding");
        let ledger = executor.ledger.lock().expect("ledger lock");
        let leases = ledger
            .provider_leases_for_lane(&lane)
            .expect("lane lease rows");
        assert_eq!(
            leases.len(),
            1,
            "every same-lane binding shares the one persisted active lease"
        );
    }

    #[test]
    fn distinct_lanes_bind_distinct_leases() {
        let lane_a = LaneId::new("lane-a").expect("lane id");
        let lane_b = LaneId::new("lane-b").expect("lane id");
        let ledger = Ledger::open_in_memory().unwrap();
        seed_lane(&ledger, &lane_a);
        seed_lane(&ledger, &lane_b);
        let port = test_gateway::serve_n(2, embeddings_reply());
        let executor = fixture_executor(port, ledger);
        let first = Arc::clone(&executor)
            .bind_lane(&lane_a)
            .expect("bind lane a");
        let second = Arc::clone(&executor)
            .bind_lane(&lane_b)
            .expect("bind lane b");
        first(&query()).expect("embedding on lane a");
        second(&query()).expect("embedding on lane b");
        let ledger = executor.ledger.lock().expect("ledger lock");
        let a = ledger
            .provider_leases_for_lane(&lane_a)
            .expect("lane a lease rows");
        let b = ledger
            .provider_leases_for_lane(&lane_b)
            .expect("lane b lease rows");
        assert_eq!(a.len(), 1, "lane a owns exactly one lease row");
        assert_eq!(b.len(), 1, "lane b owns exactly one lease row");
        assert_ne!(
            a[0].lease_id, b[0].lease_id,
            "each runtime lane binds its own lease"
        );
    }

    #[test]
    fn recreated_binding_re_adopts_the_persisted_lease() {
        let lane = LaneId::new("lane-a").expect("lane id");
        let ledger = Ledger::open_in_memory().unwrap();
        seed_lane(&ledger, &lane);
        let port = test_gateway::serve_n(2, embeddings_reply());
        let executor = fixture_executor(port, ledger);
        let first = Arc::clone(&executor).bind_lane(&lane).expect("first bind");
        first(&query()).expect("embedding under the first binding");
        let adopted = {
            let ledger = executor.ledger.lock().expect("ledger lock");
            ledger
                .active_provider_lease_for_lane(&lane)
                .expect("active lease read")
                .expect("an active lease exists")
                .lease_id
        };
        drop(first);
        let second = Arc::clone(&executor)
            .bind_lane(&lane)
            .expect("recreated binding");
        second(&query()).expect("embedding under the recreated binding");
        let ledger = executor.ledger.lock().expect("ledger lock");
        let leases = ledger
            .provider_leases_for_lane(&lane)
            .expect("lane lease rows");
        assert_eq!(
            leases.len(),
            1,
            "rebinding a dropped lane mints no new lease row"
        );
        assert_eq!(
            leases[0].lease_id, adopted,
            "the recreated binding re-adopts the persisted active lease"
        );
    }

    #[test]
    fn absent_lane_refuses_typed_and_writes_nothing() {
        let lane = LaneId::new("lane-missing").expect("lane id");
        let ledger = Ledger::open_in_memory().unwrap();
        // The gateway endpoint is a live listener the refusal must never
        // touch: nonblocking, no server thread, WouldBlock proves no
        // connection attempt.
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind gateway listener");
        let port = listener.local_addr().expect("listener address").port();
        listener
            .set_nonblocking(true)
            .expect("nonblocking gateway listener");
        let executor = fixture_executor(port, ledger);
        let embedder = Arc::clone(&executor)
            .bind_lane(&lane)
            .expect("bind resolves; the lane row law binds at the first lease");
        let error = embedder(&query()).expect_err("a missing lane row must refuse typed");
        assert!(
            matches!(error, BrainError::Unavailable { .. }),
            "the missing-lane refusal must be typed, got {error:?}"
        );
        assert!(
            matches!(listener.accept(), Err(accept) if accept.kind() == std::io::ErrorKind::WouldBlock),
            "the refused request must never reach the gateway"
        );
        let ledger = executor.ledger.lock().expect("ledger lock");
        assert!(
            odin_ledger::lane_run::read_lane(ledger.connection(), &lane)
                .expect("lane read")
                .is_none(),
            "the embedding path must never fabricate a lanes row"
        );
        assert!(
            ledger
                .provider_leases_for_lane(&lane)
                .expect("lease read")
                .is_empty(),
            "a refused lease must never persist a lease row"
        );
    }
}

#[cfg(test)]
mod embedding_protocol_tests {
    //! Wire-level checks of framing, truncation, normalization, and undeclared protocols.

    use super::test_gateway;
    use super::{
        EmbeddingFramingToml, EmbeddingProtocolToml, KernelEmbeddingExecutor,
        PrivateGatewayTransport, QueryEmbedder,
    };
    use crate::error::BrainError;
    use crate::retrieval::LaneEmbeddingProvider;
    use odin_domain::{LaneId, ProviderId, SeatId};
    use odin_kernel::provider::ProviderCoordinatorTemplate;
    use odin_ledger::lane_run::{create_lane, NewLane};
    use odin_ledger::Ledger;
    use odin_registry::schema::{
        parse_object_toml, RecoveryAttemptLimitsToml, RecoveryCooldownsToml, RecoveryPolicyToml,
        RecoveryRungToml, RegistryKind, RegistryObject, ResolvedProviderPolicy,
        ResolvedProviderRoute, ResolvedRecoveryPolicy,
    };
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use time::OffsetDateTime;

    const GATEWAY_TOML: &str = concat!(
        "schema = \"odin.registry.v1\"\n",
        "kind = \"provider\"\n",
        "enabled = true\n",
        "description = \"Loopback fixture gateway for lane-bound embedding tests.\"\n",
        "adapter = \"litellm-gateway\"\n",
        "policy = { routes = [{ gateway_lane_id = \"zai-glm\", gateway_model_id = \"openai/test-embedding\" }] }\n",
        "recovery = { allowed_rungs = [\"escalate\"], blocked_missing_decision = \"operator decision required\", max_attempts = { retry = 0, restart_worker = 0, checkpoint = 0, rehome = 0, escalate = 1 }, cooldown_seconds = { retry = 0, restart_worker = 0, checkpoint = 0, rehome = 0, escalate = 0 } }\n"
    );

    /// The declared WeMM embedding protocol under test, exactly as the
    /// brain-embedding provider declares it.
    fn wemm_protocol() -> EmbeddingProtocolToml {
        EmbeddingProtocolToml {
            id: "wemm-im-user-v1".to_owned(),
            framing: EmbeddingFramingToml::ImUserV1,
            truncate_tokens: 256,
            l2_normalize: true,
        }
    }

    fn fixture_objects() -> Vec<RegistryObject> {
        vec![parse_object_toml(
            RegistryKind::Provider,
            "gateway",
            "registry/providers/gateway/provider.toml",
            GATEWAY_TOML,
        )
        .expect("fixture provider object")]
    }

    fn fixture_policy(protocol: Option<EmbeddingProtocolToml>) -> ResolvedProviderPolicy {
        let recovery = RecoveryPolicyToml {
            max_attempts: RecoveryAttemptLimitsToml {
                retry: 0,
                restart_worker: 0,
                checkpoint: 0,
                rehome: 0,
                escalate: 1,
            },
            cooldown_seconds: RecoveryCooldownsToml {
                retry: 0,
                restart_worker: 0,
                checkpoint: 0,
                rehome: 0,
                escalate: 0,
            },
            allowed_rungs: BTreeSet::from([RecoveryRungToml::Escalate]),
            blocked_missing_decision: "operator decision required".to_owned(),
        };
        ResolvedProviderPolicy {
            budget: None,
            recovery: ResolvedRecoveryPolicy {
                registry_revision: 1,
                policy_digest: odin_domain::Digest::hash(b"recovery-policy"),
                filtered_rungs: vec![RecoveryRungToml::Escalate],
                policy: recovery,
            },
            provider_id: ProviderId::new("gateway").expect("provider id"),
            registry_revision: 1,
            policy_digest: odin_domain::Digest::hash(b"provider-policy"),
            projection_digest: odin_domain::Digest::hash(b"projection"),
            routes: vec![ResolvedProviderRoute {
                gateway_lane_id: "zai-glm".to_owned(),
                gateway_model_id: "openai/test-embedding".to_owned(),
                account_handle: "gateway-primary".to_owned(),
                endpoint: "http://127.0.0.1:4000".to_owned(),
                credential_handle: "litellm-master-key".to_owned(),
                role: "embedding".to_owned(),
                affinity_key: "skuld".to_owned(),
                priority: 0,
                protocol,
            }],
        }
    }

    fn fixture_executor(
        port: u16,
        ledger: Ledger,
        protocol: Option<EmbeddingProtocolToml>,
    ) -> Arc<KernelEmbeddingExecutor> {
        let template = Arc::new(
            ProviderCoordinatorTemplate::from_resolved_policy(
                &fixture_objects(),
                None,
                &fixture_policy(protocol.clone()),
            )
            .expect("template resolves"),
        );
        Arc::new(KernelEmbeddingExecutor::new(
            ProviderId::new("gateway").expect("provider id"),
            template,
            ledger,
            PrivateGatewayTransport::new(format!("127.0.0.1:{port}")).expect("loopback endpoint"),
            protocol,
        ))
    }

    fn seed_lane(ledger: &Ledger, lane: &LaneId) {
        create_lane(
            ledger.connection(),
            &NewLane {
                lane_id: lane.clone(),
                seat_id: SeatId::new("seat-a").expect("seat id"),
                project_id: None,
                template_id: "template-a".to_owned(),
                backend: "local_omp".to_owned(),
                created_by: "test".to_owned(),
                created_at: OffsetDateTime::UNIX_EPOCH,
                retained: false,
            },
        )
        .expect("seed lane row");
    }

    fn query_with(text: &str) -> Vec<String> {
        vec![text.to_owned()]
    }

    /// One successful OpenAI-compatible single-embedding reply.
    fn unit_reply(dims: &[f32]) -> Vec<u8> {
        let dims: Vec<String> = dims.iter().map(|dim| dim.to_string()).collect();
        let body = format!(
            r#"{{"data":[{{"index":0,"embedding":[{}]}}]}}"#,
            dims.join(",")
        );
        let mut reply = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        reply.extend_from_slice(body.as_bytes());
        reply
    }

    fn bound_embedder(
        ledger: Ledger,
        protocol: Option<EmbeddingProtocolToml>,
        reply: Vec<u8>,
    ) -> (
        Arc<QueryEmbedder>,
        std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) {
        let lane = LaneId::new("lane-a").expect("lane id");
        seed_lane(&ledger, &lane);
        let (port, bodies) = test_gateway::serve_n_capturing(1, reply);
        let executor = fixture_executor(port, ledger, protocol);
        let embedder = Arc::clone(&executor).bind_lane(&lane).expect("bind");
        (embedder, bodies)
    }

    #[test]
    fn declared_protocol_frames_the_query_input() {
        let (embedder, bodies) = bound_embedder(
            Ledger::open_in_memory().unwrap(),
            Some(wemm_protocol()),
            unit_reply(&[0.5, -0.25]),
        );
        embedder(&query_with("hello retrieval")).expect("embedding under the binding");
        let body = bodies.lock().expect("bodies")[0].clone();
        let request: serde_json::Value = serde_json::from_str(&body).expect("json body");
        assert_eq!(
            request["input"][0].as_str().expect("one string input"),
            "<|im_start|>user\nhello retrieval<|im_end|>",
            "the declared WeMM framing must wrap the input exactly once, with no \
             client EOS and no trailing newline; wire body was: {body}"
        );
        assert!(
            !body.contains("<|endoftext|>"),
            "the client must never append an EOS token; wire body was: {body}"
        );
    }

    #[test]
    fn declared_protocol_prefix_truncates_to_256_tokens() {
        let (embedder, bodies) = bound_embedder(
            Ledger::open_in_memory().unwrap(),
            Some(wemm_protocol()),
            unit_reply(&[0.5, -0.25]),
        );
        let text: String = (0..300)
            .map(|index| char::from(b'a' + (index % 26) as u8))
            .collect();
        let expected_prefix: String = text.chars().take(256).collect();
        embedder(&query_with(&text)).expect("embedding under the binding");
        let body = bodies.lock().expect("bodies")[0].clone();
        let request: serde_json::Value = serde_json::from_str(&body).expect("json body");
        assert_eq!(
            request["input"][0].as_str().expect("one string input"),
            format!("<|im_start|>user\n{expected_prefix}<|im_end|>"),
            "the declared protocol must prefix-truncate to 256 pinned tokens \
             before framing; wire body was: {body}"
        );
    }

    #[test]
    fn declared_protocol_truncates_on_a_character_boundary() {
        let (embedder, bodies) = bound_embedder(
            Ledger::open_in_memory().unwrap(),
            Some(wemm_protocol()),
            unit_reply(&[0.5, -0.25]),
        );
        let text = format!("{}é", "x".repeat(255));
        embedder(&query_with(&text)).expect("embedding under the binding");
        let body = bodies.lock().expect("bodies")[0].clone();
        let request: serde_json::Value = serde_json::from_str(&body).expect("json body");
        assert_eq!(
            request["input"][0].as_str().expect("one string input"),
            format!("<|im_start|>user\n{}<|im_end|>", "x".repeat(255)),
            "truncation must snap back to a UTF-8 character boundary instead of \
             splitting the multibyte character; wire body was: {body}"
        );
    }

    #[test]
    fn declared_protocol_returns_unit_norm_vectors() {
        let (embedder, _bodies) = bound_embedder(
            Ledger::open_in_memory().unwrap(),
            Some(wemm_protocol()),
            unit_reply(&[3.0, 4.0]),
        );
        let vector = embedder(&query_with("hello retrieval"))
            .expect("embedding under the binding")
            .remove(0);
        let dims = vector.dims();
        assert!(
            (dims[0] - 0.6).abs() < 1e-6 && (dims[1] - 0.8).abs() < 1e-6,
            "the declared L2 protocol must normalize returned vectors to unit \
             norm; got {dims:?}"
        );
        let norm = dims
            .iter()
            .map(|dim| f64::from(*dim) * f64::from(*dim))
            .sum::<f64>()
            .sqrt();
        assert!(
            (norm - 1.0).abs() < 1e-5,
            "the normalized vector must carry unit Euclidean norm; got {norm}"
        );
    }

    #[test]
    fn declared_protocol_refuses_zero_norm_vectors_typed() {
        let (embedder, _bodies) = bound_embedder(
            Ledger::open_in_memory().unwrap(),
            Some(wemm_protocol()),
            unit_reply(&[0.0, 0.0]),
        );
        let error = embedder(&query_with("hello retrieval"))
            .expect_err("a zero-norm vector must be refused, never normalized into NaNs");
        match &error {
            BrainError::EmbeddingUnavailable { reason, .. } => {
                assert!(
                    reason.contains("zero-norm"),
                    "the refusal must name the zero-norm vector; got {reason:?}"
                );
            }
            other => panic!("the zero-norm refusal must be typed, got {other:?}"),
        }
    }

    #[test]
    fn absent_protocol_keeps_raw_inputs_and_vectors() {
        let (embedder, bodies) = bound_embedder(
            Ledger::open_in_memory().unwrap(),
            None,
            unit_reply(&[0.5, -0.25]),
        );
        let vector = embedder(&query_with("hello retrieval"))
            .expect("embedding under the binding")
            .remove(0);
        let body = bodies.lock().expect("bodies")[0].clone();
        let request: serde_json::Value = serde_json::from_str(&body).expect("json body");
        assert_eq!(
            request["input"][0].as_str().expect("one string input"),
            "hello retrieval",
            "an undeclared protocol must keep the raw wire behavior; wire body \
             was: {body}"
        );
        assert_eq!(
            vector.dims(),
            [0.5, -0.25],
            "an undeclared protocol must never normalize returned vectors"
        );
    }
}
