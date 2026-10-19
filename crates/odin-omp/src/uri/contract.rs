//! Canonical URI contracts for the scoped router: the seven registered schemes,
//! request/result/error vocabulary, the deterministic scheme table, and the
//! reject-before-storage grammar.

use std::collections::BTreeSet;
use std::fmt;

use odin_atlas::SourceClass;
use odin_domain::{LaneId, RunId, Scope, SessionId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::ScopedUriRouter;

/// Content type of every canonical JSON snapshot.
pub const JSON_CONTENT_TYPE: &str = "application/json";
/// Default requested content type for `odin-artifact://` before registered metadata is proven.
pub const ARTIFACT_CONTENT_TYPE: &str = "application/octet-stream";
/// Upper bound for one URI request; canonical identifiers never exceed 128 bytes.
const MAX_URI_BYTES: usize = 1024;
/// Mirrors `odin_domain` identifier bounds for schemes without a typed identifier.
const MAX_ID_BYTES: usize = 128;

/// Pinned OMP protocol-v2 chunk payload budget: an artifact result must fit one outbound
/// unchunked JSONL frame (1,048,576 bytes physical, newline included, base64-in-JSON
/// overhead included), so the transport-derived ceiling is the chunk payload itself.
pub const OMP_CHUNK_PAYLOAD_BYTES: u64 = 262_144;
/// Hard ceiling for the constructor-injected artifact read bound, derived from the pinned
/// OMP transport budget above rather than an arbitrary number.
pub const MAX_ARTIFACT_READ_BOUND: u64 = OMP_CHUNK_PAYLOAD_BYTES;

/// The exactly seven registered schemes, in deterministic listing order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum UriScheme {
    Approval,
    Artifact,
    Atlas,
    Brain,
    Incident,
    Lane,
    Run,
}

impl UriScheme {
    pub const ALL: [UriScheme; 7] = [
        UriScheme::Approval,
        UriScheme::Artifact,
        UriScheme::Atlas,
        UriScheme::Brain,
        UriScheme::Incident,
        UriScheme::Lane,
        UriScheme::Run,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            UriScheme::Approval => "approval",
            UriScheme::Artifact => "odin-artifact",
            UriScheme::Atlas => "atlas",
            UriScheme::Brain => "brain",
            UriScheme::Incident => "incident",
            UriScheme::Lane => "lane",
            UriScheme::Run => "run",
        }
    }

    /// Exact-name lookup; the canonical form is lowercase and scheme case is significant.
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|scheme| scheme.as_str() == text)
    }
}

/// The only operation a URI may carry besides a read; writes never enter a resolver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UriOperation {
    Read,
    Write,
}

/// A validated request retaining the exact requested URL and its stated content contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UriRequest {
    pub url: String,
    pub operation: UriOperation,
    pub scheme: UriScheme,
    pub id: Option<String>,
    pub content_type: String,
    pub immutable: bool,
}

/// Session, run, lane, and epoch captured from the host's bridge at dispatch.
/// The journal retains this immutable snapshot for replay; it is never refreshed
/// from the ledger or supplied by the model, so reclaim makes old calls stale.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionBinding {
    session_id: SessionId,
    run_id: RunId,
    lane_id: LaneId,
    epoch: i64,
}

impl ExecutionBinding {
    /// Captures the host binding verbatim; epoch zero fails against a started session.
    pub fn from_binding(binding: &crate::bridge::BridgeBinding) -> Self {
        Self {
            session_id: binding.session_id.clone(),
            run_id: binding.run_id.clone(),
            lane_id: binding.lane_id.clone(),
            epoch: binding.epoch,
        }
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    pub fn lane_id(&self) -> &LaneId {
        &self.lane_id
    }

    /// The live-session ownership epoch at capture time.
    pub fn epoch(&self) -> i64 {
        self.epoch
    }
}

#[derive(Clone, Debug)]
pub struct UriContext {
    pub scope: Scope,
    /// Required for brain reads and revalidated at the resolver before materialization.
    /// Other schemes do not require it.
    pub execution: Option<ExecutionBinding>,
}

impl UriContext {
    pub fn new(scope: Scope) -> Self {
        Self {
            scope,
            execution: None,
        }
    }

    pub fn with_execution(scope: Scope, execution: ExecutionBinding) -> Self {
        Self {
            scope,
            execution: Some(execution),
        }
    }
}

/// A resolved payload: canonical JSON or verified bytes. Every registered
/// scheme resolves for real; no deferral shape exists.
#[derive(Clone, Debug, PartialEq)]
pub enum UriBody {
    Json(Value),
    Bytes(Vec<u8>),
}

/// An immutable, deterministic resolution retaining the request, payload contract, and provenance.
#[derive(Clone, Debug, PartialEq)]
pub struct UriResult {
    pub request: UriRequest,
    pub content_type: String,
    pub immutable: bool,
    pub notes: Vec<String>,
    pub body: UriBody,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemeDefinition {
    pub scheme: UriScheme,
    pub requires_id: bool,
    pub content_type: &'static str,
    pub immutable: bool,
    pub implemented: bool,
    pub source: &'static str,
    pub notes: &'static [&'static str],
}

static SCHEME_DEFINITIONS: [SchemeDefinition; 7] = [
    SchemeDefinition {
        scheme: UriScheme::Approval,
        requires_id: true,
        content_type: JSON_CONTENT_TYPE,
        immutable: true,
        implemented: true,
        source: "odin-ledger approvals",
        notes: &[],
    },
    SchemeDefinition {
        scheme: UriScheme::Artifact,
        requires_id: true,
        content_type: ARTIFACT_CONTENT_TYPE,
        immutable: true,
        implemented: true,
        source: "odin-ledger artifact metadata and verified bytes",
        notes: &[],
    },
    SchemeDefinition {
        scheme: UriScheme::Atlas,
        requires_id: false,
        content_type: JSON_CONTENT_TYPE,
        immutable: true,
        implemented: true,
        source: "odin-atlas scoped query",
        notes: &[],
    },
    SchemeDefinition {
        scheme: UriScheme::Brain,
        requires_id: false,
        content_type: JSON_CONTENT_TYPE,
        immutable: true,
        implemented: true,
        source: "odin-brain BrainService",
        notes: &[
            "brain:// resolves knowledge items, archive records, and source authority snapshots through the injected BrainService",
            "one shared identifier grammar: brain://blake3:<item>, brain://record.blake3:<key>, brain://source.<name>; scope is proven against Atlas node provenance",
        ],
    },
    SchemeDefinition {
        scheme: UriScheme::Incident,
        requires_id: true,
        content_type: JSON_CONTENT_TYPE,
        immutable: true,
        implemented: true,
        source: "odin-ledger incident cards",
        notes: &[],
    },
    SchemeDefinition {
        scheme: UriScheme::Lane,
        requires_id: true,
        content_type: JSON_CONTENT_TYPE,
        immutable: true,
        implemented: true,
        source: "odin-ledger lane records",
        notes: &[],
    },
    SchemeDefinition {
        scheme: UriScheme::Run,
        requires_id: true,
        content_type: JSON_CONTENT_TYPE,
        immutable: true,
        implemented: true,
        source: "odin-ledger run records",
        notes: &[],
    },
];

/// The deterministic registration table for all seven schemes.
pub fn scheme_definitions() -> &'static [SchemeDefinition] {
    &SCHEME_DEFINITIONS
}

/// Requested narrowing of the constructor-injected allowed atlas scope. Every field can only
/// reduce visibility; anything outside the allowed scope is denied instead of silently dropped.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AtlasNarrowing {
    pub path_prefixes: Vec<String>,
    pub node_prefixes: Vec<String>,
    pub source_classes: BTreeSet<SourceClass>,
    pub seat_categories: Option<BTreeSet<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UriError {
    UnknownScheme {
        url: String,
        scheme: String,
    },
    WriteRejected {
        url: String,
    },
    CredentialsRejected {
        url: String,
    },
    FragmentRejected {
        url: String,
    },
    TraversalRejected {
        url: String,
    },
    EncodedBytesRejected {
        url: String,
    },
    ControlByteRejected {
        url: String,
    },
    NonCanonicalId {
        url: String,
        value: String,
        reason: String,
    },
    Malformed {
        url: String,
        reason: String,
    },
    UnknownResource {
        url: String,
        kind: &'static str,
        id: String,
    },
    ScopeDenied {
        url: String,
        reason: String,
    },
    /// Missing or stale execution context, terminal state, or mismatched scope.
    /// Brain reads fail before materialization.
    ExecutionProof {
        url: String,
        reason: String,
    },
    ArtifactMismatch {
        url: String,
        detail: String,
    },
    Storage {
        detail: String,
    },
    ConfigurationRejected {
        detail: String,
    },
}

impl fmt::Display for UriError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UriError::UnknownScheme { url, scheme } => {
                write!(formatter, "{url}: unknown URI scheme {scheme:?}")
            }
            UriError::WriteRejected { url } => {
                write!(
                    formatter,
                    "{url}: URI routing is read-only; writes are rejected"
                )
            }
            UriError::CredentialsRejected { url } => {
                write!(formatter, "{url}: URI credentials are rejected")
            }
            UriError::FragmentRejected { url } => {
                write!(formatter, "{url}: URI fragments are rejected")
            }
            UriError::TraversalRejected { url } => {
                write!(formatter, "{url}: URI path traversal is rejected")
            }
            UriError::EncodedBytesRejected { url } => write!(
                formatter,
                "{url}: percent-encoded bytes are rejected; canonical URIs carry raw identifiers"
            ),
            UriError::ControlByteRejected { url } => {
                write!(formatter, "{url}: URI control bytes are rejected")
            }
            UriError::NonCanonicalId { url, value, reason } => {
                write!(
                    formatter,
                    "{url}: identifier {value:?} is not canonical: {reason}"
                )
            }
            UriError::ExecutionProof { url, reason } => {
                write!(formatter, "{url}: execution proof rejected: {reason}")
            }
            UriError::Malformed { url, reason } => {
                write!(formatter, "{url}: malformed URI: {reason}")
            }
            UriError::UnknownResource { url, kind, id } => {
                write!(formatter, "{url}: {kind} {id} was not found")
            }
            UriError::ScopeDenied { url, reason } => {
                write!(formatter, "{url}: scope denial: {reason}")
            }
            UriError::ArtifactMismatch { url, detail } => {
                write!(formatter, "{url}: artifact verification failed: {detail}")
            }
            UriError::Storage { detail } => {
                write!(formatter, "URI storage failure: {detail}")
            }
            UriError::ConfigurationRejected { detail } => {
                write!(formatter, "URI router configuration rejected: {detail}")
            }
        }
    }
}

impl std::error::Error for UriError {}

impl ScopedUriRouter {
    /// Validates a URL against the canonical grammar without touching storage.
    pub fn parse(url: &str) -> Result<UriRequest, UriError> {
        let malformed = |reason: &str| UriError::Malformed {
            url: url.to_owned(),
            reason: reason.to_owned(),
        };

        if url.is_empty() {
            return Err(malformed("URI is empty"));
        }
        if url.len() > MAX_URI_BYTES {
            return Err(malformed("URI exceeds the canonical length bound"));
        }
        if url.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(UriError::ControlByteRejected {
                url: url.to_owned(),
            });
        }
        if url.chars().any(char::is_whitespace) {
            return Err(malformed("URI contains whitespace"));
        }
        if !url.is_ascii() {
            return Err(malformed("URI must be ASCII"));
        }
        let Some((scheme_text, remainder)) = url.split_once("://") else {
            return Err(malformed("URI lacks the :// authority separator"));
        };
        let Some(scheme) = UriScheme::parse(scheme_text) else {
            return Err(UriError::UnknownScheme {
                url: url.to_owned(),
                scheme: scheme_text.to_owned(),
            });
        };
        if remainder.contains('@') {
            return Err(UriError::CredentialsRejected {
                url: url.to_owned(),
            });
        }
        if remainder.contains('#') {
            return Err(UriError::FragmentRejected {
                url: url.to_owned(),
            });
        }
        if remainder.contains('%') {
            return Err(UriError::EncodedBytesRejected {
                url: url.to_owned(),
            });
        }
        if remainder.contains('?') {
            return Err(malformed("canonical URIs carry no query component"));
        }
        if remainder.contains('\\') {
            return Err(UriError::TraversalRejected {
                url: url.to_owned(),
            });
        }
        if remainder.contains('/') && scheme != UriScheme::Brain {
            if remainder.split('/').any(|segment| segment == "..") {
                return Err(UriError::TraversalRejected {
                    url: url.to_owned(),
                });
            }
            return Err(malformed("canonical URIs address a single identifier"));
        }

        let requires_id = matches!(
            scheme,
            UriScheme::Approval
                | UriScheme::Artifact
                | UriScheme::Incident
                | UriScheme::Lane
                | UriScheme::Run
        );
        let id = if remainder.is_empty() {
            if requires_id {
                return Err(malformed("canonical URI requires exactly one identifier"));
            }
            None
        } else {
            if scheme == UriScheme::Atlas {
                return Err(malformed(
                    "atlas URIs address the whole allowed scope and carry no identifier",
                ));
            }
            if scheme == UriScheme::Brain {
                super::brain_ids::parse_brain_id(url, remainder)?;
            } else {
                ensure_canonical_id(url, remainder)?;
            }
            Some(remainder.to_owned())
        };

        let content_type = match scheme {
            UriScheme::Artifact => ARTIFACT_CONTENT_TYPE,
            _ => JSON_CONTENT_TYPE,
        };
        Ok(UriRequest {
            url: url.to_owned(),
            operation: UriOperation::Read,
            scheme,
            id,
            content_type: content_type.to_owned(),
            immutable: true,
        })
    }
}

fn ensure_canonical_id(url: &str, value: &str) -> Result<(), UriError> {
    let reason = if value.is_empty() {
        Some("must not be empty")
    } else if value.len() > MAX_ID_BYTES {
        Some("must not exceed 128 bytes")
    } else if !value
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
    {
        Some("must start with an ASCII alphanumeric character")
    } else if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        Some("must contain only ASCII alphanumeric characters or '.', '_', ':', and '-'")
    } else {
        None
    };
    let Some(reason) = reason else {
        return Ok(());
    };
    Err(UriError::NonCanonicalId {
        url: url.to_owned(),
        value: value.to_owned(),
        reason: reason.to_owned(),
    })
}

pub(super) fn malformed(url: &str, reason: &str) -> UriError {
    UriError::Malformed {
        url: url.to_owned(),
        reason: reason.to_owned(),
    }
}
