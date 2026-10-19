//! Per-session safety gate for sensitive outbound data and malware verdicts.
//!
//! The gate is one of the immutable adapter boundaries: it inspects outbound
//! text and form data for *configured* protected values, and hands staged
//! download files to the *configured* malware scanner. It carries no site,
//! domain, MIME, extension, or download-format knowledge whatsoever, and it
//! has no permissive built-in: a gate cannot be constructed without both a
//! protected-value set and a scanner, and a scanner failure never yields a
//! clean verdict. Verdicts are facts for the session actor, never policy;
//! session policy lives in [`crate::policy`] and the two never mix.

use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use odin_domain::Digest;
use thiserror::Error;
use uuid::Uuid;

/// Upper bound on protected values configured for one session.
pub const MAX_PROTECTED_VALUES: usize = 1024;
pub const MAX_PROTECTED_VALUE_BYTES: usize = 4096;
pub const MAX_PROTECTED_LABEL_BYTES: usize = 128;
/// Upper bound on an outbound field label copied into block metadata.
pub const MAX_OUTBOUND_FIELD_BYTES: usize = 128;
/// Upper bound on outbound fragments inspected per action.
pub const MAX_OUTBOUND_FRAGMENTS: usize = 256;
pub const MAX_OUTBOUND_FRAGMENT_BYTES: usize = 256 * 1024;

/// One configured secret that must never appear in outbound browser data.
///
/// `bytes` is the secret itself and is never projected into any output; only
/// `label` ever reaches metadata, so labels must stay free of secret material.
#[derive(Clone)]
pub struct ProtectedValue {
    label: String,
    bytes: Vec<u8>,
}

impl ProtectedValue {
    /// A value is configured with a metadata-safe label and its secret bytes.
    pub fn new(label: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            label: label.into(),
            bytes,
        }
    }

    /// Labels the value for evidence and block-reason metadata.
    pub fn label(&self) -> &str {
        &self.label
    }
}

impl std::fmt::Debug for ProtectedValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProtectedValue")
            .field("label", &self.label)
            .field("bytes", &format!("[{} secret bytes]", self.bytes.len()))
            .finish()
    }
}

/// The protected-value set configured for one session by higher authority.
#[derive(Clone)]
pub struct ProtectedValues {
    values: Vec<ProtectedValue>,
    matcher: AhoCorasick,
}

impl std::fmt::Debug for ProtectedValues {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProtectedValues")
            .field("count", &self.values.len())
            .finish_non_exhaustive()
    }
}

impl ProtectedValues {
    /// Validates and compiles the configured values into one aggregate
    /// linear-time matcher. An empty set would silently permit every outbound
    /// fragment, so it is rejected along with empty values, oversized values,
    /// duplicate labels, and control-character labels.
    pub fn new(values: Vec<ProtectedValue>) -> Result<Self, SafetyConfigError> {
        if values.is_empty() {
            return Err(SafetyConfigError::NoProtectedValues);
        }
        if values.len() > MAX_PROTECTED_VALUES {
            return Err(SafetyConfigError::TooManyValues {
                count: values.len(),
                limit: MAX_PROTECTED_VALUES,
            });
        }
        let mut seen = std::collections::HashSet::with_capacity(values.len());
        for value in &values {
            if value.label.is_empty() {
                return Err(SafetyConfigError::EmptyLabel);
            }
            if value.label.len() > MAX_PROTECTED_LABEL_BYTES {
                return Err(SafetyConfigError::LabelTooLong {
                    len: value.label.len(),
                    limit: MAX_PROTECTED_LABEL_BYTES,
                });
            }
            if value.label.bytes().any(|byte| byte.is_ascii_control()) {
                return Err(SafetyConfigError::LabelControlChars);
            }
            if value.bytes.is_empty() {
                return Err(SafetyConfigError::EmptyValue {
                    label: value.label.clone(),
                });
            }
            if value.bytes.len() > MAX_PROTECTED_VALUE_BYTES {
                return Err(SafetyConfigError::ValueTooLong {
                    label: value.label.clone(),
                    len: value.bytes.len(),
                    limit: MAX_PROTECTED_VALUE_BYTES,
                });
            }
            if !seen.insert(value.label.clone()) {
                return Err(SafetyConfigError::DuplicateLabel {
                    label: value.label.clone(),
                });
            }
        }
        let matcher = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostFirst)
            .build(values.iter().map(|value| value.bytes.as_slice()))
            .map_err(|_| SafetyConfigError::MatcherBuild)?;
        Ok(Self { values, matcher })
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    fn keyed_fingerprint(&self, key: &[u8; 32]) -> Digest {
        let mut hasher = blake3::Hasher::new_keyed(key);
        for value in &self.values {
            hasher.update(&(value.label.len() as u64).to_le_bytes());
            hasher.update(value.label.as_bytes());
            hasher.update(&(value.bytes.len() as u64).to_le_bytes());
            hasher.update(&value.bytes);
        }
        Digest::new(*hasher.finalize().as_bytes())
    }
}

/// Fail-closed errors raised while configuring the safety gate.
#[derive(Debug, Error)]
pub enum SafetyConfigError {
    #[error("at least one protected value must be configured")]
    NoProtectedValues,
    #[error("protected value label must not be empty")]
    EmptyLabel,
    #[error("protected value label is {len} bytes; limit is {limit}")]
    LabelTooLong { len: usize, limit: usize },
    #[error("protected value label must not contain control characters")]
    LabelControlChars,
    #[error("protected value {label:?} is configured twice")]
    DuplicateLabel { label: String },
    #[error("protected value {label:?} must not be empty")]
    EmptyValue { label: String },
    #[error("protected value {label:?} is {len} bytes; limit is {limit}")]
    ValueTooLong {
        label: String,
        len: usize,
        limit: usize,
    },
    #[error("{count} protected values configured; limit is {limit}")]
    TooManyValues { count: usize, limit: usize },
    #[error("protected values could not be compiled into a bounded matcher")]
    MatcherBuild,
}

/// Malware scanner verdict for one staged download.
///
/// Only the scanner can produce [`MalwareVerdict::Malicious`]; unknown
/// formats, unusual MIME types, and uncommon extensions are not verdicts and
/// never appear in this type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MalwareVerdict {
    Clean,
    Malicious {
        /// Scanner-provided signature label; safe for metadata.
        signature: String,
    },
}

impl MalwareVerdict {
    /// A signature must be short, non-empty, and metadata-safe; anything else
    /// is an unusable scanner response and fails closed.
    pub fn validate_signature(signature: &str) -> Result<(), ScanFailure> {
        if signature.is_empty()
            || signature.len() > 256
            || signature.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(ScanFailure::InvalidVerdict);
        }
        Ok(())
    }
}

/// Fixed scanner failure classes. Implementations keep engine diagnostics
/// private; only these bounded codes may reach browser projections.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ScanFailure {
    #[error("scanner unavailable")]
    Unavailable,
    #[error("scanner deadline exceeded")]
    DeadlineExceeded,
    #[error("scanner was cancelled")]
    Cancelled,
    #[error("scanner returned an invalid verdict")]
    InvalidVerdict,
}

impl ScanFailure {
    /// Stable bounded code suitable for projected metadata.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "scanner_unavailable",
            Self::DeadlineExceeded => "scanner_deadline_exceeded",
            Self::Cancelled => "scanner_cancelled",
            Self::InvalidVerdict => "scanner_invalid_verdict",
        }
    }
}

/// Deadline and cancellation signal shared with one running scan.
///
/// A scanner must monitor both independently of the caller so dropping the
/// outer future cannot orphan a scanner process.
#[derive(Clone, Debug)]
pub struct ScanControl {
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
}

impl ScanControl {
    pub(crate) fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Absolute deadline by which the scanner must terminate and reap.
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Remaining scan time, saturating at zero.
    pub fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    /// Whether the caller cancelled or abandoned this scan.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

/// One started scanner operation.
///
/// `kill` must be idempotent, thread-safe, and non-blocking; it must signal
/// every scanner process to terminate. `wait` must reap those processes before
/// returning and must unblock after `kill`. Dropping the final handle must
/// also terminate and reap an unfinished scan.
pub trait MalwareScan: Send + Sync {
    fn wait(&self) -> Result<MalwareVerdict, ScanFailure>;
    fn kill(&self);
}

/// The malware scanner configured for one session.
///
/// Implementations wrap a concrete engine. Production can use
/// [`crate::scanner::ExecutableMalwareScanner`] with an explicitly declared
/// executable and argument vector. The adapter never supplies a default:
/// every [`BrowserSafetyGate`] still requires a scanner.
pub trait MalwareScanner: Send + Sync {
    fn start_download_scan(
        &self,
        file: File,
        byte_len: u64,
        control: ScanControl,
    ) -> Result<Arc<dyn MalwareScan>, ScanFailure>;
}

/// One outbound string, e.g. a filled field value or a navigation URL.
#[derive(Clone, Copy, Debug)]
pub struct OutboundFragment<'a> {
    /// Safe field name used in block metadata; never the value.
    pub field: &'a str,
    pub text: &'a str,
}

/// Why an outbound fragment was blocked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutboundBlockReason {
    /// The fragment carried a protected value; only its label is reported.
    ProtectedValue { label: String },
    /// The fragment exceeded inspection bounds and cannot be cleared.
    Uninspectable { detail: &'static str },
}

/// A concrete sensitive-egress failure. Never carries the matched content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundBlock {
    pub field: String,
    pub reason: OutboundBlockReason,
}

/// Verdict for outbound data on its way to the browser.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutboundVerdict {
    Allowed,
    Blocked(OutboundBlock),
}

/// The per-session safety gate.
///
/// Constructed with its protected values and scanner; no defaults exist.
pub struct BrowserSafetyGate {
    protected: ProtectedValues,
    protected_fingerprint: Digest,
    scanner: Box<dyn MalwareScanner>,
}

impl std::fmt::Debug for BrowserSafetyGate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrowserSafetyGate")
            .field("protected_values", &self.protected.values.len())
            .field("protected_fingerprint", &self.protected_fingerprint)
            .finish_non_exhaustive()
    }
}

impl BrowserSafetyGate {
    /// Builds the gate. Both authorities are mandatory; there is no
    /// configuration under which outbound data skips protected-value checks
    /// or downloads skip the scanner.
    pub fn new(protected: ProtectedValues, scanner: Box<dyn MalwareScanner>) -> Self {
        let protected_fingerprint = protected.keyed_fingerprint(&fresh_fingerprint_key());
        Self {
            protected,
            protected_fingerprint,
            scanner,
        }
    }

    /// Opaque per-session identity for this protected-value configuration.
    ///
    /// The fingerprint is keyed with fresh session randomness, so it cannot be
    /// used as an offline oracle for low-entropy protected values.
    pub const fn protected_fingerprint(&self) -> Digest {
        self.protected_fingerprint
    }

    /// Inspects outbound data for configured protected values.
    ///
    /// Matching is byte-exact substring detection by one compiled
    /// multi-pattern automaton; nothing else (patterns, sites, formats) is
    /// consulted. A fragment beyond inspection bounds fails closed.
    pub fn inspect_outbound(&self, fragments: &[OutboundFragment<'_>]) -> OutboundVerdict {
        if fragments.len() > MAX_OUTBOUND_FRAGMENTS {
            return OutboundVerdict::Blocked(OutboundBlock {
                field: "outbound".into(),
                reason: OutboundBlockReason::Uninspectable {
                    detail: "too many outbound fragments",
                },
            });
        }
        for fragment in fragments {
            let field = safe_outbound_field(fragment.field);
            if fragment.text.len() > MAX_OUTBOUND_FRAGMENT_BYTES {
                return OutboundVerdict::Blocked(OutboundBlock {
                    field: field.to_owned(),
                    reason: OutboundBlockReason::Uninspectable {
                        detail: "outbound fragment exceeds the inspection bound",
                    },
                });
            }
            if let Some(label) = self.matched_protected_value(fragment.text) {
                return OutboundVerdict::Blocked(OutboundBlock {
                    field: field.to_owned(),
                    reason: OutboundBlockReason::ProtectedValue {
                        label: label.to_owned(),
                    },
                });
            }
        }
        OutboundVerdict::Allowed
    }

    pub(crate) fn start_download_scan(
        &self,
        file: File,
        byte_len: u64,
        control: ScanControl,
    ) -> Result<ActiveMalwareScan, ScanFailure> {
        let inner = self.scanner.start_download_scan(file, byte_len, control)?;
        Ok(ActiveMalwareScan { inner })
    }

    fn matched_protected_value(&self, text: &str) -> Option<&str> {
        let matched = self.protected.matcher.find(text.as_bytes())?;
        self.protected
            .values
            .get(matched.pattern().as_usize())
            .map(|value| value.label.as_str())
    }
}

#[derive(Clone)]
pub(crate) struct ActiveMalwareScan {
    inner: Arc<dyn MalwareScan>,
}

impl ActiveMalwareScan {
    pub(crate) fn wait(&self) -> Result<MalwareVerdict, ScanFailure> {
        let verdict = self.inner.wait()?;
        if let MalwareVerdict::Malicious { signature } = &verdict {
            MalwareVerdict::validate_signature(signature)?;
        }
        Ok(verdict)
    }

    pub(crate) fn kill(&self) {
        self.inner.kill();
    }
}

fn fresh_fingerprint_key() -> [u8; 32] {
    let mut seed = [0_u8; 32];
    seed[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    seed[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    blake3::derive_key("odin-browser protected configuration fingerprint v1", &seed)
}

/// Keeps page/caller-provided field labels from becoming an unbounded or
/// control-character-bearing metadata channel.
fn safe_outbound_field(field: &str) -> &str {
    if !field.is_empty()
        && field.len() <= MAX_OUTBOUND_FIELD_BYTES
        && !field.bytes().any(|byte| byte.is_ascii_control())
    {
        field
    } else {
        "outbound"
    }
}
