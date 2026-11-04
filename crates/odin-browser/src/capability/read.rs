//! Confined read/projection construction. Every typed read carries full
//! provenance, always-[`TrustClass::Untrusted`] metadata, and mechanical
//! byte-bound accounting; each projection is validated both when constructed
//! and when deserialized, so a forged projection cannot be smuggled through
//! persistence.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use odin_domain::knowledge::retrieval::TrustClass;
use odin_domain::Digest;

use super::dom::{AccessibilityProjection, SanitizedDomProjection};
use super::error::CapabilityError;
use super::url::{restore_sanitized_url, SanitizedUrl};
use super::{
    MAX_FRAGMENT_BYTES, MAX_LINK_ENTRIES, MAX_READ_BYTES, MAX_TABLES, MAX_TABLE_COLUMNS,
    MAX_TABLE_ROWS,
};

/// Whether a projection represents the current live document or a retained
/// observation that has become stale. The externally tagged representation is
/// exactly the `browser.observe` schema: `{ "current": { "observedAt": ... } }`
/// or `{ "stale": { "observedAt": ..., "reason": ... } }`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    try_from = "ReadFreshnessParts"
)]
pub enum ReadFreshness {
    Current {
        observed_at: OffsetDateTime,
    },
    Stale {
        observed_at: OffsetDateTime,
        reason: String,
    },
}

impl ReadFreshness {
    pub const fn current(observed_at: OffsetDateTime) -> Self {
        Self::Current { observed_at }
    }

    pub fn stale(
        observed_at: OffsetDateTime,
        reason: impl Into<String>,
    ) -> Result<Self, CapabilityError> {
        let freshness = Self::Stale {
            observed_at,
            reason: reason.into(),
        };
        freshness.validate()?;
        Ok(freshness)
    }

    pub fn observed_at(&self) -> OffsetDateTime {
        match self {
            Self::Current { observed_at } | Self::Stale { observed_at, .. } => *observed_at,
        }
    }

    pub fn validate(&self) -> Result<(), CapabilityError> {
        if let Self::Stale { reason, .. } = self {
            if reason.trim().is_empty() {
                return Err(CapabilityError::InvalidRequest {
                    reason: "stale freshness reason must not be empty".to_owned(),
                });
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
enum ReadFreshnessParts {
    Current {
        observed_at: OffsetDateTime,
    },
    Stale {
        observed_at: OffsetDateTime,
        reason: String,
    },
}

impl TryFrom<ReadFreshnessParts> for ReadFreshness {
    type Error = CapabilityError;

    fn try_from(parts: ReadFreshnessParts) -> Result<Self, Self::Error> {
        match parts {
            ReadFreshnessParts::Current { observed_at } => Ok(Self::current(observed_at)),
            ReadFreshnessParts::Stale {
                observed_at,
                reason,
            } => Self::stale(observed_at, reason),
        }
    }
}

/// Mechanical byte-bound accounting attached to every typed read.
///
/// The report is validated both when constructed and when deserialized:
/// byte bounds are non-zero and globally capped, emitted bytes cannot exceed
/// the bound, and a known total cannot be smaller than the emitted prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "BoundReportParts")]
pub struct BoundReport {
    pub byte_bound: u64,
    pub emitted_bytes: u64,
    pub total_bytes: Option<u64>,
    pub truncated: bool,
}

impl BoundReport {
    pub fn new(
        byte_bound: u64,
        emitted_bytes: u64,
        total_bytes: Option<u64>,
        truncated: bool,
    ) -> Result<Self, CapabilityError> {
        let report = Self {
            byte_bound,
            emitted_bytes,
            total_bytes,
            truncated,
        };
        report.validate()?;
        Ok(report)
    }

    pub fn validate(&self) -> Result<(), CapabilityError> {
        if self.byte_bound == 0 {
            return Err(CapabilityError::InvalidRequest {
                reason: "byte_bound must be at least 1".to_owned(),
            });
        }
        if self.byte_bound > MAX_READ_BYTES {
            return Err(CapabilityError::BoundExceeded {
                limit: MAX_READ_BYTES,
                requested: self.byte_bound,
            });
        }
        if self.emitted_bytes > self.byte_bound {
            return Err(CapabilityError::BoundExceeded {
                limit: self.byte_bound,
                requested: self.emitted_bytes,
            });
        }
        if self
            .total_bytes
            .is_some_and(|total| total < self.emitted_bytes)
        {
            return Err(CapabilityError::InvalidRequest {
                reason: "total_bytes must not be smaller than emitted_bytes".to_owned(),
            });
        }
        if !self.truncated
            && self
                .total_bytes
                .is_some_and(|total| total != self.emitted_bytes)
        {
            return Err(CapabilityError::InvalidRequest {
                reason: "an untruncated bound must emit all known bytes".to_owned(),
            });
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BoundReportParts {
    byte_bound: u64,
    emitted_bytes: u64,
    total_bytes: Option<u64>,
    truncated: bool,
}

impl TryFrom<BoundReportParts> for BoundReport {
    type Error = CapabilityError;

    fn try_from(parts: BoundReportParts) -> Result<Self, Self::Error> {
        Self::new(
            parts.byte_bound,
            parts.emitted_bytes,
            parts.total_bytes,
            parts.truncated,
        )
    }
}

/// Provenance of one observed page read. All page content returned by this
/// crate carries exactly this metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "PageProvenanceParts")]
pub struct PageProvenance {
    pub source_url: SanitizedUrl,
    pub origin: String,
    pub exact_url_digest: Digest,
    pub document_digest: Digest,
    pub observed_at: OffsetDateTime,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PageProvenanceParts {
    source_url: String,
    origin: String,
    exact_url_digest: Digest,
    document_digest: Digest,
    observed_at: OffsetDateTime,
}

impl TryFrom<PageProvenanceParts> for PageProvenance {
    type Error = CapabilityError;

    fn try_from(parts: PageProvenanceParts) -> Result<Self, Self::Error> {
        Self::from_sanitized_parts(
            parts.source_url,
            parts.origin,
            parts.exact_url_digest,
            parts.document_digest,
            parts.observed_at,
        )
    }
}

impl PageProvenance {
    /// Builds provenance from worker-sanitized location fields and digests
    /// derived from the worker's opaque exact-URL and document tokens. The
    /// sanitized display URL is re-parsed here so userinfo, query, and fragment
    /// can never be restored through this construction path.
    pub(crate) fn from_sanitized_parts(
        display_url: String,
        origin: String,
        exact_url_digest: Digest,
        document_digest: Digest,
        observed_at: OffsetDateTime,
    ) -> Result<Self, CapabilityError> {
        let source_url = restore_sanitized_url(display_url, exact_url_digest, "source_url")?;
        if source_url.origin() != origin {
            return Err(CapabilityError::InvalidRequest {
                reason: "provenance origin does not match source_url".to_owned(),
            });
        }
        Ok(Self {
            source_url,
            origin,
            exact_url_digest,
            document_digest,
            observed_at,
        })
    }

    /// Revalidates the duplicated public provenance fields against the
    /// sanitized URL retained by this value.
    pub fn validate(&self) -> Result<(), CapabilityError> {
        if self.source_url.origin() != self.origin {
            return Err(CapabilityError::InvalidRequest {
                reason: "provenance origin does not match source_url".to_owned(),
            });
        }
        if self.source_url.exact_url_digest() != self.exact_url_digest {
            return Err(CapabilityError::DigestMismatch {
                recorded: self.exact_url_digest,
                computed: self.source_url.exact_url_digest(),
            });
        }
        Ok(())
    }
}

/// Metadata attached to every read projection. `trust` is always
/// [`TrustClass::Untrusted`]; deserialization rejects any other value so a
/// forged projection cannot be smuggled through persistence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "ReadMetadataParts")]
pub struct ReadMetadata {
    pub trust: TrustClass,
    pub provenance: PageProvenance,
    pub freshness: ReadFreshness,
    pub bound: BoundReport,
    pub token_estimate: u64,
    pub reason: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReadMetadataParts {
    trust: TrustClass,
    provenance: PageProvenance,
    freshness: ReadFreshness,
    bound: BoundReport,
    token_estimate: u64,
    reason: String,
}

impl TryFrom<ReadMetadataParts> for ReadMetadata {
    type Error = CapabilityError;

    fn try_from(parts: ReadMetadataParts) -> Result<Self, Self::Error> {
        if parts.trust != TrustClass::Untrusted {
            return Err(CapabilityError::InvalidRequest {
                reason: "read metadata must carry untrusted trust".to_owned(),
            });
        }
        parts.provenance.validate()?;
        parts.freshness.validate()?;
        parts.bound.validate()?;
        if parts.freshness.observed_at() != parts.provenance.observed_at {
            return Err(CapabilityError::InvalidRequest {
                reason: "freshness observed_at must match provenance observed_at".to_owned(),
            });
        }
        if parts.token_estimate != estimate_tokens(parts.bound.emitted_bytes) {
            return Err(CapabilityError::InvalidRequest {
                reason: "token_estimate does not match emitted_bytes".to_owned(),
            });
        }
        if parts.reason.trim().is_empty() {
            return Err(CapabilityError::InvalidRequest {
                reason: "read metadata reason must not be empty".to_owned(),
            });
        }
        Ok(Self {
            trust: parts.trust,
            provenance: parts.provenance,
            freshness: parts.freshness,
            bound: parts.bound,
            token_estimate: parts.token_estimate,
            reason: parts.reason,
        })
    }
}

impl ReadMetadata {
    pub fn validate(&self) -> Result<(), CapabilityError> {
        if self.trust != TrustClass::Untrusted {
            return Err(CapabilityError::InvalidRequest {
                reason: "read metadata must carry untrusted trust".to_owned(),
            });
        }
        self.provenance.validate()?;
        self.freshness.validate()?;
        self.bound.validate()?;
        if self.freshness.observed_at() != self.provenance.observed_at {
            return Err(CapabilityError::InvalidRequest {
                reason: "freshness observed_at must match provenance observed_at".to_owned(),
            });
        }
        if self.token_estimate != estimate_tokens(self.bound.emitted_bytes) {
            return Err(CapabilityError::InvalidRequest {
                reason: "token_estimate does not match emitted_bytes".to_owned(),
            });
        }
        if self.reason.trim().is_empty() {
            return Err(CapabilityError::InvalidRequest {
                reason: "read metadata reason must not be empty".to_owned(),
            });
        }
        Ok(())
    }
}
pub fn estimate_tokens(bytes: u64) -> u64 {
    bytes / 4
}

/// Inputs shared by every projection constructor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadBasis {
    pub provenance: PageProvenance,
    pub freshness: ReadFreshness,
    pub max_bytes: u64,
}

impl ReadBasis {
    pub fn new(
        provenance: PageProvenance,
        freshness: ReadFreshness,
        max_bytes: u64,
    ) -> Result<Self, CapabilityError> {
        let basis = Self {
            provenance,
            freshness,
            max_bytes,
        };
        basis.validate()?;
        Ok(basis)
    }

    pub fn validate(&self) -> Result<(), CapabilityError> {
        self.provenance.validate()?;
        self.freshness.validate()?;
        if self.freshness.observed_at() != self.provenance.observed_at {
            return Err(CapabilityError::InvalidRequest {
                reason: "freshness observed_at must match provenance observed_at".to_owned(),
            });
        }
        if self.max_bytes == 0 {
            return Err(CapabilityError::InvalidRequest {
                reason: "max_bytes must be at least 1".to_owned(),
            });
        }
        if self.max_bytes > MAX_READ_BYTES {
            return Err(CapabilityError::BoundExceeded {
                limit: MAX_READ_BYTES,
                requested: self.max_bytes,
            });
        }
        Ok(())
    }
}

pub(super) fn metadata(basis: &ReadBasis, bound: BoundReport, reason: &str) -> ReadMetadata {
    ReadMetadata {
        trust: TrustClass::Untrusted,
        provenance: basis.provenance.clone(),
        freshness: basis.freshness.clone(),
        bound,
        token_estimate: estimate_tokens(bound.emitted_bytes),
        reason: reason.to_owned(),
    }
}

/// Truncates `text` to `max_bytes` on a UTF-8 character boundary.
fn bounded_text(text: &str, max_bytes: u64) -> (&str, BoundReport) {
    let total = text.len() as u64;
    let limit = max_bytes.min(total) as usize;
    let mut cut = limit;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    let emitted = &text[..cut];
    let truncated = cut < text.len();
    let bound = BoundReport {
        byte_bound: max_bytes,
        emitted_bytes: cut as u64,
        total_bytes: Some(total),
        truncated,
    };
    (emitted, bound)
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ProjectionBudget {
    limit: u64,
    pub(super) emitted: u64,
}

impl ProjectionBudget {
    pub(super) const fn new(limit: u64) -> Self {
        Self { limit, emitted: 0 }
    }

    pub(super) const fn remaining(self) -> u64 {
        self.limit - self.emitted
    }

    pub(super) fn take_exact(&mut self, bytes: u64) -> bool {
        if bytes > self.remaining() {
            return false;
        }
        self.emitted += bytes;
        true
    }

    pub(super) fn take_fragment(&mut self, mut text: String) -> String {
        let limit = self.remaining().min(MAX_FRAGMENT_BYTES as u64);
        truncate_owned_text(&mut text, limit);
        self.emitted += text.len() as u64;
        text
    }
}

fn truncate_owned_text(text: &mut String, max_bytes: u64) {
    let mut cut = usize::try_from(max_bytes)
        .unwrap_or(usize::MAX)
        .min(text.len());
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text.truncate(cut);
}

pub(super) fn add_string_bytes(total: &mut u64, text: &str) {
    *total = total.saturating_add(text.len() as u64);
}

pub(super) fn validate_projection_bytes(
    metadata: &ReadMetadata,
    emitted_bytes: u64,
) -> Result<(), CapabilityError> {
    metadata.validate()?;
    if metadata.bound.emitted_bytes != emitted_bytes {
        return Err(CapabilityError::InvalidRequest {
            reason: "projection payload does not match emitted_bytes".to_owned(),
        });
    }
    Ok(())
}

pub(super) fn collect_reason(basis: &ReadBasis, bound: &BoundReport, suffix: &str) -> String {
    if bound.truncated {
        format!("truncated at {} byte bound; {suffix}", basis.max_bytes)
    } else {
        format!("complete within bound; {suffix}")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "TextProjectionParts")]
pub struct TextProjection {
    pub metadata: ReadMetadata,
    pub text: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TextProjectionParts {
    metadata: ReadMetadata,
    text: String,
}

impl TryFrom<TextProjectionParts> for TextProjection {
    type Error = CapabilityError;

    fn try_from(parts: TextProjectionParts) -> Result<Self, Self::Error> {
        let projection = Self {
            metadata: parts.metadata,
            text: parts.text,
        };
        projection.validate()?;
        Ok(projection)
    }
}

impl TextProjection {
    pub fn build(basis: ReadBasis, text: String) -> Result<Self, CapabilityError> {
        basis.validate()?;
        let (emitted, bound) = bounded_text(&text, basis.max_bytes);
        let reason = collect_reason(&basis, &bound, "plain text projection");
        Ok(Self {
            metadata: metadata(&basis, bound, &reason),
            text: emitted.to_owned(),
        })
    }

    pub fn validate(&self) -> Result<(), CapabilityError> {
        validate_projection_bytes(&self.metadata, self.text.len() as u64)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "LinkEntryParts")]
pub struct LinkEntry {
    pub url: SanitizedUrl,
    pub url_digest: Digest,
    pub text: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LinkEntryParts {
    url: String,
    url_digest: Digest,
    text: String,
}

impl TryFrom<LinkEntryParts> for LinkEntry {
    type Error = CapabilityError;

    fn try_from(parts: LinkEntryParts) -> Result<Self, Self::Error> {
        Self::from_sanitized_parts(parts.url, parts.url_digest, parts.text)
    }
}

impl LinkEntry {
    /// Builds one link from a worker-sanitized display URL and the BLAKE3
    /// digest of its opaque exact-URL token. The display URL is independently
    /// revalidated before it can enter a typed projection.
    pub(crate) fn from_sanitized_parts(
        display_url: String,
        url_digest: Digest,
        text: String,
    ) -> Result<Self, CapabilityError> {
        let url = restore_sanitized_url(display_url, url_digest, "link url")?;
        let link = Self {
            url,
            url_digest,
            text,
        };
        link.validate()?;
        Ok(link)
    }

    fn validate(&self) -> Result<(), CapabilityError> {
        if self.url.exact_url_digest() != self.url_digest {
            return Err(CapabilityError::DigestMismatch {
                recorded: self.url_digest,
                computed: self.url.exact_url_digest(),
            });
        }
        if self.text.len() > MAX_FRAGMENT_BYTES {
            return Err(CapabilityError::BoundExceeded {
                limit: MAX_FRAGMENT_BYTES as u64,
                requested: self.text.len() as u64,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "LinksProjectionParts")]
pub struct LinksProjection {
    pub metadata: ReadMetadata,
    pub links: Vec<LinkEntry>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LinksProjectionParts {
    metadata: ReadMetadata,
    links: Vec<LinkEntry>,
}

impl TryFrom<LinksProjectionParts> for LinksProjection {
    type Error = CapabilityError;

    fn try_from(parts: LinksProjectionParts) -> Result<Self, Self::Error> {
        let projection = Self {
            metadata: parts.metadata,
            links: parts.links,
        };
        projection.validate()?;
        Ok(projection)
    }
}

impl LinksProjection {
    pub fn build(basis: ReadBasis, links: Vec<LinkEntry>) -> Result<Self, CapabilityError> {
        basis.validate()?;
        let total = links.len();
        let mut total_bytes = 0_u64;
        for link in &links {
            add_string_bytes(&mut total_bytes, link.url.display_url());
            add_string_bytes(&mut total_bytes, &link.text);
        }

        let mut budget = ProjectionBudget::new(basis.max_bytes);
        let mut kept = Vec::new();
        for mut link in links.into_iter().take(MAX_LINK_ENTRIES) {
            if link.url.exact_url_digest() != link.url_digest {
                return Err(CapabilityError::DigestMismatch {
                    recorded: link.url_digest,
                    computed: link.url.exact_url_digest(),
                });
            }
            if !budget.take_exact(link.url.display_url().len() as u64) {
                break;
            }
            link.text = budget.take_fragment(link.text);
            kept.push(link);
            if budget.remaining() == 0 {
                break;
            }
        }
        let truncated = total > kept.len() || total_bytes > budget.emitted;
        let bound = BoundReport::new(
            basis.max_bytes,
            budget.emitted,
            Some(total_bytes),
            truncated,
        )?;
        let reason = collect_reason(
            &basis,
            &bound,
            &format!(
                "{total} links observed, {} kept (bound {MAX_LINK_ENTRIES})",
                kept.len()
            ),
        );
        Ok(Self {
            metadata: metadata(&basis, bound, &reason),
            links: kept,
        })
    }

    pub fn validate(&self) -> Result<(), CapabilityError> {
        if self.links.len() > MAX_LINK_ENTRIES {
            return Err(CapabilityError::BoundExceeded {
                limit: MAX_LINK_ENTRIES as u64,
                requested: self.links.len() as u64,
            });
        }
        let mut emitted = 0_u64;
        for link in &self.links {
            link.validate()?;
            add_string_bytes(&mut emitted, link.url.display_url());
            add_string_bytes(&mut emitted, &link.text);
        }
        validate_projection_bytes(&self.metadata, emitted)
    }
}

/// One table: optional caption and bounded rows of bounded cells.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TableEntry {
    pub caption: Option<String>,
    pub rows: Vec<Vec<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "TablesProjectionParts")]
pub struct TablesProjection {
    pub metadata: ReadMetadata,
    pub tables: Vec<TableEntry>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TablesProjectionParts {
    metadata: ReadMetadata,
    tables: Vec<TableEntry>,
}

impl TryFrom<TablesProjectionParts> for TablesProjection {
    type Error = CapabilityError;

    fn try_from(parts: TablesProjectionParts) -> Result<Self, Self::Error> {
        let projection = Self {
            metadata: parts.metadata,
            tables: parts.tables,
        };
        projection.validate()?;
        Ok(projection)
    }
}

impl TablesProjection {
    pub fn build(basis: ReadBasis, tables: Vec<TableEntry>) -> Result<Self, CapabilityError> {
        basis.validate()?;
        let total_tables = tables.len();
        let total_bytes = table_string_bytes(&tables);
        let mut budget = ProjectionBudget::new(basis.max_bytes);
        let mut truncated = total_tables > MAX_TABLES;
        let mut kept = Vec::new();

        for table in tables.into_iter().take(MAX_TABLES) {
            let total_rows = table.rows.len();
            let caption = table.caption.map(|caption| budget.take_fragment(caption));
            let mut rows = Vec::new();
            for row in table.rows.into_iter().take(MAX_TABLE_ROWS) {
                if budget.remaining() == 0 {
                    truncated = true;
                    break;
                }
                let total_columns = row.len();
                let mut cells = Vec::new();
                for cell in row.into_iter().take(MAX_TABLE_COLUMNS) {
                    if budget.remaining() == 0 {
                        truncated = true;
                        break;
                    }
                    cells.push(budget.take_fragment(cell));
                }
                truncated |= total_columns > cells.len();
                rows.push(cells);
            }
            truncated |= total_rows > rows.len();
            kept.push(TableEntry { caption, rows });
            if budget.remaining() == 0 {
                break;
            }
        }
        truncated |= total_tables > kept.len() || total_bytes > budget.emitted;
        let bound = BoundReport::new(
            basis.max_bytes,
            budget.emitted,
            Some(total_bytes),
            truncated,
        )?;
        let reason = collect_reason(
            &basis,
            &bound,
            &format!(
                "{total_tables} tables observed, {} kept (bound {MAX_TABLES})",
                kept.len()
            ),
        );
        Ok(Self {
            metadata: metadata(&basis, bound, &reason),
            tables: kept,
        })
    }

    pub fn validate(&self) -> Result<(), CapabilityError> {
        if self.tables.len() > MAX_TABLES {
            return Err(CapabilityError::BoundExceeded {
                limit: MAX_TABLES as u64,
                requested: self.tables.len() as u64,
            });
        }
        for table in &self.tables {
            if table.rows.len() > MAX_TABLE_ROWS {
                return Err(CapabilityError::BoundExceeded {
                    limit: MAX_TABLE_ROWS as u64,
                    requested: table.rows.len() as u64,
                });
            }
            if let Some(caption) = &table.caption {
                validate_fragment(caption)?;
            }
            for row in &table.rows {
                if row.len() > MAX_TABLE_COLUMNS {
                    return Err(CapabilityError::BoundExceeded {
                        limit: MAX_TABLE_COLUMNS as u64,
                        requested: row.len() as u64,
                    });
                }
                for cell in row {
                    validate_fragment(cell)?;
                }
            }
        }
        validate_projection_bytes(&self.metadata, table_string_bytes(&self.tables))
    }
}

fn table_string_bytes(tables: &[TableEntry]) -> u64 {
    let mut bytes = 0_u64;
    for table in tables {
        if let Some(caption) = &table.caption {
            add_string_bytes(&mut bytes, caption);
        }
        for row in &table.rows {
            for cell in row {
                add_string_bytes(&mut bytes, cell);
            }
        }
    }
    bytes
}

pub(super) fn validate_fragment(fragment: &str) -> Result<(), CapabilityError> {
    if fragment.len() > MAX_FRAGMENT_BYTES {
        return Err(CapabilityError::BoundExceeded {
            limit: MAX_FRAGMENT_BYTES as u64,
            requested: fragment.len() as u64,
        });
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum TypedRead {
    Text(TextProjection),
    Links(LinksProjection),
    Tables(TablesProjection),
    Accessibility(AccessibilityProjection),
    SanitizedDom(SanitizedDomProjection),
}

impl TypedRead {
    pub fn metadata(&self) -> &ReadMetadata {
        match self {
            Self::Text(read) => &read.metadata,
            Self::Links(read) => &read.metadata,
            Self::Tables(read) => &read.metadata,
            Self::Accessibility(read) => &read.metadata,
            Self::SanitizedDom(read) => &read.metadata,
        }
    }

    pub fn validate(&self) -> Result<(), CapabilityError> {
        match self {
            Self::Text(read) => read.validate(),
            Self::Links(read) => read.validate(),
            Self::Tables(read) => read.validate(),
            Self::Accessibility(read) => read.validate(),
            Self::SanitizedDom(read) => read.validate(),
        }
    }

    /// The trust class of every read: always untrusted.
    pub const fn trust() -> TrustClass {
        TrustClass::Untrusted
    }
}
