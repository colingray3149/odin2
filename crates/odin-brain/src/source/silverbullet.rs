//! SilverBullet vault source over the real loopback HTTP API.
//!
//! Talks HTTP/1.1 to a running SilverBullet 2.x server (Go, chi router) —
//! the exact endpoints observed in the running service and its published
//! server source (`server/fs.go` at tag 2.9.0):
//!
//! - `GET /.fs/` with `X-Sync-Mode: true` → JSON file list
//!   (`[{name, created, lastModified, contentType, size, perm}]`) plus an
//!   `X-Space-Path` header naming the server-side space root.
//! - `GET /.fs/<path>` → file bytes (with `X-Get-Meta: true` → headers only).
//! - The server also exposes `PUT`/`DELETE /.fs/<path>`; this client never
//!   calls them — the product path over `/.fs/` is strictly read-only.
//!   Disposable probe pages for the live smoke are written by the
//!   integration tests (`tests/vault_source.rs`), never by the library.
//!
//! Retrieval is never filesystem-only: every byte comes from this API.
//! Hard confinement rules, all enforced before any byte moves:
//! - loopback only: the endpoint host must be the literal `127.0.0.1`;
//! - no redirects: 3xx responses fail typed (the server redirects when a
//!   request is malformed; following one would leave the API contract);
//! - bounded reads: a hard byte cap and I/O timeout apply to every response;
//! - path confinement: page names are validated segment-by-segment and
//!   percent-encoded by this module; only `.md` pages are indexed.
//! - namespace scope: the required [`VaultScope`] policy admits only pages
//!   whose first segment names a general namespace or that lie strictly
//!   beneath the generated namespace, and never a page carrying an excluded
//!   segment at any depth. Every content read and every pin enforces it
//!   before any page byte moves. The reserved per-seat memory tree
//!   (`<generated>/memories/<seat>/`) admits only through an explicit
//!   generated-only memory scope — every ordinary scope carves it out —
//!   while the rest of the generated namespace stays eligible.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use odin_domain::knowledge::ids::AtlasId;
use odin_domain::knowledge::retrieval::TrustClass;
use odin_domain::Digest;

use crate::error::{BrainError, BrainResult};
use crate::source::SourceItem;

/// Default SilverBullet loopback port on this deployment.
pub const SILVERBULLET_PORT: u16 = 3000;

/// Only host this source will ever connect to.
const LOOPBACK_HOST: &str = "127.0.0.1";

/// Hard cap on any single HTTP response body other than the space listing.
pub const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

/// Listings include every vault file, even excluded generated pages, so
/// they need a larger cap than individual page responses.
pub const MAX_LISTING_BYTES: u64 = 64 * 1024 * 1024;

/// Hard cap on one page's content when indexing.
pub const MAX_PAGE_BYTES: u64 = 4 * 1024 * 1024;

/// HTTP client timeout for one request/response exchange.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Upper bound for one namespace or page-name path segment, in bytes — the
/// same grammar the validated vault configuration enforces upstream.
const SEGMENT_MAX_BYTES: usize = 128;
/// Upper bound for a full page name, in bytes.
const PAGE_NAME_MAX_BYTES: usize = 512;
/// Upper bound for generated-namespace depth (segment count).
const GENERATED_NAMESPACE_MAX_SEGMENTS: usize = 8;
/// Upper bound for configured namespace list lengths.
const NAMESPACE_LIST_MAX: usize = 32;

/// `<generated>/memories/<seat>/` is excluded from ordinary reads but admitted
/// by generated-content writes; [`memory_namespace`] constructs its namespace.
pub const RESERVED_MEMORY_SEGMENT: &str = "memories";
/// Reserved generated-knowledge segment: `<generated_namespace>/knowledge/`
/// is the brain's own projection output (deterministic rendered source
/// projections, see [`crate::projection`]). It is write-only from the
/// generated side: [`VaultScope::admits`] refuses it through every read
/// scope — general and memory alike — so rendered knowledge can never be
/// re-ingested into a memory or general vault source and feed back into the
/// next projection. The write grammar ([`addressable_page_name`]) stays
/// permissive so the daemon's generated-write gate is the only writer.
pub const RESERVED_KNOWLEDGE_SEGMENT: &str = "knowledge";
/// Upper bound for the configured page-count limit of one scoped pin.
pub const MAX_PAGES_CEILING: usize = 100_000;
/// One entry from the `/.fs/` file list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SilverBulletPageMeta {
    pub name: String,
    pub size: u64,
    pub last_modified_millis: u64,
    /// `rw` (operator-writable) or `ro` (library content).
    pub perm: String,
}

/// One pinned page: exact bytes and content digest from the live API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SilverBulletPage {
    pub meta: SilverBulletPageMeta,
    /// The served text: the page's bytes, or — for a page whose declared
    /// privacy class is withheld from models — the plain refusal sentence.
    pub text: String,
    /// Digest of the served text, so a withheld page changes the vault
    /// revision and no generation built before the guard is reused.
    pub digest: Digest,
    /// The typed refusal when the page declares `APL_RESTRICTED`/`SECRET`.
    pub withheld: Option<odin_domain::knowledge::PrivacyRefusal>,
}

/// A pinned vault revision: selected pages plus the revision covering them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedVault {
    atlas_id: AtlasId,
    revision: Digest,
    pages: Vec<SilverBulletPage>,
}

impl PinnedVault {
    /// Revision digest over the sorted (name, content digest) page rows.
    pub const fn revision(&self) -> Digest {
        self.revision
    }

    pub const fn atlas_id(&self) -> &AtlasId {
        &self.atlas_id
    }

    /// The pinned pages, sorted by name.
    pub fn pages(&self) -> &[SilverBulletPage] {
        &self.pages
    }

    /// Projects every pinned page into one indexable item per page.
    /// Vault content is [`TrustClass::Observed`] — personal notes are
    /// observed material, not curated authority.
    pub fn items(&self) -> BrainResult<Vec<SourceItem>> {
        let mut items = Vec::with_capacity(self.pages.len());
        for page in &self.pages {
            items.push(SourceItem::new(
                self.atlas_id.clone(),
                self.revision,
                page.meta.name.as_bytes(),
                TrustClass::Observed,
                page.text.clone(),
            )?);
        }
        Ok(items)
    }
}

/// The validated vault namespace scope: the single admission authority for
/// which pages one [`SilverBulletSource`] may ever read.
///
/// Private fields ensure every scope passes [`VaultScope::new`]'s checks:
/// confined segments, a nonempty allowlist, and exclusions disjoint from
/// both the allowlist and generated namespace. Reads and pins check this scope.
#[derive(Clone, Debug)]
pub struct VaultScope {
    /// Sorted general (allowlist) namespace segments.
    general: Vec<String>,
    /// Generated-namespace segments; only strictly deeper pages admit.
    generated: Vec<String>,
    /// Sorted hard exclusion segments; any match at any depth refuses.
    excluded: Vec<String>,
    /// Whether the reserved per-seat memory tree beneath the generated
    /// namespace is carved out of this scope: true for every ordinary
    /// (operator-declared) scope, false only for an explicit
    /// generated-only memory scope.
    reserved_memories: bool,
}

impl VaultScope {
    /// Validates and normalizes the namespace policy: `general_namespaces`
    /// (1..=`NAMESPACE_LIST_MAX` single confined segments, no repeats),
    /// `generated_namespace` (1..=`GENERATED_NAMESPACE_MAX_SEGMENTS`
    /// confined `/`-separated segments), `excluded_namespaces`
    /// (0..=`NAMESPACE_LIST_MAX` single confined segments, no repeats).
    /// The allowlist and every generated segment must sit outside the
    /// exclusions; the generated namespace may nest inside a general one.
    /// Invalid input fails typed [`BrainError::InvalidPolicy`] with a
    /// field-shaped reason; no network I/O occurs here.
    pub fn new(
        general_namespaces: &[String],
        generated_namespace: &str,
        excluded_namespaces: &[String],
    ) -> BrainResult<Self> {
        let general = namespace_list(general_namespaces, "general_namespaces")?;
        if general.is_empty() {
            return Err(BrainError::InvalidPolicy(
                "vault scope field general_namespaces: at least one general namespace is required"
                    .to_owned(),
            ));
        }
        let mut scope = Self::generated_only(generated_namespace, excluded_namespaces)?;
        if let Some(clash) = general.iter().find(|name| scope.excluded.contains(name)) {
            return Err(BrainError::InvalidPolicy(format!(
                "vault scope field excluded_namespaces: {clash} is both a general and an excluded namespace"
            )));
        }
        scope.general = general;
        scope.reserved_memories = true;
        Ok(scope)
    }

    /// A generated-only projection, used for a declared seat memory source.
    /// It admits no general namespace and cannot read a sibling seat's
    /// pages. The namespace must name one seat BENEATH the reserved
    /// memories tree — ending at the reserved segment itself would scope
    /// every seat's memory at once and is refused.
    pub fn generated_only(
        generated_namespace: &str,
        excluded_namespaces: &[String],
    ) -> BrainResult<Self> {
        let generated = namespace_path(generated_namespace)?;
        if generated.last().map(String::as_str) == Some(RESERVED_MEMORY_SEGMENT) {
            return Err(BrainError::InvalidPolicy(
                "vault scope field generated_namespace: a memory scope must \
                 name one seat beneath the reserved memories tree, not the \
                 unscoped tree itself"
                    .to_owned(),
            ));
        }
        let excluded = namespace_list(excluded_namespaces, "excluded_namespaces")?;
        if let Some(clash) = generated.iter().find(|name| excluded.contains(name)) {
            return Err(BrainError::InvalidPolicy(format!(
                "vault scope field generated_namespace: {clash} is an excluded namespace"
            )));
        }
        Ok(Self {
            general: Vec::new(),
            generated,
            excluded,
            reserved_memories: false,
        })
    }

    /// The exact seat of a generated-only reserved memory scope.
    pub fn memory_seat(&self) -> Option<&str> {
        if self.reserved_memories || !self.general.is_empty() || self.generated.len() < 3 {
            return None;
        }
        let seat_index = self.generated.len() - 1;
        (self.generated[seat_index - 1] == RESERVED_MEMORY_SEGMENT)
            .then(|| self.generated[seat_index].as_str())
    }

    /// The pure scope decision for one page name: Markdown only, bounded
    /// and confined, addressable by [`encode_page_path`], first segment in
    /// a general namespace or strictly beneath the generated namespace, and
    /// no excluded segment at any depth — exclusions beat everything. No
    /// I/O; identical to the gate applied inside every content read. The
    /// reserved generated-knowledge subtree ([`RESERVED_KNOWLEDGE_SEGMENT`])
    /// is refused through every scope: projection output is never input.
    pub fn admits(&self, page_name: &str) -> bool {
        let Some(segments) = page_segments(page_name) else {
            return false;
        };
        if segments
            .iter()
            .any(|segment| self.excluded.iter().any(|name| name == segment))
        {
            return false;
        }
        let general = self
            .general
            .iter()
            .any(|namespace| namespace == segments[0]);
        let generated = segments.len() > self.generated.len()
            && segments[..self.generated.len()] == self.generated[..];
        // The reserved per-seat memory tree admits only through an explicit
        // generated-only memory scope: an ordinary scope never serves reserved
        // memory, whichever arm — general or generated — would otherwise admit
        // it (a generated namespace nested inside the general allowlist
        // included). The carve-out is exactly the memories subtree beneath the
        // generated namespace; the rest of the generated namespace stays
        // eligible, so this is never a blanket generated-data exclusion.
        let reserved_memory = self.reserved_memories
            && generated
            && segments.len() > self.generated.len() + 1
            && segments[self.generated.len()] == RESERVED_MEMORY_SEGMENT;
        // The reserved generated-knowledge subtree is the brain's own
        // projection output: refused through EVERY read scope, whichever arm
        // would admit it — a generated namespace nested inside the general
        // allowlist included — so rendered knowledge can never re-enter any
        // vault source as ingestible input (no feedback loop).
        let reserved_knowledge = generated
            && segments.len() > self.generated.len()
            && segments[self.generated.len()] == RESERVED_KNOWLEDGE_SEGMENT;
        (general || generated)
            && !reserved_memory
            && !reserved_knowledge
            && encode_page_path(page_name).is_ok()
    }
}

/// The canonical reserved per-seat memory namespace:
/// `<generated_namespace>/memories/<seat>` — the exact subtree one
/// `memory.<seat>` brain source serves and the daemon's write gate reserves
/// for that seat. Shared by source composition and the write gate so both
/// sides compose one namespace; the composed path is validated with the
/// same namespace grammar, so a seat that is not one confined segment or a
/// namespace beyond the generated-depth bound fails typed here.
pub fn memory_namespace(generated_namespace: &str, seat: &str) -> BrainResult<String> {
    if !is_confined_segment(seat) {
        return Err(BrainError::InvalidPolicy(
            "memory namespace seat: must be one confined path segment".to_owned(),
        ));
    }
    let namespace = format!("{generated_namespace}/{RESERVED_MEMORY_SEGMENT}/{seat}");
    namespace_path(&namespace)?;
    Ok(namespace)
}

/// The pure page-addressability gate — Markdown only, bounded, confined —
/// with no namespace scope decision. This is the WRITE grammar: the vault's
/// generated-write path admits reserved memory pages as ordinary
/// syntactically valid generated content (own-seat enforcement is the
/// daemon's write gate, not page syntax), while read eligibility stays
/// with [`VaultScope::admits`].
pub fn addressable_page_name(page_name: &str) -> bool {
    page_segments(page_name).is_some() && encode_page_path(page_name).is_ok()
}

/// Validates a list of single-segment namespace names: bounded count,
/// confined segment grammar, no duplicates; sorted for stable, order-
/// independent scope identity.
fn namespace_list(names: &[String], field: &'static str) -> BrainResult<Vec<String>> {
    if names.len() > NAMESPACE_LIST_MAX {
        return Err(BrainError::InvalidPolicy(format!(
            "vault scope field {field}: at most {NAMESPACE_LIST_MAX} entries"
        )));
    }
    let mut validated = Vec::with_capacity(names.len());
    for name in names {
        if !is_confined_segment(name) {
            return Err(BrainError::InvalidPolicy(format!(
                "vault scope field {field}: entries must be single confined path segments"
            )));
        }
        if validated.contains(name) {
            return Err(BrainError::InvalidPolicy(format!(
                "vault scope field {field}: entries must not repeat"
            )));
        }
        validated.push(name.clone());
    }
    validated.sort();
    Ok(validated)
}

/// Validates a `/`-separated namespace path: 1..=8 confined segments.
fn namespace_path(value: &str) -> BrainResult<Vec<String>> {
    let segments: Vec<String> = value.split('/').map(str::to_owned).collect();
    if segments.len() > GENERATED_NAMESPACE_MAX_SEGMENTS {
        return Err(BrainError::InvalidPolicy(format!(
            "vault scope field generated_namespace: must have \
             1..={GENERATED_NAMESPACE_MAX_SEGMENTS} path segments"
        )));
    }
    for segment in &segments {
        if !is_confined_segment(segment) {
            return Err(BrainError::InvalidPolicy(
                "vault scope field generated_namespace: segments must be confined path segments"
                    .to_owned(),
            ));
        }
    }
    Ok(segments)
}

/// Splits and validates a page name into confined path segments, or `None`
/// when the name is not a bounded, relative, Markdown page path.
fn page_segments(page_name: &str) -> Option<Vec<&str>> {
    if page_name.len() > PAGE_NAME_MAX_BYTES || !page_name.ends_with(".md") {
        return None;
    }
    let segments: Vec<&str> = page_name.split('/').collect();
    if segments.iter().any(|segment| !is_confined_segment(segment)) {
        return None;
    }
    Some(segments)
}

/// The confined path-segment grammar shared by page names and namespaces:
/// non-empty, bounded, one segment, no separators, no NUL, never `.` or
/// `..`.
fn is_confined_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment.len() <= SEGMENT_MAX_BYTES
        && !segment.bytes().any(|byte| byte == b'/' || byte == 0)
        && segment != "."
        && segment != ".."
}

/// Confined loopback client for one SilverBullet space.
#[derive(Clone, Debug)]
pub struct SilverBulletSource {
    atlas_id: AtlasId,
    port: u16,
    scope: VaultScope,
    expected_space_root: Option<String>,
    max_response_bytes: u64,
    /// Cap on the whole-space `/.fs/` listing (see [`MAX_LISTING_BYTES`]).
    max_listing_bytes: u64,
    max_page_bytes: u64,
    /// Page-count bound for one scoped pin.
    max_pages: usize,
    timeout: Duration,
    /// The last scoped pin, keyed by the digest of the admitted listing
    /// (name, size, modification time): an unchanged space re-serves it
    /// instead of re-reading every page body on every turn.
    last_pin: std::sync::Arc<std::sync::Mutex<Option<(Digest, PinnedVault)>>>,
}

impl SilverBulletSource {
    /// Targets a SilverBullet server on the loopback interface only. A
    /// non-loopback deployment is rejected before any network activity —
    /// this source never leaves the machine.
    ///
    /// The namespace [`VaultScope`] is mandatory and irreducible: there is
    /// no unscoped source, so no construction path — service composition,
    /// vault bridge, or test — can index outside the configured
    /// namespaces.
    pub fn new(atlas_id: AtlasId, port: u16, scope: VaultScope) -> Self {
        Self {
            atlas_id,
            port,
            scope,
            expected_space_root: None,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_listing_bytes: MAX_LISTING_BYTES,
            max_page_bytes: MAX_PAGE_BYTES,
            max_pages: MAX_PAGES_CEILING,
            timeout: DEFAULT_TIMEOUT,
            last_pin: std::sync::Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Pins the expected server-side space root; the `/.fs/` listing must
    /// carry a matching `X-Space-Path` (the one endpoint that emits it) or
    /// the source fails typed instead of indexing a different space. Every
    /// read pins through a listing first, so the check covers every byte.
    pub fn with_expected_space_root(mut self, root: impl Into<String>) -> Self {
        self.expected_space_root = Some(root.into());
        self
    }

    /// Overrides the response and page byte caps.
    pub fn with_limits(
        mut self,
        max_response_bytes: u64,
        max_page_bytes: u64,
        timeout: Duration,
    ) -> Self {
        self.max_response_bytes = max_response_bytes;
        self.max_page_bytes = max_page_bytes;
        self.timeout = timeout;
        self
    }

    /// Overrides the `/.fs/` listing cap (default [`MAX_LISTING_BYTES`]).
    pub fn with_listing_cap(mut self, max_listing_bytes: u64) -> Self {
        self.max_listing_bytes = max_listing_bytes;
        self
    }

    /// Overrides the scoped-pin page-count bound (clamped into
    /// 1..=[`MAX_PAGES_CEILING`]). Callers with a validated configuration
    /// should still reject an out-of-range value at their own validation
    /// layer; this builder only keeps the bound sane.
    pub fn with_page_bound(mut self, max_pages: usize) -> Self {
        self.max_pages = max_pages.clamp(1, MAX_PAGES_CEILING);
        self
    }

    /// The namespace scope this source admits pages through.
    pub const fn scope(&self) -> &VaultScope {
        &self.scope
    }

    /// The Atlas source identity this source pins and cites under. The
    /// open boundary checks it against the configured source key, so a
    /// composed source can never serve under another source's identity.
    pub const fn atlas_id(&self) -> &AtlasId {
        &self.atlas_id
    }

    /// The pure scope decision for one page name; identical to the gate
    /// applied inside every content read.
    pub fn admits(&self, page_name: &str) -> bool {
        self.scope.admits(page_name)
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> BrainResult<RawResponse> {
        self.request_capped(self.max_response_bytes, method, path, headers, body)
    }

    fn request_capped(
        &self,
        max_response_bytes: u64,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> BrainResult<RawResponse> {
        http_request(
            LOOPBACK_HOST,
            self.port,
            self.timeout,
            max_response_bytes,
            method,
            path,
            headers,
            body,
        )
    }

    fn check_space_root(&self, headers: &[(String, String)]) -> BrainResult<()> {
        if let Some(expected) = &self.expected_space_root {
            let actual = headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("x-space-path"))
                .map(|(_, value)| value.as_str());
            if actual != Some(expected.as_str()) {
                return Err(BrainError::Unavailable {
                    component: "silverbullet",
                    reason: format!(
                        "server space root is {actual:?}, expected {expected:?}; refusing to index a different space"
                    ),
                });
            }
        }
        Ok(())
    }

    /// Lists all pages in the space through the real API.
    pub fn list_pages(&self) -> BrainResult<Vec<SilverBulletPageMeta>> {
        let (status, headers, body) = self.request_capped(
            self.max_listing_bytes,
            "GET",
            "/.fs/",
            &[("X-Sync-Mode", "true"), ("Accept", "application/json")],
            b"",
        )?;
        ensure_plain_status(status)?;
        self.check_space_root(&headers)?;
        let entries: Vec<serde_json::Value> = serde_json::from_slice(&body)?;
        let mut pages = Vec::with_capacity(entries.len());
        for entry in entries {
            let Some(name) = entry.get("name").and_then(|value| value.as_str()) else {
                continue;
            };
            let perm = entry
                .get("perm")
                .and_then(|value| value.as_str())
                .unwrap_or("rw")
                .to_owned();
            let size = entry
                .get("size")
                .and_then(|value| value.as_u64())
                .unwrap_or(0);
            let last_modified_millis = entry
                .get("lastModified")
                .and_then(|value| value.as_u64())
                .unwrap_or(0);
            pages.push(SilverBulletPageMeta {
                name: name.to_owned(),
                size,
                last_modified_millis,
                perm,
            });
        }
        pages.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(pages)
    }

    /// Reads one page's exact bytes from the API.
    ///
    /// The namespace scope gate precedes even the listing round trip: a
    /// page outside the configured namespaces is never looked up and never
    /// fetched — no byte of excluded or unallowlisted content can move
    /// through this source, on any path.
    pub fn read_page(&self, page_name: &str) -> BrainResult<SilverBulletPage> {
        if !self.scope.admits(page_name) {
            return Err(BrainError::InvalidRequest(format!(
                "page {page_name:?} is outside the configured vault scope; \
                 it is never read, pinned, or served"
            )));
        }
        let meta = self.page_meta(page_name)?;
        self.fetch_page(meta)
    }

    /// Fetches one listed page's bytes. Callers pass metadata from a
    /// listing they already pinned, after the scope gate admitted the name.
    fn fetch_page(&self, meta: SilverBulletPageMeta) -> BrainResult<SilverBulletPage> {
        let (status, _headers, body) = self.request(
            "GET",
            &format!("/.fs/{}", encode_page_path(&meta.name)?),
            &[("Accept", "application/octet-stream")],
            b"",
        )?;
        ensure_plain_status(status)?;
        // Space-root confinement is enforced on the /.fs/ listing inside
        // page_meta: file GET responses carry no X-Space-Path header, so
        // the root check belongs to the listing every read pins through.
        if body.len() as u64 > self.max_page_bytes {
            return Err(BrainError::InvalidRequest(format!(
                "page {} exceeds the {} byte indexing bound",
                meta.name, self.max_page_bytes
            )));
        }
        let text = String::from_utf8(body.clone()).map_err(|_| {
            BrainError::InvalidRequest(format!("page {} is not valid UTF-8", meta.name))
        })?;
        Ok(guard_page(&self.atlas_id, meta, text, body))
    }

    fn page_meta(&self, page_name: &str) -> BrainResult<SilverBulletPageMeta> {
        let pages = self.list_pages()?;
        pages
            .into_iter()
            .find(|meta| meta.name == page_name)
            .ok_or_else(|| BrainError::Unavailable {
                component: "silverbullet",
                reason: format!("page {page_name:?} does not exist in the space"),
            })
    }

    /// Pins an explicit allowlist of pages into one immutable revision.
    /// Every name passes the same namespace scope gate as any other read —
    /// out-of-scope names fail typed before any byte moves — and unknown
    /// pages fail typed instead of being skipped silently.
    pub fn pin_pages(&self, page_names: &[&str]) -> BrainResult<PinnedVault> {
        // The scope gate refuses before the listing moves any byte.
        if let Some(name) = page_names.iter().find(|name| !self.scope.admits(name)) {
            return Err(BrainError::InvalidRequest(format!(
                "page {name:?} is outside the configured vault scope; \
                 it is never read, pinned, or served"
            )));
        }
        self.pin_listed(self.list_pages()?, page_names)
    }

    /// Pins `page_names` out of one listing: a lookup per page would list
    /// the whole space once per page (quadratic for a large vault).
    fn pin_listed(
        &self,
        listed: Vec<SilverBulletPageMeta>,
        page_names: &[&str],
    ) -> BrainResult<PinnedVault> {
        let mut listed: std::collections::BTreeMap<String, SilverBulletPageMeta> = listed
            .into_iter()
            .map(|meta| (meta.name.clone(), meta))
            .collect();
        let mut pages = Vec::with_capacity(page_names.len());
        for name in page_names {
            let meta = listed
                .remove(*name)
                .ok_or_else(|| BrainError::Unavailable {
                    component: "silverbullet",
                    reason: format!("page {name:?} does not exist in the space"),
                })?;
            pages.push(self.fetch_page(meta)?);
        }
        pages.sort_by(|left, right| left.meta.name.cmp(&right.meta.name));
        let revision = vault_revision(&pages);
        Ok(PinnedVault {
            atlas_id: self.atlas_id.clone(),
            revision,
            pages,
        })
    }

    /// Pins the scoped vault revision: lists the space through the real
    /// API, admits page names through the configured [`VaultScope`] —
    /// before any content read — sorts, bounds the count, and pins exactly
    /// the eligible set into one immutable revision. Zero eligible pages is
    /// an honest empty pin; a listing above the page bound fails typed
    /// instead of truncating.
    pub fn pin_scoped(&self) -> BrainResult<PinnedVault> {
        let listed = self.list_pages()?;
        let mut names: Vec<&str> = listed
            .iter()
            .map(|page| page.name.as_str())
            .filter(|name| self.scope.admits(name))
            .collect();
        if names.len() > self.max_pages {
            return Err(BrainError::InvalidRequest(format!(
                "scoped vault has {} eligible pages, above the {} page bound",
                names.len(),
                self.max_pages
            )));
        }
        names.sort_unstable();
        let mut material = b"odin-brain:vault-listing:v1\x00".to_vec();
        for meta in listed.iter().filter(|meta| self.scope.admits(&meta.name)) {
            material.extend_from_slice(
                format!(
                    "{}\x00{}\x00{}\x00",
                    meta.name, meta.size, meta.last_modified_millis
                )
                .as_bytes(),
            );
        }
        let listing = Digest::hash(&material);
        if let Ok(cache) = self.last_pin.lock() {
            if let Some((cached, pinned)) = cache.as_ref() {
                if *cached == listing {
                    return Ok(pinned.clone());
                }
            }
        }
        let names: Vec<String> = names.into_iter().map(str::to_owned).collect();
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        let pinned = self.pin_listed(listed, &names)?;
        if let Ok(mut cache) = self.last_pin.lock() {
            *cache = Some((listing, pinned.clone()));
        }
        Ok(pinned)
    }
}

/// The privacy guard every vault page passes on its way into Odin: a page
/// that declares a class withheld from models (`APL_RESTRICTED`, `SECRET`)
/// is served as the plain refusal sentence instead of its bytes, so no
/// index, embedding, retrieval hit, memory row or compiled context — on
/// any lane — ever carries its content.
fn guard_page(
    source: &AtlasId,
    meta: SilverBulletPageMeta,
    text: String,
    body: Vec<u8>,
) -> SilverBulletPage {
    let class = odin_domain::knowledge::note_privacy_class(&text)
        .filter(|class| class.withheld_from_models());
    let Some(class) = class else {
        let digest = Digest::hash(&body);
        return SilverBulletPage {
            meta,
            text,
            digest,
            withheld: None,
        };
    };
    let refusal = odin_domain::knowledge::PrivacyRefusal {
        class,
        subject: meta.name.clone(),
    };
    tracing::warn!(
        source = %source.as_str(),
        page = ?meta.name,
        %class,
        bytes = body.len(),
        "privacy withheld"
    );
    let text = refusal.sentence();
    let digest = Digest::hash(text.as_bytes());
    SilverBulletPage {
        meta,
        text,
        digest,
        withheld: Some(refusal),
    }
}

/// Revision digest over sorted (name, digest) page rows.
fn vault_revision(pages: &[SilverBulletPage]) -> Digest {
    let mut material = Vec::new();
    material.extend_from_slice(b"odin-brain:vault-revision:v1\x00");
    for page in pages {
        material.extend_from_slice(page.meta.name.as_bytes());
        material.push(0);
        material.extend_from_slice(page.digest.as_bytes());
        material.push(0);
    }
    Digest::hash(&material)
}

/// Rejects any non-2xx status; redirects are refused, never followed.
fn ensure_plain_status(status: u16) -> BrainResult<()> {
    if (300..400).contains(&status) {
        return Err(BrainError::Unavailable {
            component: "silverbullet",
            reason: format!(
                "service responded with redirect {status}; redirects are never followed"
            ),
        });
    }
    if status != 200 {
        return Err(BrainError::Unavailable {
            component: "silverbullet",
            reason: format!("service responded with HTTP {status}"),
        });
    }
    Ok(())
}

/// Validates and percent-encodes one confined page path.
///
/// Only `A-Za-z0-9 _-` segments (plus the `.` in the `.md` suffix) are
/// accepted; everything else — `..`, absolute paths, URL metacharacters,
/// non-ASCII — is rejected before encoding.
pub fn encode_page_path(page_name: &str) -> BrainResult<String> {
    let invalid = |reason: &str| {
        BrainError::InvalidRequest(format!("page name {page_name:?} rejected: {reason}"))
    };
    if page_name.is_empty() || !page_name.ends_with(".md") {
        return Err(invalid("only .md pages are indexable"));
    }
    if page_name.contains("//") || page_name.contains('\\') {
        return Err(invalid("empty path segments are not allowed"));
    }
    let mut encoded = String::with_capacity(page_name.len());
    for segment in page_name.split('/') {
        if segment.is_empty() || segment == ".." || (segment.starts_with('.') && segment != ".md") {
            return Err(invalid("path segments must be plain page names"));
        }
        for byte in segment.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.' => {
                    encoded.push(byte as char)
                }
                b' ' => encoded.push_str("%20"),
                _ => return Err(invalid("contains a character outside the confined set")),
            }
        }
        encoded.push('/');
    }
    encoded.pop();
    Ok(encoded)
}

type RawResponse = (u16, Vec<(String, String)>, Vec<u8>);

/// Minimal HTTP/1.1 client for the loopback API.
///
/// One connection per request (`Connection: close`), strict response caps,
/// chunked and identity decoding. There is no TLS, no proxy, and no
/// redirect logic to betray confinement.
#[allow(clippy::too_many_arguments)]
fn http_request(
    host: &str,
    port: u16,
    timeout: Duration,
    max_response_bytes: u64,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> BrainResult<RawResponse> {
    if host != LOOPBACK_HOST {
        return Err(BrainError::InvalidRequest(format!(
            "refusing non-loopback endpoint {host}"
        )));
    }
    let stream =
        TcpStream::connect_timeout(&std::net::SocketAddr::from(([127, 0, 0, 1], port)), timeout)
            .map_err(|error| BrainError::Unavailable {
                component: "silverbullet",
                reason: format!("cannot connect to {host}:{port}: {error}"),
            })?;
    stream.set_read_timeout(Some(timeout)).map_err(map_io)?;
    stream.set_write_timeout(Some(timeout)).map_err(map_io)?;
    let mut stream = stream;
    exchange(
        &mut stream,
        max_response_bytes,
        host,
        port,
        method,
        path,
        headers,
        body,
    )
    .map_err(|error| with_request(error, method, path, timeout))
}

/// The request/response exchange of [`http_request`] on a connected stream.
#[allow(clippy::too_many_arguments)]
fn exchange(
    stream: &mut TcpStream,
    max_response_bytes: u64,
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> BrainResult<RawResponse> {
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).map_err(map_io)?;
    stream.write_all(body).map_err(map_io)?;
    stream.flush().map_err(map_io)?;

    let mut limited = CappedReader {
        stream,
        remaining: max_response_bytes,
    };
    read_response(&mut limited)
}

/// Include the request and timeout duration so transport failures are actionable.
fn with_request(error: BrainError, method: &str, path: &str, timeout: Duration) -> BrainError {
    match error {
        BrainError::Unavailable { component, reason } => {
            let timed_out = reason.starts_with(TIMED_OUT);
            BrainError::Unavailable {
                component,
                reason: if timed_out {
                    format!(
                        "{method} {path}: no response within {}s ({reason})",
                        timeout.as_secs()
                    )
                } else {
                    format!("{method} {path}: {reason}")
                },
            }
        }
        other => other,
    }
}

/// Maps transport I/O failures to the typed unavailable error.
fn map_io(error: std::io::Error) -> BrainError {
    let reason = match error.kind() {
        // A socket read/write timeout surfaces as WouldBlock on Unix.
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
            format!("{TIMED_OUT}: {error}")
        }
        _ => format!("loopback transport failed: {error}"),
    };
    BrainError::Unavailable {
        component: "silverbullet",
        reason,
    }
}

/// The reason prefix of a transport read or write that ran out of time.
const TIMED_OUT: &str = "loopback transport timed out";

/// Reads and parses one HTTP/1.1 response off the capped stream.
fn read_response(reader: &mut CappedReader<'_>) -> BrainResult<RawResponse> {
    let mut head = Vec::with_capacity(512);
    let mut byte = [0_u8; 1];
    loop {
        reader.read_exact(&mut byte).map_err(map_io)?;
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > 64 * 1024 {
            return Err(BrainError::Unavailable {
                component: "silverbullet",
                reason: "response header block exceeds 64 KiB".to_owned(),
            });
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or_else(|| BrainError::Unavailable {
        component: "silverbullet",
        reason: "empty response".to_owned(),
    })?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| BrainError::Unavailable {
            component: "silverbullet",
            reason: format!("malformed status line {status_line:?}"),
        })?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
    }
    let header = |name: &str| {
        headers
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.clone())
    };

    let body = if header("transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
    {
        read_chunked_body(reader)?
    } else if let Some(length) =
        header("content-length").and_then(|value| value.parse::<u64>().ok())
    {
        if length > reader.remaining {
            return Err(BrainError::Unavailable {
                component: "silverbullet",
                reason: format!("content-length {length} exceeds the response byte cap"),
            });
        }
        let mut body = vec![0_u8; length as usize];
        reader.read_exact(&mut body).map_err(map_io)?;
        body
    } else {
        let mut body = Vec::new();
        reader.read_to_end(&mut body).map_err(map_io)?;
        body
    };
    Ok((status, headers, body))
}

/// Decodes a chunked transfer-encoding body under the global byte cap.
fn read_chunked_body(reader: &mut CappedReader<'_>) -> BrainResult<Vec<u8>> {
    let mut body = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        let mut line = Vec::new();
        loop {
            reader.read_exact(&mut byte).map_err(map_io)?;
            if byte[0] == b'\n' {
                break;
            }
            if byte[0] != b'\r' {
                line.push(byte[0]);
            }
            if line.len() > 32 {
                return Err(BrainError::Unavailable {
                    component: "silverbullet",
                    reason: "chunk size line too long".to_owned(),
                });
            }
        }
        let size_text = String::from_utf8_lossy(&line);
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("0").trim(), 16)
            .map_err(|_| BrainError::Unavailable {
                component: "silverbullet",
                reason: format!("malformed chunk size {size_text:?}"),
            })?;
        if size == 0 {
            // Trailer section up to a blank line.
            loop {
                reader.read_exact(&mut byte).map_err(map_io)?;
                if byte[0] == b'\n' {
                    break;
                }
            }
            return Ok(body);
        }
        if size as u64 > reader.remaining {
            return Err(BrainError::Unavailable {
                component: "silverbullet",
                reason: format!("chunk size {size} exceeds the remaining response byte cap"),
            });
        }
        let mut chunk = vec![0_u8; size];
        reader.read_exact(&mut chunk).map_err(map_io)?;
        body.extend_from_slice(&chunk);
        let mut crlf = [0_u8; 2];
        reader.read_exact(&mut crlf).map_err(map_io)?;
    }
}

/// Stream wrapper enforcing one hard cap across an entire response.
struct CappedReader<'a> {
    stream: &'a mut TcpStream,
    remaining: u64,
}

impl Read for CappedReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let length = buffer
            .len()
            .min(self.remaining.min(usize::MAX as u64) as usize);
        if length == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                "response exceeded the configured byte cap",
            ));
        }
        let read = self.stream.read(&mut buffer[..length])?;
        self.remaining -= read as u64;
        Ok(read)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod transport_error_tests {
    use super::*;

    #[test]
    fn a_silent_server_is_a_named_timeout() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let _held = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            std::thread::sleep(Duration::from_secs(3));
            drop(stream);
        });
        let error = http_request(
            LOOPBACK_HOST,
            port,
            Duration::from_millis(300),
            1024,
            "GET",
            "/.fs/",
            &[],
            &[],
        )
        .expect_err("no response");
        let BrainError::Unavailable { reason, .. } = error else {
            panic!("typed unavailable expected, got {error:?}");
        };
        assert!(
            reason.starts_with("GET /.fs/: no response within 0s"),
            "{reason}"
        );
    }
}
