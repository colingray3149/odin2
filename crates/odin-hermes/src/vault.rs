//! Scoped vault retrieval through SilverBullet and confined generated-page writes.
//!
//! Reads use the loopback HTTP source and pinned revisions; ranking stays in the brain.
//! Retrieval includes only allowed Markdown namespaces and excludes private segments at any depth.
//! Writes stay beneath the generated namespace using descriptor-relative operations without symlinks.
//! The root must be a private `0700` directory. Local writes work without SilverBullet; reads do not.
//! Paths, ports, namespaces, and limits come from [`VaultConfig`].

use std::ffi::OsStr;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::Duration;

use odin_brain::error::{BrainError, BrainResult};
use odin_brain::source::silverbullet::{
    addressable_page_name, PinnedVault, SilverBulletSource, VaultScope, MAX_PAGES_CEILING,
    MAX_PAGE_BYTES, MAX_RESPONSE_BYTES, RESERVED_KNOWLEDGE_SEGMENT,
};
use odin_confined_fs::{ConfinedError, PrivateCapability};
use odin_domain::knowledge::ids::AtlasId;
use odin_domain::{Digest, SeatId, SessionId};
use rustix::fs::{mkdirat, openat2, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Capabilities wired through governed adapter dispatch by the runtime.
pub const VAULT_CAPABILITIES: &[&str] = &["vault.search", "vault.write_generated"];

/// Upper bound for one namespace or page-name path segment, in bytes.
const SEGMENT_MAX_BYTES: usize = 128;
/// Upper bound for generated-namespace depth (segment count).
const GENERATED_NAMESPACE_MAX_SEGMENTS: usize = 8;
/// Upper bound for configured namespace list lengths.
const NAMESPACE_LIST_MAX: usize = 32;
/// Open flags for confined directory components: read-only directory, never
/// following a symlink, close-on-exec.
const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
/// The `openat2` resolution discipline: strictly beneath the starting
/// descriptor, no symlink and no magic-link resolution, ever.
const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

/// One validated failure of vault configuration. Field names are static;
/// reasons never carry more than the shape of the problem.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
#[error("vault configuration field {field}: {reason}")]
pub struct VaultConfigError {
    field: &'static str,
    /// Static-sanitized shape of the violation.
    reason: String,
}

impl VaultConfigError {
    fn field(field: &'static str, reason: impl Into<String>) -> Self {
        Self {
            field,
            reason: reason.into(),
        }
    }
}

/// The optional SilverBullet deployment facts. The host is fixed to the
/// loopback interface by the brain source module and is not configurable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SilverBulletConfig {
    /// Loopback port the SilverBullet server listens on.
    pub port: u16,
    /// Expected server-side space root (`X-Space-Path`); a mismatch fails
    /// typed instead of indexing a different space.
    pub expected_space_root: Option<String>,
}

/// Nix-injected deployment facts for one vault. Carried verbatim from the
/// `odind.toml` `[hermes]` section; [`VaultConfig::validate`] is the only
/// gate between this shape and a [`VaultBridge`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultConfig {
    /// Absolute path of the vault root (the directory SilverBullet serves
    /// and the only place machine writes may ever land inside).
    pub vault_root: PathBuf,
    /// Knowledge source identity of the vault (`AtlasId` grammar). It must
    /// equal an Atlas source the seat's knowledge policy authorizes, so the
    /// brain's exact source-set rule holds.
    pub source_id: String,
    /// The optional SilverBullet UI deployment; `None` means the vault is
    /// served by no SilverBullet instance (Obsidian coexistence), and scoped
    /// retrieval is typed unavailable while local writes keep working.
    pub silverbullet: Option<SilverBulletConfig>,
    /// General namespaces: the allowlist of top-level vault namespaces whose
    /// Markdown pages are retrieval-eligible (e.g. `knowledge`).
    pub general_namespaces: Vec<String>,
    /// The generated namespace: the only place machine writes may land,
    /// `/`-separated beneath the vault root (e.g. `generated`). Its pages
    /// are retrieval-eligible.
    pub generated_namespace: String,
    /// Hard private exclusions (e.g. finance, credentials, raw
    /// communications): no page whose any path segment names one of these is
    /// ever retrieval-eligible, and the generated namespace may not live in
    /// one.
    pub excluded_namespaces: Vec<String>,
    /// Page-count bound for one scoped pin.
    pub max_pages: usize,
    /// Per-page byte bound for indexing and generated writes.
    pub max_page_bytes: u64,
    /// Per-request deadline for the loopback SilverBullet API.
    pub timeout_ms: u64,
}

impl VaultConfig {
    /// Validates every deployment fact. Ordered, fail-closed, and
    /// value-free: each failure names its field and the shape of the
    /// violation.
    pub fn validate(&self) -> Result<(), VaultConfigError> {
        if !self.vault_root.is_absolute() {
            return Err(VaultConfigError::field(
                "vault_root",
                "must be an absolute path",
            ));
        }
        if AtlasId::new(self.source_id.clone()).is_err() {
            return Err(VaultConfigError::field(
                "source_id",
                "must be a valid knowledge source identity",
            ));
        }
        let general = namespace_list(
            &self.general_namespaces,
            "general_namespaces",
            NAMESPACE_LIST_MAX,
        )?;
        if general.is_empty() {
            return Err(VaultConfigError::field(
                "general_namespaces",
                "at least one general namespace is required",
            ));
        }
        let excluded = namespace_list(
            &self.excluded_namespaces,
            "excluded_namespaces",
            NAMESPACE_LIST_MAX,
        )?;
        if let Some(clash) = general.iter().find(|name| excluded.contains(name)) {
            return Err(VaultConfigError::field(
                "excluded_namespaces",
                format!("{clash} is both a general and an excluded namespace"),
            ));
        }
        let generated_segments = namespace_path(&self.generated_namespace, "generated_namespace")?;
        if let Some(clash) = generated_segments
            .iter()
            .find(|name| excluded.contains(name))
        {
            return Err(VaultConfigError::field(
                "generated_namespace",
                format!("{clash} is an excluded namespace"),
            ));
        }
        if let Some(config) = &self.silverbullet {
            if config.port == 0 {
                return Err(VaultConfigError::field("port", "must be 1..=65535"));
            }
            if config
                .expected_space_root
                .as_ref()
                .is_some_and(String::is_empty)
            {
                return Err(VaultConfigError::field(
                    "expected_space_root",
                    "must not be empty when present",
                ));
            }
        }
        if self.max_pages == 0 || self.max_pages > MAX_PAGES_CEILING {
            return Err(VaultConfigError::field(
                "max_pages",
                format!("must be 1..={MAX_PAGES_CEILING}"),
            ));
        }
        if self.max_page_bytes == 0 || self.max_page_bytes > MAX_PAGE_BYTES {
            return Err(VaultConfigError::field(
                "max_page_bytes",
                format!("must be 1..={MAX_PAGE_BYTES}"),
            ));
        }
        if !(1_000..=60_000).contains(&self.timeout_ms) {
            return Err(VaultConfigError::field(
                "timeout_ms",
                "must be 1000..=60000",
            ));
        }
        Ok(())
    }
}

/// Validates a list of single-segment namespace names: bounded length,
/// confined segment grammar, no duplicates.
fn namespace_list(
    names: &[String],
    field: &'static str,
    bound: usize,
) -> Result<Vec<String>, VaultConfigError> {
    if names.len() > bound {
        return Err(VaultConfigError::field(
            field,
            format!("at most {bound} entries"),
        ));
    }
    let mut validated = Vec::with_capacity(names.len());
    for name in names {
        if !is_confined_segment(name) {
            return Err(VaultConfigError::field(
                field,
                "entries must be single confined path segments",
            ));
        }
        if validated.contains(name) {
            return Err(VaultConfigError::field(field, "entries must not repeat"));
        }
        validated.push(name.clone());
    }
    validated.sort();
    Ok(validated)
}

/// Validates a `/`-separated namespace path: 1..=8 confined segments.
fn namespace_path(value: &str, field: &'static str) -> Result<Vec<String>, VaultConfigError> {
    let segments: Vec<String> = value.split('/').map(str::to_owned).collect();
    if segments.is_empty() || segments.len() > GENERATED_NAMESPACE_MAX_SEGMENTS {
        return Err(VaultConfigError::field(
            field,
            format!("must have 1..={GENERATED_NAMESPACE_MAX_SEGMENTS} path segments"),
        ));
    }
    for segment in &segments {
        if !is_confined_segment(segment) {
            return Err(VaultConfigError::field(
                field,
                "segments must be confined path segments",
            ));
        }
    }
    Ok(segments)
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

/// Typed failure of one vault operation. `Refused` is a provably
/// effect-free policy refusal (escape attempt, bound violation);
/// `Unavailable` is a genuinely missing service, vault, or configuration
/// fact — never a fake success; `Params` is a malformed operation input.
#[derive(Debug, Error)]
pub enum VaultError {
    /// The requested page lies outside the generated namespace, escapes the
    /// vault root (traversal or symlink), or violates a configured bound.
    #[error("vault operation refused: {0}")]
    Refused(String),
    /// The SilverBullet service, vault root, or deployment fact needed for
    /// the operation is genuinely absent.
    #[error("vault unavailable ({component}): {reason}")]
    Unavailable {
        /// Which deployment fact is absent.
        component: &'static str,
        /// Static-sanitized shape of the absence.
        reason: String,
    },
    /// The operation input is malformed beyond what schemas express.
    #[error("vault operation parameters invalid: {0}")]
    Params(String),
    /// The brain-backed retrieval backend failed without a narrower class.
    #[error("vault retrieval backend failed: {0}")]
    Backend(String),
    /// A confined filesystem operation failed after the policy gate.
    #[error(transparent)]
    Confined(#[from] ConfinedError),
    /// Receipt publication may have linked the final page before failing.
    /// A caller must not classify this as an effect-free refusal.
    #[error("receipt publication is uncertain: {0}")]
    PublicationUncertain(#[source] ConfinedError),
}

impl From<BrainError> for VaultError {
    fn from(error: BrainError) -> Self {
        match error {
            BrainError::Unavailable { component, reason } => {
                Self::Unavailable { component, reason }
            }
            BrainError::InvalidRequest(reason) | BrainError::InvalidPolicy(reason) => {
                Self::Params(reason)
            }
            other => Self::Backend(other.to_string()),
        }
    }
}

/// The pre-IO vault scoping gate, composed by the daemon: resolves the
/// calling session's declared project memory namespace BEFORE any vault
/// write and refuses typed when the write is not declaratively scoped
/// (no project, zero or several reachable namespaces). Ok authorizes the
/// write to proceed; Err surfaces the typed reason in the tool error and
/// no vault IO occurs.
pub trait VaultWriteGate: Send + Sync {
    /// `source_id` is the ACTUAL configured write destination
    /// (`VaultConfig::source_id`, a validated AtlasId) — the gate may
    /// require it to BE the declared memory namespace.
    fn gate_generated_write(
        &self,
        seat: &SeatId,
        session: &SessionId,
        source_id: &str,
        page_name: &str,
    ) -> Result<(), BrainError>;

    /// Post-write serving hook, invoked only AFTER the generated write is
    /// durable: refreshes the writing seat's own brain source so the new
    /// page serves. The write is never rolled back or denied by this hook
    /// — an `Err` means the serving refresh did not complete, and the
    /// receipt must stay honest about that (refresh pending), never
    /// claiming the write failed or that the page is absent.
    fn generated_written(
        &self,
        seat: &SeatId,
        session: &SessionId,
        source_id: &str,
        page_name: &str,
    ) -> Result<(), BrainError>;
}

/// Input of the `vault.search` operation: an optional caller bound on the
/// returned page count, never exceeding the configured bound. Namespace
/// scoping is configuration-owned and deliberately not caller-visible.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultSearchInput {
    /// Maximum pages to return; defaults to the configured bound.
    #[serde(default)]
    pub max_pages: Option<u32>,
}

/// Search metadata omits page text, which flows through the scoped brain index under the same digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VaultSearchPage {
    /// Vault-relative page name, including the `.md` suffix.
    pub name: String,
    /// BLAKE3 digest of the exact pinned page bytes (`blake3:` + 64 hex).
    pub digest: String,
    /// Exact pinned page size in bytes.
    pub bytes: u64,
}

/// Output of the `vault.search` operation: one digest-identified scoped
/// snapshot of the retrieval-eligible vault.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VaultSearchOutput {
    /// Knowledge source identity the snapshot was pinned under.
    pub source_id: String,
    /// Revision digest over the full eligible page set this snapshot was
    /// pinned from — the pin's exact identity even when `truncated`.
    pub revision_digest: String,
    /// Number of returned pages.
    pub page_count: usize,
    /// True when eligible pages existed beyond the returned window; the
    /// result is flagged, never silently reduced.
    pub truncated: bool,
    /// The scoped pages, sorted by name.
    pub pages: Vec<VaultSearchPage>,
}

/// Input of the `vault.write_generated` operation: one machine-authored
/// Markdown page and its full vault-relative name, which must include the
/// generated namespace prefix.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultWriteGeneratedInput {
    /// Full vault-relative page name beneath the generated namespace.
    pub page_name: String,
    /// Exact Markdown content to write.
    pub content: String,
}

/// Output of the `vault.write_generated` operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VaultWriteGeneratedOutput {
    /// The written page's vault-relative name.
    pub page_name: String,
    /// BLAKE3 digest of the exact written bytes (`blake3:` + 64 hex).
    pub content_digest: String,
    /// Exact written byte count.
    pub byte_count: usize,
}

/// How one derived receipt page landed through
/// [`VaultBridge::publish_generated_receipt`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneratedReceiptWrite {
    /// The page was absent and now holds exactly the receipt bytes.
    Written,
    /// The page already held exactly the receipt bytes; nothing was written.
    Identical,
    /// The page holds other bytes, which are the owner's; nothing was written.
    Conflict,
}

/// Scoped SilverBullet retrieval and confined generated-page writes.
#[derive(Clone)]
pub struct VaultBridge {
    config: VaultConfig,
    /// Shares namespace and exclusion rules with the brain's loopback source.
    scope: VaultScope,
    /// The generated namespace as path segments (validated configuration).
    generated_segments: Vec<String>,
    source: Option<SilverBulletSource>,
}

impl VaultBridge {
    /// Validates the configuration and builds the bridge. The loopback
    /// SilverBullet source, when configured, inherits the configured byte
    /// bounds and deadline; its host is fixed to `127.0.0.1` by the brain
    /// source module.
    pub fn new(config: VaultConfig) -> Result<Self, VaultConfigError> {
        config.validate()?;
        // Reuse the brain source's namespace grammar and exclusions.
        let scope = VaultScope::new(
            &config.general_namespaces,
            &config.generated_namespace,
            &config.excluded_namespaces,
        )
        .map_err(|error| VaultConfigError::field("namespaces", error.to_string()))?;
        let generated_segments: Vec<String> = config
            .generated_namespace
            .split('/')
            .map(str::to_owned)
            .collect();
        let atlas =
            AtlasId::new(config.source_id.clone()).map_err(|_| unreachable_setting("source_id"))?;
        let source = config.silverbullet.as_ref().map(|deployment| {
            let mut source = SilverBulletSource::new(atlas.clone(), deployment.port, scope.clone());
            if let Some(space_root) = &deployment.expected_space_root {
                source = source.with_expected_space_root(space_root.clone());
            }
            source.with_page_bound(config.max_pages).with_limits(
                MAX_RESPONSE_BYTES,
                config.max_page_bytes,
                Duration::from_millis(config.timeout_ms),
            )
        });
        Ok(Self {
            config,
            scope,
            generated_segments,
            source,
        })
    }

    /// The validated configuration this bridge serves.
    pub const fn config(&self) -> &VaultConfig {
        &self.config
    }

    /// The scope decision for one page name: pure, no I/O, identical to the
    /// decision applied during scoped pinning.
    pub fn page_scoped(&self, page_name: &str) -> bool {
        self.scope.admits(page_name)
    }

    /// Applies the scope decision to a page-name listing, preserving order.
    pub fn scoped_page_names<'a>(&self, listed: &'a [String]) -> Vec<&'a str> {
        listed
            .iter()
            .filter(|name| self.scope.admits(name))
            .map(String::as_str)
            .collect()
    }

    /// The configured loopback source, or the typed unavailability of the
    /// optional SilverBullet deployment.
    fn configured_source(&self) -> BrainResult<&SilverBulletSource> {
        self.source.as_ref().ok_or_else(|| BrainError::Unavailable {
            component: "silverbullet",
            reason: "no SilverBullet deployment is configured for this vault; \
                     the optional default UI is absent"
                .into(),
        })
    }

    /// Pins the scoped vault revision over the real loopback `/.fs/` API.
    ///
    /// With no SilverBullet deployment configured, or with the service
    /// down, this fails typed unavailable — never an empty fake success.
    /// An existing vault with zero eligible pages is an honest empty pin.
    /// The scope gate, the page-count bound, and the addressability rule
    /// are enforced by the brain source itself
    /// ([`SilverBulletSource::pin_scoped`]) before any page byte moves.
    pub fn pin_scoped_vault(&self) -> BrainResult<PinnedVault> {
        self.configured_source()?.pin_scoped()
    }

    /// Lists addressable generated page names through the configured vault
    /// endpoint. This metadata-only view lets the projection writer retire
    /// obsolete pages after restart; it does not grant source read access.
    pub fn generated_page_names(&self) -> BrainResult<Vec<String>> {
        Ok(self
            .configured_source()?
            .list_pages()?
            .into_iter()
            .filter(|page| self.generated_relative_path(&page.name).is_ok())
            .map(|page| page.name)
            .collect())
    }

    /// The `vault.search` operation: one digest-identified scoped snapshot.
    /// The optional caller bound never exceeds the configured bound.
    pub fn search(&self, input: &VaultSearchInput) -> Result<VaultSearchOutput, VaultError> {
        if let Some(max_pages) = input.max_pages {
            if max_pages as usize > MAX_PAGES_CEILING {
                return Err(VaultError::Params(format!(
                    "max_pages must be at most {MAX_PAGES_CEILING}"
                )));
            }
        }
        let limit = input.max_pages.map_or(self.config.max_pages, |max_pages| {
            (max_pages as usize).min(self.config.max_pages)
        });
        let pinned = self.pin_scoped_vault()?;
        let mut pages: Vec<VaultSearchPage> = pinned
            .pages()
            .iter()
            .map(|page| VaultSearchPage {
                name: page.meta.name.clone(),
                digest: page.digest.to_string(),
                bytes: page.text.len() as u64,
            })
            .collect();
        let truncated = pages.len() > limit;
        pages.truncate(limit);
        Ok(VaultSearchOutput {
            source_id: pinned.atlas_id().as_str().to_owned(),
            revision_digest: pinned.revision().to_string(),
            page_count: pages.len(),
            truncated,
            pages,
        })
    }

    /// The `vault.write_generated` operation: one confined machine write.
    ///
    /// The page name must lie beneath the generated namespace; every other
    /// name — outside namespaces, traversal attempts, escapes through
    /// symlinked components — is refused before any byte moves. The write
    /// replaces only entries inside the generated namespace, atomically and
    /// durably, and never follows a symlink at any path component.
    pub fn write_generated(
        &self,
        input: &VaultWriteGeneratedInput,
    ) -> Result<VaultWriteGeneratedOutput, VaultError> {
        let relative = self.generated_relative_path(&input.page_name)?;
        let bytes = input.content.as_bytes();
        if bytes.is_empty() {
            return Err(VaultError::Params("content must not be empty".into()));
        }
        if bytes.len() as u64 > self.config.max_page_bytes {
            return Err(VaultError::Refused(format!(
                "content exceeds the {} byte bound",
                self.config.max_page_bytes
            )));
        }
        // Fail closed on an absent or unprotected vault root before any
        // directory component is touched.
        PrivateCapability::seal(&self.config.vault_root).map_err(|error| {
            VaultError::Unavailable {
                component: "vault",
                reason: format!(
                    "the vault root is absent or not a private 0700 directory ({error})"
                ),
            }
        })?;
        let root = open_vault_root(&self.config.vault_root)?;
        ensure_confined_directories(&root, &relative)?;
        let capability = PrivateCapability::seal(&self.config.vault_root).map_err(|error| {
            VaultError::Unavailable {
                component: "vault",
                reason: format!(
                    "the vault root moved or was unprotected during the write ({error})"
                ),
            }
        })?;
        // An identical page is left alone: rewriting the same bytes only
        // bumps the mtime, which Syncthing then replicates to every host
        // (projections re-emit unchanged pages, and several seats emit the
        // same shared page).
        if !page_holds(&capability, &relative, bytes) {
            capability.write_atomic(&relative, bytes, 0o644)?;
        }
        Ok(VaultWriteGeneratedOutput {
            page_name: input.page_name.clone(),
            content_digest: Digest::hash(bytes).to_string(),
            byte_count: bytes.len(),
        })
    }

    /// Publishes one derived effect receipt page without ever replacing
    /// bytes it did not write: the same page-name gate, bounds, private-root
    /// seal and confined directory walk as [`Self::write_generated`], but an
    /// absent page is created exclusively, a page already holding exactly
    /// these bytes is left alone, and any other existing page — an owner's
    /// edit, or a concurrent creator — is a [`GeneratedReceiptWrite::Conflict`].
    pub fn publish_generated_receipt(
        &self,
        input: &VaultWriteGeneratedInput,
    ) -> Result<(GeneratedReceiptWrite, VaultWriteGeneratedOutput), VaultError> {
        let relative = self.generated_relative_path(&input.page_name)?;
        let bytes = input.content.as_bytes();
        if bytes.is_empty() {
            return Err(VaultError::Params("content must not be empty".into()));
        }
        if bytes.len() as u64 > self.config.max_page_bytes {
            return Err(VaultError::Refused(format!(
                "content exceeds the {} byte bound",
                self.config.max_page_bytes
            )));
        }
        PrivateCapability::seal(&self.config.vault_root).map_err(|error| {
            VaultError::Unavailable {
                component: "vault",
                reason: format!(
                    "the vault root is absent or not a private 0700 directory ({error})"
                ),
            }
        })?;
        let root = open_vault_root(&self.config.vault_root)?;
        ensure_confined_directories(&root, &relative)?;
        let capability = PrivateCapability::seal(&self.config.vault_root).map_err(|error| {
            VaultError::Unavailable {
                component: "vault",
                reason: format!(
                    "the vault root moved or was unprotected during the write ({error})"
                ),
            }
        })?;
        let held = |same: bool| {
            if same {
                GeneratedReceiptWrite::Identical
            } else {
                GeneratedReceiptWrite::Conflict
            }
        };
        let outcome = match existing_page(&capability, &relative, bytes)? {
            Some(same) => held(same),
            None => {
                // Stage complete, synced bytes away from the addressable page.
                // Exclusive linking never overwrites an owner or concurrent writer,
                // and a crash during staging cannot leave a partial receipt page.
                let staging =
                    relative.with_file_name(format!(".receipt-{}.tmp", uuid::Uuid::new_v4()));
                capability.create_atomic(&staging, bytes, 0o644)?;
                let published = capability.install_exclusive(&staging, &relative);
                if let Err(error) = capability.remove(&staging) {
                    return Err(
                        if matches!(published, Err(ConfinedError::AlreadyExists { .. })) {
                            error.into()
                        } else {
                            VaultError::PublicationUncertain(error)
                        },
                    );
                }
                match published {
                    Ok(()) => GeneratedReceiptWrite::Written,
                    Err(ConfinedError::AlreadyExists { .. }) => {
                        held(existing_page(&capability, &relative, bytes)? == Some(true))
                    }
                    Err(error) => return Err(VaultError::PublicationUncertain(error)),
                }
            }
        };
        Ok((
            outcome,
            VaultWriteGeneratedOutput {
                page_name: input.page_name.clone(),
                content_digest: Digest::hash(bytes).to_string(),
                byte_count: bytes.len(),
            },
        ))
    }

    /// Removes one page of the brain's generated knowledge projection
    /// (`<generated>/knowledge/…`). Only that reserved tree is removable —
    /// memory pages and every other generated or human page are refused
    /// before any IO — through the same confined, symlink-refusing walk as
    /// [`Self::write_generated`]. Absence is success.
    ///
    /// Delete obsolete projections so vault listings do not accumulate tombstones.
    pub fn remove_generated_knowledge(&self, page_name: &str) -> Result<(), VaultError> {
        let relative = self.generated_relative_path(page_name)?;
        let in_knowledge_tree = page_name
            .split('/')
            .nth(self.generated_segments.len())
            .is_some_and(|segment| segment == RESERVED_KNOWLEDGE_SEGMENT)
            && page_name.split('/').count() > self.generated_segments.len() + 1;
        if !in_knowledge_tree {
            return Err(VaultError::Refused(format!(
                "only pages beneath the generated knowledge tree \
                 ({}/{RESERVED_KNOWLEDGE_SEGMENT}/…) can be removed",
                self.generated_segments.join("/")
            )));
        }
        let capability = PrivateCapability::seal(&self.config.vault_root).map_err(|error| {
            VaultError::Unavailable {
                component: "vault",
                reason: format!(
                    "the vault root is absent or not a private 0700 directory ({error})"
                ),
            }
        })?;
        capability.remove(&relative)?;
        Ok(())
    }

    /// Requires an addressable path beneath the generated namespace, excluding private segments.
    /// Unlike read scope, this allows per-seat memory pages; the daemon enforces the caller's seat.
    fn generated_relative_path(&self, page_name: &str) -> Result<PathBuf, VaultError> {
        let excluded = self
            .config
            .excluded_namespaces
            .iter()
            .any(|name| page_name.split('/').any(|segment| segment == name));
        if excluded || !addressable_page_name(page_name) {
            let generated = self.generated_segments.join("/");
            return Err(VaultError::Refused(format!(
                "must be an addressable page path that begins with the generated \
                     namespace, e.g. {generated:?}/<page-name> — any other namespace, \
                     a bare page name, or a non-Markdown-addressable path is refused \
                     (M11 SilverBullet page-name grammar)"
            )));
        }
        let segments: Vec<&str> = page_name.split('/').collect();
        let generated: Vec<&str> = self.generated_segments.iter().map(String::as_str).collect();
        if segments.len() <= generated.len() {
            return Err(VaultError::Refused(format!(
                "has no component beneath the generated namespace — write to \
                     {generated:?}/<page-name>"
            )));
        }
        if segments[..generated.len()] != generated[..] {
            return Err(VaultError::Refused(
                "lies outside the generated namespace; machine writes are \
                 generated-namespace-only"
                    .into(),
            ));
        }
        // Belt and braces: the joined path must satisfy the same byte-level
        // relative-path grammar the confined writer enforces.
        let joined = segments.join("/");
        odin_confined_fs::validate_relative_path(Path::new(&joined))
            .map_err(|error| VaultError::Refused(error.to_string()))?;
        Ok(PathBuf::from(joined))
    }
}

/// Whether the confined page already holds exactly `bytes` (read bounded
/// by their length + 1; any open or read failure means "write it").
fn page_holds(capability: &PrivateCapability, relative: &Path, bytes: &[u8]) -> bool {
    use std::io::Read as _;
    let Ok(file) = capability.open_read(relative) else {
        return false;
    };
    let mut existing = Vec::with_capacity(bytes.len() + 1);
    file.take(bytes.len() as u64 + 1)
        .read_to_end(&mut existing)
        .is_ok_and(|_| existing == bytes)
}

/// Whether a confined page exists and holds exactly `bytes`: `None` when it
/// is absent, `Some(true)` for the same bytes, `Some(false)` for any other
/// content. Unlike [`page_holds`], an unreadable page is an error, never a
/// license to write over it.
fn existing_page(
    capability: &PrivateCapability,
    relative: &Path,
    bytes: &[u8],
) -> Result<Option<bool>, VaultError> {
    use std::io::Read as _;
    let file = match capability.open_read(relative) {
        Ok(file) => file,
        Err(ConfinedError::ComponentMissing { .. }) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut existing = Vec::with_capacity(bytes.len() + 1);
    file.take(bytes.len() as u64 + 1)
        .read_to_end(&mut existing)
        .map_err(|error| {
            VaultError::Confined(ConfinedError::Io {
                component: relative.display().to_string(),
                reason: error.to_string(),
            })
        })?;
    Ok(Some(existing == bytes))
}

/// A configuration invariant already enforced by `VaultConfig::validate`;
/// reaching one of these is a construction bug, not a runtime path.
fn unreachable_setting(field: &'static str) -> VaultConfigError {
    VaultConfigError::field(field, "was validated but re-parsed as invalid")
}
/// Opens the vault root descriptor for the confined directory walk. The
/// root itself is opened without creating anything: a root that vanishes
/// between the private-root seal and this walk fails the write honestly.
fn open_vault_root(vault_root: &Path) -> Result<File, VaultError> {
    let mut current = File::open("/").map_err(|error| {
        VaultError::Confined(ConfinedError::Io {
            component: "/".into(),
            reason: error.to_string(),
        })
    })?;
    // Kernel-enforced confinement: `RESOLVE_BENEATH` refuses any `..`
    // component and `O_NOFOLLOW` refuses symlinked ones, so a drifted
    // root path can only fail typed, never escape.
    for component in vault_root.iter().skip(1) {
        current = open_directory(&current, component, false)?;
    }
    Ok(current)
}

/// Opens (or exclusively creates) one directory component beneath `parent`.
/// Symlinked or non-directory components are refusals, never traversed;
/// `create` governs whether an absent component is created mode 0700.
fn open_directory(parent: &File, component: &OsStr, create: bool) -> Result<File, VaultError> {
    match openat2(parent, component, DIRECTORY_FLAGS, Mode::empty(), RESOLVE) {
        Ok(descriptor) => Ok(File::from(descriptor)),
        Err(Errno::NOENT) if create => {
            match mkdirat(parent, component, Mode::RWXU) {
                Ok(()) | Err(Errno::EXIST) => {}
                Err(error) => return Err(directory_error(component, error)),
            }
            match openat2(parent, component, DIRECTORY_FLAGS, Mode::empty(), RESOLVE) {
                Ok(descriptor) => Ok(File::from(descriptor)),
                Err(error) => Err(directory_error(component, error)),
            }
        }
        Err(error) => Err(directory_error(component, error)),
    }
}

/// Ensures every directory component above the leaf of `relative` exists
/// beneath the vault root, creating missing ones mode 0700 with the same
/// confined discipline as the writer itself.
fn ensure_confined_directories(root: &File, relative: &Path) -> Result<(), VaultError> {
    let mut current = root.try_clone().map_err(|error| {
        VaultError::Confined(ConfinedError::Io {
            component: "<vault-root-fd>".into(),
            reason: error.to_string(),
        })
    })?;
    let components: Vec<&OsStr> = relative
        .parent()
        .into_iter()
        .flat_map(|parent| parent.iter())
        .collect();
    for component in components {
        current = open_directory(&current, component, true)?;
    }
    Ok(())
}

/// Maps a confined directory failure to its typed class: symlinked and
/// non-directory components are policy refusals; everything else is a
/// confined filesystem failure.
fn directory_error(component: &OsStr, error: Errno) -> VaultError {
    let name = component.to_string_lossy().into_owned();
    match error {
        Errno::LOOP => VaultError::Refused(format!(
            "generated namespace component {name:?} is a symlink; refusing traversal"
        )),
        Errno::NOTDIR => VaultError::Refused(format!(
            "generated namespace component {name:?} is not a directory"
        )),
        error => VaultError::Confined(ConfinedError::Io {
            component: name,
            reason: error.to_string(),
        }),
    }
}
