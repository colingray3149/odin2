//! Operator-facing service surface: the construction authority, the
//! operator-declared source bindings, and the served-state projections.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use odin_domain::knowledge::{AtlasId, EmbeddingModelId, IndexGeneration, IndexedChunk};
use odin_domain::Digest;

use crate::index;

/// Operator-supplied construction authority for one [`BrainService`](super::BrainService).
#[derive(Clone)]
pub struct BrainServiceConfig {
    /// Directory holding the brain's durable stores (index, archives).
    /// Created on open; stores are confined inside.
    pub store_root: PathBuf,
    /// Every knowledge source this service may serve, keyed by exact
    /// `AtlasId`: Atlas repository roots, loopback SilverBullet vaults, and
    /// declared control-plane state. Open fails unless the wired set equals
    /// the resolved knowledge policy's authorized set.
    pub sources: BTreeMap<AtlasId, BrainSourceConfig>,
    /// Whether the runtime composition resolved a lane-bindable embedding
    /// backend at open. `false` is honest only under a lexical-only
    /// knowledge policy. The service stores no executor object: callers
    /// supply the session-bound embedder per retrieval call.
    pub embedding_available: bool,

    /// Declared embedding model of the actual backend binding the injected
    /// executor executes under, carried from the runtime binding itself.
    /// `None` is honest only under the lexical-only posture; a declared
    /// model without an executor fails vector/hybrid retrieval typed
    /// unavailable rather than serving unbound vectors.
    pub embedding_model: Option<EmbeddingModelId>,
    /// Kernel-approval verification seam for governed archive ingest,
    /// supplied by runtime wiring over the durable ledger. `None` leaves
    /// archive ingest typed-unavailable: caller-supplied approval strings
    /// alone never authorize mutation.
    pub archive_ingest_gate: Option<Arc<dyn super::archive::ArchiveIngestGate>>,
    /// The brain's PostgreSQL store (`[brain] postgres`): when present, the
    /// index mirrors every generation there and turns nominate from it.
    pub postgres: Option<Arc<crate::index::postgres::BrainPostgres>>,
}

impl std::fmt::Debug for BrainServiceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrainServiceConfig")
            .field("store_root", &self.store_root)
            .field("sources", &self.sources)
            .field("embedding_available", &self.embedding_available)
            .field("embedding_model", &self.embedding_model)
            .field("archive_ingest_gate", &self.archive_ingest_gate.is_some())
            .field("postgres", &self.postgres.is_some())
            .finish()
    }
}

/// One operator-declared knowledge source backing the brain service.
#[derive(Clone, Debug)]
pub enum BrainSourceConfig {
    /// Immutable Atlas AST index over one repository root.
    Atlas {
        /// Repository root the Atlas build indexes.
        root: PathBuf,
    },
    /// A running SilverBullet vault over its real loopback HTTP API; the
    /// host is fixed to `127.0.0.1` by the source module, and only the
    /// port, the expected server-side space root, and the validated vault
    /// namespace scope are configurable. The scope is mandatory: only
    /// allowlisted/general and generated pages are ever read or pinned —
    /// excluded segments can never enter the index through this source.
    SilverBullet {
        /// Loopback port the SilverBullet server listens on.
        port: u16,
        /// Expected `X-Space-Path` header value; responses naming a
        /// different space fail typed instead of being trusted.
        expected_space_root: Option<String>,
        /// Retrieval-eligible general namespace segments — the same
        /// allowlist fields the validated vault configuration carries.
        general_namespaces: Vec<String>,
        /// The `/`-separated generated namespace whose machine-written
        /// pages stay retrieval-eligible.
        generated_namespace: String,
        /// Hard private exclusion segments; no page carrying one at any
        /// depth is ever read, pinned, or served.
        excluded_namespaces: Vec<String>,
        /// Page-count bound for one scoped pin (1..=100_000).
        max_pages: usize,
    },
    /// One seat's reserved memory namespace, projected from the SAME
    /// validated Hermes vault singleton the daemon's vault surface serves.
    /// The source arrives fully composed — canonical id `memory.<seat>`,
    /// scope exactly `<vault generated>/memories/<seat>` — and carries no
    /// operator-declarable authority: there is no caller root, port, or
    /// namespace override for this kind, so a memory source cannot be
    /// pointed anywhere but the daemon's own vault.
    Memory {
        /// The preconfigured confined loopback vault source; its
        /// generated-only scope admits only the seat's own reserved
        /// memory subtree.
        source: crate::source::silverbullet::SilverBulletSource,
    },
    /// Published registry entities, pinned to the verified revision and hash.
    StateRegistry {
        source: crate::source::state::registry::RegistrySource,
    },
    /// Runtime entities, atomically pinned to the materialized read-model head.
    StateLive {
        source: crate::source::state::live::LiveSource,
    },
    /// Governed task and workload state from durable authority.
    StateTasks {
        source: crate::source::state::tasks::TasksSource,
    },
    /// Commit-pinned Atlas and repository observations from declared projects.
    StateRepos {
        source: crate::source::state::repos::ReposSource,
    },
    /// Deterministic project/day compression of the daemon's operation journals.
    OpsHistory {
        source: crate::source::ops::HistorySource,
    },
    /// A read-only external archive export (chat export, mailbox) ingested
    /// as normalized memory through the governed archive path. The source
    /// identity is the config map's `AtlasId` key; the declaration carries
    /// every selection rule. Nothing is read at open or retrieval: serving
    /// uses only the persisted approved revision, and ingest runs only
    /// through the governed `ingest_archive` method after operator
    /// approval. Records stay observed memory, never authority.
    Archive {
        /// The strict operator declaration: format, path, memory namespace,
        /// confidentiality class, and the declared selection policy.
        declaration: odin_domain::knowledge::archive::ArchiveSourceDeclaration,
    },
    /// A source whose declared privacy class (on the source itself, or as
    /// the floor of a project that declares it as memory) is withheld from
    /// models (`APL_RESTRICTED`, `SECRET`). Its content is never read: it
    /// serves exactly one item, the plain refusal sentence, so retrieval
    /// still answers "that is restricted" instead of a silent gap.
    Withheld {
        /// The declared class (always one withheld from models).
        class: odin_domain::knowledge::PrivacyClass,
    },
}

/// The current serving state of one brain service.
#[derive(Clone, Debug)]
pub struct BrainStatus {
    /// Policy binding the service was opened with (digest-bound).
    pub policy_digest: Digest,
    /// Registry revision the policy was resolved from.
    pub registry_revision: u64,
    /// Live pinned revision per composed knowledge source.
    pub pinned: BTreeMap<AtlasId, Digest>,
    /// Current serving generation per source, when one has been built.
    pub generations: BTreeMap<AtlasId, IndexGeneration>,
}

/// One immutable knowledge item as served by `brain://`.
#[derive(Clone, Debug)]
pub struct KnowledgeItem {
    /// Generation the item was served from.
    pub generation: IndexGeneration,
    /// Atlas node provenance for scope enforcement at the resolver boundary.
    /// `None` for sources without Atlas node identity (vault pages); such
    /// items prove no scope dimension and are readable only from an unbound
    /// caller scope.
    pub provenance: Option<index::model::ItemProvenance>,
    /// Exact chunks covering the item, in chunk order.
    pub chunks: Vec<IndexedChunk>,
    /// Structured export provenance when the item belongs to a published
    /// archive source; `None` for Atlas and vault items. Untrusted
    /// observed metadata, never authority.
    pub archive: Option<super::archive::ArchiveCitation>,
}

/// One published archive record resolved by its content-addressed
/// `record_key`, with the item that carries it. The item id is the record
/// row's own stored identity, never inferred from chunk content; the item
/// itself is served through the same pinned-generation path as
/// [`KnowledgeItem`].
#[derive(Clone, Debug)]
pub struct KnowledgeRecord {
    /// The item identity the published record is stored under.
    pub item_id: odin_domain::knowledge::ids::KnowledgeItemId,
    /// The immutable item serving the record's content.
    pub item: KnowledgeItem,
}
