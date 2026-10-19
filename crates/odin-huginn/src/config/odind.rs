//! Strict generated controller configuration (`odin.odind-config.v1`).
//!
//! One deny-unknown versioned Nix-generated `odind.toml` owns paths, listeners,
//! executables, catalog references, global capacity, and snapshot bootstrap.
//! Production constructors require it; there are no constructor defaults, and
//! applying a configuration change means a restart — never a hot reload.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::SocketAddr;
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::huginn::{ConfigError, HuginnBindConfig, HuginnLimits};
use super::manifest::PathDigestRef;

/// Exact schema discriminant of a genuine controller configuration.
pub const ODIND_CONFIG_SCHEMA: &str = "odin.odind-config.v1";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OdindConfig {
    pub schema: String,
    pub revision: u64,
    pub identity: OdindIdentityConfig,
    pub paths: OdindPathsConfig,
    pub listener: OdindListenerConfig,
    pub executables: OdindExecutablesConfig,
    pub catalogs: OdindCatalogsConfig,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub projects: BTreeMap<String, OdindProjectConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lane_bindings: Vec<OdindLaneBinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub seats: Vec<OdindSeatBinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub file_roots: Vec<odin_domain::huginn::FileRoot>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tailnet_peers: BTreeMap<String, String>,
    pub publish: OdindPublishConfig,
    /// Explicit non-secret registered worker bus endpoint; the only
    /// transport binding between the controller and its worker authority.
    pub worker_bus: String,
    pub capacity: HuginnLimits,
    /// Optional bounded governed implementation-worker delegation. Absent
    /// disables `task.create`; present, every field is validated and required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<OdindDelegationConfig>,
    /// Explicit cluster binding. Absence disables Kubernetes execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kube: Option<OdindKubeConfig>,
    /// Declared out-of-process adapter backends, keyed by
    /// canonical adapter ID. Each backend's executable is the runtime
    /// manifest identity `adapter.<id>`; its argv is static declaration
    /// data. Registry capabilities with `implementation = "<id>"` route to
    /// it. Empty: no adapter backend exists on this host and every adapter
    /// capability is a typed unavailable.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub adapter_backends: BTreeMap<String, OdindAdapterBackend>,
    /// Maps gateway credential handles to host environment variable names.
    /// Values never enter configuration, logs, argv, or receipts; missing mappings reject the route.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub gateway_host_credentials: BTreeMap<String, OdindGatewayHostCredential>,
    /// Optional brain serving section: the actual served model identity and
    /// window plus the explicit knowledge sources the brain service pins.
    /// Absence leaves the daemon without a brain — brain operations fail
    /// typed-unavailable while every unrelated surface keeps serving. No
    /// key, token, or gate material belongs here; the acceptance gate stays
    /// a trusted runtime dependency that only authentic kernel operation
    /// supplies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub brain: Option<OdindBrainConfig>,
    /// Optional Hermes/Sinmara life-workflow surface section. Absence
    /// disables the entire surface — no Hermes runtime composes, no life
    /// capability tool registers, and every affected operation fails typed.
    /// Present, every value is an operator deployment fact;
    /// no field here has a compiled default anywhere in `odin-hermes`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hermes: Option<OdindHermesConfig>,
    /// Where raised incidents alert Colin's phone.
    /// Absent: incidents still reach Huginn and the conversation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alerts: Option<OdindAlertsConfig>,
}

/// The declared phone alert sink: an ntfy topic URL on this host (plain
/// POST of the message body). A deployment fact, never a compiled default.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OdindAlertsConfig {
    pub phone_url: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OdindBrainConfig {
    /// The exact served model identity, context window, and optionally the
    /// declared brain context tokenizer the brain composes against; the
    /// provider comes from the actual served route, never from this file.
    pub serving_model: OdindServingModelConfig,
    /// Declared context window, in tokens, of every other served lane a
    /// seat may launch on or switch to, keyed by the exact lane identity.
    /// Each session's context guard binds to the window of the model it is
    /// actually running; a launch option with no declared window runs
    /// unguarded, and a live switch to it is refused.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub lane_windows: BTreeMap<String, OdindLaneWindow>,
    /// Explicit knowledge sources keyed by exact `AtlasId` (for example
    /// `atlas:odin`, `vault:silverbullet`). Every key the served policy
    /// authorizes must appear here, and no key outside the policy may be
    /// wired.
    #[serde(default)]
    pub sources: BTreeMap<String, OdindBrainSourceConfig>,
    /// Optional embedding route for vector and hybrid retrieval: the
    /// nonsecret provider identity and the private gateway endpoint the
    /// kernel provider lease binds against. The served embedding model is
    /// never declared here — it is derived from the actual published resolved
    /// provider route; a missing or disabled route keeps vector and hybrid
    /// retrieval typed-unavailable instead of downgrading. No key or token
    /// material belongs here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding: Option<OdindBrainEmbeddingConfig>,
    /// The brain's PostgreSQL store as libpq keywords (`host=/run/postgresql
    /// dbname=odin_brain`). Absent, turns serve from the SQLite index.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postgres: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OdindBrainEmbeddingConfig {
    /// Registry provider id of the embedding route; the model identity and
    /// budget come from the actual published resolved route, never from
    /// this file.
    pub provider: String,
    /// Private HTTP endpoint of the gateway serving the route, either
    /// loopback (`http://127.0.0.1:<port>`) or an explicitly declared
    /// `[tailnet_peers]` address (`http://<peer-ip>:<port>`). The daemon
    /// never sends embeddings to any other network destination.
    pub endpoint: String,
}

/// One other lane's declared window: a bare token count, counted as UTF-8
/// bytes (about four times a model tokenizer's count, so only a large window
/// guards honestly), or the count with the lane's own tokenizer — a small
/// local window (kubert-mini's 32768 on Qwen3) needs its real tokenizer.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum OdindLaneWindow {
    Bytes(NonZeroU32),
    Counted(OdindCountedLaneWindow),
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OdindCountedLaneWindow {
    pub context_window_tokens: NonZeroU32,
    /// A declared brain context tokenizer identity, as for
    /// [`OdindServingModelConfig::tokenizer`].
    pub tokenizer: String,
}

impl OdindLaneWindow {
    pub fn window(&self) -> NonZeroU32 {
        match self {
            Self::Bytes(window) => *window,
            Self::Counted(counted) => counted.context_window_tokens,
        }
    }

    /// The declared tokenizer identity; `None` counts bytes.
    pub fn tokenizer(&self) -> Option<&str> {
        match self {
            Self::Bytes(_) => None,
            Self::Counted(counted) => Some(&counted.tokenizer),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OdindServingModelConfig {
    /// Exact serving model identity of the actual served route.
    pub name: String,
    /// Positive served-context window in tokens; brain context budgets are
    /// resolved against it and never against a guessed constant.
    pub context_window_tokens: NonZeroU32,
    /// Optional declared brain context tokenizer identity. Absent keeps the
    /// conservative exact-byte default (`odin.tokenizer.utf8-bytes.v1`);
    /// `odin.tokenizer.qwen3.v1` selects the pinned Qwen3-family counter.
    /// The value is never inferred from the model name, and any other value
    /// fails the projection instead of downgrading to an approximation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokenizer: Option<String>,
}

/// One operator-declared knowledge source, discriminated by `kind`.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OdindBrainSourceConfig {
    /// `atlas` (immutable AST source over one repository root),
    /// `silverbullet` (loopback vault over its HTTP API), one
    /// `state.registry` / `state.live` / `state.tasks` — a projection of
    /// the daemon's own control-plane authorities — or `memory`, a seat's
    /// reserved memory namespace (canonical id `memory.<seat>`) composed
    /// from the daemon's validated Hermes vault singleton, which takes no
    /// operator-declarable field at all — or `archive` (read-only external
    /// export ingested as normalized memory).
    pub kind: String,
    /// Declared protocol privacy class of everything this source serves
    /// (any kind; for archive intake folders it sits beside the archive's
    /// seat-sharing `privacy_class`). `apl_restricted`/`secret` compose
    /// the source as withheld: its content is never read or given to a
    /// model, and retrieval serves one plain refusal sentence instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy: Option<odin_domain::knowledge::PrivacyClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<PathBuf>,
    /// Loopback vault port; required exactly for
    /// `kind = "silverbullet"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Expected server-side vault space root; responses naming a different
    /// space fail typed instead of being trusted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_space_root: Option<String>,
    /// Retrieval allowlist namespaces (1..=32 single confined segments);
    /// required exactly for `kind = "silverbullet"`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub general_namespaces: Vec<String>,
    /// The only machine-writable namespace (1..=8 '/'-separated confined
    /// segments); required exactly for `kind = "silverbullet"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_namespace: Option<String>,
    /// Hard private exclusions that never enter retrieval (0..=32 single
    /// confined segments, disjoint from the allowlist and from every
    /// generated segment).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded_namespaces: Vec<String>,
    /// Retrieval page-count ceiling (1..=100_000); required exactly for
    /// `kind = "silverbullet"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_pages: Option<usize>,
    /// Archive export format (`claude-export`, `grok-export`, `mbox`,
    /// `chatgpt-export`, `gemini-workspace`, `notebooklm`);
    /// required exactly for `kind = "archive"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<odin_domain::knowledge::ArchiveFormat>,
    /// Read-only archive export path (a file or directory root as the
    /// format defines); required exactly for `kind = "archive"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export_path: Option<PathBuf>,
    /// Retrieval namespace for ingested archive memory; required exactly
    /// for `kind = "archive"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_namespace: Option<String>,
    /// Confidentiality class governing which seats may be served the
    /// ingested memory; required exactly for `kind = "archive"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_class: Option<odin_domain::knowledge::ArchivePrivacyClass>,
    /// Declared record identity/dedupe strategy; required exactly for
    /// `kind = "archive"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dedupe_key: Option<odin_domain::knowledge::ArchiveDedupeKey>,
    /// Declared archive selection policy applied by the parser; required
    /// exactly for `kind = "archive"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection: Option<odin_domain::knowledge::ArchiveSelectionPolicy>,
}

impl OdindBrainSourceConfig {
    /// A `memory` source: the kind alone, every field absent — what
    /// composition serves for every `memory.*` a served seat authorizes.
    pub fn memory() -> Self {
        Self {
            kind: "memory".to_owned(),
            privacy: None,
            root: None,
            port: None,
            expected_space_root: None,
            general_namespaces: Vec::new(),
            generated_namespace: None,
            excluded_namespaces: Vec::new(),
            max_pages: None,
            format: None,
            export_path: None,
            memory_namespace: None,
            privacy_class: None,
            dedupe_key: None,
            selection: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OdindKubeConfig {
    pub kubeconfig: PathBuf,
    pub cluster: String,
    pub namespace: String,
    pub request_timeout_seconds: NonZeroU64,
    pub teardown_timeout_seconds: NonZeroU64,
    /// Declared absolute host path of the workload image's `identity.json`
    /// (the `odin.workload-image-identity.v1` document the image build emits
    /// beside the OCI archive). The operator-owned file is the trust root:
    /// the kube composition reads and validates it once, registers the exact
    /// bytes as a content-addressed ledger artifact, and every admission
    /// re-reads the identity through that digest-verified artifact — never
    /// from the build output directly. Required whenever kube is configured;
    /// there is no default.
    pub image_identity: PathBuf,
    /// Maps gateway credential handles to Secret names and keys used by SecretKeyRef.
    /// Workload launches reject routes without a credential mapping.
    #[serde(default)]
    pub gateway_credentials: std::collections::BTreeMap<String, OdindGatewayCredential>,
    /// Declared absolute host folder the node provisions for the workload
    /// uid (the pod's hostPath export, mounted as an existing Directory).
    /// When declared, every drafted workload exports exactly here: the
    /// draft supplies it and refuses any other folder, since an
    /// unprovisioned folder cannot mount and the confined uid cannot write
    /// one it does not own.
    #[serde(default)]
    pub export_root: Option<PathBuf>,
    /// Default agent-pod lane; the selected seat must still permit it.
    #[serde(default)]
    pub agent_lane: Option<String>,
}

/// Secret name and key for a gateway credential handle; values never enter configuration.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OdindGatewayCredential {
    pub secret: String,
    /// The Secret key holding the gateway credential value.
    pub key: String,
}

/// Host environment variable for a gateway credential handle; its value never enters configuration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "snake_case",
    try_from = "GatewayHostCredentialRaw"
)]
pub struct OdindGatewayHostCredential {
    environment: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
struct GatewayHostCredentialRaw {
    environment: String,
}

impl TryFrom<GatewayHostCredentialRaw> for OdindGatewayHostCredential {
    type Error = String;

    fn try_from(raw: GatewayHostCredentialRaw) -> Result<Self, Self::Error> {
        let environment = raw.environment;
        let mut chars = environment.chars();
        let valid = chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            return Err(format!(
                "gateway host credential environment name {environment:?} is not a valid \
                 environment variable name (ASCII letters, digits, underscores, not starting \
                 with a digit)"
            ));
        }
        Ok(Self { environment })
    }
}

impl OdindGatewayHostCredential {
    /// Validates the environment variable name with the deserialization checks.
    pub fn new(environment: impl Into<String>) -> Result<Self, String> {
        Self::try_from(GatewayHostCredentialRaw {
            environment: environment.into(),
        })
    }

    /// The declared host environment variable name; the VALUE stays secret
    /// and is resolved by the trusted composition only.
    pub fn environment(&self) -> &str {
        &self.environment
    }
}

/// One declared adapter backend: the static argv its manifest-bound
/// executable (`adapter.<id>`) is launched with for every framed call.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OdindAdapterBackend {
    #[serde(default)]
    pub argv: Vec<String>,
}

/// Bounded governed OMP child-session delegation settings. The child model is
/// fixed here by host configuration and must equal one declared launch option;
/// neither model nor provider is accepted from a task request. Children use
/// the same pinned OMP process specification and admitted session authority as
/// their parent, while these limits bound fan-out and lifetime.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OdindDelegationConfig {
    /// Registry provider id of the implementation-worker route.
    pub provider: String,
    /// Registry-declared implementation-worker model (gateway lane name).
    pub model: String,
    /// Per-parent concurrent child ceiling. The seat-wide supervisor ceiling
    /// remains authoritative and can narrow this further.
    pub max_children_per_session: NonZeroUsize,
    /// Hard UTF-8 byte ceiling on one child task prompt.
    pub max_prompt_bytes: NonZeroU64,
    /// Wall-clock ceiling on one implementation child.
    pub child_timeout_seconds: NonZeroU64,
    /// How long a child that finished its turn may sit idle before the
    /// kernel ends it (freeing its worker slot and tab). Absent: only the
    /// wall-clock ceiling ends children.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_idle_seconds: Option<NonZeroU64>,
    /// How long a working child may journal no progress (a stalled model
    /// stream) before the kernel cancels the stuck turn and tells it to
    /// continue — twice at most, then it ends the child. Absent: a stalled
    /// child waits for the wall-clock ceiling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_stall_seconds: Option<NonZeroU64>,
    /// Expiry of the child session's signed token. It may never exceed the
    /// child lifetime by more than the configured bounded grace period.
    pub child_token_ttl_seconds: NonZeroU64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OdindIdentityConfig {
    pub node: String,
}

/// Nix-rendered Hermes configuration; each optional sub-table enables its adapter.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OdindHermesConfig {
    /// Absolute private state directory for the Hermes surface's durable
    /// egress cursor store. Must resolve inside the declared
    /// `paths.state_root` — composition refuses a sibling root, a `..`
    /// escape, or a symlink escape by name; the directory is created mode
    /// `0700` only when absent.
    pub state_dir: PathBuf,
    /// Owner-paired Discord surface. Absence disables the Discord surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discord: Option<OdindHermesDiscordConfig>,
    /// SilverBullet vault knowledge adapter. Absence disables vault
    /// operations — they fail typed instead of degrading.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<OdindHermesVaultConfig>,
    /// Actual Budget local-first finance summary adapter. Absence is the
    /// typed `NotConfigured` finance state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finance: Option<OdindHermesFinanceConfig>,
    /// One declaration per served life account. An empty list is the typed
    /// disabled state: the email and calendar adapters compose nothing and
    /// their operations report typed unavailable instead of degrading.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accounts: Vec<OdindHermesAccountConfig>,
    /// Base URL of the model gateway brain review posts chat completions to.
    /// Absent, reviews refuse instead of using a built-in address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_gateway: Option<String>,
    /// Local Immich server `discord_file_send` fetches `immich/<id>` assets from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub immich: Option<OdindHermesImmichConfig>,
    /// Root of the brain's raw exports; brain `doc` result paths are relative to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub brain_raw_root: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OdindHermesImmichConfig {
    /// API base, e.g. `http://127.0.0.1:2283`.
    pub url: String,
    /// Web base whose `/photos/<id>` link is given when an asset is too large to attach.
    pub web_url: String,
    /// File holding the API key; the key itself never appears in config.
    pub api_key_path: PathBuf,
}

/// Owner-paired Discord binding: one egress channel, exactly one authorized
/// owner user, and the credential handle name whose sops-rendered value only
/// the runtime resolves. No credential value is representable in this file.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OdindHermesDiscordConfig {
    /// Registry seat the Discord surface tasks on behalf of (for example
    /// `sinmara`); must be an enabled seat in the pinned snapshot.
    pub seat: String,
    /// Exact declared project; transport routing never infers it from lane order.
    pub project: String,
    /// The exactly-one owner user id admitted by the pairing flow.
    pub owner_user_id: String,
    /// The single egress channel rendered to.
    pub notify_channel_id: String,
    /// Ingress capability id (for example `seat.ask.sinmara`); must exist
    /// as an admitted contract in the pinned snapshot at composition time.
    pub capability: String,
    /// Bounded capacity of the egress render queue.
    pub egress_capacity: usize,
    /// Gateway intent bitmask the listener identifies with (non-zero).
    pub gateway_intents: u64,
    /// Credential handle name (for example `cred:discord.bot`); the secret
    /// value arrives only through the sops-rendered unit environment.
    pub bot_token_handle: String,
    /// Literal tokens scrubbed from every outbound message.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub scrub_tokens: BTreeSet<String>,
    /// Lifetime bound of one Discord-originated durable task, in seconds.
    pub ttl_seconds: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OdindHermesVaultConfig {
    /// Absolute path of the served vault root.
    pub vault_root: PathBuf,
    /// Brain Atlas source id this vault feeds (for example
    /// `atlas.personal`); must equal the seat knowledge policy's authorized
    /// source id.
    pub source_id: String,
    /// Loopback SilverBullet UI port. Absence records the optional UI as
    /// absent — reads then fail typed instead of probing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub silverbullet_port: Option<u16>,
    /// Expected server-side vault space root; responses naming a different
    /// space fail typed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub silverbullet_space_root: Option<String>,
    /// Retrieval allowlist namespaces (1..=32 single segments).
    pub general_namespaces: Vec<String>,
    /// The only machine-writable namespace (1..=8 segments).
    pub generated_namespace: String,
    /// Hard private exclusions that never enter retrieval (0..=32 segments,
    /// disjoint from the allowlist).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded_namespaces: Vec<String>,
    /// Retrieval page-count ceiling (1..=100_000).
    pub max_pages: usize,
    /// Single page byte ceiling (1..=4_194_304).
    pub max_page_bytes: u64,
    /// Loopback request timeout in milliseconds (1_000..=60_000).
    pub timeout_ms: u64,
}

/// One declared life account on the `[hermes]` wire: the stable selector
/// every email/calendar operation names explicitly, the opaque credential
/// handle and the absolute sops-rendered secret file it resolves, and the
/// tagged provider facts. No secret value is representable in this file.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OdindHermesAccountConfig {
    /// Stable account selector named explicitly by every email/calendar
    /// operation; every selector must be unique across `accounts`.
    pub account: String,
    /// Credential handle name of the sops-rendered account secret.
    pub secret_handle: String,
    /// Absolute path of the sops-rendered secret file.
    pub secret_path: PathBuf,
    /// Tagged provider facts of this account.
    pub provider: OdindHermesProviderConfig,
}

/// The tagged provider facts of one declared life account, discriminated
/// by `kind` (`jmap`, `google`, `generic`). Every field is an operator
/// deployment fact rendered by Nix; nothing here has a default.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum OdindHermesProviderConfig {
    /// JMAP (RFC 8620) mail and calendar. Supported for existing
    /// consumers; new deployments declare Google or Generic providers.
    Jmap {
        /// JMAP session endpoint (HTTPS).
        session_url: String,
        /// JMAP identity id used for drafts.
        identity_id: String,
        /// From address used for drafts and sends (the account's
        /// configured identity address).
        from_address: String,
        drafts_mailbox_id: String,
        /// Mailbox id used when archiving a message.
        archive_mailbox_id: String,
        /// Mailbox id used when moving a message to trash.
        trash_mailbox_id: String,
        /// The JMAP calendar id; absence serves no calendar for this
        /// account.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        calendar_id: Option<String>,
        /// Per-request deadline in milliseconds.
        request_timeout_ms: u64,
        /// Single response byte ceiling.
        max_response_bytes: u64,
    },
    /// Google Gmail API v1 + Calendar API v3. Only public endpoints and
    /// the calendar id are configuration; the token value lives behind
    /// the account's secret handle/path.
    Google {
        /// Google OAuth2 token endpoint (HTTPS).
        token_url: String,
        /// Gmail API v1 root (HTTPS).
        gmail_api_url: String,
        /// Calendar API v3 root (HTTPS).
        calendar_api_url: String,
        /// The Google calendar id the booking adapter reads and books
        /// against.
        calendar_id: String,
        /// Per-request deadline in milliseconds.
        request_timeout_ms: u64,
        /// Single response byte ceiling.
        max_response_bytes: u64,
    },
    /// Generic IMAP/SMTP mail with optional CalDAV calendar, mirroring
    /// the generic provider's deployment structs.
    Generic {
        /// From address used for drafts and sends.
        from_address: String,
        /// IMAP server host name.
        imap_host: String,
        /// IMAP server port.
        imap_port: u16,
        /// TLS discipline of the IMAP endpoint.
        imap_tls: OdindHermesMailTls,
        /// SMTP submission host name.
        smtp_host: String,
        /// SMTP submission port.
        smtp_port: u16,
        /// TLS discipline of the SMTP endpoint.
        smtp_tls: OdindHermesMailTls,
        /// Host name the transport announces in the SMTP HELO/EHLO.
        helo_name: String,
        /// Mailbox id (or name) of the inbox.
        inbox_mailbox_id: String,
        /// Mailbox id (or name) of the drafts mailbox.
        drafts_mailbox_id: String,
        /// Mailbox id (or name) used when archiving a message.
        archive_mailbox_id: String,
        /// Mailbox id (or name) used when moving a message to trash.
        trash_mailbox_id: String,
        /// CalDAV server root (HTTPS, or plain HTTP on the loopback
        /// interface only); absence serves no calendar for this account.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        caldav_base_url: Option<String>,
        /// The CalDAV calendar collection URL the booking adapter reads
        /// and books against; requires `caldav_base_url`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        caldav_calendar_url: Option<String>,
        /// Per-request deadline in milliseconds.
        request_timeout_ms: u64,
        /// Single response byte ceiling.
        max_response_bytes: u64,
    },
}

/// The TLS discipline of one generic-provider mail endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OdindHermesMailTls {
    /// TLS from the first octet (IMAP 993 style).
    ImplicitTls,
    /// Plaintext greeting, then a mandatory STARTTLS upgrade (SMTP 587
    /// style).
    StartTls,
}
/// Actual Budget local-first finance deployment facts: the absolute path of
/// the budget database the summary adapter reads. Aggregate cents only.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OdindHermesFinanceConfig {
    /// Absolute path of the Actual Budget database file.
    pub budget_db: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OdindPathsConfig {
    pub registry_root: PathBuf,
    pub state_root: PathBuf,
    pub registry_snapshot: PathBuf,
    /// Directory of externally provisioned signed seat-token JSON files,
    /// named `<live-session-id>.json`. The host reloads; it never writes them.
    pub authority_token_root: PathBuf,
    /// Operator-provisioned token verification key file (raw bytes, at least
    /// 32 at use). The value never crosses into the child environment, logs,
    /// or the extension.
    pub authority_verification_key_file: PathBuf,
    /// Optional trusted read-only context root for model-facing
    /// `context.read` sessions (for example a private planning pack).
    /// Absolutely nothing outside this root is ever served, and the root
    /// itself is never exposed through the model surface; absence disables
    /// the capability surface entirely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_context_root: Option<PathBuf>,
    /// Optional read-only Cargo registry cache bind source. The sandbox never
    /// sees the surrounding Cargo home or any credentials file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cargo_registry_cache: Option<PathBuf>,
    /// Optional read-only Cargo git cache bind source. A configured but absent
    /// directory is tolerated by the live `--ro-bind-try` boundary and simply
    /// makes an uncached dependency fail honestly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cargo_git_cache: Option<PathBuf>,
    /// Reserved controller-side record of the Nix daemon socket. It is
    /// deliberately NOT exposed to the model eval sandbox: a trusted-user
    /// daemon connection would bypass the filesystem compartment. Governed
    /// Nix checks must flow through a separately approved operator path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nix_daemon_socket: Option<PathBuf>,
    /// Optional read-only Nix client configuration directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nix_config_root: Option<PathBuf>,
    /// The Git repository runtime registry publications commit to (its
    /// `origin` `main`), declared on the authority with
    /// `authoring_worktree`, the private linked worktree they are made in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authoring_repository: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authoring_worktree: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OdindListenerConfig {
    pub address: SocketAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_cert: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_key: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OdindExecutablesConfig {
    pub omp_bin: PathBuf,
    pub omp_revision: String,
    pub extension: PathBuf,
    pub zellij_bin: PathBuf,
    /// Declared operator Zellij session selector. Absent or empty means NO
    /// declared selector: tab targeting stays unbound until an explicit
    /// registration arrives over the live wire (typed Unavailable
    /// `terminal_target_unbound` at resolution; the daemon never guesses a
    /// session and never reads `ZELLIJ_SESSION_NAME`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub zellij_session: String,
    /// Governed attach-client argv template for persistent live-session
    /// tabs; `{session_id}` is the only allowed placeholder. Absent or
    /// empty leaves tab creation unconfigured (typed Unavailable
    /// `terminal_attach_command_unconfigured` at `open_terminal`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attach_command: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser: Option<OdindBrowserConfig>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OdindBrowserConfig {
    pub chromium: PathBuf,
    pub profile_root: PathBuf,
    pub policy: PathBuf,
    pub protected_values: PathBuf,
    pub scanner: PathBuf,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scanner_args: Vec<String>,
    pub stream: String,
    pub display: OdindDisplayConfig,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OdindDisplayConfig {
    pub source: BrowserDisplaySource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xvfb_binary: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BrowserDisplaySource {
    Xvfb,
    Existing,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OdindCatalogsConfig {
    pub gateway_projection: PathDigestRef,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OdindProjectConfig {
    pub root: PathBuf,
    /// Adopted at load from a runtime-created registry project (never
    /// rendered): a historical generation that predates the project skips
    /// it instead of refusing to recompose.
    #[serde(skip)]
    pub runtime: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OdindLaneBinding {
    pub seat: odin_domain::SeatId,
    pub project: odin_domain::ProjectId,
    pub lane: odin_domain::LaneId,
    /// Adopted at load from the published registry (never rendered): a
    /// historical generation without the lane skips it.
    #[serde(skip)]
    pub runtime: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OdindSeatBinding {
    pub seat: odin_domain::SeatId,
    pub slice: odin_domain::SliceId,
    pub display_name: String,
    pub max_sessions: usize,
    pub launch_options: Vec<odin_domain::huginn::LiveLaunchOption>,
    pub allowed_nodes: Vec<odin_domain::NodeId>,
    /// Adopted at load from a runtime-created registry seat (`seat.create`,
    /// never rendered): a historical generation that predates the seat
    /// skips it instead of refusing to recompose.
    #[serde(skip)]
    pub runtime: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OdindPublishConfig {
    pub render_session: String,
    pub file_lane: String,
    pub render_lane: String,
}

impl OdindConfig {
    /// Loads, parses, and validates one strict configuration file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            message: source.to_string(),
        })?;
        Self::parse_loaded(&text)
    }

    /// Complete either loader's single-read document with the verified registry.
    pub(super) fn parse_loaded(text: &str) -> Result<Self, ConfigError> {
        let mut config = Self::parse(text)?;
        config.adopt_registry_projects();
        config.validate()?;
        Ok(config)
    }

    /// Removes projects with absent roots and their lane bindings instead of blocking startup.
    /// Returns removed projects; the next startup checks their roots again.
    pub fn drop_absent_roots(&mut self) -> Vec<(String, PathBuf)> {
        let absent: Vec<(String, PathBuf)> = self
            .projects
            .iter()
            .filter(|(_, project)| !project.root.is_dir())
            .map(|(id, project)| (id.clone(), project.root.clone()))
            .collect();
        for (id, _) in &absent {
            self.projects.remove(id);
            self.lane_bindings
                .retain(|binding| binding.project.as_str() != id);
        }
        absent
    }

    /// Adds enabled registry projects, worker seats, and lane bindings missing from the config.
    /// Projects must be beneath the authoring repository's parent; unreadable stores add nothing.
    fn adopt_registry_projects(&mut self) {
        let Some(projects_root) = self
            .paths
            .authoring_repository
            .as_ref()
            .and_then(|repository| repository.parent())
            .map(Path::to_path_buf)
        else {
            return;
        };
        let Ok(snapshot) =
            odin_registry::SnapshotStore::new(&self.paths.registry_snapshot).load_verified()
        else {
            return;
        };
        self.adopt_projects_from(&projects_root, &snapshot.objects);
    }

    /// Applies registry additions without reading a snapshot store.
    pub fn adopt_projects_from(
        &mut self,
        projects_root: &Path,
        objects: &[odin_registry::RegistryObject],
    ) {
        for object in objects {
            let odin_registry::ObjectConfig::Project(project) = &object.config else {
                continue;
            };
            let root = PathBuf::from(&project.source_root);
            if !project.enabled
                || self.projects.contains_key(&object.id)
                || !root.is_absolute()
                || root == projects_root
                || !root.starts_with(projects_root)
            {
                continue;
            }
            self.projects.insert(
                object.id.clone(),
                OdindProjectConfig {
                    root,
                    runtime: true,
                },
            );
        }
        // Seats created at runtime run exactly like their template: the
        // configured seat that shares their declared container lends its
        // binding (slice, launch options, nodes, session limit).
        for object in objects {
            let odin_registry::ObjectConfig::Seat(seat) = &object.config else {
                continue;
            };
            let Ok(seat_id) = object.id.parse::<odin_domain::SeatId>() else {
                continue;
            };
            if !seat.enabled
                || seat.conversation.is_some()
                || self.seats.iter().any(|binding| binding.seat == seat_id)
            {
                continue;
            }
            let template = objects.iter().find_map(|container| {
                let odin_registry::ObjectConfig::Container(declared) = &container.config else {
                    return None;
                };
                if !declared.seats_offered.contains(&seat_id) {
                    return None;
                }
                self.seats.iter().find(|binding| {
                    !binding.runtime
                        && declared.seats_offered.contains(&binding.seat)
                        && binding
                            .launch_options
                            .iter()
                            .any(|option| option.container_id.as_str() == container.id)
                })
            });
            if let Some(template) = template.cloned() {
                let mut display = object.id.clone();
                if let Some(first) = display.get_mut(0..1) {
                    first.make_ascii_uppercase();
                }
                self.seats.push(OdindSeatBinding {
                    seat: seat_id.clone(),
                    display_name: display,
                    runtime: true,
                    ..template
                });
            }
        }
        self.adopt_seat_models(objects);
        let seats: std::collections::BTreeSet<_> = self
            .seats
            .iter()
            .map(|binding| binding.seat.clone())
            .collect();
        for object in objects {
            let odin_registry::ObjectConfig::Lane(lane) = &object.config else {
                continue;
            };
            let Ok(lane_id) = object.id.parse::<odin_domain::LaneId>() else {
                continue;
            };
            let bound = self.lane_bindings.iter().any(|binding| {
                binding.seat == lane.default_seat && binding.project == lane.project
            });
            if lane.enabled
                && seats.contains(&lane.default_seat)
                && self.projects.contains_key(lane.project.as_str())
                && !bound
            {
                self.lane_bindings.push(OdindLaneBinding {
                    seat: lane.default_seat.clone(),
                    project: lane.project.clone(),
                    lane: lane_id,
                    runtime: true,
                });
            }
        }
    }

    /// A seat's declared `models` become its launch options in that order: a pair the
    /// composition already launches keeps its options, any other runs in the seat's first container.
    fn adopt_seat_models(&mut self, objects: &[odin_registry::RegistryObject]) {
        for binding in &mut self.seats {
            let declared = objects.iter().find_map(|object| match &object.config {
                odin_registry::ObjectConfig::Seat(seat)
                    if object.id == binding.seat.as_str() && !seat.models.is_empty() =>
                {
                    Some(&seat.models)
                }
                _ => None,
            });
            let (Some(declared), Some(first)) = (declared, binding.launch_options.first()) else {
                continue;
            };
            let template = odin_domain::huginn::LiveLaunchOption {
                harness: None,
                ..first.clone()
            };
            let mut options = Vec::new();
            for choice in declared {
                let composed = binding
                    .launch_options
                    .iter()
                    .filter(|option| {
                        option.provider == choice.provider && option.model == choice.model
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                if composed.is_empty() {
                    options.push(odin_domain::huginn::LiveLaunchOption {
                        provider: choice.provider.clone(),
                        model: choice.model.clone(),
                        ..template.clone()
                    });
                } else {
                    options.extend(composed);
                }
            }
            binding.launch_options = options;
        }
    }

    /// Parses strict TOML text; unknown keys are rejected by the derived
    /// deserializer at every level.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        toml::from_str(text).map_err(|source| ConfigError::Toml(source.to_string()))
    }

    /// Canonical deterministic serialization used by the Nix generator and by
    /// fixture derivation.
    pub fn to_toml(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self).map_err(|source| ConfigError::Toml(source.to_string()))
    }

    /// The validated private listener binding.
    pub fn listener_address(&self) -> HuginnBindConfig {
        HuginnBindConfig::new(self.listener.address)
    }
}

#[cfg(test)]
mod absent_root_tests {
    /// An absent project root leaves the composition with its lanes; a
    /// present one stays.
    #[test]
    fn an_absent_project_root_is_dropped_with_its_lanes() {
        let present = tempfile::tempdir().unwrap();
        let minimal = format!(
            "schema = 'odin.odind-config.v1'\nrevision = 1\nworker_bus = 'unix:/tmp/bus.sock'\n[identity]\nnode = 'mini'\n[paths]\nregistry_root = '/'\nstate_root = '/'\nregistry_snapshot = '/'\nauthority_token_root = '/'\nauthority_verification_key_file = '/'\n[listener]\naddress = '127.0.0.1:18420'\n[executables]\nomp_bin = '/omp'\nomp_revision = '{a}'\nextension = '/ext.ts'\nzellij_bin = '/zellij'\nzellij_session = 'odin'\n[catalogs.gateway_projection]\npath = '/p.json'\ndigest = 'blake3:{c}'\n[publish]\nrender_session = '00000000-0000-4000-8000-0000000000aa'\nfile_lane = 'f'\nrender_lane = 'r'\n[capacity]\n",
            a = "a".repeat(40),
            c = "c".repeat(64)
        );
        let mut config = super::OdindConfig::parse(&format!(
            "{minimal}[projects.odin]\nroot = '{}'\n[projects.skuld]\nroot = '/nonexistent/skuld'\n\
             [[lane_bindings]]\nseat = 'gungnir'\nproject = 'skuld'\nlane = 'gungnir-skuld'\n\
             [[lane_bindings]]\nseat = 'gungnir'\nproject = 'odin'\nlane = 'gungnir-odin'\n",
            present.path().display()
        ))
        .unwrap();
        let dropped = config.drop_absent_roots();
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].0, "skuld");
        assert!(config.projects.contains_key("odin"));
        assert_eq!(config.lane_bindings.len(), 1);
        assert_eq!(config.lane_bindings[0].lane.as_str(), "gungnir-odin");
    }
}
