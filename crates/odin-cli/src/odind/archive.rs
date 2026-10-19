//! Archive ingest requires approval at the kernel gate and verification by
//! the brain service's injected [`ArchiveIngestGate`]; it never runs during
//! daemon startup or retrieval.
//!
//! 1. `odind archive prepare` reads the declared source without ingesting and
//!    creates a durable demand for its id, declaration digest, and content revision.
//! 2. The pinned declaration (`approval_decider = "declaration"`) approves the
//!    demand as `declaration:<device>` through the kernel gate.
//! 3. `odind archive ingest` recomputes both digests fresh, journals the
//!    deterministic command, consumes the approval at-most-once at the
//!    observed revision through [`ApprovalGate`], and only then streams the
//!    bounded ingest into every served seat whose policy authorizes the
//!    source. The brain verifies the consumed approval against the durable
//!    ledger before any mutation, so caller-supplied evidence alone can
//!    never authorize an ingest. An exact rerun replays the journaled
//!    outcome without re-minting, re-consuming, or re-executing; a crashed
//!    run resumes in place on the same consumed approval and command.
//!
//! Terminal approvals are never resurrected: changed content derives a new
//! content revision, a new demand, and requires a new decision.
use odin_brain::retrieval::embedding::{
    embed, EmbedBatch, EmbeddingVector, PrivateGatewayTransport,
};
use odin_brain::service::{
    ArchiveBackfillOutcome, ArchiveEmbeddingBackfillReport, ArchiveEmbeddingBackfillRequest,
    ArchiveIngestAuthority, ArchiveIngestGate, ArchiveIngestPlan, ArchiveIngestReport,
    ArchiveIngestRequest, ArchiveSourceStatus, BrainService, BrainServiceConfig, BrainSourceConfig,
    EmbeddingBatchLane,
};
use odin_cli::runtime_bindings::RuntimeInputs;
use odin_domain::knowledge::{ArchivePrivacyClass, ArchiveSourceDeclaration, AtlasId};
use odin_domain::{
    ApprovalId, ApprovalStatus, CapabilityId, CommandId, Digest, ProviderId, SeatId,
};
use odin_huginn::OdindConfig;
use odin_kernel::{
    ApprovalCommand, ApprovalGate, ApprovalRedirect, ApprovalScope, ConsumeOutcome, NewApproval,
    ProviderLeaseCoordinator,
};
use odin_ledger::command::{CommandOutcome, CommandSpec};
use odin_ledger::Ledger;
use odin_omp::host_tools::delegation::DelegationLinkLedger;
use odin_registry::{
    EmbeddingProtocolToml, ObjectConfig, RegistryKind, Snapshot, SnapshotHandle, SnapshotStore,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

use crate::projection::{brain_sources, served_brain_policies, served_embedding_parts};
use crate::state_knowledge::OdindTaskStateReader;

/// The governed capability every archive demand binds. The registry
/// declaration (`registry/capabilities/archive.ingest`) pins
/// `effect_class = "R3"`, `approval_policy = "operator"`, and
/// `idempotency = "required"`; this id is the runtime binding.
pub(crate) const ARCHIVE_INGEST_CAPABILITY: &str = "archive.ingest";
/// The approval target kind: one demand covers one declared archive source.
const ARCHIVE_TARGET_KIND: &str = "archive.source";
/// Demands live a day: an ingest decision gates a multi-gigabyte stream and
/// the operator may reasonably review it overnight.
const DEMAND_TTL: time::Duration = time::Duration::hours(24);

#[derive(Debug, clap::Args)]
pub(crate) struct ArchiveArgs {
    #[command(subcommand)]
    command: ArchiveCommand,
}

#[derive(Debug, clap::Subcommand)]
enum ArchiveCommand {
    /// Stream one declared archive source read-only, compute both binding
    /// digests, and mint the durable exact-scope R3 demand on first sight.
    /// Writes nothing; prints the exact approve command.
    Prepare(ArchiveSourceArgs),
    /// Recompute the binding, consume the operator approval at-most-once,
    /// and run the bounded ingest into every authorized seat's brain store.
    /// Pending approval prints the demand and authorizes nothing.
    Ingest(ArchiveSourceArgs),
    /// Show the persisted serving state of one archive source per
    /// authorized seat: the published revision, its generation, and the
    /// durable embedding view (lexical-only pending counts are real rows).
    Status(ArchiveSourceArgs),
    /// Run the declared embedding backfill lane over one published source,
    /// moving its generation from lexical-only to model-bound vectors in
    /// bounded batches. Lexical-only completion is typed and resumable.
    Backfill(ArchiveBackfillArgs),
}

#[derive(Debug, clap::Args)]
pub(crate) struct ArchiveSourceArgs {
    #[command(flatten)]
    config_args: ConfigPathArgs,
    /// The declared `brain.sources` key of one archive knowledge source.
    #[arg(long, value_name = "ID")]
    source: String,
}

#[derive(Debug, clap::Args)]
pub(crate) struct ArchiveBackfillArgs {
    #[command(flatten)]
    config_args: ConfigPathArgs,
    /// The declared `brain.sources` key of one archive knowledge source.
    #[arg(long, value_name = "ID")]
    source: String,
    /// Chunk texts per embedding batch (1..=256).
    #[arg(long, value_name = "N", default_value_t = 64)]
    batch_size: usize,
    /// Optional lane-call budget; the run stops lexical-only with durable
    /// staged progress when the budget is exhausted.
    #[arg(long, value_name = "N")]
    max_batches: Option<usize>,
}

#[derive(Debug, clap::Args)]
pub(crate) struct ConfigPathArgs {
    /// Strict Nix-generated `odind.toml`; the only constructor input.
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
}

pub(crate) fn run(args: ArchiveArgs) -> Result<(), String> {
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    match args.command {
        ArchiveCommand::Prepare(arguments) => run_prepare(arguments, &mut output),
        ArchiveCommand::Ingest(arguments) => run_ingest(arguments, &mut output),
        ArchiveCommand::Status(arguments) => run_status(arguments, &mut output),
        ArchiveCommand::Backfill(arguments) => run_backfill(arguments, &mut output),
    }
}

/// Shared arguments digest input for demand creation and brain-side verification.
fn binding_arguments(
    source: &AtlasId,
    declaration_digest: &Digest,
    content_revision: &Digest,
) -> serde_json::Value {
    serde_json::json!({
        "source": source.to_string(),
        "declarationDigest": declaration_digest.to_string(),
        "contentRevision": content_revision.to_string(),
    })
}

fn binding_arguments_digest(arguments: &serde_json::Value) -> Result<Digest, String> {
    let bytes = serde_json::to_vec(arguments).map_err(|error| error.to_string())?;
    Ok(Digest::hash(&bytes))
}

/// The one canonical demand/command derivation for one (source,
/// declaration digest, content revision) binding. Identical inputs derive
/// identical identifiers, so every rerun converges on the same durable
/// rows and no rerun can mint a parallel demand for the same approval.
#[derive(Clone, Debug)]
struct ArchiveBinding {
    approval_id: ApprovalId,
    command_id: CommandId,
    scope: ApprovalScope,
    arguments: serde_json::Value,
}

impl ArchiveBinding {
    fn derive(source: &AtlasId, plan: &ArchiveIngestPlan) -> Result<Self, String> {
        let arguments = binding_arguments(source, &plan.declaration_digest, &plan.content_revision);
        let authorization = binding_arguments_digest(&arguments)?;
        let seed = Digest::hash(
            &serde_json::to_vec(&serde_json::json!({
                "target_kind": ARCHIVE_TARGET_KIND,
                "target_id": source.to_string(),
                "capability_id": ARCHIVE_INGEST_CAPABILITY,
                "arguments_digest": authorization.to_string(),
            }))
            .map_err(|error| error.to_string())?,
        );
        let approval_id = ApprovalId::new(format!("archive-ingest-approval:{seed}"))
            .map_err(|error| format!("derived archive approval id is invalid: {error}"))?;
        let command_id = CommandId::new(format!("archive-ingest-command:{seed}"))
            .map_err(|error| format!("derived archive command id is invalid: {error}"))?;
        let capability_id = CapabilityId::new(ARCHIVE_INGEST_CAPABILITY)
            .map_err(|error| format!("archive.ingest capability id is invalid: {error}"))?;
        Ok(Self {
            approval_id,
            command_id,
            scope: ApprovalScope {
                target_kind: ARCHIVE_TARGET_KIND.to_owned(),
                target_id: source.to_string(),
                capability_id,
                arguments_digest: authorization,
            },
            arguments,
        })
    }

    fn command_spec(
        &self,
        issuer: &str,
        now: OffsetDateTime,
        capability_version: i64,
    ) -> CommandSpec {
        CommandSpec {
            id: self.command_id.clone(),
            idempotency_key: self.command_id.to_string(),
            correlation_id: self.command_id.to_string(),
            causation_id: None,
            issuer: issuer.to_owned(),
            approval_id: Some(self.approval_id.clone()),
            target_kind: self.scope.target_kind.clone(),
            target_id: self.scope.target_id.clone(),
            capability_id: self.scope.capability_id.clone(),
            capability_version,
            arguments_hash: self.scope.arguments_digest,
            arguments: self.arguments.clone(),
            expected_desired_revision: None,
            issued_at: now,
            expires_at: now + DEMAND_TTL,
        }
    }
}

/// The runtime [`ArchiveIngestGate`]: the brain's mutation seam verifies
/// the consumed approval against the durable kernel ledger before any
/// staging write. The gate is composed per seat and binds the exact
/// request key that seat's run may present — no wildcard suffixes, so a
/// consumed approval for one seat's job can never be replayed against
/// another seat or a fresh key on the same brain. Verification is
/// strictly read-only — it never consumes, revives, or mints anything.
struct LedgerArchiveIngestGate {
    ledger: Arc<Mutex<Ledger>>,
    seat: SeatId,
}

impl ArchiveIngestGate for LedgerArchiveIngestGate {
    fn verify(
        &self,
        authority: &ArchiveIngestAuthority,
        source: &AtlasId,
        idempotency_key: &str,
    ) -> odin_brain::error::BrainResult<()> {
        use odin_brain::error::BrainError;
        let ledger = self.ledger.lock().map_err(|_| BrainError::Unavailable {
            component: "archive_ingest_gate",
            reason: "the state ledger is poisoned".to_owned(),
        })?;
        // The demand identity is the approval identity; both must name the
        // row this evidence claims.
        if authority.demand_id != authority.approval_id {
            return Err(gate_mismatch(
                "demand and approval identities disagree in the evidence",
            ));
        }
        let approval_id = ApprovalId::new(authority.approval_id.clone()).map_err(|error| {
            BrainError::InvalidRequest(format!("approval evidence id is invalid: {error}"))
        })?;
        let approval = ledger.approval(&approval_id).map_err(gate_ledger_error)?;
        let Some(approval) = approval else {
            return Err(gate_mismatch("no approval row exists for the evidence"));
        };
        // The evidence must name THIS source's consumption: exact scope,
        // exact command, approved-then-consumed lifecycle, and the
        // journaled command carrying the identical binding digest.
        if approval.scope.target_kind != ARCHIVE_TARGET_KIND {
            return Err(gate_mismatch("approval target kind is not archive.source"));
        }
        if approval.scope.target_id != source.to_string() {
            return Err(gate_mismatch(
                "approval target does not name this archive source",
            ));
        }
        if approval.scope.capability_id.as_str() != ARCHIVE_INGEST_CAPABILITY {
            return Err(gate_mismatch("approval binds a different capability"));
        }
        let arguments = binding_arguments(
            source,
            &authority.declaration_digest,
            &authority.content_revision,
        );
        let arguments_digest = binding_arguments_digest(&arguments)
            .map_err(|error| BrainError::InvalidRequest(error.to_string()))?;
        if approval.scope.arguments_digest != arguments_digest {
            return Err(gate_mismatch(
                "approval binds different declaration or content digests",
            ));
        }
        if approval.status != ApprovalStatus::Consumed {
            return Err(gate_mismatch(
                "approval is not consumed; an unconsumed approval authorizes nothing",
            ));
        }
        let command_id = CommandId::new(authority.command_id.clone()).map_err(|error| {
            BrainError::InvalidRequest(format!("approval evidence command id is invalid: {error}"))
        })?;
        if approval.consumed_by_command_id.as_ref() != Some(&command_id) {
            return Err(gate_mismatch(
                "approval was consumed by a different command than the evidence names",
            ));
        }
        let command = ledger.command(&command_id).map_err(gate_ledger_error)?;
        let Some(command) = command else {
            return Err(gate_mismatch(
                "approval consumption names a journaled command that does not exist",
            ));
        };
        if command.arguments_hash != arguments_digest {
            return Err(gate_mismatch(
                "journaled command carries a different binding digest",
            ));
        }
        if command.approval_id.as_ref() != Some(&approval_id) {
            return Err(gate_mismatch(
                "journaled command names a different approval",
            ));
        }
        // Require this seat's exact key so completed commands cannot replay under a fresh suffix.
        let expected_key = format!("{command_id}:{}", self.seat.as_str());
        if idempotency_key != expected_key {
            return Err(gate_mismatch(
                "request idempotency key does not exactly bind this seat's command",
            ));
        }
        // Only a nonterminal exact job may execute or resume: a completed
        // command replays as a brain-side no-op (publication already
        // holds this revision), while failed, rejected, cancelled, or
        // expired terminal rows stay terminal — a spent approval never
        // re-authorizes work, and an older revision can never republish
        // over a newer one (the publication CAS refuses it downstream).
        match command.terminal_status {
            None | Some(odin_ledger::command::CommandTerminalStatus::Completed) => Ok(()),
            Some(terminal) => Err(gate_mismatch(&format!(
                "journaled command is terminal ({terminal:?}) and stays terminal"
            ))),
        }
    }
}

fn gate_ledger_error(error: odin_ledger::LedgerError) -> odin_brain::error::BrainError {
    odin_brain::error::BrainError::Unavailable {
        component: "archive_ingest_gate",
        reason: format!("could not read the durable ledger: {error}"),
    }
}

fn gate_mismatch(reason: &str) -> odin_brain::error::BrainError {
    odin_brain::error::BrainError::InvalidRequest(format!(
        "archive ingest approval evidence does not verify against the durable ledger: {reason}"
    ))
}

/// Admits the pinned snapshot's `archive.ingest` declaration against the
/// compiled operator tuple [`odin_cli::runtime_bindings::ARCHIVE_INGEST_BINDING`]: the declaration must be
/// present, ENABLED, carry exactly that tuple, and bind the exact governed
/// contract (operator implementation, R3, operator approval, required
/// idempotency, the compiled approval decider). Both declared schemas must
/// load through the same filesystem schema catalog the serving daemon
/// composes, so an absent, disabled, drifted, or unreadable contract refuses
/// before any demand, approval, or journaled command can exist.
///
/// The tuple is compiled once in the runtime-binding library and is admitted
/// at registry publication alongside the host-tool tuples; nothing here is a
/// model tool, and no HostTool owner is invented for it.
fn admitted_ingest_capability(config: &OdindConfig, snapshot: &Snapshot) -> Result<i64, String> {
    use odin_kernel::SchemaCatalog as _;
    use odin_registry::schema::{CapabilityApprovalToml, CapabilityIdempotencyToml};
    let binding = &odin_cli::runtime_bindings::ARCHIVE_INGEST_BINDING;
    if binding.capability != ARCHIVE_INGEST_CAPABILITY {
        return Err(format!(
            "this build compiles its operator tuple for {:?}, not {ARCHIVE_INGEST_CAPABILITY}",
            binding.capability
        ));
    }
    let object = snapshot
        .objects
        .iter()
        .find(|object| {
            object.kind() == RegistryKind::Capability
                && object.id.as_str() == ARCHIVE_INGEST_CAPABILITY
        })
        .ok_or_else(|| {
            format!(
                "the pinned published snapshot declares no {ARCHIVE_INGEST_CAPABILITY} \
                 capability; the governed ingest path refuses to journal a command naming an \
                 undeclared operator capability"
            )
        })?;
    let ObjectConfig::Capability(capability) = &object.config else {
        return Err(format!(
            "registry object {ARCHIVE_INGEST_CAPABILITY} is not a capability declaration"
        ));
    };
    if !capability.enabled {
        return Err(format!(
            "the pinned {ARCHIVE_INGEST_CAPABILITY} declaration is disabled; the governed \
             ingest path refuses a capability the published snapshot does not enable"
        ));
    }
    if capability.implementation.as_deref() != Some(binding.implementation) {
        return Err(format!(
            "the pinned {ARCHIVE_INGEST_CAPABILITY} declaration implements {:?}; the \
             governed ingest path requires the compiled {:?} operator handler",
            capability.implementation, binding.implementation
        ));
    }
    let Some(declared) = odin_registry::relational::declared_admitted_binding(capability) else {
        return Err(format!(
            "the pinned {ARCHIVE_INGEST_CAPABILITY} declaration is incomplete: the compiled \
             operator tuple requires a version, both dedicated schemas, a handler, and an \
             evidence extractor"
        ));
    };
    let expected = binding.admitted_binding();
    if declared != expected {
        return Err(format!(
            "the pinned {ARCHIVE_INGEST_CAPABILITY} declaration is not the compiled \
             operator-handler tuple (declared version {}, schemas {:?}/{:?}, handler {:?}, \
             extractor {:?}); a drifted declaration can never bind the governed command",
            declared.version,
            declared.input_schema,
            declared.output_schema,
            declared.handler,
            declared.evidence_extractor
        ));
    }
    if capability.effect_class != odin_domain::EffectClass::R3
        || capability.approval_policy != CapabilityApprovalToml::Operator
        || capability.idempotency != CapabilityIdempotencyToml::Required
    {
        return Err(format!(
            "the pinned {ARCHIVE_INGEST_CAPABILITY} declaration is not the compiled \
             R3/operator/required-idempotency contract (effect {:?}, approval {:?}, \
             idempotency {:?})",
            capability.effect_class, capability.approval_policy, capability.idempotency
        ));
    }
    // The compiled decider is part of the contract: a drifted approval_decider
    // can never bind the governed command.
    if capability.approval_decider != binding.approval_decider {
        return Err(format!(
            "the pinned {ARCHIVE_INGEST_CAPABILITY} declaration is decided by {:?}; the \
             compiled operator tuple compiles {:?}",
            capability.approval_decider, binding.approval_decider
        ));
    }
    if capability.timeout_seconds.get() != binding.timeout_seconds
        || capability.retry.max_attempts != binding.retry_max_attempts
        || capability.seat_tags.len() != 1
        || !capability.seat_tags.contains(binding.seat_tag)
    {
        return Err(format!(
            "the pinned {ARCHIVE_INGEST_CAPABILITY} declaration is not the compiled operator \
             mandate (declared timeout {}s, retry max_attempts {}, seat_tags {:?}; the \
             operator path enforces {}s, never retries automatically, and is held only by \
             {:?})",
            capability.timeout_seconds,
            capability.retry.max_attempts,
            capability.seat_tags,
            binding.timeout_seconds,
            binding.seat_tag
        ));
    }
    let odin_root = config.paths.registry_root.parent().ok_or_else(|| {
        format!(
            "registry root {} has no Odin repository parent, so the declared \
             {ARCHIVE_INGEST_CAPABILITY} schemas cannot be admitted",
            config.paths.registry_root.display()
        )
    })?;
    let schemas = odin_omp::host_tools::operations::FilesystemSchemaCatalog::new(odin_root);
    for reference in [binding.input_schema, binding.output_schema] {
        schemas.schema(reference).map_err(|error| {
            format!(
                "the declared {ARCHIVE_INGEST_CAPABILITY} schema {reference} is not admitted \
                 from {}: {error}",
                odin_root.display()
            )
        })?;
    }
    Ok(i64::from(binding.version))
}

/// The daemon's exact brain composition for the archive leg: the pinned
/// snapshot, the served per-seat policies, and the declared source set.
/// Built with the same projection functions live startup uses, so a source
/// this composition refuses is exactly a source the daemon would refuse.
struct ArchiveComposition {
    config: OdindConfig,
    snapshot: Arc<Snapshot>,
    sources: BTreeMap<AtlasId, BrainSourceConfig>,
    policies: BTreeMap<SeatId, odin_brain::config::EffectiveBrainPolicy>,
    /// The `archive.ingest` capability version the governed command journals:
    /// the compiled operator-handler tuple version, admitted only against the
    /// pinned published snapshot's identical declaration.
    capability_version: i64,
    /// The admitted run ceiling, in seconds, the ingest execution enforces.
    capability_timeout_seconds: u32,
}

impl ArchiveComposition {
    fn compose(config: OdindConfig) -> Result<Self, String> {
        let registry_handle = Arc::new(
            SnapshotHandle::open(SnapshotStore::new(&config.paths.registry_snapshot)).map_err(
                |error| {
                    format!(
                        "published registry snapshot {} is not a verified publication: {error}",
                        config.paths.registry_snapshot.display()
                    )
                },
            )?,
        );
        let snapshot = registry_handle.current();
        let runtime = RuntimeInputs::parse(&config, &snapshot.objects)?;
        let policies = served_brain_policies(
            &config,
            snapshot.revision,
            &snapshot.objects,
            &runtime.seat_bindings,
        )?;
        // The state-source authorities compose from the daemon's own
        // durable stores: the same pinned snapshot handle, the same
        // controller ledger and delegation-link directory, and a
        // command-scoped read model (these operator passes never retrieve
        // live-plane state). The memory authority composes through the SAME
        // vault derivation the daemon's composition uses — the strict
        // [hermes] section mapped by the shared hermes_settings parser and
        // validated by the same VaultBridge constructor — so a declared
        // memory source composes consistently with the daemon and requires a configured vault.
        let hermes_vault = super::hermes::configured_hermes_vault(&config)?;
        let huginn_root = config.paths.state_root.join("huginn");
        let ledger = Arc::new(Mutex::new(
            Ledger::open(config.paths.state_root.join("ledger.sqlite3"))
                .map_err(|error| format!("could not open the state ledger: {error}"))?,
        ));
        let delegation_links = DelegationLinkLedger::open(huginn_root.join("delegation-links"))
            .map_err(|error| format!("could not open delegation link ledger: {error}"))?;
        let max_objects = snapshot.objects.len().saturating_add(65_536);
        let read_model = odin_huginn::read_model::MaterializedReadModel::with_limits(
            max_objects,
            max_objects.saturating_mul(2),
            OffsetDateTime::now_utc(),
        );
        let task_reader: Arc<dyn odin_brain::source::state::tasks::TaskStateReader> = Arc::new(
            OdindTaskStateReader::new(Arc::clone(&ledger), delegation_links, read_model.clone()),
        );
        let sources = match config.brain.as_ref() {
            Some(brain) if !policies.is_empty() => brain_sources(
                &policies,
                &crate::projection::DeclaredBrainSources {
                    sources: &brain.sources,
                    project_roots: &config.projects,
                },
                &registry_handle,
                &read_model,
                &task_reader,
                hermes_vault.as_ref().map(|bridge| bridge.config()),
                &ledger,
            )?,
            _ => BTreeMap::new(),
        };
        let capability_version = admitted_ingest_capability(&config, &snapshot)?;
        Ok(Self {
            config,
            snapshot,
            sources,
            policies,
            capability_version,
            capability_timeout_seconds: odin_cli::runtime_bindings::ARCHIVE_INGEST_BINDING
                .timeout_seconds,
        })
    }

    fn archive_source(&self, source: &str) -> Result<(AtlasId, ArchiveSourceDeclaration), String> {
        let id = AtlasId::new(source)
            .map_err(|error| format!("--source {source:?} is not a valid AtlasId: {error}"))?;
        let declaration = match self.sources.get(&id) {
            Some(BrainSourceConfig::Archive { declaration }) => declaration.clone(),
            Some(_) => {
                return Err(format!(
                    "brain.sources.{source} is not an archive source; the archive ingest \
                     path serves declared archive exports only"
                ));
            }
            None => {
                return Err(format!(
                    "brain.sources.{source} is not declared, or no served seat's published \
                     policy authorizes it"
                ));
            }
        };
        declaration
            .validate()
            .map_err(|error| format!("brain.sources.{source} declaration is invalid: {error}"))?;
        Ok((id, declaration))
    }

    /// Served seats whose published policies authorize this source.
    fn authorized_seats(
        &self,
        source: &AtlasId,
    ) -> Vec<(SeatId, odin_brain::config::EffectiveBrainPolicy)> {
        self.policies
            .iter()
            .filter(|(_, policy)| {
                policy
                    .knowledge
                    .as_ref()
                    .is_some_and(|knowledge| knowledge.atlas_sources.contains(source))
            })
            .map(|(seat, policy)| (seat.clone(), policy.clone()))
            .collect()
    }

    fn seat_sources(
        &self,
        policy: &odin_brain::config::EffectiveBrainPolicy,
    ) -> BTreeMap<AtlasId, BrainSourceConfig> {
        self.sources
            .iter()
            .filter(|(id, _)| {
                policy
                    .knowledge
                    .as_ref()
                    .is_some_and(|knowledge| knowledge.atlas_sources.contains(*id))
            })
            .map(|(id, config)| (id.clone(), config.clone()))
            .collect()
    }

    fn open_ledger(&self) -> Result<Ledger, String> {
        Ledger::open(self.config.paths.state_root.join("ledger.sqlite3"))
            .map_err(|error| format!("could not open the state ledger: {error}"))
    }

    fn brain_store_root(&self, seat: &SeatId) -> PathBuf {
        self.config
            .paths
            .state_root
            .join("huginn")
            .join("artifacts")
            .join("brain-store")
            .join(seat.as_str())
    }

    /// Opens the brain service for one seat over exactly its authorized
    /// source subset. The governed ingest gate is always injected: ingest
    /// through this composition verifies against the durable ledger, and
    /// there is no composition here that leaves the mutation seam unwired.
    /// The archive passes are lexical: no embedder is bound, so vector and
    /// hybrid retrieval stay typed-unavailable in these command-scoped
    /// services, and the backfill lane supplies its vectors explicitly.
    fn open_brain(
        &self,
        seat: &SeatId,
        policy: &odin_brain::config::EffectiveBrainPolicy,
        ledger: &Arc<Mutex<Ledger>>,
    ) -> Result<BrainService, String> {
        BrainService::open(
            BrainServiceConfig {
                store_root: self.brain_store_root(seat),
                sources: self.seat_sources(policy),
                embedding_available: false,
                embedding_model: None,
                archive_ingest_gate: Some(Arc::new(LedgerArchiveIngestGate {
                    ledger: Arc::clone(ledger),
                    seat: seat.clone(),
                })),
                postgres: None,
            },
            policy.clone(),
            Arc::clone(ledger),
        )
        .map_err(|error| {
            format!(
                "could not open the brain store of seat {}: {error}",
                seat.as_str()
            )
        })
    }

    /// Opens each authorized seat's service sequentially; the caller
    /// consumes and drops each service before opening the next where the
    /// flow allows, so a multi-seat run holds one store set, not all.
    fn open_authorized_brains(
        &self,
        source: &AtlasId,
        ledger: &Arc<Mutex<Ledger>>,
    ) -> Result<Vec<(SeatId, BrainService)>, String> {
        let mut brains = Vec::new();
        for (seat, policy) in self.authorized_seats(source) {
            let service = self.open_brain(&seat, &policy, ledger)?;
            brains.push((seat, service));
        }
        Ok(brains)
    }
}

/// Verify the workstation's paired, unrevoked device against the trust store.
fn operator_issuer(
    config: &OdindConfig,
) -> Result<odin_cli::operator_prompt::OperatorIdentity, String> {
    use odin_huginn::client::FileCredentialStore;
    use odin_huginn::DeviceCredentialStore as _;
    let credential_root = config.paths.state_root.join("huginn");
    let credentials =
        FileCredentialStore::open(&credential_root).map_err(|error| error.to_string())?;
    let credential = credentials
        .load()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| {
            format!(
                "no enrolled device credential exists at {}; an archive ingest demand must \
                 be issued by a paired operator device, never a guessed identity — pair \
                 this workstation with `odin huginn devices pair` against this state root",
                credential_root.join("device.credential").display()
            )
        })?;
    let device = credential.device_id().map_err(|error| {
        format!("the enrolled credential has no valid device identity: {error}")
    })?;
    odin_cli::operator_prompt::operator_identity(&config.paths.state_root, device)
}

#[derive(Debug, Serialize, Deserialize)]
struct SeatReport {
    seat: String,
    #[serde(flatten)]
    material: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct ArchiveReport {
    schema: &'static str,
    status: &'static str,
    source: String,
    memory_namespace: String,
    /// The declaration's own confidentiality class: the typed value (serde
    /// snake_case on the wire), never Debug text, so the operator report and
    /// the `brain://` attribution speak one contract.
    privacy_class: ArchivePrivacyClass,
    declaration_digest: Option<String>,
    content_revision: Option<String>,
    /// Present only on reports that ran the raw binding pass (prepare,
    /// ingest); status and backfill read persisted state and never touch
    /// the export.
    /// Source messages the binding pass classified; the derived record and
    /// event counters are checked against this total.
    #[serde(skip_serializing_if = "Option::is_none")]
    messages_parsed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    records: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    skip_reasons: Option<BTreeMap<String, u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_revision: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    command_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seats: Option<Vec<SeatReport>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resumed: Option<bool>,
}

const ARCHIVE_REPORT_SCHEMA: &str = "odin.archive-ingest/v1";

fn write_report(output: &mut dyn Write, report: &ArchiveReport) -> Result<(), String> {
    let json = serde_json::to_string_pretty(report).map_err(|error| error.to_string())?;
    writeln!(output, "{json}").map_err(|error| format!("could not write the report: {error}"))
}

/// The shared composition phase of every archive subcommand: the config,
/// the pinned snapshot, the resolved source declaration, and the ledger.
/// Status and backfill consume exactly this — they serve the persisted
/// approved publication and must keep working (and stay cheap) even when
/// the raw export is unreachable; nothing here reads the export.
struct ArchiveSetup {
    composition: ArchiveComposition,
    ledger: Arc<Mutex<Ledger>>,
    source: AtlasId,
    declaration: ArchiveSourceDeclaration,
}

fn setup(config_path: &PathBuf, source: &str) -> Result<ArchiveSetup, String> {
    let config = OdindConfig::load(config_path)
        .map_err(|error| format!("could not load the controller configuration: {error}"))?;
    let composition = ArchiveComposition::compose(config)?;
    let ledger = Arc::new(Mutex::new(composition.open_ledger()?));
    let (source_id, declaration) = composition.archive_source(source)?;
    Ok(ArchiveSetup {
        composition,
        ledger,
        source: source_id,
        declaration,
    })
}

/// Read-only preparation computes both digests and verifies the operator device.
struct Prepared {
    setup: ArchiveSetup,
    issuer: String,
    plan: ArchiveIngestPlan,
    binding: ArchiveBinding,
}

fn prepare(config_path: &PathBuf, source: &str) -> Result<Prepared, String> {
    let setup_state = setup(config_path, source)?;
    // Reuse the brain's parser and digest computation rather than duplicating them here.
    let plan = {
        // Preparation is seat-independent, so open only one authorized seat's store.
        let Some((seat, policy)) = setup_state
            .composition
            .authorized_seats(&setup_state.source)
            .into_iter()
            .next()
        else {
            return Err(format!(
                "no served seat's published policy authorizes brain.sources.{}",
                setup_state.source
            ));
        };
        let service = setup_state
            .composition
            .open_brain(&seat, &policy, &setup_state.ledger)?;
        service
            .prepare_archive_ingest(&setup_state.source)
            .map_err(|error| format!("archive prepare pass failed: {error}"))?
    };
    let binding = ArchiveBinding::derive(&setup_state.source, &plan)?;
    let issuer = operator_issuer(&setup_state.composition.config)?.actor();
    Ok(Prepared {
        setup: setup_state,
        issuer,
        plan,
        binding,
    })
}

/// The durable disposition phase prepare and ingest share: mint a genuinely
/// absent demand, let the pinned declaration decide a standing one, and
/// refuse to resurrect terminal rows. Returns the approval when it is
/// Approved (ready to be consumed) or already Consumed by exactly this
/// command.
enum Disposition {
    /// The approval is granted; the caller journals and consumes.
    Approved(odin_ledger::approval::Approval),
    /// This exact command already consumed this exact approval; the stored
    /// outcome (or an in-place resume) is the standing authority.
    Consumed(odin_ledger::approval::Approval),
}

fn disposition(prepared: &Prepared) -> Result<Disposition, String> {
    let now = OffsetDateTime::now_utc();
    let mut ledger = prepared
        .setup
        .ledger
        .lock()
        .map_err(|_| "the state ledger is poisoned".to_owned())?;
    standing_demand(&mut ledger, &prepared.binding, &prepared.issuer, now)
}

/// Create a demand or approve a requested one as `declaration:<device>`;
/// terminal rows cannot be reused.
fn standing_demand(
    ledger: &mut Ledger,
    binding: &ArchiveBinding,
    issuer: &str,
    now: OffsetDateTime,
) -> Result<Disposition, String> {
    let approval = ledger
        .approval(&binding.approval_id)
        .map_err(|error| format!("could not read the approval row: {error}"))?;
    let approval = match approval {
        None => {
            // First sight of this exact binding: mint the durable demand.
            // A binding that was ever decided terminal under this id is
            // still present in the ledger, so this arm can never overwrite
            // or resurrect a decided row.
            ApprovalGate::new(ledger)
                .request(NewApproval {
                    approval_id: binding.approval_id.clone(),
                    issuer: issuer.to_owned(),
                    scope: binding.scope.clone(),
                    requested_at: now,
                    expires_at: now + DEMAND_TTL,
                })
                .map_err(|error| format!("could not mint the archive demand: {error}"))?
        }
        Some(approval) => approval,
    };
    if approval.issuer != issuer {
        return Err(format!(
            "archive demand {} was issued by {}; this workstation's paired device is {issuer} — \
             demands are bound to their issuing device and no other identity may consume \
             or redirect them",
            binding.approval_id, approval.issuer,
        ));
    }
    match approval.status {
        ApprovalStatus::Requested => {
            let decider = format!("declaration:{issuer}");
            let outcome = ApprovalGate::new(ledger)
                .decide(
                    &approval.approval_id,
                    approval.revision,
                    odin_ledger::approval::ApprovalDecision::Approve {
                        evidence_ref: Some(decider.clone()),
                    },
                    &decider,
                    now,
                )
                .map_err(|error| {
                    format!(
                        "the {decider} decision for {} failed: {error}",
                        binding.approval_id
                    )
                })?;
            let odin_kernel::DecisionOutcome::Approved(decided) = outcome else {
                return Err(format!(
                    "the {decider} decision for {} did not approve",
                    binding.approval_id
                ));
            };
            tracing::info!(
                "archive-demand-decided approval_id={} decider={} revision={}",
                binding.approval_id,
                decider,
                decided.revision
            );
            Ok(Disposition::Approved(decided))
        }
        ApprovalStatus::Approved => Ok(Disposition::Approved(approval)),
        ApprovalStatus::Consumed
            if approval.consumed_by_command_id.as_ref() == Some(&binding.command_id)
                && approval.scope == binding.scope =>
        {
            Ok(Disposition::Consumed(approval))
        }
        terminal => Err(format!(
            "archive demand {} is terminal ({terminal:?}) for this content revision; \
             terminal approvals are never resurrected — if the export changed, prepare \
             derived a new demand binding the new content revision",
            binding.approval_id
        )),
    }
}

fn plan_report(
    prepared: &Prepared,
    status: &'static str,
    approval: &odin_ledger::approval::Approval,
) -> ArchiveReport {
    ArchiveReport {
        schema: ARCHIVE_REPORT_SCHEMA,
        status,
        source: prepared.setup.source.to_string(),
        memory_namespace: prepared.setup.declaration.memory_namespace.clone(),
        privacy_class: prepared.setup.declaration.privacy_class,
        declaration_digest: Some(prepared.plan.declaration_digest.to_string()),
        content_revision: Some(prepared.plan.content_revision.to_string()),
        messages_parsed: Some(prepared.plan.messages_parsed),
        records: Some(prepared.plan.records),
        bytes: Some(prepared.plan.bytes),
        skip_reasons: Some(prepared.plan.skip_reasons.clone()),
        approval_id: Some(approval.approval_id.to_string()),
        approval_revision: Some(approval.revision),
        command_id: None,
        seats: None,
        resumed: None,
    }
}

fn finish_report(
    mut report: ArchiveReport,
    prepared: &Prepared,
    approval: &odin_ledger::approval::Approval,
    outcome: &serde_json::Value,
    status: &'static str,
) -> Result<ArchiveReport, String> {
    report.status = status;
    report.approval_id = Some(approval.approval_id.to_string());
    report.approval_revision = Some(approval.revision);
    report.command_id = Some(prepared.binding.command_id.to_string());
    // A stored outcome that no longer decodes is corruption of the
    // journaled record, surfaced — never silently reported as absent.
    report.seats = Some(
        outcome
            .get("seats")
            .map(|value| serde_json::from_value::<Vec<SeatReport>>(value.clone()))
            .transpose()
            .map_err(|error| format!("the journaled outcome is corrupt: {error}"))?
            .unwrap_or_default(),
    );
    report.resumed = Some(
        outcome
            .get("resumed")
            .and_then(|value| value.as_bool())
            .ok_or_else(|| "the journaled outcome resumed flag is corrupt".to_owned())?,
    );
    Ok(report)
}

pub(crate) fn run_prepare(args: ArchiveSourceArgs, output: &mut dyn Write) -> Result<(), String> {
    let prepared = prepare(&args.config_args.config, &args.source)?;
    let report = match disposition(&prepared)? {
        Disposition::Approved(approval) => plan_report(&prepared, "pending", &approval),
        Disposition::Consumed(approval) => {
            let mut report = plan_report(&prepared, "pending", &approval);
            report.command_id = Some(prepared.binding.command_id.to_string());
            match stored_outcome(&prepared)? {
                // The command reached its terminal state: the ingest is
                // durably complete and reruns replay it.
                Some(outcome) => finish_report(report, &prepared, &approval, &outcome, "ingested")?,
                // Consumed but never settled: a previous run crashed
                // mid-flight. Report the resumable in-progress job — not a
                // successful ingestion; `odind archive ingest` resumes and
                // settles it.
                None => {
                    report.status = "in_progress";
                    report
                }
            }
        }
    };
    write_report(output, &report)
}

pub(crate) fn run_ingest(args: ArchiveSourceArgs, output: &mut dyn Write) -> Result<(), String> {
    let prepared = prepare(&args.config_args.config, &args.source)?;
    match disposition(&prepared)? {
        Disposition::Approved(approval) => {
            let outcome = execute_ingest(&prepared, &approval)?;
            let report = finish_report(
                plan_report(&prepared, "pending", &approval),
                &prepared,
                &approval,
                &outcome,
                "ingested",
            )?;
            write_report(output, &report)
        }
        Disposition::Consumed(approval) => {
            let outcome = stored_outcome(&prepared)?;
            let (status, outcome) = match outcome {
                // The command reached its terminal state: replay the stored
                // outcome without re-executing anything.
                Some(outcome) => ("replayed", outcome),
                // Journaled and consumed but never settled: the previous run
                // crashed mid-flight. Resume the exact bound job — same
                // approval, same command, same idempotency keys — and
                // settle it now. The brain's job seam dedupes staging by
                // content address, so no second effect is minted and no
                // terminal row is revived.
                None => ("ingested", execute_ingest(&prepared, &approval)?),
            };
            let report = finish_report(
                plan_report(&prepared, "pending", &approval),
                &prepared,
                &approval,
                &outcome,
                status,
            )?;
            write_report(output, &report)
        }
    }
}

/// The stored terminal outcome of the journaled command, when one exists.
/// `Ok(None)` means the command is journaled and accepted but not yet
/// settled — a crashed run to resume. Missing rows and ledger errors stay
/// errors: a consumed approval without its command row is corruption, not
/// a resume opportunity.
fn stored_outcome(prepared: &Prepared) -> Result<Option<serde_json::Value>, String> {
    let ledger = prepared
        .setup
        .ledger
        .lock()
        .map_err(|_| "the state ledger is poisoned".to_owned())?;
    let command = ledger
        .command(&prepared.binding.command_id)
        .map_err(|error| format!("could not read the journaled command: {error}"))?
        .ok_or_else(|| {
            format!(
                "approval {} names consumed command {} but the command row is missing",
                prepared.binding.approval_id, prepared.binding.command_id
            )
        })?;
    Ok(command.terminal_result)
}

/// Journals the deterministic command and consumes the approval through
/// the real R3 gate, handling every non-terminal crash position without
/// re-driving any ledger transition (`accept_command` requires
/// `accepted_at IS NULL`; it is never re-called):
///
/// - Fresh row: record → accept → consume.
/// - Row accepted, approval still `Approved` (crash between accept and
///   consume): the standing acceptance is reused and the approval is
///   consumed now — the demand is never stranded.
/// - Row accepted, approval already `Consumed` by this command (crash
///   between consume and settlement): the gate's `AlreadyConsumed` names
///   this exact command; the standing consumption is reused.
///
/// An approval is consumed at most once, ever; an identical retry reclaims
/// the journaled row; a different payload under the same id stays refused
/// by the journal's idempotency claim.
enum Admission {
    /// Newly accepted command whose approval has been consumed.
    Consumed(odin_ledger::command::AcceptedCommand),
    /// Resume an accepted command from its durable row without accepting it again.
    Resumed(odin_ledger::command::AcceptedCommand),
}

fn journal_accept_consume(
    prepared: &Prepared,
    approval: &odin_ledger::approval::Approval,
) -> Result<Admission, String> {
    let now = OffsetDateTime::now_utc();
    let mut ledger = prepared
        .setup
        .ledger
        .lock()
        .map_err(|_| "the state ledger is poisoned".to_owned())?;
    let spec = prepared.binding.command_spec(
        &prepared.issuer,
        now,
        prepared.setup.composition.capability_version,
    );
    let recorded = ledger
        .record_command(&spec)
        .map_err(|error| format!("could not journal the archive command: {error}"))?
        .into_recorded();
    if recorded.command().terminal_status.is_some() {
        return Err(
            "the journaled command is already terminal; an exact rerun replays its stored \
             outcome instead of executing"
                .to_owned(),
        );
    }
    // Accept only fresh rows; a resumed command retains its recorded acceptance.
    let accepted = if recorded.command().accepted_at.is_some() {
        None
    } else {
        let revision = recorded.command().revision;
        Some(
            ledger
                .accept_command(&recorded, revision, now)
                .map_err(|error| {
                    format!("could not accept the journaled archive command: {error}")
                })?,
        )
    };
    let consumed = ApprovalGate::new(&mut ledger)
        .authorize_command(
            odin_domain::EffectClass::R3,
            ApprovalCommand {
                command_id: &prepared.binding.command_id,
                approval_id: Some(&prepared.binding.approval_id),
                scope: &prepared.binding.scope,
                expected_revision: Some(approval.revision),
                now,
            },
        )
        .map_err(|error| format!("could not consume the archive approval: {error}"))?;
    match (consumed, accepted) {
        (ConsumeOutcome::Consumed(_), Some(accepted)) => {
            drop(ledger);
            Ok(Admission::Consumed(accepted))
        }
        (ConsumeOutcome::Consumed(_), None) => {
            // Resume after acceptance but before consumption.
            let accepted = ledger
                .accepted_proof(&prepared.binding.command_id)
                .map_err(|error| format!("could not recover the accepted command proof: {error}"))?
                .ok_or_else(|| {
                    "the accepted command proof is absent after consumption".to_owned()
                })?;
            drop(ledger);
            Ok(Admission::Resumed(accepted))
        }
        (
            ConsumeOutcome::Redirect(ApprovalRedirect::AlreadyConsumed {
                approval_id: _,
                command_id,
            }),
            _,
        ) if command_id == prepared.binding.command_id => {
            // Resume after consumption but before settlement of this exact command.
            let accepted = ledger
                .accepted_proof(&prepared.binding.command_id)
                .map_err(|error| format!("could not recover the accepted command proof: {error}"))?
                .ok_or_else(|| {
                    "the accepted command proof is absent for the standing consumption".to_owned()
                })?;
            drop(ledger);
            Ok(Admission::Resumed(accepted))
        }
        (ConsumeOutcome::Redirect(ApprovalRedirect::Denied(_)), _) => Err(
            "the archive approval was denied; a denied demand authorizes nothing and is \
             never resurrected"
                .to_owned(),
        ),
        (ConsumeOutcome::Redirect(redirect), _) => Err(format!(
            "the archive approval did not authorize this exact command binding: {redirect:?}"
        )),
        (ConsumeOutcome::NotRequired, _) => Err(
            "archive ingest is always R3; the gate's lower-risk short circuit must not admit"
                .to_owned(),
        ),
    }
}

fn authority_evidence(
    prepared: &Prepared,
    approval: &odin_ledger::approval::Approval,
) -> ArchiveIngestAuthority {
    ArchiveIngestAuthority {
        demand_id: prepared.binding.approval_id.to_string(),
        approval_id: approval.approval_id.to_string(),
        command_id: prepared.binding.command_id.to_string(),
        declaration_digest: prepared.plan.declaration_digest,
        content_revision: prepared.plan.content_revision,
    }
}

fn seat_ingest_report(seat: &SeatId, report: &ArchiveIngestReport) -> SeatReport {
    SeatReport {
        seat: seat.as_str().to_owned(),
        material: serde_json::json!({
            "recordsSeen": report.records_seen,
            "recordsStaged": report.records_staged,
            "recordsDuplicate": report.records_duplicate,
            "chunks": report.chunks,
            "resumed": report.resumed,
            "generation": report.generation.generation_id.to_string(),
        }),
    }
}

/// Runs the bounded ingest for every authorized seat and settles the
/// journaled command — on the fresh consumption and on the crash-resume
/// alike, so a recovered run reaches the same terminal replayable state as
/// an uninterrupted one. Only ever called on a non-terminal exact approval
/// binding; the brain gate re-verifies that consumption before any seat
/// mutates.
fn execute_ingest(
    prepared: &Prepared,
    approval: &odin_ledger::approval::Approval,
) -> Result<serde_json::Value, String> {
    let admission = journal_accept_consume(prepared, approval)?;
    let outcome = run_seated_ingest(prepared, approval)?;
    let accepted = match admission {
        Admission::Consumed(accepted) | Admission::Resumed(accepted) => accepted,
    };
    let completion_revision = accepted.command().revision;
    let mut ledger = prepared
        .setup
        .ledger
        .lock()
        .map_err(|_| "the state ledger is poisoned".to_owned())?;
    ledger
        .complete_command(
            &accepted,
            &CommandOutcome {
                status: odin_ledger::command::CommandTerminalStatus::Completed,
                result: outcome.clone(),
            },
            completion_revision,
            OffsetDateTime::now_utc(),
        )
        .map_err(|error| format!("could not settle the archive command: {error}"))?;
    Ok(outcome)
}

fn run_seated_ingest(
    prepared: &Prepared,
    approval: &odin_ledger::approval::Approval,
) -> Result<serde_json::Value, String> {
    let evidence = authority_evidence(prepared, approval);
    // The declared ceiling is enforced by the brain between staging batches:
    // an overrun stops the run typed with every staged batch durable, so the
    // command stays resumable instead of pretending to have finished.
    let deadline = OffsetDateTime::now_utc()
        + time::Duration::seconds(i64::from(
            prepared.setup.composition.capability_timeout_seconds,
        ));
    let mut seats = Vec::new();
    let mut resumed = false;
    for (seat, policy) in prepared
        .setup
        .composition
        .authorized_seats(&prepared.setup.source)
    {
        let brain =
            prepared
                .setup
                .composition
                .open_brain(&seat, &policy, &prepared.setup.ledger)?;
        let report = brain
            .ingest_archive(&ArchiveIngestRequest {
                source: prepared.setup.source.clone(),
                declaration: prepared.setup.declaration.clone(),
                approval: evidence.clone(),
                idempotency_key: format!("{}:{}", prepared.binding.command_id, seat.as_str()),
                deadline: Some(deadline),
            })
            .map_err(|error| format!("bounded ingest failed: {error}"))?;
        resumed = resumed || report.resumed;
        seats.push(seat_ingest_report(&seat, &report));
    }
    Ok(serde_json::json!({ "seats": seats, "resumed": resumed }))
}

/// The report shape for status and backfill: no binding pass ran, so the
/// digest and count fields stay absent — these commands serve the
/// persisted approved state and never touch the raw export.
fn setup_report(state: &ArchiveSetup, status: &'static str) -> ArchiveReport {
    ArchiveReport {
        schema: ARCHIVE_REPORT_SCHEMA,
        status,
        source: state.source.to_string(),
        memory_namespace: state.declaration.memory_namespace.clone(),
        privacy_class: state.declaration.privacy_class,
        declaration_digest: None,
        content_revision: None,
        messages_parsed: None,
        records: None,
        bytes: None,
        skip_reasons: None,
        approval_id: None,
        approval_revision: None,
        command_id: None,
        seats: None,
        resumed: None,
    }
}

pub(crate) fn run_status(args: ArchiveSourceArgs, output: &mut dyn Write) -> Result<(), String> {
    // Read persisted publication state so status works while the export is offline.
    let state = setup(&args.config_args.config, &args.source)?;
    let mut seats = Vec::new();
    for (seat, service) in state
        .composition
        .open_authorized_brains(&state.source, &state.ledger)?
    {
        let status: ArchiveSourceStatus = service
            .archive_status(&state.source)
            .map_err(|error| format!("could not read the archive status: {error}"))?;
        let material = match status.published {
            Some(publication) => {
                let embedding = match publication.embedding {
                    odin_brain::service::ArchiveEmbeddingView::LexicalOnly {
                        pending_chunks,
                        staged_vectors,
                    } => serde_json::json!({
                        "kind": "lexical_only",
                        "pendingChunks": pending_chunks,
                        "stagedVectors": staged_vectors,
                    }),
                    odin_brain::service::ArchiveEmbeddingView::Embedded { model } => {
                        serde_json::json!({ "kind": "embedded", "model": model.as_str() })
                    }
                };
                serde_json::json!({
                    "published": {
                        "revision": publication.revision.to_string(),
                        "generationId": publication.generation_id.to_string(),
                        "records": publication.records,
                        "chunks": publication.chunks,
                    },
                    "embedding": embedding,
                })
            }
            None => serde_json::json!({ "published": null }),
        };
        seats.push(SeatReport {
            seat: seat.as_str().to_owned(),
            material,
        });
    }
    let mut report = setup_report(&state, "status");
    report.seats = Some(seats);
    write_report(output, &report)
}

pub(crate) fn run_backfill(
    args: ArchiveBackfillArgs,
    output: &mut dyn Write,
) -> Result<(), String> {
    // Backfill moves the persisted publication to model-bound vectors: no
    // prepare stream, no demand disposition.
    let state = setup(&args.config_args.config, &args.source)?;
    let mut seats = Vec::new();
    for (seat, policy) in state.composition.authorized_seats(&state.source) {
        // The backfill brain opens lexical: the lane supplies vectors
        // explicitly, and retrieval-time embedding of this one-shot
        // service is never used. A seat policy that hard-requires vectors
        // at open refuses typed, exactly as the serving daemon would.
        let brain = state
            .composition
            .open_brain(&seat, &policy, &state.ledger)?;
        // The lane owns the raw parts of this declared route: the lease
        // coordinator, its ledger, and its transport are single-owner by
        // construction (the daemon's executor binds its own composition),
        // so every seat's lane composes its own and its request ids are
        // its own.
        let lease_lane = state
            .composition
            .config
            .lane_bindings
            .iter()
            .filter(|binding| binding.seat == seat)
            .map(|binding| binding.lane.clone())
            .min()
            .ok_or_else(|| {
                format!("seat {seat} declares no session lane to lease the backfill under")
            })?;
        let parts = served_embedding_parts(
            &state.composition.config,
            &state.composition.snapshot,
            &lease_lane,
            &mut |name| std::env::var(name).ok(),
        )?
        .ok_or_else(|| {
            "no embedding route is declared for this controller; vector backfill stays \
                     typed-unavailable and the source keeps serving lexical-only"
                .to_owned()
        })?;
        let embedding_model = parts.model.clone();
        let mut lane = GatewayBatchLane {
            provider: parts.provider,
            coordinator: parts.coordinator,
            ledger: parts.ledger,
            transport: parts.transport,
            protocol: parts.protocol,
            request_counter: 0,
        };
        let report = brain
            .backfill_archive_embeddings(
                &ArchiveEmbeddingBackfillRequest {
                    source: state.source.clone(),
                    embedding_model,
                    batch_size: args.batch_size,
                    max_batches: args.max_batches,
                },
                &mut lane,
            )
            .map_err(|error| format!("embedding backfill failed: {error}"))?;
        seats.push(seat_backfill_report(&seat, &report));
    }
    let mut report = setup_report(&state, "backfilled");
    report.seats = Some(seats);
    write_report(output, &report)
}

fn seat_backfill_report(seat: &SeatId, report: &ArchiveEmbeddingBackfillReport) -> SeatReport {
    let outcome = match &report.outcome {
        ArchiveBackfillOutcome::Embedded => serde_json::json!({ "kind": "embedded" }),
        ArchiveBackfillOutcome::LexicalOnly { reason, pending } => serde_json::json!({
            "kind": "lexical_only",
            "reason": reason,
            "pending": pending,
        }),
    };
    SeatReport {
        seat: seat.as_str().to_owned(),
        material: serde_json::json!({
            "vectorsStaged": report.vectors_staged,
            "generation": report.generation.generation_id.to_string(),
            "embeddingModel": report.embedding_model.as_str(),
            "outcome": outcome,
        }),
    }
}

/// The declared gateway lane the archive backfill embeds through: one
/// kernel-lease-governed batch per call over the composed provider
/// identity. The brain names the lane contract; this wiring supplies the
/// existing executor port — the brain never contacts a provider directly.
struct GatewayBatchLane {
    provider: ProviderId,
    coordinator: ProviderLeaseCoordinator,
    ledger: Ledger,
    transport: PrivateGatewayTransport,
    /// The resolved route's declared embedding protocol; the brain's
    /// `embed` seam applies it once for every backfill batch, exactly as it
    /// does for serving queries.
    protocol: Option<EmbeddingProtocolToml>,
    request_counter: u64,
}

impl EmbeddingBatchLane for GatewayBatchLane {
    fn embed_batch(
        &mut self,
        texts: &[String],
    ) -> odin_brain::error::BrainResult<Vec<EmbeddingVector>> {
        self.request_counter += 1;
        let request_id = format!(
            "archive-backfill-{}-{}",
            self.provider.as_str(),
            self.request_counter
        );
        let output = embed(
            &self.provider,
            &mut self.coordinator,
            &mut self.ledger,
            EmbedBatch {
                request_id: &request_id,
                inputs: texts,
                protocol: self.protocol.as_ref(),
                now: OffsetDateTime::now_utc(),
            },
            &mut self.transport,
        )?;
        Ok(output.vectors)
    }
}

#[cfg(test)]
#[path = "tests/archive.rs"]
mod tests;
