//! Service construction and policy replacement: the policy binding is
//! verified, the complete declared source set is composed, and every
//! durable store is opened exactly once.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::audit::BrainAudit;
use crate::config::EffectiveBrainPolicy;
use crate::error::{BrainError, BrainResult};
use crate::index;
use crate::retrieval::query::validate_embedding_binding;
use crate::source;

use super::authority::{pin_atlas, validate_source_set, KnowledgeSource};
use super::{BrainService, BrainServiceConfig, BrainSourceConfig};
use odin_domain::knowledge::AtlasId;

impl BrainService {
    /// Opens the service: verifies the policy binding, pins the Atlas heads,
    /// and opens the index and archive stores under `store_root`.
    pub fn open(
        config: BrainServiceConfig,
        policy: EffectiveBrainPolicy,
        ledger: Arc<Mutex<odin_ledger::Ledger>>,
    ) -> BrainResult<Self> {
        policy.verify()?;
        validate_source_set(policy.knowledge.as_ref(), &config.sources)?;
        // A partial embedding binding — an executor without the declared
        // model it executes under, or the reverse — under a vector/hybrid
        // policy would burn real execution leases and then serve an empty
        // candidate set: it is rejected before any component is built.
        validate_embedding_binding(
            policy
                .knowledge
                .as_ref()
                .map(|knowledge| knowledge.retrieval_mode),
            config.embedding_available,
            config.embedding_model.is_some(),
        )?;
        // Validation above proved the wired set equals the authorized set
        // exactly (or that no policy composes no source at all), so this
        // loop composes the complete authorized set: retrieval and item
        // resolution over an absent policy fail
        // typed-unavailable instead of inventing a restriction.
        let mut sources = BTreeMap::new();
        if policy.knowledge.is_some() {
            Self::validate_archive_policy(&policy, &config.sources)?;
            for (id, source) in &config.sources {
                let state_id = match source {
                    BrainSourceConfig::StateRegistry { source } => Some(source.atlas_id()),
                    BrainSourceConfig::StateLive { source } => Some(source.atlas_id()),
                    BrainSourceConfig::StateTasks { source } => Some(source.atlas_id()),
                    BrainSourceConfig::Memory { source } => Some(source.atlas_id()),
                    BrainSourceConfig::StateRepos { source } => Some(source.atlas_id()),
                    BrainSourceConfig::OpsHistory { source } => Some(source.atlas_id()),
                    _ => None,
                };
                if state_id.is_some_and(|source_id| source_id != id) {
                    return Err(BrainError::InvalidPolicy(format!(
                        "composed source identity does not match configured key {id}"
                    )));
                }
                let composed = match source {
                    BrainSourceConfig::Atlas { root } => {
                        KnowledgeSource::Atlas(source::atlas::AtlasSource::new(root, id.clone()))
                    }
                    BrainSourceConfig::Withheld { class } => {
                        if !class.withheld_from_models() {
                            return Err(BrainError::InvalidPolicy(format!(
                                "source {id}: only APL_RESTRICTED or SECRET compose as \
                                 withheld, not {class}"
                            )));
                        }
                        tracing::warn!(
                            source = %id.as_str(),
                            %class,
                            "privacy withheld (declared; never read)"
                        );
                        KnowledgeSource::Withheld {
                            id: id.clone(),
                            class: *class,
                        }
                    }
                    BrainSourceConfig::Archive { declaration } => {
                        // Validate without opening the export; serving uses its approved persisted revision.
                        declaration.validate()?;
                        KnowledgeSource::Archive { id: id.clone() }
                    }
                    BrainSourceConfig::SilverBullet {
                        port,
                        expected_space_root,
                        general_namespaces,
                        generated_namespace,
                        excluded_namespaces,
                        max_pages,
                    } => {
                        // The vault scope is validated at open, before the
                        // source exists: an invalid namespace policy or
                        // page bound is an authority violation, never a
                        // deferred per-serving failure. Composition then
                        // carries a source that cannot read outside the
                        // scope at all — scope admission lives inside the
                        // source, so no serving path can bypass it.
                        if *max_pages == 0 || *max_pages > source::silverbullet::MAX_PAGES_CEILING {
                            return Err(BrainError::InvalidPolicy(format!(
                                "source {id}: vault max_pages must be within 1..={}",
                                source::silverbullet::MAX_PAGES_CEILING
                            )));
                        }
                        let scope = source::silverbullet::VaultScope::new(
                            general_namespaces,
                            generated_namespace,
                            excluded_namespaces,
                        )?;
                        let mut vault =
                            source::silverbullet::SilverBulletSource::new(id.clone(), *port, scope)
                                .with_page_bound(*max_pages);
                        if let Some(space_root) = expected_space_root {
                            vault = vault.with_expected_space_root(space_root.clone());
                        }
                        KnowledgeSource::Vault(vault)
                    }
                    BrainSourceConfig::Memory { source } => {
                        if source.scope().memory_seat() != id.as_str().strip_prefix("memory.")
                            || source.scope().memory_seat().is_none()
                        {
                            return Err(BrainError::InvalidPolicy(format!(
                                "memory source {id} must bind exactly its named seat's reserved subtree"
                            )));
                        }
                        // The memory source arrives fully scoped from the
                        // daemon's validated Hermes vault singleton: its
                        // generated-only scope was validated at composition
                        // and is checked against the configured key above —
                        // there is no authority left to validate here, only
                        // one to preserve. It serves through the same vault
                        // pin and index path as any other vault source.
                        KnowledgeSource::Memory(source.clone())
                    }
                    BrainSourceConfig::StateRegistry { source } => {
                        KnowledgeSource::Registry(source.clone())
                    }
                    BrainSourceConfig::StateLive { source } => {
                        KnowledgeSource::Live(source.clone())
                    }
                    BrainSourceConfig::StateTasks { source } => {
                        KnowledgeSource::Tasks(source.clone())
                    }
                    BrainSourceConfig::StateRepos { source } => KnowledgeSource::Repos(
                        source.restrict_projects(&policy.project_memory.keys().cloned().collect()),
                    ),
                    BrainSourceConfig::OpsHistory { source } => KnowledgeSource::History(
                        source.restrict_projects(&policy.project_memory.keys().cloned().collect()),
                    ),
                };
                sources.insert(id.clone(), composed);
            }
        }
        // Validate immutable Atlas sources at open; check live vault availability per request.
        pin_atlas(&sources)?;
        std::fs::create_dir_all(&config.store_root).map_err(|error| BrainError::Unavailable {
            component: "brain_store_root",
            reason: format!(
                "{} could not be created: {error}",
                config.store_root.display()
            ),
        })?;
        // The archive store exists exactly when an archive source is wired.
        // Every archive declaration is persisted here at open — validated,
        // digest-bound, namespace-unique — so a request carrying any other
        // declaration can never pass the ingest binding. Opening the store
        // reads and writes only this durable state, never the export.
        let archives = if config
            .sources
            .values()
            .any(|source| matches!(source, BrainSourceConfig::Archive { .. }))
        {
            let store = crate::archive::ArchiveStore::open(&config.store_root)?;
            for (id, source) in &config.sources {
                let BrainSourceConfig::Archive { declaration } = source else {
                    continue;
                };
                store.declare_source(
                    id,
                    declaration,
                    &crate::archive::declaration_digest(declaration)?,
                )?;
            }
            Some(store)
        } else {
            None
        };
        Ok(Self {
            index: index::store::IndexStore::open(&config.store_root)?
                .with_postgres(config.postgres.clone()),
            archives,
            audit: BrainAudit::new(ledger),
            sources,
            config,
            policy,
            projection_sink: std::sync::OnceLock::new(),
            projection: std::sync::Mutex::new(super::projection::PublicationState::default()),
            compact: std::sync::Mutex::new(BTreeMap::new()),
        })
    }

    pub fn policy(&self) -> &EffectiveBrainPolicy {
        &self.policy
    }

    pub fn config(&self) -> &BrainServiceConfig {
        &self.config
    }

    /// Archive declaration invariants that must hold under EVERY policy
    /// binding, at open and at every policy swap: memory namespaces are
    /// unique across wired archive sources (the namespace↔source mapping
    /// is enforced, never inferred), and a Private (single-operator
    /// confidential) archive can never be bound as a project's shared
    /// memory namespace — a policy swap must not become a live privacy
    /// bypass. Both classes keep the exact source scope the knowledge
    /// policy authorizes; neither widens authorization.
    fn validate_archive_policy(
        policy: &EffectiveBrainPolicy,
        sources: &BTreeMap<AtlasId, BrainSourceConfig>,
    ) -> BrainResult<()> {
        let mut archive_namespaces: BTreeMap<String, AtlasId> = BTreeMap::new();
        for (id, source) in sources {
            let BrainSourceConfig::Archive { declaration } = source else {
                continue;
            };
            if let Some(other) =
                archive_namespaces.insert(declaration.memory_namespace.clone(), id.clone())
            {
                return Err(BrainError::InvalidPolicy(format!(
                    "archive memory namespace {} is declared for both source {other} and {}",
                    declaration.memory_namespace,
                    id.as_str()
                )));
            }
            if matches!(
                declaration.privacy_class,
                odin_domain::knowledge::archive::ArchivePrivacyClass::Private
            ) && policy
                .project_memory
                .values()
                .any(|namespaces| namespaces.contains(id))
            {
                return Err(BrainError::InvalidPolicy(format!(
                    "source {id}: a Private archive is single-operator confidential                      and can never be bound as a project's shared memory namespace"
                )));
            }
        }
        Ok(())
    }
}
