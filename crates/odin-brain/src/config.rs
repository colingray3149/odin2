//! Effective brain policy composition.
//!
//! [`EffectiveBrainPolicy`] is the single composition point where real
//! registry project, seat, and slice TOML (`[knowledge]`, `[context]`,
//! `[tools]` blocks), the seat `brain_scope`, the seat `project_scope`, the
//! projects' declared `memory_namespaces`, and the model descriptor resolve
//! into the existing domain effective policies under one canonical,
//! revision-bound digest. Composition only ever narrows: every ceiling,
//! source set, and tool set in the output is bounded by both the slice
//! delegation and the seat restriction, and the kernel remains the sole
//! capability authority.
//!
//! Project memory is declared, never inferred: each project in the seat's
//! `project_scope` contributes exactly its declared `memory_namespaces`
//! intersected with the seat's authorized knowledge sources, so a session
//! bound to project A can never read or write project-scoped memory that A
//! did not declare, and a namespace co-declared by several projects is the
//! one explicit shared-memory form. There is no implicit default project
//! and no first-source selection anywhere in this composition.
//!
//! Absence semantics (deliberate, monotonic):
//! - An absent slice block means the slice delegates no authority of that
//!   kind; the composed policy carries `None` for it.
//! - A seat block without the corresponding slice block is an authority
//!   violation and is rejected: seats restrict, they never grant.
//! - An absent seat block means no restriction beyond the slice delegation
//!   (the identity restriction), intersected with `brain_scope` for
//!   knowledge sources.
//! - A project whose declared namespaces intersect nothing the seat is
//!   authorized to read composes an empty per-project memory set: declared
//!   but unusable here, never widened.

use std::collections::{BTreeMap, BTreeSet};

use odin_domain::knowledge::context::{
    resolve_context_policy, resolve_tool_policy, SeatContextPolicy, SeatToolPolicy,
    SliceContextPolicy, SliceToolPolicy,
};
use odin_domain::knowledge::retrieval::{ModelDescriptor, SliceKnowledgePolicy};
use odin_domain::knowledge::{AtlasId, RelevanceScore, SeatKnowledgePolicy};
use odin_domain::{Digest, ProjectId, SeatId};
use odin_registry::schema::{ContextProfileToml, ProjectToml, SeatToml, SliceToml};
use serde::Serialize;

use crate::error::{BrainError, BrainResult};

/// Knowledge, context, and tool authority for one seat on one slice, bound
/// to the registry revision it was resolved from by one canonical digest.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveBrainPolicy {
    /// Registry snapshot revision this policy was resolved from.
    pub registry_revision: u64,
    /// Knowledge authority, or `None` when the slice delegates none.
    pub knowledge: Option<EffectiveKnowledgePolicy>,
    /// Context budgets, or `None` when the slice declares none.
    pub context: Option<EffectiveContextPolicy>,
    /// Brain-side tool narrowing, or `None` when the slice declares none
    /// (the exact kernel capability listing then stands alone).
    pub tools: Option<EffectiveToolPolicy>,
    /// Project-scoped memory, per project of the seat's `project_scope`:
    /// exactly the atlas namespaces each project declares as its memory,
    /// intersected with the seat's authorized knowledge sources. A session
    /// bound to a project may read and write project-scoped memory only in
    /// its own entry; shared namespaces appear in every co-declaring
    /// project's entry. Never widened: an empty set is a declared project
    /// with no memory this seat may reach, and a project absent from this
    /// map was never in the seat's scope at all.
    pub project_memory: BTreeMap<ProjectId, BTreeSet<AtlasId>>,
    /// The seat's authorized atlas sources that NO project in the pinned
    /// snapshot declares as its project memory: the general knowledge set.
    /// The classification is resolved against EVERY declared project in the
    /// snapshot, not only this seat's `project_scope`: a namespace some
    /// project declares as its memory is project memory everywhere, so it
    /// can never degrade to seat-general for a seat whose scope does not
    /// reach the declaring project. General sources serve every session of
    /// the seat; project memory never enters this set.
    pub seat_global_sources: BTreeSet<AtlasId>,
    /// Declared owner profile namespace, when this seat serves one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_namespace: Option<AtlasId>,
    /// This seat may write the profile namespace: it declares a conversation
    /// and the namespace is in its authorized sources.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub writes_profile: bool,
    /// The seat's declared brain review lane (`[context] review_lane`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_lane: Option<String>,
    /// The exact served model identity the policy was resolved against:
    /// the descriptor every context compilation for this seat carries.
    /// Composition identity, not policy content — the resolved context
    /// budgets already carry the model window, so this descriptor is
    /// deliberately not part of the binding digest material.
    pub model: ModelDescriptor,
    /// Canonical digest binding the revision and the policy surfaces.
    pub policy_digest: Digest,
}

/// The exact material hashed into [`EffectiveBrainPolicy::policy_digest`].
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BindingMaterial<'a> {
    registry_revision: u64,
    knowledge: &'a Option<EffectiveKnowledgePolicy>,
    context: &'a Option<EffectiveContextPolicy>,
    tools: &'a Option<EffectiveToolPolicy>,
    project_memory: &'a BTreeMap<ProjectId, BTreeSet<AtlasId>>,
    seat_global_sources: &'a BTreeSet<AtlasId>,
    profile_namespace: &'a Option<AtlasId>,
    writes_profile: bool,
}

impl EffectiveBrainPolicy {
    /// Resolves the effective brain policy from real registry objects and
    /// the model descriptor serving the seat. `projects` is the project
    /// index of the same pinned snapshot the seat and slice come from;
    /// every project in the seat's `project_scope` must resolve there,
    /// because project memory is declared, never guessed. The namespace
    /// classification reads every declared project in the index, so a
    /// namespace is project memory everywhere in the snapshot or it is
    /// not project memory at all.
    ///
    /// `profiles` indexes the snapshot's `context-profile` objects; a seat's
    /// `[context] profile` must name an enabled one.
    ///
    /// Fails when either registry object is disabled, when a seat block
    /// appears without its slice block, when a scoped project is absent
    /// from the snapshot, or when the domain resolution rejects a
    /// non-monotonic restriction.
    pub fn resolve(
        registry_revision: u64,
        slice: &SliceToml,
        seat: &SeatToml,
        projects: &BTreeMap<&str, &ProjectToml>,
        profiles: &BTreeMap<&str, &ContextProfileToml>,
        model: &ModelDescriptor,
    ) -> BrainResult<Self> {
        if !slice.enabled {
            return Err(BrainError::InvalidPolicy(
                "slice is disabled in the registry".into(),
            ));
        }
        if !seat.enabled {
            return Err(BrainError::InvalidPolicy(
                "seat is disabled in the registry".into(),
            ));
        }
        let knowledge = resolve_knowledge(&slice.knowledge, &seat.knowledge, &seat.brain_scope)?;
        let context = resolve_context(&slice.context, &seat.context, profiles, model)?;
        let tools = resolve_tools(&slice.tools, &seat.tools)?;
        let project_memory = resolve_project_memory(seat, projects, knowledge.as_ref())?;
        let seat_global_sources = resolve_seat_global_sources(knowledge.as_ref(), projects);
        let profile_namespace = seat.profile_namespace.clone();
        let writes_profile = seat.conversation.is_some()
            && profile_namespace.as_ref().is_some_and(|namespace| {
                knowledge
                    .as_ref()
                    .is_some_and(|policy| policy.atlas_sources.contains(namespace))
            });
        let policy_digest = binding_digest(&BindingMaterial {
            registry_revision,
            knowledge: &knowledge,
            context: &context,
            tools: &tools,
            project_memory: &project_memory,
            seat_global_sources: &seat_global_sources,
            profile_namespace: &profile_namespace,
            writes_profile,
        })?;
        Ok(Self {
            registry_revision,
            knowledge,
            context,
            tools,
            project_memory,
            seat_global_sources,
            profile_namespace,
            writes_profile,
            review_lane: seat
                .context
                .as_ref()
                .and_then(|context| context.review_lane.clone()),
            model: model.clone(),
            policy_digest,
        })
    }

    /// The declared project memory namespaces of one project, or `None`
    /// when the project is not in this seat's scope at all. The empty set
    /// is a scoped project whose declared namespaces this seat cannot
    /// reach: present, explicit, and unusable — never a default.
    pub fn project_memory(&self, project: &ProjectId) -> Option<&BTreeSet<AtlasId>> {
        self.project_memory.get(project)
    }

    /// Recomputes the binding digest and rejects the policy when its
    /// content no longer matches the revision it claims to be bound to.
    pub fn verify(&self) -> BrainResult<()> {
        let expected = binding_digest(&self.material())?;
        if self.policy_digest != expected {
            return Err(BrainError::InvalidPolicy(
                "binding digest does not match the composed policy and registry revision".into(),
            ));
        }
        Ok(())
    }

    /// The exact serving scope of one session: the seat's general knowledge
    /// sources plus, for a project-bound session, exactly that project's
    /// declared memory namespaces. General is a SEAT DECLARATION semantics,
    /// not an inference: a source that no project in the pinned snapshot
    /// declares is seat-general and serves EVERY session of the seat, while
    /// a namespace some project declares serves only sessions bound to a
    /// project that declares it (projects co-declaring one namespace share
    /// it explicitly). Project memory never serves without a declared
    /// project.
    pub fn project_serving_scope(&self, project: Option<&ProjectId>) -> BTreeSet<AtlasId> {
        let mut scope = self.seat_global_sources.clone();
        if let Some(memory) = project.and_then(|project| self.project_memory.get(project)) {
            scope.extend(memory.iter().cloned());
        }
        scope
    }

    fn material(&self) -> BindingMaterial<'_> {
        BindingMaterial {
            registry_revision: self.registry_revision,
            knowledge: &self.knowledge,
            context: &self.context,
            tools: &self.tools,
            project_memory: &self.project_memory,
            seat_global_sources: &self.seat_global_sources,
            profile_namespace: &self.profile_namespace,
            writes_profile: self.writes_profile,
        }
    }

    /// Directory-name write grant: own namespace when authorized, and the
    /// profile directory only when this seat may write it.
    pub fn memory_write_grant(&self, seat: &SeatId) -> MemoryWriteGrant {
        let authorized = self.knowledge.as_ref().map(|policy| &policy.atlas_sources);
        let granted = |id: &str| {
            authorized.is_some_and(|sources| sources.iter().any(|source| source.as_str() == id))
        };
        let own_id = format!("memory.{seat}");
        let profile = if self.writes_profile {
            self.profile_namespace.as_ref().and_then(|id| {
                let name = id.as_str().strip_prefix("memory.")?;
                granted(id.as_str()).then(|| name.to_owned())
            })
        } else {
            None
        };
        MemoryWriteGrant {
            own: granted(&own_id),
            profile,
        }
    }
}

/// Namespaces one seat may change: its own directory, and the profile
/// directory when the declaration grants that write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryWriteGrant {
    pub own: bool,
    pub profile: Option<String>,
}

fn binding_digest(material: &BindingMaterial<'_>) -> BrainResult<Digest> {
    let bytes = serde_json::to_vec(material)?;
    Ok(Digest::hash(&bytes))
}

fn resolve_knowledge(
    slice: &Option<odin_registry::schema::SliceKnowledgeToml>,
    seat: &Option<odin_registry::schema::SeatKnowledgeToml>,
    brain_scope: &BTreeSet<AtlasId>,
) -> BrainResult<Option<EffectiveKnowledgePolicy>> {
    let Some(slice) = slice else {
        if seat.is_some() {
            return Err(BrainError::InvalidPolicy(
                "seat knowledge policy without a slice knowledge policy exceeds slice authority"
                    .into(),
            ));
        }
        return Ok(None);
    };
    // Absent seat knowledge is the identity restriction; brain_scope then
    // bounds the effective source set. Present seat knowledge is narrowed
    // by brain_scope before domain validation so the subset check runs
    // against the sources the brain may actually reach.
    let seat_policy = match seat {
        Some(seat) => SeatKnowledgePolicy {
            atlas_sources: seat
                .atlas_sources
                .intersection(brain_scope)
                .cloned()
                .collect(),
            required_tags: seat.required_tags.clone(),
            denied_tags: seat.denied_tags.clone(),
            top_k: seat.top_k,
        },
        None => SeatKnowledgePolicy {
            atlas_sources: slice
                .atlas_sources
                .intersection(brain_scope)
                .cloned()
                .collect(),
            required_tags: BTreeSet::new(),
            denied_tags: BTreeSet::new(),
            top_k: slice.top_k,
        },
    };
    let slice_policy = SliceKnowledgePolicy {
        required: slice.required,
        atlas_sources: slice.atlas_sources.clone(),
        retrieval_mode: slice.retrieval_mode,
        candidate_limit: slice.candidate_limit,
        top_k: slice.top_k,
        min_score: RelevanceScore::new(slice.min_score_micros)?,
        chunk_tokens: slice.chunk_tokens,
        chunk_overlap_tokens: slice.chunk_overlap_tokens,
        embedding_backend: slice.embedding_backend,
    };
    Ok(Some(EffectiveKnowledgePolicy::resolve(
        &slice_policy,
        &seat_policy,
    )?))
}

/// Composes the seat's project-scoped memory: for every project in the
/// seat's `project_scope`, exactly the namespaces that project declares,
/// intersected with the seat's authorized knowledge sources. The scope
/// reference must resolve against the same pinned snapshot — a missing
/// project is a broken declaration, never an inferred empty scope. When
/// the slice delegates no knowledge authority at all, every project composes
/// an empty set: declared memory exists, and this seat may reach none of it.
fn resolve_project_memory(
    seat: &SeatToml,
    projects: &BTreeMap<&str, &ProjectToml>,
    knowledge: Option<&EffectiveKnowledgePolicy>,
) -> BrainResult<BTreeMap<ProjectId, BTreeSet<AtlasId>>> {
    let empty: BTreeSet<AtlasId> = BTreeSet::new();
    let authorized = knowledge
        .map(|policy| &policy.atlas_sources)
        .unwrap_or(&empty);
    let mut composed = BTreeMap::new();
    for project in &seat.project_scope {
        let declaration = projects.get(project.as_str()).ok_or_else(|| {
            BrainError::InvalidPolicy(format!(
                "project {} is in the seat's project_scope but absent from the registry snapshot",
                project.as_str()
            ))
        })?;
        if !declaration.enabled {
            return Err(BrainError::InvalidPolicy(format!(
                "project {} is in the seat's project_scope but disabled in the registry",
                project.as_str()
            )));
        }
        composed.insert(
            project.clone(),
            declaration
                .memory_namespaces
                .intersection(authorized)
                .cloned()
                .collect(),
        );
    }
    Ok(composed)
}

/// Classifies the seat's authorized atlas sources against EVERY declared
/// project in the pinned snapshot. A namespace any project declares as its
/// memory is project memory everywhere in that snapshot — including for a
/// seat whose `project_scope` does not reach the declaring project — so it
/// can never degrade to seat-general there. Only sources no project
/// declares remain seat-general; an authorized-but-reserved source keeps
/// its place in the authorized ceiling and simply never serves as general
/// knowledge.
fn resolve_seat_global_sources(
    knowledge: Option<&EffectiveKnowledgePolicy>,
    projects: &BTreeMap<&str, &ProjectToml>,
) -> BTreeSet<AtlasId> {
    let empty = BTreeSet::new();
    let authorized = knowledge
        .map(|policy| &policy.atlas_sources)
        .unwrap_or(&empty);
    let reserved: BTreeSet<&AtlasId> = projects
        .values()
        .flat_map(|project| project.memory_namespaces.iter())
        .collect();
    authorized
        .iter()
        .filter(|source| !reserved.contains(source))
        .cloned()
        .collect()
}

fn resolve_context(
    slice: &Option<odin_registry::schema::SliceContextToml>,
    seat: &Option<odin_registry::schema::SeatContextToml>,
    profiles: &BTreeMap<&str, &ContextProfileToml>,
    model: &ModelDescriptor,
) -> BrainResult<Option<EffectiveContextPolicy>> {
    let Some(slice) = slice else {
        if seat.is_some() {
            return Err(BrainError::InvalidPolicy(
                "seat context policy without a slice context policy exceeds slice authority".into(),
            ));
        }
        return Ok(None);
    };
    let slice_policy = SliceContextPolicy {
        max_bundle_tokens: slice.max_bundle_tokens,
        reserve_output_tokens: slice.reserve_output_tokens,
        control_tokens: slice.control_tokens,
        history_tokens: slice.history_tokens,
        core_tokens: slice.core_tokens,
        prefetch_tokens: slice.prefetch_tokens,
        tool_result_tokens: slice.tool_result_tokens,
        tool_schema_tokens: slice.tool_schema_tokens,
        max_item_tokens: slice.max_item_tokens,
    };
    // Absent seat context is the identity restriction: the seat imposes no
    // ceiling beyond the slice delegation and the model window.
    let seat_policy = match seat {
        None => SeatContextPolicy {
            max_bundle_tokens: slice.max_bundle_tokens,
            core_tokens: slice.core_tokens,
            prefetch_tokens: slice.prefetch_tokens,
            per_turn_tokens: 0,
        },
        Some(seat) => {
            let profile = profiles
                .get(seat.profile.as_str())
                .filter(|profile| profile.enabled)
                .ok_or_else(|| {
                    BrainError::InvalidPolicy(format!(
                        "seat context profile {:?} is not an enabled context-profile",
                        seat.profile
                    ))
                })?;
            if u64::from(profile.core_tokens.get()) + u64::from(profile.inject_tokens.get())
                > u64::from(seat.max_bundle_tokens.get())
            {
                return Err(BrainError::InvalidPolicy(format!(
                    "context profile {:?} needs more than the seat's max_bundle_tokens",
                    seat.profile
                )));
            }
            SeatContextPolicy {
                max_bundle_tokens: seat.max_bundle_tokens,
                core_tokens: profile.core_tokens,
                prefetch_tokens: profile.inject_tokens,
                per_turn_tokens: profile.per_turn_tokens,
            }
        }
    };
    Ok(Some(resolve_context_policy(
        &slice_policy,
        &seat_policy,
        model,
    )?))
}

fn resolve_tools(
    slice: &Option<odin_registry::schema::SliceToolsToml>,
    seat: &Option<odin_registry::schema::SeatToolsToml>,
) -> BrainResult<Option<EffectiveToolPolicy>> {
    let Some(slice) = slice else {
        if seat.is_some() {
            return Err(BrainError::InvalidPolicy(
                "seat tools policy without a slice tools policy exceeds slice authority".into(),
            ));
        }
        return Ok(None);
    };
    let slice_policy = SliceToolPolicy {
        allow: slice.allow.clone(),
        deny: slice.deny.clone(),
        redirects: RedirectPolicy {
            max_http_hops: slice.redirects.max_http_hops,
            allow_cross_origin: slice.redirects.allow_cross_origin,
            allow_https_downgrade: slice.redirects.allow_https_downgrade,
            disabled_aliases: BTreeSet::new(),
        },
        alias_redirects: slice
            .alias_redirect
            .iter()
            .map(|alias| AliasRedirectPolicy {
                from: alias.from.clone(),
                to: alias.to.clone(),
                schema_digest: alias.schema_digest,
            })
            .collect(),
    };
    // Absent seat tools is the identity restriction: nothing extra denied,
    // redirects inherit the slice ceilings. Seat redirects never allow an
    // HTTPS downgrade; the field does not exist in the seat vocabulary.
    let seat_policy = seat.as_ref().map_or_else(
        || SeatToolPolicy {
            deny: BTreeSet::new(),
            redirects: RedirectPolicy {
                max_http_hops: slice.redirects.max_http_hops,
                allow_cross_origin: slice.redirects.allow_cross_origin,
                allow_https_downgrade: false,
                disabled_aliases: BTreeSet::new(),
            },
        },
        |seat| SeatToolPolicy {
            deny: seat.deny.clone(),
            redirects: RedirectPolicy {
                max_http_hops: seat.redirects.max_http_hops,
                allow_cross_origin: seat.redirects.allow_cross_origin,
                allow_https_downgrade: false,
                disabled_aliases: seat.redirects.disabled_aliases.clone(),
            },
        },
    );
    Ok(Some(resolve_tool_policy(&slice_policy, &seat_policy)?))
}
/// Re-exported so callers of the composed policy resolve the domain
/// vocabulary from this module without a second import path.
pub use odin_domain::knowledge::context::{
    AliasRedirectPolicy, EffectiveContextPolicy, EffectiveToolPolicy, RedirectPolicy,
};
pub use odin_domain::knowledge::retrieval::EffectiveKnowledgePolicy;
