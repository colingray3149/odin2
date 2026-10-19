//! Registry TOML → effective brain policy resolution contracts.
//!
//! Defends the three invariants of `config::EffectiveBrainPolicy`:
//! monotonic ceilings (seats narrow slices, never widen), authority
//! restriction (seat blocks cannot exceed slice delegation, knowledge
//! acceptance stays gated), and the one canonical revision-bound binding
//! digest (any content or revision change is rejected on verify).

use std::collections::{BTreeMap, BTreeSet};
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};

use odin_brain::config::EffectiveBrainPolicy;
use odin_brain::error::{BrainError, BrainResult};
use odin_domain::huginn::ids::ModelName;
use odin_domain::knowledge::ids::TokenizerId;
use odin_domain::knowledge::retrieval::ModelDescriptor;
use odin_domain::knowledge::{AtlasId, ToolName};
use odin_domain::{ProjectId, SeatId};
use odin_registry::schema::{
    AccountingWindowToml, ApprovalDefaultToml, ApprovalDefaultsToml, BudgetPolicyToml, ProjectToml,
    RegistryKind, SeatContextToml, SeatKnowledgeToml, SeatLimitsToml, SeatToml,
    SeatToolRedirectsToml, SeatToolsToml, SliceContextToml, SliceKnowledgeToml, SliceRedirectsToml,
    SliceToml, SliceToolRedirectsToml, SliceToolsToml, REGISTRY_SCHEMA,
};

fn nz16(value: u16) -> NonZeroU16 {
    NonZeroU16::new(value).unwrap()
}

fn nz32(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).unwrap()
}

fn atlas_ids(values: &[&str]) -> BTreeSet<AtlasId> {
    values
        .iter()
        .map(|value| AtlasId::new(*value).unwrap())
        .collect()
}

fn tool_names(values: &[&str]) -> BTreeSet<ToolName> {
    values
        .iter()
        .map(|value| ToolName::new(*value).unwrap())
        .collect()
}

fn slice() -> SliceToml {
    SliceToml {
        schema: REGISTRY_SCHEMA.to_owned(),
        kind: RegistryKind::Slice,
        enabled: true,
        description: "policy fixture slice".to_owned(),
        capabilities: BTreeSet::new(),
        variables: BTreeMap::new(),
        redirects: SliceRedirectsToml {
            out_of_scope: "NeedsPlan".to_owned(),
        },
        knowledge: Some(SliceKnowledgeToml {
            required: false,
            atlas_sources: atlas_ids(&["atlas.code", "atlas.operations"]),
            retrieval_mode: odin_domain::knowledge::RetrievalMode::Hybrid,
            candidate_limit: nz16(128),
            top_k: nz16(16),
            min_score_micros: 100_000,
            chunk_tokens: nz32(512),
            chunk_overlap_tokens: 64,
            embedding_backend: odin_domain::knowledge::EmbeddingBackend::Local,
        }),
        context: Some(SliceContextToml {
            max_bundle_tokens: nz32(32768),
            reserve_output_tokens: nz32(8192),
            control_tokens: nz32(4096),
            history_tokens: nz32(12288),
            core_tokens: nz32(2048),
            prefetch_tokens: nz32(6144),
            tool_result_tokens: nz32(4096),
            tool_schema_tokens: nz32(4096),
            max_item_tokens: nz32(2048),
        }),
        tools: Some(SliceToolsToml {
            allow: tool_names(&["read_one", "search_one"]),
            deny: tool_names(&["secret_read_raw"]),
            redirects: SliceToolRedirectsToml {
                max_http_hops: 2,
                allow_cross_origin: false,
                allow_https_downgrade: false,
            },
            alias_redirect: BTreeSet::new(),
        }),
        live: None,
        budget: None,
    }
}

fn seat() -> SeatToml {
    SeatToml {
        schema: REGISTRY_SCHEMA.to_owned(),
        kind: RegistryKind::Seat,
        enabled: true,
        description: "policy fixture seat".to_owned(),
        categories: BTreeSet::new(),
        tool_refs: BTreeSet::new(),
        project_scope: BTreeSet::new(),
        read_project_scope: BTreeSet::new(),
        models: Vec::new(),
        approval_defaults: ApprovalDefaultsToml {
            r0: ApprovalDefaultToml::Auto,
            r1: ApprovalDefaultToml::Auto,
            r2: ApprovalDefaultToml::Auto,
            r3: ApprovalDefaultToml::Approval,
        },
        brain_scope: atlas_ids(&["atlas.code", "atlas.research"]),
        limits: SeatLimitsToml {
            max_parallel_runs: 4,
            max_sessions: 4,
            budget: Some(BudgetPolicyToml {
                usd_micros: 30_000_000,
                window: AccountingWindowToml {
                    duration_seconds: NonZeroU64::new(2_592_000).unwrap(),
                },
            }),
        },
        live: None,
        guidance: None,
        conversation: None,
        profile_namespace: None,
        knowledge: Some(SeatKnowledgeToml {
            atlas_sources: atlas_ids(&["atlas.code"]),
            required_tags: BTreeSet::new(),
            denied_tags: BTreeSet::new(),
            top_k: nz16(8),
        }),
        context: Some(SeatContextToml {
            max_bundle_tokens: nz32(24576),
            profile: "sized".into(),
            review_lane: None,
        }),
        tools: Some(SeatToolsToml {
            deny: tool_names(&["search_one"]),
            redirects: SeatToolRedirectsToml {
                max_http_hops: 2,
                allow_cross_origin: false,
                disabled_aliases: BTreeSet::new(),
            },
            always: BTreeSet::new(),
        }),
        ephemeral: None,
        sandbox: odin_registry::schema::SeatSandboxToml::default(),
    }
}

fn model() -> ModelDescriptor {
    ModelDescriptor {
        name: ModelName::new("model.policy").unwrap(),
        tokenizer: TokenizerId::new("tokenizer.policy").unwrap(),
        context_window_tokens: nz32(65536),
    }
}

fn projects<'a>(entries: &'a [(&str, ProjectToml)]) -> BTreeMap<&'a str, &'a ProjectToml> {
    entries.iter().map(|(id, project)| (*id, project)).collect()
}

fn project(_id: &str, namespaces: &[&str]) -> ProjectToml {
    ProjectToml {
        schema: REGISTRY_SCHEMA.to_owned(),
        kind: RegistryKind::Project,
        enabled: true,
        description: "policy fixture project".to_owned(),
        source_root: String::new(),
        default_seat: SeatId::new("policy-seat").unwrap(),
        memory_namespaces: atlas_ids(namespaces),
        artifact_policy: "standard".to_owned(),
        privacy: None,
        accounts: Default::default(),
        review_verdict: None,
    }
}

fn resolved() -> BrainResult<EffectiveBrainPolicy> {
    EffectiveBrainPolicy::resolve(
        74,
        &slice(),
        &seat(),
        &BTreeMap::new(),
        &std::collections::BTreeMap::from([(
            "sized",
            &odin_registry::ContextProfileToml::sized(nz32(2048), nz32(6144)),
        )]),
        &model(),
    )
}

#[test]
fn registry_blocks_resolve_to_effective_policies() {
    let policy = resolved().unwrap();

    // Knowledge: seat sources are intersected with brain_scope and must be
    // a subset of slice sources; seat top_k narrows the slice top_k.
    let knowledge = policy.knowledge.as_ref().unwrap();
    assert_eq!(
        knowledge.atlas_sources,
        atlas_ids(&["atlas.code"]),
        "seat knowledge sources must be the brain_scope intersection"
    );
    assert_eq!(knowledge.top_k, nz16(8));
    assert_eq!(
        knowledge.retrieval_mode,
        odin_domain::knowledge::RetrievalMode::Hybrid
    );

    // Context: seat ceiling narrows the slice bundle; retrieval tokens are
    // the minimum of slice, seat, and bundle; the model window bounds
    // bundle plus reserved output.
    let context = policy.context.as_ref().unwrap();
    assert_eq!(context.max_bundle_tokens, nz32(24576));
    assert_eq!(context.prefetch_tokens, nz32(6144));
    assert_eq!(context.reserve_output_tokens, nz32(8192));
    assert_eq!(context.effective_model_input_tokens, nz32(32768));
    assert_eq!(context.max_item_tokens, nz32(2048));

    // Tools: deny is the union of slice and seat; allow loses denied names;
    // redirect ceilings are the monotonic minimum.
    let tools = policy.tools.as_ref().unwrap();
    assert_eq!(tools.allow, tool_names(&["read_one"]));
    assert_eq!(tools.deny, tool_names(&["search_one", "secret_read_raw"]));
    assert_eq!(tools.redirects.max_http_hops, 2);
    assert!(!tools.redirects.allow_cross_origin);
    assert!(!tools.redirects.allow_https_downgrade);
}

#[test]
fn seat_ceilings_only_narrow() {
    let mut seat = seat();
    seat.knowledge.as_mut().unwrap().top_k = nz16(2);
    seat.context.as_mut().unwrap().max_bundle_tokens = nz32(4096);

    let narrow = odin_registry::ContextProfileToml::sized(nz32(1024), nz32(1024));
    let policy = EffectiveBrainPolicy::resolve(
        74,
        &slice(),
        &seat,
        &BTreeMap::new(),
        &BTreeMap::from([("sized", &narrow)]),
        &model(),
    )
    .unwrap();
    let knowledge = policy.knowledge.as_ref().unwrap();
    let context = policy.context.as_ref().unwrap();
    assert_eq!(knowledge.top_k, nz16(2), "seat top_k narrows slice top_k");
    assert_eq!(
        context.max_bundle_tokens,
        nz32(4096),
        "seat bundle ceiling narrows slice ceiling"
    );
    assert_eq!(
        context.prefetch_tokens,
        nz32(1024),
        "retrieval budget is the minimum of slice, seat, and bundle"
    );
    assert_eq!(
        context.effective_model_input_tokens,
        nz32(12288),
        "bundle plus reserved output stays inside the model window"
    );
    assert_eq!(
        context.core_tokens,
        nz32(1024),
        "seat core_tokens narrows the slice ceiling"
    );

    let wide = crate::seat();
    let wide_profile = odin_registry::ContextProfileToml::sized(nz32(4096), nz32(2048));
    let wide = EffectiveBrainPolicy::resolve(
        74,
        &slice(),
        &wide,
        &BTreeMap::new(),
        &BTreeMap::from([("sized", &wide_profile)]),
        &model(),
    )
    .unwrap();
    assert_eq!(
        wide.context.unwrap().core_tokens,
        nz32(2048),
        "a seat core_tokens above the slice stays at the slice ceiling"
    );
}

#[test]
fn review_lane_survives_resolve() {
    let mut seat = seat();
    seat.context.as_mut().unwrap().review_lane = Some("zai-glm".to_owned());
    let policy = EffectiveBrainPolicy::resolve(
        74,
        &slice(),
        &seat,
        &BTreeMap::new(),
        &std::collections::BTreeMap::from([(
            "sized",
            &odin_registry::ContextProfileToml::sized(nz32(2048), nz32(6144)),
        )]),
        &model(),
    )
    .unwrap();
    assert_eq!(policy.review_lane.as_deref(), Some("zai-glm"));
    assert!(resolved().unwrap().review_lane.is_none());
}

#[test]
fn authority_restrictions_bind() {
    // A seat claiming knowledge sources outside the slice delegation is
    // rejected: atlas.research is visible to the brain (brain_scope) but
    // never delegated by the slice.
    let mut research_seat = seat();
    research_seat.knowledge.as_mut().unwrap().atlas_sources = atlas_ids(&["atlas.research"]);
    let error = EffectiveBrainPolicy::resolve(
        74,
        &slice(),
        &research_seat,
        &BTreeMap::new(),
        &std::collections::BTreeMap::from([(
            "sized",
            &odin_registry::ContextProfileToml::sized(nz32(2048), nz32(6144)),
        )]),
        &model(),
    )
    .unwrap_err();
    assert!(
        matches!(error, BrainError::Domain(_)),
        "seat Atlas sources outside the slice must be a domain rejection: {error:?}"
    );

    // Disabled registry objects resolve to nothing.
    let mut disabled = slice();
    disabled.enabled = false;
    let error = EffectiveBrainPolicy::resolve(
        74,
        &disabled,
        &seat(),
        &BTreeMap::new(),
        &std::collections::BTreeMap::from([(
            "sized",
            &odin_registry::ContextProfileToml::sized(nz32(2048), nz32(6144)),
        )]),
        &model(),
    )
    .unwrap_err();
    assert!(matches!(error, BrainError::InvalidPolicy(_)));
}

#[test]
fn seat_block_without_slice_block_is_rejected() {
    let mut knowledgeless = slice();
    knowledgeless.knowledge = None;
    let error = EffectiveBrainPolicy::resolve(
        74,
        &knowledgeless,
        &seat(),
        &BTreeMap::new(),
        &std::collections::BTreeMap::from([(
            "sized",
            &odin_registry::ContextProfileToml::sized(nz32(2048), nz32(6144)),
        )]),
        &model(),
    )
    .unwrap_err();
    assert!(matches!(error, BrainError::InvalidPolicy(_)));

    let mut contextless = slice();
    contextless.context = None;
    let error = EffectiveBrainPolicy::resolve(
        74,
        &contextless,
        &seat(),
        &BTreeMap::new(),
        &std::collections::BTreeMap::from([(
            "sized",
            &odin_registry::ContextProfileToml::sized(nz32(2048), nz32(6144)),
        )]),
        &model(),
    )
    .unwrap_err();
    assert!(matches!(error, BrainError::InvalidPolicy(_)));

    let mut toolless = slice();
    toolless.tools = None;
    let error = EffectiveBrainPolicy::resolve(
        74,
        &toolless,
        &seat(),
        &BTreeMap::new(),
        &std::collections::BTreeMap::from([(
            "sized",
            &odin_registry::ContextProfileToml::sized(nz32(2048), nz32(6144)),
        )]),
        &model(),
    )
    .unwrap_err();
    assert!(matches!(error, BrainError::InvalidPolicy(_)));

    // With every seat brain block dropped, absent slice blocks are the
    // honest "no authority delegated" outcome rather than an error.
    let mut seat = seat();
    seat.knowledge = None;
    seat.context = None;
    seat.tools = None;
    let mut bare = slice();
    bare.knowledge = None;
    bare.context = None;
    bare.tools = None;
    let policy = EffectiveBrainPolicy::resolve(
        74,
        &bare,
        &seat,
        &BTreeMap::new(),
        &std::collections::BTreeMap::from([(
            "sized",
            &odin_registry::ContextProfileToml::sized(nz32(2048), nz32(6144)),
        )]),
        &model(),
    )
    .unwrap();
    assert!(policy.knowledge.is_none());
    assert!(policy.context.is_none());
    assert!(policy.tools.is_none());
}

#[test]
fn absent_seat_blocks_inherit_slice_authority() {
    let mut seat = seat();
    seat.knowledge = None;
    seat.context = None;
    seat.tools = None;

    let policy = EffectiveBrainPolicy::resolve(
        74,
        &slice(),
        &seat,
        &BTreeMap::new(),
        &std::collections::BTreeMap::from([(
            "sized",
            &odin_registry::ContextProfileToml::sized(nz32(2048), nz32(6144)),
        )]),
        &model(),
    )
    .unwrap();

    let knowledge = policy.knowledge.as_ref().unwrap();
    assert_eq!(
        knowledge.atlas_sources,
        atlas_ids(&["atlas.code"]),
        "inherited slice sources still respect brain_scope"
    );
    assert_eq!(knowledge.top_k, nz16(16));

    let context = policy.context.as_ref().unwrap();
    assert_eq!(context.max_bundle_tokens, nz32(32768));
    assert_eq!(context.prefetch_tokens, nz32(6144));
    assert_eq!(context.effective_model_input_tokens, nz32(40960));

    let tools = policy.tools.as_ref().unwrap();
    assert_eq!(tools.allow, tool_names(&["read_one", "search_one"]));
    assert_eq!(tools.deny, tool_names(&["secret_read_raw"]));
}

#[test]
fn binding_digest_is_revision_bound_and_verified() {
    let policy = resolved().unwrap();
    policy.verify().expect("freshly resolved policy verifies");

    // The digest binds the registry revision: a different revision under
    // identical policy content produces a different binding.
    let repinned = EffectiveBrainPolicy::resolve(
        75,
        &slice(),
        &seat(),
        &BTreeMap::new(),
        &std::collections::BTreeMap::from([(
            "sized",
            &odin_registry::ContextProfileToml::sized(nz32(2048), nz32(6144)),
        )]),
        &model(),
    )
    .unwrap();
    assert_ne!(
        policy.policy_digest, repinned.policy_digest,
        "binding digest must change with the registry revision"
    );

    // The digest binds the content: any mutation without a re-resolve is
    // rejected as a stale binding.
    let mut tampered = policy.clone();
    tampered.registry_revision = 75;
    assert!(tampered.verify().is_err());

    let mut tampered = policy.clone();
    tampered.knowledge.as_mut().unwrap().top_k = nz16(4);
    assert!(tampered.verify().is_err());

    let mut tampered = policy.clone();
    tampered.context.as_mut().unwrap().max_bundle_tokens = nz32(1024);
    assert!(tampered.verify().is_err());

    let mut tampered = policy;
    tampered.tools.as_mut().unwrap().allow = tool_names(&["write_one"]);
    assert!(tampered.verify().is_err());
}

#[test]
fn project_memory_intersects_declared_namespaces_with_authorized_sources() {
    // The fixture seat's authorized knowledge set is exactly {atlas.code}
    // (seat knowledge ∩ brain_scope ∩ slice). Project alpha declares two
    // namespaces; only the authorized one may survive composition.
    let mut scoped_seat = seat();
    scoped_seat.project_scope = BTreeSet::from([ProjectId::new("alpha").unwrap()]);
    let alpha = project("alpha", &["atlas.code", "atlas.operations"]);
    let policy = EffectiveBrainPolicy::resolve(
        74,
        &slice(),
        &scoped_seat,
        &projects(&[("alpha", alpha)]),
        &std::collections::BTreeMap::from([(
            "sized",
            &odin_registry::ContextProfileToml::sized(nz32(2048), nz32(6144)),
        )]),
        &model(),
    )
    .unwrap();
    assert_eq!(
        policy.project_memory(&ProjectId::new("alpha").unwrap()),
        Some(&atlas_ids(&["atlas.code"])),
        "project memory is the declared namespaces intersected with the seat's \
         authorized sources, never wider"
    );

    // A project the seat does not scope has no entry at all — not an
    // implicit default.
    assert_eq!(
        policy.project_memory(&ProjectId::new("beta").unwrap()),
        None
    );

    // Declared namespaces the seat cannot authorize compose an explicit
    // empty set: present, declared, unusable.
    let mut other_seat = seat();
    other_seat.project_scope = BTreeSet::from([ProjectId::new("gamma").unwrap()]);
    let gamma = project("gamma", &["atlas.research"]);
    let policy = EffectiveBrainPolicy::resolve(
        74,
        &slice(),
        &other_seat,
        &projects(&[("gamma", gamma)]),
        &std::collections::BTreeMap::from([(
            "sized",
            &odin_registry::ContextProfileToml::sized(nz32(2048), nz32(6144)),
        )]),
        &model(),
    )
    .unwrap();
    let empty: BTreeSet<AtlasId> = BTreeSet::new();
    assert_eq!(
        policy.project_memory(&ProjectId::new("gamma").unwrap()),
        Some(&empty),
        "an unreachable declaration composes empty, never widened"
    );
}

#[test]
fn scoped_project_absent_from_the_snapshot_is_a_broken_declaration() {
    let mut scoped_seat = seat();
    scoped_seat.project_scope = BTreeSet::from([ProjectId::new("alpha").unwrap()]);
    let error = EffectiveBrainPolicy::resolve(
        74,
        &slice(),
        &scoped_seat,
        &BTreeMap::new(),
        &std::collections::BTreeMap::from([(
            "sized",
            &odin_registry::ContextProfileToml::sized(nz32(2048), nz32(6144)),
        )]),
        &model(),
    )
    .unwrap_err();
    assert!(
        matches!(error, BrainError::InvalidPolicy(_)),
        "a scoped project missing from the snapshot must refuse composition: {error:?}"
    );

    let mut disabled_project = project("alpha", &["atlas.code"]);
    disabled_project.enabled = false;
    let error = EffectiveBrainPolicy::resolve(
        74,
        &slice(),
        &scoped_seat,
        &projects(&[("alpha", disabled_project)]),
        &std::collections::BTreeMap::from([(
            "sized",
            &odin_registry::ContextProfileToml::sized(nz32(2048), nz32(6144)),
        )]),
        &model(),
    )
    .unwrap_err();
    assert!(
        matches!(error, BrainError::InvalidPolicy(_)),
        "a disabled scoped project must refuse composition: {error:?}"
    );
}

#[test]
fn project_memory_is_bound_into_the_policy_digest() {
    let mut scoped_seat = seat();
    scoped_seat.project_scope = BTreeSet::from([ProjectId::new("alpha").unwrap()]);
    // The slice ceiling AND the seat's knowledge must both admit the two
    // namespaces, else the authorized intersection collapses the two
    // compositions to the same map and the digest cannot move.
    let mut slice = slice();
    if let Some(knowledge) = slice.knowledge.as_mut() {
        knowledge.atlas_sources = atlas_ids(&["atlas.code", "atlas.research"]);
    }
    scoped_seat.knowledge = Some(SeatKnowledgeToml {
        atlas_sources: atlas_ids(&["atlas.code", "atlas.research"]),
        required_tags: BTreeSet::new(),
        denied_tags: BTreeSet::new(),
        top_k: nz16(8),
    });
    let narrow = project("alpha", &["atlas.code"]);
    let wide = project("alpha", &["atlas.code", "atlas.research"]);
    let base = EffectiveBrainPolicy::resolve(
        74,
        &slice,
        &scoped_seat,
        &projects(&[("alpha", narrow)]),
        &std::collections::BTreeMap::from([(
            "sized",
            &odin_registry::ContextProfileToml::sized(nz32(2048), nz32(6144)),
        )]),
        &model(),
    )
    .unwrap();
    let other = EffectiveBrainPolicy::resolve(
        74,
        &slice,
        &scoped_seat,
        &projects(&[("alpha", wide)]),
        &std::collections::BTreeMap::from([(
            "sized",
            &odin_registry::ContextProfileToml::sized(nz32(2048), nz32(6144)),
        )]),
        &model(),
    )
    .unwrap();
    assert_ne!(
        base.policy_digest, other.policy_digest,
        "the binding digest must cover the composed project memory map"
    );
    let mut tampered = base.clone();
    tampered.project_memory.insert(
        ProjectId::new("alpha").unwrap(),
        atlas_ids(&["atlas.operations"]),
    );
    assert!(
        tampered.verify().is_err(),
        "a mutated project memory map must fail the binding digest check"
    );
}

#[test]
fn out_of_scope_project_namespaces_never_degrade_to_seat_general() {
    // The seat authorizes {atlas.code, atlas.research}. Project alpha (in
    // scope) privately declares atlas.code; project beta (OUT of scope)
    // privately declares atlas.research. The classification reads every
    // declared project in the snapshot, so atlas.research is project
    // memory everywhere: it must never serve as this seat's general
    // knowledge, or beta's private memory would leak into every session
    // of a seat that cannot even scope beta.
    let mut wide_slice = slice();
    wide_slice.knowledge.as_mut().unwrap().atlas_sources =
        atlas_ids(&["atlas.code", "atlas.research"]);
    let mut private_seat = seat();
    private_seat.knowledge.as_mut().unwrap().atlas_sources =
        atlas_ids(&["atlas.code", "atlas.research"]);
    private_seat.project_scope = BTreeSet::from([ProjectId::new("alpha").unwrap()]);
    let alpha = project("alpha", &["atlas.code"]);
    let mut beta = project("beta", &["atlas.research"]);
    let policy = EffectiveBrainPolicy::resolve(
        74,
        &wide_slice,
        &private_seat,
        &projects(&[("alpha", alpha), ("beta", beta.clone())]),
        &std::collections::BTreeMap::from([(
            "sized",
            &odin_registry::ContextProfileToml::sized(nz32(2048), nz32(6144)),
        )]),
        &model(),
    )
    .unwrap();
    let empty: BTreeSet<AtlasId> = BTreeSet::new();
    assert_eq!(
        policy.seat_global_sources, empty,
        "every authorized source is reserved by some project declaration"
    );
    assert_eq!(
        policy.project_serving_scope(None),
        empty,
        "a projectless session serves no project-private source, even one \
         the seat authorizes but an out-of-scope project declared"
    );
    assert_eq!(
        policy.project_serving_scope(Some(&ProjectId::new("alpha").unwrap())),
        atlas_ids(&["atlas.code"]),
        "the scoped project serves exactly its own declared memory"
    );
    assert_eq!(
        policy.project_memory(&ProjectId::new("beta").unwrap()),
        None,
        "beta is not in the seat's scope: no entry, never a default"
    );

    // Reservation is declaration-based, not enabled-based: a disabled
    // out-of-scope project's durable private memory must not resurface as
    // seat-general either. (Scoped-but-disabled projects still refuse
    // composition; beta is not scoped here.)
    beta.enabled = false;
    let policy = EffectiveBrainPolicy::resolve(
        74,
        &wide_slice,
        &private_seat,
        &projects(&[("alpha", project("alpha", &["atlas.code"])), ("beta", beta)]),
        &std::collections::BTreeMap::from([(
            "sized",
            &odin_registry::ContextProfileToml::sized(nz32(2048), nz32(6144)),
        )]),
        &model(),
    )
    .unwrap();
    assert_eq!(
        policy.seat_global_sources, empty,
        "a disabled project's declared namespace still reserves"
    );

    // The classification is canonical composition output: the binding
    // digest covers it, so a tampered general set fails verify.
    let mut tampered = policy.clone();
    tampered
        .seat_global_sources
        .insert(AtlasId::new("atlas.research").unwrap());
    assert!(
        tampered.verify().is_err(),
        "a mutated seat-global classification must fail the binding digest check"
    );
}
