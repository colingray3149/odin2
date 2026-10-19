//! Governed archive ingest end to end: approval-bound ingest, content-
//! addressed idempotence, durable resume, namespace isolation, citation
//! provenance, and the lexical-only/backfill embedding posture — all over
//! the public `BrainService` API and tiny synthetic Claude exports written
//! to per-test temporary directories (raw export data never enters the
//! repo).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::sync::{Arc, Mutex};

use odin_brain::config::EffectiveBrainPolicy;
use odin_brain::error::{BrainError, BrainResult};
use odin_brain::retrieval::embedding::EmbeddingVector;
use odin_brain::service::{
    archive_declaration_digest, ArchiveBackfillOutcome, ArchiveEmbeddingBackfillRequest,
    ArchiveEmbeddingView, ArchiveIngestAuthority, ArchiveIngestGate, ArchiveIngestRequest,
    BrainService, BrainServiceConfig, BrainSourceConfig, EmbeddingBatchLane, RetrievalPosture,
};
use odin_domain::huginn::ids::ModelName;
use odin_domain::knowledge::archive::{
    ArchiveDedupeKey, ArchiveFormat, ArchivePrivacyClass, ArchiveSelectionPolicy,
    ArchiveSourceDeclaration,
};
use odin_domain::knowledge::ids::{AtlasId, EmbeddingModelId, RelevanceScore, TokenizerId};
use odin_domain::knowledge::retrieval::{ModelDescriptor, RetrievalQuery, TrustClass};
use odin_domain::knowledge::{EmbeddingBackend, RetrievalMode};
use odin_domain::Digest;
use odin_ledger::Ledger;
use odin_registry::schema::{
    AccountingWindowToml, ApprovalDefaultToml, ApprovalDefaultsToml, BudgetPolicyToml, ProjectToml,
    RegistryKind, SeatContextToml, SeatKnowledgeToml, SeatLimitsToml, SeatToml, SliceContextToml,
    SliceKnowledgeToml, SliceRedirectsToml, SliceToml, REGISTRY_SCHEMA,
};

const ALPHA_SOURCE: &str = "archive:alpha";
const BETA_SOURCE: &str = "archive:beta";
const ALPHA_FACT: &str = "ALPHA-ONYX: the onyx hatch opens only at low tide";
const BETA_FACT: &str = "BETA-CINDER: the cinder vault seals at moonrise";
const META_SOURCE: &str = "archive:meta";
const META_FACT: &str = "META-ONYX: the meta hatch opens only at high noon";

fn nz16(value: u16) -> NonZeroU16 {
    NonZeroU16::new(value).unwrap()
}

fn nz32(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).unwrap()
}

fn atlas_ids(values: &[&str]) -> BTreeSet<AtlasId> {
    values.iter().map(|v| AtlasId::new(*v).unwrap()).collect()
}

fn declaration(path: &std::path::Path, namespace: &str) -> ArchiveSourceDeclaration {
    ArchiveSourceDeclaration {
        format: ArchiveFormat::ClaudeExport,
        path: path.to_path_buf(),
        memory_namespace: namespace.to_owned(),
        privacy_class: ArchivePrivacyClass::Private,
        dedupe_key: ArchiveDedupeKey::ContentDigest,
        selection: ArchiveSelectionPolicy {
            since: None,
            exclude_labels: Vec::new(),
            exclude_if_header: Vec::new(),
            keep_if_participant: false,
            participant_emails: Vec::new(),
            suspicious_rules: Vec::new(),
            exclude_do_not_remember: None,
        },
    }
}

/// Synthetic exports stay in temporary directories, never the repository.
fn write_export(tag: &str, fact: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "odin-brain-archive-ingest-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let export = serde_json::json!([
        {
            "uuid": format!("conv-{tag}"),
            "name": format!("fixture {tag}"),
            "account": { "uuid": format!("account-{tag}") },
            "created_at": "2026-01-01T00:00:00Z",
            "chat_messages": [
                {
                    "uuid": format!("msg-{tag}"),
                    "sender": "user",
                    "text": fact,
                    "created_at": "2026-01-02T00:00:00Z"
                }
            ]
        }
    ]);
    std::fs::write(
        dir.join("conversations.json"),
        serde_json::to_string(&export).unwrap(),
    )
    .unwrap();
    dir
}

fn replace_fact(tag: &str, dir: &std::path::Path, fact: &str) {
    let export = serde_json::json!([
        {
            "uuid": format!("conv-{tag}"),
            "name": format!("fixture {tag}"),
            "account": { "uuid": format!("account-{tag}") },
            "created_at": "2026-01-01T00:00:00Z",
            "chat_messages": [
                {
                    "uuid": format!("msg-{tag}"),
                    "sender": "user",
                    "text": fact,
                    "created_at": "2026-01-02T00:00:00Z"
                }
            ]
        }
    ]);
    std::fs::write(
        dir.join("conversations.json"),
        serde_json::to_string(&export).unwrap(),
    )
    .unwrap();
}

fn slice_mode(sources: &[&str], mode: RetrievalMode, backend: EmbeddingBackend) -> SliceToml {
    SliceToml {
        schema: REGISTRY_SCHEMA.to_owned(),
        kind: RegistryKind::Slice,
        enabled: true,
        description: "archive ingest fixture slice".to_owned(),
        capabilities: BTreeSet::new(),
        variables: BTreeMap::new(),
        redirects: SliceRedirectsToml {
            out_of_scope: "NeedsPlan".to_owned(),
        },
        knowledge: Some(SliceKnowledgeToml {
            required: false,
            atlas_sources: atlas_ids(sources),
            retrieval_mode: mode,
            candidate_limit: nz16(64),
            top_k: nz16(8),
            min_score_micros: 0,
            chunk_tokens: nz32(512),
            chunk_overlap_tokens: 64,
            embedding_backend: backend,
        }),
        context: Some(SliceContextToml {
            max_bundle_tokens: nz32(8192),
            reserve_output_tokens: nz32(1024),
            control_tokens: nz32(2048),
            history_tokens: nz32(256),
            core_tokens: nz32(2048),
            prefetch_tokens: nz32(2048),
            tool_result_tokens: nz32(256),
            tool_schema_tokens: nz32(512),
            max_item_tokens: nz32(1024),
        }),
        tools: None,
        live: None,
        budget: None,
    }
}

fn seat(sources: &[&str]) -> SeatToml {
    SeatToml {
        schema: REGISTRY_SCHEMA.to_owned(),
        kind: RegistryKind::Seat,
        enabled: true,
        description: "archive ingest fixture seat".to_owned(),
        categories: BTreeSet::new(),
        project_scope: BTreeSet::new(),
        read_project_scope: BTreeSet::new(),
        models: Vec::new(),
        tool_refs: BTreeSet::new(),
        approval_defaults: ApprovalDefaultsToml {
            r0: ApprovalDefaultToml::Auto,
            r1: ApprovalDefaultToml::Auto,
            r2: ApprovalDefaultToml::Auto,
            r3: ApprovalDefaultToml::Auto,
        },
        brain_scope: atlas_ids(sources),
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
            atlas_sources: atlas_ids(sources),
            required_tags: BTreeSet::new(),
            denied_tags: BTreeSet::new(),
            top_k: nz16(8),
        }),
        context: Some(SeatContextToml {
            max_bundle_tokens: nz32(8192),
            profile: "sized".into(),
            review_lane: None,
        }),
        tools: None,
        ephemeral: None,
        sandbox: odin_registry::schema::SeatSandboxToml::default(),
    }
}

fn model() -> ModelDescriptor {
    ModelDescriptor {
        name: ModelName::new("model.archive").unwrap(),
        tokenizer: TokenizerId::new("odin.tokenizer.utf8-bytes.v1").unwrap(),
        context_window_tokens: nz32(8192),
    }
}

fn policy(sources: &[&str]) -> EffectiveBrainPolicy {
    policy_mode(sources, RetrievalMode::Lexical, EmbeddingBackend::Disabled)
}

fn policy_mode(
    sources: &[&str],
    mode: RetrievalMode,
    backend: EmbeddingBackend,
) -> EffectiveBrainPolicy {
    EffectiveBrainPolicy::resolve(
        74,
        &slice_mode(sources, mode, backend),
        &seat(sources),
        &BTreeMap::<&str, &ProjectToml>::new(),
        &std::collections::BTreeMap::from([(
            "sized",
            &odin_registry::ContextProfileToml::sized(nz32(2048), nz32(2048)),
        )]),
        &model(),
    )
    .unwrap()
}

fn ledger() -> Arc<Mutex<Ledger>> {
    Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()))
}

fn config(tag: &str, sources: BTreeMap<AtlasId, BrainSourceConfig>) -> BrainServiceConfig {
    let store_root = std::env::temp_dir().join(format!(
        "odin-brain-archive-store-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&store_root);
    BrainServiceConfig {
        store_root,
        sources,
        embedding_available: false,
        embedding_model: None,
        archive_ingest_gate: test_gate(),
        postgres: None,
    }
}

fn archive_source(declaration: ArchiveSourceDeclaration) -> BrainSourceConfig {
    BrainSourceConfig::Archive { declaration }
}

fn query(sources: BTreeSet<AtlasId>, text: &str) -> RetrievalQuery {
    RetrievalQuery::new(
        text.to_owned(),
        sources,
        BTreeSet::new(),
        BTreeSet::new(),
        [
            TrustClass::Curated,
            TrustClass::Observed,
            TrustClass::Untrusted,
        ]
        .into_iter()
        .collect(),
        nz16(64),
        nz16(8),
        RelevanceScore::new(0).unwrap(),
    )
    .unwrap()
}

/// Approval IDs ending in "denied" simulate gate rejection before mutation.
struct TestGate;

impl ArchiveIngestGate for TestGate {
    fn verify(
        &self,
        authority: &ArchiveIngestAuthority,
        source: &AtlasId,
        _idempotency_key: &str,
    ) -> odin_brain::error::BrainResult<()> {
        if source.as_str().is_empty() {
            return Err(odin_brain::error::BrainError::InvalidRequest(
                "empty source".to_owned(),
            ));
        }
        if authority.approval_id.ends_with("denied") {
            return Err(odin_brain::error::BrainError::Unavailable {
                component: "archive_ingest_gate",
                reason: "approval is not in an approved-and-consumed state".to_owned(),
            });
        }
        Ok(())
    }
}

fn test_gate() -> Option<Arc<dyn ArchiveIngestGate>> {
    Some(Arc::new(TestGate))
}

fn ingest_request(
    source: &AtlasId,
    declaration: &ArchiveSourceDeclaration,
    content_revision: Digest,
    key: &str,
) -> ArchiveIngestRequest {
    ArchiveIngestRequest {
        source: source.clone(),
        declaration: declaration.clone(),
        approval: ArchiveIngestAuthority {
            demand_id: format!("demand-{key}"),
            approval_id: format!("approval-{key}"),
            command_id: format!("command-{key}"),
            declaration_digest: archive_declaration_digest(declaration).unwrap(),
            content_revision,
        },
        idempotency_key: key.to_owned(),
        deadline: None,
    }
}

/// The ingested fact must serve with source attribution. One tiny fixture
/// legitimately serves it from two records — the message itself and the
/// conversation summary the parser derives (which embeds the first user
/// message) — so this asserts service, never a record count.
fn assert_fact_serves(hits: &[odin_domain::knowledge::RetrievalHit], needle: &str) {
    let served = hit_count(hits, needle);
    assert!(
        served >= 1,
        "the ingested fact {needle:?} must serve with source attribution, got {served} hits"
    );
}

fn hit_count(hits: &[odin_domain::knowledge::RetrievalHit], needle: &str) -> usize {
    hits.iter()
        .filter(|hit| hit.content.contains(needle))
        .count()
}

/// Governed ingest serves persisted approved state with citation
/// provenance; the lexical-only posture is observable; a re-run of the
/// identical approved revision is an idempotent no-op.
#[test]
fn governed_ingest_publishes_serves_cites_and_reanswers_zero_rows() {
    let tag = "governed";
    let export = write_export(tag, ALPHA_FACT);
    let source = AtlasId::new(ALPHA_SOURCE).unwrap();
    let declaration = declaration(&export, "memory.alpha");
    let sources = BTreeMap::from([(source.clone(), archive_source(declaration.clone()))]);
    let service =
        BrainService::open(config(tag, sources), policy(&[ALPHA_SOURCE]), ledger()).unwrap();

    // Retrieval before any approval serves nothing and never auto-ingests.
    let empty = service
        .retrieve(&query(atlas_ids(&[ALPHA_SOURCE]), "onyx hatch"), None, None)
        .unwrap()
        .hits;
    assert_eq!(hit_count(&empty, ALPHA_FACT), 0);
    assert!(service.archive_status(&source).unwrap().published.is_none());

    let plan = service.prepare_archive_ingest(&source).unwrap();
    assert!(
        plan.records >= 2,
        "conversation, summary, and message records"
    );
    let request = ingest_request(&source, &declaration, plan.content_revision, "run-1");
    let report = service.ingest_archive(&request).unwrap();
    assert!(!report.resumed);
    assert_eq!(report.records_seen, plan.records);
    assert_eq!(report.records_staged, plan.records);
    assert_eq!(report.records_duplicate, 0);
    assert!(report.chunks > 0);

    // Serving path: the fact is retrievable, and the citation expands to
    // the exact export record — no raw archive re-read.
    let hits = service
        .retrieve(&query(atlas_ids(&[ALPHA_SOURCE]), "onyx hatch"), None, None)
        .unwrap()
        .hits;
    assert_fact_serves(&hits, ALPHA_FACT);
    // Each hit's citation resolves to its OWN record: the message record
    // carrying the fact cites the exact export message, and the derived
    // conversation summary (whose text embeds the first user message)
    // legitimately serves the same fact as its own record. Ranking between
    // the two is not part of the contract, so the message citation is
    // selected by identity, never by position.
    let citation = hits
        .iter()
        .filter(|hit| hit.content.contains(ALPHA_FACT))
        .map(|hit| {
            service
                .archive_citation(
                    &hit.citation.source,
                    &hit.citation.source_revision,
                    &hit.citation.item_id,
                )
                .unwrap()
                .expect("every served hit expands to stored provenance")
        })
        .find(|citation| citation.message_id.as_deref() == Some(format!("msg-{tag}").as_str()))
        .expect("the message record serving the fact must cite the exact export message");
    assert_eq!(
        citation.export_account.as_deref(),
        Some(format!("account-{tag}").as_str())
    );
    assert_eq!(
        citation.conversation_id.as_deref(),
        Some(format!("conv-{tag}").as_str())
    );
    assert_eq!(
        citation.message_id.as_deref(),
        Some(format!("msg-{tag}").as_str())
    );
    assert_eq!(citation.namespace, "memory.alpha");
    assert_eq!(citation.privacy_class, ArchivePrivacyClass::Private);

    // The lexical-only backlog is durable and observable.
    let status = service.archive_status(&source).unwrap();
    let published = status.published.clone().unwrap();
    assert_eq!(published.revision, plan.content_revision);
    assert_eq!(published.records, plan.records);
    match published.embedding {
        ArchiveEmbeddingView::LexicalOnly {
            pending_chunks,
            staged_vectors,
        } => {
            assert_eq!(pending_chunks, report.chunks);
            assert_eq!(staged_vectors, 0);
        }
        ArchiveEmbeddingView::Embedded { .. } => panic!("ingest must be lexical-only"),
    }

    // Re-running the identical approved revision adds zero rows.
    let again = service
        .ingest_archive(&ingest_request(
            &source,
            &declaration,
            plan.content_revision,
            "run-2",
        ))
        .unwrap();
    assert!(again.resumed);
    assert_eq!(again.records_staged, 0);
    assert_eq!(
        again.generation.generation_id,
        report.generation.generation_id
    );
    let status = service.archive_status(&source).unwrap();
    assert_eq!(status.published.unwrap().records, plan.records);
}

/// A rejected or expired approval (gate verification fails) and an
/// approval bound to the wrong content revision both mutate nothing: no
/// publication, no serving generation, durable state untouched.
#[test]
fn denied_approval_cannot_mutate_the_corpus() {
    let tag = "denied";
    let export = write_export(tag, ALPHA_FACT);
    let source = AtlasId::new(ALPHA_SOURCE).unwrap();
    let declaration = declaration(&export, "memory.alpha");
    let sources = BTreeMap::from([(source.clone(), archive_source(declaration.clone()))]);
    let service =
        BrainService::open(config(tag, sources), policy(&[ALPHA_SOURCE]), ledger()).unwrap();

    // Gate-level denial: the approval is not in an approved state.
    let mut denied = ingest_request(&source, &declaration, Digest::hash(b"unused"), "run-denied");
    denied.approval.approval_id = "approval-denied".to_owned();
    assert!(matches!(
        service.ingest_archive(&denied),
        Err(BrainError::Unavailable { .. })
    ));
    assert!(service.archive_status(&source).unwrap().published.is_none());

    // Wrong content revision binding: verified by the brain after the
    // stream reproduces the real revision.
    let wrong_revision = Digest::hash(b"not the export");
    let request = ingest_request(&source, &declaration, wrong_revision, "run-1");
    let error = service.ingest_archive(&request).unwrap_err();
    assert!(
        matches!(error, BrainError::InvalidRequest(_)),
        "stale approval must refuse typed, got {error}"
    );
    assert!(service.archive_status(&source).unwrap().published.is_none());
    let hits = service
        .retrieve(&query(atlas_ids(&[ALPHA_SOURCE]), "onyx hatch"), None, None)
        .unwrap()
        .hits;
    assert_eq!(hit_count(&hits, ALPHA_FACT), 0);
}

/// Content changed after approval: the same export UUIDs now carry edited
/// bytes, the revision moves, and the stale approval refuses before any
/// publication. Re-prepare + re-approve publishes the new revision.
#[test]
fn changed_content_under_stable_uuids_refuses_stale_approval() {
    let tag = "changed";
    let export = write_export(tag, ALPHA_FACT);
    let source = AtlasId::new(ALPHA_SOURCE).unwrap();
    let declaration = declaration(&export, "memory.alpha");
    let sources = BTreeMap::from([(source.clone(), archive_source(declaration.clone()))]);
    let service =
        BrainService::open(config(tag, sources), policy(&[ALPHA_SOURCE]), ledger()).unwrap();

    let plan = service.prepare_archive_ingest(&source).unwrap();
    // One byte changes under the same conversation and message UUIDs.
    replace_fact(tag, &export, &format!("{ALPHA_FACT} (edited)"));
    let stale = service.ingest_archive(&ingest_request(
        &source,
        &declaration,
        plan.content_revision,
        "run-1",
    ));
    assert!(
        matches!(stale, Err(BrainError::InvalidRequest(_))),
        "stale approval must refuse typed"
    );
    assert!(service.archive_status(&source).unwrap().published.is_none());

    // A fresh approval against the new content publishes it.
    let replanned = service.prepare_archive_ingest(&source).unwrap();
    assert_ne!(replanned.content_revision, plan.content_revision);
    let report = service
        .ingest_archive(&ingest_request(
            &source,
            &declaration,
            replanned.content_revision,
            "run-2",
        ))
        .unwrap();
    assert!(!report.resumed);
    let hits = service
        .retrieve(&query(atlas_ids(&[ALPHA_SOURCE]), "onyx hatch"), None, None)
        .unwrap()
        .hits;
    assert_fact_serves(&hits, "(edited)");
}

/// Per-source namespaces isolate retrieval: a query scoped to one archive
/// source never surfaces another source's memory, even when both are
/// published and the wording overlaps.
#[test]
fn namespace_isolation_between_archive_sources() {
    let tag = "isolated";
    let alpha_export = write_export(&format!("{tag}-a"), ALPHA_FACT);
    let beta_export = write_export(&format!("{tag}-b"), BETA_FACT);
    let alpha = AtlasId::new(ALPHA_SOURCE).unwrap();
    let beta = AtlasId::new(BETA_SOURCE).unwrap();
    let alpha_decl = declaration(&alpha_export, "memory.alpha");
    let beta_decl = declaration(&beta_export, "memory.beta");
    let sources = BTreeMap::from([
        (alpha.clone(), archive_source(alpha_decl.clone())),
        (beta.clone(), archive_source(beta_decl.clone())),
    ]);
    let service = BrainService::open(
        config(tag, sources),
        policy(&[ALPHA_SOURCE, BETA_SOURCE]),
        ledger(),
    )
    .unwrap();

    for (source, decl, key) in [(&alpha, &alpha_decl, "alpha"), (&beta, &beta_decl, "beta")] {
        let plan = service.prepare_archive_ingest(source).unwrap();
        service
            .ingest_archive(&ingest_request(source, decl, plan.content_revision, key))
            .unwrap();
    }
    let alpha_hits = service
        .retrieve(
            &query(atlas_ids(&[ALPHA_SOURCE]), "hatch vault opens seals"),
            None,
            None,
        )
        .unwrap()
        .hits;
    assert_fact_serves(&alpha_hits, ALPHA_FACT);
    assert_eq!(
        hit_count(&alpha_hits, BETA_FACT),
        0,
        "beta memory must not serve under alpha's scope"
    );
    let status = service.archive_status(&beta).unwrap();
    assert_eq!(status.memory_namespace, "memory.beta");
}

/// A deterministic fake lane: batch-of-N in, N aligned vectors out. The
/// unavailability variant models the gateway being down (mini offline).
struct FakeLane {
    dims: usize,
    unavailable: bool,
    calls: usize,
}

impl FakeLane {
    fn working(dims: usize) -> Self {
        Self {
            dims,
            unavailable: false,
            calls: 0,
        }
    }

    fn unavailable() -> Self {
        Self {
            dims: 4,
            unavailable: true,
            calls: 0,
        }
    }
}

impl EmbeddingBatchLane for FakeLane {
    fn embed_batch(&mut self, texts: &[String]) -> BrainResult<Vec<EmbeddingVector>> {
        self.calls += 1;
        if self.unavailable {
            return Err(BrainError::EmbeddingUnavailable {
                provider: "fake-gateway".to_owned(),
                reason: "lane down for the test".to_owned(),
            });
        }
        texts
            .iter()
            .map(|_| EmbeddingVector::from_dims(vec![0.5; self.dims]))
            .collect()
    }
}

/// The embedding backlog is observable; lane unavailability completes
/// lexical-only with durable staged progress; a later run resumes and the
/// complete pool flips the publication to the model-bound generation.
#[test]
fn backfill_lexical_only_typed_unavailable_then_resumes_to_embedded() {
    let tag = "backfill";
    let export = write_export(tag, ALPHA_FACT);
    let source = AtlasId::new(ALPHA_SOURCE).unwrap();
    let declaration = declaration(&export, "memory.alpha");
    let sources = BTreeMap::from([(source.clone(), archive_source(declaration.clone()))]);
    let service =
        BrainService::open(config(tag, sources), policy(&[ALPHA_SOURCE]), ledger()).unwrap();
    let plan = service.prepare_archive_ingest(&source).unwrap();
    service
        .ingest_archive(&ingest_request(
            &source,
            &declaration,
            plan.content_revision,
            "run-1",
        ))
        .unwrap();
    let lexical = service.archive_status(&source).unwrap();
    let lexical_chunks = match lexical.published.unwrap().embedding {
        ArchiveEmbeddingView::LexicalOnly { pending_chunks, .. } => pending_chunks,
        ArchiveEmbeddingView::Embedded { .. } => panic!("ingest must be lexical-only"),
    };

    let model = EmbeddingModelId::new("embedding.archive-test.v1").unwrap();
    // One-batch budget with a batch size of one: the first run stages a
    // single vector and stops honest, well short of the pool.
    let mut lane = FakeLane::working(4);
    let partial = service
        .backfill_archive_embeddings(
            &ArchiveEmbeddingBackfillRequest {
                source: source.clone(),
                embedding_model: model.clone(),
                batch_size: 1,
                max_batches: Some(1),
            },
            &mut lane,
        )
        .unwrap();
    let (reason, pending) = match &partial.outcome {
        ArchiveBackfillOutcome::LexicalOnly { reason, pending } => (reason.clone(), *pending),
        ArchiveBackfillOutcome::Embedded => panic!("a budgeted run must stay lexical"),
    };
    assert_eq!(lane.calls, 1, "the budget is measured in lane calls");
    assert!(
        reason.contains("budget"),
        "budget exhaustion is the honest stop reason, got: {reason}"
    );
    assert!(pending > 0);
    let status = service.archive_status(&source).unwrap();
    match status.published.unwrap().embedding {
        ArchiveEmbeddingView::LexicalOnly {
            pending_chunks,
            staged_vectors,
        } => {
            assert_eq!(staged_vectors, lexical_chunks - pending);
            assert_eq!(pending_chunks, pending);
        }
        ArchiveEmbeddingView::Embedded { .. } => panic!("partial backfill must stay lexical"),
    }

    // Typed unavailability keeps staged progress and changes nothing else.
    let mut down = FakeLane::unavailable();
    let blocked = service
        .backfill_archive_embeddings(
            &ArchiveEmbeddingBackfillRequest {
                source: source.clone(),
                embedding_model: model.clone(),
                batch_size: 1,
                max_batches: None,
            },
            &mut down,
        )
        .unwrap();
    match blocked.outcome {
        ArchiveBackfillOutcome::LexicalOnly {
            reason,
            pending: still_pending,
        } => {
            assert!(reason.contains("unavailable") || reason.contains("down"));
            assert_eq!(still_pending, pending);
        }
        ArchiveBackfillOutcome::Embedded => panic!("an unavailable lane must not embed"),
    }

    // Resume to completion: the pool moves and the publication flips.
    let mut lane = FakeLane::working(4);
    let done = service
        .backfill_archive_embeddings(
            &ArchiveEmbeddingBackfillRequest {
                source: source.clone(),
                embedding_model: model.clone(),
                batch_size: 8,
                max_batches: None,
            },
            &mut lane,
        )
        .unwrap();
    assert_eq!(done.outcome, ArchiveBackfillOutcome::Embedded);
    assert_eq!(done.vectors_staged, lexical_chunks);
    let status = service.archive_status(&source).unwrap();
    match status.published.unwrap().embedding {
        ArchiveEmbeddingView::Embedded { model: bound } => assert_eq!(bound, model),
        ArchiveEmbeddingView::LexicalOnly { .. } => panic!("backfill must complete embedded"),
    }
    // The old lexical generation is untouched history: the fact still
    // serves, now from the model-bound pool's generation.
    let hits = service
        .retrieve(&query(atlas_ids(&[ALPHA_SOURCE]), "onyx hatch"), None, None)
        .unwrap()
        .hits;
    assert_fact_serves(&hits, ALPHA_FACT);
}

/// Two differing records may legitimately share one export natural key: the
/// real personal export repeats message uuids, and one message can carry two
/// same-named attachments. Item identity is content-addressed, so each record
/// stays a distinct retrieval item whose citation expands to exactly that
/// record — never to its twin.
#[test]
fn reused_natural_keys_keep_unambiguous_item_identity() {
    let tag = "reuse";
    let dir = std::env::temp_dir().join(format!(
        "odin-brain-archive-reuse-{}-{}",
        tag,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let second_fact = "BETA-CINDER: the cinder vault seals at moonrise";
    let export = serde_json::json!([
        {
            "uuid": format!("conv-{tag}"),
            "name": format!("fixture {tag}"),
            "account": { "uuid": format!("account-{tag}") },
            "created_at": "2026-01-01T00:00:00Z",
            "chat_messages": [
                {
                    "uuid": format!("msg-{tag}"),
                    "sender": "user",
                    "text": ALPHA_FACT,
                    "created_at": "2026-01-02T00:00:00Z"
                },
                {
                    "uuid": format!("msg-{tag}"),
                    "sender": "user",
                    "text": second_fact,
                    "created_at": "2026-01-03T00:00:00Z"
                }
            ]
        }
    ]);
    std::fs::write(
        dir.join("conversations.json"),
        serde_json::to_string(&export).unwrap(),
    )
    .unwrap();

    let source = AtlasId::new(ALPHA_SOURCE).unwrap();
    let declaration = declaration(&dir, "memory.alpha");
    let sources = BTreeMap::from([(source.clone(), archive_source(declaration.clone()))]);
    let service =
        BrainService::open(config(tag, sources), policy(&[ALPHA_SOURCE]), ledger()).unwrap();
    let plan = service.prepare_archive_ingest(&source).unwrap();
    let report = service
        .ingest_archive(&ingest_request(
            &source,
            &declaration,
            plan.content_revision,
            "run-1",
        ))
        .unwrap();
    assert!(!report.resumed);

    // Each fact is cited by the record that declares it on that date: the
    // derived conversation summary also carries the first message's text, so
    // identity — never ranking — selects the record.
    let citation_for = |needle: &str, day: time::Date| {
        let hits = service
            .retrieve(&query(atlas_ids(&[ALPHA_SOURCE]), needle), None, None)
            .unwrap()
            .hits;
        hits.iter()
            .filter(|hit| hit.content.contains(needle))
            .map(|hit| {
                service
                    .archive_citation(
                        &hit.citation.source,
                        &hit.citation.source_revision,
                        &hit.citation.item_id,
                    )
                    .unwrap()
                    .expect("every served hit expands to stored provenance")
            })
            .find(|citation| citation.created_at.map(|at| at.date()) == Some(day))
            .unwrap_or_else(|| panic!("{needle:?} must cite the record dated {day}"))
    };
    let first = citation_for(ALPHA_FACT, time::macros::date!(2026 - 01 - 02));
    let second = citation_for(second_fact, time::macros::date!(2026 - 01 - 03));
    // Same export natural key, different content: distinct items, each
    // expanding to exactly its own record's provenance.
    assert_ne!(
        first.record_key, second.record_key,
        "differing records keep distinct content-addressed identities"
    );
    assert_eq!(
        first.message_id.as_deref(),
        second.message_id.as_deref(),
        "the two records share the export natural key this test defends"
    );
}

/// The declared run ceiling is real: an already-expired deadline stops the
/// run typed before anything is staged or published, and the identical rerun
/// (fresh key, no ceiling) publishes the same approved revision.
#[test]
fn expired_run_ceiling_stops_typed_and_the_rerun_publishes() {
    let tag = "ceiling";
    let export = write_export(tag, ALPHA_FACT);
    let source = AtlasId::new(ALPHA_SOURCE).unwrap();
    let declaration = declaration(&export, "memory.alpha");
    let sources = BTreeMap::from([(source.clone(), archive_source(declaration.clone()))]);
    let service =
        BrainService::open(config(tag, sources), policy(&[ALPHA_SOURCE]), ledger()).unwrap();
    let plan = service.prepare_archive_ingest(&source).unwrap();

    let mut expired = ingest_request(&source, &declaration, plan.content_revision, "run-1");
    expired.deadline = Some(time::OffsetDateTime::now_utc() - time::Duration::seconds(1));
    let error = service
        .ingest_archive(&expired)
        .expect_err("an expired ceiling must stop the run");
    assert!(
        matches!(error, BrainError::Unavailable { .. }),
        "the ceiling refusal is typed, got {error}"
    );
    assert!(
        service.archive_status(&source).unwrap().published.is_none(),
        "nothing publishes under an expired ceiling"
    );

    let report = service
        .ingest_archive(&ingest_request(
            &source,
            &declaration,
            plan.content_revision,
            "run-2",
        ))
        .unwrap();
    assert!(!report.resumed);
    assert_eq!(report.content_revision, plan.content_revision);
}

/// The lexical-only usability promise: under a Hybrid policy, a typed
/// lane unavailability (and a lexical-only archive generation) serves the
/// lexical leg with an explicit reported posture — never silently, and
/// the unserved chunks stay observable as embedding-pending. Vector
/// policy keeps its declared semantics: typed-unavailable, no downgrade.
#[test]
fn hybrid_lane_unavailable_serves_lexical_with_explicit_posture() {
    let tag = "posture";
    let export = write_export(tag, ALPHA_FACT);
    let source = AtlasId::new(ALPHA_SOURCE).unwrap();
    let declaration = declaration(&export, "memory.alpha");
    let sources = BTreeMap::from([(source.clone(), archive_source(declaration.clone()))]);
    // A lane that is typed-unavailable, like the gateway with mini
    // offline. The brain must consume the typed error and keep the
    // archive usable through its lexical leg.
    let lane_down: Arc<odin_brain::retrieval::QueryEmbedder> = Arc::new(|_query| {
        Err(BrainError::EmbeddingUnavailable {
            provider: "fixture-gateway".to_owned(),
            reason: "fixture lane is down".to_owned(),
        })
    });
    let mut config = config(tag, sources);
    config.embedding_available = true;
    config.embedding_model = Some(EmbeddingModelId::new("embedding.posture-test.v1").unwrap());
    let service = BrainService::open(
        config,
        policy_mode(
            &[ALPHA_SOURCE],
            RetrievalMode::Hybrid,
            EmbeddingBackend::Local,
        ),
        ledger(),
    )
    .unwrap();
    let plan = service.prepare_archive_ingest(&source).unwrap();
    service
        .ingest_archive(&ingest_request(
            &source,
            &declaration,
            plan.content_revision,
            "run-1",
        ))
        .unwrap();

    // Hybrid + unavailable lane: lexical leg serves, posture is explicit.
    let response = service
        .retrieve(
            &query(atlas_ids(&[ALPHA_SOURCE]), "onyx hatch"),
            None,
            Some(&lane_down),
        )
        .unwrap();
    assert_fact_serves(&response.hits, ALPHA_FACT);
    match response.posture {
        RetrievalPosture::LexicalOnly { reason } => {
            assert!(
                !reason.is_empty(),
                "posture must report why the vector leg is out"
            );
        }
        RetrievalPosture::Full => panic!("an unavailable lane must be reported, never silent"),
    }
    // The backlog is observable and durable.
    let status = service.archive_status(&source).unwrap();
    assert!(matches!(
        status.published.unwrap().embedding,
        ArchiveEmbeddingView::LexicalOnly { .. }
    ));
}

/// Vector-declared retrieval over an unembedded archive stays
/// typed-unavailable: the lexical fallback is a Hybrid-only declaration,
/// never a broad downgrade.
#[test]
fn vector_policy_archive_stays_typed_unavailable() {
    let tag = "vectorposture";
    let export = write_export(tag, ALPHA_FACT);
    let source = AtlasId::new(ALPHA_SOURCE).unwrap();
    let declaration = declaration(&export, "memory.alpha");
    let sources = BTreeMap::from([(source.clone(), archive_source(declaration.clone()))]);
    let lane_down: Arc<odin_brain::retrieval::QueryEmbedder> = Arc::new(|_query| {
        Err(BrainError::EmbeddingUnavailable {
            provider: "fixture-gateway".to_owned(),
            reason: "fixture lane is down".to_owned(),
        })
    });
    let mut config = config(tag, sources);
    config.embedding_available = true;
    config.embedding_model = Some(EmbeddingModelId::new("embedding.posture-test.v1").unwrap());
    let service = BrainService::open(
        config,
        policy_mode(
            &[ALPHA_SOURCE],
            RetrievalMode::Vector,
            EmbeddingBackend::Local,
        ),
        ledger(),
    )
    .unwrap();
    let plan = service.prepare_archive_ingest(&source).unwrap();
    service
        .ingest_archive(&ingest_request(
            &source,
            &declaration,
            plan.content_revision,
            "run-1",
        ))
        .unwrap();
    let error = service
        .retrieve(
            &query(atlas_ids(&[ALPHA_SOURCE]), "onyx hatch"),
            None,
            Some(&lane_down),
        )
        .unwrap_err();
    assert!(
        matches!(
            error,
            BrainError::EmbeddingUnavailable { .. } | BrainError::Unavailable { .. }
        ),
        "vector-only semantics stay typed-unavailable, got {error}"
    );
}

/// Fixture vocabulary for identity addressing. The needle carries only
/// content the question never quotes; the framing twin carries only the
/// question's own framing words — the exact shape that made a lexically
/// scored turn serve the twin instead of the addressed record.
const ADDRESSED_NEEDLE: &str = "NEEDLE-TIDE: the onyx hatch ledger key is TIDE-4471";
const ADDRESSED_FRAMING: &str = "in the memory of this archive source, in the conversation \
     titled which path did that message contain, answer with the exact path from the message, \
     sent by assistant, name the source it came from, conversation message source answer exact";
const ADDRESSED_CONVERSATION: &str = "addr-one";
const ADDRESSED_MESSAGE: &str = "msg-addr-needle";
/// A second message of the addressed conversation: matching the
/// conversation's own id must not read as an ambiguity, and the sibling's
/// content must never ride along with the addressed record's.
const ADDRESSED_SIBLING: &str = "msg-addr-sibling";
const ADDRESSED_TIMESTAMP: &str = "2026-02-02T02:02:02.000000Z";
/// A message in another conversation carrying the SAME instant as the
/// addressed one: batched exports do this constantly, so a shared instant is
/// never ambiguity.
const ADDRESSED_SAME_INSTANT: &str = "SAME-INSTANT-TIDE: an unrelated message at the same instant";
/// A record larger than the segmentation bound is delivered as ordered parts
/// that share its message id: one logical record, never an ambiguity.
const SEGMENTED_CONVERSATION: &str = "addr-segmented";
const SEGMENTED_MESSAGE: &str = "msg-addr-segmented";
const SEGMENTED_TIMESTAMP: &str = "2026-04-04T04:04:04.000000Z";
const SEGMENTED_HEAD: &str = "SEGMENT-ONE-TIDE";
const SEGMENTED_TAIL: &str = "SEGMENT-TWO-TIDE";

/// Two conversations: one message carries the needle, a second (unrelated)
/// message is saturated with the question's framing vocabulary.
fn write_addressed_export(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "odin-brain-archive-addressed-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let export = serde_json::json!([
        {
            "uuid": ADDRESSED_CONVERSATION,
            "name": "Address fixture one",
            "account": { "uuid": "account-addr" },
            "created_at": "2026-02-01T00:00:00Z",
            "chat_messages": [
                {
                    "uuid": ADDRESSED_MESSAGE,
                    "sender": "assistant",
                    "text": ADDRESSED_NEEDLE,
                    "created_at": ADDRESSED_TIMESTAMP
                },
                {
                    "uuid": ADDRESSED_SIBLING,
                    "sender": "user",
                    "text": "SIBLING-TIDE: the sibling message carries no needle",
                    "created_at": "2026-02-02T03:03:03.000000Z"
                }
            ]
        },
        {
            "uuid": "addr-two",
            "name": "Address fixture two",
            "account": { "uuid": "account-addr" },
            "created_at": "2026-03-01T00:00:00Z",
            "chat_messages": [
                {
                    "uuid": "msg-addr-framing",
                    "sender": "assistant",
                    "text": ADDRESSED_FRAMING,
                    "created_at": "2026-03-03T03:03:03.000000Z"
                },
                {
                    "uuid": "msg-addr-same-instant",
                    "sender": "assistant",
                    "text": ADDRESSED_SAME_INSTANT,
                    "created_at": ADDRESSED_TIMESTAMP
                }
            ]
        },
        {
            "uuid": SEGMENTED_CONVERSATION,
            "name": "Address fixture segmented",
            "account": { "uuid": "account-addr" },
            "created_at": "2026-04-01T00:00:00Z",
            "chat_messages": [
                {
                    "uuid": SEGMENTED_MESSAGE,
                    "sender": "assistant",
                    "text": format!("{SEGMENTED_HEAD} {} {SEGMENTED_TAIL}", "s".repeat(1_100_000)),
                    "created_at": SEGMENTED_TIMESTAMP
                }
            ]
        }
    ]);
    std::fs::write(
        dir.join("conversations.json"),
        serde_json::to_string(&export).unwrap(),
    )
    .unwrap();
    dir
}

/// A query that quotes one record's own identity serves THAT record's
/// content, with its citation provenance intact, and serves no other
/// record — even when another record's text matches the question's framing
/// vocabulary far more closely. A query whose quoted identity contradicts
/// the record (a timestamp that is not its own second) addresses nothing:
/// the ordinary pool stands, and nothing is guessed.
#[test]
fn identity_addressed_query_serves_only_the_addressed_record() {
    let tag = "addressed";
    let export = write_addressed_export(tag);
    let source = AtlasId::new(ALPHA_SOURCE).unwrap();
    let declaration = declaration(&export, "memory.alpha");
    let sources = BTreeMap::from([(source.clone(), archive_source(declaration.clone()))]);
    let service =
        BrainService::open(config(tag, sources), policy(&[ALPHA_SOURCE]), ledger()).unwrap();
    let plan = service.prepare_archive_ingest(&source).unwrap();
    service
        .ingest_archive(&ingest_request(
            &source,
            &declaration,
            plan.content_revision,
            "run-1",
        ))
        .unwrap();

    let addressed = format!(
        "In the memory of this archive source, in the conversation titled \"Address fixture \
         one\" (message {ADDRESSED_MESSAGE} at {ADDRESSED_TIMESTAMP}, sent by assistant), \
         which path did that message contain? Answer with the exact path from the message \
         and name the source it came from."
    );
    let hits = service
        .retrieve(&query(atlas_ids(&[ALPHA_SOURCE]), &addressed), None, None)
        .unwrap()
        .hits;
    assert_fact_serves(&hits, ADDRESSED_NEEDLE);
    // Only the addressed record serves: the framing twin is not in the
    // addressed record's content, and neither is any other record's.
    assert_eq!(
        hit_count(&hits, ADDRESSED_FRAMING),
        0,
        "an addressed turn serves the addressed record, never the record that \
         merely shares its framing vocabulary"
    );
    let needle_citation = hits
        .iter()
        .filter(|hit| hit.content.contains(ADDRESSED_NEEDLE))
        .map(|hit| {
            service
                .archive_citation(
                    &hit.citation.source,
                    &hit.citation.source_revision,
                    &hit.citation.item_id,
                )
                .unwrap()
                .expect("a served hit expands to stored provenance")
        })
        .find(|citation| citation.message_id.as_deref() == Some(ADDRESSED_MESSAGE))
        .expect("the addressed record must cite the exact export message");
    assert_eq!(
        needle_citation.conversation_id.as_deref(),
        Some(ADDRESSED_CONVERSATION)
    );
    assert_eq!(
        needle_citation.created_at,
        Some(
            time::OffsetDateTime::parse(
                ADDRESSED_TIMESTAMP,
                &time::format_description::well_known::Rfc3339
            )
            .unwrap()
        )
    );

    // A conversation literal names the addressed record's own conversation
    // (its other messages match by that id too) and is coherent; a
    // contradicting conversation literal is refused instead of guessed.
    let conversation_addressed = format!(
        "In the memory of this archive source, in the conversation \
         {ADDRESSED_CONVERSATION} (message {ADDRESSED_MESSAGE} at \
         {ADDRESSED_TIMESTAMP}), which path did that message contain?"
    );
    let scoped = service
        .retrieve(
            &query(atlas_ids(&[ALPHA_SOURCE]), &conversation_addressed),
            None,
            None,
        )
        .unwrap()
        .hits;
    assert_fact_serves(&scoped, ADDRESSED_NEEDLE);
    assert_eq!(
        hit_count(&scoped, "SIBLING-TIDE"),
        0,
        "the addressed record's conversation siblings never ride along"
    );
    assert_eq!(hit_count(&scoped, ADDRESSED_FRAMING), 0);

    let contradicted_conversation =
        conversation_addressed.replace(ADDRESSED_CONVERSATION, "addr-two");
    assert!(
        service
            .retrieve(
                &query(atlas_ids(&[ALPHA_SOURCE]), &contradicted_conversation,),
                None,
                None
            )
            .unwrap()
            .hits
            .is_empty(),
        "a conversation the addressed record does not belong to leaves the address \
         unresolved: nothing is served as if it were the record asked for"
    );

    // A timestamp that is not the addressed record's own second is refused
    // the same way, and so is a query whose quoted instant cannot be checked
    // against the record at all.
    for contradicted in [
        addressed.replace(ADDRESSED_TIMESTAMP, "2026-02-02T02:02:03.000000Z"),
        addressed.replace(ADDRESSED_TIMESTAMP, "2026-02-02T02:02:02.500000Z"),
    ] {
        assert!(
            service
                .retrieve(
                    &query(atlas_ids(&[ALPHA_SOURCE]), &contradicted),
                    None,
                    None
                )
                .unwrap()
                .hits
                .is_empty(),
            "an instant the addressed record does not carry leaves the address unresolved"
        );
    }

    // A segmented logical record's parts share one message id: the address
    // resolves to that one record and its parts are all in the served pool,
    // never refused as ambiguity.
    let segmented = format!(
        "{SEGMENTED_TAIL} and {SEGMENTED_HEAD} in message {SEGMENTED_MESSAGE} at \
         {SEGMENTED_TIMESTAMP}"
    );
    let segmented_hits = service
        .retrieve(&query(atlas_ids(&[ALPHA_SOURCE]), &segmented), None, None)
        .unwrap()
        .hits;
    assert!(
        hit_count(&segmented_hits, SEGMENTED_TAIL) >= 1
            && hit_count(&segmented_hits, SEGMENTED_HEAD) >= 1,
        "every part of a segmented addressed record serves"
    );
    assert_eq!(hit_count(&segmented_hits, ADDRESSED_FRAMING), 0);

    // A query that names no record at all stays ordinary: hyphenated prose
    // is a candidate literal that resolves to nothing, never an inference.
    let unaddressed = "Which path did the state-of-the-art onyx hatch fixture mention? \
         Answer with the exact path and name the source it came from.";

    assert!(
        hit_count(
            &service
                .retrieve(&query(atlas_ids(&[ALPHA_SOURCE]), unaddressed), None, None)
                .unwrap()
                .hits,
            ADDRESSED_NEEDLE
        ) >= 1,
        "a query that addresses nothing keeps serving the ordinary pool"
    );
}
/// B5 smoke over the REAL governed path — synthetic stream → store →
/// citation: an attachment's original locator (declaration site +
/// position, no member — the export ships no asset bytes) and the
/// declared export root ride the expanded citation, while locator-less
/// records stay origin-less (the legacy-null read path). Asset bodies
/// are never read: the declared filename is never promoted to a member.
#[test]
fn citation_carries_origin_locator_export_root_and_legacy_nulls() {
    let tag = "origin";
    let dir = write_export(tag, ALPHA_FACT);
    let export_path = dir.join("conversations.json");
    let mut export: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&export_path).unwrap()).unwrap();
    export[0]["chat_messages"][0]["attachments"] = serde_json::json!([
        {"file_name": "origin-proof.md", "file_size": "42", "file_type": "text/markdown"}
    ]);
    std::fs::write(&export_path, serde_json::to_string(&export).unwrap()).unwrap();

    let source = AtlasId::new(ALPHA_SOURCE).unwrap();
    let declaration = declaration(&dir, "memory.alpha");
    let sources = BTreeMap::from([(source.clone(), archive_source(declaration.clone()))]);
    let service =
        BrainService::open(config(tag, sources), policy(&[ALPHA_SOURCE]), ledger()).unwrap();

    let plan = service.prepare_archive_ingest(&source).unwrap();
    let request = ingest_request(&source, &declaration, plan.content_revision, "origin-1");
    service.ingest_archive(&request).unwrap();

    // The asset metadata record serves by its own declared tokens, and
    // its citation carries the locator: declaration site + 1-based
    // position, member=None (bytes not exported), against the exact
    // declared export root read from the persisted declaration.
    let asset_hits = service
        .retrieve(
            &query(atlas_ids(&[ALPHA_SOURCE]), "origin-proof markdown"),
            None,
            None,
        )
        .unwrap()
        .hits;
    let asset_citation = asset_hits
        .iter()
        .map(|hit| {
            service
                .archive_citation(
                    &hit.citation.source,
                    &hit.citation.source_revision,
                    &hit.citation.item_id,
                )
                .unwrap()
                .expect("every served hit expands to stored provenance")
        })
        .find(|citation| {
            citation.kind == odin_brain::source::archive::ArchiveRecordKind::AssetMetadata
        })
        .expect("the attachment metadata record must serve and cite itself");
    let origin = asset_citation
        .origin
        .as_ref()
        .expect("asset records carry their original locator");
    assert_eq!(origin.declared_in.as_deref(), Some("conversations.json"));
    assert_eq!(origin.member, None);
    assert_eq!(origin.asset_id, None);
    assert_eq!(origin.position, Some(1));
    assert_eq!(
        asset_citation.export_root.as_deref(),
        dir.to_str(),
        "the export root is the persisted declaration's exact path"
    );

    // Locator-less records (the fact's message record among them) read
    // back origin-less: old rows and locator-free records keep `None`,
    // and the root never leaks into record text.
    let fact_hits = service
        .retrieve(&query(atlas_ids(&[ALPHA_SOURCE]), "onyx hatch"), None, None)
        .unwrap()
        .hits;
    assert!(hit_count(&fact_hits, ALPHA_FACT) >= 1);
    for hit in &fact_hits {
        let citation = service
            .archive_citation(
                &hit.citation.source,
                &hit.citation.source_revision,
                &hit.citation.item_id,
            )
            .unwrap()
            .expect("every served hit expands to stored provenance");
        assert_eq!(
            citation.export_root.as_deref(),
            dir.to_str(),
            "the declared root is present on every archive citation"
        );
        if citation.kind != odin_brain::source::archive::ArchiveRecordKind::AssetMetadata {
            assert!(
                citation.origin.is_none(),
                "locator-less record {:?} must stay origin-less",
                citation.natural_key
            );
        }
    }
}

/// Format export metadata rides the governed vertical: prepare binds it
/// into the content revision, ingest stages it, a reopened service replays
/// the same approval as the documented zero-row no-op, and item/record
/// reads cite the persisted structured values.
#[test]
fn export_metadata_survives_ingest_reopen_replay_and_citation() {
    let tag = "meta";
    let dir = std::env::temp_dir().join(format!(
        "odin-brain-archive-ingest-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let zip_path = dir.join("export.zip");
    let conversation = serde_json::json!({
        "id": "conv-meta",
        "conversation_id": "conv-meta",
        "title": "Metadata fixture",
        "create_time": 1_788_256_800.0,
        "current_node": "u1",
        "mapping": {
            "root": {"message": null, "parent": null},
            "u1": {
                "message": {
                    "author": {"role": "user", "name": null},
                    "content": {"content_type": "text", "parts": [META_FACT]},
                    "create_time": 1_788_256_801.0,
                    "metadata": {}
                },
                "parent": "root"
            },
        },
    });
    let library = serde_json::json!([{
        "file_id": "file-META",
        "file_name": "meta-artifact.png",
        "file_size_bytes": 7,
        "initiating_conversation_id": "conv-meta"
    }]);
    {
        let mut zip = zip::ZipWriter::new(std::fs::File::create(&zip_path).unwrap());
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, value) in [
            ("conversations-000.json", serde_json::json!([conversation])),
            ("library_files.json", library),
        ] {
            zip.start_file(name, options).unwrap();
            zip.write_all(serde_json::to_vec(&value).unwrap().as_slice())
                .unwrap();
        }
        zip.finish().unwrap();
    }
    let source = AtlasId::new(META_SOURCE).unwrap();
    let declaration = ArchiveSourceDeclaration {
        format: ArchiveFormat::ChatGptExport,
        path: zip_path,
        memory_namespace: "memory.meta".to_owned(),
        privacy_class: ArchivePrivacyClass::Private,
        dedupe_key: ArchiveDedupeKey::ContentDigest,
        selection: ArchiveSelectionPolicy {
            since: None,
            exclude_labels: Vec::new(),
            exclude_if_header: Vec::new(),
            keep_if_participant: false,
            participant_emails: Vec::new(),
            suspicious_rules: Vec::new(),
            exclude_do_not_remember: None,
        },
    };
    let sources = BTreeMap::from([(source.clone(), archive_source(declaration.clone()))]);
    let service_config = |store_root: std::path::PathBuf| BrainServiceConfig {
        store_root,
        sources: sources.clone(),
        embedding_available: false,
        embedding_model: None,
        archive_ingest_gate: test_gate(),
        postgres: None,
    };
    let store_root = dir.join("state");
    let service = BrainService::open(
        service_config(store_root.clone()),
        policy(&[META_SOURCE]),
        ledger(),
    )
    .unwrap();
    let plan = service.prepare_archive_ingest(&source).unwrap();
    let request = ingest_request(&source, &declaration, plan.content_revision, "meta-1");
    service.ingest_archive(&request).unwrap();
    assert_eq!(
        service
            .prepare_archive_ingest(&source)
            .unwrap()
            .content_revision,
        plan.content_revision,
        "a fresh prepare over unchanged content recomputes the approved revision"
    );

    let reopened =
        BrainService::open(service_config(store_root), policy(&[META_SOURCE]), ledger()).unwrap();
    let replay = reopened.ingest_archive(&request).unwrap();
    assert!(
        replay.resumed,
        "unchanged re-ingest is the documented no-op"
    );
    assert_eq!(replay.records_staged, 0);
    let mut message_citation = None;
    let mut library_citation = None;
    for text in ["META-ONYX hatch", "uploaded asset meta-artifact"] {
        let hits = reopened
            .retrieve(&query(atlas_ids(&[META_SOURCE]), text), None, None)
            .unwrap()
            .hits;
        for hit in &hits {
            let citation = reopened
                .archive_citation(
                    &hit.citation.source,
                    &hit.citation.source_revision,
                    &hit.citation.item_id,
                )
                .unwrap()
                .expect("every served hit expands to stored provenance");
            match citation.natural_key.as_str() {
                "conv-meta:u1" => message_citation = Some(citation),
                "library:file-META" => library_citation = Some(citation),
                _ => {}
            }
        }
    }
    let message = message_citation.expect("the message must cite");
    assert_eq!(
        message.export_metadata["node_id"],
        serde_json::Value::from("u1")
    );
    assert_eq!(
        message.export_metadata["parent_node"],
        serde_json::Value::from("root")
    );
    let record = reopened
        .knowledge_record(&message.record_key, None)
        .unwrap();
    assert_eq!(record.item.chunks[0].text, META_FACT);
    assert_eq!(
        record
            .item
            .archive
            .as_ref()
            .map(|archive| archive.record_key),
        Some(message.record_key),
        "the record read cites the same stored record"
    );
    let library = library_citation.expect("the library record must cite");
    assert_eq!(
        library.export_metadata["library_file_id"],
        serde_json::Value::from("file-META")
    );
}

/// Large generations serve lexically until background warming completes their vector pools.
#[test]
fn a_large_new_generation_serves_lexically_while_the_warm_fills_it() {
    const SOURCE: &str = "atlas.warm";
    let root = std::env::temp_dir().join(format!("odin-brain-warm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let src = root.join("crates").join("warm_demo").join("src");
    std::fs::create_dir_all(&src).unwrap();
    for dir in ["extension", "registry", "skeletons"] {
        std::fs::create_dir_all(root.join(dir)).unwrap();
    }
    let mut lib = String::from("//! Warm fixture.\n");
    for index in 0..120 {
        lib.push_str(&format!(
            "\n/// Function {index} computes the {index}th quartz lantern value; {}\npub fn quartz_{index}(v: u64) -> u64 {{ v + {index} }}\n",
            "it documents lantern behaviour in detail. ".repeat(12)
        ));
    }
    std::fs::write(src.join("lib.rs"), lib).unwrap();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let embedder: Arc<odin_brain::retrieval::QueryEmbedder> = Arc::new(move |texts| {
        counted.fetch_add(texts.len(), std::sync::atomic::Ordering::SeqCst);
        texts
            .iter()
            .map(|text| {
                let seed = Digest::hash(text.as_bytes());
                EmbeddingVector::from_dims(
                    seed.as_bytes()[..8]
                        .iter()
                        .map(|b| f32::from(*b) + 1.0)
                        .collect(),
                )
            })
            .collect()
    });
    let mut config = config(
        "warm",
        BTreeMap::from([(
            AtlasId::new(SOURCE).unwrap(),
            BrainSourceConfig::Atlas { root: root.clone() },
        )]),
    );
    config.embedding_available = true;
    config.embedding_model = Some(EmbeddingModelId::new("embedding.warm-test.v1").unwrap());
    let service = BrainService::open(
        config,
        policy_mode(&[SOURCE], RetrievalMode::Hybrid, EmbeddingBackend::Local),
        ledger(),
    )
    .unwrap();

    let first = service
        .retrieve(
            &query(atlas_ids(&[SOURCE]), "quartz lantern"),
            None,
            Some(&embedder),
        )
        .unwrap();
    assert!(
        matches!(&first.posture, RetrievalPosture::LexicalOnly { reason } if reason.contains("being embedded")),
        "an oversized new generation serves lexically with an explicit posture: {:?}",
        first.posture
    );
    assert!(!first.hits.is_empty(), "the lexical leg serves");
    assert!(
        calls.load(std::sync::atomic::Ordering::SeqCst) <= 32,
        "inline embedding stays bounded"
    );

    assert_eq!(service.warm_vectors(embedder.as_ref(), 100_000).unwrap(), 0);
    let second = service
        .retrieve(
            &query(atlas_ids(&[SOURCE]), "quartz lantern"),
            None,
            Some(&embedder),
        )
        .unwrap();
    assert_eq!(
        second.posture,
        RetrievalPosture::Full,
        "the warmed pool serves the full plan"
    );
}
