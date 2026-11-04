//! Governed archive ingest end to end: approval-bound ingest, content-
//! addressed idempotence, durable resume, namespace isolation, citation
//! provenance, and the lexical-only/backfill embedding posture — all over
//! the public `BrainService` API and tiny synthetic Claude exports written
//! to per-test temporary directories (raw export data never enters the
//! repo).

use std::collections::BTreeMap;
use std::sync::Arc;

use odin_brain::config::EffectiveBrainPolicy;
use odin_brain::error::{BrainError, BrainResult};
use odin_brain::index::postgres::EMBEDDING_DIMS;
use odin_brain::retrieval::embedding::EmbeddingVector;
use odin_brain::service::{
    ArchiveBackfillOutcome, ArchiveEmbeddingBackfillRequest, ArchiveEmbeddingView, BrainService,
    BrainSourceConfig, EmbeddingBatchLane, RetrievalPosture,
};
use odin_brain::test_cluster::TestCluster;
use odin_domain::huginn::ids::ModelName;
use odin_domain::knowledge::archive::{
    ArchiveDedupeKey, ArchiveFormat, ArchivePrivacyClass, ArchiveSourceDeclaration,
};
use odin_domain::knowledge::ids::{AtlasId, EmbeddingModelId, TokenizerId};
use odin_domain::knowledge::retrieval::ModelDescriptor;
use odin_domain::knowledge::{EmbeddingBackend, RetrievalMode};
use odin_domain::Digest;
use odin_registry::schema::ProjectToml;

use crate::support::{
    atlas_ids, config_with, ingest_request, ledger, nz32, query, seat, selection, slice, test_gate,
};

const ALPHA_SOURCE: &str = "archive:alpha";
const BETA_SOURCE: &str = "archive:beta";
const ALPHA_FACT: &str = "ALPHA-ONYX: the onyx hatch opens only at low tide";
const BETA_FACT: &str = "BETA-CINDER: the cinder vault seals at moonrise";
fn declaration(path: &std::path::Path, namespace: &str) -> ArchiveSourceDeclaration {
    ArchiveSourceDeclaration {
        format: ArchiveFormat::ClaudeExport,
        path: path.to_path_buf(),
        memory_namespace: namespace.to_owned(),
        privacy_class: ArchivePrivacyClass::Private,
        dedupe_key: ArchiveDedupeKey::ContentDigest,
        selection: selection(),
    }
}

/// One Claude export of one conversation holding one message `fact`; synthetic
/// exports stay in temporary directories, never the repository.
fn write_export(tag: &str, fact: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    replace_fact(tag, dir.path(), fact);
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
        &slice(sources, mode, backend),
        &seat(sources, &[]),
        &BTreeMap::<&str, &ProjectToml>::new(),
        &std::collections::BTreeMap::from([(
            "sized",
            &odin_registry::ContextProfileToml::sized(nz32(2048), nz32(2048)),
        )]),
        &model(),
    )
    .unwrap()
}

fn archive_source(declaration: ArchiveSourceDeclaration) -> BrainSourceConfig {
    BrainSourceConfig::Archive { declaration }
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
    let declaration = declaration(export.path(), "memory.alpha");
    let sources = BTreeMap::from([(source.clone(), archive_source(declaration.clone()))]);
    let (_store, cfg) = config_with(sources, test_gate());
    let service = BrainService::open(cfg, policy(&[ALPHA_SOURCE]), ledger()).unwrap();

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
        ArchiveEmbeddingView::LexicalOnly { pending_chunks } => {
            assert_eq!(pending_chunks, report.chunks);
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
    let declaration = declaration(export.path(), "memory.alpha");
    let sources = BTreeMap::from([(source.clone(), archive_source(declaration.clone()))]);
    let (_store, cfg) = config_with(sources, test_gate());
    let service = BrainService::open(cfg, policy(&[ALPHA_SOURCE]), ledger()).unwrap();

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
    let declaration = declaration(export.path(), "memory.alpha");
    let sources = BTreeMap::from([(source.clone(), archive_source(declaration.clone()))]);
    let (_store, cfg) = config_with(sources, test_gate());
    let service = BrainService::open(cfg, policy(&[ALPHA_SOURCE]), ledger()).unwrap();

    let plan = service.prepare_archive_ingest(&source).unwrap();
    // One byte changes under the same conversation and message UUIDs.
    replace_fact(tag, export.path(), &format!("{ALPHA_FACT} (edited)"));
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
    let alpha_decl = declaration(alpha_export.path(), "memory.alpha");
    let beta_decl = declaration(beta_export.path(), "memory.beta");
    let sources = BTreeMap::from([
        (alpha.clone(), archive_source(alpha_decl.clone())),
        (beta.clone(), archive_source(beta_decl.clone())),
    ]);
    let (_store, cfg) = config_with(sources, test_gate());
    let service = BrainService::open(cfg, policy(&[ALPHA_SOURCE, BETA_SOURCE]), ledger()).unwrap();

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
}

impl FakeLane {
    fn working(dims: usize) -> Self {
        Self {
            dims,
            unavailable: false,
        }
    }

    fn unavailable() -> Self {
        Self {
            dims: 4,
            unavailable: true,
        }
    }
}

impl EmbeddingBatchLane for FakeLane {
    fn embed_batch(&mut self, texts: &[String]) -> BrainResult<Vec<EmbeddingVector>> {
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

/// A keyword-only publication restamps under the declared model at its
/// first backfill and embeds in place: an unavailable lane leaves the rest
/// pending, a working one finishes it, and the fact still serves.
#[test]
fn backfill_restamps_a_keyword_only_publication_and_embeds_in_place() {
    let cluster = TestCluster::start();
    let tag = "backfill";
    let export = write_export(tag, ALPHA_FACT);
    let source = AtlasId::new(ALPHA_SOURCE).unwrap();
    let declaration = declaration(export.path(), "memory.alpha");
    let sources = BTreeMap::from([(source.clone(), archive_source(declaration.clone()))]);
    let (_store, mut cfg) = config_with(sources, test_gate());
    cfg.postgres = cluster.store();
    let service = BrainService::open(cfg, policy(&[ALPHA_SOURCE]), ledger()).unwrap();
    let plan = service.prepare_archive_ingest(&source).unwrap();
    let report = service
        .ingest_archive(&ingest_request(
            &source,
            &declaration,
            plan.content_revision,
            "run-1",
        ))
        .unwrap();
    match service
        .archive_status(&source)
        .unwrap()
        .published
        .unwrap()
        .embedding
    {
        ArchiveEmbeddingView::LexicalOnly { pending_chunks } => {
            assert_eq!(pending_chunks, report.chunks)
        }
        ArchiveEmbeddingView::Embedded { .. } => panic!("no model is declared at ingest"),
    }
    let model = EmbeddingModelId::new("embedding.archive-test.v1").unwrap();
    let request = |batch_size| ArchiveEmbeddingBackfillRequest {
        source: source.clone(),
        embedding_model: model.clone(),
        batch_size,
        max_batches: None,
        until: None,
    };

    let mut down = FakeLane::unavailable();
    let blocked = service
        .backfill_archive_embeddings(&request(1), &mut down)
        .unwrap();
    match blocked.outcome {
        ArchiveBackfillOutcome::Pending { reason, pending } => {
            assert!(reason.contains("down"), "{reason}");
            assert_eq!(pending, report.chunks);
        }
        ArchiveBackfillOutcome::Embedded => panic!("an unavailable lane must not embed"),
    }
    match service
        .archive_status(&source)
        .unwrap()
        .published
        .unwrap()
        .embedding
    {
        ArchiveEmbeddingView::Embedded {
            model: bound,
            pending_chunks,
        } => {
            assert_eq!(bound, model);
            assert_eq!(pending_chunks, report.chunks);
        }
        ArchiveEmbeddingView::LexicalOnly { .. } => panic!("the backfill restamps first"),
    }

    let mut lane = FakeLane::working(EMBEDDING_DIMS);
    let done = service
        .backfill_archive_embeddings(&request(8), &mut lane)
        .unwrap();
    assert_eq!(done.outcome, ArchiveBackfillOutcome::Embedded);
    assert_eq!(done.vectors_embedded, report.chunks);
    match service
        .archive_status(&source)
        .unwrap()
        .published
        .unwrap()
        .embedding
    {
        ArchiveEmbeddingView::Embedded { pending_chunks, .. } => assert_eq!(pending_chunks, 0),
        ArchiveEmbeddingView::LexicalOnly { .. } => panic!("the backfill restamps first"),
    }
    let hits = service
        .retrieve(&query(atlas_ids(&[ALPHA_SOURCE]), "onyx hatch"), None, None)
        .unwrap()
        .hits;
    assert_fact_serves(&hits, ALPHA_FACT);
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
    let declaration = declaration(export.path(), "memory.alpha");
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
    let (_store, mut config) = config_with(sources, test_gate());
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
        ArchiveEmbeddingView::Embedded { pending_chunks, .. } if pending_chunks > 0
    ));
}
