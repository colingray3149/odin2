//! Relevant mail must outrank chat records and fit the first compiled bundle.
//! Fixtures use synthetic data in per-test temporary directories.

use std::collections::{BTreeMap, BTreeSet};
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::sync::{Arc, Mutex};

use odin_brain::config::EffectiveBrainPolicy;
use odin_brain::error::BrainError;
use odin_brain::service::{
    archive_declaration_digest, ArchiveIngestAuthority, ArchiveIngestGate, ArchiveIngestRequest,
    BrainService, BrainServiceConfig, BrainSourceConfig,
};
use odin_domain::huginn::ids::ModelName;
use odin_domain::knowledge::archive::{
    ArchiveDedupeKey, ArchiveFormat, ArchivePrivacyClass, ArchiveSelectionPolicy,
    ArchiveSourceDeclaration,
};
use odin_domain::knowledge::ids::{AtlasId, RelevanceScore, TokenizerId};
use odin_domain::knowledge::retrieval::{ModelDescriptor, RetrievalQuery};
use odin_domain::knowledge::{EmbeddingBackend, RetrievalMode, TrustClass};
use odin_domain::{Digest, ProjectId};
use odin_ledger::Ledger;
use odin_registry::schema::{
    AccountingWindowToml, ApprovalDefaultToml, ApprovalDefaultsToml, BudgetPolicyToml, ProjectToml,
    RegistryKind, SeatContextToml, SeatKnowledgeToml, SeatLimitsToml, SeatToml, SliceContextToml,
    SliceKnowledgeToml, SliceRedirectsToml, SliceToml, REGISTRY_SCHEMA,
};

const MAIL_SOURCE: &str = "archive:mail";
const CHAT_SOURCE: &str = "archive:chat";

/// Sender and refund window expected from the mail source.
const REPLY_SENDER: &str = "Priya Nair";
const REPLY_FACT: &str = "4-6 business days";
const REPLY_SUBJECT: &str = "Widget Refund Request";

/// Ask without identifiers or answer wording to exercise natural-language retrieval.
const NATURAL_QUESTION: &str = "In the email thread where I asked for a refund on my unused \
widget order, the support reply confirmed the refund was submitted. According to that reply, \
who sent the confirmation and how long should the refund take to appear in my account?";

fn nz16(value: u16) -> NonZeroU16 {
    NonZeroU16::new(value).unwrap()
}

fn nz32(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).unwrap()
}

fn atlas_ids(values: &[&str]) -> BTreeSet<AtlasId> {
    values.iter().map(|v| AtlasId::new(*v).unwrap()).collect()
}

fn selection() -> ArchiveSelectionPolicy {
    ArchiveSelectionPolicy {
        since: None,
        exclude_labels: Vec::new(),
        exclude_if_header: Vec::new(),
        keep_if_participant: false,
        participant_emails: Vec::new(),
        suspicious_rules: Vec::new(),
        exclude_do_not_remember: None,
    }
}

fn mbox_declaration(path: &std::path::Path) -> ArchiveSourceDeclaration {
    ArchiveSourceDeclaration {
        format: ArchiveFormat::Mbox,
        path: path.to_path_buf(),
        memory_namespace: "memory.mail".to_owned(),
        privacy_class: ArchivePrivacyClass::Private,
        dedupe_key: ArchiveDedupeKey::ContentDigest,
        selection: selection(),
    }
}

fn chat_declaration(path: &std::path::Path) -> ArchiveSourceDeclaration {
    ArchiveSourceDeclaration {
        format: ArchiveFormat::ClaudeExport,
        path: path.to_path_buf(),
        memory_namespace: "memory.chat".to_owned(),
        privacy_class: ArchivePrivacyClass::Private,
        dedupe_key: ArchiveDedupeKey::ContentDigest,
        selection: selection(),
    }
}

/// The synthetic mail thread: the operator's refund request and the support
/// reply carrying the answer. Separators follow the mbox convention (a
/// blank line before every `From ` separator line); bodies never begin with
/// an unescaped `From `.
const MAIL_FIXTURE: &str = "\
From rowan@example.net Mon Sep  1 09:00:00 2026
Message-ID: <m1@fixture>
Date: Mon, 01 Sep 2026 09:00:00 +0000
From: Rowan <rowan@example.net>
To: support@example.org
Subject: Widget Refund Request
X-Gmail-Labels: Sent

Hello support,

Could I get a refund on my widget order? I never opened the box, I did not
mean to place the order, and I already picked one up in person last week.

Order FIX-1001

Thanks,
Rowan

From support@example.org Mon Sep  1 10:30:00 2026
Message-ID: <m2@fixture>
Date: Mon, 01 Sep 2026 10:30:00 +0000
From: Priya Nair <priya.nair@example.org>
To: rowan@example.net
Subject: Re: Widget Refund Request
In-Reply-To: <m1@fixture>
References: <m1@fixture>
X-Gmail-Labels: Inbox

Hi Rowan,

Your refund confirmation has been successfully submitted and should appear
in your account within 4-6 business days, depending on your bank.

Priya Nair
Widget Support

";

/// The chat corpus competes hard on the question's framing vocabulary: one
/// conversation discusses the same refund situation (so it shares terms
/// like refund/order/account/support) but never names the sender or the
/// window, and one conversation is unrelated mass.
fn write_chat_export(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "odin-brain-mail-retrieval-chat-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let export = serde_json::json!([
        {
            "uuid": format!("conv-{tag}-refund"),
            "name": format!("refund advice {tag}"),
            "account": { "uuid": format!("account-{tag}") },
            "created_at": "2026-09-01T12:00:00Z",
            "chat_messages": [
                {
                    "uuid": format!("msg-{tag}-refund-q"),
                    "sender": "user",
                    "text": "I bought a widget order by mistake and requested a refund \
                             through the store's support portal. They said my request is \
                             in review. What is the typical resolution time, and will they \
                             email me a receipt when the money shows up?",
                    "created_at": "2026-09-01T12:00:00Z"
                },
                {
                    "uuid": format!("msg-{tag}-refund-a"),
                    "sender": "assistant",
                    "text": "Merchant refunds on mistaken orders usually settle in one or \
                             two billing cycles once approved. Monitor your account \
                             statement and the store's support thread, and keep the order \
                             receipt until the money shows up.",
                    "created_at": "2026-09-01T12:01:00Z"
                }
            ]
        },
        {
            "uuid": format!("conv-{tag}-trail"),
            "name": format!("weekend trail notes {tag}"),
            "account": { "uuid": format!("account-{tag}") },
            "created_at": "2026-08-20T09:00:00Z",
            "chat_messages": [
                {
                    "uuid": format!("msg-{tag}-trail"),
                    "sender": "user",
                    "text": "Weekend plan: check the weather, pack water, and leave early so the \
                             trailhead parking is not full when we arrive at the ranger station.",
                    "created_at": "2026-08-20T09:00:00Z"
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

fn write_mail_fixture(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "odin-brain-mail-retrieval-mail-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("thread.mbox"), MAIL_FIXTURE).unwrap();
    dir.join("thread.mbox")
}

fn slice_mode(sources: &[&str]) -> SliceToml {
    SliceToml {
        schema: REGISTRY_SCHEMA.to_owned(),
        kind: RegistryKind::Slice,
        enabled: true,
        description: "mail retrieval fixture slice".to_owned(),
        capabilities: BTreeSet::new(),
        variables: BTreeMap::new(),
        redirects: SliceRedirectsToml {
            out_of_scope: "NeedsPlan".to_owned(),
        },
        knowledge: Some(SliceKnowledgeToml {
            required: false,
            atlas_sources: atlas_ids(sources),
            retrieval_mode: RetrievalMode::Lexical,
            candidate_limit: nz16(64),
            top_k: nz16(8),
            min_score_micros: 0,
            chunk_tokens: nz32(512),
            chunk_overlap_tokens: 64,
            embedding_backend: EmbeddingBackend::Disabled,
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
        description: "mail retrieval fixture seat".to_owned(),
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
        name: ModelName::new("model.mail").unwrap(),
        tokenizer: TokenizerId::new("odin.tokenizer.utf8-bytes.v1").unwrap(),
        context_window_tokens: nz32(8192),
    }
}

fn policy(sources: &[&str]) -> EffectiveBrainPolicy {
    EffectiveBrainPolicy::resolve(
        76,
        &slice_mode(sources),
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
        "odin-brain-mail-retrieval-store-{tag}-{}",
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

struct TestGate;

impl ArchiveIngestGate for TestGate {
    fn verify(
        &self,
        authority: &ArchiveIngestAuthority,
        source: &AtlasId,
        _idempotency_key: &str,
    ) -> Result<(), BrainError> {
        if source.as_str().is_empty() {
            return Err(BrainError::InvalidRequest("empty source".to_owned()));
        }
        if authority.approval_id.ends_with("denied") {
            return Err(BrainError::Unavailable {
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

/// Ingests the synthetic mail thread and chat corpus into one service and
/// returns it with both sources published.
fn service_with_mail_and_chat(tag: &str) -> BrainService {
    let mail_path = write_mail_fixture(tag);
    let chat_dir = write_chat_export(tag);
    let mail = AtlasId::new(MAIL_SOURCE).unwrap();
    let chat = AtlasId::new(CHAT_SOURCE).unwrap();
    let mail_declaration = mbox_declaration(&mail_path);
    let chat_declaration = chat_declaration(&chat_dir);
    let sources = BTreeMap::from([
        (
            mail.clone(),
            BrainSourceConfig::Archive {
                declaration: mail_declaration.clone(),
            },
        ),
        (
            chat.clone(),
            BrainSourceConfig::Archive {
                declaration: chat_declaration.clone(),
            },
        ),
    ]);
    let service = BrainService::open(
        config(tag, sources),
        policy(&[MAIL_SOURCE, CHAT_SOURCE]),
        ledger(),
    )
    .unwrap();
    for (source, declaration, key) in [
        (&mail, &mail_declaration, "mail"),
        (&chat, &chat_declaration, "chat"),
    ] {
        let plan = service.prepare_archive_ingest(source).unwrap();
        let report = service
            .ingest_archive(&ingest_request(
                source,
                declaration,
                plan.content_revision,
                key,
            ))
            .unwrap();
        assert!(report.records_staged > 0, "fixture source must stage");
    }
    service
}

/// Subject-indexed: a question about the mail's subject topic finds the
/// record through its `Subject:` header line.
#[test]
fn mail_subject_terms_retrieve_the_record() {
    let service = service_with_mail_and_chat("subject");
    let hits = service
        .retrieve(
            &query(
                atlas_ids(&[MAIL_SOURCE, CHAT_SOURCE]),
                "what did the Widget Refund Request email say about my order?",
            ),
            None,
            None,
        )
        .unwrap()
        .hits;
    let mail_hit = hits
        .iter()
        .find(|hit| hit.source.as_str() == MAIL_SOURCE)
        .unwrap_or_else(|| panic!("the subject question must reach the mail record: {hits:?}"));
    assert!(
        mail_hit.content.contains(REPLY_SUBJECT),
        "the mail hit must carry the subject header, got: {}",
        mail_hit.content
    );
}

/// Sender-indexed: a question naming the support sender finds the record
/// through its `From:` header line.
#[test]
fn mail_sender_terms_retrieve_the_record() {
    let service = service_with_mail_and_chat("sender");
    let hits = service
        .retrieve(
            &query(
                atlas_ids(&[MAIL_SOURCE, CHAT_SOURCE]),
                "when did Priya Nair confirm my refund by email?",
            ),
            None,
            None,
        )
        .unwrap()
        .hits;
    let mail_hit = hits
        .iter()
        .find(|hit| hit.source.as_str() == MAIL_SOURCE)
        .unwrap_or_else(|| panic!("the sender question must reach the mail record: {hits:?}"));
    assert!(
        mail_hit.content.contains(REPLY_SENDER),
        "the mail hit must carry the sender header, got: {}",
        mail_hit.content
    );
}

/// The record-selector read path (`brain://record.blake3:<hex>`): the
/// published record's content-addressed key resolves to its item through
/// the same pinned-generation serving path as item reads, with the item id
/// taken from the record row — never inferred from chunk content. Unknown
/// keys are a typed miss for exactly the record asked for.
#[test]
fn knowledge_record_resolves_by_key_and_misses_unknown_keys() {
    let service = service_with_mail_and_chat("record");
    let hits = service
        .retrieve(
            &query(atlas_ids(&[MAIL_SOURCE, CHAT_SOURCE]), NATURAL_QUESTION),
            None,
            None,
        )
        .unwrap()
        .hits;
    let mail_hit = hits
        .iter()
        .find(|hit| hit.source.as_str() == MAIL_SOURCE && hit.content.contains(REPLY_FACT))
        .expect("the reply record carrying the fact must serve");
    let citation = service
        .archive_citation(
            &mail_hit.citation.source,
            &mail_hit.citation.source_revision,
            &mail_hit.citation.item_id,
        )
        .unwrap()
        .expect("a served archive hit expands to stored provenance");

    let record = service
        .knowledge_record(&citation.record_key, None)
        .unwrap_or_else(|error| panic!("record key must resolve: {error}"));
    assert_eq!(
        record.item_id, mail_hit.item_id,
        "the record row's own item identity is the served item"
    );
    assert!(
        record
            .item
            .chunks
            .iter()
            .any(|chunk| chunk.text.contains(REPLY_SENDER)),
        "the served item must carry the record's content"
    );
    assert!(
        record.item.archive.is_some(),
        "an archive record's item carries its structured citation"
    );

    let unknown = service
        .knowledge_record(&Digest::hash(b"no-such-record"), None)
        .unwrap_err();
    assert!(
        matches!(unknown, BrainError::NotFound { kind, .. } if kind == "knowledge record"),
        "unknown record key must miss typed, got {unknown}"
    );

    // The same record resolves under a bound project whose declared memory
    // includes this corpus's general knowledge scope.
    let project = ProjectId::new("project.mail-fixture").unwrap();
    let scoped = service.knowledge_record(&citation.record_key, Some(&project));
    assert!(
        scoped.is_ok(),
        "the record must resolve under a bound project: {scoped:?}"
    );
}
