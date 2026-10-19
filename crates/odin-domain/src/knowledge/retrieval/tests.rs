//! Invariant tests for the knowledge retrieval vocabulary.

use super::*;

use crate::knowledge::ids::{AtlasId, KnowledgeFactId, KnowledgeItemId, RelevanceScore};
use crate::Digest;
use odin_types::CapsuleId;

fn digest(value: &str) -> Digest {
    Digest::hash(value.as_bytes())
}

fn fact_id(value: &str) -> KnowledgeFactId {
    KnowledgeFactId::parse(value).expect("canonical fact ID")
}

fn capsule(value: &str) -> CapsuleId {
    CapsuleId::new(value).expect("canonical capsule ID")
}

fn parent(capsule_id: CapsuleId, fact_id: KnowledgeFactId) -> KnowledgeLineageParent {
    KnowledgeLineageParent::new(
        fact_id,
        capsule_id,
        digest("parent-revision"),
        digest("parent-content"),
    )
}

fn lineage(
    capsule_id: CapsuleId,
    completeness: KnowledgeLineageCompleteness,
    as_of_revision: Digest,
) -> KnowledgeLineage {
    KnowledgeLineage::new(
        capsule_id.clone(),
        vec![parent(
            capsule_id,
            fact_id("b14d975b-6234-4ceb-8ee2-d7c404cd3ff8"),
        )],
        completeness,
        KnowledgeFreshness::new(as_of_revision),
    )
    .expect("structurally valid lineage")
}

fn fact_with_tombstone(
    tombstone: Option<KnowledgeTombstone>,
    revision: Digest,
    origin: KnowledgeOrigin,
) -> KnowledgeFact {
    KnowledgeFact::new(
        fact_id("8f9c2ee3-85ec-46e9-a43a-a2cd6048c1e9"),
        KnowledgeItemId::new(digest("immutable-item")),
        capsule("capsule.fact"),
        revision,
        "canonical fact",
        digest("canonical fact"),
        origin,
        Some(lineage(
            capsule("capsule.fact"),
            KnowledgeLineageCompleteness::Complete,
            digest("atlas-head"),
        )),
        None,
        tombstone,
    )
    .expect("valid fact")
}

#[test]
fn knowledge_lineage_rejects_missing_stale_partial_and_cross_capsule() {
    let capsule_id = capsule("capsule.fact");
    let fresh = lineage(
        capsule_id.clone(),
        KnowledgeLineageCompleteness::Complete,
        digest("atlas-head"),
    );
    assert!(
        KnowledgeLineage::require_fresh(Some(&fresh), &capsule_id, digest("atlas-head")).is_ok()
    );
    assert!(KnowledgeLineage::require_fresh(None, &capsule_id, digest("atlas-head")).is_err());

    let partial = lineage(
        capsule_id.clone(),
        KnowledgeLineageCompleteness::Partial,
        digest("atlas-head"),
    );
    assert!(
        KnowledgeLineage::require_fresh(Some(&partial), &capsule_id, digest("atlas-head")).is_err()
    );
    assert!(
        KnowledgeLineage::require_fresh(Some(&fresh), &capsule_id, digest("newer-atlas-head"))
            .is_err()
    );
    assert!(KnowledgeLineage::require_fresh(
        Some(&fresh),
        &capsule("capsule.other"),
        digest("atlas-head")
    )
    .is_err());

    assert!(
        KnowledgeLineage::new(
            capsule_id,
            vec![parent(
                capsule("capsule.other"),
                fact_id("b14d975b-6234-4ceb-8ee2-d7c404cd3ff8"),
            )],
            KnowledgeLineageCompleteness::Complete,
            KnowledgeFreshness::new(digest("atlas-head")),
        )
        .is_err(),
        "a parent from another capsule must reject before publication"
    );
}

#[test]
fn knowledge_lineage_rejects_duplicate_self_and_unknown_parent_projection() {
    let capsule_id = capsule("capsule.fact");
    let parent_id = fact_id("b14d975b-6234-4ceb-8ee2-d7c404cd3ff8");
    assert!(
        KnowledgeLineage::new(
            capsule_id.clone(),
            vec![
                parent(capsule_id.clone(), parent_id),
                KnowledgeLineageParent::new(
                    parent_id,
                    capsule_id.clone(),
                    digest("different-parent-revision"),
                    digest("different-parent-content"),
                ),
            ],
            KnowledgeLineageCompleteness::Complete,
            KnowledgeFreshness::new(digest("atlas-head")),
        )
        .is_err(),
        "a parent fact ID may appear only once"
    );
    let ordered = KnowledgeLineage::new(
        capsule_id.clone(),
        vec![
            parent(
                capsule_id.clone(),
                fact_id("b14d975b-6234-4ceb-8ee2-d7c404cd3ff8"),
            ),
            parent(
                capsule_id.clone(),
                fact_id("11111111-1111-4111-8111-111111111111"),
            ),
        ],
        KnowledgeLineageCompleteness::Complete,
        KnowledgeFreshness::new(digest("atlas-head")),
    )
    .expect("constructor canonicalizes parent order");
    let mut out_of_order = serde_json::to_value(ordered).expect("serialize lineage");
    out_of_order["parents"]
        .as_array_mut()
        .expect("parent array")
        .reverse();
    assert!(serde_json::from_value::<KnowledgeLineage>(out_of_order).is_err());

    let self_id = fact_id("8f9c2ee3-85ec-46e9-a43a-a2cd6048c1e9");
    let self_lineage = KnowledgeLineage::new(
        capsule_id.clone(),
        vec![parent(capsule_id.clone(), self_id)],
        KnowledgeLineageCompleteness::Complete,
        KnowledgeFreshness::new(digest("atlas-head")),
    )
    .expect("lineage is structurally ordered");
    let origin = KnowledgeOrigin::new(
        KnowledgeOriginKind::OwnerExplicit,
        digest("fact-revision"),
        digest("canonical fact"),
    );
    assert!(
        KnowledgeFact::new(
            self_id,
            KnowledgeItemId::new(digest("immutable-item")),
            capsule_id,
            digest("fact-revision"),
            "canonical fact",
            digest("canonical fact"),
            origin,
            Some(self_lineage),
            None,
            None,
        )
        .is_err(),
        "a fact cannot be its own parent"
    );

    let mut unknown = serde_json::to_value(lineage(
        capsule("capsule.fact"),
        KnowledgeLineageCompleteness::Complete,
        digest("atlas-head"),
    ))
    .expect("serialize lineage");
    unknown["parents"][0]["surprise"] = serde_json::json!(true);
    assert!(serde_json::from_value::<KnowledgeLineage>(unknown).is_err());
}

#[test]
fn knowledge_lineage_fact_codec_records_owner_precedence_and_distinct_identity() {
    let fact_id = fact_id("8f9c2ee3-85ec-46e9-a43a-a2cd6048c1e9");
    let item_id = KnowledgeItemId::new(digest("immutable-item"));
    let revision = digest("restoring-revision");
    let owner = KnowledgeOrigin::new(
        KnowledgeOriginKind::OwnerExplicit,
        revision,
        digest("canonical fact"),
    );
    let synthesized = KnowledgeOrigin::new(
        KnowledgeOriginKind::Synthesized,
        digest("synthesized-revision"),
        digest("conflicting synthesis"),
    );
    let precedence =
        KnowledgeOriginPrecedence::owner_wins(owner, synthesized, "owner statement wins")
            .expect("valid precedence");
    let resurrection = KnowledgeResurrection::new(
        fact_id,
        capsule("capsule.fact"),
        digest("tombstone-revision"),
        revision,
        owner,
        digest("recorded-owner-authorization"),
        "owner restored the fact",
    )
    .expect("owner-shaped resurrection metadata");
    let tombstone = KnowledgeTombstone::new(
        fact_id,
        capsule("capsule.fact"),
        digest("tombstone-revision"),
        "owner retired the old revision",
        Some(resurrection),
    )
    .expect("persistent tombstone history");
    let fact = KnowledgeFact::new(
        fact_id,
        item_id,
        capsule("capsule.fact"),
        revision,
        "canonical fact",
        digest("canonical fact"),
        owner,
        Some(lineage(
            capsule("capsule.fact"),
            KnowledgeLineageCompleteness::Complete,
            digest("atlas-head"),
        )),
        Some(precedence),
        Some(tombstone),
    )
    .expect("restored fact projection");
    assert!(fact.validate_for_publication(digest("atlas-head")).is_ok());
    assert!(!fact.has_unresolved_tombstone());

    let json = serde_json::to_value(&fact).expect("serialize fact");
    assert_eq!(
        json["factId"],
        serde_json::json!("8f9c2ee3-85ec-46e9-a43a-a2cd6048c1e9")
    );
    assert!(
        json["itemId"]
            .as_str()
            .is_some_and(|value| value.starts_with("blake3:")),
        "immutable content identity remains digest-backed"
    );
    assert_ne!(json["factId"], json["itemId"]);
    assert_eq!(
        json["precedence"]["owner"]["kind"],
        serde_json::json!("ownerExplicit")
    );
    assert_eq!(
        json["precedence"]["synthesized"]["kind"],
        serde_json::json!("synthesized")
    );
    assert_eq!(
        json["precedence"]["reason"],
        serde_json::json!("owner statement wins")
    );
    assert_eq!(
        serde_json::from_value::<KnowledgeFact>(json.clone()).expect("deserialize fact"),
        fact
    );
    let mut synthesis_selected = json.clone();
    synthesis_selected["precedence"]["selected"] = serde_json::json!("synthesized");
    assert!(serde_json::from_value::<KnowledgeFact>(synthesis_selected).is_err());

    let mut missing_lineage = json.clone();
    missing_lineage
        .as_object_mut()
        .expect("fact object")
        .remove("lineage")
        .expect("required nullable lineage key");
    assert!(serde_json::from_value::<KnowledgeFact>(missing_lineage).is_err());

    let mut unknown = json;
    unknown["precedence"]["owner"]["surprise"] = serde_json::json!(true);
    assert!(serde_json::from_value::<KnowledgeFact>(unknown).is_err());
}

#[test]
fn knowledge_lineage_tombstone_requires_explicit_owner_resurrection_metadata() {
    let fact_id = fact_id("8f9c2ee3-85ec-46e9-a43a-a2cd6048c1e9");
    let capsule_id = capsule("capsule.fact");
    let tombstone = KnowledgeTombstone::new(
        fact_id,
        capsule_id.clone(),
        digest("tombstone-revision"),
        "owner retired the fact",
        None,
    )
    .expect("explicit non-resurrected tombstone");
    assert!(tombstone.recorded_restoring_revision().is_err());

    let tombstone_json = serde_json::to_value(&tombstone).expect("serialize tombstone");
    assert!(tombstone_json["resurrection"].is_null());
    let decoded: KnowledgeTombstone =
        serde_json::from_value(tombstone_json.clone()).expect("decode explicit null");
    assert!(decoded.recorded_restoring_revision().is_err());

    let mut missing = tombstone_json;
    missing
        .as_object_mut()
        .expect("tombstone object")
        .remove("resurrection")
        .expect("required nullable resurrection key");
    assert!(serde_json::from_value::<KnowledgeTombstone>(missing).is_err());

    let synthesized = KnowledgeOrigin::new(
        KnowledgeOriginKind::Synthesized,
        digest("restoring-revision"),
        digest("canonical fact"),
    );
    assert!(
        KnowledgeResurrection::new(
            fact_id,
            capsule_id.clone(),
            digest("tombstone-revision"),
            digest("restoring-revision"),
            synthesized,
            digest("untrusted-binding"),
            "synthesis attempted resurrection",
        )
        .is_err(),
        "synthesized metadata cannot stand in for an owner resurrection"
    );

    let owner = KnowledgeOrigin::new(
        KnowledgeOriginKind::OwnerExplicit,
        digest("restoring-revision"),
        digest("canonical fact"),
    );
    let wrong_capsule = KnowledgeResurrection::new(
        fact_id,
        capsule("capsule.other"),
        digest("tombstone-revision"),
        digest("restoring-revision"),
        owner,
        digest("recorded-owner-authorization"),
        "owner restored the fact",
    )
    .expect("structurally owner-shaped metadata");
    assert!(KnowledgeTombstone::new(
        fact_id,
        capsule_id,
        digest("tombstone-revision"),
        "owner retired the fact",
        Some(wrong_capsule),
    )
    .is_err());
}

#[test]
fn knowledge_lineage_citation_codec_preserves_exact_fact_lineage() {
    let capsule_id = capsule("capsule.fact");
    let fact_id = fact_id("8f9c2ee3-85ec-46e9-a43a-a2cd6048c1e9");
    let lineage = lineage(
        capsule_id.clone(),
        KnowledgeLineageCompleteness::Complete,
        digest("atlas-head"),
    );
    let fact_origin = KnowledgeOrigin::new(
        KnowledgeOriginKind::OwnerExplicit,
        digest("fact-revision"),
        digest("retrieved fact"),
    );
    let citation = Citation::new(
        AtlasId::new("atlas.core").expect("Atlas ID"),
        digest("atlas-head"),
        KnowledgeItemId::new(digest("immutable-item")),
        Some(fact_id),
        Some(digest("fact-revision")),
        Some(fact_origin),
        Some(lineage.clone()),
        0,
        4,
    )
    .expect("fact citation");
    assert!(citation
        .validate_fresh_lineage(&capsule_id, digest("atlas-head"))
        .is_ok());
    let hit = RetrievalHit {
        item_id: citation.item_id,
        source: citation.source.clone(),
        source_revision: citation.source_revision,
        fact_id: citation.fact_id,
        fact_revision: citation.fact_revision,
        fact_origin: citation.fact_origin,
        lineage: Some(lineage.clone()),
        trust: TrustClass::Curated,
        content_digest: digest("retrieved fact"),
        content: "retrieved fact".to_owned(),
        score: RelevanceScore::new(900_000).expect("score"),
        citation: citation.clone(),
    };
    assert!(hit
        .validate_fresh_lineage(&capsule_id, digest("atlas-head"))
        .is_ok());
    assert_eq!(
        serde_json::from_value::<RetrievalHit>(serde_json::to_value(&hit).expect("serialize hit"),)
            .expect("deserialize hit"),
        hit
    );
    let mut parent_mismatch = hit.clone();
    parent_mismatch
        .lineage
        .as_mut()
        .expect("fact lineage")
        .parents[0]
        .content_digest = digest("incorrect-parent-content");
    assert!(parent_mismatch.validate().is_err());

    let mut mismatched = hit;
    mismatched.fact_revision = Some(digest("different-fact-revision"));
    assert!(mismatched.validate().is_err());

    let json = serde_json::to_value(&citation).expect("serialize citation");
    assert_eq!(
        serde_json::from_value::<Citation>(json.clone()).expect("deserialize citation"),
        citation
    );
    let mut missing = json;
    missing
        .as_object_mut()
        .expect("citation object")
        .remove("lineage")
        .expect("required nullable lineage key");
    assert!(serde_json::from_value::<Citation>(missing).is_err());

    assert!(
        Citation::new(
            AtlasId::new("atlas.core").expect("Atlas ID"),
            digest("atlas-head"),
            KnowledgeItemId::new(digest("immutable-item")),
            Some(fact_id),
            None,
            Some(fact_origin),
            Some(lineage),
            0,
            4,
        )
        .is_err(),
        "partial fact citation metadata must reject"
    );
}

#[test]
fn knowledge_status_single_owner_fact_state_uses_tombstone_predicates() {
    let original = KnowledgeOrigin::new(
        KnowledgeOriginKind::OwnerExplicit,
        digest("fact-revision"),
        digest("canonical fact"),
    );
    let active = fact_with_tombstone(None, digest("fact-revision"), original);
    assert!(!active.has_unresolved_tombstone());

    let fact_id = active.fact_id;
    let tombstone = KnowledgeTombstone::new(
        fact_id,
        capsule("capsule.fact"),
        digest("tombstone-revision"),
        "owner retired the fact",
        None,
    )
    .expect("persistent tombstone");
    let retired = fact_with_tombstone(Some(tombstone), digest("fact-revision"), original);
    assert!(retired.has_unresolved_tombstone());
    assert!(retired
        .validate_for_publication(digest("atlas-head"))
        .is_err());

    let restoring_revision = digest("restoring-revision");
    let restored_origin = KnowledgeOrigin::new(
        KnowledgeOriginKind::OwnerExplicit,
        restoring_revision,
        digest("canonical fact"),
    );
    let resurrection = KnowledgeResurrection::new(
        fact_id,
        capsule("capsule.fact"),
        digest("tombstone-revision"),
        restoring_revision,
        restored_origin,
        digest("recorded-owner-authorization"),
        "owner restored the fact",
    )
    .expect("explicit owner metadata");
    let history = KnowledgeTombstone::new(
        fact_id,
        capsule("capsule.fact"),
        digest("tombstone-revision"),
        "owner retired the fact",
        Some(resurrection),
    )
    .expect("persistent restored tombstone");
    let restored = fact_with_tombstone(Some(history), restoring_revision, restored_origin);
    assert!(!restored.has_unresolved_tombstone());
    assert!(
        restored.tombstone.is_some(),
        "restoration must preserve tombstone history"
    );
}
