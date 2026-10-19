//! Retrieval, model, and knowledge policy contracts for canonical knowledge.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::num::{NonZeroU16, NonZeroU32};

use serde::{Deserialize, Deserializer, Serialize};

use super::fact::{
    validate_fact_reference, Citation, KnowledgeLineage, KnowledgeOrigin, TrustClass,
};
use super::index::EmbeddingBackend;
use crate::huginn::ids::ModelName;
use crate::knowledge::ids::{
    AtlasId, KnowledgeFactId, KnowledgeItemId, RelevanceScore, TokenizerId,
};
use crate::knowledge::required_nullable;
use crate::{Digest, DomainError};
use odin_types::CapsuleId;

/// Retrieval filters and budgets applied before candidate ranking.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetrievalQuery {
    pub text: String,
    pub sources: BTreeSet<AtlasId>,
    pub required_tags: BTreeSet<String>,
    pub denied_tags: BTreeSet<String>,
    pub allowed_trust: BTreeSet<TrustClass>,
    pub candidate_limit: NonZeroU16,
    pub top_k: NonZeroU16,
    pub min_score: RelevanceScore,
}

impl RetrievalQuery {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        text: String,
        sources: BTreeSet<AtlasId>,
        required_tags: BTreeSet<String>,
        denied_tags: BTreeSet<String>,
        allowed_trust: BTreeSet<TrustClass>,
        candidate_limit: NonZeroU16,
        top_k: NonZeroU16,
        min_score: RelevanceScore,
    ) -> Result<Self, DomainError> {
        let query = Self {
            text,
            sources,
            required_tags,
            denied_tags,
            allowed_trust,
            candidate_limit,
            top_k,
            min_score,
        };
        query.validate()?;
        Ok(query)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        if self.text.trim().is_empty() {
            return Err(invalid_knowledge_policy(
                "retrieval query text must not be empty",
            ));
        }
        if self.sources.is_empty() {
            return Err(invalid_knowledge_policy(
                "retrieval query must allow at least one Atlas source",
            ));
        }
        if self.allowed_trust.is_empty() {
            return Err(invalid_knowledge_policy(
                "retrieval query must allow at least one trust class",
            ));
        }
        if self.allowed_trust.contains(&TrustClass::Control) {
            return Err(invalid_knowledge_policy(
                "retrieval queries cannot classify retrieved content as control",
            ));
        }
        validate_limits(self.candidate_limit, self.top_k)?;
        validate_tags(&self.required_tags, &self.denied_tags)
    }
}

/// A ranked retrieval result with immutable content identity and fact lineage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetrievalHit {
    pub item_id: KnowledgeItemId,
    pub source: AtlasId,
    pub source_revision: Digest,
    pub fact_id: Option<KnowledgeFactId>,
    pub fact_revision: Option<Digest>,
    pub fact_origin: Option<KnowledgeOrigin>,
    pub lineage: Option<KnowledgeLineage>,
    pub trust: TrustClass,
    pub content_digest: Digest,
    pub content: String,
    pub score: RelevanceScore,
    pub citation: Citation,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RetrievalHitWire {
    item_id: KnowledgeItemId,
    source: AtlasId,
    source_revision: Digest,
    #[serde(deserialize_with = "required_nullable")]
    fact_id: Option<KnowledgeFactId>,
    #[serde(deserialize_with = "required_nullable")]
    fact_revision: Option<Digest>,
    #[serde(deserialize_with = "required_nullable")]
    fact_origin: Option<KnowledgeOrigin>,
    #[serde(deserialize_with = "required_nullable")]
    lineage: Option<KnowledgeLineage>,
    trust: TrustClass,
    content_digest: Digest,
    content: String,
    score: RelevanceScore,
    citation: Citation,
}

impl<'de> Deserialize<'de> for RetrievalHit {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = RetrievalHitWire::deserialize(deserializer)?;
        let hit = Self {
            item_id: wire.item_id,
            source: wire.source,
            source_revision: wire.source_revision,
            fact_id: wire.fact_id,
            fact_revision: wire.fact_revision,
            fact_origin: wire.fact_origin,
            lineage: wire.lineage,
            trust: wire.trust,
            content_digest: wire.content_digest,
            content: wire.content,
            score: wire.score,
            citation: wire.citation,
        };
        hit.validate().map_err(serde::de::Error::custom)?;
        Ok(hit)
    }
}

impl RetrievalHit {
    pub fn validate(&self) -> Result<(), DomainError> {
        self.citation.validate()?;
        validate_fact_reference(
            self.fact_id.as_ref(),
            self.fact_revision.as_ref(),
            self.fact_origin.as_ref(),
            self.lineage.as_ref(),
        )?;
        if self.source != self.citation.source
            || self.source_revision != self.citation.source_revision
            || self.item_id != self.citation.item_id
            || self.fact_id != self.citation.fact_id
            || self.fact_revision != self.citation.fact_revision
            || self.fact_origin != self.citation.fact_origin
            || self.lineage.as_ref() != self.citation.lineage.as_ref()
        {
            return Err(invalid_knowledge_policy(
                "retrieval hit and citation provenance must agree",
            ));
        }
        Ok(())
    }

    /// Returns a total deterministic key whose ascending order is ranking order.
    pub fn ordering_key(&self) -> RetrievalHitOrderingKey {
        RetrievalHitOrderingKey {
            score: self.score,
            trust: self.trust,
            source: self.source.clone(),
            item_id: self.item_id,
            content_digest: self.content_digest,
        }
    }

    /// Compares hits in deterministic best-first retrieval order.
    pub fn compare_rank(left: &Self, right: &Self) -> Ordering {
        left.ordering_key().cmp(&right.ordering_key())
    }

    /// Rechecks source, trust, score, and provenance before a hit enters ranking.
    pub fn validate_for_query(&self, query: &RetrievalQuery) -> Result<(), DomainError> {
        query.validate()?;
        self.validate()?;
        if !query.sources.contains(&self.source) {
            return Err(invalid_knowledge_policy(
                "retrieval hit source is outside the query source filter",
            ));
        }
        if !query.allowed_trust.contains(&self.trust) {
            return Err(invalid_knowledge_policy(
                "retrieval hit trust is outside the query trust filter",
            ));
        }
        if self.score < query.min_score {
            return Err(invalid_knowledge_policy(
                "retrieval hit score is below the query minimum",
            ));
        }
        Ok(())
    }

    pub fn validate_fresh_lineage(
        &self,
        capsule_id: &CapsuleId,
        required_revision: Digest,
    ) -> Result<(), DomainError> {
        self.validate()?;
        KnowledgeLineage::require_fresh(self.lineage.as_ref(), capsule_id, required_revision)
    }
}

/// Complete ranking metadata for the frozen hybrid-retrieval tie-break contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetrievalHitOrderingKey {
    pub score: RelevanceScore,
    pub trust: TrustClass,
    pub source: AtlasId,
    pub item_id: KnowledgeItemId,
    pub content_digest: Digest,
}

impl Ord for RetrievalHitOrderingKey {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .score
            .cmp(&self.score)
            .then_with(|| other.trust.cmp(&self.trust))
            .then_with(|| self.source.cmp(&other.source))
            .then_with(|| self.item_id.cmp(&other.item_id))
            .then_with(|| self.content_digest.cmp(&other.content_digest))
    }
}

impl PartialOrd for RetrievalHitOrderingKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Model limits and tokenizer identity needed for deterministic policy resolution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelDescriptor {
    pub name: ModelName,
    pub tokenizer: TokenizerId,
    pub context_window_tokens: NonZeroU32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RetrievalMode {
    Lexical,
    Vector,
    Hybrid,
}

/// Knowledge authority and retrieval budgets declared by a slice.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SliceKnowledgePolicy {
    pub required: bool,
    pub atlas_sources: BTreeSet<AtlasId>,
    pub retrieval_mode: RetrievalMode,
    pub candidate_limit: NonZeroU16,
    pub top_k: NonZeroU16,
    pub min_score: RelevanceScore,
    pub chunk_tokens: NonZeroU32,
    pub chunk_overlap_tokens: u32,
    pub embedding_backend: EmbeddingBackend,
}

impl SliceKnowledgePolicy {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.required && self.atlas_sources.is_empty() {
            return Err(invalid_knowledge_policy(
                "required knowledge needs at least one Atlas source",
            ));
        }
        validate_limits(self.candidate_limit, self.top_k)?;
        validate_chunking(self.chunk_tokens, self.chunk_overlap_tokens)?;
        if matches!(
            self.retrieval_mode,
            RetrievalMode::Vector | RetrievalMode::Hybrid
        ) && self.embedding_backend == EmbeddingBackend::Disabled
        {
            return Err(invalid_knowledge_policy(
                "vector retrieval requires an embedding backend",
            ));
        }
        Ok(())
    }
}

/// Seat restrictions applied monotonically to slice knowledge authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SeatKnowledgePolicy {
    pub atlas_sources: BTreeSet<AtlasId>,
    pub required_tags: BTreeSet<String>,
    pub denied_tags: BTreeSet<String>,
    pub top_k: NonZeroU16,
}

impl SeatKnowledgePolicy {
    pub fn validate(&self) -> Result<(), DomainError> {
        validate_tags(&self.required_tags, &self.denied_tags)
    }

    pub fn validate_against_slice(&self, slice: &SliceKnowledgePolicy) -> Result<(), DomainError> {
        self.validate()?;
        slice.validate()?;
        if !self.atlas_sources.is_subset(&slice.atlas_sources) {
            return Err(invalid_knowledge_policy(
                "seat Atlas sources must be a subset of slice Atlas sources",
            ));
        }
        if self.top_k > slice.top_k {
            return Err(invalid_knowledge_policy(
                "seat top_k must not exceed slice top_k",
            ));
        }
        Ok(())
    }
}

/// Fully resolved knowledge policy consumed by query planning and context compilation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveKnowledgePolicy {
    pub required: bool,
    pub atlas_sources: BTreeSet<AtlasId>,
    pub required_tags: BTreeSet<String>,
    pub denied_tags: BTreeSet<String>,
    pub allowed_trust: BTreeSet<TrustClass>,
    pub retrieval_mode: RetrievalMode,
    pub candidate_limit: NonZeroU16,
    pub top_k: NonZeroU16,
    pub min_score: RelevanceScore,
    pub chunk_tokens: NonZeroU32,
    pub chunk_overlap_tokens: u32,
    pub embedding_backend: EmbeddingBackend,
}

impl EffectiveKnowledgePolicy {
    pub fn resolve(
        slice: &SliceKnowledgePolicy,
        seat: &SeatKnowledgePolicy,
    ) -> Result<Self, DomainError> {
        seat.validate_against_slice(slice)?;
        let policy = Self {
            required: slice.required,
            atlas_sources: seat.atlas_sources.clone(),
            required_tags: seat.required_tags.clone(),
            denied_tags: seat.denied_tags.clone(),
            allowed_trust: retrievable_trust_classes(),
            retrieval_mode: slice.retrieval_mode,
            candidate_limit: slice.candidate_limit,
            top_k: seat.top_k,
            min_score: slice.min_score,
            chunk_tokens: slice.chunk_tokens,
            chunk_overlap_tokens: slice.chunk_overlap_tokens,
            embedding_backend: slice.embedding_backend,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        if self.required && self.atlas_sources.is_empty() {
            return Err(invalid_knowledge_policy(
                "required effective knowledge needs at least one Atlas source",
            ));
        }
        if self.allowed_trust.is_empty() {
            return Err(invalid_knowledge_policy(
                "effective knowledge must allow at least one trust class",
            ));
        }
        if self.allowed_trust.contains(&TrustClass::Control) {
            return Err(invalid_knowledge_policy(
                "retrieved knowledge cannot have control trust",
            ));
        }
        validate_limits(self.candidate_limit, self.top_k)?;
        validate_chunking(self.chunk_tokens, self.chunk_overlap_tokens)?;
        validate_tags(&self.required_tags, &self.denied_tags)?;
        if matches!(
            self.retrieval_mode,
            RetrievalMode::Vector | RetrievalMode::Hybrid
        ) && self.embedding_backend == EmbeddingBackend::Disabled
        {
            return Err(invalid_knowledge_policy(
                "vector retrieval requires an embedding backend",
            ));
        }
        Ok(())
    }

    /// Builds a query with all trust and source filters represented before ranking.
    pub fn retrieval_query(&self, text: String) -> Result<RetrievalQuery, DomainError> {
        self.validate()?;
        RetrievalQuery::new(
            text,
            self.atlas_sources.clone(),
            self.required_tags.clone(),
            self.denied_tags.clone(),
            self.allowed_trust.clone(),
            self.candidate_limit,
            self.top_k,
            self.min_score,
        )
    }
}

fn validate_limits(candidate_limit: NonZeroU16, top_k: NonZeroU16) -> Result<(), DomainError> {
    if top_k > candidate_limit {
        return Err(invalid_knowledge_policy(
            "top_k must not exceed candidate_limit",
        ));
    }
    Ok(())
}

fn validate_chunking(
    chunk_tokens: NonZeroU32,
    chunk_overlap_tokens: u32,
) -> Result<(), DomainError> {
    if chunk_overlap_tokens >= chunk_tokens.get() {
        return Err(invalid_knowledge_policy(
            "chunk overlap must be smaller than chunk size",
        ));
    }
    Ok(())
}

fn validate_tags(
    required_tags: &BTreeSet<String>,
    denied_tags: &BTreeSet<String>,
) -> Result<(), DomainError> {
    if required_tags
        .iter()
        .chain(denied_tags)
        .any(|tag| tag.is_empty() || tag.trim() != tag || tag.contains('\0'))
    {
        return Err(invalid_knowledge_policy(
            "tags must be non-empty, trimmed, and contain no NUL",
        ));
    }
    if !required_tags.is_disjoint(denied_tags) {
        return Err(invalid_knowledge_policy(
            "required and denied tags must be disjoint",
        ));
    }
    Ok(())
}

fn retrievable_trust_classes() -> BTreeSet<TrustClass> {
    [
        TrustClass::Curated,
        TrustClass::Observed,
        TrustClass::Untrusted,
    ]
    .into_iter()
    .collect()
}

pub(super) fn invalid_knowledge_policy(reason: impl Into<String>) -> DomainError {
    DomainError::InvalidScope(format!("knowledge policy: {}", reason.into()))
}
