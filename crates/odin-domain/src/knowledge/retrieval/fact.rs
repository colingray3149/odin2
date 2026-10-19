//! Fact, origin, lineage, tombstone, and trust projections for canonical knowledge.

use std::cmp::Ordering;

use serde::{Deserialize, Deserializer, Serialize};

use super::policy::invalid_knowledge_policy;
use crate::knowledge::ids::{AtlasId, KnowledgeFactId, KnowledgeItemId};
use crate::knowledge::required_nullable;
use crate::{Digest, DomainError};
use odin_types::CapsuleId;

/// Trust assigned by authority and provenance, from least to most trusted.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TrustClass {
    Control,
    Curated,
    Observed,
    Untrusted,
}

impl TrustClass {
    /// Returns the explicit authority rank used for monotonic trust comparisons.
    pub const fn rank(self) -> u8 {
        match self {
            Self::Untrusted => 0,
            Self::Observed => 1,
            Self::Curated => 2,
            Self::Control => 3,
        }
    }
}

impl Ord for TrustClass {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl PartialOrd for TrustClass {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn invalid_knowledge_fact(reason: impl Into<String>) -> DomainError {
    DomainError::InvalidEnvelope(format!("knowledge fact: {}", reason.into()))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum KnowledgeOriginKind {
    OwnerExplicit,
    Synthesized,
}

/// Public source revision and content identity recorded for one fact origin.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KnowledgeOrigin {
    pub kind: KnowledgeOriginKind,
    pub source_revision: Digest,
    pub content_digest: Digest,
}

impl KnowledgeOrigin {
    pub const fn new(
        kind: KnowledgeOriginKind,
        source_revision: Digest,
        content_digest: Digest,
    ) -> Self {
        Self {
            kind,
            source_revision,
            content_digest,
        }
    }
}

/// Owner-wins conflict projection. It records both public origins and the reason.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KnowledgeOriginPrecedence {
    pub owner: KnowledgeOrigin,
    pub synthesized: KnowledgeOrigin,
    pub selected: KnowledgeOriginKind,
    pub reason: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KnowledgeOriginPrecedenceWire {
    owner: KnowledgeOrigin,
    synthesized: KnowledgeOrigin,
    selected: KnowledgeOriginKind,
    reason: String,
}

impl<'de> Deserialize<'de> for KnowledgeOriginPrecedence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = KnowledgeOriginPrecedenceWire::deserialize(deserializer)?;
        let precedence = Self {
            owner: wire.owner,
            synthesized: wire.synthesized,
            selected: wire.selected,
            reason: wire.reason,
        };
        precedence.validate().map_err(serde::de::Error::custom)?;
        Ok(precedence)
    }
}

impl KnowledgeOriginPrecedence {
    pub fn owner_wins(
        owner: KnowledgeOrigin,
        synthesized: KnowledgeOrigin,
        reason: impl Into<String>,
    ) -> Result<Self, DomainError> {
        let precedence = Self {
            owner,
            synthesized,
            selected: KnowledgeOriginKind::OwnerExplicit,
            reason: reason.into(),
        };
        precedence.validate()?;
        Ok(precedence)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        if self.owner.kind != KnowledgeOriginKind::OwnerExplicit {
            return Err(invalid_knowledge_fact(
                "owner precedence must record an owner-explicit origin",
            ));
        }
        if self.synthesized.kind != KnowledgeOriginKind::Synthesized {
            return Err(invalid_knowledge_fact(
                "owner precedence must record a synthesized origin",
            ));
        }
        if self.selected != KnowledgeOriginKind::OwnerExplicit {
            return Err(invalid_knowledge_fact(
                "an owner-explicit origin must beat a conflicting synthesis",
            ));
        }
        if self.owner.content_digest == self.synthesized.content_digest {
            return Err(invalid_knowledge_fact(
                "owner precedence must describe conflicting content",
            ));
        }
        if self.reason.trim().is_empty() {
            return Err(invalid_knowledge_fact(
                "owner precedence requires a non-empty reason",
            ));
        }
        Ok(())
    }
}

/// Atlas head at which a lineage projection was observed.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KnowledgeFreshness {
    pub as_of_revision: Digest,
}

impl KnowledgeFreshness {
    pub const fn new(as_of_revision: Digest) -> Self {
        Self { as_of_revision }
    }

    pub fn is_fresh_at(self, required_revision: Digest) -> bool {
        self.as_of_revision == required_revision
    }
}

/// Whether the public lineage projection names every parent.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum KnowledgeLineageCompleteness {
    Complete,
    Partial,
}

/// One exact parent fact revision consumed by a derived fact.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KnowledgeLineageParent {
    pub fact_id: KnowledgeFactId,
    pub capsule_id: CapsuleId,
    pub fact_revision: Digest,
    pub content_digest: Digest,
}

impl KnowledgeLineageParent {
    pub fn new(
        fact_id: KnowledgeFactId,
        capsule_id: CapsuleId,
        fact_revision: Digest,
        content_digest: Digest,
    ) -> Self {
        Self {
            fact_id,
            capsule_id,
            fact_revision,
            content_digest,
        }
    }
}

/// Canonical capsule-bound fact lineage. This is a projection, not storage authority.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KnowledgeLineage {
    pub capsule_id: CapsuleId,
    pub parents: Vec<KnowledgeLineageParent>,
    pub completeness: KnowledgeLineageCompleteness,
    pub freshness: KnowledgeFreshness,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KnowledgeLineageWire {
    capsule_id: CapsuleId,
    parents: Vec<KnowledgeLineageParent>,
    completeness: KnowledgeLineageCompleteness,
    freshness: KnowledgeFreshness,
}

impl<'de> Deserialize<'de> for KnowledgeLineage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = KnowledgeLineageWire::deserialize(deserializer)?;
        let lineage = Self {
            capsule_id: wire.capsule_id,
            parents: wire.parents,
            completeness: wire.completeness,
            freshness: wire.freshness,
        };
        lineage.validate().map_err(serde::de::Error::custom)?;
        Ok(lineage)
    }
}

impl KnowledgeLineage {
    pub fn new(
        capsule_id: CapsuleId,
        mut parents: Vec<KnowledgeLineageParent>,
        completeness: KnowledgeLineageCompleteness,
        freshness: KnowledgeFreshness,
    ) -> Result<Self, DomainError> {
        parents.sort_by_key(|parent| parent.fact_id);
        let lineage = Self {
            capsule_id,
            parents,
            completeness,
            freshness,
        };
        lineage.validate()?;
        Ok(lineage)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        for parent in &self.parents {
            if parent.capsule_id != self.capsule_id {
                return Err(invalid_knowledge_fact(
                    "every lineage parent must belong to the lineage capsule",
                ));
            }
        }
        for pair in self.parents.windows(2) {
            if pair[0].fact_id >= pair[1].fact_id {
                return Err(invalid_knowledge_fact(
                    "lineage parents must be unique and sorted by fact ID",
                ));
            }
        }
        Ok(())
    }

    pub fn contains_parent(&self, fact_id: KnowledgeFactId) -> bool {
        self.parents.iter().any(|parent| parent.fact_id == fact_id)
    }

    /// Requires present, same-capsule, complete lineage observed at an exact Atlas head.
    pub fn require_fresh(
        lineage: Option<&Self>,
        capsule_id: &CapsuleId,
        required_revision: Digest,
    ) -> Result<(), DomainError> {
        let lineage = lineage.ok_or_else(|| invalid_knowledge_fact("fresh lineage is missing"))?;
        lineage.validate()?;
        if &lineage.capsule_id != capsule_id {
            return Err(invalid_knowledge_fact(
                "lineage capsule does not match the enclosing fact",
            ));
        }
        if lineage.completeness != KnowledgeLineageCompleteness::Complete {
            return Err(invalid_knowledge_fact(
                "partial lineage cannot satisfy a fresh-lineage requirement",
            ));
        }
        if !lineage.freshness.is_fresh_at(required_revision) {
            return Err(invalid_knowledge_fact(
                "lineage was observed at a stale Atlas revision",
            ));
        }
        Ok(())
    }
}

/// Public metadata for an explicit owner-authored restoring revision.
///
/// `authorization_digest` records the opaque authorization evidence binding. This
/// projection does not prove authority or perform resurrection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KnowledgeResurrection {
    pub fact_id: KnowledgeFactId,
    pub capsule_id: CapsuleId,
    pub tombstone_revision: Digest,
    pub restoring_revision: Digest,
    pub owner_origin: KnowledgeOrigin,
    pub authorization_digest: Digest,
    pub reason: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KnowledgeResurrectionWire {
    fact_id: KnowledgeFactId,
    capsule_id: CapsuleId,
    tombstone_revision: Digest,
    restoring_revision: Digest,
    owner_origin: KnowledgeOrigin,
    authorization_digest: Digest,
    reason: String,
}

impl<'de> Deserialize<'de> for KnowledgeResurrection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = KnowledgeResurrectionWire::deserialize(deserializer)?;
        let resurrection = Self {
            fact_id: wire.fact_id,
            capsule_id: wire.capsule_id,
            tombstone_revision: wire.tombstone_revision,
            restoring_revision: wire.restoring_revision,
            owner_origin: wire.owner_origin,
            authorization_digest: wire.authorization_digest,
            reason: wire.reason,
        };
        resurrection.validate().map_err(serde::de::Error::custom)?;
        Ok(resurrection)
    }
}

impl KnowledgeResurrection {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fact_id: KnowledgeFactId,
        capsule_id: CapsuleId,
        tombstone_revision: Digest,
        restoring_revision: Digest,
        owner_origin: KnowledgeOrigin,
        authorization_digest: Digest,
        reason: impl Into<String>,
    ) -> Result<Self, DomainError> {
        let resurrection = Self {
            fact_id,
            capsule_id,
            tombstone_revision,
            restoring_revision,
            owner_origin,
            authorization_digest,
            reason: reason.into(),
        };
        resurrection.validate()?;
        Ok(resurrection)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        if self.owner_origin.kind != KnowledgeOriginKind::OwnerExplicit {
            return Err(invalid_knowledge_fact(
                "resurrection metadata must name an owner-explicit origin",
            ));
        }
        if self.restoring_revision == self.tombstone_revision {
            return Err(invalid_knowledge_fact(
                "restoring revision must differ from the tombstone revision",
            ));
        }
        if self.reason.trim().is_empty() {
            return Err(invalid_knowledge_fact(
                "resurrection metadata requires a non-empty reason",
            ));
        }
        Ok(())
    }
}

/// Persistent tombstone history for a stable fact identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KnowledgeTombstone {
    pub fact_id: KnowledgeFactId,
    pub capsule_id: CapsuleId,
    pub tombstone_revision: Digest,
    pub reason: String,
    pub resurrection: Option<KnowledgeResurrection>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KnowledgeTombstoneWire {
    fact_id: KnowledgeFactId,
    capsule_id: CapsuleId,
    tombstone_revision: Digest,
    reason: String,
    #[serde(deserialize_with = "required_nullable")]
    resurrection: Option<KnowledgeResurrection>,
}

impl<'de> Deserialize<'de> for KnowledgeTombstone {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = KnowledgeTombstoneWire::deserialize(deserializer)?;
        let tombstone = Self {
            fact_id: wire.fact_id,
            capsule_id: wire.capsule_id,
            tombstone_revision: wire.tombstone_revision,
            reason: wire.reason,
            resurrection: wire.resurrection,
        };
        tombstone.validate().map_err(serde::de::Error::custom)?;
        Ok(tombstone)
    }
}

impl KnowledgeTombstone {
    pub fn new(
        fact_id: KnowledgeFactId,
        capsule_id: CapsuleId,
        tombstone_revision: Digest,
        reason: impl Into<String>,
        resurrection: Option<KnowledgeResurrection>,
    ) -> Result<Self, DomainError> {
        let tombstone = Self {
            fact_id,
            capsule_id,
            tombstone_revision,
            reason: reason.into(),
            resurrection,
        };
        tombstone.validate()?;
        Ok(tombstone)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        if self.reason.trim().is_empty() {
            return Err(invalid_knowledge_fact(
                "tombstone metadata requires a non-empty reason",
            ));
        }
        if let Some(resurrection) = &self.resurrection {
            resurrection.validate()?;
            if resurrection.fact_id != self.fact_id
                || resurrection.capsule_id != self.capsule_id
                || resurrection.tombstone_revision != self.tombstone_revision
            {
                return Err(invalid_knowledge_fact(
                    "resurrection metadata does not bind the tombstoned fact",
                ));
            }
        }
        Ok(())
    }

    /// Returns recorded metadata only; it neither proves authority nor performs restoration.
    pub fn recorded_restoring_revision(&self) -> Result<Digest, DomainError> {
        let resurrection = self.resurrection.as_ref().ok_or_else(|| {
            invalid_knowledge_fact("no explicit owner resurrection metadata is present")
        })?;
        self.validate()?;
        Ok(resurrection.restoring_revision)
    }
}

/// Canonical accepted-fact projection with distinct stable and content identities.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KnowledgeFact {
    pub fact_id: KnowledgeFactId,
    pub item_id: KnowledgeItemId,
    pub capsule_id: CapsuleId,
    pub revision: Digest,
    pub content: String,
    pub content_digest: Digest,
    pub origin: KnowledgeOrigin,
    pub lineage: Option<KnowledgeLineage>,
    pub precedence: Option<KnowledgeOriginPrecedence>,
    pub tombstone: Option<KnowledgeTombstone>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KnowledgeFactWire {
    fact_id: KnowledgeFactId,
    item_id: KnowledgeItemId,
    capsule_id: CapsuleId,
    revision: Digest,
    content: String,
    content_digest: Digest,
    origin: KnowledgeOrigin,
    #[serde(deserialize_with = "required_nullable")]
    lineage: Option<KnowledgeLineage>,
    #[serde(deserialize_with = "required_nullable")]
    precedence: Option<KnowledgeOriginPrecedence>,
    #[serde(deserialize_with = "required_nullable")]
    tombstone: Option<KnowledgeTombstone>,
}

impl<'de> Deserialize<'de> for KnowledgeFact {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = KnowledgeFactWire::deserialize(deserializer)?;
        let fact = Self {
            fact_id: wire.fact_id,
            item_id: wire.item_id,
            capsule_id: wire.capsule_id,
            revision: wire.revision,
            content: wire.content,
            content_digest: wire.content_digest,
            origin: wire.origin,
            lineage: wire.lineage,
            precedence: wire.precedence,
            tombstone: wire.tombstone,
        };
        fact.validate().map_err(serde::de::Error::custom)?;
        Ok(fact)
    }
}

impl KnowledgeFact {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fact_id: KnowledgeFactId,
        item_id: KnowledgeItemId,
        capsule_id: CapsuleId,
        revision: Digest,
        content: impl Into<String>,
        content_digest: Digest,
        origin: KnowledgeOrigin,
        lineage: Option<KnowledgeLineage>,
        precedence: Option<KnowledgeOriginPrecedence>,
        tombstone: Option<KnowledgeTombstone>,
    ) -> Result<Self, DomainError> {
        let fact = Self {
            fact_id,
            item_id,
            capsule_id,
            revision,
            content: content.into(),
            content_digest,
            origin,
            lineage,
            precedence,
            tombstone,
        };
        fact.validate()?;
        Ok(fact)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        if self.content.is_empty() {
            return Err(invalid_knowledge_fact(
                "canonical fact content must not be empty",
            ));
        }
        if self.content_digest != Digest::hash(self.content.as_bytes()) {
            return Err(invalid_knowledge_fact(
                "canonical fact content digest does not match its content",
            ));
        }
        if self.origin.content_digest != self.content_digest {
            return Err(invalid_knowledge_fact(
                "fact origin does not bind its content digest",
            ));
        }
        if let Some(lineage) = &self.lineage {
            lineage.validate()?;
            if lineage.capsule_id != self.capsule_id {
                return Err(invalid_knowledge_fact(
                    "fact and lineage capsule IDs do not match",
                ));
            }
            if lineage.contains_parent(self.fact_id) {
                return Err(invalid_knowledge_fact(
                    "a fact cannot name itself as a lineage parent",
                ));
            }
        }
        if let Some(precedence) = &self.precedence {
            precedence.validate()?;
            if precedence.owner != self.origin {
                return Err(invalid_knowledge_fact(
                    "fact origin does not match the selected owner origin",
                ));
            }
        }
        if let Some(tombstone) = &self.tombstone {
            tombstone.validate()?;
            if tombstone.fact_id != self.fact_id || tombstone.capsule_id != self.capsule_id {
                return Err(invalid_knowledge_fact(
                    "tombstone metadata does not bind the enclosing fact",
                ));
            }
            if let Some(resurrection) = &tombstone.resurrection {
                if resurrection.restoring_revision != self.revision
                    || resurrection.owner_origin != self.origin
                {
                    return Err(invalid_knowledge_fact(
                        "restored fact does not match its explicit owner resurrection metadata",
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn has_unresolved_tombstone(&self) -> bool {
        self.tombstone
            .as_ref()
            .is_some_and(|tombstone| tombstone.resurrection.is_none())
    }

    /// Structural predicate for a fresh-lineage publication projection.
    ///
    /// Resurrection metadata is checked for internal consistency only. This
    /// predicate does not establish owner authority or perform publication.
    pub fn validate_for_publication(&self, required_revision: Digest) -> Result<(), DomainError> {
        self.validate()?;
        if self.has_unresolved_tombstone() {
            return Err(invalid_knowledge_fact(
                "a tombstoned fact cannot be published without explicit owner resurrection metadata",
            ));
        }
        KnowledgeLineage::require_fresh(self.lineage.as_ref(), &self.capsule_id, required_revision)
    }
}

pub(super) fn validate_fact_reference(
    fact_id: Option<&KnowledgeFactId>,
    fact_revision: Option<&Digest>,
    fact_origin: Option<&KnowledgeOrigin>,
    lineage: Option<&KnowledgeLineage>,
) -> Result<(), DomainError> {
    match (fact_id, fact_revision, fact_origin, lineage) {
        (None, None, None, None) => Ok(()),
        (Some(fact_id), Some(_), Some(_), Some(lineage)) => {
            lineage.validate()?;
            if lineage.contains_parent(*fact_id) {
                return Err(invalid_knowledge_fact(
                    "a cited fact cannot name itself as a lineage parent",
                ));
            }
            Ok(())
        }
        _ => Err(invalid_knowledge_fact(
            "fact ID, fact revision, fact origin, and lineage must be all present or all null",
        )),
    }
}

/// Immutable Atlas revision selected as a knowledge source.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KnowledgeSourceRevision {
    pub source: AtlasId,
    pub revision: Digest,
}

/// Provenance for an exact byte range, including optional fact lineage.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Citation {
    pub source: AtlasId,
    pub source_revision: Digest,
    pub item_id: KnowledgeItemId,
    pub fact_id: Option<KnowledgeFactId>,
    pub fact_revision: Option<Digest>,
    pub fact_origin: Option<KnowledgeOrigin>,
    pub lineage: Option<KnowledgeLineage>,
    pub byte_start: u64,
    pub byte_end: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CitationWire {
    source: AtlasId,
    source_revision: Digest,
    item_id: KnowledgeItemId,
    #[serde(deserialize_with = "required_nullable")]
    fact_id: Option<KnowledgeFactId>,
    #[serde(deserialize_with = "required_nullable")]
    fact_revision: Option<Digest>,
    #[serde(deserialize_with = "required_nullable")]
    fact_origin: Option<KnowledgeOrigin>,
    #[serde(deserialize_with = "required_nullable")]
    lineage: Option<KnowledgeLineage>,
    byte_start: u64,
    byte_end: u64,
}

impl<'de> Deserialize<'de> for Citation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = CitationWire::deserialize(deserializer)?;
        let citation = Self {
            source: wire.source,
            source_revision: wire.source_revision,
            item_id: wire.item_id,
            fact_id: wire.fact_id,
            fact_revision: wire.fact_revision,
            fact_origin: wire.fact_origin,
            lineage: wire.lineage,
            byte_start: wire.byte_start,
            byte_end: wire.byte_end,
        };
        citation.validate().map_err(serde::de::Error::custom)?;
        Ok(citation)
    }
}

impl Citation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source: AtlasId,
        source_revision: Digest,
        item_id: KnowledgeItemId,
        fact_id: Option<KnowledgeFactId>,
        fact_revision: Option<Digest>,
        fact_origin: Option<KnowledgeOrigin>,
        lineage: Option<KnowledgeLineage>,
        byte_start: u64,
        byte_end: u64,
    ) -> Result<Self, DomainError> {
        let citation = Self {
            source,
            source_revision,
            item_id,
            fact_id,
            fact_revision,
            fact_origin,
            lineage,
            byte_start,
            byte_end,
        };
        citation.validate()?;
        Ok(citation)
    }

    /// Validates the range and the all-or-none fact-lineage binding.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.byte_start >= self.byte_end {
            return Err(invalid_knowledge_policy(
                "citation byte range must be non-empty and ordered",
            ));
        }
        validate_fact_reference(
            self.fact_id.as_ref(),
            self.fact_revision.as_ref(),
            self.fact_origin.as_ref(),
            self.lineage.as_ref(),
        )
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
