//! Deterministic chunking and index generation.
//!
//! Derives [`IndexedChunk`] records from [`SourceItem`] projections under the
//! slice-resolved chunking parameters (`chunk_tokens`, `chunk_overlap_tokens`
//! on `EffectiveKnowledgePolicy`), stamps `chunker_version`, tokenizer, and
//! embedding model into each [`IndexGeneration`], and hashes all content with
//! `Digest::hash`. Everything here is a pure function of its inputs: the same
//! pinned revision and chunking parameters always produce the same generation
//! ID, manifest digest, and chunk list.
//!
//! Token counting is pinned to [`INDEX_TOKENIZER`] — the crate's one
//! canonical pinned tokenizer ([`PinnedTokenizer`]): one token is exactly
//! one UTF-8 byte. Chunk windows are counted in those bytes, so chunk text
//! is always an exact byte range of the item, every chunk is bounded by
//! construction (the window's end edge snaps backward to a UTF-8 character
//! boundary, so no chunk ever exceeds the byte budget), consecutive chunk
//! ranges overlap or abut so the chunks reconstruct the item completely, a
//! window too small to hold one scalar fails typed, and every chunk is a
//! valid `str` slice.

use std::collections::BTreeMap;
use std::num::NonZeroU32;

use odin_domain::knowledge::ids::{AtlasId, EmbeddingModelId};
use odin_domain::knowledge::ids::{IndexGenerationId, KnowledgeChunkId, KnowledgeItemId};
use odin_domain::knowledge::retrieval::EffectiveKnowledgePolicy;
use odin_domain::knowledge::retrieval::{IndexGeneration, IndexedChunk};
use odin_domain::Digest;

use crate::context::tokenizer::{PinnedTokenizer, PINNED_TOKENIZER_ID};
use crate::error::{BrainError, BrainResult};
use crate::index::model::ItemProvenance;
use crate::source::SourceItem;

/// Version stamped into every [`IndexGeneration`] produced by this chunker.
/// Bumping it invalidates old generations (they become stale and rebuildable).
pub const CHUNKER_VERSION: &str = "odin-brain:index-chunker:v1";

/// Tokenizer identity pinned by this chunker: the crate's canonical pinned
/// tokenizer ([`PINNED_TOKENIZER_ID`]). Chunking parameters are counted in
/// its exact UTF-8 byte tokens; every other tokenizer identity is rejected
/// by [`PinnedTokenizer`], which implements nothing else.
pub const INDEX_TOKENIZER: &str = PINNED_TOKENIZER_ID;

/// Embedding model recorded when the embedding backend is disabled.
pub const NO_EMBEDDING_MODEL: &str = "none:lexical-only-v1";

/// Upper bound on a single item's text so indexing stays bounded.
pub const MAX_ITEM_BYTES: u64 = 16 * 1024 * 1024;

/// Deterministic chunker bound to one slice's chunking parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Chunker {
    chunk_tokens: NonZeroU32,
    chunk_overlap_tokens: u32,
}

impl Chunker {
    /// Validates the parameters exactly as `EffectiveKnowledgePolicy` does:
    /// overlap must be strictly smaller than the window.
    pub fn new(chunk_tokens: NonZeroU32, chunk_overlap_tokens: u32) -> BrainResult<Self> {
        if chunk_overlap_tokens >= chunk_tokens.get() {
            return Err(BrainError::InvalidPolicy(format!(
                "chunk overlap ({chunk_overlap_tokens}) must be smaller than the chunk window ({})",
                chunk_tokens.get()
            )));
        }
        Ok(Self {
            chunk_tokens,
            chunk_overlap_tokens,
        })
    }

    pub fn from_policy(policy: &EffectiveKnowledgePolicy) -> BrainResult<Self> {
        Self::new(policy.chunk_tokens, policy.chunk_overlap_tokens)
    }

    pub const fn chunk_tokens(&self) -> u32 {
        self.chunk_tokens.get()
    }

    pub const fn chunk_overlap_tokens(&self) -> u32 {
        self.chunk_overlap_tokens
    }

    /// Splits one item into deterministic, bounded, overlapping chunks that
    /// cover the item completely.
    ///
    /// The first chunk starts at byte 0. Each window is at most
    /// `chunk_tokens` bytes and the next window starts
    /// `chunk_tokens - chunk_overlap_tokens` tokens later, never past the
    /// previous chunk's end, so consecutive chunks overlap or abut and their
    /// citation byte ranges reconstruct the whole item in order. Window
    /// edges snap to UTF-8 character boundaries: the end edge snaps backward,
    /// bounding every chunk by the byte budget; the advance snaps to the
    /// nearest earlier boundary, never past the previous end. A window too
    /// small to hold the scalar at its own start fails typed
    /// ([`BrainError::InvalidPolicy`]) rather than emitting an over-budget or
    /// empty chunk.
    pub fn chunk_item(&self, item: &SourceItem) -> BrainResult<Vec<IndexedChunk>> {
        crate::source::ensure_item_size(&item.text, MAX_ITEM_BYTES)?;
        let text = item.text.as_str();
        let total = text.len();
        let window = self.chunk_tokens.get() as usize;
        let step = window - self.chunk_overlap_tokens as usize;
        let mut chunks = Vec::new();
        let mut start = 0_usize;
        loop {
            // The window end snaps backward to a UTF-8 character boundary, so
            // every chunk is a non-empty exact byte range of the item within
            // the byte budget; the start is always a boundary (0 or chosen
            // below), so every chunk is a valid `str` slice.
            let mut end = (start + window).min(total);
            while end > start && !text.is_char_boundary(end) {
                end -= 1;
            }
            if end == start {
                return Err(BrainError::InvalidPolicy(format!(
                    "chunk window ({window}) is smaller than one UTF-8 scalar at byte offset {start}"
                )));
            }
            let chunk_text = &text[start..end];
            let digest = Digest::hash(chunk_text.as_bytes());
            let chunk_id = chunk_id(&item.item_id, chunks.len(), &digest);
            let citation = odin_domain::knowledge::retrieval::Citation::new(
                item.source.clone(),
                item.source_revision,
                item.item_id,
                None,
                None,
                None,
                None,
                start as u64,
                end as u64,
            )?;
            chunks.push(IndexedChunk {
                item_id: item.item_id,
                chunk_id,
                trust: item.trust,
                text: chunk_text.to_owned(),
                digest,
                citation,
            });
            if end == total {
                break;
            }
            // Advance by `window - overlap` tokens, snapped back to a
            // character boundary and never past this chunk's end: consecutive
            // chunks overlap or abut, starts strictly advance, and the chunk
            // ranges cover the item with no gaps.
            let candidate = start + step;
            start = if candidate >= end {
                end
            } else {
                let mut next = candidate;
                while next > start && !text.is_char_boundary(next) {
                    next -= 1;
                }
                if next == start {
                    end
                } else {
                    next
                }
            };
        }
        Ok(chunks)
    }
}

/// Derives the stable chunk identity from the item, ordinal, and content.
fn chunk_id(
    item_id: &odin_domain::knowledge::ids::KnowledgeItemId,
    ordinal: usize,
    digest: &Digest,
) -> KnowledgeChunkId {
    let mut material = Vec::with_capacity(64);
    material.extend_from_slice(b"odin-brain:chunk:v1\x00");
    material.extend_from_slice(item_id.as_digest().as_bytes());
    material.extend_from_slice(&ordinal.to_be_bytes());
    material.extend_from_slice(digest.as_bytes());
    KnowledgeChunkId::new(Digest::hash(&material))
}

/// A complete, deterministic index build: one generation plus its chunks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexBuild {
    pub generation: IndexGeneration,
    pub chunks: Vec<IndexedChunk>,
    /// Atlas node provenance per indexed item, keyed by item ID.
    pub provenance: BTreeMap<KnowledgeItemId, ItemProvenance>,
}

/// Builds the generation record and chunk list for one pinned source,
/// lexically: the generation is stamped with [`NO_EMBEDDING_MODEL`].
///
/// The manifest digest covers the pinned Atlas source and revision, the
/// generation metadata, and the ordered chunk identities; the generation ID
/// covers the manifest digest. Rebuilding from the same pinned revision
/// yields byte-identical values; a different source or revision always
/// yields a different generation. This is the only honest build posture
/// while no embedding backend is wired.
pub fn build_index(
    atlas_id: AtlasId,
    atlas_revision: Digest,
    items: &[SourceItem],
    chunker: &Chunker,
) -> BrainResult<IndexBuild> {
    build_index_with_embedding_model(
        atlas_id,
        atlas_revision,
        items,
        chunker,
        EmbeddingModelId::new(NO_EMBEDDING_MODEL)?,
    )
}

/// Builds the generation record and chunk list for one pinned source,
/// stamped with the declared [`EmbeddingModelId`].
///
/// Identical in chunking to [`build_index`], but the declared embedding
/// model replaces the lexical-only [`NO_EMBEDDING_MODEL`] stamp: the model
/// enters the manifest digest, so the same pinned revision built for a
/// configured model carries a distinct, immutable generation identity that
/// lexical-only builds can never share. Embeddings from that model may then
/// be stored into this generation and no other.
///
/// The manifest digest covers the pinned Atlas source and revision, the
/// generation metadata, and the ordered chunk identities; the generation ID
/// covers the manifest digest. Rebuilding from the same pinned revision and
/// declared model yields byte-identical values.
pub fn build_index_with_embedding_model(
    atlas_id: AtlasId,
    atlas_revision: Digest,
    items: &[SourceItem],
    chunker: &Chunker,
    embedding_model: EmbeddingModelId,
) -> BrainResult<IndexBuild> {
    let mut chunks = Vec::new();
    let mut provenance: BTreeMap<KnowledgeItemId, ItemProvenance> = BTreeMap::new();
    for item in items {
        if item.source != atlas_id {
            return Err(BrainError::InvalidRequest(format!(
                "source item {} belongs to atlas source {} but the generation pins {}",
                item.item_id, item.source, atlas_id
            )));
        }
        if item.source_revision != atlas_revision {
            return Err(BrainError::InvalidRequest(format!(
                "source item {} was read from revision {} but the generation pins {}",
                item.item_id, item.source_revision, atlas_revision
            )));
        }
        if let Some(item_provenance) = item.provenance.as_ref() {
            provenance.insert(item.item_id, item_provenance.clone());
        }
        chunks.extend(chunker.chunk_item(item)?);
    }
    // Canonical order is citation order: chunk starts strictly advance and
    // the chunk list reconstructs each item in reading order. This stays
    // fully deterministic (spans are a pure function of the items); the
    // chunk ID is only the tie-breaker for a range collision that the
    // chunker cannot produce.
    chunks.sort_by(|left, right| {
        left.citation
            .byte_start
            .cmp(&right.citation.byte_start)
            .then_with(|| left.chunk_id.cmp(&right.chunk_id))
    });

    let manifest_digest = manifest_digest(
        &atlas_id,
        &atlas_revision,
        &chunks,
        &provenance,
        CHUNKER_VERSION,
        INDEX_TOKENIZER,
        embedding_model.as_str(),
    );
    let generation_id = IndexGenerationId::new(Digest::hash(manifest_digest.as_bytes()));
    let generation = IndexGeneration {
        generation_id,
        atlas_id,
        atlas_revision,
        chunker_version: CHUNKER_VERSION.to_owned(),
        tokenizer: PinnedTokenizer::id()?,
        embedding_model,
        manifest_digest,
    };
    Ok(IndexBuild {
        generation,
        chunks,
        provenance,
    })
}

/// Incremental builder for the canonical manifest digest: feeds chunk
/// identities (and item provenance) one at a time, so stores can persist
/// mbox-scale builds without materializing every chunk in RAM. The byte
/// layout is defined here, exactly once; [`manifest_digest`] delegates to
/// it, so one-shot and streaming builds derive identical digests.
pub(crate) struct ManifestHasher {
    hasher: blake3::Hasher,
}

impl ManifestHasher {
    /// Starts one manifest over the pinned source, revision, and stamped
    /// build metadata. Callers pass their actual `chunker_version` and
    /// `tokenizer` values so tampering with a stored header is detected
    /// when the manifest is recomputed against it.
    pub(crate) fn new(
        atlas_id: &AtlasId,
        atlas_revision: &Digest,
        chunker_version: &str,
        tokenizer: &str,
        embedding_model: &str,
    ) -> Self {
        let mut hasher = blake3::Hasher::new();
        for field in [
            atlas_id.as_str().as_bytes(),
            atlas_revision.as_bytes(),
            chunker_version.as_bytes(),
            tokenizer.as_bytes(),
            embedding_model.as_bytes(),
        ] {
            hasher.update(field);
            hasher.update(&[0]);
        }
        Self { hasher }
    }

    /// Feeds one chunk identity in canonical (stored ordinal) order.
    pub(crate) fn push_chunk(&mut self, chunk: &IndexedChunk) {
        self.push_chunk_identity(
            chunk.chunk_id.as_digest(),
            chunk.item_id.as_digest(),
            chunk.trust,
            &chunk.digest,
        );
    }

    /// Feeds one raw chunk identity (stored row form) in ordinal order.
    pub(crate) fn push_chunk_identity(
        &mut self,
        chunk_id: &Digest,
        item_id: &Digest,
        trust: odin_domain::knowledge::retrieval::TrustClass,
        digest: &Digest,
    ) {
        self.hasher.update(chunk_id.as_bytes());
        self.hasher.update(item_id.as_bytes());
        self.hasher.update(trust_bytes(trust).as_bytes());
        self.hasher.update(digest.as_bytes());
        self.hasher.update(&[0]);
    }

    /// Feeds one item's recorded provenance in sorted item order.
    pub(crate) fn push_provenance(
        &mut self,
        item_id: &KnowledgeItemId,
        item_provenance: &ItemProvenance,
    ) {
        self.hasher.update(item_id.as_digest().as_bytes());
        self.hasher.update(item_provenance.node_id.as_bytes());
        self.hasher.update(&[0]);
        self.hasher.update(item_provenance.path.as_bytes());
        self.hasher.update(&[0]);
        self.hasher
            .update(source_class_bytes(item_provenance.source_class).as_bytes());
        self.hasher.update(&[0]);
        for tag in &item_provenance.scope_tags {
            self.hasher.update(tag.as_bytes());
            self.hasher.update(&[0]);
        }
        self.hasher.update(&[0]);
    }

    pub(crate) fn finish(self) -> Digest {
        Digest::from_bytes(*self.hasher.finalize().as_bytes())
    }
}

/// Recomputes the canonical manifest digest for one pinned generation.
///
/// The material covers the pinned Atlas source and revision (so a
/// generation ID is exact to one source at one revision: identical content
/// under another source or revision is a different generation), the
/// generation metadata, the ordered chunk identities, and the recorded item
/// provenance (scope enforcement data: tampering it must fail verification).
/// Shared with
/// [`crate::index::store`], which recomputes it over loaded rows to detect
/// tampering. Byte material is NUL-delimited; digest values are fixed-width
/// so no ambiguity arises.
pub(crate) fn manifest_digest(
    atlas_id: &AtlasId,
    atlas_revision: &Digest,
    chunks: &[IndexedChunk],
    provenance: &BTreeMap<KnowledgeItemId, ItemProvenance>,
    chunker_version: &str,
    tokenizer: &str,
    embedding_model: &str,
) -> Digest {
    let mut hasher = ManifestHasher::new(
        atlas_id,
        atlas_revision,
        chunker_version,
        tokenizer,
        embedding_model,
    );
    for chunk in chunks {
        hasher.push_chunk(chunk);
    }
    for (item_id, item_provenance) in provenance {
        hasher.push_provenance(item_id, item_provenance);
    }
    hasher.finish()
}

/// Canonical byte token for a trust class, shared with the index store.
pub(crate) fn trust_bytes(trust: odin_domain::knowledge::retrieval::TrustClass) -> &'static str {
    use odin_domain::knowledge::retrieval::TrustClass;
    match trust {
        TrustClass::Control => "control",
        TrustClass::Curated => "curated",
        TrustClass::Observed => "observed",
        TrustClass::Untrusted => "untrusted",
    }
}

/// Canonical byte token for an Atlas source class, shared with the index store.
pub(crate) fn source_class_bytes(source_class: odin_atlas::SourceClass) -> &'static str {
    source_class.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::SourceItem;
    use std::num::NonZeroU32;

    fn item(text: &str) -> SourceItem {
        item_at(
            AtlasId::new("atlas:test").unwrap(),
            Digest::hash(b"revision"),
            text,
        )
    }

    /// Builds an item stamped with an exact source and revision, so tests
    /// can rebuild matching items at every pin instead of weakening
    /// `build_index`'s strict source/revision validation.
    fn item_at(source: AtlasId, revision: Digest, text: &str) -> SourceItem {
        SourceItem::new(
            source,
            revision,
            b"node:test",
            odin_domain::knowledge::retrieval::TrustClass::Curated,
            text,
        )
        .unwrap()
    }

    #[test]
    fn chunks_are_bounded_and_overlapping() {
        let chunker = Chunker::new(NonZeroU32::new(6).unwrap(), 2).unwrap();
        let text = "alpha beta gamma delta epsilon";
        let chunks = chunker.chunk_item(&item(text)).unwrap();
        assert!(chunks.len() > 1);
        for chunk in &chunks {
            assert!(chunk.text.len() <= 6);
            assert_eq!(chunk.digest, Digest::hash(chunk.text.as_bytes()));
            assert_eq!(
                chunk.citation.byte_end - chunk.citation.byte_start,
                chunk.text.len() as u64
            );
            assert_eq!(
                &text[chunk.citation.byte_start as usize..chunk.citation.byte_end as usize],
                chunk.text
            );
        }
        // Consecutive windows advance by window - overlap tokens (exact
        // UTF-8 bytes), so adjacent chunks start exactly four bytes apart.
        for pair in chunks.windows(2) {
            assert_eq!(pair[1].citation.byte_start - pair[0].citation.byte_start, 4);
        }
    }

    #[test]
    fn byte_windows_never_split_utf8_characters() {
        let chunker = Chunker::new(NonZeroU32::new(3).unwrap(), 0).unwrap();
        let text = "漢字漢字";
        let chunks = chunker.chunk_item(&item(text)).unwrap();
        assert_eq!(chunks.len(), 4);
        for chunk in &chunks {
            assert_eq!(chunk.text.chars().count(), 1);
            // Exactly at budget: a 3-byte scalar under a 3-byte window.
            assert!(chunk.text.len() <= 3);
            assert_eq!(
                &text[chunk.citation.byte_start as usize..chunk.citation.byte_end as usize],
                chunk.text
            );
        }
        // Gapless coverage: ranges overlap or abut and rebuild the item.
        let mut rebuilt = String::new();
        let mut covered_to = 0_usize;
        for chunk in &chunks {
            let range_start = chunk.citation.byte_start as usize;
            let range_end = chunk.citation.byte_end as usize;
            assert!(range_start <= covered_to);
            if range_end > covered_to {
                rebuilt.push_str(&text[covered_to..range_end]);
                covered_to = range_end;
            }
        }
        assert_eq!(covered_to, text.len());
        assert_eq!(rebuilt, text);
        // A window smaller than one scalar cannot hold any chunk under the
        // byte budget and fails typed instead of exceeding the ceiling.
        let too_small = Chunker::new(NonZeroU32::new(2).unwrap(), 0).unwrap();
        let error = too_small.chunk_item(&item(text)).unwrap_err();
        assert!(matches!(error, BrainError::InvalidPolicy(_)));
    }

    #[test]
    fn chunking_is_deterministic_and_generation_ids_stable() {
        let atlas = AtlasId::new("atlas:test").unwrap();
        let chunker = Chunker::new(NonZeroU32::new(4).unwrap(), 1).unwrap();
        let items = vec![item_at(
            atlas.clone(),
            Digest::hash(b"r"),
            "one two three four five six seven",
        )];
        let first = build_index(atlas.clone(), Digest::hash(b"r"), &items, &chunker).unwrap();
        let second = build_index(atlas.clone(), Digest::hash(b"r"), &items, &chunker).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first.generation.generation_id,
            second.generation.generation_id
        );
        assert_eq!(first.generation.chunker_version, CHUNKER_VERSION);
        // The generation stamps exactly the canonical pinned tokenizer.
        assert_eq!(first.generation.tokenizer, PinnedTokenizer::id().unwrap());
        // A different pinned revision or source is a different generation;
        // the items are rebuilt to match each pin exactly, as the strict
        // source/revision validation requires.
        let moved_items = vec![item_at(
            atlas.clone(),
            Digest::hash(b"r2"),
            "one two three four five six seven",
        )];
        let moved =
            build_index(atlas.clone(), Digest::hash(b"r2"), &moved_items, &chunker).unwrap();
        assert_ne!(
            first.generation.generation_id,
            moved.generation.generation_id
        );
        let else_atlas = AtlasId::new("atlas:else").unwrap();
        let other_items = vec![item_at(
            else_atlas.clone(),
            Digest::hash(b"r"),
            "one two three four five six seven",
        )];
        let other = build_index(else_atlas, Digest::hash(b"r"), &other_items, &chunker).unwrap();
        assert_ne!(
            first.generation.generation_id,
            other.generation.generation_id
        );
    }

    #[test]
    fn overlapping_window_must_be_smaller_than_window() {
        assert!(Chunker::new(NonZeroU32::new(4).unwrap(), 4).is_err());
        assert!(Chunker::new(NonZeroU32::new(4).unwrap(), 5).is_err());
    }

    #[test]
    fn item_must_match_pinned_source_and_revision() {
        let chunker = Chunker::new(NonZeroU32::new(4).unwrap(), 0).unwrap();
        let foreign = SourceItem::new(
            AtlasId::new("atlas:other").unwrap(),
            Digest::hash(b"r"),
            b"node:x",
            odin_domain::knowledge::retrieval::TrustClass::Observed,
            "text",
        )
        .unwrap();
        let error = build_index(
            AtlasId::new("atlas:test").unwrap(),
            Digest::hash(b"r"),
            &[foreign],
            &chunker,
        )
        .unwrap_err();
        assert!(matches!(error, BrainError::InvalidRequest(_)));
    }
}
