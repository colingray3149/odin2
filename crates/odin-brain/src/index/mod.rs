//! The index: deterministic generation, exact persistence, shared records.
//!
//! - [`build`] derives [`IndexBuild`]s — one [`odin_domain::knowledge::retrieval::IndexGeneration`] plus its
//!   [`odin_domain::knowledge::retrieval::IndexedChunk`]s — from pinned source projections, counting chunking
//!   parameters in the crate's canonical pinned tokenizer bytes.
//! - [`store`] persists builds insert-only in one SQLite database, verifying
//!   manifest and content digests on every load and pinning each generation
//!   to the exact Atlas source and revision it was built from. Its private
//!   `lexical` sibling derives the persistent FTS5 BM25 lexical pools
//!   behind [`IndexStore::generation_lexical_top`]: rebuildable, content-keyed
//!   derived cache state whose statistics cover exactly one authorized
//!   candidate corpus per pool.

pub mod build;
pub(crate) mod lexical;
pub mod model;
pub mod postgres;
pub mod store;
pub use build::{
    build_index, build_index_with_embedding_model, Chunker, IndexBuild, CHUNKER_VERSION,
    INDEX_TOKENIZER, MAX_ITEM_BYTES,
};
pub use model::ItemProvenance;
pub use store::{IndexStore, StoreOutcome};
