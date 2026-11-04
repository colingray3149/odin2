//! The index: deterministic generation, exact persistence, shared records.
//!
//! - [`build`] derives [`IndexBuild`]s — one [`odin_domain::knowledge::retrieval::IndexGeneration`] plus its
//!   [`odin_domain::knowledge::retrieval::IndexedChunk`]s — from pinned source projections, counting chunking
//!   parameters in the crate's canonical pinned tokenizer bytes.
//! - [`store`] persists builds insert-only in the PostgreSQL store
//!   ([`postgres`]), sealing each generation once its rows read back to its
//!   manifest and pinning it to the exact Atlas source and revision it was
//!   built from.

pub mod build;
pub mod model;
pub mod postgres;
pub mod store;
pub use build::{
    build_index, build_index_with_embedding_model, Chunker, IndexBuild, CHUNKER_VERSION,
    INDEX_TOKENIZER, MAX_ITEM_BYTES,
};
pub use model::ItemProvenance;
pub use store::{IndexStore, StoreOutcome};
