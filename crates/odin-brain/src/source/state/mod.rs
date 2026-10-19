//! Deterministic projections of existing control-plane authorities.
//!
//! State sources use the existing chunker, index, and freshness-checked
//! serving path. They are not learning authorities.

pub mod live;
pub mod registry;
pub mod repos;
pub mod tasks;
