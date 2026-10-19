#![forbid(unsafe_code)]
#![deny(dead_code)]

//! `odin-brain`: knowledge indexing, retrieval, seat memory, and the learned
//! entry store over the immutable `odin-atlas` authority.
//!
//! Authority boundaries:
//! - Atlas is the immutable knowledge authority; index generations are exact
//!   and disposable, rebuilt from pinned revisions.
//! - The kernel owns capabilities; the brain formats tool schemas from an
//!   exact capability listing and never grants tools or widens authority.
//! - The ledger owns money, approvals, and audit; brain-relevant events go
//!   through `odin_ledger::audit` and the `odin.knowledge.changed` subject.

pub mod archive;
pub mod audit;
pub mod config;
pub mod context;
pub mod error;
pub mod index;
pub mod learn;
pub mod projection;
pub mod retrieval;
pub mod service;
pub mod source;
mod sqlite;

#[cfg(test)]
#[path = "../tests/support/postgres.rs"]
pub(crate) mod postgres_test_cluster;
