#![forbid(unsafe_code)]
#![deny(dead_code)]

//! Standard code-quality gates and direct production system/integration checks.

pub mod probe_registry;
pub mod report;
pub mod runner;
pub mod syscheck;

pub use report::{repository_build_contract, CheckResult, CheckStatus};
