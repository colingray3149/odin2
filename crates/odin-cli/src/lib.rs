//! Shared production authorities used by Odin command-line binaries.

#![forbid(unsafe_code)]

pub mod authority_provision;
pub mod browser_runtime;
pub mod eval_daemon;
pub mod eval_protocol;
pub mod live_authority;
pub mod omp_conformance;
pub mod operator_prompt;
pub mod runtime_bindings;
#[cfg(test)]
mod test_support;
