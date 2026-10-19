//! Life-workflow adapters for email, calendar, vault, finance, purchases, and Discord.
//!
//! Consequential operations use kernel authorization and approval gates.
//! Durable tasks claim their idempotency keys in the same transaction as their command rows.
//! Credentials stay behind opaque handles and secret files, never in model envelopes or the Nix store.
//!
//! Deployment endpoints, paths, lanes, and credential handles come from daemon configuration.
//! Unavailable services, credentials, or accounts return typed errors rather than simulated success.

#![forbid(unsafe_code)]

pub mod account;
pub mod calendar;
pub mod config;
pub mod conversation;
pub mod correlation;
pub mod delegation;
pub mod discord;
pub mod egress;
pub mod email;
pub mod finance;
pub mod fixtures;
pub mod generic_provider;
pub mod google;
mod http_pool;
pub mod ingress;
pub mod jmap;
pub mod natural;
pub mod provider;
pub mod purchase;
pub mod runtime;
pub mod schedule;
pub mod vault;
