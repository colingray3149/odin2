//! `odin-browser` — the headed BrowserArm of Odin.
//!
//! The crate runs a real headed Chromium as the current non-root user with a
//! dedicated marked profile, drives it through a bounded Playwright worker,
//! and projects bounded, always-untrusted reads and authority-gated actions
//! onto the frozen `odin-domain` browser vocabulary.
//!
//! Policy boundary (non-negotiable): every changeable browser rule lives in
//! [`policy`], is supplied per session, carries `{revision, digest}`, and
//! updates only through expected-revision CAS. This crate never hard-codes
//! domains, sites, effect classes, approval requirements, or scraping rules,
//! and page content can never become policy. The higher API/kernel assigns
//! capability, effect class, and approval; immutable adapter gates (credentials,
//! quarantine, integrity, resource bounds) live in `safety` and `profile`.

#![forbid(unsafe_code)]

pub mod capability;
pub mod config;
mod display;
pub mod download;
pub mod policy;
pub mod profile;
pub mod relay;
pub mod relay_supervisor;
pub mod safety;
pub mod scanner;
pub mod session;
pub mod stream;
pub mod takeover;

/// Bounded Playwright worker client. Private by design: sessions speak to the
/// worker through it, but it is a mechanism detail, not public API.
mod worker;

pub use capability::{
    ActionRequest, ApprovalScopeMaterial, ArtifactPublication, ArtifactPublisher, BoundReport,
    PublicationKind, ReadFreshness, ReadKind, ReadRequest, SanitizedUrl, TrustClass, TypedRead,
};
pub use config::BrowserStopHost;
pub use policy::{
    ActionRule, BrowserPolicyError, BrowserPolicySnapshot, BrowserPolicyUpdate,
    BrowserPolicyUpdateOutcome, PolicyInvalidation, StructuralAction,
};
pub use scanner::{
    ExecutableMalwareScanner, ExecutableScannerConfigError, EXECUTABLE_SCANNER_MALICIOUS_SIGNATURE,
};
