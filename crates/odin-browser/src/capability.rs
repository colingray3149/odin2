//! Typed, bounded browser reads and authority-gated actions.
//!
//! Every read projects page content as [`TrustClass::Untrusted`] data with
//! full provenance (sanitized source URL, origin, exact-URL digest, document
//! digest, observation time, freshness, byte bounds, reason, token estimate).
//! Reads never expose cookies, storage, autofill, password values, request
//! auth headers, or runtime form values, and no projection can be reclassified
//! as trusted or as control.
//!
//! Actions are structural requests. Structural preflight distinguishes form
//! submission from ordinary activation as a mechanical DOM fact; it never
//! assigns effect or risk. Capability, effect class, and approval stay with
//! the higher API/kernel.

mod action;
mod dispatch;
mod dom;
mod error;
mod read;
mod request;
mod url;

pub use action::{
    classify_activation, ActivationStructure, DomBinding, ElementStructure, PolicyBinding,
    StructuralDescriptor,
};
pub use dispatch::{
    ApprovalScopeMaterial, ArtifactPublication, ArtifactPublisher, NavigationObservation,
    PublicationKind,
};
pub use dom::{
    AccessibilityNode, AccessibilityProjection, DomNode, DomSanitization, SanitizedDomProjection,
};
pub use error::CapabilityError;
pub use read::{
    estimate_tokens, BoundReport, LinkEntry, LinksProjection, PageProvenance, ReadBasis,
    ReadFreshness, ReadMetadata, TableEntry, TablesProjection, TextProjection, TypedRead,
};
pub use request::{ActionArguments, ActionRequest, ElementRef, ReadKind, ReadRequest};
pub use url::SanitizedUrl;

pub use odin_domain::knowledge::retrieval::TrustClass;

/// Shared output ceiling for [`ReadRequest`] and all projections.
pub const MAX_READ_BYTES: u64 = 1_048_576;

/// Hard ceiling on exact URL length accepted by [`SanitizedUrl::parse`].
pub const MAX_URL_BYTES: usize = 4096;

pub const MAX_SELECTOR_BYTES: usize = 1024;

/// Hard ceiling on typed/filled text carried by one action request.
pub const MAX_ACTION_TEXT_BYTES: usize = 8192;

/// Hard ceiling on one key name in a press-key request.
pub const MAX_KEY_BYTES: usize = 64;

pub const MAX_LINK_ENTRIES: usize = 512;

pub const MAX_TABLES: usize = 16;

/// Hard ceiling on rows kept per table.
pub const MAX_TABLE_ROWS: usize = 256;

/// Hard ceiling on columns kept per table row.
pub const MAX_TABLE_COLUMNS: usize = 32;

pub const MAX_ACCESSIBILITY_NODES: usize = 1024;

pub const MAX_DOM_NODES: usize = 2048;

/// Hard ceiling applied to individual fragment strings (link text, table
/// cells, node names) inside collections.
pub const MAX_FRAGMENT_BYTES: usize = 4096;
