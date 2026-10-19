//! Error vocabulary shared by read projection, action preparation, authority
//! dispatch, and publication paths.

use std::fmt;

use odin_domain::{CapabilityId, Digest, EffectClass};

use super::dispatch::ApprovalScopeMaterial;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityError {
    InvalidRequest {
        reason: String,
    },
    BoundExceeded {
        limit: u64,
        requested: u64,
    },
    DigestMismatch {
        recorded: Digest,
        computed: Digest,
    },
    StaleBinding {
        reason: String,
    },
    PublisherFailure {
        reason: String,
    },
    AuthorityDenied {
        reason: String,
    },
    AuthorityRequired {
        effect_class: EffectClass,
        capability_id: CapabilityId,
        capability_version: u64,
        approval_scope: Box<ApprovalScopeMaterial>,
    },
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest { reason } => write!(formatter, "invalid request: {reason}"),
            Self::BoundExceeded { limit, requested } => {
                write!(
                    formatter,
                    "bound exceeded: requested {requested}, limit {limit}"
                )
            }
            Self::DigestMismatch { recorded, computed } => write!(
                formatter,
                "digest mismatch: recorded {recorded}, computed {computed}"
            ),
            Self::StaleBinding { reason } => write!(formatter, "stale binding: {reason}"),
            Self::PublisherFailure { reason } => write!(formatter, "publisher failure: {reason}"),
            Self::AuthorityDenied { reason } => write!(formatter, "authority denied: {reason}"),
            Self::AuthorityRequired {
                effect_class,
                capability_id,
                capability_version,
                ..
            } => {
                write!(
                    formatter,
                    "approval required for {capability_id} v{capability_version} ({effect_class:?})"
                )
            }
        }
    }
}

impl std::error::Error for CapabilityError {}
