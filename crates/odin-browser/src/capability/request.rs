//! Argument and identity contracts: the bounded typed-read request, the
//! element selector, and the structural action arguments paired with their
//! canonical digest. These are structural requests only — they carry no
//! authority and assign no effect.

use serde::{Deserialize, Serialize};

use odin_domain::Digest;

use crate::policy::StructuralAction;

use super::error::CapabilityError;
use super::{
    MAX_ACTION_TEXT_BYTES, MAX_KEY_BYTES, MAX_READ_BYTES, MAX_SELECTOR_BYTES, MAX_URL_BYTES,
};

/// The kind of bounded typed read to project from the live page.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReadKind {
    Text,
    Links,
    Tables,
    Accessibility,
    SanitizedDom,
}

/// A bounded typed read request. `max_bytes` is the caller's output bound; it
/// is clamped further by the projection constructors and by session-level
/// configuration.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadRequest {
    pub kind: ReadKind,
    pub max_bytes: u64,
}

impl ReadRequest {
    pub fn new(kind: ReadKind, max_bytes: u64) -> Result<Self, CapabilityError> {
        if max_bytes == 0 {
            return Err(CapabilityError::InvalidRequest {
                reason: "max_bytes must be at least 1".to_owned(),
            });
        }
        if max_bytes > MAX_READ_BYTES {
            return Err(CapabilityError::BoundExceeded {
                limit: MAX_READ_BYTES,
                requested: max_bytes,
            });
        }
        Ok(Self { kind, max_bytes })
    }
}

/// An element selector targeting one node of the live DOM. Opaque to policy:
/// it selects structure, never semantics or sites.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "String")]
pub struct ElementRef {
    pub selector: String,
}

impl ElementRef {
    pub fn new(selector: String) -> Result<Self, CapabilityError> {
        let element = Self { selector };
        element.validate()?;
        Ok(element)
    }

    pub fn validate(&self) -> Result<(), CapabilityError> {
        if self.selector.is_empty() {
            return Err(CapabilityError::InvalidRequest {
                reason: "selector is empty".to_owned(),
            });
        }
        if self.selector.len() > MAX_SELECTOR_BYTES {
            return Err(CapabilityError::BoundExceeded {
                limit: MAX_SELECTOR_BYTES as u64,
                requested: self.selector.len() as u64,
            });
        }
        Ok(())
    }
}

impl TryFrom<String> for ElementRef {
    type Error = CapabilityError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Arguments carried by one action request. Exactly one variant matches each
/// [`StructuralAction`], enforced by [`ActionRequest::new`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum ActionArguments {
    None,
    Url { url: String },
    Selector { selector: ElementRef },
    Fill { selector: ElementRef, text: String },
    Key { key: String },
    Scroll { delta_x: i32, delta_y: i32 },
}

impl ActionArguments {
    fn validate(&self) -> Result<(), CapabilityError> {
        match self {
            Self::None | Self::Scroll { .. } => Ok(()),
            Self::Url { url } => {
                if url.is_empty() {
                    Err(CapabilityError::InvalidRequest {
                        reason: "url is empty".to_owned(),
                    })
                } else if url.len() > MAX_URL_BYTES {
                    Err(CapabilityError::BoundExceeded {
                        limit: MAX_URL_BYTES as u64,
                        requested: url.len() as u64,
                    })
                } else {
                    Ok(())
                }
            }
            Self::Selector { selector } => selector.validate(),
            Self::Fill { selector, text } => {
                selector.validate()?;
                if text.len() > MAX_ACTION_TEXT_BYTES {
                    Err(CapabilityError::BoundExceeded {
                        limit: MAX_ACTION_TEXT_BYTES as u64,
                        requested: text.len() as u64,
                    })
                } else {
                    Ok(())
                }
            }
            Self::Key { key } => {
                if key.is_empty() {
                    Err(CapabilityError::InvalidRequest {
                        reason: "key is empty".to_owned(),
                    })
                } else if key.len() > MAX_KEY_BYTES {
                    Err(CapabilityError::BoundExceeded {
                        limit: MAX_KEY_BYTES as u64,
                        requested: key.len() as u64,
                    })
                } else {
                    Ok(())
                }
            }
        }
    }
}

/// One structural action request: the action plus its arguments. Constructed
/// only through [`ActionRequest::new`], which enforces the action/argument
/// pairing; the canonical arguments digest is computed at construction time
/// and recomputed (never trusted) before journal or worker dispatch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "ActionRequestParts")]
pub struct ActionRequest {
    pub action: StructuralAction,
    pub arguments: ActionArguments,
}

impl ActionRequest {
    pub fn new(
        action: StructuralAction,
        arguments: ActionArguments,
    ) -> Result<Self, CapabilityError> {
        let request = Self { action, arguments };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), CapabilityError> {
        let pairing_ok = matches!(
            (&self.action, &self.arguments),
            (StructuralAction::Navigate, ActionArguments::Url { .. })
                | (
                    StructuralAction::Back
                        | StructuralAction::Forward
                        | StructuralAction::Reload
                        | StructuralAction::Screenshot
                        | StructuralAction::Close,
                    ActionArguments::None,
                )
                | (StructuralAction::Fill, ActionArguments::Fill { .. })
                | (
                    StructuralAction::Activate | StructuralAction::SubmitForm,
                    ActionArguments::Selector { .. },
                )
                | (StructuralAction::PressKey, ActionArguments::Key { .. })
                | (StructuralAction::Scroll, ActionArguments::Scroll { .. })
        );
        if !pairing_ok {
            return Err(CapabilityError::InvalidRequest {
                reason: format!("arguments do not match action {:?}", self.action),
            });
        }
        self.arguments.validate()
    }

    /// BLAKE3 digest over the canonical serialization of (action, arguments).
    /// This is the digest recorded in approvals and re-verified before any
    /// journal write or worker dispatch.
    pub fn canonical_arguments_digest(&self) -> Digest {
        let canonical = serde_json::to_vec(&(&self.action, &self.arguments))
            .expect("ActionRequest serialization is infallible");
        Digest::hash(&canonical)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActionRequestParts {
    action: StructuralAction,
    arguments: ActionArguments,
}

impl TryFrom<ActionRequestParts> for ActionRequest {
    type Error = CapabilityError;

    fn try_from(parts: ActionRequestParts) -> Result<Self, Self::Error> {
        Self::new(parts.action, parts.arguments)
    }
}
