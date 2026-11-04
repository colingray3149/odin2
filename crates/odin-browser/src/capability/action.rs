//! Consequential action contracts: structural facts, mechanical activation
//! preflight, and the policy and DOM bindings a dispatch is checked against.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use odin_domain::Digest;

use crate::policy::{BrowserPolicySnapshot, StructuralAction};

use super::error::CapabilityError;

/// Structural facts about one target element observed in the DOM. Facts only:
/// no risk, no effect, no site semantics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElementStructure {
    pub tag: String,
    pub input_type: Option<String>,
    pub in_form: bool,
}

/// Mechanical classification of what activating a target would do
/// structurally. This is DOM semantics only — the higher API alone decides
/// what it means.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ActivationStructure {
    Ordinary,
    FormSubmission,
}

/// Preflight: distinguish form submission from ordinary activation from
/// target structure. Never assigns effect class or risk.
pub fn classify_activation(target: Option<&ElementStructure>) -> ActivationStructure {
    let Some(target) = target else {
        return ActivationStructure::Ordinary;
    };
    let tag = target.tag.to_ascii_lowercase();
    let input_type = target
        .input_type
        .as_deref()
        .map(|value| value.to_ascii_lowercase());
    let submits_form = match (tag.as_str(), input_type.as_deref()) {
        ("input", Some("submit") | Some("image")) if target.in_form => true,
        ("button", None | Some("submit")) if target.in_form => true,
        _ => false,
    };
    if submits_form {
        ActivationStructure::FormSubmission
    } else {
        ActivationStructure::Ordinary
    }
}

/// The structural descriptor bound into a prepared action: the structural
/// action, the mechanical activation classification, and the observed target
/// facts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StructuralDescriptor {
    pub action: StructuralAction,
    pub activation: ActivationStructure,
    pub target: Option<ElementStructure>,
}

impl StructuralDescriptor {
    pub fn new(
        action: StructuralAction,
        target: Option<ElementStructure>,
    ) -> Result<Self, CapabilityError> {
        let activation = match action {
            StructuralAction::Activate => classify_activation(target.as_ref()),
            StructuralAction::SubmitForm => ActivationStructure::FormSubmission,
            _ => ActivationStructure::Ordinary,
        };
        Ok(Self {
            action,
            activation,
            target,
        })
    }

    pub fn validate(&self) -> Result<(), CapabilityError> {
        let expected = match self.action {
            StructuralAction::Activate => classify_activation(self.target.as_ref()),
            StructuralAction::SubmitForm => ActivationStructure::FormSubmission,
            _ => ActivationStructure::Ordinary,
        };
        if self.activation != expected {
            return Err(CapabilityError::InvalidRequest {
                reason: format!(
                    "activation {:?} does not match structural action {:?}",
                    self.activation, self.action
                ),
            });
        }
        Ok(())
    }
}

/// The policy (revision, digest) a prepared action is bound to. Stale the
/// moment the session policy moves.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyBinding {
    pub revision: u64,
    pub digest: Digest,
}

impl PolicyBinding {
    pub fn of(snapshot: &BrowserPolicySnapshot) -> Self {
        Self {
            revision: snapshot.revision(),
            digest: snapshot.digest(),
        }
    }

    pub fn validate(&self) -> Result<(), CapabilityError> {
        if self.revision == 0 {
            return Err(CapabilityError::InvalidRequest {
                reason: "policy revision must be at least 1".to_owned(),
            });
        }
        Ok(())
    }

    pub fn matches(&self, snapshot: &BrowserPolicySnapshot) -> bool {
        self.revision == snapshot.revision() && self.digest == snapshot.digest()
    }
}

/// The DOM snapshot a prepared action was validated against. Execution
/// revalidates this binding before dispatch; a changed document digest means
/// the binding is stale.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomBinding {
    pub document_digest: Digest,
    pub observed_at: OffsetDateTime,
}
