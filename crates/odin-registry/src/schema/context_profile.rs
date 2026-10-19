//! Share context sizes across seats and pods; inject epoch context only at startup and after compaction.

use std::num::{NonZeroU16, NonZeroU32};

use serde::{Deserialize, Serialize};

use super::object::RegistryKind;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextProfileToml {
    pub schema: String,
    pub kind: RegistryKind,
    pub enabled: bool,
    pub description: String,
    /// Core memory carried in the system prompt from session open.
    pub core_tokens: NonZeroU32,
    /// Brain context injected at session start and after compaction.
    pub inject_tokens: NonZeroU32,
    /// How many retrieved items (a pod's memory facts) one epoch carries.
    pub inject_k: NonZeroU16,
    /// Zero disables per-turn context injection.
    #[serde(default)]
    pub per_turn_tokens: u32,
}

impl ContextProfileToml {
    pub fn check(&self) -> Result<(), String> {
        if self.per_turn_tokens > self.inject_tokens.get() {
            return Err("per_turn_tokens exceeds inject_tokens".into());
        }
        Ok(())
    }
}

pub fn context_profiles(
    objects: &[crate::RegistryObject],
) -> std::collections::BTreeMap<&str, &ContextProfileToml> {
    objects
        .iter()
        .filter_map(|object| match &object.config {
            super::ObjectConfig::ContextProfile(profile) => {
                Some((object.id.as_str(), profile.as_ref()))
            }
            _ => None,
        })
        .collect()
}

impl ContextProfileToml {
    pub fn sized(core_tokens: NonZeroU32, inject_tokens: NonZeroU32) -> Self {
        Self {
            schema: super::REGISTRY_SCHEMA.to_owned(),
            kind: RegistryKind::ContextProfile,
            enabled: true,
            description: "Sized context profile.".to_owned(),
            core_tokens,
            inject_tokens,
            inject_k: NonZeroU16::new(8).expect("eight is non-zero"),
            per_turn_tokens: 0,
        }
    }
}
