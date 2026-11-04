use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use odin_browser::safety::{ProtectedValue, ProtectedValues};
use odin_browser::{ActionRule, BrowserPolicySnapshot, StructuralAction};
use odin_domain::huginn as live;
use odin_domain::{CapabilityId, EffectClass};
use odin_registry::schema::CapabilityApprovalToml;
use odin_registry::{ObjectConfig, RegistryObject};
use serde::Deserialize;

use super::launch::BrowserRuntimeError;

const POLICY_FILE_MAX_BYTES: u64 = 1024 * 1024;
const PROTECTED_VALUES_FILE_MAX_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserPolicyInput {
    pub session_id: live::BrowserSessionId,
    pub rules: BTreeMap<StructuralAction, BrowserPolicyRuleInput>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserPolicyRuleInput {
    pub capability_id: CapabilityId,
    pub capability_version: u64,
    pub effect_class: EffectClass,
    pub approval_required: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtectedValueInput {
    pub label: String,
    pub value: String,
}

pub(super) fn load_policy_input(path: &Path) -> Result<BrowserPolicyInput, BrowserRuntimeError> {
    read_json_file(path, POLICY_FILE_MAX_BYTES)
        .map_err(|error| BrowserRuntimeError::PolicyRead(format!("{}: {error}", path.display())))
}

pub(super) fn policy_from_input(
    input: BrowserPolicyInput,
    registry: &[RegistryObject],
) -> Result<BrowserPolicySnapshot, BrowserRuntimeError> {
    let mut rules = BTreeMap::new();
    for (action, input_rule) in input.rules {
        validate_registry_capability(
            registry,
            &input_rule.capability_id,
            input_rule.capability_version,
            input_rule.effect_class,
            input_rule.approval_required,
        )
        .map_err(|error| BrowserRuntimeError::PolicyCapability(format!("{action:?}: {error}")))?;
        rules.insert(
            action,
            ActionRule {
                capability_id: input_rule.capability_id,
                capability_version: input_rule.capability_version,
                effect_class: input_rule.effect_class,
                approval_required: input_rule.approval_required,
            },
        );
    }
    BrowserPolicySnapshot::initial(input.session_id, rules)
        .map_err(|error| BrowserRuntimeError::PolicyInvalid(error.to_string()))
}

pub(super) fn validate_registry_capability(
    registry: &[RegistryObject],
    capability_id: &CapabilityId,
    version: u64,
    effect_class: EffectClass,
    approval_required: bool,
) -> Result<(), String> {
    let capability = registry.iter().find_map(|object| {
        if object.id != capability_id.as_str() || !object.enters_listing() {
            return None;
        }
        match &object.config {
            ObjectConfig::Capability(capability) => Some(capability.as_ref()),
            _ => None,
        }
    });
    let Some(capability) = capability else {
        return Err(format!(
            "capability {capability_id} is not in the registry listing"
        ));
    };
    let registry_requires_approval = capability.approval_policy == CapabilityApprovalToml::Operator;
    if u64::from(capability.version) != version {
        return Err(format!(
            "capability {capability_id} is version {}, not {version}",
            capability.version
        ));
    }
    if !rule_within_capability_envelope(
        effect_class,
        approval_required,
        capability.effect_class,
        registry_requires_approval,
    ) {
        return Err(format!(
            "rule {effect_class:?} (approval {approval_required}) exceeds capability {capability_id}'s envelope"
        ));
    }
    Ok(())
}

fn rule_within_capability_envelope(
    rule_effect: EffectClass,
    rule_approval_required: bool,
    capability_effect: EffectClass,
    capability_approval_required: bool,
) -> bool {
    rule_effect <= capability_effect && (!capability_approval_required || rule_approval_required)
}

pub(super) fn load_protected_values(path: &Path) -> Result<ProtectedValues, BrowserRuntimeError> {
    let read_error = |error: std::io::Error| {
        BrowserRuntimeError::ProtectedValuesRead(format!("{}: {error}", path.display()))
    };
    let mut file = File::open(path).map_err(read_error)?;
    let metadata = file.metadata().map_err(read_error)?;
    if !metadata.is_file() || metadata.mode() & 0o7777 != 0o600 {
        return Err(BrowserRuntimeError::ProtectedValuesPermissions);
    }
    if metadata.len() > PROTECTED_VALUES_FILE_MAX_BYTES {
        return Err(BrowserRuntimeError::ProtectedValuesInvalid(format!(
            "{} is larger than {PROTECTED_VALUES_FILE_MAX_BYTES} bytes",
            path.display()
        )));
    }
    let mut limited = (&mut file).take(PROTECTED_VALUES_FILE_MAX_BYTES + 1);
    // The serde message can quote a value, so only its position is kept.
    let inputs: Vec<ProtectedValueInput> =
        serde_json::from_reader(&mut limited).map_err(|error| {
            BrowserRuntimeError::ProtectedValuesInvalid(format!(
                "not a JSON list of label/value objects (line {}, column {})",
                error.line(),
                error.column()
            ))
        })?;
    let values = inputs
        .into_iter()
        .map(|input| ProtectedValue::new(input.label, input.value.into_bytes()))
        .collect();
    ProtectedValues::new(values)
        .map_err(|error| BrowserRuntimeError::ProtectedValuesInvalid(error.to_string()))
}

fn read_json_file<T: for<'de> Deserialize<'de>>(path: &Path, limit: u64) -> Result<T, String> {
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(format!("not a regular file of at most {limit} bytes"));
    }
    let mut limited = (&mut file).take(limit + 1);
    serde_json::from_reader(&mut limited).map_err(|error| error.to_string())
}

#[cfg(test)]
mod policy_tests {
    use super::{rule_within_capability_envelope, EffectClass};

    #[test]
    fn stronger_action_and_approval_downgrade_are_rejected() {
        assert!(!rule_within_capability_envelope(
            EffectClass::R3,
            true,
            EffectClass::R2,
            true,
        ));
        assert!(!rule_within_capability_envelope(
            EffectClass::R2,
            false,
            EffectClass::R2,
            true,
        ));
    }
}
