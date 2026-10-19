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
    read_json_file(path, POLICY_FILE_MAX_BYTES).map_err(|_| BrowserRuntimeError::PolicyRead)
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
        .map_err(|_| BrowserRuntimeError::PolicyCapability)?;
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
        .map_err(|_| BrowserRuntimeError::PolicyInvalid)
}

pub(super) fn validate_registry_capability(
    registry: &[RegistryObject],
    capability_id: &CapabilityId,
    version: u64,
    effect_class: EffectClass,
    approval_required: bool,
) -> Result<(), ()> {
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
        return Err(());
    };
    let registry_requires_approval = capability.approval_policy == CapabilityApprovalToml::Operator;
    if u64::from(capability.version) != version
        || !rule_within_capability_envelope(
            effect_class,
            approval_required,
            capability.effect_class,
            registry_requires_approval,
        )
    {
        return Err(());
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
    let mut file = File::open(path).map_err(|_| BrowserRuntimeError::ProtectedValuesRead)?;
    let metadata = file
        .metadata()
        .map_err(|_| BrowserRuntimeError::ProtectedValuesRead)?;
    if !metadata.is_file() || metadata.mode() & 0o7777 != 0o600 {
        return Err(BrowserRuntimeError::ProtectedValuesPermissions);
    }
    if metadata.len() > PROTECTED_VALUES_FILE_MAX_BYTES {
        return Err(BrowserRuntimeError::ProtectedValuesInvalid);
    }
    let mut limited = (&mut file).take(PROTECTED_VALUES_FILE_MAX_BYTES + 1);
    let inputs: Vec<ProtectedValueInput> = serde_json::from_reader(&mut limited)
        .map_err(|_| BrowserRuntimeError::ProtectedValuesInvalid)?;
    let values = inputs
        .into_iter()
        .map(|input| ProtectedValue::new(input.label, input.value.into_bytes()))
        .collect();
    ProtectedValues::new(values).map_err(|_| BrowserRuntimeError::ProtectedValuesInvalid)
}

fn read_json_file<T: for<'de> Deserialize<'de>>(path: &Path, limit: u64) -> Result<T, ()> {
    let mut file = File::open(path).map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(());
    }
    let mut limited = (&mut file).take(limit + 1);
    serde_json::from_reader(&mut limited).map_err(|_| ())
}

#[cfg(test)]
mod policy_tests {
    use super::{rule_within_capability_envelope, EffectClass};

    #[test]
    fn get_r0_and_dialog_r2_fit_conservative_capability_envelopes() {
        assert!(rule_within_capability_envelope(
            EffectClass::R0,
            false,
            EffectClass::R2,
            false,
        ));
        assert!(rule_within_capability_envelope(
            EffectClass::R2,
            true,
            EffectClass::R3,
            true,
        ));
    }

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

    #[test]
    fn r3_post_envelope_keeps_its_approval_floor() {
        assert!(rule_within_capability_envelope(
            EffectClass::R3,
            true,
            EffectClass::R3,
            true,
        ));
        assert!(!rule_within_capability_envelope(
            EffectClass::R3,
            false,
            EffectClass::R3,
            true,
        ));
    }
}
