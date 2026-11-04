use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;

use odin_domain::knowledge::context::{ToolName, ToolSchema};
use odin_domain::{CapabilityId, EffectClass};
use odin_registry::relational::AdmittedBinding;
use odin_registry::schema::{
    BatchLimitsToml, CapabilityApprovalToml, CapabilityIdempotencyToml, HandlerBindingToml,
    ObjectConfig, PreviewKindToml,
};
use odin_registry::RegistryObject;

use crate::error::{KernelError, KernelResult};

/// Structured bindings avoid ambiguous executable and argument splitting.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HandlerBinding {
    Builtin {
        name: String,
    },
    Exec {
        executable: String,
        argv: Vec<String>,
    },
}

impl HandlerBinding {
    /// Length-prefix each UTF-8 part to prevent separator collisions in canonical keys.
    pub fn canonical_key(&self) -> String {
        fn part(out: &mut String, raw: &str) {
            out.push_str(&(raw.len() as u64).to_string());
            out.push(':');
            out.push_str(raw);
        }
        let mut out = String::new();
        match self {
            Self::Builtin { name } => {
                out.push_str("builtin:");
                part(&mut out, name);
            }
            Self::Exec { executable, argv } => {
                out.push_str("exec:");
                part(&mut out, executable);
                out.push_str(&(argv.len() as u64).to_string());
                out.push(':');
                for item in argv {
                    part(&mut out, item);
                }
            }
        }
        out
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdempotencyPolicy {
    Pure,
    Required,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalRequirement {
    None,
    Operator,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryPolicy {
    pub max_attempts: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityContract {
    pub id: CapabilityId,
    pub version: u16,
    pub tool_name: ToolName,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub toolset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expose: Option<odin_registry::schema::CapabilityExposureToml>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub seat_ops: BTreeMap<odin_domain::SeatId, odin_registry::schema::CapabilitySeatOpToml>,
    pub handler: HandlerBinding,
    pub input_schema_ref: String,
    pub output_schema_ref: String,
    pub effect_class: EffectClass,
    pub seat_tags: BTreeSet<String>,
    pub timeout_seconds: NonZeroU32,
    pub idempotency: IdempotencyPolicy,
    pub retry: RetryPolicy,
    pub approval: ApprovalRequirement,
    pub evidence_extractor: HandlerBinding,
    pub adapter: Option<String>,
    /// Exact-effect preview the owner must see before consent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<PreviewKindToml>,
    /// A grant batch may name this capability.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub batchable: bool,
    /// Bounds of one grant batch. Present only on the grant capability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch: Option<BatchLimitsToml>,
    /// Exact declared delegation target; never selected by model arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegate_to: Option<odin_domain::SeatId>,
}

pub trait SchemaCatalog {
    fn schema(&self, reference: &str) -> KernelResult<ToolSchema>;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AdapterHealth {
    pub adapters: BTreeMap<String, bool>,
}

impl AdapterHealth {
    pub fn new(adapters: BTreeMap<String, bool>) -> Self {
        Self { adapters }
    }

    pub fn is_healthy(&self, adapter: Option<&str>) -> bool {
        adapter.is_none_or(|adapter| self.adapters.get(adapter).copied().unwrap_or(false))
    }
}

impl CapabilityContract {
    /// Host-derived routing metadata included in approval and operation digests.
    pub const DELEGATION_TARGET_ARGUMENT: &'static str = "_delegate_to";

    pub(crate) fn arguments_bind_declared_target(&self, arguments: &serde_json::Value) -> bool {
        match (
            &self.delegate_to,
            arguments.get(Self::DELEGATION_TARGET_ARGUMENT),
        ) {
            (None, None) => true,
            (Some(target), Some(serde_json::Value::String(actual))) => actual == target.as_str(),
            _ => false,
        }
    }

    pub fn try_from_registry(
        object: &RegistryObject,
        admitted: &AdmittedBinding,
    ) -> KernelResult<Self> {
        let ObjectConfig::Capability(capability) = &object.config else {
            return Err(invalid_contract(&object.id, "object is not a capability"));
        };
        if !capability.enabled {
            return Err(invalid_contract(&object.id, "capability is disabled"));
        }
        if capability.version == 0 {
            return Err(invalid_contract(&object.id, "version must be positive"));
        }
        if capability.description.trim().is_empty() {
            return Err(invalid_contract(
                &object.id,
                "description must not be empty",
            ));
        }
        if capability.retry.max_attempts > 10 {
            return Err(invalid_contract(
                &object.id,
                "retry max_attempts must not exceed 10",
            ));
        }
        if capability.delegate_to.is_some() && capability.effect_class != EffectClass::R3 {
            return Err(invalid_contract(
                &object.id,
                "delegation capabilities require R3",
            ));
        }

        let implementation = required(&object.id, "implementation", &capability.implementation)?;
        if implementation == "unimplemented" {
            return Err(invalid_contract(&object.id, "capability is unimplemented"));
        }
        let (handler_toml, handler) =
            handler_binding(&object.id, "handler", capability.handler.as_ref())?;
        let (extractor_toml, evidence_extractor) = handler_binding(
            &object.id,
            "evidence_extractor",
            capability.evidence_extractor.as_ref(),
        )?;
        let input_schema_ref = required(&object.id, "input_schema", &capability.input_schema)?;
        let output_schema_ref = required(&object.id, "output_schema", &capability.output_schema)?;
        let declared = AdmittedBinding {
            version: capability.version,
            input_schema: input_schema_ref.to_owned(),
            output_schema: output_schema_ref.to_owned(),
            handler: handler_toml.clone(),
            evidence_extractor: extractor_toml.clone(),
        };
        if &declared != admitted {
            return Err(invalid_contract(
                &object.id,
                "declaration does not match the admitted binding",
            ));
        }
        validate_schema_ref(
            &object.id,
            input_schema_ref,
            &admitted.input_schema,
            "input",
        )?;
        validate_schema_ref(
            &object.id,
            output_schema_ref,
            &admitted.output_schema,
            "output",
        )?;
        if input_schema_ref == output_schema_ref {
            return Err(invalid_contract(
                &object.id,
                "input and output schema references must be distinct",
            ));
        }
        if capability.seat_tags.is_empty() {
            return Err(invalid_contract(&object.id, "seat_tags must not be empty"));
        }

        let id = CapabilityId::new(object.id.clone())?;
        let tool_name = ToolName::new(
            object
                .id
                .chars()
                .map(|character| match character {
                    '.' | ':' => '_',
                    other => other,
                })
                .collect::<String>(),
        )?;

        Ok(Self {
            id,
            version: capability.version,
            tool_name,
            description: capability.description.clone(),
            toolset: capability.toolset.clone(),
            op: capability.op.clone(),
            expose: capability.expose,
            seat_ops: capability.seat_ops.clone(),
            delegate_to: capability.delegate_to.clone(),
            handler,
            input_schema_ref: input_schema_ref.to_owned(),
            output_schema_ref: output_schema_ref.to_owned(),
            effect_class: capability.effect_class,
            seat_tags: capability.seat_tags.clone(),
            timeout_seconds: capability.timeout_seconds,
            idempotency: match capability.idempotency {
                CapabilityIdempotencyToml::Pure => IdempotencyPolicy::Pure,
                CapabilityIdempotencyToml::Required => IdempotencyPolicy::Required,
            },
            retry: RetryPolicy {
                max_attempts: capability.retry.max_attempts,
            },
            approval: match capability.approval_policy {
                CapabilityApprovalToml::None => ApprovalRequirement::None,
                CapabilityApprovalToml::Operator => ApprovalRequirement::Operator,
            },
            evidence_extractor,
            adapter: capability.adapter_implementation().map(str::to_owned),
            preview: capability.preview,
            batchable: capability.batchable,
            batch: capability.batch,
        })
    }
}

fn required<'a>(id: &str, field: &'static str, value: &'a Option<String>) -> KernelResult<&'a str> {
    value
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| invalid_contract(id, format!("missing {field}")))
}

/// The declared binding and its validated form.
fn handler_binding<'a>(
    id: &str,
    field: &'static str,
    binding: Option<&'a HandlerBindingToml>,
) -> KernelResult<(&'a HandlerBindingToml, HandlerBinding)> {
    let binding = binding.ok_or_else(|| invalid_contract(id, format!("missing {field}")))?;
    binding
        .validate()
        .map_err(|reason| invalid_contract(id, format!("{field} {reason}")))?;
    let validated = match binding {
        HandlerBindingToml::Builtin(builtin) => HandlerBinding::Builtin {
            name: builtin.id.clone(),
        },
        HandlerBindingToml::Exec(exec) => HandlerBinding::Exec {
            executable: exec.executable.clone(),
            argv: exec.argv.clone(),
        },
    };
    Ok((binding, validated))
}

fn validate_schema_ref(
    logical_id: &str,
    reference: &str,
    admitted: &str,
    direction: &str,
) -> KernelResult<()> {
    if reference != admitted {
        return Err(invalid_contract(
            logical_id,
            format!("{direction} schema does not match the admitted binding"),
        ));
    }
    let lower = reference.to_ascii_lowercase();
    if lower.contains("generic") {
        return Err(invalid_contract(
            logical_id,
            format!("{direction} schema must not be generic"),
        ));
    }
    if reference.starts_with('/')
        || reference.split('/').any(|component| component == "..")
        || !reference.starts_with("schemas/capability/")
    {
        return Err(invalid_contract(
            logical_id,
            format!("{direction} schema must be a dedicated capability schema reference"),
        ));
    }
    let suffix = format!(".{direction}.json");
    if !reference.ends_with(&suffix) {
        return Err(invalid_contract(
            logical_id,
            format!("{direction} schema must end in {suffix}"),
        ));
    }
    Ok(())
}

fn invalid_contract(id: &str, reason: impl std::fmt::Display) -> KernelError {
    KernelError::InvalidContract(format!("{id}: {reason}"))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use odin_registry::schema::{
        BuiltinHandlerToml, CapabilityApprovalToml, CapabilityToml, ExecHandlerToml,
        HandlerBindingToml, RegistryKind, RetryToml,
    };

    use super::*;

    fn object() -> RegistryObject {
        RegistryObject {
            id: "artifact.read".to_owned(),
            relative_config: PathBuf::from("registry/capabilities/artifact.read/capability.toml"),
            config: ObjectConfig::Capability(Box::new(CapabilityToml { schema: "odin.registry.v1".to_owned(), toolset: None, op: None, expose: None, seat_ops: Default::default(), kind: RegistryKind::Capability,
            enabled: true,
            implementation: Some("builtin".to_owned()),
            version: 1,
            description: "Read one artifact".to_owned(),
            handler: Some(HandlerBindingToml::Builtin(BuiltinHandlerToml {
                id: "artifact_read".to_owned(),
            })),
            delegate_to: None,
            input_schema: Some("schemas/capability/artifact.read.input.json".to_owned()),
            output_schema: Some("schemas/capability/artifact.read.output.json".to_owned()),
            effect_class: EffectClass::R0,
            seat_tags: BTreeSet::from(["operator".to_owned()]),
            timeout_seconds: NonZeroU32::new(30).unwrap(),
            idempotency: CapabilityIdempotencyToml::Pure,
            retry: RetryToml { max_attempts: 2 },
            approval_policy: CapabilityApprovalToml::None,
            approval_decider: Default::default(),
            preview: None,
            batchable: false,
            batch: None,
            evidence_extractor: Some(HandlerBindingToml::Exec(ExecHandlerToml {
                executable:
                    "/nix/store/q0000000000000000000000000000000-odin-artifact/bin/extract-artifact"
                        .to_owned(),
                argv: vec!["--json".to_owned()],
            })),
            exec: None, tests: Vec::new(), probes: Vec::new() })),
        }
    }

    fn capability_mut(object: &mut RegistryObject) -> &mut CapabilityToml {
        let ObjectConfig::Capability(capability) = &mut object.config else {
            panic!("fixture must be a capability");
        };
        capability
    }

    fn admitted_of(object: &RegistryObject) -> AdmittedBinding {
        let ObjectConfig::Capability(capability) = &object.config else {
            panic!("fixture must be a capability");
        };
        odin_registry::relational::declared_admitted_binding(capability).unwrap_or(
            AdmittedBinding {
                version: capability.version,
                input_schema: capability.input_schema.clone().unwrap_or_default(),
                output_schema: capability.output_schema.clone().unwrap_or_default(),
                handler: capability.handler.clone().unwrap_or_else(|| {
                    HandlerBindingToml::Builtin(BuiltinHandlerToml {
                        id: "absent".to_owned(),
                    })
                }),
                evidence_extractor: capability.evidence_extractor.clone().unwrap_or_else(|| {
                    HandlerBindingToml::Builtin(BuiltinHandlerToml {
                        id: "absent".to_owned(),
                    })
                }),
            },
        )
    }

    fn try_from_object(object: &RegistryObject) -> KernelResult<CapabilityContract> {
        CapabilityContract::try_from_registry(object, &admitted_of(object))
    }

    #[test]
    fn converts_complete_enabled_contract() {
        let contract = try_from_object(&object()).unwrap();

        assert_eq!(contract.id.as_str(), "artifact.read");
        assert_eq!(contract.tool_name.as_str(), "artifact_read");
        assert_eq!(
            contract.handler,
            HandlerBinding::Builtin {
                name: "artifact_read".to_owned()
            }
        );
        assert_eq!(
            contract.evidence_extractor,
            HandlerBinding::Exec {
                executable:
                    "/nix/store/q0000000000000000000000000000000-odin-artifact/bin/extract-artifact"
                        .to_owned(),
                argv: vec!["--json".to_owned()]
            }
        );
        assert_eq!(contract.idempotency, IdempotencyPolicy::Pure);
        assert_eq!(contract.retry.max_attempts, 2);
        assert_eq!(contract.approval, ApprovalRequirement::None);
        assert_eq!(contract.adapter, None);
    }

    #[test]
    fn an_invalid_exec_binding_is_denied_through_its_field_and_a_valid_one_loads() {
        let mut invalid = object();
        capability_mut(&mut invalid).evidence_extractor =
            Some(HandlerBindingToml::Exec(ExecHandlerToml {
                executable: "bin/extract-artifact".to_owned(),
                argv: vec!["--json".to_owned()],
            }));
        let error = try_from_object(&invalid).unwrap_err();
        assert!(
            matches!(&error, KernelError::InvalidContract(message)
                if message.contains("evidence_extractor")),
            "not denied through the evidence extractor: {error}"
        );

        let mut valid_exec = object();
        capability_mut(&mut valid_exec).evidence_extractor =
            Some(HandlerBindingToml::Exec(ExecHandlerToml {
                executable: "/nix/store/q0000000000000000000000000000000-odin/bin/extract"
                    .to_owned(),
                argv: vec!["--framed".to_owned(), "--json".to_owned()],
            }));
        let contract = try_from_object(&valid_exec).unwrap();
        assert_eq!(
            contract.evidence_extractor,
            HandlerBinding::Exec {
                executable: "/nix/store/q0000000000000000000000000000000-odin/bin/extract"
                    .to_owned(),
                argv: vec!["--framed".to_owned(), "--json".to_owned()],
            }
        );
    }
}
