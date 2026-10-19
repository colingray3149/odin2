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
            (Some(target), Some(serde_json::Value::String(actual))) => {
                self.effect_class == EffectClass::R3
                    && self.approval == ApprovalRequirement::Operator
                    && actual == target.as_str()
            }
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
        if capability.effect_class == EffectClass::R3
            && capability.approval_policy != CapabilityApprovalToml::Operator
        {
            return Err(invalid_contract(
                &object.id,
                "R3 capabilities require operator approval",
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
        let handler = handler_binding(&object.id, "handler", capability.handler.as_ref())?;
        let evidence_extractor = handler_binding(
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
            handler: capability.handler.clone().expect("handler present"),
            evidence_extractor: capability
                .evidence_extractor
                .clone()
                .expect("extractor present"),
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

fn handler_binding(
    id: &str,
    field: &'static str,
    binding: Option<&HandlerBindingToml>,
) -> KernelResult<HandlerBinding> {
    let binding = binding.ok_or_else(|| invalid_contract(id, format!("missing {field}")))?;
    binding
        .validate()
        .map_err(|reason| invalid_contract(id, format!("{field} {reason}")))?;
    Ok(match binding {
        HandlerBindingToml::Builtin(builtin) => HandlerBinding::Builtin {
            name: builtin.id.clone(),
        },
        HandlerBindingToml::Exec(exec) => HandlerBinding::Exec {
            executable: exec.executable.clone(),
            argv: exec.argv.clone(),
        },
    })
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
            config: ObjectConfig::Capability(Box::new(CapabilityToml {
                schema: "odin.registry.v1".to_owned(),
                kind: RegistryKind::Capability,
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
            })),
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
    fn accepts_admitted_schema_alias_and_rejects_mismatch() {
        let mut aliased = object();
        aliased.id = "fixture.read".to_owned();
        capability_mut(&mut aliased).input_schema =
            Some("schemas/capability/odin08.fixture.read.input.json".to_owned());
        capability_mut(&mut aliased).output_schema =
            Some("schemas/capability/odin08.fixture.read.output.json".to_owned());
        let contract = try_from_object(&aliased).expect("admitted schema alias is valid");
        assert_eq!(contract.id.as_str(), "fixture.read");
        assert_eq!(
            contract.input_schema_ref,
            "schemas/capability/odin08.fixture.read.input.json"
        );

        let mismatch = object();
        let mut admitted = admitted_of(&mismatch);
        admitted.input_schema = "schemas/capability/other.read.input.json".to_owned();
        let error = CapabilityContract::try_from_registry(&mismatch, &admitted).unwrap_err();
        assert!(
            matches!(&error, KernelError::InvalidContract(message)
                if message.contains("does not match the admitted binding")),
            "unexpected denial: {error}"
        );
    }

    #[test]
    fn rejects_disabled_unimplemented_and_missing_contracts() {
        let mut disabled = object();
        capability_mut(&mut disabled).enabled = false;
        assert!(try_from_object(&disabled).is_err());

        let mut unimplemented = object();
        capability_mut(&mut unimplemented).implementation = Some("unimplemented".to_owned());
        assert!(try_from_object(&unimplemented).is_err());

        let mut missing = object();
        capability_mut(&mut missing).evidence_extractor = None;
        assert!(try_from_object(&missing).is_err());
    }

    #[test]
    fn rejects_generic_schemas_and_accepts_empty_static_argv() {
        let mut generic = object();
        capability_mut(&mut generic).input_schema =
            Some("schemas/capability/generic.input.json".to_owned());
        assert!(try_from_object(&generic).is_err());

        // The record declares a static argv, not a nonempty one: an empty
        // argv is a valid static argument list.
        let mut empty_argv = object();
        capability_mut(&mut empty_argv).handler = Some(HandlerBindingToml::Exec(ExecHandlerToml {
            executable: "/nix/store/q0000000000000000000000000000000-odin/bin/tool".to_owned(),
            argv: Vec::new(),
        }));
        let contract = try_from_object(&empty_argv).unwrap();
        assert_eq!(
            contract.handler,
            HandlerBinding::Exec {
                executable: "/nix/store/q0000000000000000000000000000000-odin/bin/tool".to_owned(),
                argv: Vec::new(),
            }
        );
    }

    #[test]
    fn adapter_health_fails_closed_for_unknown_adapters() {
        let health = AdapterHealth::new(BTreeMap::from([
            ("healthy".to_owned(), true),
            ("failed".to_owned(), false),
        ]));

        assert!(health.is_healthy(None));
        assert!(health.is_healthy(Some("healthy")));
        assert!(!health.is_healthy(Some("failed")));
        assert!(!health.is_healthy(Some("unknown")));
    }

    #[test]
    fn handler_resolution_denial_for_missing_or_malformed_builtin_bindings() {
        let mut missing = object();
        capability_mut(&mut missing).handler = None;
        let error = try_from_object(&missing).unwrap_err();
        assert!(
            matches!(&error, KernelError::InvalidContract(message)
                if message.contains("missing handler")),
            "unexpected denial: {error}"
        );

        for malformed in ["artifact read", "artifact/read", "artifact;read", ""] {
            let mut invalid = object();
            capability_mut(&mut invalid).handler =
                Some(HandlerBindingToml::Builtin(BuiltinHandlerToml {
                    id: malformed.to_owned(),
                }));
            let error = try_from_object(&invalid).unwrap_err();
            assert!(
                matches!(&error, KernelError::InvalidContract(message)
                    if message.contains("handler builtin handler id")),
                "builtin id {malformed:?} was not denied: {error}"
            );
        }

        let mut missing_extractor = object();
        capability_mut(&mut missing_extractor).evidence_extractor = None;
        let error = try_from_object(&missing_extractor).unwrap_err();
        assert!(
            matches!(&error, KernelError::InvalidContract(message)
                if message.contains("missing evidence_extractor")),
            "unexpected denial: {error}"
        );
    }

    #[test]
    fn handler_resolution_denial_for_invalid_exec_bindings() {
        let invalid_exec_bindings = [
            (
                "relative executable",
                "bin/extract-artifact",
                vec!["--json".to_owned()],
            ),
            (
                "traversing executable",
                "/nix/store/../extract-artifact",
                vec!["--json".to_owned()],
            ),
            (
                "whitespace in executable",
                "/nix/store/x-tool/bin/extract artifact",
                vec!["--json".to_owned()],
            ),
            (
                "shell syntax in argv",
                "/nix/store/q0000000000000000000000000000000-odin/bin/extract-artifact",
                vec!["--json;rm".to_owned()],
            ),
            (
                "whitespace in argv element",
                "/nix/store/q0000000000000000000000000000000-odin/bin/extract-artifact",
                vec!["--json extra".to_owned()],
            ),
            (
                "empty argv element",
                "/nix/store/q0000000000000000000000000000000-odin/bin/extract-artifact",
                vec![String::new()],
            ),
        ];
        for (label, executable, argv) in invalid_exec_bindings {
            let mut invalid = object();
            capability_mut(&mut invalid).evidence_extractor =
                Some(HandlerBindingToml::Exec(ExecHandlerToml {
                    executable: executable.to_owned(),
                    argv,
                }));
            let error = try_from_object(&invalid).unwrap_err();
            assert!(
                matches!(&error, KernelError::InvalidContract(message)
                    if message.contains("evidence_extractor")),
                "{label} was not denied through the evidence extractor: {error}"
            );
        }

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

    #[test]
    fn preview_and_batch_fields_load_onto_the_contract() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../registry/capabilities");
        let load = |id: &str| {
            let path = root.join(id).join("capability.toml");
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            let object = odin_registry::schema::parse_object_toml(
                RegistryKind::Capability,
                id,
                format!("registry/capabilities/{id}/capability.toml"),
                &source,
            )
            .unwrap_or_else(|finding| panic!("parse {id}: {finding:?}"));
            try_from_object(&object).unwrap_or_else(|error| panic!("load {id}: {error}"))
        };
        let email = load("email.send");
        assert!(email.batchable);
        assert_eq!(
            email.preview,
            Some(odin_registry::schema::PreviewKindToml::Email)
        );
        let browser = load("browser.consequential");
        assert!(browser.batchable);
        assert_eq!(
            browser.preview,
            Some(odin_registry::schema::PreviewKindToml::Browser)
        );
        let grant = load("task.grant");
        assert_eq!(
            grant.preview,
            Some(odin_registry::schema::PreviewKindToml::Batch)
        );
        let limits = grant.batch.expect("task.grant declares batch limits");
        assert_eq!(limits.max_effects, 16);
        assert_eq!(limits.max_minutes, 1440);
        assert_eq!(limits.max_uses, 500);
    }
}
