use std::path::PathBuf;

use crate::schema::{
    CapabilityToml, HandlerBindingToml, RegistryObject, ADAPTER_OPERATION_HANDLER_ID,
    ADAPTER_RECEIPT_EVIDENCE_ID,
};
use crate::RegistryFinding;

use super::paths::relation_failure;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationContext {
    pub odin_root: PathBuf,
    pub schemas_root: PathBuf,
    /// None performs structural checks; Some requires exact admitted tuples, and an empty set admits nothing.
    pub admitted_bindings: Option<Vec<AdmittedBinding>>,
}

impl RelationContext {
    pub fn new(odin_root: impl Into<PathBuf>) -> Self {
        let odin_root = odin_root.into();
        let schemas_root = odin_root.join("schemas");
        Self {
            odin_root,
            schemas_root,
            admitted_bindings: None,
        }
    }

    pub fn with_admitted_bindings(
        mut self,
        bindings: impl IntoIterator<Item = AdmittedBinding>,
    ) -> Result<Self, RegistryFinding> {
        let mut ordered = Vec::new();
        for binding in bindings {
            if ordered.iter().any(|existing| existing == &binding) {
                return Err(RegistryFinding::fail(
                    "registry-broken-relation",
                    "registry/capabilities",
                    "duplicate admitted binding tuple",
                ));
            }
            ordered.push(binding);
        }
        self.admitted_bindings = Some(ordered);
        Ok(self)
    }
}

/// Match handler, schema, and version rather than the logical capability ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedBinding {
    pub version: u16,
    pub input_schema: String,
    pub output_schema: String,
    pub handler: HandlerBindingToml,
    pub evidence_extractor: HandlerBindingToml,
}
impl AdmittedBinding {
    /// Select builtins by handler ID and executable tuples by canonical digest.
    pub fn binding_id(&self) -> Result<String, serde_json::Error> {
        match &self.handler {
            HandlerBindingToml::Builtin(binding) => Ok(binding.id.clone()),
            HandlerBindingToml::Exec(_) => {
                let bytes = serde_json::to_vec(&(
                    self.version,
                    &self.input_schema,
                    &self.output_schema,
                    &self.handler,
                    &self.evidence_extractor,
                ))?;
                Ok(format!("binding-{}", blake3::hash(&bytes).to_hex()))
            }
        }
    }
}

/// Match the full tuple rather than using the logical capability ID as an admission key.
pub(super) fn validate_production_binding(
    object: &RegistryObject,
    capability: &CapabilityToml,
    context: &RelationContext,
    findings: &mut Vec<RegistryFinding>,
) {
    // Adapter capabilities require reserved markers; dispatch checks the adapter descriptor.
    match (
        capability.adapter_implementation(),
        capability.binds_adapter_markers(),
    ) {
        (Some(adapter), false) => {
            findings.push(relation_failure(
                object,
                format!(
                    "capability {} is implemented by adapter {adapter:?} and must bind handler \
                     {{ id = \"{ADAPTER_OPERATION_HANDLER_ID}\" }} and evidence_extractor \
                     {{ id = \"{ADAPTER_RECEIPT_EVIDENCE_ID}\" }}",
                    object.id
                ),
            ));
            return;
        }
        (Some(_), true) => return,
        (None, true) => {
            findings.push(relation_failure(
                object,
                format!(
                    "capability {} binds the declared-adapter markers but its implementation \
                     names no adapter",
                    object.id
                ),
            ));
            return;
        }
        (None, false) => {}
    }
    if context.admitted_bindings.is_none() {
        return;
    }
    if match_admitted_binding(capability, context).is_none() {
        findings.push(relation_failure(
            object,
            format!(
                "enabled capability {} has no compiled production HostTool binding",
                object.id
            ),
        ));
    }
}

pub fn declared_admitted_binding(capability: &CapabilityToml) -> Option<AdmittedBinding> {
    Some(AdmittedBinding {
        version: capability.version,
        input_schema: capability.input_schema.clone()?,
        output_schema: capability.output_schema.clone()?,
        handler: capability.handler.clone()?,
        evidence_extractor: capability.evidence_extractor.clone()?,
    })
}

pub(super) fn match_admitted_binding<'a>(
    capability: &CapabilityToml,
    context: &'a RelationContext,
) -> Option<&'a AdmittedBinding> {
    let declared = declared_admitted_binding(capability)?;
    context
        .admitted_bindings
        .as_ref()?
        .iter()
        .find(|admitted| *admitted == &declared)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use crate::relational::fixtures::{
        admitted_binding, bound_capability, capability_relation_messages,
        capability_relation_messages_for,
    };
    use crate::schema::{CapabilityToml, SeatToml};

    use super::*;
    use crate::relational::capabilities::validate_capability_relations;

    #[test]
    fn binding_catalog_relations_require_exact_tuple_matches() {
        let (object, capability) = bound_capability();
        let bound_context = RelationContext::new("/nonexistent/odin-relation-fixture")
            .with_admitted_bindings([admitted_binding(&capability)])
            .expect("unique admitted tuple");
        let mut findings = Vec::new();
        let seats: BTreeMap<&str, &SeatToml> = BTreeMap::new();
        validate_capability_relations(
            &object,
            &capability,
            &bound_context,
            &seats,
            &BTreeSet::from(["builder"]),
            &mut BTreeMap::new(),
            &mut findings,
        );
        assert!(findings
            .iter()
            .all(|finding| finding.message.contains("schemas/capability")
                || finding.message.contains("cannot be resolved")));

        let drift_cases: Vec<(&str, CapabilityToml)> = vec![
            ("version", {
                let mut drifted = capability.clone();
                drifted.version = 4;
                drifted
            }),
            ("input_schema", {
                let mut drifted = capability.clone();
                drifted.input_schema = Some("schemas/capability/other.input.json".to_owned());
                drifted
            }),
            ("output_schema", {
                let mut drifted = capability.clone();
                drifted.output_schema = Some("schemas/capability/other.output.json".to_owned());
                drifted
            }),
            ("handler", {
                let mut drifted = capability.clone();
                drifted.handler =
                    Some(toml::from_str(r#"id = "other.handle""#).expect("parse drifted handler"));
                drifted
            }),
            ("evidence_extractor", {
                let mut drifted = capability.clone();
                drifted.evidence_extractor = Some(
                        toml::from_str(
                            r#"executable = "/nix/store/q0000000000000000000000000000000-odin-fixture/bin/odin-fixture-extract"
argv = ["--unframed"]"#,
                        )
                        .expect("parse drifted extractor"),
                    );
                drifted
            }),
        ];
        for (field, drifted) in drift_cases {
            let messages = capability_relation_messages(&drifted, &bound_context);
            assert!(
                messages
                    .iter()
                    .any(|message| message.contains("no compiled production HostTool binding")),
                "drifted {field} did not fail the compiled production binding: {messages:?}"
            );

            let unbound = capability_relation_messages(
                &drifted,
                &RelationContext::new("/nonexistent/odin-relation-fixture"),
            );
            assert!(
                !unbound
                    .iter()
                    .any(|message| message.contains("compiled production")),
                "fixture context unexpectedly enforced a production binding: {unbound:?}"
            );
        }

        let alias_messages =
            capability_relation_messages_for("alias.observe", &capability, &bound_context);
        assert!(
            !alias_messages
                .iter()
                .any(|message| message.contains("compiled production")),
            "distinct logical id must retain identity and match the admitted tuple: {alias_messages:?}"
        );
        assert_eq!(object.id, "fixture.tool");
    }

    /// Adapter capabilities require both reserved markers and cannot select compiled builtins.
    #[test]
    fn declared_adapter_capabilities_admit_by_markers_alone() {
        let production = RelationContext::new("/nonexistent/odin-relation-fixture")
            .with_admitted_bindings([])
            .expect("empty admitted set");
        let marker = |id: &str| {
            HandlerBindingToml::Builtin(crate::schema::BuiltinHandlerToml { id: id.to_owned() })
        };
        let (_, mut adapter) = bound_capability();
        adapter.implementation = Some("mcp-time".to_owned());
        adapter.handler = Some(marker(ADAPTER_OPERATION_HANDLER_ID));
        adapter.evidence_extractor = Some(marker(ADAPTER_RECEIPT_EVIDENCE_ID));
        let admitted = capability_relation_messages(&adapter, &production);
        assert!(
            !admitted.iter().any(
                |message| message.contains("compiled production") || message.contains("marker")
            ),
            "a declared adapter capability needs no compiled tuple: {admitted:?}"
        );

        let mut smuggled = adapter.clone();
        smuggled.handler = Some(marker("fixture.handle"));
        assert!(capability_relation_messages(&smuggled, &production)
            .iter()
            .any(|message| message.contains("implemented by adapter \"mcp-time\"")));

        let mut builtin = adapter;
        builtin.implementation = Some("builtin".to_owned());
        assert!(capability_relation_messages(&builtin, &production)
            .iter()
            .any(|message| message.contains("names no adapter")));
    }

    #[test]
    fn binding_catalog_relations_require_a_binding_for_every_enabled_capability() {
        let (_, capability) = bound_capability();
        let mut other = admitted_binding(&capability);
        other.version = 99;
        let context = RelationContext::new("/nonexistent/odin-relation-fixture")
            .with_admitted_bindings([other])
            .expect("unique admitted tuple");
        let messages = capability_relation_messages(&capability, &context);
        assert!(messages
            .iter()
            .any(|message| message.contains("no compiled production HostTool binding")));
        let empty_catalog = RelationContext::new("/nonexistent/odin-relation-fixture")
            .with_admitted_bindings([])
            .expect("empty admitted set");
        let messages = capability_relation_messages(&capability, &empty_catalog);
        assert!(messages
            .iter()
            .any(|message| message.contains("no compiled production HostTool binding")));

        let duplicate = RelationContext::new("/nonexistent/odin-relation-fixture")
            .with_admitted_bindings([admitted_binding(&capability), admitted_binding(&capability)]);
        assert!(
            duplicate.is_err(),
            "duplicate admitted tuples must be rejected"
        );
    }
}
