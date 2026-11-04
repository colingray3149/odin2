use std::path::PathBuf;

use crate::schema::{
    CapabilityToml, HandlerBindingToml, RegistryObject, ADAPTER_OPERATION_HANDLER_ID,
    ADAPTER_RECEIPT_EVIDENCE_ID, POD_EXEC_HANDLER_ID, POD_EXEC_IMPLEMENTATION, POD_EXEC_RECEIPT_ID,
    WORKFLOW_HANDLER_ID, WORKFLOW_IMPLEMENTATION, WORKFLOW_RECEIPT_ID,
};
use crate::RegistryFinding;

use super::paths::relation_failure;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationContext {
    pub odin_root: PathBuf,
    pub schemas_root: PathBuf,
    /// None performs structural checks; Some requires exact admitted tuples, and an empty set admits nothing.
    pub admitted_bindings: Option<Vec<AdmittedBinding>>,
    /// Companion schemas compiled in this authoring batch, not published yet.
    pub(crate) schema_documents: std::collections::BTreeMap<PathBuf, Vec<u8>>,
}

impl RelationContext {
    pub fn new(odin_root: impl Into<PathBuf>) -> Self {
        let odin_root = odin_root.into();
        let schemas_root = odin_root.join("schemas");
        Self {
            odin_root,
            schemas_root,
            admitted_bindings: None,
            schema_documents: std::collections::BTreeMap::new(),
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

/// Match the full tuple rather than using the logical capability ID as an admission key.
pub(super) fn validate_production_binding(
    object: &RegistryObject,
    capability: &CapabilityToml,
    context: &RelationContext,
    findings: &mut Vec<RegistryFinding>,
) {
    // Pod-exec capabilities are admitted by their markers and [exec] table.
    let pod_exec_cause = match (
        capability.is_pod_exec(),
        capability.binds_pod_exec_markers(),
        capability.exec.is_some(),
    ) {
        (true, true, true) => return,
        (false, false, false) => None,
        (true, false, _) => Some(format!(
            "must bind handler {{ id = \"{POD_EXEC_HANDLER_ID}\" }} and evidence_extractor \
             {{ id = \"{POD_EXEC_RECEIPT_ID}\" }}"
        )),
        (true, true, false) => Some("must declare an [exec] table".to_owned()),
        (false, true, _) => Some(format!(
            "binds the pod-exec markers but its implementation is not \"{POD_EXEC_IMPLEMENTATION}\""
        )),
        (false, false, true) => Some(format!(
            "declares an [exec] table but its implementation is not \"{POD_EXEC_IMPLEMENTATION}\""
        )),
    };
    if let Some(cause) = pod_exec_cause {
        findings.push(relation_failure(
            object,
            format!("pod-exec capability {} {cause}", object.id),
        ));
        return;
    }
    // Workflow capabilities are admitted by their markers; odind checks the compiled function.
    match (
        capability.is_workflow(),
        capability.binds_workflow_markers(),
    ) {
        (true, true) => return,
        (false, false) => {}
        (true, false) => {
            findings.push(relation_failure(
                object,
                format!(
                    "workflow capability {} must bind handler {{ id = \"{WORKFLOW_HANDLER_ID}\" }} \
                     and evidence_extractor {{ id = \"{WORKFLOW_RECEIPT_ID}\" }}",
                    object.id
                ),
            ));
            return;
        }
        (false, true) => {
            findings.push(relation_failure(
                object,
                format!(
                    "capability {} binds the workflow markers but its implementation is not \
                     \"{WORKFLOW_IMPLEMENTATION}\"",
                    object.id
                ),
            ));
            return;
        }
    }
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
    use std::collections::BTreeMap;

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
            &mut BTreeMap::new(),
            &mut findings,
        );
        assert!(
            findings.iter().all(|finding| {
                !finding.message.contains("production HostTool binding")
                    && !finding.message.contains("admitted binding")
            }),
            "the exact admitted tuple raises no binding finding: {findings:?}"
        );

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


    fn workflow_marker(id: &str) -> HandlerBindingToml {
        HandlerBindingToml::Builtin(crate::schema::BuiltinHandlerToml { id: id.to_owned() })
    }

    #[test]
    fn workflow_capability_requires_both_markers() {
        let production = RelationContext::new("/nonexistent/odin-relation-fixture")
            .with_admitted_bindings([])
            .expect("empty admitted set");
        let (_, mut workflow) = bound_capability();
        workflow.implementation = Some(WORKFLOW_IMPLEMENTATION.to_owned());
        workflow.handler = Some(workflow_marker("x"));
        workflow.evidence_extractor = Some(workflow_marker(WORKFLOW_RECEIPT_ID));
        let messages = capability_relation_messages(&workflow, &production);
        assert_eq!(
            messages
                .iter()
                .filter(
                    |message| message.contains("must bind handler { id = \"odin_workflow.run\" }")
                )
                .count(),
            1,
            "{messages:?}"
        );
        workflow.handler = Some(workflow_marker(WORKFLOW_HANDLER_ID));
        let admitted = capability_relation_messages(&workflow, &production);
        assert!(
            !admitted.iter().any(
                |message| message.contains("compiled production") || message.contains("marker")
            ),
            "a marked workflow needs no compiled tuple: {admitted:?}"
        );
    }
}
