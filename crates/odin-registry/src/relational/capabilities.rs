use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::schema::{
    CapabilityToml, HandlerBindingToml, RegistryObject, SeatToml, SEAT_ASK_INPUT_SCHEMA,
};
use crate::RegistryFinding;

use super::context::{match_admitted_binding, validate_production_binding, RelationContext};
use super::paths::{normalize_relative, relation_failure, validate_regular_file};
use super::seats::validate_delegation_target;

pub(super) fn validate_capability_relations(
    object: &RegistryObject,
    capability: &CapabilityToml,
    context: &RelationContext,
    seats: &BTreeMap<&str, &SeatToml>,
    seat_categories: &BTreeSet<&str>,
    schema_owners: &mut BTreeMap<PathBuf, (String, bool)>,
    findings: &mut Vec<RegistryFinding>,
) {
    if crate::ROOT_EQUIVALENT_CAPABILITIES.contains(&object.id.as_str()) {
        findings.push(relation_failure(
            object,
            "declares root-equivalent power, which no governed seat or pod may hold".to_owned(),
        ));
    }
    if !capability.enabled {
        return;
    }
    for tag in &capability.seat_tags {
        if tag != "*" && !seat_categories.contains(tag.as_str()) {
            findings.push(relation_failure(
                object,
                format!("seat_tags references unknown enabled seat category {tag:?}"),
            ));
        }
    }

    let input = capability.input_schema.as_deref();
    let output = capability.output_schema.as_deref();
    for (field, reference) in [("input_schema", input), ("output_schema", output)] {
        if reference.is_none_or(str::is_empty) {
            findings.push(relation_failure(
                object,
                format!("enabled capability requires a dedicated {field}"),
            ));
        }
    }
    if let (Some(input), Some(output)) = (
        input.filter(|value| !value.is_empty()),
        output.filter(|value| !value.is_empty()),
    ) {
        let input_path = validate_dedicated_schema_ref(
            object,
            "input_schema",
            input,
            "input",
            context,
            findings,
        );
        let output_path = validate_dedicated_schema_ref(
            object,
            "output_schema",
            output,
            "output",
            context,
            findings,
        );
        if input == output {
            findings.push(relation_failure(
                object,
                "input_schema and output_schema must be distinct dedicated files",
            ));
        }
        let input_stem = schema_stem(input, ".input.json");
        let output_stem = schema_stem(output, ".output.json");
        if input_stem.is_none() || input_stem != output_stem {
            findings.push(relation_failure(
                object,
                "input/output schema filenames must share one <capability>.input|output.json stem",
            ));
        } else if (context.admitted_bindings.is_none()
            || capability.adapter_implementation().is_some())
            && !stem_identifies_capability(object, capability, input_stem)
        {
            findings.push(relation_failure(
                object,
                format!(
                    "dedicated schema stem {:?} does not identify capability {:?}",
                    input_stem.unwrap_or_default(),
                    object.id
                ),
            ));
        } else if let Some(admitted) = match_admitted_binding(capability, context) {
            let admitted_stem = schema_stem(&admitted.input_schema, ".input.json");
            if input_stem != admitted_stem {
                findings.push(relation_failure(
                    object,
                    format!(
                        "dedicated schema stem {:?} does not follow the admitted binding stem {:?}",
                        input_stem.unwrap_or_default(),
                        admitted_stem.unwrap_or_default()
                    ),
                ));
            }
        }
        for path in [input_path, output_path].into_iter().flatten() {
            let primitive = capability.is_seat_ask_primitive();
            if let Some((owner, owner_is_primitive)) =
                schema_owners.insert(path.clone(), (object.id.clone(), primitive))
            {
                if owner != object.id
                    && context.admitted_bindings.is_none()
                    // Sharing requires both claimants to own the generic primitive.
                    && !(primitive && owner_is_primitive)
                {
                    findings.push(relation_failure(
                        object,
                        format!(
                            "schema {} is already owned by enabled capability {owner:?}",
                            path.display()
                        ),
                    ));
                }
            }
        }
    }

    for (field, binding) in [
        ("handler", capability.handler.as_ref()),
        ("evidence_extractor", capability.evidence_extractor.as_ref()),
    ] {
        match binding {
            Some(binding) => validate_handler(object, field, binding, findings),
            None => findings.push(relation_failure(
                object,
                format!("enabled capability requires {field}"),
            )),
        }
    }
    validate_production_binding(object, capability, context, findings);
    validate_delegation_target(object, capability, seats, findings);
}

/// Dedicated schema stems identify capabilities; cross-seat asks share the generic primitive stem.
fn stem_identifies_capability(
    object: &RegistryObject,
    capability: &CapabilityToml,
    stem: Option<&str>,
) -> bool {
    let Some(stem) = stem else {
        return false;
    };
    if stem == object.id || stem == object.id.replace('-', ".") {
        return true;
    }
    capability.is_seat_ask_primitive()
        && Some(stem) == schema_stem(SEAT_ASK_INPUT_SCHEMA, ".input.json")
}

fn validate_dedicated_schema_ref(
    object: &RegistryObject,
    field: &str,
    reference: &str,
    direction: &str,
    context: &RelationContext,
    findings: &mut Vec<RegistryFinding>,
) -> Option<PathBuf> {
    let normalized = match normalize_relative(reference) {
        Ok(path) => path,
        Err(message) => {
            findings.push(relation_failure(
                object,
                format!("{field} {reference:?} is invalid: {message}"),
            ));
            return None;
        }
    };
    let expected_prefix = Path::new("schemas/capability");
    if !normalized.starts_with(expected_prefix) {
        findings.push(relation_failure(
            object,
            format!("{field} must resolve below schemas/capability, found {reference:?}"),
        ));
    }
    let suffix = format!(".{direction}.json");
    if normalized
        .file_name()
        .and_then(OsStr::to_str)
        .is_none_or(|name| !name.ends_with(&suffix))
    {
        findings.push(relation_failure(
            object,
            format!("{field} must end in {suffix:?}"),
        ));
    }
    let absolute = context.odin_root.join(&normalized);
    validate_regular_file(object, field, &normalized, &absolute, context, findings)
        .then_some(normalized)
}

fn validate_handler(
    object: &RegistryObject,
    field: &str,
    binding: &HandlerBindingToml,
    findings: &mut Vec<RegistryFinding>,
) {
    if let Err(message) = binding.validate() {
        findings.push(relation_failure(object, format!("{field} {message}")));
    }
}

fn schema_stem<'a>(reference: &'a str, suffix: &str) -> Option<&'a str> {
    Path::new(reference)
        .file_name()
        .and_then(OsStr::to_str)
        .and_then(|name| name.strip_suffix(suffix))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;

    use crate::relational::fixtures::{
        admitted_binding, ask_capability_object, ask_schema_root, bound_capability, capability_mut,
        capability_relation_messages, lane_fixtures, project_object, seat_object,
    };
    use crate::relational::refs::{seat_categories, seat_index};
    use crate::relational::validate;
    use crate::schema::{CapabilityToml, ObjectConfig, RegistryObject, SeatToml};

    use super::*;

    #[test]
    fn enabled_capabilities_are_a_closed_contract() {
        let capability: CapabilityToml = toml::from_str(
            r#"
schema = "odin.registry.v1"
kind = "capability"
enabled = true
version = 1
description = "fixture"
effect_class = "R1"
seat_tags = ["builder"]
timeout_seconds = 1
idempotency = "pure"
retry = { max_attempts = 1 }
approval_policy = "none"
"#,
        )
        .expect("parse capability fixture");
        let capability_object = RegistryObject {
            id: "fixture.tool".to_owned(),
            relative_config: PathBuf::from("registry/capabilities/fixture.tool/capability.toml"),
            config: ObjectConfig::Capability(Box::new(capability.clone())),
        };
        let mut findings = Vec::new();
        let seats: BTreeMap<&str, &SeatToml> = BTreeMap::new();
        validate_capability_relations(
            &capability_object,
            &capability,
            &RelationContext::new("/nonexistent/odin-relation-fixture"),
            &seats,
            &BTreeSet::from(["builder"]),
            &mut BTreeMap::new(),
            &mut findings,
        );
        for field in [
            "input_schema",
            "output_schema",
            "handler",
            "evidence_extractor",
        ] {
            assert!(findings
                .iter()
                .any(|finding| finding.message.contains(field)));
        }
    }

    #[test]
    fn binding_catalog_relations_validate_handlers_without_filesystem_reachability() {
        let unresolvable: CapabilityToml = toml::from_str(
            r#"
schema = "odin.registry.v1"
kind = "capability"
enabled = true
implementation = "builtin"
version = 3
description = "Exec handler whose store executable is absent from this fixture root."
handler = { executable = "/nix/store/q0000000000000000000000000000000-absent/bin/absent-handler", argv = ["--serve"] }
input_schema = "schemas/capability/fixture.tool.input.json"
output_schema = "schemas/capability/fixture.tool.output.json"
effect_class = "R0"
seat_tags = ["builder"]
timeout_seconds = 1
idempotency = "pure"
retry = { max_attempts = 1 }
approval_policy = "none"
evidence_extractor = { id = "fixture.handle_evidence" }
"#,
        )
        .expect("parse exec-handler fixture");
        let messages = capability_relation_messages(
            &unresolvable,
            &RelationContext::new("/nonexistent/odin-relation-fixture"),
        );
        assert!(
            !messages.iter().any(|message| {
                (message.starts_with("handler ") || message.starts_with("evidence_extractor "))
                    && message.contains("cannot be resolved")
            }),
            "handler validation performed file-exists reachability: {messages:?}"
        );

        let malformed: CapabilityToml = toml::from_str(
            r#"
schema = "odin.registry.v1"
kind = "capability"
enabled = true
implementation = "builtin"
version = 3
description = "Malformed handler references."
handler = { id = "bad handle" }
input_schema = "schemas/capability/fixture.tool.input.json"
output_schema = "schemas/capability/fixture.tool.output.json"
effect_class = "R0"
seat_tags = ["builder"]
timeout_seconds = 1
idempotency = "pure"
retry = { max_attempts = 1 }
approval_policy = "none"
evidence_extractor = { executable = "relative/tool", argv = ["--json"] }
"#,
        )
        .expect("parse malformed handler fixture");
        let messages = capability_relation_messages(
            &malformed,
            &RelationContext::new("/nonexistent/odin-relation-fixture"),
        );
        assert!(messages
            .iter()
            .any(|message| message.starts_with("handler builtin handler id")));
        assert!(messages
            .iter()
            .any(|message| message.starts_with("evidence_extractor exec executable")));
    }

    #[test]
    fn seat_ask_capabilities_share_one_generic_tuple() {
        let root = ask_schema_root();
        let conversation =
            "conversation = { project = \"fixture\", ask_capability = \"seat.ask.a\", guidance = \"Speak plainly.\", answer_timeout_seconds = 240 }";
        // Registry-wide invariants (node authority, provider availability)
        // are other layers' contracts; this test judges only findings at the
        // delegation's own declarations.
        let relevant = |findings: Vec<RegistryFinding>| -> Vec<String> {
            findings
                .into_iter()
                .filter(|finding| {
                    let path = finding.path.to_string_lossy();
                    path.contains("seat.toml") || path.contains("capability.toml")
                })
                .map(|finding| finding.message)
                .collect()
        };
        let mut objects = lane_fixtures();
        objects.push(project_object(true));
        objects.push(ask_capability_object("seat.ask.a", "fixture"));
        objects.push(ask_capability_object("seat.ask.b", "fixture"));
        objects.push(seat_object(conversation, true));
        let context = RelationContext::new(&root);
        let clean = relevant(validate(&objects, &context));
        assert!(
            clean.is_empty(),
            "arbitrary ask capabilities must share the generic tuple cleanly: {clean:?}"
        );

        // A non-primitive capability claiming the generic files stays a
        // broken relation.
        let (mut bound_object, _) = bound_capability();
        bound_object.id = "seat.ask".to_owned();
        bound_object.relative_config =
            PathBuf::from("registry/capabilities/seat.ask/capability.toml");
        capability_mut(&mut bound_object).input_schema =
            Some(crate::schema::SEAT_ASK_INPUT_SCHEMA.to_owned());
        capability_mut(&mut bound_object).output_schema =
            Some(crate::schema::SEAT_ASK_OUTPUT_SCHEMA.to_owned());
        capability_mut(&mut bound_object).seat_tags = BTreeSet::from(["*".to_owned()]);
        let ObjectConfig::Capability(claimant) = &bound_object.config else {
            panic!("capability fixture");
        };
        let mut standalone = Vec::new();
        validate_capability_relations(
            &bound_object,
            claimant,
            &context,
            &seat_index(&objects),
            &seat_categories(&objects),
            &mut BTreeMap::new(),
            &mut standalone,
        );
        assert!(
            standalone.is_empty(),
            "the lone claimant must otherwise be valid: {standalone:?}"
        );
        let mut contested = objects.clone();
        contested.push(bound_object);
        assert!(!relevant(validate(&contested, &context)).is_empty());
        contested.reverse();
        assert!(
            !relevant(validate(&contested, &context)).is_empty(),
            "a non-primitive schema claimant must fail in either declaration order"
        );

        // Production admission: one compiled tuple admits every logical ask
        // capability, so the daemon registers the primitive exactly once.
        let generic = match &objects
            .iter()
            .find(|object| object.id == "seat.ask.a")
            .expect("ask capability fixture")
            .config
        {
            ObjectConfig::Capability(capability) => capability.as_ref().clone(),
            _ => panic!("ask capability fixture must be a capability"),
        };
        let production = RelationContext::new(&root)
            .with_admitted_bindings([admitted_binding(&generic)])
            .expect("unique admitted tuple");
        let admitted = relevant(validate(&objects, &production));
        assert!(
            admitted.is_empty(),
            "one compiled tuple must admit every logical ask capability: {admitted:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
