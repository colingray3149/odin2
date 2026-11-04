//! Authoring schemas are validated through kernel input checks, model-surface narrowing, and canonical schemas.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use crate::runtime::fixtures::tool_named;
use odin_domain::knowledge::ToolSchema;
use odin_hermes::config::HermesSettings;
use odin_hermes::runtime::{HermesLedgers, HermesRuntime};
use odin_ledger::Ledger;
use odin_omp::host_tools::schema_compat::{drop_null_optionals, model_parameters};
use serde_json::{json, Value};

const GRANT_TOOL: &str = "registry_author_grant";
const APPROVAL: &str = "approval:r3:fixture";
const ENVIRONMENT_VALUES: &str = "enabled = true\ndescription = \"the owner's pc over ssh\"\n\
     transport = \"ssh-host\"\nhost = \"owner@pc\"\nseats = [\"gungnir\"]\n\
     observation = { channel = \"events\" }\n";

/// The exact argument narrowing the operation surface compiles for every
/// dispatch (odin-omp `declared_narrowing_schema`): the registered model
/// surface minus its top-level `additionalProperties`.
fn narrowing_of(parameters: &Value) -> Value {
    let mut narrowing = parameters.clone();
    narrowing
        .as_object_mut()
        .expect("a tool surface is an object")
        .remove("additionalProperties");
    narrowing
}

/// A canonical capability schema from the repository filesystem — the
/// same file the production schema catalog serves.
fn canonical_value(file: &str) -> Value {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/capability");
    let raw = std::fs::read_to_string(root.join(file)).unwrap();
    serde_json::from_str(&raw).unwrap()
}

fn canonical(file: &str) -> ToolSchema {
    ToolSchema::from_value(canonical_value(file)).unwrap()
}

/// The registered model surface of one authoring tool.
fn registered_surface(runtime: &Arc<HermesRuntime>, name: &str) -> Value {
    tool_named(runtime, name).definition().parameters.clone()
}

/// The arguments of the approved retry: the identical call plus the
/// selector the approval names.
fn with_approval(arguments: &Value) -> Value {
    let mut retry = arguments.clone();
    retry["approvalId"] = json!(APPROVAL);
    retry
}

#[test]
fn the_grant_surface_admits_fills_and_removals_and_refuses_malformed_shapes() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = HermesRuntime::open(
        HermesSettings::new(
            dir.path().join("state"),
            None,
            None,
            vec![],
        )
        .unwrap(),
        HermesLedgers {
            conversation: Ledger::open_in_memory().unwrap(),
            adapter: Arc::new(parking_lot::Mutex::new(Ledger::open_in_memory().unwrap())),
            purchase: Arc::new(std::sync::Mutex::new(Ledger::open_in_memory().unwrap())),
        },
        &BTreeMap::new(),
        None,
        8_192,
        BTreeMap::new(),
        None,
    )
    .unwrap();
    let registered = registered_surface(&runtime, GRANT_TOOL);
    let surfaces = [
        (
            "registered surface",
            ToolSchema::from_value(registered.clone()).unwrap(),
        ),
        (
            "dispatch narrowing",
            ToolSchema::from_value(narrowing_of(&registered)).unwrap(),
        ),
        (
            "canonical schema",
            canonical("registry.author.grant.input.json"),
        ),
    ];
    let fill = json!({
        "skeleton": "new-environment",
        "id": "pc-ssh",
        "values": ENVIRONMENT_VALUES,
    });
    let removal = json!({ "skeleton": "remove-environment", "id": "pc-ssh" });
    let enable = json!({
        "skeleton": "enable-capability",
        "id": "web.search",
        "values": "seat = \"sinmara\"",
    });
    let admitted: &[(&str, Value)] = &[
        (
            "a fill's first call, before any approval exists",
            fill.clone(),
        ),
        (
            "a fill's approved retry with its approvalId",
            with_approval(&fill),
        ),
        ("an enable-capability fill", enable.clone()),
        (
            "an enable-capability's approved retry",
            with_approval(&enable),
        ),
        ("a declared removal's first call", removal.clone()),
        (
            "a declared removal's approved retry",
            with_approval(&removal),
        ),
    ];
    let refused: &[(&str, Value)] = &[
        (
            "a fill without its values",
            json!({ "skeleton": "new-environment", "id": "pc-ssh" }),
        ),
        (
            "an open-tier skeleton through the grant tier",
            json!({ "skeleton": "new-lane", "id": "lane", "values": "project = \"rig\"" }),
        ),
    ];
    for (surface, schema) in &surfaces {
        for (name, arguments) in admitted {
            odin_kernel::validate_input_arguments(schema, arguments)
                .unwrap_or_else(|error| panic!("{surface} must admit {name}: {error}"));
        }
    }
    // Cross-field rules are the kernel's, against the declared schema.
    for (name, arguments) in refused {
        assert!(
            odin_kernel::validate_input_arguments(&surfaces[2].1, arguments).is_err(),
            "the canonical schema must refuse {name}"
        );
    }
    let projected = ToolSchema::from_value(model_parameters(&registered)).unwrap();
    let canonical_value = canonical_value("registry.author.grant.input.json");
    for arguments in [&fill, &enable, &removal] {
        {
            let absent = Value::Null;
            let mut initial = arguments.clone();
            initial["approvalId"] = absent.clone();
            if initial.get("values").is_none() {
                initial["values"] = absent;
            }
            assert!(odin_kernel::validate_input_arguments(&surfaces[2].1, &initial).is_err());
            let normalized = drop_null_optionals(&canonical_value, initial.clone());
            assert_eq!(&normalized, arguments);
            odin_kernel::validate_input_arguments(&projected, &normalized)
                .expect("the model call admits an omitted selector after null normalization");
            for (surface, schema) in &surfaces {
                odin_kernel::validate_input_arguments(schema, &normalized).unwrap_or_else(
                    |error| panic!("{surface} must admit normalized call: {error}"),
                );
            }
            let retry = with_approval(&initial);
            let normalized_retry = drop_null_optionals(&canonical_value, retry);
            assert_eq!(normalized_retry, with_approval(arguments));
            odin_kernel::validate_input_arguments(&projected, &normalized_retry)
                .expect("the normalized projected retry admits the real approval selector");
            for (surface, schema) in &surfaces {
                odin_kernel::validate_input_arguments(schema, &normalized_retry).unwrap_or_else(
                    |error| panic!("{surface} must admit normalized retry: {error}"),
                );
            }
        }
    }
    let mut empty_approval = fill.clone();
    empty_approval["approvalId"] = json!("");
    let normalized = drop_null_optionals(&canonical_value, empty_approval.clone());
    assert_eq!(normalized, empty_approval);
    assert!(odin_kernel::validate_input_arguments(&projected, &empty_approval).is_err());
    assert!(odin_kernel::validate_input_arguments(&surfaces[2].1, &normalized).is_err());
    let mut rogue = fill.clone();
    rogue["seat"] = json!("gungnir");
    let rogue = with_approval(&rogue);
    for (surface, schema) in [&surfaces[0], &surfaces[2]] {
        assert!(
            odin_kernel::validate_input_arguments(schema, &rogue).is_err(),
            "{surface} must forbid undeclared keys"
        );
    }
    // Removal values reach the daemon's typed refusal.
    let mut removal_with_values = removal.clone();
    removal_with_values["values"] = json!("reason = \"cleanup\"");
    for (surface, schema) in &surfaces {
        odin_kernel::validate_input_arguments(schema, &removal_with_values).unwrap_or_else(
            |error| panic!("{surface} must forward a removal's values to the daemon: {error}"),
        );
    }
}

/// Asks the route for the skeleton the caller names; nothing else.
struct SkeletonRoute;

impl odin_hermes::runtime::registry_author::RegistryAuthorRoute for SkeletonRoute {
    fn skeleton(&self, skeleton: &str) -> Result<Value, String> {
        match skeleton {
            "new-lane" => Ok(json!({ "variables": [{ "name": "project", "required": true }] })),
            other => Err(format!("{other} is not a registry skeleton")),
        }
    }

    fn author(
        &self,
        _caller: &odin_domain::SeatId,
        _request: odin_hermes::runtime::registry_author::AuthorRequest,
    ) -> Result<odin_hermes::runtime::registry_author::AuthorChange, String> {
        unreachable!("reading a skeleton never authors")
    }
}

#[test]
fn a_skeleton_read_returns_the_routes_variables_and_names_an_unknown_skeleton() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = crate::runtime::fixtures::gate_runtime(dir.path());
    let read = tool_named(&runtime, "registry_skeleton_read");
    let invoke = |skeleton: &str| {
        read.invoke(odin_omp::host_tools::HostInvocation {
            scope: odin_domain::Scope::default(),
            arguments: json!({ "skeleton": skeleton }),
        })
    };
    let unrouted = invoke("new-lane").unwrap_err().to_string();
    assert!(unrouted.contains("not composed"), "{unrouted}");
    runtime.set_registry_author_route(Arc::new(SkeletonRoute));
    assert_eq!(
        invoke("new-lane").unwrap()["variables"][0]["name"],
        "project"
    );
    let unknown = invoke("new-thing").unwrap_err().to_string();
    assert!(
        unknown.contains("new-thing is not a registry skeleton"),
        "{unknown}"
    );
}
