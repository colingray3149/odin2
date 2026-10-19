use super::*;

use crate::host_tools::binding::{BrowserListedTool, FramedExecTool};

/// The browser listed routes fail closed on bare invocation: the BrowserArm
/// owner is only reachable through the kernel-minted prepared operation,
/// exactly like the kube listed wrappers.
#[test]
fn browser_listed_routes_fail_closed_without_a_prepared_operation() {
    let mut registry = HostToolRegistry::new();
    let owner: Arc<dyn BrowserCapabilityOwner> = Arc::new(BoundTestOwner);
    registry
        .register_browser_capabilities(Arc::clone(&owner))
        .expect("browser surface registers");
    let definitions = registry.definitions();
    let names: Vec<&str> = definitions
        .iter()
        .map(|definition| definition.name.as_ref())
        .collect();
    for name in [
        "browser_observe",
        "browser_interact",
        "browser_consequential",
    ] {
        assert!(names.contains(&name), "{name} must be a listed route");
    }
    for binding in [
        BrowserCapabilityBinding::Observe,
        BrowserCapabilityBinding::Interact,
        BrowserCapabilityBinding::Consequential,
    ] {
        let listed = Arc::new(
            BrowserListedTool::new(binding, Arc::clone(&owner))
                .expect("listed browser route builds"),
        );
        assert_eq!(listed.definition().name, binding.listed_name());
        assert!(!listed.definition().hidden, "the route is model-visible");
        let error = listed
            .invoke(HostInvocation {
                scope: Scope::default(),
                arguments: json!({}),
            })
            .expect_err("bare invocation must fail closed");
        assert!(
            matches!(error, HostToolError::Catalog { .. }),
            "the refusal must be the operation-authority law, got {error:?}"
        );
    }
}

fn exec_invocation(arguments: Value) -> HostInvocation {
    HostInvocation {
        scope: Scope::default(),
        arguments,
    }
}

fn exec_tool(script: &'static str, timeout: std::time::Duration) -> FramedExecTool {
    let shell = std::fs::canonicalize("/bin/sh").expect("/bin/sh resolves");
    let worker = crate::process::launch_for_fixture(&shell);
    FramedExecTool::with_timeout(
        shell.to_string_lossy().into_owned(),
        vec!["-c".to_owned(), script.to_owned()],
        timeout,
        worker,
    )
}

#[test]
fn exec_runner_actuates_one_canonical_framed_round_trip() {
    // Read stdin before replying so an early child exit cannot race the parent's write with EPIPE.
    let tool = exec_tool(
        r#"IFS= read -r _; printf '{"a":1,"b":2}\n'"#,
        std::time::Duration::from_secs(10),
    );
    let reply = tool
        .invoke(exec_invocation(json!({ "key": "value" })))
        .expect("canonical framed stdout round trips");
    assert_eq!(reply["a"], 1);
    assert_eq!(reply["b"], 2);
}

#[test]
fn exec_runner_rejects_noncanonical_stdout_bytes() {
    // Read stdin first so this tests output canonicalization rather than an EPIPE race.
    let tool = exec_tool(
        r#"IFS= read -r _; printf '{ "b": 2, "a": 1 }\n'"#,
        std::time::Duration::from_secs(10),
    );
    let error = tool
        .invoke(exec_invocation(json!({})))
        .expect_err("whitespace/key-order drift must not pass");
    assert!(
        matches!(&error, HostToolError::Uncertain { detail, .. }
                if detail.contains("not canonical JSON")),
        "the completed child's effect state is unprovable, not rejected: {error}"
    );
}

#[test]
fn exec_runner_times_out_when_a_forked_descendant_holds_stdout() {
    // The HUP-ignoring descendant keeps stdout open until the process group is killed.
    // Read stdin first to avoid an EPIPE race with the parent's write.
    let started = std::time::Instant::now();
    let tool = exec_tool(
        r##"exec 3>&1; (trap '' HUP; coproc P { read; }; read -t 2 -u ${P[0]}) >&3 2>/dev/null <&- & IFS= read -r _; printf '{"ok":true}\n'; exit 0"##,
        std::time::Duration::from_millis(400),
    );
    let error = tool
        .invoke(exec_invocation(json!({})))
        .expect_err("a fork-held stdout pipe must end in a timeout error");
    assert!(
        matches!(&error, HostToolError::Uncertain { .. }),
        "a killed child leaves the effect state unprovable: {error}"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "the group kill must bound the wait, took {:?}",
        started.elapsed()
    );
}

#[test]
fn capsule_eval_listing_omits_source_sha256_while_canonical_binding_keeps_it() {
    let mut registry = HostToolRegistry::new();
    registry
        .register_capsule_listed_tools(Arc::new(CanonicalTestOwner))
        .expect("capsule listed tools register");

    let definitions = registry.definitions();
    let eval = definitions
        .iter()
        .find(|definition| definition.name == "capsule_eval_run")
        .expect("listed eval route");
    assert!(!eval.hidden, "the eval route stays model-visible");
    assert_eq!(eval.label, "Capsule Eval");
    let required = eval.parameters["required"].as_array().expect("required");
    assert!(
        !required
            .iter()
            .any(|entry| entry.as_str() == Some("source_sha256")),
        "the model is never asked for a source digest"
    );
    let properties = eval
        .parameters
        .get("properties")
        .and_then(Value::as_object)
        .expect("eval properties object");
    assert!(!properties.contains_key("source_sha256"));
    for kept in [
        "interpreter",
        "source",
        "timeout_ms",
        "max_stdout_bytes",
        "max_stderr_bytes",
    ] {
        assert!(properties.contains_key(kept), "{kept} stays listed");
        assert!(
            required.iter().any(|entry| entry.as_str() == Some(kept)),
            "{kept} stays required"
        );
    }

    // The canonical inner binding keeps the exact published schema: the
    // authority wire still requires the digest the trusted host supplies.
    let canonical: Value = serde_json::from_str(CanonicalV2CapabilityBinding::EvalRun.schema())
        .expect("canonical eval schema");
    assert!(canonical["properties"]["source_sha256"].is_object());
    assert!(
        canonical["required"]
            .as_array()
            .expect("canonical required")
            .iter()
            .any(|entry| entry.as_str() == Some("source_sha256")),
        "the canonical binding must still require source_sha256"
    );

    // The confined edit route keeps its own published shape untouched.
    let edit = definitions
        .iter()
        .find(|definition| definition.name == "capsule_file_edit")
        .expect("listed edit route");
    assert!(!edit.hidden);
    for property in ["old_text", "new_text", "content", "preimage_sha256"] {
        assert!(
            edit.parameters["properties"][property].is_object(),
            "{property}"
        );
    }
    assert_eq!(edit.parameters["required"], serde_json::json!(["path"]));
}

#[test]
fn kube_routes_reject_unprepared_invocations() {
    let mut registry = HostToolRegistry::new();
    registry
        .register_kube_capabilities(Arc::new(KubeTestOwner))
        .expect("kube surface registers");
    let catalog =
        CompiledHostToolCatalog::compile(PRE_ADMITTED_BINDINGS).expect("compiled catalog");
    for definition in registry.definitions() {
        let result = registry.dispatch(
            &definition.name,
            HostInvocation {
                scope: Scope::default(),
                arguments: json!({}),
            },
        );
        assert!(matches!(result, Err(HostToolError::Catalog { .. })));
    }
    for name in [
        "odin_kube.workload.create",
        "odin_kube.workload.create_evidence",
    ] {
        let handler = catalog.resolve(name, &registry).expect("admitted adapter");
        let result = handler.invoke(HostInvocation {
            scope: Scope::default(),
            arguments: json!({ "profile": "kubert-job" }),
        });
        assert!(matches!(result, Err(HostToolError::Catalog { .. })));
    }
}

#[test]
fn kube_create_listing_and_model_projection_preserve_bounded_initial_target() {
    use crate::host_tools::schema_compat::{drop_null_optionals, model_parameters};

    let mut registry = HostToolRegistry::new();
    registry
        .register_kube_capabilities(Arc::new(KubeTestOwner))
        .expect("kube surface registers");
    let definitions = registry.definitions();
    let create = definitions
        .iter()
        .find(|definition| definition.name == "kube_workload_create")
        .expect("create is listed for the model");
    let declared = &create.parameters;
    let validator = jsonschema::validator_for(declared).expect("listed schema compiles");
    let omitted = json!({ "profile": "gpu-smoke" });
    assert!(
        validator.is_valid(&omitted),
        "initial target remains optional"
    );
    assert!(!validator.is_valid(&json!({ "targetNode": "mini" })));
    assert!(!validator.is_valid(&json!({ "profile": "gpu-smoke", "targetNode": null })));

    // Exercise the actual strict-model projection, including the null-to-omitted
    // normalization used before capability validation, not just schema wiring.
    let shown = model_parameters(declared);
    let shown_validator = jsonschema::validator_for(&shown).expect("model schema compiles");
    let mut model_omitted = omitted.clone();
    for name in declared["properties"]
        .as_object()
        .expect("input properties")
        .keys()
    {
        if name != "profile" {
            model_omitted[name] = Value::Null;
        }
    }
    assert!(shown_validator.is_valid(&model_omitted));
    assert_eq!(
        drop_null_optionals(declared, model_omitted.clone()),
        omitted
    );
    assert!(
        !shown_validator.is_valid(&omitted),
        "strict model must spell out optionals"
    );

    for target in ["mini", "pc", "node.example", "a", &"a".repeat(63)] {
        let mut arguments = omitted.clone();
        arguments["targetNode"] = json!(target);
        assert!(
            validator.is_valid(&arguments),
            "listed schema accepts {target}"
        );
        let mut sent = model_omitted.clone();
        sent["targetNode"] = json!(target);
        assert!(
            shown_validator.is_valid(&sent),
            "model schema accepts {target}"
        );
        assert_eq!(drop_null_optionals(declared, sent), arguments);
    }
    for target in [
        json!("Node"),
        json!("-mini"),
        json!("mini-"),
        json!("mini pc"),
        json!("mini/pc"),
        json!("a".repeat(64)),
        json!(3),
        json!({ "name": "mini" }),
    ] {
        let mut arguments = omitted.clone();
        arguments["targetNode"] = target.clone();
        assert!(
            !validator.is_valid(&arguments),
            "listed schema rejects {target}"
        );
        let mut sent = model_omitted.clone();
        sent["targetNode"] = target.clone();
        assert!(
            !shown_validator.is_valid(&sent),
            "model schema rejects {target}"
        );
    }
    let mut empty = model_omitted.clone();
    empty["targetNode"] = json!("");
    assert!(!shown_validator.is_valid(&empty));
    assert!(!validator.is_valid(&drop_null_optionals(declared, empty)));
    let mut literal = model_omitted.clone();
    literal["targetNode"] = json!("null");
    let mut expected = omitted.clone();
    expected["targetNode"] = json!("null");
    assert!(shown_validator.is_valid(&literal));
    assert_eq!(drop_null_optionals(declared, literal), expected);
    for selector in [
        "nodeSelector",
        "nodeName",
        "affinity",
        "tolerations",
        "allowed_nodes",
    ] {
        let mut arguments = omitted.clone();
        arguments[selector] = json!({ "kubernetes.io/hostname": "mini" });
        assert!(
            !validator.is_valid(&arguments),
            "listed schema forbids {selector}"
        );
        let mut sent = model_omitted.clone();
        sent[selector] = arguments[selector].clone();
        assert!(
            !shown_validator.is_valid(&sent),
            "model schema forbids {selector}"
        );
    }
}

#[test]
fn kube_mutation_listings_require_the_admitted_resource_version() {
    // The published mutation input binds the run AND the exact opaque
    // expectedResourceVersion observed at admission: the model-visible
    // listing carries both and nothing else, so the R3 approval settles
    // over the observed cluster state and the runtime can pass the
    // resourceVersion to the reconciler verbatim as the compare-and-swap.
    let slot = Arc::new(kube::KubeCapabilityOwnerSlot::new());
    slot.bind(Arc::new(KubeTestOwner))
        .expect("the slot binds the owner exactly once");
    let mut registry = HostToolRegistry::new();
    registry
        .register_kube_capabilities(slot)
        .expect("kube surface registers over the bound slot");
    let definitions = registry.definitions();
    for name in [
        "kube_workload_pause",
        "kube_workload_resume",
        "kube_workload_restart",
        "kube_workload_cancel",
    ] {
        let definition = definitions
            .iter()
            .find(|definition| definition.name == name)
            .unwrap_or_else(|| panic!("{name} must be a listed mutation route"));
        assert_eq!(definition.parameters["additionalProperties"], json!(false));
        assert_eq!(
            definition.parameters["required"],
            json!(["runId", "expectedResourceVersion"]),
            "{name} must require the run and the admitted resourceVersion"
        );
        let properties = definition.parameters["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("{name} must publish an input properties object"));
        // Beyond the run, its observed revision and the approval selector,
        // only the verb's own option: a rehome target, a pause checkpoint.
        let mut keys: Vec<&str> = properties.keys().map(String::as_str).collect();
        keys.sort_unstable();
        let mut expected = vec!["approvalId", "expectedResourceVersion", "runId"];
        match name {
            "kube_workload_restart" => expected.push("targetNode"),
            "kube_workload_pause" => expected.push("checkpoint"),
            _ => {}
        }
        expected.sort_unstable();
        assert_eq!(keys, expected, "{name} invites no other keys");
        let selector = &properties["approvalId"];
        assert_eq!(selector["type"], json!("string"));
        assert_eq!(selector["minLength"], json!(1));
        assert_eq!(selector["maxLength"], json!(128));
        let expected = &properties["expectedResourceVersion"];
        assert_eq!(expected["type"], json!("string"));
        assert_eq!(expected["minLength"], json!(1));
        assert_eq!(expected["maxLength"], json!(512));
    }
}

#[test]
fn browser_input_schemas_keep_canonical_action_pairing() {
    // Provider schema restrictions belong in the model projection, not the pre-approval validator.
    for binding in BrowserCapabilityBinding::ALL {
        if binding.is_evidence_extractor() {
            continue;
        }
        let schema: Value = serde_json::from_str(binding.schema()).unwrap_or_else(|error| {
            panic!("{} input schema parses: {error}", binding.capability_id())
        });
        assert_eq!(
            schema.get("type").and_then(Value::as_str),
            Some("object"),
            "{} input schema is a top-level object",
            binding.capability_id()
        );
        if binding.pairs_action_with_arguments() {
            assert!(
                schema.get("oneOf").is_some(),
                "{} input schema keeps its canonical action/argument pairing",
                binding.capability_id()
            );
        } else {
            assert!(
                schema.get("oneOf").is_none(),
                "{} input schema lists canonically as a plain object",
                binding.capability_id()
            );
        }
    }
}

/// Strict providers reject top-level combinators; only the listed projection may drop them.
#[test]
fn browser_listed_surfaces_strip_only_the_top_level_pairing() {
    let owner: Arc<dyn BrowserCapabilityOwner> = Arc::new(BoundTestOwner);
    for binding in [
        BrowserCapabilityBinding::Observe,
        BrowserCapabilityBinding::Interact,
        BrowserCapabilityBinding::Consequential,
    ] {
        let listed = BrowserListedTool::new(binding, Arc::clone(&owner)).unwrap_or_else(|error| {
            panic!("{} listed route builds: {error}", binding.listed_name())
        });
        let parameters = &listed.definition().parameters;
        assert_eq!(
            parameters.get("type").and_then(Value::as_str),
            Some("object"),
            "{} listed parameters are a top-level object",
            binding.listed_name()
        );
        for forbidden in ["oneOf", "anyOf", "allOf", "enum", "const", "not"] {
            assert!(
                parameters.get(forbidden).is_none(),
                "{} listed parameters carry no top-level {forbidden}",
                binding.listed_name()
            );
        }
        let mut expected: Value = serde_json::from_str(binding.schema()).unwrap_or_else(|error| {
            panic!("{} input schema parses: {error}", binding.capability_id())
        });
        if binding.pairs_action_with_arguments() {
            expected
                .as_object_mut()
                .expect("canonical input schema object")
                .remove("oneOf");
        }
        assert_eq!(
            *parameters,
            expected,
            "{} listed parameters equal the canonical schema minus the top-level pairing",
            binding.listed_name()
        );
    }
}

/// A seat can only launch a profile it can name: the listed create route
/// carries the owner's launchable profiles on `profile`.
#[test]
fn the_listed_create_route_names_the_launchable_profiles() {
    let mut registry = HostToolRegistry::new();
    registry
        .register_kube_capabilities(Arc::new(KubeTestOwner))
        .expect("kube surface registers");
    let create = registry
        .definitions()
        .into_iter()
        .find(|definition| definition.name == "kube_workload_create")
        .expect("listed create route");
    let profile = create.parameters["properties"]["profile"]["description"]
        .as_str()
        .expect("profile description");
    assert!(
        profile.contains("`gpu-smoke`")
            && profile.contains("[1 GPU]")
            && profile.contains("kubert")
    );
    assert!(create.description.contains("launchable profiles"));
}
