use std::path::Path;

use super::*;

static ECHO_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 2,
    input_schema: "schemas/capability/fixture.echo.input.json",
    output_schema: "schemas/capability/fixture.echo.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_fixture_echo",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_fixture_echo_evidence",
    },
};

static EXTRACT_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/fixture.extract.input.json",
    output_schema: "schemas/capability/fixture.extract.output.json",
    handler: CompiledHandlerBinding::Exec {
        executable:
            "/nix/store/q0000000000000000000000000000000-odin-fixture/bin/odin-fixture-extract",
        argv: &["--framed", "--json"],
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_fixture_extract_evidence",
    },
};

static EMPTY_ARGV: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/fixture.noargv.input.json",
    output_schema: "schemas/capability/fixture.noargv.output.json",
    handler: CompiledHandlerBinding::Exec {
        executable: "/nix/store/q0000000000000000000000000000000-odin/bin/tool",
        argv: &[],
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_fixture_noargv_evidence",
    },
};

static TEST_BINDINGS: &[&CompiledCapabilityBinding] =
    &[&ECHO_BINDING, &EXTRACT_BINDING, &EMPTY_ARGV];
fn registry_with(name: &'static str) -> HostToolRegistry {
    let mut registry = HostToolRegistry::new();
    registry
        .register(Arc::new(StubTool::new(name)))
        .expect("unique stub name registers");
    registry
}

#[test]
fn compiled_host_tool_binding_matches_real_enabled_registry_and_production_surface() {
    let declarations = real_enabled_capabilities();
    let catalog =
        CompiledHostToolCatalog::compile(PRE_ADMITTED_BINDINGS).expect("compiled catalog");
    assert!(!declarations.is_empty());
    CompiledHostToolCatalog::compile(crate::host_tools::production_bindings())
        .expect("compiled production catalog");

    for (id, capability) in &declarations {
        assert!(!id.is_empty(), "logical capability id is retained");
        let admitted = odin_registry::relational::AdmittedBinding {
            version: capability.version,
            input_schema: capability.input_schema.clone().expect("input schema"),
            output_schema: capability.output_schema.clone().expect("output schema"),
            handler: capability.handler.clone().expect("handler"),
            evidence_extractor: capability.evidence_extractor.clone().expect("extractor"),
        };
        if capability.implementation.as_deref() == Some("operator") {
            // Operator CLI capabilities must not acquire a model-dispatch route.
            assert!(
                !crate::host_tools::production_bindings()
                    .iter()
                    .any(|binding| binding.to_admitted_binding() == admitted),
                "operator capability {id} must not be a compiled host-tool tuple"
            );
            continue;
        }
        if capability.is_pod_exec() {
            // Pod-exec capabilities admit by their markers and [exec] table.
            assert!(
                capability.binds_pod_exec_markers() && capability.exec.is_some(),
                "pod-exec capability {id} must bind the pod-exec markers and declare [exec]"
            );
            continue;
        }
        if capability.is_workflow() {
            // Workflow capabilities admit by their markers; odind checks the compiled function.
            assert!(
                capability.binds_workflow_markers(),
                "workflow capability {id} must bind the workflow markers"
            );
            assert!(
                !crate::host_tools::production_bindings()
                    .iter()
                    .any(|binding| binding.to_admitted_binding() == admitted),
                "workflow capability {id} must not be a compiled host-tool tuple"
            );
            continue;
        }
        if let Some(adapter) = capability.adapter_implementation() {
            // Declared-adapter capabilities are admitted by declaration: they
            // bind the two markers, never a compiled host-tool tuple; the
            // adapter's descriptor is checked at dispatch.
            assert!(
                capability.binds_adapter_markers(),
                "adapter capability {id} ({adapter}) must bind the declared-adapter markers"
            );
            assert!(
                !crate::host_tools::production_bindings()
                    .iter()
                    .any(|binding| binding.to_admitted_binding() == admitted),
                "adapter capability {id} must not be a compiled host-tool tuple"
            );
            continue;
        }
        assert!(
            crate::host_tools::production_bindings()
                .iter()
                .any(|binding| binding.to_admitted_binding() == admitted),
            "enabled {id} must match a production admitted tuple"
        );
    }

    let root = std::env::temp_dir().join(format!(
        "odin-omp-compiled-host-tool-binding-{}",
        std::process::id()
    ));
    for directory in ["crates/demo/src", "extension", "registry", "skeletons"] {
        fs::create_dir_all(root.join(directory)).expect("create atlas fixture directory");
    }
    fs::write(
        root.join("crates/demo/src/lib.rs"),
        "pub fn stable(value: u64) -> u64 { value }\n",
    )
    .expect("write Rust fixture");
    let mut production_registry = HostToolRegistry::model_visible(ModelVisibleToolConfig {
        ledger: Arc::new(Mutex::new(
            Ledger::open_in_memory().expect("in-memory ledger opens"),
        )),
        atlas: Arc::new(OnceLock::from(Arc::new(
            odin_atlas::build(AtlasSources::new(&root)).expect("build atlas fixture"),
        ))),
        allowed_atlas_scope: AtlasScope::seat(["coding".to_owned()]).expect("valid seat scope"),
    })
    .expect("real production HostTool registry assembles");
    let missing = catalog
        .validate_production_composition(&production_registry)
        .expect_err("model-visible tools alone do not own the enabled capability surface");
    assert!(matches!(missing, HostToolError::Catalog { .. }));
    let task_slot = Arc::new(delegation::TaskOwnerSlot::new());
    production_registry
        .register_task_capabilities(Arc::clone(&task_slot))
        .expect("task HostTools register over the production owner slot");
    let task_owner: Arc<dyn delegation::TaskOwner> = Arc::new(CatalogTestTaskOwner);
    task_slot
        .bind(task_owner)
        .expect("concrete task test owner binds");
    production_registry
        .register_context_read(&root, 4_096)
        .expect("bounded context HostTools register");
    let brain_slot = Arc::new(std::sync::OnceLock::new());
    let root_registry = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../registry");
    let parsed = odin_registry::parse_objects(&odin_registry::walk(root_registry).objects);
    let contracts = parsed
        .objects
        .iter()
        .filter(|object| object.enabled())
        .filter_map(|object| {
            let odin_registry::ObjectConfig::Capability(capability) = &object.config else {
                return None;
            };
            let admitted = odin_registry::relational::declared_admitted_binding(capability)
                .expect("enabled capability binding");
            let contract = odin_kernel::CapabilityContract::try_from_registry(object, &admitted)
                .expect("registry capability contract");
            Some((contract.id.clone(), contract))
        })
        .collect();
    crate::host_tools::brain::register(
        &mut production_registry,
        Arc::clone(&brain_slot),
        &contracts,
    )
    .expect("governed brain tools register");
    let owner: Arc<dyn BrowserCapabilityOwner> = Arc::new(BoundTestOwner);
    production_registry
        .register_browser_capabilities(owner)
        .expect("concrete browser HostTools register");
    let canonical: Arc<dyn CanonicalV2CapabilityOwner> = Arc::new(CanonicalTestOwner);
    production_registry
        .register_canonical_v2_capabilities(canonical)
        .expect("canonical-v2 authority HostTools register");
    let kube_owner: Arc<dyn kube::KubeCapabilityOwner> = Arc::new(KubeTestOwner);
    production_registry
        .register_kube_capabilities(kube_owner)
        .expect("concrete kube HostTools register");
    let definitions = production_registry.definitions();
    let names: Vec<&str> = definitions
        .iter()
        .map(|definition| definition.name.as_ref())
        .collect();
    assert!(
        definitions.iter().all(|definition| !definition.hidden),
        "every listed production definition must remain model-visible"
    );
    // Memory tools must be available without a tool-discovery search.
    for brain in ["brain_search", "brain_read"] {
        let definition = definitions
            .iter()
            .find(|definition| definition.name.as_ref() == brain)
            .expect("brain tool listed");
        assert_eq!(definition.load_mode, ToolLoadMode::Essential, "{brain}");
    }
    for binding in BrowserCapabilityBinding::ALL {
        assert!(
            !names.contains(&binding.id()),
            "{} must remain an unlisted internal adapter",
            binding.id()
        );
        catalog
            .resolve(binding.id(), &production_registry)
            .expect("hidden browser adapter resolves");
    }
    for binding in CanonicalV2CapabilityBinding::ALL {
        assert!(
            !names.contains(&binding.id()),
            "{} must remain an unlisted internal adapter",
            binding.id()
        );
        catalog
            .resolve(binding.id(), &production_registry)
            .expect("hidden canonical-v2 adapter resolves");
    }
    for binding in kube::KubeCapabilityBinding::ALL {
        assert!(
            !names.contains(&binding.id()),
            "{} must remain an unlisted internal adapter",
            binding.id()
        );
        catalog
            .resolve(binding.id(), &production_registry)
            .expect("hidden kube adapter resolves");
    }
    for id in [
        CONTEXT_READ_HANDLER_ID,
        CONTEXT_READ_EVIDENCE_ID,
        delegation::TASK_CREATE_HANDLER_ID,
        delegation::TASK_CREATE_EVIDENCE_ID,
        delegation::TASK_READ_HANDLER_ID,
        delegation::TASK_READ_EVIDENCE_ID,
    ] {
        assert!(
            !names.contains(&id),
            "{id} must remain an unlisted internal adapter"
        );
        catalog
            .resolve(id, &production_registry)
            .expect("internal context/task adapter resolves");
    }
    catalog
        .validate_production_composition(&production_registry)
        .expect("every pre-admitted binding has a concrete HostTool owner");
    let error = catalog
        .resolve("odin_not_a_tool", &production_registry)
        .err()
        .expect("registered production tool outside catalog must not resolve");
    assert!(
        matches!(&error, HostToolError::Catalog { detail }
                if detail.contains("not bound in the compiled catalog")),
        "unexpected denial: {error}"
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn compiled_host_tool_binding_resolves_only_cataloged_builtin_handlers() {
    let catalog = CompiledHostToolCatalog::compile(TEST_BINDINGS).expect("static entries compile");
    assert_eq!(catalog.bindings().count(), 3);
    let registry = registry_with("odin_fixture_echo");
    let tool = catalog
        .resolve("odin_fixture_echo", &registry)
        .expect("cataloged builtin handler resolves");
    assert_eq!(tool.definition().name, "odin_fixture_echo");
}

#[test]
fn exec_binding_requires_registered_identity_then_actuates_over_framed_stdin_stdout() {
    let catalog = CompiledHostToolCatalog::compile(TEST_BINDINGS)
        .expect("catalog with one Exec binding compiles");
    let unregistered = HostToolRegistry::new();
    let error = catalog
        .validate_production_composition(&unregistered)
        .expect_err("an Exec identity without a HostTool owner is denied");
    assert!(
        matches!(&error, HostToolError::Catalog { detail }
                if detail.contains("has no concrete production HostTool owner")),
        "unexpected denial: {error}"
    );

    let executable = "/nix/store/q0000000000000000000000000000000-odin/bin/tool".to_owned();
    let mut registry = registry_with("odin_fixture_echo");
    registry
        .register_internal(
            InternalBindingKey::Builtin("odin_fixture_echo_evidence".to_owned()),
            Arc::new(StubTool::new("odin_fixture_echo_evidence")),
        )
        .expect("evidence stub registers");
    registry
        .register_internal(
            InternalBindingKey::Builtin("odin_fixture_extract_evidence".to_owned()),
            Arc::new(StubTool::new("odin_fixture_extract_evidence")),
        )
        .expect("extract evidence stub registers");
    registry
        .register_internal(
            InternalBindingKey::Builtin("odin_fixture_noargv_evidence".to_owned()),
            Arc::new(StubTool::new("odin_fixture_noargv_evidence")),
        )
        .expect("noargv evidence stub registers");
    let worker = crate::process::launch_for_fixture(Path::new("/bin/sh"));
    registry
        .register_framed_exec(executable.clone(), Vec::new(), worker.clone())
        .expect("the framed exec HostTool registers under its identity");
    registry
        .register_framed_exec(
            "/nix/store/q0000000000000000000000000000000-odin-fixture/bin/odin-fixture-extract"
                .to_owned(),
            vec!["--framed".to_owned(), "--json".to_owned()],
            worker,
        )
        .expect("the extract exec HostTool registers under its identity");
    assert!(
        registry.resolves_admitted(&odin_registry::schema::HandlerBindingToml::Exec(
            odin_registry::schema::ExecHandlerToml {
                executable: executable.clone(),
                argv: Vec::new(),
            }
        ))
    );
    assert!(
        !registry.resolves_admitted(&odin_registry::schema::HandlerBindingToml::Exec(
            odin_registry::schema::ExecHandlerToml {
                executable: "/nix/store/q0000000000000000000000000000000-other/bin/tool".to_owned(),
                argv: Vec::new(),
            }
        ))
    );
    catalog
        .validate_production_composition(&registry)
        .expect("the registered exec identity owns its catalog binding");
}

#[test]
fn extractor_reuse_requires_identical_outputs_and_never_aliases_a_handler() {
    static SHARED: CompiledCapabilityBinding = CompiledCapabilityBinding {
        input_schema: "schemas/capability/fixture.shared_evidence.input.json",
        handler: CompiledHandlerBinding::Builtin {
            id: "fixture_shared_evidence_handler",
        },
        ..ECHO_BINDING
    };
    static WRONG_OUTPUT: CompiledCapabilityBinding = CompiledCapabilityBinding {
        output_schema: "schemas/capability/fixture.other.output.json",
        ..SHARED
    };
    static WRONG_VERSION: CompiledCapabilityBinding = CompiledCapabilityBinding {
        version: ECHO_BINDING.version + 1,
        ..SHARED
    };
    static ROLE_ALIAS: CompiledCapabilityBinding = CompiledCapabilityBinding {
        handler: ECHO_BINDING.evidence_extractor,
        ..SHARED
    };
    static SHARING: &[&CompiledCapabilityBinding] = &[&ECHO_BINDING, &SHARED];
    static OUTPUT_CONFLICT: &[&CompiledCapabilityBinding] = &[&ECHO_BINDING, &WRONG_OUTPUT];
    static VERSION_CONFLICT: &[&CompiledCapabilityBinding] = &[&ECHO_BINDING, &WRONG_VERSION];
    static ROLE_CONFLICT: &[&CompiledCapabilityBinding] = &[&ECHO_BINDING, &ROLE_ALIAS];
    assert!(CompiledHostToolCatalog::compile(SHARING).is_ok());
    assert!(CompiledHostToolCatalog::compile(OUTPUT_CONFLICT).is_err());
    assert!(CompiledHostToolCatalog::compile(VERSION_CONFLICT).is_err());
    assert!(CompiledHostToolCatalog::compile(ROLE_CONFLICT).is_err());
}
