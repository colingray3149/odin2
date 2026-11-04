use super::*;

use crate::host_tools::binding::{BrowserCapabilityTool, BrowserListedTool, FramedExecTool};

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

/// A browser service that answers observations from a page it holds and refuses a closed session.
struct FakeBrowser;

const OPEN_SESSION: &str = "00000000-0000-4000-8000-000000000001";

impl BrowserCapabilityOwner for FakeBrowser {
    fn invoke_browser_capability(
        &self,
        binding: BrowserCapabilityBinding,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        if invocation.arguments["sessionId"] != OPEN_SESSION {
            return Err(HostToolError::unavailable(
                binding.id(),
                "the browser session is closed",
            ));
        }
        Ok(json!({
            "kind": invocation.arguments["kind"],
            "trust": "untrusted",
            "text": "Order summary",
        }))
    }

    fn preflight_browser_capability(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        binding: BrowserCapabilityBinding,
        _scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        if arguments["sessionId"] != OPEN_SESSION {
            return Err(HostToolError::unavailable(
                binding.id(),
                "the browser session is closed",
            ));
        }
        Ok(())
    }
}

/// browser.observe reaches the browser through its owner slot and returns the typed read; a
/// closed session and an unbound slot are refused by name.
#[test]
fn browser_observe_returns_the_typed_read_and_refuses_a_closed_session_or_an_unbound_slot() {
    let slot = Arc::new(BrowserCapabilityOwnerSlot::new());
    let tool = BrowserCapabilityTool::new(
        BrowserCapabilityBinding::Observe,
        Arc::clone(&slot) as Arc<dyn BrowserCapabilityOwner>,
    )
    .expect("observe binding builds");
    let observe = |session: &str| {
        tool.invoke(exec_invocation(
            json!({"sessionId": session, "kind": "text", "maxBytes": 4096}),
        ))
    };
    let unbound = observe(OPEN_SESSION).expect_err("no browser is bound yet");
    assert!(
        matches!(&unbound, HostToolError::Catalog { detail } if detail.contains("not bound")),
        "{unbound:?}"
    );

    slot.bind(Arc::new(FakeBrowser)).expect("bind once");
    assert!(
        slot.bind(Arc::new(FakeBrowser)).is_err(),
        "the owner binds once"
    );
    let read = observe(OPEN_SESSION).expect("the page reads");
    assert_eq!(
        read,
        json!({"kind": "text", "trust": "untrusted", "text": "Order summary"})
    );
    let closed = observe("00000000-0000-4000-8000-000000000002").expect_err("closed session");
    assert!(
        matches!(&closed, HostToolError::Unavailable { reason, .. } if reason.contains("session is closed")),
        "{closed:?}"
    );
    let refused = tool.preflight(
        &crate::host_tools::fixtures::fixture_contract(),
        &Scope::default(),
        &json!({"sessionId": "00000000-0000-4000-8000-000000000002"}),
    );
    assert!(
        matches!(refused, Err(HostToolError::Unavailable { .. })),
        "{refused:?}"
    );
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
