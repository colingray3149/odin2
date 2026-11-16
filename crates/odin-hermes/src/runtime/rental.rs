//! Prepared kernel boundary for provider rentals.
use super::{tools::CapabilityTool, HermesRuntime};
use odin_domain::Scope;
use odin_kernel::PreparedEffect;
use odin_omp::host_tools::schema_compat::declared_parameters;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode};
use serde_json::Value;
use std::sync::Arc;

pub trait RentalRoute: Send + Sync {
    fn preflight(&self, capability: &str, scope: &Scope, arguments: &Value) -> Result<(), String>;
    fn execute(
        &self,
        effect: &PreparedEffect,
        scope: Scope,
        arguments: Value,
    ) -> Result<Value, HostToolError>;
}

pub(super) fn rental_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    for (name, capability, schema) in [
        (
            "compute_lease_create",
            "compute.lease.create",
            include_str!("../../../../schemas/capability/compute.lease.create.input.json"),
        ),
        (
            "compute_lease_destroy",
            "compute.lease.destroy",
            include_str!("../../../../schemas/capability/compute.lease.destroy.input.json"),
        ),
        (
            "compute_lease_enroll",
            "compute.lease.enroll",
            include_str!("../../../../schemas/capability/compute.lease.enroll.input.json"),
        ),
        (
            "compute_lease_list",
            "compute.lease.list",
            include_str!("../../../../schemas/capability/compute.lease.list.input.json"),
        ),
    ] {
        let handler = Arc::clone(runtime);
        let preflight = Arc::clone(runtime);
        tools.push(Arc::new(CapabilityTool::prepared(
            RpcHostToolDefinition {
                name: name.into(),
                label: name.into(),
                description: format!("Governed {capability} operation").into(),
                parameters: declared_parameters(schema),
                hidden: false,
                load_mode: ToolLoadMode::Discoverable,
            },
            Box::new(move |effect, scope, arguments| {
                let bound =
                    serde_json::to_value(&scope).map_err(|error| HostToolError::Arguments {
                        tool: name,
                        detail: error.to_string(),
                    })?;
                if effect.contract().id.as_str() != capability
                    || effect.contract().tool_name.as_str() != name
                    || effect.payload().arguments != arguments
                    || effect.executor_binding().and_then(|v| v.get("scope")) != Some(&bound)
                    || scope.run.as_ref().is_none_or(|run| {
                        effect.target().kind != "run" || effect.target().id != run.as_str()
                    })
                {
                    return Err(HostToolError::Catalog {
                        detail: format!(
                            "{name} requires its exact prepared contract, payload and run scope"
                        ),
                    });
                }
                if capability != "compute.lease.list"
                    && effect.contract().approval
                        != odin_kernel::capability::ApprovalRequirement::Operator
                {
                    return Err(HostToolError::Catalog {
                        detail: format!("{name} requires operator approval"),
                    });
                }
                let route = route(&handler, name)?;
                let result = route.execute(effect, scope, arguments)?;
                odin_omp::host_tools::response(name, &result)
            }),
            Box::new(move |scope, arguments| {
                route(&preflight, name)?
                    .preflight(capability, scope, arguments)
                    .map_err(|reason| HostToolError::Unavailable { tool: name, reason })
            }),
        )));
    }
}

fn route(
    runtime: &HermesRuntime,
    tool: &'static str,
) -> Result<Arc<dyn RentalRoute>, HostToolError> {
    runtime
        .rental_route
        .lock()
        .map_err(|error| HostToolError::Storage {
            tool,
            detail: error.to_string(),
        })?
        .clone()
        .ok_or_else(|| HostToolError::Unavailable {
            tool,
            reason: "rental route is not bound".into(),
        })
}

impl HermesRuntime {
    pub fn set_rental_route(&self, route: Arc<dyn RentalRoute>) {
        if let Ok(mut cell) = self.rental_route.lock() {
            *cell = Some(route);
        }
    }
}
