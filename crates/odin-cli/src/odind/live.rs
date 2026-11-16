//! Async daemon composition and serving, entered through `serving`.

use std::sync::Arc;

#[path = "live/adapter_inputs.rs"]
mod adapter_inputs;
#[path = "live/brain_bindings.rs"]
mod brain_bindings;
#[path = "live/browser_capsule.rs"]
mod browser_capsule;
#[path = "live/deferred_delegations.rs"]
mod deferred_delegations;
#[path = "live/harness_launch.rs"]
mod harness_launch;
#[path = "live/hermes_routes.rs"]
pub(crate) mod hermes_routes;
#[path = "live/kube_cell.rs"]
mod kube_cell;
#[path = "launch_queue.rs"]
pub(super) mod launch_queue;
#[path = "live/model_windows.rs"]
mod model_windows;
#[path = "offload.rs"]
pub(crate) mod offload;
#[path = "live/pump_arming.rs"]
mod pump_arming;
#[path = "repo_watch.rs"]
pub(crate) mod repo_watch;
#[path = "live/root_consent_wake.rs"]
mod root_consent_wake;
#[path = "live/serving.rs"]
pub(crate) mod serving;
#[path = "live/compose.rs"]
mod compose;
#[path = "compute_meter.rs"]
mod compute_meter;
#[path = "live/session_discovery.rs"]
mod session_discovery;
#[path = "live/settle.rs"]
mod settle;
#[path = "live/shutdown.rs"]
mod shutdown;
#[path = "live/spheres.rs"]
mod spheres;
#[path = "live/vehicle_open.rs"]
mod vehicle_open;
#[path = "live/worker_process.rs"]
mod worker_process;
#[path = "workload.rs"]
pub(crate) mod workload;
#[path = "workload_monitor.rs"]
mod workload_monitor;
#[path = "workload_recovery.rs"]
mod workload_recovery;
#[path = "workload_review.rs"]
mod workload_review;
#[path = "workload_watch.rs"]
pub(super) mod workload_watch;
use compose::serve_huginn_async;

fn rental_approval(
    project: &str,
    input: &serde_json::Value,
    id: &str,
) -> Result<odin_registry::RentalApproval, String> {
    let provider = input
        .get("provider")
        .and_then(serde_json::Value::as_str)
        .filter(|provider| !provider.is_empty())
        .ok_or_else(|| "spend approval has no provider".to_owned())?;
    let hours = input
        .get("hours")
        .and_then(serde_json::Value::as_u64)
        .and_then(|hours| u32::try_from(hours).ok())
        .filter(|hours| *hours > 0)
        .ok_or_else(|| "spend approval has invalid hours".to_owned())?;
    let estimated_usd = input
        .get("estimated_usd")
        .and_then(serde_json::Value::as_f64)
        .ok_or_else(|| "spend approval has invalid estimate".to_owned())?;
    let approved_cap_usd = input
        .get("cap_usd")
        .and_then(serde_json::Value::as_f64)
        .ok_or_else(|| "spend approval has invalid cap".to_owned())?;
    Ok(odin_registry::RentalApproval {
        id: id.to_owned(),
        project: project.to_owned(),
        provider: provider.to_owned(),
        hours,
        estimated_usd,
        approved_cap_usd,
    })
}

#[cfg(test)]
mod project_sphere_tests {
    use super::spheres::declared_project_spheres;
    use odin_registry::schema::{ObjectConfig, ProjectSphereToml, ProjectToml, RegistryKind};
    use odin_registry::RegistryObject;

    fn project(id: &str, enabled: bool, sphere: Option<ProjectSphereToml>) -> RegistryObject {
        RegistryObject {
            id: id.to_owned(),
            relative_config: format!("projects/{id}/project.toml").into(),
            config: ObjectConfig::Project(Box::new(ProjectToml {
                schema: odin_registry::schema::REGISTRY_SCHEMA.to_owned(),
                kind: RegistryKind::Project,
                enabled,
                description: "fixture".to_owned(),
                source_root: "/work".to_owned(),
                default_seat: "gungnir".parse().expect("seat"),
                memory_namespaces: Default::default(),
                privacy: None,
                accounts: Default::default(),
                review_verdict: None,
                repo: None,
                deploy: None,
                sphere,
                hub_refresh_seconds: None,
                agents: Default::default(),
            })),
        }
    }

    fn sphere(scratch: &str, data_roots: Vec<String>) -> ProjectSphereToml {
        ProjectSphereToml {
            data_roots,
            scratch: scratch.to_owned(),
            pod_profiles: Default::default(),
            devices: Vec::new(),
        }
    }

}

#[cfg(test)]
use serving::orchestrate_serving;

#[cfg(test)]
#[path = "tests/browser_capsule.rs"]
mod browser_capsule_tests;

