//! Resolve pod references against enabled declarations and restrict memory to the seat and project scopes.

use std::collections::{BTreeMap, BTreeSet};

use crate::schema::{
    HarnessToml, ProjectToml, RegistryObject, SeatToml, WorkloadProfileToml, SCRIPT_HARNESS,
};
use crate::RegistryFinding;

use super::paths::relation_failure;

pub(super) fn admit_pod_harness(
    object: &RegistryObject,
    profile: &WorkloadProfileToml,
    harnesses: &BTreeMap<&str, &HarnessToml>,
    findings: &mut Vec<RegistryFinding>,
) {
    let harness = profile.harness();
    if harness == SCRIPT_HARNESS {
        return;
    }
    match harnesses.get(harness) {
        Some(declared) if declared.enabled && declared.pod => {}
        Some(_) => findings.push(relation_failure(
            object,
            format!("harness {harness:?} does not declare pod support"),
        )),
        None => findings.push(relation_failure(
            object,
            format!("harness {harness:?} is not a declared harness"),
        )),
    }
}

pub(super) fn validate_workload_relations(
    object: &RegistryObject,
    profile: &WorkloadProfileToml,
    seats: &BTreeMap<&str, &SeatToml>,
    projects: &BTreeMap<&str, &ProjectToml>,
    gateway_lanes: &BTreeSet<&str>,
    node_capabilities: &BTreeSet<&str>,
    findings: &mut Vec<RegistryFinding>,
) {
    for capability in &profile.placement {
        if !node_capabilities.contains(capability.as_str()) {
            findings.push(relation_failure(
                object,
                format!(
                    "placement {capability:?} is declared by no enabled node that admits \
                     workloads; node capabilities: {}",
                    node_capabilities
                        .iter()
                        .copied()
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        }
    }
    if let Some(reason) = profile.browser_engine_conflict() {
        findings.push(relation_failure(object, reason));
    }
    for tool in &profile.tools {
        if !crate::schema::pod_may_hold(tool.as_str()) {
            findings.push(relation_failure(
                object,
                format!(
                    "tools entry {:?} launches, delegates or creates; nothing a pod creates can \
                     create",
                    tool.as_str()
                ),
            ));
        }
    }
    let Some(seat) = seats.get(profile.seat.seat.as_str()) else {
        findings.push(relation_failure(
            object,
            format!(
                "seat binding references missing seat {:?}",
                profile.seat.seat.as_str()
            ),
        ));
        return;
    };
    if !seat.enabled {
        findings.push(relation_failure(
            object,
            format!(
                "seat binding references disabled seat {:?}",
                profile.seat.seat.as_str()
            ),
        ));
    }
    for tool in &profile.tools {
        if !seat.tool_refs.contains(tool) {
            findings.push(relation_failure(
                object,
                format!(
                    "tools entry {:?} is not a tool of seat {:?}; a pod narrows its seat's tools",
                    tool.as_str(),
                    profile.seat.seat.as_str()
                ),
            ));
        }
    }
    // Pods cannot receive capabilities that create pods, projects, seats, or plan grants.
    if seat
        .tool_refs
        .iter()
        .any(|capability| crate::CREATION_CAPABILITIES.contains(&capability.as_str()))
    {
        findings.push(relation_failure(
            object,
            format!(
                "seat binding {:?} holds creation capabilities; a pod may not run as a seat \
                 that can create pods, projects, or seats",
                profile.seat.seat.as_str()
            ),
        ));
    }
    let project_id = profile.seat.project.as_str();
    let project = match projects.get(project_id) {
        Some(project) => {
            if !project.enabled {
                findings.push(relation_failure(
                    object,
                    format!("seat binding references disabled project {project_id:?}"),
                ));
            }
            Some(*project)
        }
        None => {
            findings.push(relation_failure(
                object,
                format!("seat binding references missing project {project_id:?}"),
            ));
            None
        }
    };
    if !seat
        .project_scope
        .iter()
        .any(|scoped| scoped.as_str() == project_id)
    {
        findings.push(relation_failure(
            object,
            format!("project {project_id:?} is outside the bound seat's project_scope"),
        ));
    }
    if let Some(lane) = &profile.seat.gateway_lane {
        if !gateway_lanes.contains(lane.as_str()) {
            findings.push(relation_failure(
                object,
                // Include valid routes so authors can correct the lane instead of guessing.
                format!(
                    "gateway_lane {lane:?} is not declared by any enabled provider route; \
                     declared routes: {}",
                    gateway_lanes.iter().copied().collect::<Vec<_>>().join(", ")
                ),
            ));
        }
    }
    let Some(memory) = &profile.memory else {
        return;
    };
    if !seat
        .brain_scope
        .iter()
        .any(|scope| scope.as_str() == memory.namespace.as_str())
    {
        findings.push(relation_failure(
            object,
            format!(
                "memory namespace {:?} is outside the bound seat's brain_scope",
                memory.namespace.as_str()
            ),
        ));
    }
    // Require explicitly shared namespaces so one project cannot read another's private memory.
    if project.is_some_and(|project| {
        !project
            .memory_namespaces
            .iter()
            .any(|namespace| namespace.as_str() == memory.namespace.as_str())
    }) {
        findings.push(relation_failure(
            object,
            format!(
                "memory namespace {:?} is not declared by the bound project's \
                 memory_namespaces",
                memory.namespace.as_str()
            ),
        ));
    }
}

/// Reject missing gateway lanes instead of inferring model defaults.
pub(super) fn gateway_lane_index(objects: &[RegistryObject]) -> BTreeSet<&str> {
    objects
        .iter()
        .filter(|object| object.kind() == crate::schema::RegistryKind::Provider && object.enabled())
        .filter_map(|object| match &object.config {
            crate::schema::ObjectConfig::Provider(provider) => Some(provider),
            _ => None,
        })
        .flat_map(|provider| {
            provider
                .policy
                .routes
                .iter()
                .map(|route| route.gateway_lane_id.as_str())
        })
        .collect()
}

#[cfg(test)]
mod tests;
