use std::collections::BTreeMap;

use crate::schema::{LaneDirection, ObjectConfig, PayloadKind, RegistryKind, RegistryObject};
use crate::RegistryFinding;

use super::capabilities::validate_capability_relations;
use super::catalog::inspect_schema_catalog;
use super::containers::{validate_alias_redirect, validate_container_relations};
use super::context::RelationContext;
use super::graph::{validate_host_relations, validate_node_relations, validate_provider_relations};
use super::paths::relation_failure;
use super::refs::{
    capability_index, lane_index, project_index, seat_categories, seat_index, validate_ref,
    validate_refs, Indices,
};
use super::seats::{
    validate_brain_scope, validate_conversation_ask_capability, validate_creation_holder,
    validate_seat_lane, validate_seat_tools,
};
use super::workloads::{admit_pod_harness, gateway_lane_index, validate_workload_relations};

pub fn validate(objects: &[RegistryObject], context: &RelationContext) -> Vec<RegistryFinding> {
    let mut findings = inspect_schema_catalog(context);
    let indices = Indices::new(objects);
    let lanes = lane_index(objects);
    let projects = project_index(objects);
    let capabilities = capability_index(objects);
    let seats = seat_index(objects);
    let seat_categories = seat_categories(objects);
    let gateway_lanes = gateway_lane_index(objects);
    let harnesses: BTreeMap<&str, &crate::schema::HarnessToml> = objects
        .iter()
        .filter_map(|object| match &object.config {
            ObjectConfig::Harness(harness) => Some((object.id.as_str(), harness.as_ref())),
            _ => None,
        })
        .collect();
    let slices: Vec<_> = objects
        .iter()
        .filter_map(|object| match &object.config {
            ObjectConfig::Slice(slice) => Some(slice.as_ref()),
            _ => None,
        })
        .collect();
    let mut schema_owners = BTreeMap::new();
    // Workloads may require only capabilities declared by enabled workload nodes.
    let node_capabilities: std::collections::BTreeSet<&str> = objects
        .iter()
        .filter_map(|object| match &object.config {
            ObjectConfig::Node(node) if node.enabled && node.allow_workloads => Some(node),
            _ => None,
        })
        .flat_map(|node| node.capabilities.iter().map(String::as_str))
        .collect();

    for object in objects {
        match &object.config {
            ObjectConfig::Seat(value) => {
                validate_refs(
                    object,
                    "context.profile",
                    value.context.iter().map(|context| context.profile.as_str()),
                    RegistryKind::ContextProfile,
                    &indices,
                    &mut findings,
                );
                validate_refs(
                    object,
                    "tool_refs",
                    value.tool_refs.iter().map(|id| id.as_str()),
                    RegistryKind::Capability,
                    &indices,
                    &mut findings,
                );
                validate_refs(
                    object,
                    "project_scope",
                    value.project_scope.iter().map(|id| id.as_str()),
                    RegistryKind::Project,
                    &indices,
                    &mut findings,
                );
                validate_refs(
                    object,
                    "models",
                    value.models.iter().map(|choice| choice.provider.as_str()),
                    RegistryKind::Provider,
                    &indices,
                    &mut findings,
                );
                validate_refs(
                    object,
                    "read_project_scope",
                    value.read_project_scope.iter().map(|id| id.as_str()),
                    RegistryKind::Project,
                    &indices,
                    &mut findings,
                );
                validate_refs(
                    object,
                    "conversation.project",
                    value
                        .conversation
                        .iter()
                        .map(|conversation| conversation.project.as_str()),
                    RegistryKind::Project,
                    &indices,
                    &mut findings,
                );
                if let Some(conversation) = &value.conversation {
                    if let Some(project) = projects.get(conversation.project.as_str()) {
                        if !project.enabled {
                            findings.push(relation_failure(
                                object,
                                format!(
                                    "conversation.project {:?} references a disabled project",
                                    conversation.project.as_str()
                                ),
                            ));
                        }
                    }
                    validate_conversation_ask_capability(
                        object,
                        conversation,
                        &capabilities,
                        &mut findings,
                    );
                }
                validate_brain_scope(object, value, &mut findings);
                validate_creation_holder(object, value, &mut findings);
                validate_seat_tools(object, value, &capabilities, &slices, &mut findings);
                if let Some(live) = &value.live {
                    validate_seat_lane(
                        object,
                        "live.file_ingress_lane",
                        live.file_ingress_lane.as_str(),
                        LaneDirection::Ingress,
                        PayloadKind::File,
                        &lanes,
                        &mut findings,
                    );
                    validate_seat_lane(
                        object,
                        "live.file_egress_lane",
                        live.file_egress_lane.as_str(),
                        LaneDirection::Egress,
                        PayloadKind::File,
                        &lanes,
                        &mut findings,
                    );
                    validate_seat_lane(
                        object,
                        "live.render_ingress_lane",
                        live.render_ingress_lane.as_str(),
                        LaneDirection::Ingress,
                        PayloadKind::Render,
                        &lanes,
                        &mut findings,
                    );
                    validate_seat_lane(
                        object,
                        "live.render_egress_lane",
                        live.render_egress_lane.as_str(),
                        LaneDirection::Egress,
                        PayloadKind::Render,
                        &lanes,
                        &mut findings,
                    );
                }
            }
            ObjectConfig::Project(value) => validate_ref(
                object,
                "default_seat",
                value.default_seat.as_str(),
                RegistryKind::Seat,
                &indices,
                &mut findings,
            ),
            ObjectConfig::Lane(value) => {
                validate_ref(
                    object,
                    "project",
                    value.project.as_str(),
                    RegistryKind::Project,
                    &indices,
                    &mut findings,
                );
                validate_ref(
                    object,
                    "default_seat",
                    value.default_seat.as_str(),
                    RegistryKind::Seat,
                    &indices,
                    &mut findings,
                );
            }
            ObjectConfig::Node(value) => validate_ref(
                object,
                "host",
                &value.host,
                RegistryKind::Host,
                &indices,
                &mut findings,
            ),
            ObjectConfig::Provider(_) => {}
            ObjectConfig::Capability(value) => validate_capability_relations(
                object,
                value,
                context,
                &seats,
                &seat_categories,
                &mut schema_owners,
                &mut findings,
            ),
            ObjectConfig::Slice(value) => {
                validate_refs(
                    object,
                    "capabilities",
                    value.capabilities.iter().map(|id| id.as_str()),
                    RegistryKind::Capability,
                    &indices,
                    &mut findings,
                );
                if let Some(tools) = &value.tools {
                    for alias in &tools.alias_redirect {
                        validate_alias_redirect(
                            object,
                            alias.from.as_str(),
                            alias.to.as_str(),
                            tools.allow.contains(&alias.from),
                            tools.allow.contains(&alias.to),
                            &mut findings,
                        );
                    }
                }
            }
            ObjectConfig::Container(value) => {
                validate_container_relations(object, value, context, &indices, &mut findings)
            }
            ObjectConfig::Host(_) => {}
            ObjectConfig::Workload(value) => {
                validate_refs(
                    object,
                    "memory.profile",
                    value
                        .memory
                        .iter()
                        .filter_map(|memory| memory.profile.as_deref()),
                    RegistryKind::ContextProfile,
                    &indices,
                    &mut findings,
                );
                admit_pod_harness(object, value, &harnesses, &mut findings);
                validate_workload_relations(
                    object,
                    value,
                    &seats,
                    &projects,
                    &gateway_lanes,
                    &node_capabilities,
                    &mut findings,
                );
            }
            ObjectConfig::ClaudeCode(value) => {
                for problem in value.validate(objects) {
                    findings.push(relation_failure(object, problem));
                }
            }
            ObjectConfig::Harness(_) | ObjectConfig::ContextProfile(_) => {}
            ObjectConfig::Environment(value) => {
                for seat in &value.seats {
                    if !seats.contains_key(seat.as_str()) {
                        findings.push(relation_failure(
                            object,
                            format!("seat {:?} is not a declared seat", seat.as_str()),
                        ));
                    }
                }
            }
            ObjectConfig::Routine(value) => {
                match seats.get(value.seat.as_str()) {
                    Some(seat) if seat.enabled && seat.conversation.is_some() => {}
                    _ => findings.push(relation_failure(
                        object,
                        format!(
                            "seat {:?} is not an enabled conversation seat; a routine speaks \
                             through one",
                            value.seat.as_str()
                        ),
                    )),
                }
                if let Some(profile) = &value.trigger.profile {
                    if !indices.contains(RegistryKind::Workload, profile) {
                        findings.push(relation_failure(
                            object,
                            format!("trigger.profile {profile:?} is not a declared pod profile"),
                        ));
                    }
                }
            }
        }
    }

    validate_node_relations(objects, &mut findings);
    validate_provider_relations(objects, &mut findings);
    validate_host_relations(objects, &mut findings);
    findings.sort();
    findings
}
