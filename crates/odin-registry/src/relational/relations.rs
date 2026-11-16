use odin_domain::huginn::GATEWAY_PROVIDER;
use std::collections::BTreeMap;

use crate::schema::{LaneDirection, ObjectConfig, PayloadKind, RegistryKind, RegistryObject};
use crate::RegistryFinding;

use super::capabilities::validate_capability_relations;
use super::catalog::inspect_schema_catalog;
use super::containers::validate_container_relations;
use super::context::RelationContext;
use super::graph::{validate_host_relations, validate_node_relations, validate_provider_relations};
use super::paths::relation_failure;
use super::probes::validate_probe_relations;
use super::refs::{
    capability_index, family_member, lane_index, model_card_index, project_index, seat_index,
    validate_ref, validate_refs, Indices,
};
use super::seats::{
    validate_brain_scope, validate_conversation_ask_capability, validate_creation_holder,
    validate_seat_lane, validate_seat_tools,
};
use super::workloads::{admit_pod_harness, validate_workload_relations};

pub fn validate(objects: &[RegistryObject], context: &RelationContext) -> Vec<RegistryFinding> {
    let mut findings = inspect_schema_catalog(context);
    findings.extend(crate::toolsets::validate(
        objects,
        &context.odin_root,
        &context.schema_documents,
    ));
    let indices = Indices::new(objects);
    let lanes = lane_index(objects);
    let projects = project_index(objects);
    let capabilities = capability_index(objects);
    let seats = seat_index(objects);
    let cards = model_card_index(objects);
    let mut card_ids: BTreeMap<&str, usize> = BTreeMap::new();
    let mut card_orders: BTreeMap<(&str, u32), &str> = BTreeMap::new();
    for object in objects {
        if let ObjectConfig::Model(card) = &object.config {
            let seen = card_ids.entry(card.id.as_str()).or_default();
            *seen += 1;
            if *seen == 2 {
                findings.push(relation_failure(
                    object,
                    format!("model card id {:?} is declared more than once", card.id),
                ));
            }
            if let (Some(tier), Some(order)) =
                (card.tier.as_deref(), card.order.map(|order| order.get()))
            {
                if let Some(previous) = card_orders.insert((tier, order), card.id.as_str()) {
                    findings.push(relation_failure(
                        object,
                        format!(
                            "class order {order} in tier {tier:?} is declared by both \
                             {previous:?} and {:?}",
                            card.id
                        ),
                    ));
                }
            }
        }
    }
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
    let workload_nodes: Vec<&crate::schema::NodeToml> = objects
        .iter()
        .filter_map(|object| match &object.config {
            ObjectConfig::Node(node) if node.enabled && node.allow_workloads => Some(&**node),
            _ => None,
        })
        .collect();

    let mut workload_owners = BTreeMap::new();
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
                for choice in &value.models {
                    let card_id = format!("{}/{}", choice.provider.as_str(), choice.model.as_str());
                    let gateway = choice.provider.as_str() == GATEWAY_PROVIDER;
                    if gateway && family_member(&cards, choice.model.as_str()) {
                        continue;
                    }
                    match cards.get(card_id.as_str()) {
                        Some(card) if card.enabled && card.seats => {
                            if gateway && card.route != GATEWAY_PROVIDER {
                                findings.push(relation_failure(
                                    object,
                                    format!(
                                        "models entry {card_id:?} is a gateway id on the {route} route",
                                        route = card.route
                                    ),
                                ));
                            }
                            if !gateway && card.route == GATEWAY_PROVIDER {
                                findings.push(relation_failure(
                                    object,
                                    format!(
                                        "models entry {card_id:?} names a gateway card under a non-gateway provider"
                                    ),
                                ));
                            }
                        }
                        Some(card) if !card.enabled => findings.push(relation_failure(
                            object,
                            format!("models entry {card_id:?} references a disabled model card"),
                        )),
                        Some(_) => findings.push(relation_failure(
                            object,
                            format!("models entry {card_id:?} is a model card not open to seats"),
                        )),
                        None => findings.push(relation_failure(
                            object,
                            format!("models entry {card_id:?} references a missing model card"),
                        )),
                    }
                }
                if let Some(context) = &value.context {
                    let lanes = [
                        ("context.review_lane", context.review_lane.as_deref()),
                        (
                            "context.consult.lane",
                            context
                                .consult
                                .as_ref()
                                .map(|consult| consult.lane.as_str()),
                        ),
                    ];
                    for (field, lane) in lanes
                        .into_iter()
                        .filter_map(|(field, lane)| lane.map(|lane| (field, lane)))
                    {
                        let card_id = format!("{GATEWAY_PROVIDER}/{lane}");
                        if !cards.contains_key(card_id.as_str()) {
                            findings.push(relation_failure(
                                object,
                                format!("{field} references a missing model card {card_id:?}"),
                            ));
                        }
                    }
                }
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
            ObjectConfig::Project(value) => {
                validate_ref(
                    object,
                    "default_seat",
                    value.default_seat.as_str(),
                    RegistryKind::Seat,
                    &indices,
                    &mut findings,
                );
                for (role, lane) in &value.agents {
                    let card_id = format!("{GATEWAY_PROVIDER}/{lane}");
                    if !cards.get(card_id.as_str()).is_some_and(|card| card.enabled) {
                        findings.push(relation_failure(
                            object,
                            format!(
                                "agents.{role} = {lane:?} names no enabled model card {card_id:?}"
                            ),
                        ));
                    }
                }
                if let Some(deploy) = &value.deploy {
                    for host in std::iter::once(&deploy.host).chain(&deploy.targets) {
                        validate_ref(
                            object,
                            "deploy",
                            host,
                            RegistryKind::Host,
                            &indices,
                            &mut findings,
                        );
                    }
                }
            }
            ObjectConfig::Lane(value) => {
                validate_ref(
                    object,
                    "project",
                    value.project.as_str(),
                    RegistryKind::Project,
                    &indices,
                    &mut findings,
                );
                if value.owns_workloads {
                    if let Some(other) = workload_owners.insert(&value.project, &object.id) {
                        findings.push(relation_failure(
                            object,
                            format!(
                                "owns_workloads: project {:?} is already owned by lane {other:?}",
                                value.project.as_str()
                            ),
                        ));
                    }
                }
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
            ObjectConfig::Provider(value) => {
                for route in &value.policy.routes {
                    let card_id = format!("{GATEWAY_PROVIDER}/{}", route.gateway_lane_id);
                    if !cards.contains_key(card_id.as_str()) {
                        findings.push(relation_failure(
                            object,
                            format!(
                                "policy route lane {:?} references a missing model card {card_id:?}",
                                route.gateway_lane_id
                            ),
                        ));
                    }
                }
            }
            ObjectConfig::Model(value) => {
                for fallback in &value.fallbacks {
                    match cards.get(format!("{GATEWAY_PROVIDER}/{fallback}").as_str()) {
                        Some(card) if card.enabled => {}
                        Some(_) => findings.push(relation_failure(
                            object,
                            format!("fallback {fallback:?} references a disabled model card"),
                        )),
                        None => findings.push(relation_failure(
                            object,
                            format!("fallback {fallback:?} references a missing model card"),
                        )),
                    }
                }
            }
            ObjectConfig::Capability(value) => validate_capability_relations(
                object,
                value,
                context,
                &seats,
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
                for target in value.offload.iter().flat_map(|offload| &offload.targets) {
                    let declared = objects
                        .iter()
                        .find_map(|candidate| match &candidate.config {
                            ObjectConfig::ComputeTarget(declared) if &candidate.id == target => {
                                Some(declared)
                            }
                            _ => None,
                        });
                    match declared {
                        None => findings.push(relation_failure(
                            object,
                            format!("offload target {target:?} is not a declared compute target"),
                        )),
                        Some(declared)
                            if !declared
                                .allowed_projects
                                .contains(value.seat.project.as_str()) =>
                        {
                            findings.push(relation_failure(
                                object,
                                format!(
                                    "offload target {target:?} does not admit project {:?}",
                                    value.seat.project.as_str()
                                ),
                            ))
                        }
                        Some(declared)
                            if value
                                .offload
                                .as_ref()
                                .is_some_and(|offload| offload.restricted_data)
                                && !declared.restricted_data =>
                        {
                            findings.push(relation_failure(
                                object,
                                format!("offload target {target:?} does not take restricted data"),
                            ))
                        }
                        Some(_) => {}
                    }
                }
                validate_workload_relations(
                    object,
                    value,
                    &seats,
                    &projects,
                    &node_capabilities,
                    &mut findings,
                );
                let placeable = value.data.is_empty()
                    || workload_nodes.iter().any(|node| {
                        value
                            .placement
                            .iter()
                            .all(|capability| node.capabilities.contains(capability))
                            && node
                                .covers_data(value.data.iter().map(|data| data.host_path.as_str()))
                    });
                if !placeable {
                    findings.push(relation_failure(
                        object,
                        "workload-data-unplaceable: no enabled workload node satisfying the \
                         placement declares data_roots covering every [[data]] host_path",
                    ));
                }
                if let Some(lane) = value.seat.gateway_lane.as_deref() {
                    let card_id = format!("{GATEWAY_PROVIDER}/{lane}");
                    if !cards.contains_key(card_id.as_str()) {
                        findings.push(relation_failure(
                            object,
                            format!(
                                "gateway_lane {lane:?} references a missing model card {card_id:?}"
                            ),
                        ));
                    }
                }
            }
            ObjectConfig::ClaudeCode(value) => {
                for problem in value.validate(objects) {
                    findings.push(relation_failure(object, problem));
                }
            }
            ObjectConfig::BrainRole(value) if value.enabled => {
                for lane in value.lanes() {
                    let card_id = format!("{GATEWAY_PROVIDER}/{lane}");
                    if !cards.contains_key(card_id.as_str()) && !family_member(&cards, lane) {
                        findings.push(relation_failure(
                            object,
                            format!("lane {lane:?} references a missing model card {card_id:?}"),
                        ));
                    }
                }
            }
            ObjectConfig::BrainRole(_) => {}
            ObjectConfig::Harness(_)
            | ObjectConfig::ContextProfile(_)
            | ObjectConfig::Toolset(_)
            | ObjectConfig::Feature(_)
            | ObjectConfig::ComputeTarget(_)
            | ObjectConfig::ComputeProvider(_) => {}
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
    validate_probe_relations(objects, &indices, &mut findings);
    findings.sort();
    findings
}
