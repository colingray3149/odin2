use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::schema::{ObjectConfig, RegistryObject};
use crate::RegistryFinding;

use super::paths::relation_failure;

pub(super) fn validate_node_relations(
    objects: &[RegistryObject],
    findings: &mut Vec<RegistryFinding>,
) {
    let hosts: BTreeMap<&str, _> = objects
        .iter()
        .filter_map(|object| match &object.config {
            ObjectConfig::Host(host) => Some((object.id.as_str(), (object, host.as_ref()))),
            _ => None,
        })
        .collect();
    let enabled_nodes: Vec<_> = objects
        .iter()
        .filter_map(|object| match &object.config {
            ObjectConfig::Node(value) if value.enabled => Some((object, value.as_ref())),
            _ => None,
        })
        .collect();
    let authorities: Vec<_> = enabled_nodes
        .iter()
        .filter(|(_, node)| node.authoritative_state)
        .collect();
    if authorities.len() != 1 {
        findings.push(RegistryFinding::fail(
            "registry-node-authority",
            PathBuf::from("registry/nodes"),
            format!(
                "exactly one enabled node must hold authoritative_state, found {}",
                authorities.len()
            ),
        ));
    }

    let mut active_by_host: BTreeMap<&str, &RegistryObject> = BTreeMap::new();
    for (object, node) in enabled_nodes {
        let Some((host_object, host)) = hosts.get(node.host.as_str()).copied() else {
            continue;
        };
        if !host.enabled || !host.enrolled {
            findings.push(relation_failure(
                object,
                format!(
                    "enabled node references host {:?} that is not both enabled and enrolled",
                    node.host
                ),
            ));
        }
        if node.role != host.role {
            findings.push(relation_failure(
                object,
                format!(
                    "enabled node role {:?} does not match host {} deployment role {:?}",
                    node.role,
                    host_object.relative_config.display(),
                    host.role
                ),
            ));
        }
        if let Some(previous) = active_by_host.insert(&node.host, object) {
            findings.push(relation_failure(
                object,
                format!(
                    "host {:?} has more than one enabled node; previous is {}",
                    node.host,
                    previous.relative_config.display()
                ),
            ));
        }
    }
}

pub(super) fn validate_provider_relations(
    objects: &[RegistryObject],
    findings: &mut Vec<RegistryFinding>,
) {
    let enabled_count = objects
        .iter()
        .filter(|object| matches!(&object.config, ObjectConfig::Provider(value) if value.enabled))
        .count();
    if objects
        .iter()
        .any(|object| matches!(&object.config, ObjectConfig::Seat(value) if value.enabled))
        && enabled_count == 0
    {
        findings.push(RegistryFinding::fail(
            "registry-provider-availability",
            PathBuf::from("registry/providers"),
            "enabled seats require at least one enabled provider",
        ));
    }
}

pub(super) fn validate_host_relations(
    objects: &[RegistryObject],
    findings: &mut Vec<RegistryFinding>,
) {
    let enrolled = objects.iter().filter_map(|object| match &object.config {
        ObjectConfig::Host(value) if value.enrolled => Some((object, value.tailscale.as_str())),
        _ => None,
    });
    validate_unique_named(enrolled, "tailscale", findings);
}

fn validate_unique_named<'a>(
    values: impl IntoIterator<Item = (&'a RegistryObject, &'a str)>,
    field: &str,
    findings: &mut Vec<RegistryFinding>,
) {
    let mut seen: BTreeMap<&str, &RegistryObject> = BTreeMap::new();
    for (object, value) in values {
        if let Some(previous) = seen.insert(value, object) {
            findings.push(relation_failure(
                object,
                format!(
                    "{field} {value:?} duplicates {}",
                    previous.relative_config.display()
                ),
            ));
        }
    }
}
