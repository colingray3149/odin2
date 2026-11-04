//! Expand explicit toolset grants once before relation checks, never by capability prefix.
use super::{CapabilityToml, ObjectConfig, RegistryObject};
use crate::RegistryFinding;
use odin_domain::CapabilityId;
use std::collections::BTreeSet;

pub fn expand_toolset_grants(objects: &mut [RegistryObject]) -> Vec<RegistryFinding> {
    let mut capabilities = Vec::new();
    let mut declarations = Vec::new();
    for object in objects {
        match &mut object.config {
            ObjectConfig::Capability(capability) => {
                capabilities.push((object.id.as_str(), &**capability));
            }
            ObjectConfig::Seat(seat) => declarations.push((
                Some(object.id.as_str()),
                &object.relative_config,
                &mut seat.tool_refs,
            )),
            ObjectConfig::Slice(slice) => {
                declarations.push((None, &object.relative_config, &mut slice.capabilities));
            }
            _ => {}
        }
    }
    let mut findings = Vec::new();
    for (seat, path, grants) in declarations {
        for group in expand_toolset_refs(grants, seat, capabilities.iter().copied()) {
            findings.push(RegistryFinding::fail(
                "toolset-grant",
                path,
                format!("unknown or empty toolset {group:?}"),
            ));
        }
    }
    findings
}

/// Expand one declaration's grants using the same enabled and seat-specific membership as registry loading.
/// Unknown or empty groups remain unresolved and are returned to the caller.
pub fn expand_toolset_refs<'a>(
    grants: &mut BTreeSet<CapabilityId>,
    seat: Option<&str>,
    capabilities: impl Iterator<Item = (&'a str, &'a CapabilityToml)> + Clone,
) -> Vec<String> {
    let macros: Vec<_> = grants
        .iter()
        .filter(|id| id.as_str().starts_with("toolset:"))
        .cloned()
        .collect();
    let mut missing = Vec::new();
    for entry in macros {
        let group = entry.as_str().strip_prefix("toolset:").unwrap();
        let mut members = capabilities.clone().filter_map(|(id, capability)| {
            if !capability.enabled {
                return None;
            }
            let view = seat.and_then(|seat| {
                capability
                    .seat_ops
                    .iter()
                    .find(|(id, _)| id.as_str() == seat)
                    .map(|(_, view)| view)
            });
            let declared_group = view
                .map(|view| view.toolset.as_str())
                .or(capability.toolset.as_deref());
            (declared_group == Some(group)).then_some(id)
        });
        let Some(first) = members.next() else {
            missing.push(group.to_owned());
            continue;
        };
        grants.remove(&entry);
        grants.insert(CapabilityId::new(first).expect("parsed capability identity"));
        grants.extend(members.map(|id| CapabilityId::new(id).expect("parsed capability identity")));
    }
    missing
}

#[cfg(test)]
mod tests {
    use super::*;
    fn objects() -> Vec<RegistryObject> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let parsed = crate::parse_objects(&crate::walk(root.join("registry")).objects);
        assert!(
            !parsed.findings.iter().any(RegistryFinding::is_failure),
            "{:?}",
            parsed.findings
        );
        parsed.objects
    }
}
