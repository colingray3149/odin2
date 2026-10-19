use std::collections::{BTreeMap, BTreeSet};

use crate::schema::{
    CapabilityToml, LaneToml, ObjectConfig, ProjectToml, RegistryKind, RegistryObject, SeatToml,
};
use crate::RegistryFinding;

use super::paths::relation_failure;

pub(super) struct Indices {
    by_kind: BTreeMap<RegistryKind, BTreeSet<String>>,
}

impl Indices {
    pub(super) fn new(objects: &[RegistryObject]) -> Self {
        let mut by_kind: BTreeMap<RegistryKind, BTreeSet<String>> = RegistryKind::ALL
            .into_iter()
            .map(|kind| (kind, BTreeSet::new()))
            .collect();
        for object in objects {
            by_kind
                .entry(object.kind())
                .or_default()
                .insert(object.id.clone());
        }
        Self { by_kind }
    }

    pub(super) fn contains(&self, kind: RegistryKind, id: &str) -> bool {
        self.by_kind
            .get(&kind)
            .is_some_and(|objects| objects.contains(id))
    }

    fn kind_is_empty(&self, kind: RegistryKind) -> bool {
        self.by_kind.get(&kind).is_none_or(BTreeSet::is_empty)
    }
}

pub(super) fn lane_index(objects: &[RegistryObject]) -> BTreeMap<&str, &LaneToml> {
    objects
        .iter()
        .filter_map(|object| match &object.config {
            ObjectConfig::Lane(value) => Some((object.id.as_str(), value.as_ref())),
            _ => None,
        })
        .collect()
}

pub(super) fn project_index(objects: &[RegistryObject]) -> BTreeMap<&str, &ProjectToml> {
    objects
        .iter()
        .filter_map(|object| match &object.config {
            ObjectConfig::Project(value) => Some((object.id.as_str(), value.as_ref())),
            _ => None,
        })
        .collect()
}

pub(super) fn capability_index(objects: &[RegistryObject]) -> BTreeMap<&str, &CapabilityToml> {
    objects
        .iter()
        .filter_map(|object| match &object.config {
            ObjectConfig::Capability(value) => Some((object.id.as_str(), value.as_ref())),
            _ => None,
        })
        .collect()
}

pub(super) fn seat_index(objects: &[RegistryObject]) -> BTreeMap<&str, &SeatToml> {
    objects
        .iter()
        .filter_map(|object| match &object.config {
            ObjectConfig::Seat(value) => Some((object.id.as_str(), value.as_ref())),
            _ => None,
        })
        .collect()
}

pub(super) fn seat_categories(objects: &[RegistryObject]) -> BTreeSet<&str> {
    objects
        .iter()
        .filter_map(|object| match &object.config {
            ObjectConfig::Seat(value) if value.enabled => Some(&value.categories),
            _ => None,
        })
        .flatten()
        .map(String::as_str)
        .collect()
}

pub(super) fn validate_ref(
    object: &RegistryObject,
    field: &str,
    id: &str,
    target_kind: RegistryKind,
    indices: &Indices,
    findings: &mut Vec<RegistryFinding>,
) {
    if indices.contains(target_kind, id) {
        return;
    }
    let message = format!("{field} references missing {target_kind} {id:?}");
    if !object.enabled() && indices.kind_is_empty(target_kind) {
        findings.push(RegistryFinding::flag(
            "registry-forward-reference",
            &object.relative_config,
            message,
        ));
    } else {
        findings.push(relation_failure(object, message));
    }
}

pub(super) fn validate_refs<'a>(
    object: &RegistryObject,
    field: &str,
    ids: impl IntoIterator<Item = &'a str>,
    target_kind: RegistryKind,
    indices: &Indices,
    findings: &mut Vec<RegistryFinding>,
) {
    for id in ids {
        validate_ref(object, field, id, target_kind, indices, findings);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::relational::fixtures::slice_object;
    use crate::FindingSeverity;

    #[test]
    fn enabled_unknown_and_disabled_stale_refs_fail() {
        let enabled = slice_object(true);
        let disabled = slice_object(false);
        let empty = Indices::new(&[]);
        let mut findings = Vec::new();
        validate_ref(
            &disabled,
            "capabilities",
            "future.tool",
            RegistryKind::Capability,
            &empty,
            &mut findings,
        );
        assert_eq!(findings[0].severity, FindingSeverity::Flag);
        findings.clear();
        validate_ref(
            &enabled,
            "capabilities",
            "future.tool",
            RegistryKind::Capability,
            &empty,
            &mut findings,
        );
        assert!(findings[0].is_failure());

        let mut by_kind: BTreeMap<RegistryKind, BTreeSet<String>> = RegistryKind::ALL
            .into_iter()
            .map(|kind| (kind, BTreeSet::new()))
            .collect();
        by_kind
            .get_mut(&RegistryKind::Capability)
            .expect("capability index")
            .insert("known.tool".to_owned());
        findings.clear();
        validate_ref(
            &disabled,
            "capabilities",
            "stale.tool",
            RegistryKind::Capability,
            &Indices { by_kind },
            &mut findings,
        );
        assert!(findings[0].is_failure());
    }
}
