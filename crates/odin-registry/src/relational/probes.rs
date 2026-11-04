//! Probe relations: a `unit:` or `file:` probe names a declared host and a `models:` probe a declared model card.

use std::collections::BTreeSet;

use odin_domain::huginn::GATEWAY_PROVIDER;

use crate::schema::{ObjectConfig, Probe, RegistryKind, RegistryObject};
use crate::RegistryFinding;

use super::paths::relation_failure;
use super::refs::Indices;

pub(super) fn validate_probe_relations(
    objects: &[RegistryObject],
    indices: &Indices,
    findings: &mut Vec<RegistryFinding>,
) {
    let cards: BTreeSet<&str> = objects
        .iter()
        .filter_map(|object| match &object.config {
            ObjectConfig::Model(card) => Some(card.id.as_str()),
            _ => None,
        })
        .collect();

    for object in objects {
        let (owner, probes) = match &object.config {
            ObjectConfig::Feature(value) => ("feature", &value.probes),
            ObjectConfig::Capability(value) => ("capability", &value.probes),
            _ => continue,
        };
        let id = &object.id;
        for text in probes {
            // Form and grammar errors are reported by validate_object; only resolvable targets here.
            let Ok(parsed) = Probe::parse(text) else {
                continue;
            };
            let problem = match &parsed {
                Probe::Unit { host, .. } | Probe::File { host, .. }
                    if !indices.contains(RegistryKind::Host, host) =>
                {
                    Some(format!(
                        "{owner} {id:?}: probe {text:?} names host {host:?}, which is not a declared host"
                    ))
                }
                Probe::Models { lane } if !cards.contains(format!("{GATEWAY_PROVIDER}/{lane}").as_str()) => {
                    Some(format!(
                        "{owner} {id:?}: probe {text:?} names no model card {GATEWAY_PROVIDER}/{lane}"
                    ))
                }
                _ => None,
            };
            if let Some(problem) = problem {
                findings.push(relation_failure(object, problem));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::parse_object_toml;

    fn feature(id: &str, probes: &[&str]) -> RegistryObject {
        let probes: Vec<String> = probes.iter().map(|probe| format!("{probe:?}")).collect();
        let source = format!(
            "schema = \"odin.registry.v1\"\nkind = \"feature\"\nenabled = true\ntitle = \"{id}\"\n\
             description = \"fixture\"\nprobes = [{}]\n",
            probes.join(", ")
        );
        parse_object_toml(
            RegistryKind::Feature,
            id,
            format!("registry/features/{id}/feature.toml"),
            &source,
        )
        .expect("feature fixture parses")
    }

    fn mini_host() -> RegistryObject {
        parse_object_toml(
            RegistryKind::Host,
            "mini",
            "registry/hosts/mini/host.toml",
            include_str!("../../../../registry/hosts/mini/host.toml"),
        )
        .expect("mini host parses")
    }

    fn findings_for(objects: &[RegistryObject]) -> Vec<String> {
        let mut findings = Vec::new();
        validate_probe_relations(objects, &Indices::new(objects), &mut findings);
        findings
            .into_iter()
            .map(|finding| finding.message)
            .collect()
    }

    #[test]
    fn probe_hosts_and_models_must_be_declared() {
        let objects = [
            mini_host(),
            feature(
                "alpha",
                &[
                    "unit:mini system odind.service",
                    "unit:nowhere user x",
                    "models:zai-glm",
                ],
            ),
        ];
        let messages = findings_for(&objects);
        assert!(
            messages.iter().any(|m| m.contains("nowhere")),
            "{messages:?}"
        );
        assert!(
            messages.iter().any(|m| m.contains("gateway/zai-glm")),
            "{messages:?}"
        );
        assert!(
            !messages.iter().any(|m| m.contains("\"mini\"")),
            "{messages:?}"
        );
    }
}
