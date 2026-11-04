//! A Services row: live probes for a service no capability names. A capability declares its own `tests` and
//! `probes`; the probe grammar here serves both.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::RegistryKind;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureToml {
    pub schema: String,
    pub kind: RegistryKind,
    pub enabled: bool,
    pub title: String,
    pub description: String,
    /// Probe strings, each parsed by `Probe::parse`.
    pub probes: Vec<String>,
}

/// Which systemd manager owns a unit named by a `unit:` probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnitManager {
    System,
    User,
}

/// One live probe. Each form names what it reads; none guesses a hardware or account id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Probe {
    /// `http:<url>`: the URL, written as `http:https://…` or `http:http://…`.
    Http { url: String },
    /// `unit:<host> <system|user> <unit> [<age>]`: an active unit, fresher than the age if given.
    Unit {
        host: String,
        manager: UnitManager,
        unit: String,
        max_age: Option<Duration>,
    },
    /// `file:<host> <path> [<age>]`: a file on the host, newer than the age if given.
    File {
        host: String,
        path: String,
        max_age: Option<Duration>,
    },
    /// `models:<lane>`: the bare lane names the `gateway/<lane>` model card.
    Models { lane: String },
}

impl Probe {
    /// Parse one probe string. Every error names the probe it refused.
    pub fn parse(text: &str) -> Result<Self, String> {
        let (kind, rest) = text.split_once(':').ok_or_else(|| {
            format!("probe {text:?} has no form prefix; use http:, unit:, file: or models:")
        })?;
        let words: Vec<&str> = rest.split_whitespace().collect();
        match kind {
            "models" => single(text, kind, &words).map(|lane| Self::Models { lane }),
            "http" => {
                if !(rest.starts_with("https://") || rest.starts_with("http://"))
                    || words.len() != 1
                {
                    return Err(format!(
                        "probe {text:?} must be http:<url> starting with http:// or https://"
                    ));
                }
                Ok(Self::Http {
                    url: rest.to_owned(),
                })
            }
            "unit" => {
                let (host, manager, unit, age) = match words.as_slice() {
                    [host, manager, unit] => (*host, *manager, *unit, None),
                    [host, manager, unit, age] => (*host, *manager, *unit, Some(*age)),
                    _ => {
                        return Err(format!(
                            "probe {text:?} must be unit:<host> <system|user> <unit> [<age>]"
                        ))
                    }
                };
                let manager = match manager {
                    "system" => UnitManager::System,
                    "user" => UnitManager::User,
                    other => {
                        return Err(format!(
                            "probe {text:?} names manager {other:?}; use system or user"
                        ))
                    }
                };
                Ok(Self::Unit {
                    host: host.to_owned(),
                    manager,
                    unit: unit.to_owned(),
                    max_age: age.map(|age| parse_age(text, age)).transpose()?,
                })
            }
            "file" => {
                let (host, path, age) = match words.as_slice() {
                    [host, path] => (*host, *path, None),
                    [host, path, age] => (*host, *path, Some(*age)),
                    _ => return Err(format!("probe {text:?} must be file:<host> <path> [<age>]")),
                };
                if !(path.starts_with('/') || path.starts_with("~/")) {
                    return Err(format!(
                        "probe {text:?} names path {path:?}; it must be absolute or start with ~/"
                    ));
                }
                Ok(Self::File {
                    host: host.to_owned(),
                    path: path.to_owned(),
                    max_age: age.map(|age| parse_age(text, age)).transpose()?,
                })
            }
            other => Err(format!(
                "probe {text:?} has unknown form {other:?}; use http:, unit:, file: or models:"
            )),
        }
    }
}

fn single(text: &str, form: &str, words: &[&str]) -> Result<String, String> {
    match words {
        [one] => Ok((*one).to_owned()),
        _ => Err(format!("probe {text:?} must be {form}:<one word>")),
    }
}

/// Ages are a positive count of minutes, hours or days: `30m`, `6h`, `2d`.
fn parse_age(text: &str, age: &str) -> Result<Duration, String> {
    let bad = || format!("probe {text:?} names age {age:?}; use <n>m, <n>h or <n>d with n >= 1");
    let unit = age.chars().last().ok_or_else(bad)?;
    let count: u64 = age[..age.len() - unit.len_utf8()]
        .parse()
        .ok()
        .filter(|count| *count >= 1)
        .ok_or_else(bad)?;
    let seconds = match unit {
        'm' => count * 60,
        'h' => count * 3_600,
        'd' => count * 86_400,
        _ => return Err(bad()),
    };
    Ok(Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{parse_object_toml, RegistryObject};
    use crate::snapshot::{CompositionDigest, Snapshot};

    const SEAT: &str = include_str!("../../../../registry/seats/kubert/seat.toml");

    const SERVICE: &str = r#"
schema = "odin.registry.v1"
kind = "feature"
enabled = true
title = "A service"
description = "Every probe form in one service."
probes = [
  "http:https://mini.example/healthz",
  "unit:mini system odind.service 6h",
  "unit:pc user sinmara-desk",
  "file:mini ~/.local/state/odin/tested.json 1d",
  "models:zai-glm",
]
"#;

    fn feature(id: &str, source: &str) -> RegistryObject {
        parse_object_toml(
            RegistryKind::Feature,
            id,
            format!("registry/features/{id}/feature.toml"),
            source,
        )
        .expect("feature parses")
    }

    #[test]
    fn a_probe_that_is_not_a_live_form_is_refused_by_name() {
        for refused in [
            "sparkle:pc",
            "decl:capability/routine.set",
            "test:odin-registry a",
            "gate:clippy",
            "http://mini.example",
            "unit:mini kernel odind.service",
            "file:pc relative/path",
            "file:pc /tmp/x 0d",
        ] {
            let error = Probe::parse(refused).unwrap_err();
            assert!(error.contains(refused), "{error}");
        }
    }

    fn digest(revision: u64, objects: Vec<RegistryObject>) -> CompositionDigest {
        Snapshot::build(revision, objects)
            .expect("snapshot")
            .composition_digest()
            .expect("digest")
    }

    /// Service rows are read live, so publishing or editing one keeps the composition.
    #[test]
    fn publishing_a_service_leaves_the_composition_digest_unchanged() {
        let seat = parse_object_toml(
            RegistryKind::Seat,
            "kubert",
            "registry/seats/kubert/seat.toml",
            SEAT,
        )
        .expect("seat parses");
        let base = digest(7, vec![seat.clone()]);
        assert_eq!(
            base,
            digest(8, vec![seat.clone(), feature("every-form", SERVICE)])
        );
        let edited = SERVICE.replace("A service", "Edited");
        assert_eq!(
            base,
            digest(9, vec![seat.clone(), feature("every-form", &edited)])
        );
        assert_eq!(base, digest(10, vec![seat]));
    }
}
