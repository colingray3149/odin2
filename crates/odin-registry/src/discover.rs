use std::ffi::OsStr;
use std::fs::{self, DirEntry};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::schema::RegistryKind;
use crate::RegistryFinding;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawObject {
    pub kind: RegistryKind,
    pub id: String,
    pub relative_dir: PathBuf,
    pub relative_config: PathBuf,
    #[serde(skip)]
    pub absolute_config: PathBuf,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Discovery {
    pub objects: Vec<RawObject>,
    pub findings: Vec<RegistryFinding>,
}

pub fn walk(root: impl AsRef<Path>) -> Discovery {
    let root = root.as_ref();
    let mut discovery = Discovery::default();

    let root_entries = match sorted_entries(root) {
        Ok(entries) => entries,
        Err(error) => {
            discovery.findings.push(RegistryFinding::fail(
                "registry-root-read",
                registry_prefix(root),
                format!("could not read registry root: {error}"),
            ));
            return discovery;
        }
    };

    for entry in &root_entries {
        let name = entry.file_name();
        if ignored(&name) {
            continue;
        }
        let Some(name) = name.to_str() else {
            discovery.findings.push(RegistryFinding::flag(
                "registry-non-utf8-entry",
                relative(root, &entry.path()),
                "top-level registry entry is not valid UTF-8",
            ));
            continue;
        };
        if RegistryKind::from_directory(name).is_none() {
            discovery.findings.push(RegistryFinding::flag(
                "registry-unknown-kind",
                relative(root, &entry.path()),
                "unknown registry kind is not authoritative",
            ));
        }
    }

    for kind in RegistryKind::ALL {
        discover_kind(root, kind, &mut discovery);
    }
    discovery
        .objects
        .sort_by(|left, right| (left.kind, left.id.as_str()).cmp(&(right.kind, right.id.as_str())));
    discovery.findings.sort();
    discovery
}

fn discover_kind(root: &Path, kind: RegistryKind, discovery: &mut Discovery) {
    let kind_path = root.join(kind.directory());
    match fs::symlink_metadata(&kind_path) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            discovery.findings.push(RegistryFinding::fail(
                "registry-kind-type",
                registry_prefix(root).join(kind.directory()),
                "required registry kind must be a regular directory, not a symlink or special file",
            ));
            return;
        }
        Err(error) => {
            discovery.findings.push(RegistryFinding::fail(
                "registry-kind-missing",
                registry_prefix(root).join(kind.directory()),
                format!("required registry kind directory is unavailable: {error}"),
            ));
            return;
        }
    }
    let entries = match sorted_entries(&kind_path) {
        Ok(entries) => entries,
        Err(error) => {
            discovery.findings.push(RegistryFinding::fail(
                "registry-kind-read",
                registry_prefix(root).join(kind.directory()),
                format!("could not read registry kind: {error}"),
            ));
            return;
        }
    };
    for entry in entries {
        let file_name = entry.file_name();
        if ignored(&file_name) {
            continue;
        }
        let object_path = entry.path();
        let relative_dir = relative(root, &object_path);
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                discovery.findings.push(RegistryFinding::fail(
                    "registry-entry-type",
                    &relative_dir,
                    format!("could not inspect object entry: {error}"),
                ));
                continue;
            }
        };
        if !file_type.is_dir() {
            discovery.findings.push(RegistryFinding::flag(
                "registry-anomalous-entry",
                &relative_dir,
                "registry kind entries must be object folders",
            ));
            continue;
        }
        let Some(id) = file_name.to_str().map(str::to_owned) else {
            discovery.findings.push(RegistryFinding::fail(
                "registry-object-non-utf8",
                &relative_dir,
                "object folder name is not valid UTF-8",
            ));
            continue;
        };
        discover_object(root, kind, id, object_path, relative_dir, discovery);
    }
}

fn discover_object(
    root: &Path,
    kind: RegistryKind,
    id: String,
    object_path: PathBuf,
    relative_dir: PathBuf,
    discovery: &mut Discovery,
) {
    let entries = match sorted_entries(&object_path) {
        Ok(entries) => entries,
        Err(error) => {
            discovery.findings.push(RegistryFinding::fail(
                "registry-object-read",
                &relative_dir,
                format!("could not read object folder: {error}"),
            ));
            return;
        }
    };
    let mut configs = Vec::new();
    for entry in entries {
        let name = entry.file_name();
        if ignored(&name) {
            continue;
        }
        let entry_path = entry.path();
        let relative_entry = relative(root, &entry_path);
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                discovery.findings.push(RegistryFinding::fail(
                    "registry-object-entry-type",
                    &relative_entry,
                    format!("could not inspect object content: {error}"),
                ));
                continue;
            }
        };
        if file_type.is_dir() {
            discovery.findings.push(RegistryFinding::flag(
                "registry-anomalous-folder",
                &relative_entry,
                "nested object folder is not a registry object and confers no authority",
            ));
            continue;
        }
        if name.as_encoded_bytes().ends_with(b".toml") {
            if !file_type.is_file() {
                discovery.findings.push(RegistryFinding::fail(
                    "registry-config-file-type",
                    &relative_entry,
                    "registry config must be a regular file, not a symlink or special file",
                ));
            } else {
                configs.push((name, entry_path, relative_entry));
            }
        }
    }

    if configs.len() != 1 {
        discovery.findings.push(RegistryFinding::fail(
            "registry-config-count",
            &relative_dir,
            format!(
                "object folder must contain exactly one TOML config, found {}",
                configs.len()
            ),
        ));
        return;
    }
    let (name, absolute_config, relative_config) = configs.remove(0);
    let expected = kind.config_name();
    if name != OsStr::new(&expected) {
        discovery.findings.push(RegistryFinding::fail(
            "registry-config-name",
            &relative_config,
            format!("{kind} object config must be named {expected:?}"),
        ));
        return;
    }
    discovery.objects.push(RawObject {
        kind,
        id,
        relative_dir,
        relative_config,
        absolute_config,
    });
}

fn sorted_entries(path: &Path) -> std::io::Result<Vec<DirEntry>> {
    let mut entries = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(DirEntry::file_name);
    Ok(entries)
}

fn ignored(name: &OsStr) -> bool {
    name.as_encoded_bytes().starts_with(b".") || name == OsStr::new("_disabled")
}

fn relative(root: &Path, path: &Path) -> PathBuf {
    let prefix = registry_prefix(root);
    path.strip_prefix(root)
        .map(|relative| prefix.join(relative))
        .unwrap_or_else(|_| path.to_path_buf())
}

fn registry_prefix(root: &Path) -> PathBuf {
    root.file_name()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("registry"))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "odin-registry-discover-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("create discovery fixture");
            for kind in RegistryKind::ALL {
                fs::create_dir(root.join(kind.directory())).expect("create registry kind");
            }
            Self { root }
        }

        fn object(&self, kind: RegistryKind, id: &str, configs: &[&str]) {
            let directory = self.root.join(kind.directory()).join(id);
            fs::create_dir(&directory).expect("create object directory");
            for config in configs {
                fs::write(directory.join(config), b"").expect("write object config");
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).expect("remove discovery fixture");
        }
    }

    #[test]
    fn discovery_requires_exactly_one_toml_and_the_canonical_name() {
        let fixture = Fixture::new();
        fixture.object(RegistryKind::Seat, "valid", &["seat.toml"]);
        fixture.object(
            RegistryKind::Seat,
            "ambiguous",
            &["seat.toml", "notes.toml"],
        );
        fixture.object(RegistryKind::Seat, "stale-name", &["role.toml"]);

        let discovery = walk(&fixture.root);

        assert_eq!(
            discovery
                .objects
                .iter()
                .map(|object| object.id.as_str())
                .collect::<Vec<_>>(),
            ["valid"]
        );
        assert!(discovery.findings.iter().any(|finding| {
            finding.code == "registry-config-count"
                && finding.path.ends_with("seats/ambiguous")
                && finding.is_failure()
        }));
        assert!(discovery.findings.iter().any(|finding| {
            finding.code == "registry-config-name"
                && finding.path.ends_with("seats/stale-name/role.toml")
                && finding.is_failure()
        }));
    }

    #[test]
    fn discovery_skips_dot_and_disabled_trees_deterministically() {
        let fixture = Fixture::new();
        fixture.object(RegistryKind::Seat, "visible", &["seat.toml"]);
        fixture.object(RegistryKind::Seat, ".draft", &["seat.toml"]);
        fixture.object(RegistryKind::Seat, "_disabled", &["seat.toml"]);
        let visible = fixture.root.join("seats/visible");
        fs::write(visible.join(".stale.toml"), b"").expect("write ignored config");
        fs::create_dir(visible.join(".cache")).expect("create ignored nested directory");
        fs::create_dir(visible.join("_disabled")).expect("create disabled nested directory");

        let first = walk(&fixture.root);
        let second = walk(&fixture.root);

        assert_eq!(first, second);
        assert_eq!(first.objects.len(), 1);
        assert_eq!(first.objects[0].id, "visible");
        assert!(first.findings.is_empty());
    }
}
