use std::ffi::OsStr;
use std::fs::{self, DirEntry};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::relational::{display_path, ignored};
use crate::schema::{RegistryKind, MODELS_AVAILABLE, REGISTRY_DIR};
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
        // The committed model catalog AVAILABLE is data beside the cards,
        // never a registry object.
        if name == MODELS_AVAILABLE {
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
                "registry kind must be a regular directory, not a symlink or special file",
            ));
            return;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && kind.is_optional() => {
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

fn relative(root: &Path, path: &Path) -> PathBuf {
    display_path(root, path, REGISTRY_DIR)
}

fn registry_prefix(root: &Path) -> PathBuf {
    root.file_name()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(REGISTRY_DIR))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _directory: tempfile::TempDir,
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("create discovery fixture");
            let root = directory.path().to_path_buf();
            for kind in RegistryKind::ALL {
                fs::create_dir(root.join(kind.directory())).expect("create registry kind");
            }
            Self {
                _directory: directory,
                root,
            }
        }

        fn object(&self, kind: RegistryKind, id: &str, configs: &[&str]) {
            let directory = self.root.join(kind.directory()).join(id);
            fs::create_dir(&directory).expect("create object directory");
            for config in configs {
                fs::write(directory.join(config), b"").expect("write object config");
            }
        }
    }

    #[test]
    fn compute_kinds_are_optional_but_validated_when_present() {
        let fixture = Fixture::new();
        for kind in [RegistryKind::ComputeProvider, RegistryKind::ComputeTarget] {
            fs::remove_dir(fixture.root.join(kind.directory())).expect("remove optional kind");
        }
        fs::remove_dir(fixture.root.join(RegistryKind::Seat.directory()))
            .expect("remove required kind");

        let discovery = walk(&fixture.root);
        assert_eq!(discovery.findings.len(), 1);
        assert_eq!(discovery.findings[0].code, "registry-kind-missing");
        assert!(discovery.findings[0].path.ends_with("seats"));
        assert!(discovery.findings[0].is_failure());

        fs::create_dir(fixture.root.join(RegistryKind::Seat.directory()))
            .expect("restore required kind");
        fs::write(
            fixture.root.join(RegistryKind::ComputeProvider.directory()),
            b"",
        )
        .expect("create invalid kind entry");
        fs::create_dir(fixture.root.join(RegistryKind::ComputeTarget.directory()))
            .expect("create optional kind");
        fixture.object(RegistryKind::ComputeTarget, "invalid", &["wrong.toml"]);

        let discovery = walk(&fixture.root);
        assert!(discovery.findings.iter().any(|finding| {
            finding.code == "registry-kind-type"
                && finding.path.ends_with("compute-providers")
                && finding.is_failure()
        }));
        assert!(discovery.findings.iter().any(|finding| {
            finding.code == "registry-config-name"
                && finding.path.ends_with("compute-targets/invalid/wrong.toml")
                && finding.is_failure()
        }));
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
}
