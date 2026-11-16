//! Lease target registrations, linked to a published target template.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::lane_budget::RaiseLock;
use super::ComputeTargetToml;

#[derive(Clone, Deserialize, Serialize)]
struct Target {
    alias: String,
    project: String,
    config: ComputeTargetToml,
}

#[derive(Default, Deserialize, Serialize)]
struct Store {
    targets: BTreeMap<String, Target>,
}

/// Durable target registrations; a profile must authorize the published alias before use.
pub struct RentalTargets;

impl RentalTargets {
    /// Pin a leased endpoint to its published alias. Only connection identity changes; all
    /// execution limits, project scopes and data policy come from the published template.
    pub fn register(
        root: &Path,
        id: &str,
        alias: &str,
        project: &str,
        template: &ComputeTargetToml,
        identity: &super::RentalEnrollment,
    ) -> Result<(), String> {
        identity.validate()?;
        let ssh_host = format!("{}@{}", identity.ssh_user, identity.ssh_host);
        if !super::valid_id(id)
            || !super::valid_id(alias)
            || !super::valid_id(project)
            || !template.allowed_projects.contains(project)
            || id == alias
            || !template.enabled
            || ssh_host.is_empty()
            || !ssh_host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@'))
        {
            return Err("invalid rental target identity".into());
        }
        let mut key = identity.known_host.split_whitespace();
        if !key
            .next()
            .is_some_and(|kind| kind.starts_with("ssh-") || kind.starts_with("ecdsa-"))
            || key.next().is_none()
            || key.next().is_some()
        {
            return Err("invalid rental target host key".into());
        }
        let mut config = template.clone();
        config.ssh_host = ssh_host;
        config.ssh_port = std::num::NonZeroU16::new(identity.ssh_port);
        config.known_host = identity.known_host.clone();
        config.allowed_projects = std::collections::BTreeSet::from([project.to_owned()]);
        update(root, |store| {
            if let Some(existing) = store.targets.get(id) {
                if existing.alias == alias
                    && existing.project == project
                    && existing.config == config
                {
                    return Ok(());
                }
                return Err("rental target identity already registered".into());
            }
            store.targets.insert(
                id.to_owned(),
                Target {
                    alias: alias.to_owned(),
                    project: project.to_owned(),
                    config,
                },
            );
            Ok(())
        })
    }

    /// Remove only the exact target associated with this alias.
    pub fn remove(root: &Path, id: &str, alias: &str) -> Result<(), String> {
        update(root, |store| {
            if let Some(target) = store.targets.get(id) {
                if target.alias != alias {
                    return Err("rental target alias mismatch".into());
                }
                store.targets.remove(id);
            }
            Ok(())
        })
    }

    /// Resolve an exact target already recorded on a run.
    pub fn get(root: &Path, id: &str) -> Result<Option<ComputeTargetToml>, String> {
        let _lock = lock(root)?;
        Ok(read(root)?.targets.remove(id).map(|target| target.config))
    }

    /// Resolve only children of an alias explicitly listed by the profile.
    pub fn children(
        root: &Path,
        alias: &str,
    ) -> Result<Vec<(String, ComputeTargetToml, String)>, String> {
        let _lock = lock(root)?;
        Ok(read(root)?
            .targets
            .into_iter()
            .filter_map(|(id, target)| {
                (target.alias == alias).then_some((id, target.config, target.project))
            })
            .collect())
    }
}

fn lock(root: &Path) -> Result<RaiseLock, String> {
    RaiseLock::acquire_file(root, ".rental-targets.lock")
}

fn read(root: &Path) -> Result<Store, String> {
    let path = root.join("rental-targets.json");
    match crate::snapshot::read_regular_file(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| format!("{} is malformed: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Store::default()),
        Err(e) => Err(format!("{} is unreadable: {e}", path.display())),
    }
}

fn update(
    root: &Path,
    change: impl FnOnce(&mut Store) -> Result<(), String>,
) -> Result<(), String> {
    let _lock = lock(root)?;
    let mut store = read(root)?;
    change(&mut store)?;
    let bytes = serde_json::to_vec(&store).map_err(|e| e.to_string())?;
    let path = root.join("rental-targets.json");
    crate::snapshot::atomic_write(&path, &bytes)
        .map_err(|e| format!("{} {}: {}", e.action, e.path.display(), e.source))
}
