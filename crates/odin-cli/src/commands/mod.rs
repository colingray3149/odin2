pub(crate) mod account;
pub(crate) mod approval;
pub(crate) mod atlas;
pub(crate) mod authority;
pub(crate) mod huginn;
pub(crate) mod output;
pub(crate) mod registry;
pub(crate) mod session;
pub(crate) mod worker;

use std::env;
use std::path::{Path, PathBuf};

use odin_registry::{parse_objects, walk};

#[cfg(test)]
mod tests;

pub(crate) fn load_registry_objects(
    registry_root: &Path,
) -> Result<Vec<odin_registry::RegistryObject>, String> {
    let discovery = walk(registry_root);
    let parsed = parse_objects(&discovery.objects);
    let mut failures = discovery
        .findings
        .iter()
        .chain(&parsed.findings)
        .filter(|finding| finding.is_failure())
        .collect::<Vec<_>>();
    failures.sort();
    if !failures.is_empty() {
        let details = failures
            .into_iter()
            .map(|finding| {
                format!(
                    "{} {}: {}",
                    finding.code,
                    finding.path.display(),
                    finding.message
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        return Err(format!("registry validation failed:\n{details}"));
    }
    Ok(parsed.objects)
}

pub(crate) fn resolve_odin_root() -> Result<PathBuf, String> {
    if let Some(root) = env::var_os("ODIN_ROOT").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(root));
    }
    env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .map(|home| home.join("valhalla/odin"))
        .ok_or_else(|| {
            "ODIN_ROOT is not set and HOME is unavailable for the default Odin root".to_owned()
        })
}
