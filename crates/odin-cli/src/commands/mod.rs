//! The `odin` subcommands: one module per subcommand, wired into the
//! parser in `main.rs`.

pub(crate) mod approval;
pub(crate) mod atlas;
pub(crate) mod authority;
pub(crate) mod compute_sample;
pub(crate) mod context;
pub(crate) mod host_file;
pub(crate) mod huginn;
pub(crate) mod models;
pub(crate) mod output;
pub(crate) mod registry;
pub(crate) mod session;
pub(crate) mod view;
pub(crate) mod worker;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use odin_registry::{parse_objects, walk};

#[cfg(test)]
mod tests;

/// The gateway renderer executable the publish and model commands default to.
pub(crate) const DEFAULT_RENDERER: &str = "odin-gateway-render";

/// Runs `git -C <directory> <args>` and returns stdout; a failure names the git
/// verb, the directory and git's own stderr.
pub(crate) fn run_git(directory: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(args)
        .output()
        .map_err(|error| format!("could not run git: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed in {}: {}",
            args.join(" "),
            directory.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output.stdout)
}

/// Creates the directory a file is about to be written into; a bare file name needs none.
pub(crate) fn ensure_parent_dir(path: &Path) -> Result<(), String> {
    match path.parent() {
        Some(parent) => fs::create_dir_all(parent)
            .map_err(|error| format!("could not create {}: {error}", parent.display())),
        None => Ok(()),
    }
}

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
