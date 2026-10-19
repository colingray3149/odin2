//! Standard developer tooling, without report grading or recursive sweep calls.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub struct Scratch {
    directory: tempfile::TempDir,
}

impl Scratch {
    pub fn new() -> Result<Self, String> {
        let uid = fs::metadata("/proc/self")
            .map_err(|error| error.to_string())?
            .uid();
        let base = PathBuf::from(format!("/run/user/{uid}"));
        remove_abandoned_scratch(&base);
        let directory = tempfile::Builder::new()
            .prefix(&format!("sw-{}-", std::process::id()))
            .tempdir_in(&base)
            .map_err(|error| {
                format!(
                    "cannot create private sweep runtime under {}: {error}",
                    base.display()
                )
            })?;
        Ok(Self { directory })
    }

    pub fn path(&self) -> &Path {
        self.directory.path()
    }
}

/// SIGKILL skips TempDir cleanup; only PID-tagged directories with no live process are safe to remove.
fn remove_abandoned_scratch(base: &Path) {
    let Ok(entries) = fs::read_dir(base) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(rest) = name.to_str().and_then(|name| name.strip_prefix("sw-")) else {
            continue;
        };
        let owner = rest.split_once('-').map(|(pid, _)| pid.parse::<u32>());
        if let Some(Ok(pid)) = owner {
            if Path::new(&format!("/proc/{pid}")).exists() {
                continue;
            }
            match fs::remove_dir_all(entry.path()) {
                Ok(()) => tracing::info!(
                    path = %entry.path().display(),
                    "removed abandoned scratch"
                ),
                Err(error) => tracing::warn!(
                    path = %entry.path().display(),
                    %error,
                    "abandoned scratch not removed"
                ),
            }
        }
    }
}

/// Give child tooling disposable user state while retaining the caller's Cargo cache.
pub fn configure_command(command: &mut Command, scratch: &Path) -> Result<(), String> {
    fs::create_dir_all(scratch).map_err(|error| error.to_string())?;
    fs::set_permissions(scratch, fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())?;
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")));
    let bus = match std::env::var_os("DBUS_SESSION_BUS_ADDRESS")
        .or_else(|| std::env::var_os("ODIN_WORKER_BUS"))
    {
        Some(bus) => bus,
        None => OsString::from(format!("unix:path=/run/user/{}/bus", host_uid()?)),
    };
    for (key, directory) in [
        ("HOME", "home"),
        ("XDG_CONFIG_HOME", "config"),
        ("XDG_STATE_HOME", "state"),
        ("XDG_CACHE_HOME", "cache"),
        ("TMPDIR", "tmp"),
    ] {
        let path = scratch.join(directory);
        fs::create_dir_all(&path).map_err(|error| error.to_string())?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
        command.env(key, path);
    }
    command.env("XDG_RUNTIME_DIR", scratch);
    // Tooling needs the host session bus; effect workers strip this variable separately.
    command.env("DBUS_SESSION_BUS_ADDRESS", bus);
    if let Some(cargo_home) = cargo_home {
        command.env("CARGO_HOME", cargo_home);
    }
    for key in ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"] {
        command.env_remove(key);
    }
    command.stdin(Stdio::null());
    Ok(())
}

fn host_uid() -> Result<u32, String> {
    fs::metadata("/proc/self")
        .map_err(|error| error.to_string())
        .map(|meta| meta.uid())
}

/// Only unit-state reads use the host runtime directory; test children must not discover live state.
pub fn host_runtime_dir() -> Result<PathBuf, String> {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        return Ok(PathBuf::from(dir));
    }
    Ok(PathBuf::from(format!("/run/user/{}", host_uid()?)))
}

/// Store sources require `path:.`; checkouts retain Git filtering to avoid copying build output.
fn flake_ref(root: &Path) -> OsString {
    if root.starts_with("/nix/store") {
        OsString::from("path:.")
    } else {
        root.as_os_str().to_owned()
    }
}

/// Cache each store source separately: identical mtimes can make Cargo reuse stale binaries.
fn cargo_target(
    root: &Path,
    scratch: &Path,
    configured: Option<PathBuf>,
    cache: Option<PathBuf>,
) -> PathBuf {
    match configured {
        Some(path) if path.is_absolute() => path,
        Some(path) => root.join(path),
        None if root.starts_with("/nix/store") => match (cache, root.file_name()) {
            (Some(cache), Some(source)) => cache.join("odin-sweep").join(source).join("target"),
            _ => scratch.join("target"),
        },
        None => root.join("target"),
    }
}

/// Serialized runs allow deleting other sources' build caches to limit disk use.
fn prune_other_sources(sweep_cache: &Path, keep: &OsStr) {
    let Ok(entries) = fs::read_dir(sweep_cache) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_name() == keep {
            continue;
        }
        let path = entry.path();
        match fs::remove_dir_all(&path) {
            Ok(()) => tracing::info!(path = %path.display(), "pruned stale source target"),
            Err(error) => tracing::warn!(
                path = %path.display(),
                %error,
                "stale source target not pruned"
            ),
        }
    }
}

/// Resolve the persistent cache before configuring disposable child state.
fn caller_cache() -> Option<PathBuf> {
    std::env::var_os("XDG_CACHE_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .filter(|path| path.is_absolute())
}

pub fn cargo_command(root: &Path, scratch: &Path, arguments: &[&str]) -> Command {
    let in_devshell = std::env::var_os("IN_NIX_SHELL").is_some();
    let mut command = if root.join("flake.nix").is_file() && !in_devshell {
        let mut command = Command::new("nix");
        command
            .arg("develop")
            .arg(flake_ref(root))
            .args(["--command", "cargo"]);
        command
    } else {
        Command::new(std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo")))
    };
    let target = cargo_target(
        root,
        scratch,
        std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from),
        caller_cache(),
    );
    if let (Some(source), Some(sweep_cache)) = (
        target.parent().and_then(Path::file_name),
        target.parent().and_then(Path::parent),
    ) {
        if root.starts_with("/nix/store")
            && sweep_cache.file_name() == Some(OsStr::new("odin-sweep"))
        {
            prune_other_sources(sweep_cache, source);
        }
    }
    command.env("CARGO_TARGET_DIR", target);
    let split = arguments
        .iter()
        .position(|argument| *argument == "--")
        .unwrap_or(arguments.len());
    command.current_dir(root).args(&arguments[..split]);
    if !arguments[..split].contains(&"--locked") {
        command.arg("--locked");
    }
    command.args(&arguments[split..]);
    command
}

pub fn find_program(name: &str) -> Option<PathBuf> {
    let supplied = Path::new(name);
    if supplied.is_absolute() {
        return executable(supplied).then(|| supplied.to_path_buf());
    }
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .map(|directory| directory.join(name))
        .find(|path| executable(path))
}

fn executable(path: &Path) -> bool {
    fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

/// k3s writes this group-readable config when no explicit KUBECONFIG is supplied.
pub const K3S_KUBECONFIG_PATH: &str = "/etc/rancher/k3s/k3s.yaml";

/// Return None for an inherited KUBECONFIG so colon-separated path lists remain intact.
pub fn kube_config_path() -> Option<PathBuf> {
    match std::env::var_os("KUBECONFIG") {
        Some(value) if !value.is_empty() => None,
        _ => Some(PathBuf::from(K3S_KUBECONFIG_PATH)),
    }
}

pub fn configure_worker_tests(
    command: &mut Command,
    root: &Path,
    runtime: Option<&Path>,
) -> Result<(), String> {
    let (bootstrap, unshare, bus, adapter) = if let Some(path) = runtime {
        let manifest =
            odin_huginn::RuntimeManifest::load(path).map_err(|error| error.to_string())?;
        let config = manifest.load_config().map_err(|error| error.to_string())?;
        (
            manifest
                .executable("worker_bootstrap")
                .map_err(|error| error.to_string())?
                .path
                .clone(),
            manifest
                .executable("unshare")
                .map_err(|error| error.to_string())?
                .path
                .clone(),
            config.worker_bus,
            manifest
                .executable("odin-adapter-web")
                .map_err(|error| error.to_string())?
                .path
                .clone(),
        )
    } else {
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .map(|path| {
                if path.is_absolute() {
                    path
                } else {
                    root.join(path)
                }
            })
            .unwrap_or_else(|| root.join("target"));
        let uid = fs::metadata("/proc/self")
            .map_err(|error| error.to_string())?
            .uid();
        (
            target.join("debug/odin-worker-bootstrap"),
            find_program("unshare")
                .ok_or_else(|| "unshare is required for worker integration tests".to_owned())?,
            format!("unix:path=/run/user/{uid}/bus"),
            target.join("debug/odin-adapter-web"),
        )
    };
    for (key, value) in [
        ("ODIN_WORKER_BOOTSTRAP_BIN", bootstrap.as_os_str()),
        ("ODIN_TEST_WORKER_BOOTSTRAP", bootstrap.as_os_str()),
        ("ODIN_WORKER_UNSHARE_BIN", unshare.as_os_str()),
        ("ODIN_TEST_WORKER_UNSHARE", unshare.as_os_str()),
        ("ODIN_WORKER_BUS", OsStr::new(&bus)),
        ("ODIN_TEST_WORKER_BUS", OsStr::new(&bus)),
        ("ODIN_TEST_ADAPTER_WEB_EXECUTABLE", adapter.as_os_str()),
    ] {
        if std::env::var_os(key).is_none() {
            command.env(key, value);
        }
    }
    Ok(())
}

pub fn run_development_checks(
    root: &Path,
    scratch: &Path,
    runtime: Option<&Path>,
) -> Result<i32, String> {
    // Dependency policy gates the mode before the heavier build/test steps.
    // cargo-deny comes from the flake devShell/runtime PATH; when it is
    // absent the environment is blocked, never green.
    if find_program("cargo-deny").is_none() {
        println!("== cargo deny check ==");
        println!(
            "BLOCKED: cargo-deny is not on PATH; run sweep from the flake \
             devShell or the installed profile that supplies it."
        );
        return Ok(1);
    }
    let steps: [(&str, &[&str]); 5] = [
        (
            "cargo check",
            &["check", "--workspace", "--all-targets", "--locked"],
        ),
        (
            "cargo clippy",
            &[
                "clippy",
                "--workspace",
                "--all-targets",
                "--locked",
                "--",
                "-D",
                "warnings",
            ],
        ),
        ("cargo deny check", &["deny", "--locked", "check"]),
        (
            "build test executables",
            &["build", "--workspace", "--bins", "--locked"],
        ),
        (
            "cargo unit tests",
            &["test", "--workspace", "--locked", "-j", "3"],
        ),
    ];
    for (name, arguments) in steps {
        println!("== {name} ==");
        let mut command = cargo_command(root, scratch, arguments);
        configure_command(&mut command, scratch)?;
        if name == "cargo unit tests" {
            configure_worker_tests(&mut command, root, runtime)?;
        }
        let status = command
            .status()
            .map_err(|error| format!("{name} could not start: {error}"))?;
        if !status.success() {
            return Ok(status.code().unwrap_or(1));
        }
    }
    Ok(0)
}

#[cfg(test)]
mod cargo_root_tests {
    use super::*;

    #[test]
    fn abandoned_scratch_is_removed_and_live_scratch_kept() {
        let base = tempfile::tempdir().unwrap();
        let dead = base.path().join(format!("sw-{}-dead", u32::MAX));
        let live = base.path().join(format!("sw-{}-live", std::process::id()));
        let legacy = base.path().join("sw-a1B2c3");
        let other = base.path().join("other");
        for directory in [&dead, &live, &legacy, &other] {
            fs::create_dir(directory).unwrap();
        }
        // An untagged scratch directory may still belong to a live process, regardless of age.
        fs::File::open(&legacy)
            .and_then(|root| {
                root.set_modified(
                    std::time::SystemTime::now() - std::time::Duration::from_secs(7200),
                )
            })
            .unwrap();
        remove_abandoned_scratch(base.path());
        assert!(!dead.exists());
        assert!(live.exists() && legacy.exists() && other.exists());
    }

    /// Store sources use path:. and the available persistent build cache;
    /// checkouts keep Git filtering and their target directory.
    #[test]
    fn a_store_root_is_a_path_flake_that_builds_in_the_persistent_cache() {
        let store = Path::new("/nix/store/zg6vpgyxx4cry45vaysvszmr7k6hl0c2-source");
        let checkout = Path::new("/home/colin/valhalla/odin");
        let scratch = Path::new("/tmp/sweep-scratch");
        assert_eq!(flake_ref(store), OsString::from("path:."));
        assert_eq!(
            flake_ref(checkout),
            OsString::from("/home/colin/valhalla/odin")
        );
        let cache = Some(PathBuf::from("/home/colin/.cache"));
        assert_eq!(
            cargo_target(store, scratch, None, cache.clone()),
            PathBuf::from(
                "/home/colin/.cache/odin-sweep/zg6vpgyxx4cry45vaysvszmr7k6hl0c2-source/target"
            )
        );
        assert_eq!(
            cargo_target(store, scratch, None, None),
            scratch.join("target")
        );
        assert_eq!(
            cargo_target(checkout, scratch, None, cache.clone()),
            checkout.join("target")
        );
        assert_eq!(
            cargo_target(store, scratch, Some(PathBuf::from("/cache/target")), cache),
            PathBuf::from("/cache/target")
        );
    }

    /// Separate targets prevent equal store mtimes from reusing stale binaries;
    /// only the current source cache is retained.
    #[test]
    fn each_pinned_source_builds_in_its_own_target_and_only_the_current_is_kept() {
        let scratch = Path::new("/tmp/sweep-scratch");
        let cache = tempfile::tempdir().expect("cache dir");
        let old = Path::new("/nix/store/5wlcm7qqir0pjk1a9dk76zb9cyqh353f-source");
        let new = Path::new("/nix/store/zg6vpgyxx4cry45vaysvszmr7k6hl0c2-source");
        let old_target = cargo_target(old, scratch, None, Some(cache.path().to_path_buf()));
        let new_target = cargo_target(new, scratch, None, Some(cache.path().to_path_buf()));
        assert_ne!(old_target, new_target, "each source owns its target");

        let sweep_cache = cache.path().join("odin-sweep");
        fs::create_dir_all(&old_target).expect("old target");
        fs::create_dir_all(sweep_cache.join("target")).expect("legacy shared target");
        fs::create_dir_all(&new_target).expect("new target");
        prune_other_sources(
            &sweep_cache,
            OsStr::new("zg6vpgyxx4cry45vaysvszmr7k6hl0c2-source"),
        );
        assert!(new_target.is_dir(), "the current source's build stays");
        assert!(!old_target.exists(), "an older source's build is removed");
        assert!(
            !sweep_cache.join("target").exists(),
            "the shared target is removed"
        );
    }
}
