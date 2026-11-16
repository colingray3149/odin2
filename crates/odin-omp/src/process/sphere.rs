//! Project a declared project sphere into a lane's bwrap.
//!
//! The bubble binds the lane capsule writable at its own path, each declared
//! data root read-only at its own path, and the one scratch root writable.
//! The process retains bubblewrap's private `/dev` for its runtime; the shell
//! sees only explicitly selected device nodes. A project without a sphere keeps the seat sandbox.

use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use odin_registry::schema::ProjectSphereToml;

use super::sandbox::{
    binds_host_root, path_arg, push_bind, SandboxSubject, SeatSandboxProfile, ENV_PATH,
};

/// One lane's resolved sphere. Paths are the declaration, already absolute.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SphereProjection {
    /// Read-only data roots, bound at their own paths.
    pub data_roots: Vec<PathBuf>,
    /// The one writable root besides the capsule.
    pub scratch: PathBuf,
    /// Declared serial nodes, bound at their own `/dev/serial/by-id` paths.
    pub devices: Vec<PathBuf>,
    /// Declared `unix://` socket files. When the socket exists it is bound
    /// read-only at [`DEVICE_SOCKET`], not at its host path: binding the
    /// host path would mount the parent directory. HTTP(S) endpoints are
    /// not filesystem binds.
    pub endpoints: Vec<PathBuf>,
}

/// Where a declared unix socket appears inside the bubble. One project
/// declares one such socket; the parent directory of the host socket is
/// not mounted.
pub const DEVICE_SOCKET: &str = "/run/odin/device.sock";

/// The sphere a lane of `project` projects, when that project declares one.
pub fn project_sphere<'a>(
    objects: impl IntoIterator<Item = &'a odin_registry::RegistryObject>,
    project: &odin_domain::ProjectId,
) -> Option<&'a ProjectSphereToml> {
    objects.into_iter().find_map(|object| {
        let odin_registry::ObjectConfig::Project(declared) = &object.config else {
            return None;
        };
        (object.id == project.as_str() && declared.enabled)
            .then_some(declared.sphere.as_ref())
            .flatten()
    })
}

impl SphereProjection {
    /// The declared roots and serial nodes. A device path outside
    /// `/dev/serial/by-id`, or a root that nests another, is refused: the
    /// bubble must not gain a path the declaration did not name.
    pub fn from_sphere(sphere: &ProjectSphereToml) -> Result<Self, String> {
        let scratch = PathBuf::from(&sphere.scratch);
        if !plain_root(&scratch) {
            return Err(format!(
                "sphere scratch {} is not a plain absolute path",
                scratch.display()
            ));
        }
        let mut data_roots = Vec::with_capacity(sphere.data_roots.len());
        for root in &sphere.data_roots {
            let path = PathBuf::from(root);
            if !plain_root(&path) {
                return Err(format!(
                    "sphere data root {root:?} is not a plain absolute path"
                ));
            }
            if path == scratch || nests(&path, &scratch) || nests(&scratch, &path) {
                return Err(format!(
                    "sphere data root {} overlaps scratch {}",
                    path.display(),
                    scratch.display()
                ));
            }
            if data_roots.iter().any(|previous: &PathBuf| {
                previous == &path || nests(previous, &path) || nests(&path, previous)
            }) {
                return Err(format!(
                    "sphere data root {} overlaps another root",
                    path.display()
                ));
            }
            data_roots.push(path);
        }
        let mut devices = Vec::new();
        for device in &sphere.devices {
            let Some(node) = &device.node else {
                continue;
            };
            let path = PathBuf::from(node);
            if !declared_serial(&path) {
                return Err(format!(
                    "sphere device {} node {} is not a stable serial path",
                    device.name,
                    path.display()
                ));
            }
            if !devices.contains(&path) {
                devices.push(path);
            }
        }
        let mut endpoints = Vec::new();
        for device in &sphere.devices {
            let Some(endpoint) = &device.endpoint else {
                continue;
            };
            if is_http(endpoint) {
                continue;
            }
            let Some(socket) = endpoint.strip_prefix("unix://") else {
                return Err(format!(
                    "sphere device {} endpoint is not unix:// or http(s)",
                    device.name
                ));
            };
            let socket = PathBuf::from(socket);
            if !plain_root(&socket) {
                return Err(format!(
                    "sphere device {} unix endpoint is not a plain absolute socket path",
                    device.name
                ));
            }
            if socket == scratch || nests(&scratch, &socket) || nests(&socket, &scratch) {
                return Err(format!(
                    "sphere device {} endpoint overlaps scratch",
                    device.name
                ));
            }
            if !endpoints.contains(&socket) {
                endpoints.push(socket);
            }
        }
        Ok(Self {
            data_roots,
            scratch,
            devices,
            endpoints,
        })
    }

    /// Host paths this projection binds, besides the lane capsule.
    pub fn mounts(&self) -> impl Iterator<Item = &Path> {
        self.data_roots
            .iter()
            .chain(std::iter::once(&self.scratch))
            .chain(&self.devices)
            .chain(&self.endpoints)
            .map(PathBuf::as_path)
    }
}

fn plain_root(path: &Path) -> bool {
    let Some(text) = path.to_str() else {
        return false;
    };
    path.is_absolute()
        && text != "/"
        && !text.ends_with('/')
        && !text.contains("//")
        && !path.starts_with("/dev")
        && path
            .components()
            .skip(1)
            .all(|part| matches!(part, std::path::Component::Normal(_)))
}
fn is_http(value: &str) -> bool {
    value.starts_with("http://") || value.starts_with("https://")
}

fn declared_serial(path: &Path) -> bool {
    let Some(text) = path.to_str() else {
        return false;
    };
    let Some(name) = text.strip_prefix("/dev/serial/by-id/") else {
        return false;
    };
    !name.is_empty()
        && !name.contains('/')
        && path
            .components()
            .skip(1)
            .all(|part| matches!(part, std::path::Component::Normal(_)))
}

fn nests(outer: &Path, inner: &Path) -> bool {
    inner.starts_with(outer) && inner != outer
}

/// Drop the shell's private `--dev /dev` without touching `--proc /proc`.
fn drop_shell_dev(argv: &mut Vec<String>) -> Result<(), String> {
    let Some(index) = argv.iter().position(|arg| arg == "--dev") else {
        return Ok(());
    };
    if argv.get(index + 1).map(String::as_str) != Some("/dev") {
        return Err("sphere sandbox has --dev without /dev".to_owned());
    }
    argv.drain(index..index + 2);
    if argv.iter().any(|arg| arg == "--dev")
        || argv.windows(2).any(|pair| pair == ["--dev-bind", "/dev"])
    {
        return Err("sphere sandbox still mounts the host /dev".to_owned());
    }
    Ok(())
}

/// Bind the capsule writable, data roots read-only, and scratch writable.
/// A declared serial node is bound only while it is attached, and only at
/// its declared path: the symlink is resolved so the open stays inside
/// `/dev`, and the target is not given its own mount.
fn push_sphere(
    argv: &mut Vec<String>,
    capsule: &Path,
    sphere: &SphereProjection,
) -> Result<(), String> {
    push_bind(argv, "--bind", capsule, capsule)?;
    for root in &sphere.data_roots {
        push_bind(argv, "--ro-bind", root, root)?;
    }
    if sphere.scratch != capsule {
        std::fs::create_dir_all(&sphere.scratch).map_err(|error| {
            format!(
                "create sphere scratch {}: {error}",
                sphere.scratch.display()
            )
        })?;
        push_bind(argv, "--bind", &sphere.scratch, &sphere.scratch)?;
    }
    Ok(())
}

/// Bind one selected device into a `device.run` bubble. The shell, a build,
/// and artifact analysis never call this: they have the data roots and the
/// scratch, and cannot open a serial node or the device socket.
pub fn push_selected_device(
    argv: &mut Vec<String>,
    node: Option<&Path>,
    socket: Option<&Path>,
) -> Result<(), String> {
    if let Some(node) = node {
        push_attached_node(argv, node)?;
    }
    if let Some(socket) = socket {
        if socket.exists() {
            push_bind(argv, "--ro-bind", socket, Path::new(DEVICE_SOCKET))?;
        }
    }
    Ok(())
}
/// Where one staged artifact appears inside the bubble. The host path is
/// not the destination: binding a file at its real path also mounts that
/// path's parent, and the program could walk sibling files.
pub const STAGED_ARTIFACT: &str = "/run/odin/artifact";

/// Bind one staged artifact file read-only. A file already inside the
/// capsule keeps its path, over the writable capsule mount. Any other
/// absolute file is bound at [`STAGED_ARTIFACT`], so its parent directory
/// stays outside the bubble.
fn push_staged_file(
    argv: &mut Vec<String>,
    capsule: &Path,
    sphere: &SphereProjection,
    path: &Path,
) -> Result<(), String> {
    if !path.is_absolute() || path == Path::new("/") {
        return Err(format!(
            "staged artifact {} is not an absolute file",
            path.display()
        ));
    }
    if sphere.mounts().any(|mount| mount == path) || path == capsule {
        return Err(format!("staged artifact {} is not a file", path.display()));
    }
    let inside = path.starts_with(capsule)
        || path.starts_with(&sphere.scratch)
        || sphere.data_roots.iter().any(|root| path.starts_with(root));
    let dest = if inside {
        path
    } else {
        Path::new(STAGED_ARTIFACT)
    };
    push_bind(argv, "--ro-bind", path, dest)
}

/// Bind the declared by-id path when that symlink resolves to one character
/// device under `/dev`. The source is the resolved node, not the symlink:
/// `--dev-bind` of the by-id path mounts `/dev` and would expose every host
/// device. The destination stays the declared path, so the action opens the
/// name it was given and nothing else under `/dev` appears. An absent node
/// is an error naming it: the action declared it and would run without it.
fn push_attached_node(argv: &mut Vec<String>, node: &Path) -> Result<(), String> {
    let resolved = std::fs::canonicalize(node)
        .map_err(|error| format!("sphere device {} is not attached: {error}", node.display()))?;
    let metadata = std::fs::metadata(&resolved)
        .map_err(|error| format!("sphere device {} metadata: {error}", node.display()))?;
    if !resolved.starts_with("/dev/")
        || !metadata.file_type().is_char_device()
        || resolved
            .components()
            .skip(1)
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err(format!(
            "sphere device {} does not resolve to one character device under /dev",
            node.display()
        ));
    }
    push_bind(argv, "--dev-bind", &resolved, node)
}

/// bwrap options for one subject inside a sphere. Seat path roles do not
/// join: the capsule, the data roots and the scratch are the filesystem.
/// Process infrastructure stays on the profile. That includes the resolved
/// models file, recorded as `models_overlay` (source and dest are the
/// canonical path when the home link already names it) so clearing the
/// seat-role lists does not drop the only mount that makes the link resolve.
pub fn sphere_sandbox_argv(
    subject: SandboxSubject,
    profile: &SeatSandboxProfile,
    capsule: &Path,
    sphere: &SphereProjection,
) -> Result<Vec<String>, String> {
    let mut confined = profile.clone();
    // Seat roles only. Do not clear models_overlay, omp state, or provider
    // auth: those are process infrastructure, not declared role paths.
    confined.writable.clear();
    confined.readonly.clear();
    if subject == SandboxSubject::Shell {
        // The shell's working directory is the capsule, not a seat role.
        confined.writable.push(capsule.to_path_buf());
    }
    let mut argv = super::sandbox::seat_sandbox_argv(subject, &confined)?;
    if subject == SandboxSubject::Shell {
        drop_shell_dev(&mut argv)?;
    }
    // The shell helper bound the capsule so `--chdir` names it. Bind it
    // once, with the rest of the sphere, below.
    if subject == SandboxSubject::Shell {
        let bind = ["--bind".to_owned(), path_arg(capsule)?, path_arg(capsule)?];
        if let Some(index) = argv.windows(3).position(|window| window == bind) {
            argv.drain(index..index + 3);
        }
    }
    push_sphere(&mut argv, capsule, sphere)?;
    if binds_host_root(&argv) {
        return Err("sphere sandbox argv must not bind the host root or /dev".to_owned());
    }
    Ok(argv)
}

/// The host Nix daemon's socket directory.
pub const NIX_DAEMON_SOCKET: &str = "/nix/var/nix/daemon-socket";

/// The daemon's build logs; `nix log` reads them as files.
const NIX_BUILD_LOGS: &str = "/nix/var/log/nix";

/// bwrap options for a Nix eval, build or check inside the capsule. The
/// client sees only the capsule, its sphere and the read-only host store;
/// builds go to the host daemon through its socket and run in the daemon's
/// own build sandbox. The client detects no network and would otherwise
/// tell the daemon not to substitute, so callers pass `substitute = true`.
/// The daemon's build logs and a linked worktree's git common directory are
/// bound read-only, for `nix log` and `git+file:` flakes. `--dev /dev` mounts a fresh
/// devtmpfs, not `--dev-bind /dev`: no host device node is mounted.
pub fn capsule_nix_argv(
    capsule: &Path,
    sphere: &SphereProjection,
    tool_path: &[PathBuf],
    command: &[String],
) -> Result<Vec<String>, String> {
    let mut argv = capsule_command_argv(capsule, sphere, &[], tool_path, command)?;
    let dash = argv
        .iter()
        .position(|arg| arg == "--")
        .ok_or("capsule nix argv has no command separator")?;
    let mut binds = Vec::new();
    if let Some(common) = worktree_common_dir(capsule) {
        push_bind(&mut binds, "--ro-bind", &common, &common)?;
    }
    let logs = Path::new(NIX_BUILD_LOGS);
    if logs.is_dir() {
        push_bind(&mut binds, "--ro-bind", logs, logs)?;
    }
    let socket = Path::new(NIX_DAEMON_SOCKET);
    push_bind(&mut binds, "--bind", socket, socket)?;
    binds.extend([
        "--setenv".to_owned(),
        "NIX_REMOTE".to_owned(),
        "daemon".to_owned(),
    ]);
    for (offset, arg) in binds.into_iter().enumerate() {
        argv.insert(dash + offset, arg);
    }
    // After `--proc`: a private devtmpfs, not `--dev-bind /dev /dev`.
    let proc = argv
        .windows(2)
        .position(|window| window == ["--proc", "/proc"])
        .ok_or("capsule nix argv has no /proc")?;
    argv.insert(proc + 2, "/dev".to_owned());
    argv.insert(proc + 2, "--dev".to_owned());
    if binds_host_root(&argv) {
        return Err("capsule nix argv binds a host root".to_owned());
    }
    Ok(argv)
}

/// The main repository's git directory when `capsule` is a linked
/// worktree outside it: its `.git` file names a gitdir whose `commondir`
/// points back to the main repository.
fn worktree_common_dir(capsule: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(capsule.join(".git")).ok()?;
    let gitdir = capsule.join(text.strip_prefix("gitdir:")?.trim());
    let common = std::fs::read_to_string(gitdir.join("commondir")).ok()?;
    let common = gitdir.join(common.trim()).canonicalize().ok()?;
    (!common.starts_with(capsule)).then_some(common)
}

/// bwrap options for a daemon-owned command inside the lane capsule: analysis
/// of one artifact, or a device action. `PATH` is the command's directory plus
/// `tool_path`, the declared sandbox tool bins. An `env` in one of those
/// directories is bound at `/usr/bin/env`.
///
/// `readonly` is one staged artifact file, bound read-only at its own path.
/// That path must already sit inside the capsule: binding a host file at its
/// real path would also expose its parent directory. A path outside the
/// capsule, a data root, or the scratch root is refused.
pub fn capsule_command_argv(
    capsule: &Path,
    sphere: &SphereProjection,
    readonly: &[PathBuf],
    tool_path: &[PathBuf],
    command: &[String],
) -> Result<Vec<String>, String> {
    if command.is_empty() {
        return Err("capsule command has no executable".to_owned());
    }
    let executable = Path::new(&command[0]);
    if !executable.is_absolute() {
        return Err(format!(
            "capsule command {} is not absolute",
            executable.display()
        ));
    }
    let mut argv = vec![
        "--die-with-parent".to_owned(),
        "--unshare-all".to_owned(),
        "--new-session".to_owned(),
    ];
    argv.extend([
        "--cap-drop".to_owned(),
        "ALL".to_owned(),
        "--clearenv".to_owned(),
        "--ro-bind".to_owned(),
        "/nix/store".to_owned(),
        "/nix/store".to_owned(),
        "--proc".to_owned(),
        "/proc".to_owned(),
        "--tmpfs".to_owned(),
        "/tmp".to_owned(),
        "--setenv".to_owned(),
        "HOME".to_owned(),
        "/tmp".to_owned(),
        "--setenv".to_owned(),
        "TMPDIR".to_owned(),
        "/tmp".to_owned(),
    ]);
    let mut path_dirs = Vec::new();
    if let Some(dir) = executable.parent() {
        path_dirs.push(dir.to_path_buf());
    }
    for dir in tool_path {
        if dir.is_absolute() && !path_dirs.iter().any(|have| have == dir) {
            path_dirs.push(dir.clone());
        }
    }
    if let Some(env) = path_dirs
        .iter()
        .map(|dir| dir.join("env"))
        .find(|path| path.is_file())
    {
        argv.extend([
            "--dir".to_owned(),
            "/usr".to_owned(),
            "--dir".to_owned(),
            "/usr/bin".to_owned(),
        ]);
        push_bind(&mut argv, "--ro-bind", &env, Path::new(ENV_PATH))?;
    }
    push_sphere(&mut argv, capsule, sphere)?;
    argv.extend(["--chdir".to_owned(), path_arg(capsule)?]);
    for path in readonly {
        push_staged_file(&mut argv, capsule, sphere, path)?;
    }
    let path = if path_dirs.is_empty() {
        "/nix/store".to_owned()
    } else {
        std::env::join_paths(&path_dirs)
            .map_err(|error| format!("capsule PATH rejected: {error}"))?
            .to_string_lossy()
            .into_owned()
    };
    argv.extend(["--setenv".to_owned(), "PATH".to_owned(), path]);
    argv.push("--".to_owned());
    argv.extend(command.iter().cloned());
    if binds_host_root(&argv) || argv.windows(2).any(|pair| pair == ["--dev", "/dev"]) {
        return Err("capsule command argv binds a host root".to_owned());
    }
    Ok(argv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use odin_registry::schema::{ProjectDeviceToml, ProjectSphereToml};

    fn sphere(data: &[&str], scratch: &str) -> ProjectSphereToml {
        ProjectSphereToml {
            data_roots: data.iter().map(|root| (*root).to_owned()).collect(),
            scratch: scratch.to_owned(),
            pod_profiles: Default::default(),
            devices: Vec::new(),
        }
    }

    fn refused(sphere: &ProjectSphereToml) -> String {
        SphereProjection::from_sphere(sphere).expect_err("sphere is refused")
    }

    #[test]
    fn data_roots_may_not_overlap_scratch_or_each_other() {
        assert!(refused(&sphere(&["/data"], "/data/scratch")).contains("overlaps scratch"));
        assert!(refused(&sphere(&["/data", "/data/reference"], "/scratch"))
            .contains("overlaps another root"));
    }

    #[test]
    fn an_absent_selected_node_fails_naming_it() {
        let mut argv = Vec::new();
        let node = Path::new("/dev/serial/by-id/usb-absent");
        let error = push_selected_device(&mut argv, Some(node), None).unwrap_err();
        assert!(error.contains("/dev/serial/by-id/usb-absent"), "{error}");
        assert!(argv.is_empty());
    }

    #[test]
    fn a_device_is_a_stable_serial_node_an_unattached_action_set_or_a_bound_endpoint() {
        let device = |node: Option<&str>, endpoint: Option<&str>| {
            let mut declared = sphere(&[], "/scratch");
            declared.devices.push(ProjectDeviceToml {
                name: "dev".to_owned(),
                node: node.map(str::to_owned),
                api: None,
                endpoint: endpoint.map(str::to_owned),
                actions: Vec::new(),
            });
            declared
        };
        assert!(refused(&device(Some("/dev/ttyUSB0"), None)).contains("stable serial path"));
        assert!(refused(&device(None, Some("ftp://host/x"))).contains("not unix:// or http(s)"));
        assert!(
            refused(&device(None, Some("unix:///scratch/dev.sock"))).contains("overlaps scratch")
        );

        let serial = SphereProjection::from_sphere(&device(Some("/dev/serial/by-id/usb-A"), None))
            .expect("serial node");
        assert_eq!(serial.devices, [PathBuf::from("/dev/serial/by-id/usb-A")]);
        let socket = SphereProjection::from_sphere(&device(None, Some("unix:///run/dev.sock")))
            .expect("unix endpoint");
        assert_eq!(socket.endpoints, [PathBuf::from("/run/dev.sock")]);
        let http = SphereProjection::from_sphere(&device(None, Some("https://dev.example/")))
            .expect("http endpoint is not a filesystem bind");
        assert!(http.endpoints.is_empty());
        let bare = SphereProjection::from_sphere(&device(None, None))
            .expect("the registry admits a device with actions only");
        assert_eq!(bare.mounts().collect::<Vec<_>>(), [Path::new("/scratch")]);
    }
}
