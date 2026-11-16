//! One bwrap argv for a seat declaration. The OMP process and the bash tool
//! are different subjects: the process keeps the host network namespace so
//! provider HTTP still works. The shell unshares its network (`none`) or
//! shares the host namespace (`host`). Neither is a packet allowlist.

use std::path::{Path, PathBuf};

use odin_registry::schema::{SeatSandboxNetwork, SeatSandboxToml};

/// Which program the argv confines.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxSubject {
    /// The OMP process. Always retains the host network namespace.
    Process,
    /// The bash tool. `none` unshares its network; `host` shares the host namespace.
    Shell,
}

/// Seat system prompt in the launch directory; OMP reads a newline-free
/// `--system-prompt`/`--append-system-prompt` value as a file path,
/// keeping the text off argv.
pub const SYSTEM_PROMPT_FILE: &str = "system-prompt.md";

/// Where models and scripts look for bash and sh; each bubble binds its shell
/// at every one of them.
const BASH_PATHS: [&str; 3] = ["/bin/bash", "/usr/bin/bash", "/usr/local/bin/bash"];
const SH_PATHS: [&str; 2] = ["/bin/sh", "/usr/bin/sh"];
/// Scripts start with `#!/usr/bin/env <tool>`.
pub(super) const ENV_PATH: &str = "/usr/bin/env";
/// Where the process bubble mounts the shell's bwrap argv file.
const SHELL_ARGV_MOUNT: &str = "/odin-shell.argv";
/// OMP's agent directory under HOME, which holds the models file.
const OMP_AGENT_DIR: &str = ".omp/agent";
/// The directories a seat's `read` may open, colon-separated: the bubble's own seat mounts.
pub const READ_ROOTS_ENV: &str = "ODIN_READ_ROOTS";
/// The seat scratch directory under the launch directory, and its role name.
const SCRATCH_DIR: &str = "scratch";

/// Resolved mounts for one launch. Role names are already absolute paths.
#[derive(Clone, Debug)]
pub struct SeatSandboxProfile {
    pub network: SeatSandboxNetwork,
    pub writable: Vec<PathBuf>,
    pub readonly: Vec<PathBuf>,
    /// Existing /etc entries, bound at the same path. No secrets.
    pub etc_files: Vec<PathBuf>,
    /// Host OMP state directories, bound at their original paths. Process only.
    pub omp_state: Vec<PathBuf>,
    /// Provider credential files. Process only; never the shell.
    pub provider_auth: Vec<PathBuf>,
    /// `(source, dest)` models overlay. Process only.
    pub models_overlay: Option<(PathBuf, PathBuf)>,
    /// Wrapper bound over the bash paths OMP probes. Process only.
    pub shell_wrapper: Option<PathBuf>,
    /// Real bash: /bin/sh for OMP `!` config commands; /bin/sh and /bin/bash in the shell.
    pub real_sh: Option<PathBuf>,
    /// Directories after the wrapper dirs on the process PATH (grep, cut).
    pub path_extra: Vec<PathBuf>,
    /// Launch identity; an undeclared directory is empty rather than host-bound.
    pub cwd: PathBuf,
    pub home: PathBuf,
    /// Host shell-argv file, bound read-only at `/odin-shell.argv`. Process only.
    pub shell_argv: Option<PathBuf>,
    pub shell_path: Vec<PathBuf>,
}

/// bwrap options for `subject`, without the bwrap binary or the inner command.
pub fn seat_sandbox_argv(
    subject: SandboxSubject,
    profile: &SeatSandboxProfile,
) -> Result<Vec<String>, String> {
    let mut argv = vec!["--unshare-all".to_owned(), "--new-session".to_owned()];
    argv.extend(["--cap-drop".to_owned(), "ALL".to_owned()]);
    match subject {
        // Provider HTTP needs this process on the host network.
        // This is not the seat's shell policy. No --die-with-parent: its
        // PDEATHSIG follows the odind thread that forked the bubble, and a
        // runtime thread that retires would SIGKILL a healthy session. The
        // worker scope owns this process's lifetime.
        SandboxSubject::Process => argv.push("--share-net".to_owned()),
        SandboxSubject::Shell => {
            // The OMP process forks each shell; it dies with that process.
            argv.push("--die-with-parent".to_owned());
            match profile.network {
                SeatSandboxNetwork::None => argv.push("--unshare-net".to_owned()),
                SeatSandboxNetwork::Host => argv.push("--share-net".to_owned()),
            }
        }
    }
    argv.extend([
        "--ro-bind".to_owned(),
        "/nix/store".to_owned(),
        "/nix/store".to_owned(),
        "--tmpfs".to_owned(),
        "/tmp".to_owned(),
        "--proc".to_owned(),
        "/proc".to_owned(),
        "--dev".to_owned(),
        "/dev".to_owned(),
    ]);
    if subject == SandboxSubject::Process || profile.network == SeatSandboxNetwork::Host {
        for path in &profile.etc_files {
            push_bind(&mut argv, "--ro-bind", path, path)?;
        }
    }
    for path in &profile.writable {
        push_bind(&mut argv, "--bind", path, path)?;
    }
    for path in &profile.readonly {
        if profile.writable.iter().any(|writable| writable == path) {
            continue;
        }
        push_bind(&mut argv, "--ro-bind", path, path)?;
    }
    match subject {
        SandboxSubject::Process => {
            // Transcript paths and project slugs must survive a daemon restart.
            argv.extend([
                "--dir".to_owned(),
                path_arg(&profile.home.join(OMP_AGENT_DIR))?,
                "--setenv".to_owned(),
                "HOME".to_owned(),
                path_arg(&profile.home)?,
            ]);
            for path in &profile.omp_state {
                push_bind(&mut argv, "--bind", path, path)?;
            }
            for path in &profile.provider_auth {
                push_bind(&mut argv, "--ro-bind", path, path)?;
            }
            if let Some((source, dest)) = &profile.models_overlay {
                push_bind(&mut argv, "--ro-bind", source, dest)?;
            }
            argv.extend([
                "--dir".to_owned(),
                path_arg(&profile.cwd)?,
                "--chdir".to_owned(),
                path_arg(&profile.cwd)?,
            ]);
            let system_prompt = profile.cwd.join(SYSTEM_PROMPT_FILE);
            push_bind(&mut argv, "--ro-bind", &system_prompt, &system_prompt)?;
            for parent in ["/bin", "/usr", "/usr/bin", "/usr/local", "/usr/local/bin"] {
                argv.extend(["--dir".to_owned(), parent.to_owned()]);
            }
            if let Some(argv_file) = &profile.shell_argv {
                push_bind(
                    &mut argv,
                    "--ro-bind",
                    argv_file,
                    Path::new(SHELL_ARGV_MOUNT),
                )?;
            }
            if let Some(wrapper) = &profile.shell_wrapper {
                for dest in BASH_PATHS {
                    push_bind(&mut argv, "--ro-bind", wrapper, Path::new(dest))?;
                }
            }
            // execSync uses /bin/sh for models.yml `!` commands. That stays
            if let Some(sh) = &profile.real_sh {
                for dest in SH_PATHS {
                    push_bind(&mut argv, "--ro-bind", sh, Path::new(dest))?;
                }
            }
            let mut path = "/bin:/usr/bin:/usr/local/bin".to_owned();
            for extra in &profile.path_extra {
                path.push(':');
                path.push_str(&path_arg(extra)?);
            }
            argv.extend(["--setenv".to_owned(), "PATH".to_owned(), path]);
            if profile.shell_wrapper.is_some() {
                argv.extend([
                    "--setenv".to_owned(),
                    "SHELL".to_owned(),
                    BASH_PATHS[0].to_owned(),
                ]);
            }
        }
        SandboxSubject::Shell => {
            // Drop the process environment so provider tokens and the worker
            // bus address do not ride into the shell.
            argv.push("--clearenv".to_owned());
            // HOME is the bubble's own /tmp, so tool caches (nix, cargo)
            // never land in the checkout and vanish with the command.
            let cwd = profile
                .writable
                .first()
                .map(|path| path_arg(path))
                .transpose()?
                .unwrap_or_else(|| "/tmp".to_owned());
            argv.extend(["--setenv".to_owned(), "HOME".to_owned(), "/tmp".to_owned()]);
            argv.extend(["--chdir".to_owned(), cwd]);
            // Models and scripts name /bin/bash, /bin/sh and /usr/bin/env;
            // these are the store binaries the shell already has on PATH.
            if let Some(sh) = &profile.real_sh {
                for dest in SH_PATHS.into_iter().chain(BASH_PATHS) {
                    push_bind(&mut argv, "--ro-bind", sh, Path::new(dest))?;
                }
            }
            let env = profile
                .shell_path
                .iter()
                .map(|dir| dir.join("env"))
                .find(|path| path.is_file())
                .ok_or_else(|| {
                    format!(
                        "the seat shell PATH ({}) holds no `env` to bind at {ENV_PATH}",
                        profile
                            .shell_path
                            .iter()
                            .map(|dir| dir.display().to_string())
                            .collect::<Vec<_>>()
                            .join(":")
                    )
                })?;
            push_bind(&mut argv, "--ro-bind", &env, Path::new(ENV_PATH))?;
            if !profile.shell_path.is_empty() {
                let path = std::env::join_paths(&profile.shell_path)
                    .map_err(|error| format!("shell PATH rejected: {error}"))?
                    .to_string_lossy()
                    .into_owned();
                argv.extend(["--setenv".to_owned(), "PATH".to_owned(), path]);
            }
        }
    }
    if binds_host_root(&argv) {
        return Err("seat sandbox argv must not bind the host root".to_owned());
    }
    Ok(argv)
}

/// Whether `argv` binds the host root or the host's `/dev`, which no bubble may.
pub(super) fn binds_host_root(argv: &[String]) -> bool {
    argv.windows(2)
        .any(|pair| pair == ["--bind", "/"] || pair == ["--dev-bind", "/dev"])
}

/// Store-shebang wrapper. The shebang is the real bash, not `/bin/bash`,
/// because the process bubble binds this file over `/bin/bash`.
pub fn shell_wrapper_script(bwrap: &Path, argv_file: &Path, bash: &Path) -> Result<String, String> {
    for (name, path) in [("bwrap", bwrap), ("argv", argv_file), ("bash", bash)] {
        if !path.is_absolute() {
            return Err(format!("shell wrapper {name} path is not absolute"));
        }
    }
    Ok(format!(
        "#!{}\nexec {} --args 3 3< {} -- {} \"$@\"\n",
        bash.display(),
        bwrap.display(),
        argv_file.display(),
        bash.display()
    ))
}

/// Writable and read-only paths after resolving role names.
pub fn resolve_sandbox_paths(
    sandbox: &SeatSandboxToml,
    capsule: &Path,
    scratch: &Path,
) -> Result<(Vec<PathBuf>, Vec<PathBuf>), String> {
    let writable = sandbox
        .writable_entries()
        .iter()
        .map(|entry| resolve_role(entry, capsule, scratch))
        .collect::<Result<Vec<_>, _>>()?;
    let readonly = sandbox
        .readonly
        .iter()
        .map(|entry| resolve_role(entry, capsule, scratch))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((writable, readonly))
}
pub(super) fn path_arg(path: &Path) -> Result<String, String> {
    path.to_str()
        .filter(|value| !value.contains('\0'))
        .map(str::to_owned)
        .ok_or_else(|| format!("sandbox path {} is not UTF-8", path.display()))
}

fn resolve_role(entry: &str, capsule: &Path, scratch: &Path) -> Result<PathBuf, String> {
    let path = match entry {
        "capsule" | "checkout" => capsule.to_path_buf(),
        SCRATCH_DIR => scratch.to_path_buf(),
        other => PathBuf::from(other),
    };
    if !path.is_absolute() {
        return Err(format!(
            "sandbox path {entry:?} did not resolve to an absolute path"
        ));
    }
    Ok(path)
}

pub(super) fn push_bind(
    argv: &mut Vec<String>,
    flag: &str,
    source: &Path,
    dest: &Path,
) -> Result<(), String> {
    argv.push(flag.to_owned());
    argv.push(path_arg(source)?);
    argv.push(path_arg(dest)?);
    Ok(())
}

/// Host paths the launch reads from the composed environment. Not seat names.
#[derive(Clone, Debug)]
pub struct SeatSandboxHost {
    pub bwrap: PathBuf,
    pub bash: PathBuf,
    pub python: Option<PathBuf>,
    pub models_file: Option<PathBuf>,
    pub provider_auth: Vec<PathBuf>,
    pub omp_state: Vec<PathBuf>,
    pub etc_files: Vec<PathBuf>,
    pub path_extra: Vec<PathBuf>,
}

const ETC_CANDIDATES: &[&str] = &[
    "/etc/resolv.conf",
    "/etc/ssl",
    "/etc/passwd",
    "/etc/group",
    "/etc/nsswitch.conf",
    "/etc/hosts",
    "/etc/static",
    "/run/systemd/resolve",
    "/run/nscd",
];

/// Reads the seat-sandbox host binding. `ODIN_BWRAP` and `ODIN_BASH` are
/// required; a missing one is a named failure, not an unconfined launch.
pub fn sandbox_host_from_env() -> Result<SeatSandboxHost, String> {
    sandbox_host(|name| std::env::var(name).ok())
}

fn sandbox_host(env: impl Fn(&str) -> Option<String>) -> Result<SeatSandboxHost, String> {
    let bwrap = required_path(&env, "ODIN_BWRAP")?;
    let bash = required_path(&env, "ODIN_BASH")?;
    let python = optional_path(&env, "ODIN_PYTHON3")?;
    let models_file = optional_path(&env, "ODIN_OMP_MODELS")?;
    let provider_auth = path_list(&env, "ODIN_PROVIDER_AUTH", Path::is_file, "file")?;
    let path_extra = path_list(&env, "ODIN_PATH_EXTRA", Path::is_dir, "directory")?;
    let omp_state = env("HOME")
        .map(PathBuf::from)
        .map(|home| {
            [".omp/run", ".omp/cache", ".omp/logs", OMP_AGENT_DIR]
                .into_iter()
                .map(|leaf| home.join(leaf))
                .filter(|path| path.is_dir())
                .collect()
        })
        .unwrap_or_default();
    let etc_files = ETC_CANDIDATES
        .iter()
        .map(PathBuf::from)
        .filter(|path| path.exists())
        .collect();
    Ok(SeatSandboxHost {
        bwrap,
        bash,
        python,
        models_file,
        provider_auth,
        omp_state,
        etc_files,
        path_extra,
    })
}

fn required_path(env: &impl Fn(&str) -> Option<String>, name: &str) -> Result<PathBuf, String> {
    let value = env(name)
        .ok_or_else(|| format!("{name} is unset; the seat sandbox has no host binding"))?;
    let path = PathBuf::from(value);
    if !path.is_absolute() || !path.is_file() {
        return Err(format!("{name}={} is not an absolute file", path.display()));
    }
    Ok(path)
}

fn optional_path(
    env: &impl Fn(&str) -> Option<String>,
    name: &str,
) -> Result<Option<PathBuf>, String> {
    let Some(value) = env(name).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let path = PathBuf::from(value);
    if !path.is_absolute() || !path.exists() {
        return Err(format!(
            "{name}={} is not an absolute existing path",
            path.display()
        ));
    }
    Ok(Some(path))
}

/// A colon-separated list of absolute paths that must each satisfy `exists`.
fn path_list(
    env: &impl Fn(&str) -> Option<String>,
    name: &str,
    exists: fn(&Path) -> bool,
    kind: &str,
) -> Result<Vec<PathBuf>, String> {
    let Some(value) = env(name).filter(|value| !value.is_empty()) else {
        return Ok(Vec::new());
    };
    value
        .split(':')
        .map(|entry| {
            let path = PathBuf::from(entry);
            if path.is_absolute() && exists(&path) {
                Ok(path)
            } else {
                Err(format!("{name} entry {entry} is not an absolute {kind}"))
            }
        })
        .collect()
}

/// Writes the process bubble argv and, when the seat has a shell, the wrapper
/// the OMP bash tool execs. Sets `ODIN_SEAT_SANDBOX` and `ODIN_SHELL`.
/// `sphere`, when the lane's project declares one, replaces the seat's path
/// roles and the generic `/dev` mount with the capsule, the exact data roots,
/// the scratch root, and only the declared serial nodes.
pub fn apply_seat_sandbox(
    process: &mut crate::process::OmpProcessSpec,
    sandbox: &SeatSandboxToml,
    capsule: &Path,
    host: &SeatSandboxHost,
    sphere: Option<&super::sphere::SphereProjection>,
    read_roots: &[PathBuf],
) -> Result<(), String> {
    let home = process
        .explicit_env
        .iter()
        .find(|(name, _)| name == "HOME")
        .map(|(_, value)| PathBuf::from(value))
        .ok_or("sandbox process environment carries no HOME")?;
    let scratch = process.cwd.join(SCRATCH_DIR);
    std::fs::create_dir_all(&scratch)
        .map_err(|error| format!("create seat scratch {}: {error}", scratch.display()))?;
    let (mut writable, mut readonly) = resolve_sandbox_paths(sandbox, capsule, &scratch)?;
    if let Some(sphere) = sphere {
        // The sphere is the filesystem. Seat roles would admit host paths
        // the project did not declare. A serial node is bound only for the
        // selected `device.run` action, which fails when it is absent.
        std::fs::create_dir_all(&sphere.scratch).map_err(|error| {
            format!(
                "create sphere scratch {}: {error}",
                sphere.scratch.display()
            )
        })?;
        writable = vec![capsule.to_path_buf(), sphere.scratch.clone()];
        readonly = sphere.data_roots.clone();
    } else {
        // The seat's own file roots: a declared folder that is absent today is skipped, not fatal.
        readonly.extend(read_roots.iter().filter(|root| root.is_dir()).cloned());
    }
    // Everything the bubble mounts for the seat is what `read` may open (the extension checks).
    let readable: Vec<&str> = writable
        .iter()
        .chain(readonly.iter())
        .filter_map(|path| path.to_str())
        .collect();
    process
        .explicit_env
        .push((READ_ROOTS_ENV.to_owned(), readable.join(":")));
    for path in writable.iter().chain(readonly.iter()) {
        if !path.exists() {
            return Err(format!("sandbox mount {} does not exist", path.display()));
        }
    }
    if sandbox.network == SeatSandboxNetwork::Host && !sandbox.shell {
        return Err("network = host requires shell = true".to_owned());
    }
    let mut shell_wrapper = None;
    let mut shell_path = Vec::new();
    let mut shell_argv = None;
    if sandbox.shell {
        // The launch directory is not a bubble mount. The wrapper opens the
        // read-only bind, not this host path, so a shell write cannot replace
        // the next bubble's argv.
        let argv_file = process.cwd.join("shell.argv");
        let wrapper_path = process.cwd.join("shell-bash");
        if writable
            .iter()
            .any(|mount| argv_file.starts_with(mount) || wrapper_path.starts_with(mount))
        {
            return Err(
                "shell argv would be writable from the shell bubble; launch directory must not be a declared writable"
                    .to_owned(),
            );
        }
        if let Some(parent) = host.bash.parent() {
            shell_path.push(parent.to_path_buf());
        }
        if let Some(python) = &host.python {
            if let Some(parent) = python.parent() {
                shell_path.push(parent.to_path_buf());
            }
        }
        shell_path.extend(host.path_extra.iter().cloned());
        let shell_profile = profile_for(
            sandbox,
            &writable,
            &readonly,
            host,
            &process.cwd,
            &home,
            ShellLaunch {
                wrapper: None,
                argv: None,
                path: shell_path.clone(),
            },
        );
        write_subject_argv(
            &argv_file,
            SandboxSubject::Shell,
            &shell_profile,
            capsule,
            sphere,
        )?;
        let script = shell_wrapper_script(&host.bwrap, Path::new(SHELL_ARGV_MOUNT), &host.bash)?;
        std::fs::write(&wrapper_path, script)
            .map_err(|error| format!("write shell wrapper {}: {error}", wrapper_path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&wrapper_path, std::fs::Permissions::from_mode(0o755))
                .map_err(|error| {
                    format!("chmod shell wrapper {}: {error}", wrapper_path.display())
                })?;
        }
        shell_wrapper = Some(wrapper_path);
        shell_argv = Some(argv_file);
        enable_shell_tool(&mut process.explicit_args);
        process
            .explicit_env
            .push(("ODIN_SHELL".to_owned(), "1".to_owned()));
        // Login bash (-l) would source a profile and can replace PATH,
        // walking past the wrapper. Non-login -c keeps the bubble PATH.
        process
            .explicit_env
            .push(("PI_BASH_NO_LOGIN".to_owned(), "1".to_owned()));
    }
    let process_profile = profile_for(
        sandbox,
        &writable,
        &readonly,
        host,
        &process.cwd,
        &home,
        ShellLaunch {
            wrapper: shell_wrapper,
            argv: shell_argv,
            path: shell_path,
        },
    );
    let argv_file = process.cwd.join("process.argv");
    write_subject_argv(
        &argv_file,
        SandboxSubject::Process,
        &process_profile,
        capsule,
        sphere,
    )?;
    let argv = argv_file
        .to_str()
        .ok_or_else(|| "process sandbox argv path is not UTF-8".to_owned())?;
    process
        .explicit_env
        .push(("ODIN_SEAT_SANDBOX".to_owned(), argv.to_owned()));
    Ok(())
}

struct ShellLaunch {
    wrapper: Option<PathBuf>,
    argv: Option<PathBuf>,
    path: Vec<PathBuf>,
}

fn profile_for(
    sandbox: &SeatSandboxToml,
    writable: &[PathBuf],
    readonly: &[PathBuf],
    host: &SeatSandboxHost,
    cwd: &Path,
    home: &Path,
    shell: ShellLaunch,
) -> SeatSandboxProfile {
    // Home Manager links ~/.omp/agent/models.yml into the store, and bwrap
    // cannot mount over a symlink. When the link already resolves to the
    // declared file there is nothing to overlay: bind the canonical source
    // at itself so the link resolves. That bind is process infrastructure,
    // not a seat role, so it stays on `models_overlay`. A sphere bubble
    // clears `readonly` and would otherwise drop the only mount.
    let models_overlay = host.models_file.as_ref().map(|source| {
        let dest = home.join(OMP_AGENT_DIR).join("models.yml");
        match (std::fs::canonicalize(source), std::fs::canonicalize(&dest)) {
            (Ok(resolved), Ok(resolved_dest)) if resolved == resolved_dest => {
                (resolved.clone(), resolved)
            }
            _ => (source.clone(), dest),
        }
    });
    let real_sh = Some(host.bash.clone());
    let path_extra = host.path_extra.clone();
    SeatSandboxProfile {
        network: sandbox.network,
        writable: writable.to_vec(),
        readonly: readonly.to_vec(),
        etc_files: host.etc_files.clone(),
        omp_state: host.omp_state.clone(),
        provider_auth: host.provider_auth.clone(),
        models_overlay,
        shell_wrapper: shell.wrapper,
        real_sh,
        path_extra,
        cwd: cwd.to_path_buf(),
        home: home.to_path_buf(),
        shell_argv: shell.argv,
        shell_path: shell.path,
    }
}

fn write_subject_argv(
    path: &Path,
    subject: SandboxSubject,
    profile: &SeatSandboxProfile,
    capsule: &Path,
    sphere: Option<&super::sphere::SphereProjection>,
) -> Result<(), String> {
    let argv = match sphere {
        Some(sphere) => super::sphere::sphere_sandbox_argv(subject, profile, capsule, sphere)?,
        None => seat_sandbox_argv(subject, profile)?,
    };
    let mut bytes = Vec::new();
    for arg in &argv {
        bytes.extend(arg.as_bytes());
        bytes.push(0);
    }
    std::fs::write(path, bytes)
        .map_err(|error| format!("write sandbox argv {}: {error}", path.display()))
}

fn enable_shell_tool(args: &mut [String]) {
    let Some(index) = args.iter().position(|arg| arg == "--tools") else {
        return;
    };
    let Some(value) = args.get_mut(index + 1) else {
        return;
    };
    if !value.split(',').any(|tool| tool == "bash") {
        value.push_str(",bash");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> SeatSandboxProfile {
        SeatSandboxProfile {
            network: SeatSandboxNetwork::None,
            writable: vec![PathBuf::from("/work/scratch")],
            readonly: vec![PathBuf::from("/work/checkout")],
            etc_files: vec![PathBuf::from("/etc/resolv.conf")],
            omp_state: vec![PathBuf::from("/home/owner/.omp/run")],
            provider_auth: vec![PathBuf::from(
                "/home/owner/.config/sops-nix/secrets/rendered/litellm-env",
            )],
            models_overlay: Some((
                PathBuf::from("/nix/store/models.yml"),
                PathBuf::from("/home/owner/.omp/agent/models.yml"),
            )),
            shell_wrapper: Some(PathBuf::from("/work/shell-bash")),
            real_sh: Some(PathBuf::from("/nix/store/bash/bin/bash")),
            path_extra: vec![PathBuf::from("/nix/store/coreutils/bin")],
            cwd: PathBuf::from("/work/launch"),
            home: PathBuf::from("/home/owner"),
            shell_argv: Some(PathBuf::from("/work/launch/shell.argv")),
            shell_path: vec![PathBuf::from("/nix/store/bash/bin"), host_env_dir()],
        }
    }

    /// The test host's directory holding `env`, so the shell bubble can bind it.
    fn host_env_dir() -> PathBuf {
        std::env::split_paths(&std::env::var_os("PATH").expect("PATH"))
            .find(|dir| dir.join("env").is_file())
            .expect("an env on the test host's PATH")
    }

    fn binds(argv: &[String], source: &str, dest: &str) -> bool {
        argv.windows(3)
            .any(|window| window[0].ends_with("bind") && window[1] == source && window[2] == dest)
    }

    #[test]
    fn process_keeps_provider_network_and_shell_does_not_see_it() {
        let profile = profile();
        let process = seat_sandbox_argv(SandboxSubject::Process, &profile).expect("process argv");
        let shell = seat_sandbox_argv(SandboxSubject::Shell, &profile).expect("shell argv");
        let has = |argv: &[String], flag: &str| argv.iter().any(|arg| arg == flag);

        // The process needs provider HTTP and must outlive the thread that forked it;
        // the shell has no network and dies with the process.
        assert!(has(&process, "--share-net") && !has(&process, "--unshare-net"));
        assert!(!has(&process, "--die-with-parent"));
        assert!(has(&shell, "--unshare-net") && !has(&shell, "--share-net"));
        assert!(has(&shell, "--die-with-parent"));
        assert!(!binds_host_root(&process) && !binds_host_root(&shell));

        // Only the process sees provider auth, the omp state and the shell's argv file.
        assert!(process.iter().any(|arg| arg.contains("litellm-env")));
        assert!(has(&process, "/home/owner/.omp/run"));
        assert!(binds(
            &process,
            "/work/launch/shell.argv",
            "/odin-shell.argv"
        ));
        assert!(binds(
            &process,
            "/work/launch/system-prompt.md",
            "/work/launch/system-prompt.md"
        ));
        assert!(!process
            .windows(2)
            .any(|pair| pair == ["--bind", "/work/launch"]));
        assert!(!shell
            .iter()
            .any(|arg| arg.contains("litellm-env") || arg.contains(".omp")));
        assert!(!has(&shell, "/odin-shell.argv"));

        // The process's bash is the wrapper; its sh and the shell's sh and bash are the store bash.
        assert!(binds(&process, "/work/shell-bash", "/bin/bash"));
        assert!(binds(&process, "/nix/store/bash/bin/bash", "/bin/sh"));
        for dest in SH_PATHS.into_iter().chain(BASH_PATHS) {
            assert!(binds(&shell, "/nix/store/bash/bin/bash", dest), "{dest}");
        }
        assert!(binds(&shell, "/work/scratch", "/work/scratch"));
        assert!(binds(&shell, "/work/checkout", "/work/checkout"));
    }

    /// odind forks a session's bubble from whichever runtime thread runs the
    /// launch, and that thread may retire while the session lives. With
    /// `--die-with-parent` the kernel SIGKILLs the bubble then (signal 9).
    #[test]
    fn the_process_bubble_outlives_the_thread_that_forked_it() {
        let store = |name: &str| {
            std::env::split_paths(&std::env::var_os("PATH").expect("PATH"))
                .find(|dir| dir.join(name).is_file())
                .and_then(|dir| std::fs::canonicalize(dir).ok())
                .map(|dir| dir.join(name))
                .unwrap_or_else(|| panic!("{name} is not on the test PATH"))
        };
        let (bwrap, sleep) = (store("bwrap"), store("sleep"));
        let launch = tempfile::tempdir().expect("launch dir");
        let home = tempfile::tempdir().expect("home dir");
        std::fs::write(launch.path().join(SYSTEM_PROMPT_FILE), "").expect("prompt");
        let profile = SeatSandboxProfile {
            network: SeatSandboxNetwork::None,
            writable: Vec::new(),
            readonly: Vec::new(),
            etc_files: Vec::new(),
            omp_state: Vec::new(),
            provider_auth: Vec::new(),
            models_overlay: None,
            shell_wrapper: None,
            real_sh: None,
            path_extra: Vec::new(),
            cwd: launch.path().to_path_buf(),
            home: home.path().to_path_buf(),
            shell_argv: None,
            shell_path: Vec::new(),
        };
        let argv = seat_sandbox_argv(SandboxSubject::Process, &profile).expect("process argv");
        let mut child = std::thread::spawn(move || {
            std::process::Command::new(bwrap)
                .args(argv)
                .arg("--")
                .arg(sleep)
                .arg("30")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("the bubble starts")
        })
        .join()
        .expect("the forking thread exits");
        // The thread is gone; a bubble tied to it would be dead within the window.
        let window = std::time::Instant::now() + std::time::Duration::from_millis(300);
        while std::time::Instant::now() < window {
            let status = child.try_wait().expect("poll the bubble");
            assert_eq!(status, None, "the bubble died with its forking thread");
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        child.kill().expect("stop the bubble");
        child.wait().expect("reap the bubble");
    }

    #[test]
    fn a_models_link_that_resolves_outside_the_sandbox_binds_its_target() {
        // The authority's ~/.omp/agent/models.yml links through the Home Manager
        // store to the odin-gateway state copy, which is also the declared file.
        let root = tempfile::tempdir().expect("root");
        let state = root.path().join("state/omp-models.yml");
        std::fs::create_dir_all(state.parent().expect("state dir")).expect("state dir");
        std::fs::write(&state, "{}").expect("models");
        let store = root.path().join("store-models.yml");
        std::os::unix::fs::symlink(&state, &store).expect("store link");
        let home = root.path().join("home");
        std::fs::create_dir_all(home.join(".omp/agent")).expect("agent dir");
        std::os::unix::fs::symlink(&store, home.join(".omp/agent/models.yml")).expect("home link");
        let host = SeatSandboxHost {
            bwrap: PathBuf::from("/nix/store/bwrap/bin/bwrap"),
            bash: PathBuf::from("/nix/store/bash/bin/bash"),
            python: None,
            models_file: Some(store),
            provider_auth: Vec::new(),
            omp_state: vec![home.join(".omp/agent")],
            etc_files: Vec::new(),
            path_extra: Vec::new(),
        };
        let shell = ShellLaunch {
            wrapper: None,
            argv: None,
            path: Vec::new(),
        };
        let profile = profile_for(
            &SeatSandboxToml::default(),
            &[PathBuf::from("/work/role")],
            &[PathBuf::from("/work/checkout")],
            &host,
            root.path(),
            &home,
            shell,
        );
        let target = std::fs::canonicalize(&state).expect("canonical state");
        assert_eq!(
            profile.models_overlay,
            Some((target.clone(), target.clone()))
        );
        assert!(
            !profile.readonly.iter().any(|path| path == &target),
            "resolved models file must not sit on the seat-role list: {:?}",
            profile.readonly
        );
        let capsule = root.path().join("capsule");
        std::fs::create_dir_all(&capsule).expect("capsule");
        let sphere = crate::process::SphereProjection {
            data_roots: vec![root.path().join("data")],
            scratch: capsule.clone(),
            devices: Vec::new(),
            endpoints: Vec::new(),
        };
        let argv = crate::process::sphere_sandbox_argv(
            SandboxSubject::Process,
            &profile,
            &capsule,
            &sphere,
        )
        .expect("sphere process argv");
        let rendered = target.display().to_string();
        assert!(
            argv.windows(3)
                .any(|window| { window == ["--ro-bind", rendered.as_str(), rendered.as_str()] }),
            "sphere process dropped the resolved models file: {argv:?}"
        );
        // OMP resolves provider apiKey commands through Bun.spawn with ignored
        // stdin, which needs the process's private /dev to start the command.
        assert!(argv.windows(2).any(|pair| pair == ["--dev", "/dev"]));
        assert!(!argv
            .iter()
            .any(|arg| arg == "/work/checkout" || arg == "/work/role"));
        assert!(!argv
            .windows(2)
            .any(|pair| pair == ["--bind", "/"] || pair == ["--dev-bind", "/dev"]));
        let mut shell_profile = profile;
        let env_dir = std::env::split_paths(&std::env::var_os("PATH").expect("PATH"))
            .find(|dir| dir.join("env").is_file())
            .expect("env on PATH");
        shell_profile.shell_path = vec![env_dir];
        let shell_argv = crate::process::sphere_sandbox_argv(
            SandboxSubject::Shell,
            &shell_profile,
            &capsule,
            &sphere,
        )
        .expect("sphere shell argv");
        assert!(!shell_argv.windows(2).any(|pair| pair == ["--dev", "/dev"]));
        assert!(!shell_argv
            .windows(2)
            .any(|pair| pair == ["--dev-bind", "/dev"]));
        assert!(
            !shell_argv.iter().any(|arg| {
                arg == rendered.as_str() || arg == "/work/checkout" || arg == "/work/role"
            }),
            "shell received a seat role or the models file: {shell_argv:?}"
        );
    }

    #[test]
    fn the_host_binding_names_what_is_missing_or_unusable_before_any_launch() {
        let dir = tempfile::tempdir().expect("dir");
        let file = |name: &str| {
            let path = dir.path().join(name);
            std::fs::write(&path, "").expect("file");
            path.display().to_string()
        };
        let (bwrap, bash) = (file("bwrap"), file("bash"));
        let host = |vars: Vec<(&'static str, String)>| {
            sandbox_host(move |name| {
                vars.iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| value.clone())
            })
        };

        let missing = host(vec![("ODIN_BASH", bash.clone())]).expect_err("no bwrap");
        assert!(missing.contains("ODIN_BWRAP"), "{missing}");
        let relative = host(vec![
            ("ODIN_BWRAP", "bwrap".to_owned()),
            ("ODIN_BASH", bash.clone()),
        ])
        .expect_err("relative bwrap");
        assert!(
            relative.contains("ODIN_BWRAP") && relative.contains("absolute"),
            "{relative}"
        );
        let bad_auth = host(vec![
            ("ODIN_BWRAP", bwrap.clone()),
            ("ODIN_BASH", bash.clone()),
            ("ODIN_PROVIDER_AUTH", "relative/auth".to_owned()),
        ])
        .expect_err("relative auth");
        assert!(bad_auth.contains("ODIN_PROVIDER_AUTH"), "{bad_auth}");

        let ok = host(vec![
            ("ODIN_BWRAP", bwrap.clone()),
            ("ODIN_BASH", bash.clone()),
            ("ODIN_PROVIDER_AUTH", bwrap.clone()),
            ("ODIN_PATH_EXTRA", dir.path().display().to_string()),
        ])
        .expect("a complete binding");
        assert_eq!(ok.bwrap, PathBuf::from(bwrap.clone()));
        assert_eq!(ok.provider_auth, [PathBuf::from(bwrap)]);
        assert_eq!(ok.path_extra, [dir.path().to_path_buf()]);
        assert_eq!(ok.python, None);
    }
}
