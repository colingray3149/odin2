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
/// `--append-system-prompt` value as a file path, keeping the text off argv.
pub const SYSTEM_PROMPT_FILE: &str = "system-prompt.md";

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
    /// Real interpreter bound at /bin/sh for OMP `!` config commands. Process only.
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
    let mut argv = vec![
        "--unshare-all".to_owned(),
        "--die-with-parent".to_owned(),
        "--new-session".to_owned(),
    ];
    argv.extend(["--cap-drop".to_owned(), "ALL".to_owned()]);
    match subject {
        // Provider HTTP needs this process on the host network.
        // This is not the seat's shell policy.
        SandboxSubject::Process => argv.push("--share-net".to_owned()),
        SandboxSubject::Shell => match profile.network {
            SeatSandboxNetwork::None => argv.push("--unshare-net".to_owned()),
            SeatSandboxNetwork::Host => argv.push("--share-net".to_owned()),
        },
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
                path_arg(&profile.home.join(".omp/agent"))?,
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
                    Path::new("/odin-shell.argv"),
                )?;
            }
            if let Some(wrapper) = &profile.shell_wrapper {
                for dest in ["/bin/bash", "/usr/bin/bash", "/usr/local/bin/bash"] {
                    push_bind(&mut argv, "--ro-bind", wrapper, Path::new(dest))?;
                }
            }
            // execSync uses /bin/sh for models.yml `!` commands. That stays
            if let Some(sh) = &profile.real_sh {
                for dest in ["/bin/sh", "/usr/bin/sh"] {
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
                    "/bin/bash".to_owned(),
                ]);
            }
        }
        SandboxSubject::Shell => {
            // Drop the process environment so provider tokens and the worker
            // bus address do not ride into the shell.
            argv.push("--clearenv".to_owned());
            let home = profile
                .writable
                .first()
                .map(|path| path_arg(path))
                .transpose()?
                .unwrap_or_else(|| "/tmp".to_owned());
            argv.extend(["--setenv".to_owned(), "HOME".to_owned(), home.clone()]);
            argv.extend(["--chdir".to_owned(), home]);
            if !profile.shell_path.is_empty() {
                let path = std::env::join_paths(&profile.shell_path)
                    .map_err(|error| format!("shell PATH rejected: {error}"))?
                    .to_string_lossy()
                    .into_owned();
                argv.extend(["--setenv".to_owned(), "PATH".to_owned(), path]);
            }
        }
    }
    if argv.windows(2).any(|pair| pair == ["--bind", "/"]) {
        return Err("seat sandbox argv must not bind the host root".to_owned());
    }
    Ok(argv)
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
fn path_arg(path: &Path) -> Result<String, String> {
    path.to_str()
        .filter(|value| !value.contains('\0'))
        .map(str::to_owned)
        .ok_or_else(|| format!("sandbox path {} is not UTF-8", path.display()))
}

fn resolve_role(entry: &str, capsule: &Path, scratch: &Path) -> Result<PathBuf, String> {
    let path = match entry {
        "capsule" | "checkout" => capsule.to_path_buf(),
        "scratch" => scratch.to_path_buf(),
        other => PathBuf::from(other),
    };
    if !path.is_absolute() {
        return Err(format!(
            "sandbox path {entry:?} did not resolve to an absolute path"
        ));
    }
    Ok(path)
}

fn push_bind(argv: &mut Vec<String>, flag: &str, source: &Path, dest: &Path) -> Result<(), String> {
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
    let bwrap = required_env_path("ODIN_BWRAP")?;
    let bash = required_env_path("ODIN_BASH")?;
    let python = optional_env_path("ODIN_PYTHON3")?;
    let models_file = optional_env_path("ODIN_OMP_MODELS")?;
    let provider_auth = match std::env::var("ODIN_PROVIDER_AUTH") {
        Ok(value) if !value.is_empty() => value
            .split(':')
            .map(|entry| {
                let path = PathBuf::from(entry);
                if !path.is_absolute() || !path.is_file() {
                    Err(format!(
                        "ODIN_PROVIDER_AUTH entry {} is not an absolute file",
                        path.display()
                    ))
                } else {
                    Ok(path)
                }
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => Vec::new(),
    };
    let omp_state = std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| {
            [".omp/run", ".omp/cache", ".omp/logs", ".omp/agent"]
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
    let path_extra = std::env::var("ODIN_PATH_EXTRA")
        .ok()
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .split(':')
                .map(|entry| {
                    let path = PathBuf::from(entry);
                    if !path.is_absolute() || !path.is_dir() {
                        Err(format!(
                            "ODIN_PATH_EXTRA entry {} is not an absolute directory",
                            path.display()
                        ))
                    } else {
                        Ok(path)
                    }
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
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

fn required_env_path(name: &str) -> Result<PathBuf, String> {
    let value = std::env::var(name)
        .map_err(|_| format!("{name} is unset; the seat sandbox has no host binding"))?;
    let path = PathBuf::from(value);
    if !path.is_absolute() || !path.is_file() {
        return Err(format!("{name}={} is not an absolute file", path.display()));
    }
    Ok(path)
}

fn optional_env_path(name: &str) -> Result<Option<PathBuf>, String> {
    match std::env::var(name) {
        Ok(value) if !value.is_empty() => {
            let path = PathBuf::from(value);
            if !path.is_absolute() || !path.exists() {
                return Err(format!(
                    "{name}={} is not an absolute existing path",
                    path.display()
                ));
            }
            Ok(Some(path))
        }
        _ => Ok(None),
    }
}

/// Writes the process bubble argv and, when the seat has a shell, the wrapper
/// the OMP bash tool execs. Sets `ODIN_SEAT_SANDBOX` and `ODIN_SHELL`.
pub fn apply_seat_sandbox(
    process: &mut crate::process::OmpProcessSpec,
    sandbox: &SeatSandboxToml,
    capsule: &Path,
    host: &SeatSandboxHost,
) -> Result<(), String> {
    let home = process
        .explicit_env
        .iter()
        .find(|(name, _)| name == "HOME")
        .map(|(_, value)| PathBuf::from(value))
        .ok_or("sandbox process environment carries no HOME")?;
    let scratch = process.cwd.join("scratch");
    std::fs::create_dir_all(&scratch)
        .map_err(|error| format!("create seat scratch {}: {error}", scratch.display()))?;
    let (writable, readonly) = resolve_sandbox_paths(sandbox, capsule, &scratch)?;
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
        write_argv(&argv_file, SandboxSubject::Shell, &shell_profile)?;
        let script = shell_wrapper_script(&host.bwrap, Path::new("/odin-shell.argv"), &host.bash)?;
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
    write_argv(&argv_file, SandboxSubject::Process, &process_profile)?;
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
    // declared file there is nothing to overlay.
    let models_overlay = host
        .models_file
        .as_ref()
        .map(|source| (source.clone(), home.join(".omp/agent/models.yml")))
        .filter(|(source, dest)| {
            match (std::fs::canonicalize(source), std::fs::canonicalize(dest)) {
                (Ok(source), Ok(dest)) => source != dest,
                _ => true,
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

fn write_argv(
    path: &Path,
    subject: SandboxSubject,
    profile: &SeatSandboxProfile,
) -> Result<(), String> {
    let argv = seat_sandbox_argv(subject, profile)?;
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
            omp_state: vec![PathBuf::from("/home/colin/.omp/run")],
            provider_auth: vec![PathBuf::from(
                "/home/colin/.config/sops-nix/secrets/rendered/litellm-env",
            )],
            models_overlay: Some((
                PathBuf::from("/nix/store/models.yml"),
                PathBuf::from("/home/colin/.omp/agent/models.yml"),
            )),
            shell_wrapper: Some(PathBuf::from("/work/shell-bash")),
            real_sh: Some(PathBuf::from("/nix/store/bash/bin/bash")),
            path_extra: vec![PathBuf::from("/nix/store/coreutils/bin")],
            cwd: PathBuf::from("/work/launch"),
            home: PathBuf::from("/home/colin"),
            shell_argv: Some(PathBuf::from("/work/launch/shell.argv")),
            shell_path: vec![PathBuf::from("/nix/store/bash/bin")],
        }
    }

    #[test]
    fn process_keeps_provider_network_and_shell_does_not_see_it() {
        let profile = profile();
        let process = seat_sandbox_argv(SandboxSubject::Process, &profile).expect("process argv");
        let shell = seat_sandbox_argv(SandboxSubject::Shell, &profile).expect("shell argv");

        assert!(process.iter().any(|arg| arg == "--share-net"));
        assert!(process.iter().any(|arg| arg == "--unshare-all"));
        assert!(process.iter().any(|arg| arg == "--die-with-parent"));
        assert!(process.iter().any(|arg| arg == "--new-session"));
        assert!(process
            .windows(3)
            .any(|window| { window == ["--ro-bind", "/nix/store", "/nix/store"] }));
        assert!(process
            .windows(2)
            .any(|window| window == ["--tmpfs", "/tmp"]));
        assert!(!process.windows(2).any(|window| window == ["--bind", "/"]));
        assert!(!process.iter().any(|arg| arg == "--cap-add"));
        assert!(process.iter().any(|arg| arg.contains("litellm-env")));
        assert!(process.iter().any(|arg| arg == "/home/colin/.omp/run"));
        assert!(process
            .windows(3)
            .any(|window| { window == ["--ro-bind", "/nix/store/bash/bin/bash", "/bin/sh"] }));
        assert!(process
            .windows(3)
            .any(|window| { window == ["--ro-bind", "/work/shell-bash", "/bin/bash"] }));
        assert!(process.windows(3).any(|window| {
            window == ["--ro-bind", "/work/launch/shell.argv", "/odin-shell.argv"]
        }));
        assert!(process.windows(3).any(|window| {
            window
                == [
                    "--ro-bind",
                    "/work/launch/system-prompt.md",
                    "/work/launch/system-prompt.md",
                ]
        }));
        assert!(!shell.iter().any(|arg| arg == "/odin-shell.argv"));
        assert!(!shell.iter().any(|arg| arg == "--share-net"));
        assert!(shell.iter().any(|arg| arg == "--unshare-net"));
        assert!(!process.iter().any(|arg| arg == "--unshare-net"));
        assert!(!shell.iter().any(|arg| arg == "/bin/sh"));
        assert!(!shell.iter().any(|arg| arg == "/nix/store/bash/bin/bash"));

        assert!(shell
            .windows(2)
            .any(|window| window == ["--cap-drop", "ALL"]));
        assert!(shell.iter().any(|arg| arg == "--clearenv"));
        assert!(!shell.iter().any(|arg| arg.contains("litellm-env")));
        assert!(!shell.iter().any(|arg| arg.contains(".omp")));
        assert!(!shell.windows(2).any(|window| window == ["--bind", "/"]));
        assert!(shell.iter().any(|arg| arg == "/work/scratch"));
        assert!(shell
            .windows(3)
            .any(|window| { window == ["--ro-bind", "/work/checkout", "/work/checkout"] }));
    }

    #[test]
    fn shell_host_network_shares_the_host_namespace() {
        let mut profile = profile();
        profile.network = SeatSandboxNetwork::Host;
        let process = seat_sandbox_argv(SandboxSubject::Process, &profile).expect("process");
        let shell = seat_sandbox_argv(SandboxSubject::Shell, &profile).expect("shell");
        assert!(process.iter().any(|arg| arg == "--share-net"));
        assert!(!process.iter().any(|arg| arg == "--unshare-net"));
        assert!(shell.iter().any(|arg| arg == "--share-net"));
        assert!(!shell.iter().any(|arg| arg == "--unshare-net"));
        assert!(shell.iter().any(|arg| arg == "--unshare-all"));
        assert!(!shell.windows(2).any(|window| window == ["--bind", "/"]));
        assert!(!shell.iter().any(|arg| arg.contains("litellm-env")));
    }

    #[test]
    fn process_drops_caps_and_does_not_bind_an_undeclared_cwd() {
        let process = seat_sandbox_argv(SandboxSubject::Process, &profile()).expect("process");
        assert!(process
            .windows(2)
            .any(|window| window == ["--cap-drop", "ALL"]));
        assert!(!process
            .windows(3)
            .any(|window| { window[0] == "--bind" && window[1] == "/work/launch" }));
    }
}
