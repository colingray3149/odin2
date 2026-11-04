//! The argv transports every non-OMP harness launches through: a fleet host
//! runs the agent in a confined transient user unit, an ssh host runs it in
//! its remote workspace through a login shell.

use std::path::{Path, PathBuf};

use odin_registry::DEFAULT_ACCOUNT;

use super::HarnessRoute;

/// The directories a confined unit and odind look for programs in.
pub fn program_path(home: &Path) -> Vec<PathBuf> {
    let user = home
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    vec![
        home.join(".local/state/nix/profile/bin"),
        PathBuf::from(format!("/etc/profiles/per-user/{user}/bin")),
        PathBuf::from("/run/current-system/sw/bin"),
    ]
}

/// [`program_path`] as a `PATH` value.
pub fn path_env(home: &Path) -> String {
    program_path(home)
        .iter()
        .map(|dir| dir.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(":")
}

/// The fleet-host transient unit wrapper: the declared confinement as unit
/// properties (writes only to the workspace and the harness's own state,
/// hidden paths unreadable, optional no-network), stdio piped through.
pub fn fleet_host_argv(
    unit: &str,
    home: &Path,
    workspace: &Path,
    route: &HarnessRoute,
    agent: &[String],
) -> Vec<String> {
    let mut argv: Vec<String> = ["systemd-run", "--user", "--quiet", "--collect", "--pipe"]
        .iter()
        .map(|part| (*part).to_owned())
        .collect();
    argv.push(format!("--unit={unit}"));
    argv.push(format!("--working-directory={}", workspace.display()));
    argv.push(format!("--setenv=HOME={}", home.display()));
    argv.push(format!("--setenv=PATH={}", path_env(home)));
    let sandbox = &route.environment.sandbox;
    let mut property = |value: String| {
        argv.push("-p".to_owned());
        argv.push(value);
    };
    property("NoNewPrivileges=yes".to_owned());
    property("PrivateTmp=yes".to_owned());
    // Removable media (the encrypted vault) is never visible to a fleet unit.
    property("InaccessiblePaths=-/run/media".to_owned());
    property(format!(
        "KillSignal={}",
        route.harness.stop.signal.trim_start_matches("SIG")
    ));
    property(format!(
        "TimeoutStopSec={}",
        route.harness.stop.grace_seconds
    ));
    if sandbox.private_home {
        property("ProtectHome=tmpfs".to_owned());
        property(format!("BindPaths={}", workspace.display()));
        for path in &route.harness.state_paths {
            property(format!("BindPaths=-{}", home.join(path).display()));
        }
        property(format!(
            "BindReadOnlyPaths=-{}",
            home.join(".local/state/nix").display()
        ));
    }
    if sandbox.confine_writes {
        property("ProtectSystem=strict".to_owned());
        if !sandbox.private_home {
            property("ProtectHome=read-only".to_owned());
        }
        property(format!("ReadWritePaths={}", workspace.display()));
        for path in &route.harness.state_paths {
            property(format!("ReadWritePaths=-{}", home.join(path).display()));
        }
    }
    for path in &sandbox.hidden {
        property(format!("InaccessiblePaths=-{}", home.join(path).display()));
    }
    // A private home shows only what is bound into it; a shared one hides every
    // account's login but the session's own.
    if !sandbox.private_home {
        let own = route
            .harness
            .account
            .map(|kind| (kind, route.account.as_deref().unwrap_or(DEFAULT_ACCOUNT)));
        for path in odin_registry::foreign_account_paths(home, own) {
            property(format!("InaccessiblePaths=-{}", home.join(path).display()));
        }
    }
    if sandbox.no_network {
        property("PrivateNetwork=yes".to_owned());
    }
    argv.push("--".to_owned());
    argv.extend(agent.iter().cloned());
    argv
}

/// Ignore user config because sandbox ownership mapping makes linked SSH config unusable.
pub const SSH_OPTIONS: [&str; 6] = [
    "-F",
    "none",
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=10",
];

/// The ssh arguments every Odin host call shares: [`SSH_OPTIONS`], the caller's own `options`
/// (its tty, multiplexing or host-key policy), then `--`, the destination and the remote words.
/// The program is the caller's choice.
pub fn ssh_argv(options: &[&str], destination: &str, remote: &[&str]) -> Vec<String> {
    let mut argv: Vec<String> = SSH_OPTIONS
        .iter()
        .chain(options)
        .map(|word| (*word).to_owned())
        .collect();
    argv.push("--".to_owned());
    argv.push(destination.to_owned());
    argv.extend(remote.iter().map(|word| (*word).to_owned()));
    argv
}

/// `GIT_SSH_COMMAND` for every Git transport Odin runs: the [`ssh_argv`] policy, which Git splits
/// as a shell command.
pub fn git_ssh_command() -> String {
    format!("ssh {}", SSH_OPTIONS.join(" "))
}

/// The ssh-host wrapper: a forced tty so closing the client hangs up the
/// remote process group (the declared stop path), batch mode, the agent run
/// in its remote workspace through a login shell (the user's PATH).
pub fn ssh_host_argv(
    destination: &str,
    workspace: &Path,
    agent: &[String],
    tty: bool,
) -> Vec<String> {
    let remote = format!(
        "cd {} && exec {}",
        odin_process::shell_quote(&workspace.display().to_string()),
        agent
            .iter()
            .map(|word| odin_process::shell_quote(word))
            .collect::<Vec<_>>()
            .join(" ")
    );
    let command = format!("bash -lc {}", odin_process::shell_quote(&remote));
    let mut argv = vec!["ssh".to_owned()];
    argv.extend(ssh_argv(
        &[if tty { "-tt" } else { "-T" }],
        destination,
        &[command.as_str()],
    ));
    argv
}

#[cfg(test)]
mod tests {
    use super::{ssh_argv, ssh_host_argv};

    #[test]
    fn ssh_argv_keeps_the_fleet_policy_and_its_options_before_the_destination() {
        let argv = ssh_argv(&["-T"], "pc", &["odin", "feature-probe"]);
        let end = argv
            .iter()
            .position(|word| word == "--")
            .expect("a -- before the destination");
        assert!(argv[..end].windows(2).any(|pair| pair == ["-F", "none"]));
        assert!(argv[..end].contains(&"-T".to_owned()));
        assert_eq!(&argv[end + 1..], ["pc", "odin", "feature-probe"]);
    }

    /// The remote command runs the agent in a workspace with a space in its path with an argument
    /// holding a quote, and the tty switch picks the hang-up (`-tt`) or protocol-safe (`-T`) client.
    #[test]
    fn the_ssh_host_command_runs_the_agent_in_its_workspace() {
        let root = tempfile::tempdir().expect("root");
        let workspace = root.path().join("a b");
        std::fs::create_dir(&workspace).expect("workspace");
        let agent = root.path().join("agent");
        std::fs::write(&agent, "#!/bin/sh\nprintf '%s|%s' \"$PWD\" \"$1\"\n").expect("agent");
        std::fs::set_permissions(&agent, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .expect("executable");
        let words = vec![agent.display().to_string(), "it's".to_owned()];

        let tty = ssh_host_argv("pc", &workspace, &words, true);
        assert!(tty.contains(&"-tt".to_owned()) && !tty.contains(&"-T".to_owned()));
        assert!(ssh_host_argv("pc", &workspace, &words, false).contains(&"-T".to_owned()));

        let remote = tty.last().expect("the remote command");
        let output = std::process::Command::new("sh")
            .args(["-c", remote])
            .output()
            .expect("sh runs the remote command");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            format!("{}|it's", workspace.display())
        );
    }
}
