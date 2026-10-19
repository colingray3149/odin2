//! The argv transports every non-OMP harness launches through: a fleet host
//! runs the agent in a confined transient user unit, an ssh host runs it in
//! its remote workspace through a login shell.

use std::path::Path;

use odin_registry::DEFAULT_ACCOUNT;

use super::HarnessRoute;

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
    argv.push(format!(
        "--setenv=PATH={}/bin:/etc/profiles/per-user/{}/bin:/run/current-system/sw/bin",
        home.join(".local/state/nix/profile").display(),
        home.file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
    ));
    let sandbox = &route.environment.sandbox;
    let mut property = |value: String| {
        argv.push("-p".to_owned());
        argv.push(value);
    };
    property("NoNewPrivileges=yes".to_owned());
    property("PrivateTmp=yes".to_owned());
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

/// POSIX single-quote one word for a remote shell.
fn shell_quote(word: &str) -> String {
    format!("'{}'", word.replace('\'', "'\\''"))
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
        shell_quote(&workspace.display().to_string()),
        agent
            .iter()
            .map(|word| shell_quote(word))
            .collect::<Vec<_>>()
            .join(" ")
    );
    let mut argv = vec!["ssh".to_owned(), if tty { "-tt" } else { "-T" }.to_owned()];
    argv.extend(SSH_OPTIONS.iter().map(|option| (*option).to_owned()));
    argv.extend([
        destination.to_owned(),
        "--".to_owned(),
        format!("bash -lc {}", shell_quote(&remote)),
    ]);
    argv
}
