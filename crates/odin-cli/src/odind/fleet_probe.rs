//! The production fleet zellij-session probe: one bounded, non-mutating
//! `ssh <tailscale-name> zellij list-sessions -n` per declared host.
//!
//! The host name is the declared tailscale name from the registry — never a
//! hardcoded host. The child is spawned as a bare argv array (no shell), is
//! killed with the timed-out future (`kill_on_drop`), and every failure —
//! non-zero exit, timeout, or an unusable listing — resolves to the typed
//! [`ZellijSessions::Unreachable`]. The one carve-out: zellij's exact
//! "No active zellij sessions found" non-zero exit is a REACHABLE host with
//! zero live sessions, resolved [`ZellijSessions::Live`] with no names. The
//! probe lists sessions only: it never attaches to, creates, or kills one,
//! and no production state is mutated.

use std::time::Duration;

use odin_huginn::fleet::{FleetZellijProbe, ZellijSessions};

/// The wall-clock ceiling of one zellij session probe. The ssh child is
/// spawned with `kill_on_drop`, so a timed-out probe kills its child and
/// resolves typed instead of hanging the pass.
pub(super) const ZELLIJ_PROBE_TIMEOUT: Duration = Duration::from_secs(8);

pub(super) struct SshZellijProbe;

/// Extracts the session names from one `zellij list-sessions -n` listing:
/// the first whitespace-delimited token of every non-empty line (the
/// session name; the rest of each line is the creation stamp). No tokens
/// at all is not an empty-live reading — it is an unusable answer, and the
/// caller resolves it typed.
fn session_names(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Only zellij's exact no-sessions marker means a reachable host with zero sessions.
fn classify(success: bool, stdout: &str, stderr: &str) -> ZellijSessions {
    if success {
        let names = session_names(stdout);
        // A successful exit that names no session is an unusable answer (a
        // dead daemon socket, a truncated transport), not proof of a live
        // zellij with zero sessions.
        return if names.is_empty() {
            ZellijSessions::Unreachable
        } else {
            ZellijSessions::Live(names)
        };
    }
    // zellij exits non-zero WITH this exact marker when the host is
    // reachable and simply has no live sessions (verified against the
    // zellij 0.45 binary: `No active zellij sessions found.`) — that is a
    // live reading of zero, not an offline host. Every other non-zero exit
    // (ssh refusal, timeout, dead socket) is unusable.
    let typed_empty = stderr.contains("No active zellij sessions found");
    if typed_empty {
        ZellijSessions::Live(Vec::new())
    } else {
        ZellijSessions::Unreachable
    }
}

/// Shared SSH options bypass the store-backed config's sandbox ownership checks;
/// argv lists sessions without a shell or attachment.
pub(super) fn probe_args(host_tailnet: &str) -> Vec<&str> {
    let mut args: Vec<&str> = odin_omp::live::harness::SSH_OPTIONS.to_vec();
    args.extend([host_tailnet, "zellij", "list-sessions", "-n"]);
    args
}

#[async_trait::async_trait]
impl FleetZellijProbe for SshZellijProbe {
    async fn sessions(&self, host_tailnet: &str) -> ZellijSessions {
        let observed = tokio::time::timeout(
            ZELLIJ_PROBE_TIMEOUT,
            tokio::process::Command::new("ssh")
                .args(probe_args(host_tailnet))
                .stdin(std::process::Stdio::null())
                .kill_on_drop(true)
                .output(),
        )
        .await;
        match observed {
            Ok(Ok(output)) => {
                let stdout = std::str::from_utf8(&output.stdout).unwrap_or_default();
                let stderr = std::str::from_utf8(&output.stderr).unwrap_or_default();
                classify(output.status.success(), stdout, stderr)
            }
            _ => ZellijSessions::Unreachable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{classify, session_names, ZELLIJ_PROBE_TIMEOUT};
    use odin_huginn::fleet::{FleetZellijProbe, ZellijSessions};
    use std::time::Instant;

    #[test]
    fn classify_separates_zero_sessions_from_offline() {
        // zellij's exact no-sessions marker on a non-zero exit is a
        // reachable host with zero live sessions — never Unreachable.
        assert_eq!(
            classify(false, "", "Error: No active zellij sessions found.\n"),
            ZellijSessions::Live(Vec::new())
        );
        // Any other non-zero exit (ssh refusal, dead socket) is offline.
        assert_eq!(
            classify(
                false,
                "",
                "ssh: connect to host mini port 22: Connection refused"
            ),
            ZellijSessions::Unreachable
        );
        // A successful listing is its live names.
        assert_eq!(
            classify(true, "odin [Created 2h ago]\n", ""),
            ZellijSessions::Live(vec!["odin".to_owned()])
        );
        // A successful exit naming nothing is unusable, not zero-live.
        assert_eq!(classify(true, "", ""), ZellijSessions::Unreachable);
    }

    #[test]
    fn session_names_take_the_first_whitespace_token_of_every_line() {
        let listing = "odin [Created 2h 48m 21s ago]\nscratch [Created 5m ago]\n\n";
        assert_eq!(
            session_names(listing),
            vec!["odin".to_owned(), "scratch".to_owned()]
        );
        assert!(session_names("").is_empty());
        assert!(session_names("   \n\t\n").is_empty());
    }

    #[test]
    fn the_probe_ignores_the_user_ssh_config() {
        let args = super::probe_args("laptop");
        assert!(
            args.windows(2).any(|pair| pair == ["-F", "none"]),
            "{args:?}"
        );
        assert_eq!(
            &args[args.len() - 4..],
            ["laptop", "zellij", "list-sessions", "-n"]
        );
    }

    #[tokio::test]
    async fn loopback_ssh_argv_failure_resolves_unreachable_within_the_bound() {
        // `ssh` to the loopback resolver port with a null-configured,
        // batch-style invocation cannot succeed here, but the exact
        // production argv shape is exercised: the probe must resolve
        // typed well inside the timeout, never hang, and never leave a
        // child behind (kill_on_drop).
        let started = Instant::now();
        let probe = super::SshZellijProbe;
        let outcome = probe.sessions("127.0.0.1").await;
        assert!(
            started.elapsed() < ZELLIJ_PROBE_TIMEOUT,
            "the probe resolved inside its bound"
        );
        assert_eq!(outcome, ZellijSessions::Unreachable);
    }
}
