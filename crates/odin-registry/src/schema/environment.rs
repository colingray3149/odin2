//! Derive confinement from transport and sandbox settings so declarations cannot overstate isolation.

use odin_domain::SeatId;
use serde::{Deserialize, Serialize};

use super::object::RegistryKind;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentToml {
    pub schema: String,
    pub kind: RegistryKind,
    pub enabled: bool,
    pub description: String,
    pub transport: EnvironmentTransport,
    /// Fleet host ID, SSH destination, or transcript host; absent for k3s-pod.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Credential handle such as a secret name, never its value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
    pub seats: Vec<SeatId>,
    pub observation: EnvironmentObservationToml,
    #[serde(default)]
    pub sandbox: EnvironmentSandboxToml,
    /// Evaluate watchdogs without running a model while the stream is quiet.
    #[serde(default, rename = "watchdog", skip_serializing_if = "Vec::is_empty")]
    pub watchdogs: Vec<EnvironmentWatchdogToml>,
    /// Only k3s-pod environments declare pod access; omit absent settings to preserve snapshot hashes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod: Option<EnvironmentPodToml>,
    /// Session clone origin points to this read-only git mirror; only fleet-host and k3s-pod declare it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_mirror: Option<String>,
}

pub const GIT_MIRROR_PORT: u16 = 9418;

/// Empty egress and account lists grant no access.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentPodToml {
    /// Allow HTTPS to these hosts; DNS and the node kernel bridge are configured separately.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_hosts: Vec<String>,
    /// Admit only listed account kinds before creating a pod; their credentials are mounted read-write.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accounts: Vec<super::AccountKind>,
}

/// Choose exactly one trigger: matching output or silence while a turn is active.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentWatchdogToml {
    pub name: String,
    #[serde(default, rename = "match", skip_serializing_if = "Option::is_none")]
    pub matches: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub silent_seconds: Option<u32>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnvironmentTransport {
    K3sPod,
    FleetHost,
    SshHost,
    /// Observe only: Odin did not start this workspace.
    RemoteSession,
}

impl EnvironmentTransport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::K3sPod => "k3s-pod",
            Self::FleetHost => "fleet-host",
            Self::SshHost => "ssh-host",
            Self::RemoteSession => "remote-session",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentObservationToml {
    pub channel: ObservationChannel,
    /// Follow this file or the newest file in this directory; tilde refers to the observed host's home.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Required for followed files; harness-run environments use the harness output format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ObservationChannel {
    Events,
    Transcript,
    Log,
}

/// Reject confinement settings when the transport does not start work.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentSandboxToml {
    /// Restrict writes to the workspace and declared harness state paths.
    #[serde(default)]
    pub confine_writes: bool,
    /// Deny reads below these home-relative paths, including credentials and private state.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hidden: Vec<String>,
    /// Cut the network (loopback only).
    #[serde(default)]
    pub no_network: bool,
    /// Expose only workspace, harness state, and Nix profile; omit false to preserve snapshot hashes.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub private_home: bool,
}

/// Report enforced confinement and its limits.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EnvironmentPosture {
    pub can_start: bool,
    pub can_stop: bool,
    pub enforced: Vec<String>,
    pub not_enforced: Vec<String>,
}

impl EnvironmentToml {
    pub fn starts_work(&self) -> bool {
        self.transport != EnvironmentTransport::RemoteSession
    }

    /// Derive posture from transport and sandbox settings, not descriptive prose.
    pub fn posture(&self) -> EnvironmentPosture {
        let mut enforced = Vec::new();
        let mut not_enforced = Vec::new();
        match self.transport {
            EnvironmentTransport::K3sPod => {
                enforced.push(
                    "the pod's image filesystem, its declared egress hosts and resource limits"
                        .to_owned(),
                );
                match self.pod.as_ref().map(|pod| pod.accounts.as_slice()) {
                    Some(accounts) if !accounts.is_empty() => not_enforced.push(format!(
                        "the account login it carries, usable by the agent as it likes: {}",
                        accounts
                            .iter()
                            .map(|kind| kind.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )),
                    _ => enforced.push("no credential rides into it".to_owned()),
                }
            }
            EnvironmentTransport::FleetHost => {
                enforced
                    .push("a transient user unit Odin stops (process tree included)".to_owned());
                if self.sandbox.confine_writes {
                    enforced.push(
                        "writes confined to the session workspace and the harness's own state"
                            .to_owned(),
                    );
                } else {
                    not_enforced.push("writes anywhere the user can write".to_owned());
                }
                if self.sandbox.hidden.is_empty() {
                    not_enforced.push("reads anywhere the user can read".to_owned());
                } else {
                    enforced.push(format!(
                        "hidden from it: {}",
                        self.sandbox.hidden.join(", ")
                    ));
                }
                if self.sandbox.no_network {
                    enforced.push("no network".to_owned());
                } else {
                    not_enforced.push("network egress".to_owned());
                }
            }
            EnvironmentTransport::SshHost => {
                not_enforced.push(
                    "filesystem and network on the remote machine: the agent runs as the ssh \
                     user with that user's full rights"
                        .to_owned(),
                );
                not_enforced.push(
                    "whether closing the ssh client ended the remote process group: Odin does \
                     not observe that"
                        .to_owned(),
                );
            }
            EnvironmentTransport::RemoteSession => {
                not_enforced.push(
                    "everything: Odin did not start this agent, cannot confine or stop it, and \
                     only reads its transcript"
                        .to_owned(),
                );
            }
        }
        EnvironmentPosture {
            can_start: self.starts_work(),
            can_stop: self.starts_work(),
            enforced,
            not_enforced,
        }
    }

    pub fn check(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let host_required = !matches!(self.transport, EnvironmentTransport::K3sPod);
        match (&self.host, host_required) {
            (None, true) => problems.push(format!(
                "a {} environment names its host",
                self.transport.as_str()
            )),
            (Some(_), false) => problems.push("a k3s-pod environment names no host".to_owned()),
            (Some(host), true)
                if host.is_empty()
                    || host.starts_with('-')
                    || host.chars().any(|c| c.is_whitespace() || c == '\0') =>
            {
                problems.push(format!("host {host:?} is not a host id or ssh destination"))
            }
            _ => {}
        }
        if self.seats.is_empty() {
            problems.push("seats names at least one seat".to_owned());
        }
        let followed = matches!(
            self.observation.channel,
            ObservationChannel::Transcript | ObservationChannel::Log
        );
        if followed != self.observation.path.is_some() {
            problems.push(
                "observation.path is declared exactly for a transcript or log channel".to_owned(),
            );
        }
        if followed && self.observation.format.is_none() {
            problems.push("a followed transcript or log declares observation.format".to_owned());
        }
        if self.transport == EnvironmentTransport::RemoteSession {
            if !followed {
                problems.push(
                    "a remote session is observed through its transcript or log (Odin did not \
                     start it, so it has no event stream)"
                        .to_owned(),
                );
            }
            if self.sandbox != EnvironmentSandboxToml::default() {
                problems.push(
                    "a remote session declares no sandbox: Odin cannot confine what it did not \
                     start"
                        .to_owned(),
                );
            }
        }
        if self.transport == EnvironmentTransport::SshHost
            && self.sandbox != EnvironmentSandboxToml::default()
        {
            problems.push(
                "an ssh-host environment declares no sandbox: Odin cannot confine a process on \
                 another machine's account"
                    .to_owned(),
            );
        }
        for watchdog in &self.watchdogs {
            if !super::validation::valid_id(&watchdog.name) {
                problems.push(format!("watchdog name {:?} is not an id", watchdog.name));
            }
            match (&watchdog.matches, watchdog.silent_seconds) {
                (Some(text), None) if !text.trim().is_empty() && text.len() <= 200 => {}
                (None, Some(30..=86_400)) => {}
                _ => problems.push(format!(
                    "watchdog {} declares exactly one of match (1..=200 chars) or \
                     silent_seconds (30..=86400)",
                    watchdog.name
                )),
            }
        }
        if let Some(pod) = &self.pod {
            if self.transport != EnvironmentTransport::K3sPod {
                problems.push("only a k3s-pod environment declares [pod]".to_owned());
            }
            for host in &pod.allow_hosts {
                if !super::valid_allow_host(host) {
                    problems.push(format!("pod.allow_hosts {host:?} is not a host name"));
                }
            }
        }
        if let Some(mirror) = &self.git_mirror {
            if !matches!(
                self.transport,
                EnvironmentTransport::FleetHost | EnvironmentTransport::K3sPod
            ) {
                problems.push(format!(
                    "only a fleet-host or k3s-pod environment declares git_mirror, not a {}",
                    self.transport.as_str()
                ));
            }
            if !super::valid_allow_host(mirror) && mirror.parse::<std::net::Ipv4Addr>().is_err() {
                problems.push(format!(
                    "git_mirror {mirror:?} is not a host name or IPv4 address"
                ));
            }
        }
        for path in &self.sandbox.hidden {
            if path.is_empty() || path.starts_with('/') || path.split('/').any(|part| part == "..")
            {
                problems.push(format!(
                    "hidden path {path:?} must be relative to $HOME without '..'"
                ));
            }
        }
        problems
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pod_authority() -> EnvironmentToml {
        toml::from_str(include_str!(
            "../../../../registry/environments/pod-authority/environment.toml"
        ))
        .expect("pod-authority parses")
    }

    /// Pod settings declare egress and account kinds; absent settings are omitted from serialization.
    #[test]
    fn the_pod_environment_declares_egress_and_the_claude_code_account() {
        let pod = pod_authority();
        assert!(pod.check().is_empty(), "{:?}", pod.check());
        let declared = pod.pod.as_ref().expect("[pod]");
        // The API carries model/Remote Control traffic; the platform host
        // refreshes the selected subscription account's OAuth token.
        assert_eq!(
            declared.allow_hosts,
            ["api.anthropic.com", "platform.claude.com"]
        );
        assert_eq!(declared.accounts, [super::super::AccountKind::ClaudeCode]);
        assert!(pod.posture().not_enforced.iter().any(|fact| fact
            == "the account login it carries, usable by the agent as it likes: claude-code"));
        let encoded = serde_json::to_value(&pod).expect("encode");
        assert_eq!(encoded["pod"]["accounts"][0], "claude-code");
        let fleet: EnvironmentToml = toml::from_str(include_str!(
            "../../../../registry/environments/sandbox-authority/environment.toml"
        ))
        .expect("sandbox-authority");
        assert!(serde_json::to_value(&fleet)
            .expect("encode")
            .get("pod")
            .is_none());
    }

    #[test]
    fn pod_declarations_are_confined_to_pods_and_hosts() {
        let mut pod = pod_authority();
        pod.pod.as_mut().expect("pod").accounts.clear();
        assert!(pod
            .posture()
            .enforced
            .iter()
            .any(|fact| fact == "no credential rides into it"));
        pod.pod.as_mut().expect("pod").allow_hosts = vec!["not a host".to_owned()];
        assert!(!pod.check().is_empty());
        let mut fleet: EnvironmentToml = toml::from_str(include_str!(
            "../../../../registry/environments/sandbox-authority/environment.toml"
        ))
        .expect("sandbox-authority");
        fleet.pod = Some(EnvironmentPodToml::default());
        assert!(fleet
            .check()
            .iter()
            .any(|problem| problem.contains("only a k3s-pod")));
    }

    #[test]
    fn a_git_mirror_is_declared_only_where_odin_starts_local_work() {
        let mut pod = pod_authority();
        assert_eq!(pod.git_mirror.as_deref(), Some("10.77.0.11"));
        pod.git_mirror = Some("not a host".to_owned());
        assert!(pod
            .check()
            .iter()
            .any(|problem| problem.contains("git_mirror \"not a host\"")));
        let mut laptop: EnvironmentToml = toml::from_str(include_str!(
            "../../../../registry/environments/laptop-ssh/environment.toml"
        ))
        .expect("laptop-ssh parses");
        assert!(serde_json::to_value(&laptop)
            .expect("encode")
            .get("git_mirror")
            .is_none());
        laptop.git_mirror = Some("10.77.0.11".to_owned());
        assert!(laptop
            .check()
            .iter()
            .any(|problem| problem.contains("only a fleet-host or k3s-pod")));
    }

    /// An environment that does not declare `private_home` serializes
    /// without it, so snapshots published before the field keep their hash.
    #[test]
    fn an_undeclared_private_home_is_not_serialized() {
        let sandbox: EnvironmentSandboxToml =
            toml::from_str("confine_writes = true").expect("sandbox parses");
        let json = serde_json::to_string(&sandbox).expect("serializes");
        assert!(!json.contains("private_home"), "{json}");
        let private: EnvironmentSandboxToml =
            toml::from_str("private_home = true").expect("sandbox parses");
        assert!(serde_json::to_string(&private)
            .expect("serializes")
            .contains("\"private_home\":true"));
    }
}
