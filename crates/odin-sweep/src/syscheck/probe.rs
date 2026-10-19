use super::*;

mod bounded;
mod config;
mod facts;
mod manifest;
mod observe;
mod sessions;
mod systemd;
mod vcs;

pub(in crate::syscheck) use bounded::command_problem;
pub(crate) use bounded::{run_bounded, trimmed_stdout, BoundedOutput};
#[cfg(test)]
pub(in crate::syscheck) use config::decimal_budget_ok;
pub(in crate::syscheck) use config::{
    decimal_budget_units, gateway_answers_as_litellm, model_endpoint, odin_discord_declared,
    parse_yaml_file, yaml_json_scalar_equal, yaml_model_names, zellij_declared_endpoint,
};

#[cfg(test)]
pub(in crate::syscheck) use facts::load_host_facts_from;
pub(in crate::syscheck) use facts::{
    load_host_facts, Bootloader, GatewayRelayFacts, HostFacts, ZellijWebFacts,
};
pub(in crate::syscheck) use manifest::{
    command_scratch, flake_locked_revision, nix_store_root, package_build_metadata_path,
    read_bounded, require_config, require_manifest, require_tool, verify_manifest_executable,
    verify_store_artifact,
};
pub(in crate::syscheck) use observe::{
    endpoint_host_port, host_allowed, is_loopback_host, is_safe_identifier, is_wildcard_host,
    listener_inventory, lower_hex, parse_last_u64, path_has_component, system_generation_links,
    walk_entries,
};
#[cfg(test)]
pub(in crate::syscheck) use observe::{listener_owner_pid, parse_listener_endpoint};
pub(in crate::syscheck) use sessions::{
    leftover_captures, live_journal_root, session_capture_entries, terminal_capture_root,
};
pub(in crate::syscheck) use systemd::{unit_active, ManagerScope, UnitStateReader};
pub(in crate::syscheck) use vcs::{
    find_stray_dotenv, git_head, git_show, git_tracked_paths, gitignore_missing_rules,
    is_credential_shaped_path, is_log_or_jsonl_path, is_store_source, store_source_tracked_paths,
    tracked_hygiene_violation, tracked_inventory,
};

/// One real LISTEN socket observed in the `ss` inventory.
#[derive(Debug)]
pub(super) struct SocketObservation {
    pub(super) address: String,
    pub(super) port: u16,
    pub(super) owner_pid: Option<u32>,
    pub(super) owner_name: Option<String>,
}

/// The zellij web endpoint the host declares: the zellij-web user unit's
/// listener, read from the declared host facts or from the tracked
/// dotfiles declaration. The endpoint stays required even when the server
/// is declared off: the declared port must remain known so the listener
/// checks can detect drift against it.
#[derive(Debug)]
pub(super) struct ZellijWebDeclaration {
    pub(super) enabled: bool,
    pub(super) endpoint: (String, u16),
}

/// Deny-unknown typed view of the retained package-build identity file.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PackageBuildMetadata {
    pub(super) schema: String,
    pub(super) repository: String,
    pub(super) revision: String,
    pub(super) cargo_package: String,
    pub(super) executables: BTreeMap<String, InstalledExecutable>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InstalledExecutable {
    pub(super) path: PathBuf,
    pub(super) blake3: String,
    #[serde(default)]
    pub(super) payload: Option<PayloadBinding>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PayloadBinding {
    pub(super) path: PathBuf,
    pub(super) blake3: String,
}
