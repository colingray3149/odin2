//! A machine Odin runs script work on without a Job: an HPC login (Slurm), a lab box or a
//! container rental reached over ssh. Read live: a changed limit applies to the next poll and
//! the next launch, with no restart.

use std::collections::BTreeSet;
use std::num::NonZeroU32;

use serde::{Deserialize, Serialize};

use super::RegistryKind;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComputeTargetToml {
    pub schema: String,
    pub kind: RegistryKind,
    pub enabled: bool,
    pub description: String,
    pub executor: ComputeExecutor,
    /// The host ssh connects to (an alias of the declared ssh config, or a name or address).
    pub ssh_host: String,
    /// SSH server port; absent uses the standard SSH port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_port: Option<std::num::NonZeroU16>,
    /// Absolute path of the private key ssh offers this target (a rendered sops secret, never
    /// the fleet key); absent, ssh offers its default identities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_file: Option<String>,
    /// The target's host key, `<type> <base64>`; ssh refuses any other.
    pub known_host: String,
    /// Absolute directory on the target holding one folder per run.
    pub remote_root: String,
    pub runtime: OffloadRuntime,
    /// The image a container runtime runs (a SIF path or an OCI reference); absent uses the
    /// profile's image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Runs in flight on this target at once; more wait in the launch queue.
    pub max_concurrent: NonZeroU32,
    /// Seconds between status reads of each run.
    pub poll_seconds: NonZeroU32,
    /// Seconds a stopped run has between TERM and KILL.
    pub stop_grace_seconds: NonZeroU32,
    /// Seconds one remote command (submit, status read, stop) may take; absent: 120.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_timeout_seconds: Option<NonZeroU32>,
    /// Seconds staging a run's inputs or copying its export home may take; absent: 1200.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copy_timeout_seconds: Option<NonZeroU32>,
    /// Log lines read per status poll; absent: 400.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_tail_lines: Option<NonZeroU32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_core_hours_per_run: Option<NonZeroU32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partition: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub gpus: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<ComputeTargetCost>,
    /// Projects whose profiles may run here; empty admits none.
    pub allowed_projects: BTreeSet<String>,
    /// Whether restricted data may be staged here.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub restricted_data: bool,
    /// An ssh ControlMaster socket for a login that needs interactive MFA. Without a live
    /// master the target is unavailable and no run is lost.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_master: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ComputeExecutor {
    /// A plain box: each run is a transient `systemd-run --user` unit.
    Ssh,
    /// An HPC login: each run is an `sbatch` job.
    Slurm,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OffloadRuntime {
    /// The command runs directly on the target.
    Host,
    Podman,
    Apptainer,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComputeTargetCost {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usd_per_core_hour: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usd_per_hour: Option<f64>,
}

impl ComputeTargetToml {
    pub fn ssh_port(&self) -> u16 {
        self.ssh_port.map_or(22, std::num::NonZeroU16::get)
    }

    pub fn command_timeout(&self) -> std::time::Duration {
        seconds(self.command_timeout_seconds, 120)
    }

    pub fn copy_timeout(&self) -> std::time::Duration {
        seconds(self.copy_timeout_seconds, 1200)
    }

    pub fn log_tail_lines(&self) -> u32 {
        self.log_tail_lines.map_or(400, NonZeroU32::get)
    }
}

fn seconds(declared: Option<NonZeroU32>, fallback: u64) -> std::time::Duration {
    std::time::Duration::from_secs(declared.map_or(fallback, |value| u64::from(value.get())))
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}
