#![forbid(unsafe_code)]
#![deny(dead_code)]

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use clap::Parser as _;
use odin_cli::live_authority;
use std::process::ExitCode;

mod controller;
mod huginn_conformance;
mod kube_runtime;
#[cfg(test)]
#[path = "test_support.rs"]
mod test_support;

#[path = "odind/adapter.rs"]
mod adapter;
#[path = "odind/archive.rs"]
mod archive;
#[path = "odind/authority.rs"]
mod authority;
#[cfg(test)]
#[path = "authority_provision/fixture.rs"]
mod authority_fixture;
#[path = "odind/browser.rs"]
mod browser;
#[path = "odind/browser_relay_cli.rs"]
mod browser_relay_cli;
#[path = "odind/child_report.rs"]
mod child_report;
#[path = "odind/claude_host.rs"]
mod claude_host;
#[path = "odind/claude_host_transport.rs"]
mod claude_host_transport;
#[path = "odind/claude_pod_backend.rs"]
mod claude_pod_backend;
#[path = "odind/claude_protocol.rs"]
mod claude_protocol;
#[path = "odind/claude_sessions.rs"]
mod claude_sessions;
#[path = "odind/coding_route.rs"]
mod coding_route;
#[path = "odind/composition.rs"]
mod composition;
#[path = "odind/conversation_surface.rs"]
mod conversation_surface;
#[path = "odind/credentials.rs"]
mod credentials;
#[path = "odind/delivery.rs"]
mod delivery;
#[path = "odind/device_admin.rs"]
mod device_admin;
#[cfg(test)]
#[path = "odind/tests/device_admin.rs"]
mod device_admin_tests;
#[path = "odind/device_open.rs"]
mod device_open;
#[path = "odind/emergency_stop.rs"]
mod emergency_stop;
#[path = "odind/entry.rs"]
mod entry;
#[path = "odind/fleet_probe.rs"]
mod fleet_probe;
#[path = "odind/fleet_workloads.rs"]
mod fleet_workloads;
#[cfg(test)]
#[path = "odind/tests/follower.rs"]
mod follower_tests;
#[path = "odind/harness.rs"]
mod harness;
#[path = "odind/hermes.rs"]
mod hermes;
#[path = "odind/huginn_spend.rs"]
mod huginn_spend;
#[path = "odind/incidents.rs"]
mod incidents;
#[path = "odind/kernel_mcp.rs"]
mod kernel_mcp;
#[path = "odind/knowledge_vault.rs"]
mod knowledge_vault;
#[path = "odind/kube.rs"]
mod kube;
#[path = "odind/lane_command.rs"]
mod lane_command;
#[path = "odind/learning.rs"]
mod learning;
#[path = "odind/live.rs"]
mod live;
#[cfg(test)]
#[path = "odind/tests/mismatch_recovery.rs"]
mod mismatch_recovery_tests;
#[path = "odind/project_authoring.rs"]
mod project_authoring;
#[path = "odind/projection.rs"]
mod projection;
#[path = "odind/pumps.rs"]
mod pumps;
#[path = "odind/registry_authoring.rs"]
mod registry_authoring;
#[path = "odind/retention.rs"]
mod retention;
#[path = "odind/ring_gesture.rs"]
mod ring_gesture;
#[path = "odind/routine_authoring.rs"]
mod routine_authoring;
#[path = "odind/simulation.rs"]
mod simulation;
#[path = "odind/state_knowledge.rs"]
mod state_knowledge;
#[cfg(test)]
#[path = "odind/test_fixture.rs"]
mod test_fixture;
#[cfg(test)]
#[path = "odind/test_vault.rs"]
pub(crate) mod test_vault;
#[cfg(test)]
#[path = "odind/tests/wedge_escape.rs"]
mod wedge_escape_tests;
#[path = "odind/workload_authoring.rs"]
mod workload_authoring;
#[path = "odind/workload_exec.rs"]
mod workload_exec;
#[path = "odind/workload_park.rs"]
mod workload_park;

use crate::entry::{run, Cli};
use crate::kube::{KubeLaunchBinding, KubeRuntimeCell};

fn main() -> ExitCode {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .compact()
        .with_writer(std::io::stderr)
        .init();
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!("{error}");
            ExitCode::FAILURE
        }
    }
}
