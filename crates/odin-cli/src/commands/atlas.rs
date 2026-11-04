use std::io::Write;
use std::path::{Path, PathBuf};

use clap::Args;
use odin_domain::LaneId;
use odin_kernel::{provider_status_snapshot, ProviderStatusSnapshot};
use odin_ledger::Ledger;
use odin_registry::RegistryKind;
use time::OffsetDateTime;

use super::load_registry_objects;
use super::output::provider_stamp;
use crate::RunStatus;

#[derive(Debug, Args)]
pub(crate) struct ProvidersArgs {
    #[arg(long, value_name = "PATH")]
    pub(crate) state_root: PathBuf,
    /// Restrict the report to one registry lane.
    #[arg(long, value_name = "ID")]
    pub(crate) lane: Option<String>,
    /// Emit the shared provider status model as JSON.
    #[arg(long)]
    pub(crate) json: bool,
}

pub(crate) fn providers(
    arguments: ProvidersArgs,
    registry_root: &Path,
    output: &mut impl Write,
) -> Result<RunStatus, String> {
    let objects = load_registry_objects(registry_root)?;
    let lane = arguments
        .lane
        .as_deref()
        .map(|id| {
            match objects
                .iter()
                .find(|object| object.kind() == RegistryKind::Lane && object.id == id)
            {
                None => return Err(format!("unknown lane {id:?} in the registry")),
                Some(object) if !object.enabled() => {
                    return Err(format!("lane {id:?} is disabled"));
                }
                Some(_) => {}
            }
            LaneId::new(id).map_err(|error| format!("invalid lane {id:?}: {error}"))
        })
        .transpose()?;

    let ledger_path = arguments.state_root.join("ledger.sqlite3");
    let ledger = Ledger::open(&ledger_path)
        .map_err(|error| format!("could not open ledger {}: {error}", ledger_path.display()))?;
    let snapshot =
        provider_status_snapshot(&ledger, &objects, OffsetDateTime::now_utc(), lane.as_ref())
            .map_err(|error| format!("could not build provider status: {error}"))?;
    if arguments.json {
        serde_json::to_writer(&mut *output, &snapshot)
            .map_err(|error| format!("could not serialize provider status: {error}"))?;
        writeln!(output).map_err(|error| format!("could not write provider status: {error}"))?;
    } else {
        write_provider_status(output, &snapshot)?;
    }
    Ok(RunStatus::Success)
}

fn write_provider_status(
    output: &mut impl Write,
    snapshot: &ProviderStatusSnapshot,
) -> Result<(), String> {
    let providers = snapshot
        .providers
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    writeln!(output, "providers {providers}")
        .map_err(|error| format!("could not write provider status: {error}"))?;
    if snapshot.lanes.is_empty() {
        writeln!(output, "no provider leases")
            .map_err(|error| format!("could not write provider status: {error}"))?;
        return Ok(());
    }

    for lane in &snapshot.lanes {
        writeln!(output, "lane {}", lane.lane)
            .map_err(|error| format!("could not write provider status: {error}"))?;
        match &lane.active {
            Some(active) => writeln!(
                output,
                "  active {} revision {} provider {} account {} model {}",
                active.lease_id,
                active.revision,
                active.provider,
                active.account_handle,
                active.model
            ),
            None => writeln!(output, "  active none"),
        }
        .map_err(|error| format!("could not write provider status: {error}"))?;

        for lease in &lane.lineage {
            writeln!(
                output,
                "  lease {} revision {} provider {} account {} model {} role {} affinity {}",
                lease.lease_id,
                lease.revision,
                lease.provider,
                lease.account_handle,
                lease.model,
                lease.role,
                lease.affinity_key
            )
            .map_err(|error| format!("could not write provider status: {error}"))?;
            let predecessor = lease
                .predecessor
                .as_ref()
                .map_or_else(|| "none".to_owned(), ToString::to_string);
            let ended = match &lease.end {
                None => "none".to_owned(),
                Some(end) => serde_json::to_string(end)
                    .map_err(|error| format!("could not serialize provider lease end: {error}"))?,
            };
            writeln!(
                output,
                "    lineage predecessor {predecessor} started {} expires {} ended {ended}",
                provider_stamp(Some(lease.started_at)),
                provider_stamp(lease.expires_at)
            )
            .map_err(|error| format!("could not write provider status: {error}"))?;
            writeln!(
                output,
                "    health {} eligible {} enabled {}",
                lease.health.label(),
                lease.eligible,
                lease.provider_enabled
            )
            .map_err(|error| format!("could not write provider status: {error}"))?;
            let quota = serde_json::to_string(&lease.quota_snapshot)
                .map_err(|error| format!("could not serialize quota snapshot: {error}"))?;
            writeln!(output, "    quota {quota}")
                .map_err(|error| format!("could not write provider status: {error}"))?;
            writeln!(output, "    selection {}", lease.selection_reason)
                .map_err(|error| format!("could not write provider status: {error}"))?;
        }
    }
    Ok(())
}
