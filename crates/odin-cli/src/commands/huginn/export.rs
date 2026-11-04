//! Local `odin huginn export`. Reads this machine's ledger, not a Huginn
//! endpoint. Rows are `odin.trace.export.v2`: `requested_model` is the lane
//! asked, `served_model` is the gateway deployment header (null when absent),
//! `stop_reason` is not an outcome, `estimated_cost_usd` is an estimate, and
//! `lessons` are memory-tool results, not later corrections. `inferred_redo`
//! is inferred. Every project's sessions are exported; Claude Code sessions
//! never run through the harness, so they are not read.
//! `--finetune` writes chat messages plus labels.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use clap::Args;
use odin_ledger::trace::finetune_row;
use odin_ledger::Ledger;
use odin_omp::redact::redact_value;
use time::format_description::well_known::Rfc3339;
use time::{Date, OffsetDateTime, Time};

#[derive(Debug, Args)]
pub(crate) struct HuginnExportArgs {
    /// Inclusive lower bound. `YYYY-MM-DD` or an RFC3339 timestamp.
    #[arg(long, value_name = "DATE")]
    since: String,
    /// Seat id whose sessions are exported.
    #[arg(long, value_name = "SEAT")]
    seat: String,
    /// JSONL file to write. Created, never appended to a remote store.
    #[arg(long, value_name = "PATH")]
    out: PathBuf,
    /// Write chat messages, function tools, and labels instead of the raw row.
    #[arg(long)]
    finetune: bool,
}

pub(crate) fn export_local(
    state_root: &std::path::Path,
    arguments: HuginnExportArgs,
    output: &mut impl Write,
) -> Result<(), String> {
    let since = parse_since(&arguments.since)?;
    if arguments.seat.trim().is_empty() {
        return Err("export --seat must name a seat".to_owned());
    }
    let ledger_path = state_root.join("ledger.sqlite3");
    let ledger = Ledger::open_read_only(&ledger_path)
        .map_err(|error| format!("could not open ledger {}: {error}", ledger_path.display()))?;
    let mut rows = ledger
        .export_traces(&arguments.seat, since)
        .map_err(|error| format!("trace export failed: {error}"))?;
    rows.sort_by(|left, right| {
        left["occurred_at"]
            .as_str()
            .unwrap_or("")
            .cmp(right["occurred_at"].as_str().unwrap_or(""))
            .then_with(|| {
                left["entry_id"]
                    .as_str()
                    .unwrap_or("")
                    .cmp(right["entry_id"].as_str().unwrap_or(""))
            })
    });
    crate::commands::ensure_parent_dir(&arguments.out)?;
    let mut file = fs::File::create(&arguments.out)
        .map_err(|error| format!("could not create {}: {error}", arguments.out.display()))?;
    for row in &rows {
        let scrubbed = redact_value(row);
        let written = if arguments.finetune {
            finetune_row(&scrubbed)
        } else {
            scrubbed
        };
        serde_json::to_writer(&mut file, &written)
            .map_err(|error| format!("export write failed: {error}"))?;
        file.write_all(b"\n")
            .map_err(|error| format!("export write failed: {error}"))?;
    }
    file.sync_all()
        .map_err(|error| format!("export sync failed: {error}"))?;
    writeln!(
        output,
        "exported {} trace rows for {} since {} to {}",
        rows.len(),
        arguments.seat,
        arguments.since,
        arguments.out.display()
    )
    .map_err(|error| format!("export report failed: {error}"))?;
    Ok(())
}

fn parse_since(value: &str) -> Result<OffsetDateTime, String> {
    if let Ok(parsed) = OffsetDateTime::parse(value, &Rfc3339) {
        return Ok(parsed);
    }
    let date = Date::parse(
        value,
        &time::macros::format_description!("[year]-[month]-[day]"),
    )
    .map_err(|error| format!("--since {value:?} is not YYYY-MM-DD or RFC3339: {error}"))?;
    Ok(date.with_time(Time::MIDNIGHT).assume_utc())
}
