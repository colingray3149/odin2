//! Local reconstruction of captured model requests.
//!
//! `odin huginn export` reads the authority ledger on this machine. It does
//! not call a Huginn endpoint. A remote `--endpoint` is rejected: the export
//! is the local ledger, not a relayed view.
//!
//! Each JSONL row is `odin.trace.export.v1`:
//!
//! - `schema`, `session_id`, `seat_id`, `entry_id`, `occurred_at`
//! - `provider`, `model`, `api` from the model that served the request
//! - `request_id`, `response_id` as observed; absent ids stay null
//! - `request` the reconstructed provider body (`messages`/`input`/`contents`,
//!   `tools`/`toolConfig`, system fields) from content-addressed blobs
//! - `messages`, `tools` the same arrays lifted out of `request`
//! - `response` the journaled assistant `message_end` with that `response_id`
//! - `tool_calls`, `tool_results` journaled tool frames whose `toolCallId`
//!   is in the linked set
//! - `usage`, `outcome` from that assistant message
//! - `lessons` `memory_remember` / `memory_forget` results from the call's
//!   tool ids, plus later session corrections after that response
//! - `trace_error` when an id or blob is missing; the row is still emitted

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use clap::Args;
use odin_ledger::Ledger;
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
    let ledger = Ledger::open(&ledger_path)
        .map_err(|error| format!("could not open ledger {}: {error}", ledger_path.display()))?;
    let rows = ledger
        .export_traces(&arguments.seat, since)
        .map_err(|error| format!("trace export failed: {error}"))?;
    if let Some(parent) = arguments.out.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
        }
    }
    let mut file = fs::File::create(&arguments.out)
        .map_err(|error| format!("could not create {}: {error}", arguments.out.display()))?;
    for row in &rows {
        serde_json::to_writer(&mut file, row)
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
