//! `odin context <session> [--turn N]`: what each injection put into a
//! session's context, and the prefix each provider request carried, from
//! this host's injected-context trace (the authority's state root).

use std::io::Write;
use std::path::PathBuf;

use clap::Args;
use odin_domain::huginn::LiveSessionId;
use odin_omp::live::context_trace::{self, Record};

#[derive(Debug, Args)]
pub(crate) struct ContextArgs {
    /// The session id (a UUID).
    session: String,
    /// Only the injections sent on this turn.
    #[arg(long, value_name = "N")]
    turn: Option<u64>,
    /// Holds the injected-context trace (the authority's state root).
    #[arg(
        long,
        env = "ODIN_HUGINN_STATE_ROOT",
        default_value = "state",
        value_name = "PATH"
    )]
    state_root: PathBuf,
}

pub(crate) fn context(arguments: ContextArgs, output: &mut impl Write) -> Result<(), String> {
    let session = LiveSessionId::parse(&arguments.session)
        .map_err(|error| format!("{:?} is not a session id: {error}", arguments.session))?;
    let records = context_trace::read(&context_trace::root(&arguments.state_root), session)?
        .unwrap_or_default();
    let records: Vec<Record> = records
        .into_iter()
        .filter(|record| arguments.turn.is_none_or(|turn| record.turn == Some(turn)))
        .collect();
    if records.is_empty() {
        writeln!(output, "no injected context recorded for {session}")
            .map_err(|error| error.to_string())?;
        return Ok(());
    }
    let mut lanes = std::collections::BTreeMap::<&str, (u64, u64)>::new();
    for record in &records {
        let Some(measured) = record.prefix.as_ref().map(|prefix| &prefix.measured) else {
            continue;
        };
        if let (Some(lane), Some(prompt)) = (&measured.lane, measured.prompt_tokens) {
            let entry = lanes.entry(lane.as_str()).or_default();
            entry.0 += prompt;
            entry.1 += measured.cached_tokens.unwrap_or(0);
        }
    }
    for record in &records {
        let turn = record
            .turn
            .map_or_else(String::new, |turn| format!(" turn={turn}"));
        writeln!(output, "{} {}{turn}", record.at, record.kind.label())
            .map_err(|error| error.to_string())?;
        if let Some(prefix) = &record.prefix {
            writeln!(
                output,
                "  system {} B, tools {} B, injected {} B, prefix {}",
                prefix.system_bytes,
                prefix.tool_bytes,
                prefix.injected_bytes,
                &prefix.hash.hex()[..12]
            )
            .map_err(|error| error.to_string())?;
            let measured = &prefix.measured;
            let count =
                |value: Option<u64>| value.map_or_else(|| "?".to_owned(), |n| n.to_string());
            if measured.prompt_tokens.is_some() || measured.history_bytes.is_some() {
                writeln!(
                    output,
                    "  lane {}, history {} B, tool results {} B, prompt {} tokens, cached {}",
                    measured.lane.as_deref().unwrap_or("?"),
                    count(measured.history_bytes),
                    count(measured.tool_result_bytes),
                    count(measured.prompt_tokens),
                    count(measured.cached_tokens),
                )
                .map_err(|error| error.to_string())?;
            }
        }
        for block in &record.blocks {
            let sources = if block.sources.is_empty() {
                String::new()
            } else {
                format!(" [{}]", block.sources.join(", "))
            };
            writeln!(
                output,
                "  {} (≈{} tokens){sources}",
                block.label, block.tokens
            )
            .map_err(|error| error.to_string())?;
            for line in block.text.lines() {
                writeln!(output, "    {line}").map_err(|error| error.to_string())?;
            }
        }
    }
    for (lane, (prompt, cached)) in lanes {
        let share = (cached * 100).checked_div(prompt).unwrap_or(0);
        writeln!(
            output,
            "lane {lane}: {cached} of {prompt} prompt tokens cached ({share}%)"
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}
