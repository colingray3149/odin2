use std::io::Write;
use std::path::PathBuf;

use odin_domain::huginn as live;
use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub(crate) fn write_huginn_message(
    output: &mut impl Write,
    message: &live::HuginnMessage,
    compact: bool,
    limits: &odin_huginn::protocol::CodecLimits,
) -> Result<(), String> {
    if let live::HuginnMessage::ProtocolError(error) = message {
        return Err(error.to_string());
    }
    write_huginn_value(output, message, compact, limits)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HuginnDownloadReport {
    pub(super) output: PathBuf,
    pub(super) digest: odin_domain::Digest,
}

pub(crate) fn write_huginn_value(
    output: &mut impl Write,
    value: &impl Serialize,
    compact: bool,
    limits: &odin_huginn::protocol::CodecLimits,
) -> Result<(), String> {
    let redacted = odin_huginn::protocol::redacted_json(value, limits)
        .map_err(|error| format!("could not redact Huginn output: {error}"))?;
    if compact {
        serde_json::to_writer(&mut *output, &redacted)
    } else {
        serde_json::to_writer_pretty(&mut *output, &redacted)
    }
    .map_err(|error| format!("could not serialize Huginn output: {error}"))?;
    writeln!(output).map_err(|error| format!("could not write Huginn output: {error}"))
}

pub(crate) fn provider_stamp(moment: Option<OffsetDateTime>) -> String {
    moment.map_or_else(
        || "-".to_owned(),
        |moment| moment.format(&Rfc3339).unwrap_or_else(|_| "-".to_owned()),
    )
}

/// The `odin huginn status` view for a person (Huginn View, the desktop
/// entry): the daemon line and one line per seat with its sessions, times
/// in local-agnostic UTC `YYYY-MM-DD HH:MM`. `None` when the page holds
/// anything but status objects; status ids this view does not read
/// (`spend`, `incident:…`) are skipped, not fatal.
pub(crate) fn human_status(page: &live::SnapshotPage) -> Option<String> {
    use std::fmt::Write as _;
    let stamp = |at: OffsetDateTime| {
        let at = at.to_offset(time::UtcOffset::UTC);
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02} UTC",
            at.year(),
            u8::from(at.month()),
            at.day(),
            at.hour(),
            at.minute()
        )
    };
    let mut text = String::new();
    for snapshot in &page.objects {
        if snapshot.object.kind != live::ObjectKind::Status {
            return None;
        }
        match snapshot.object.id.as_str() {
            "odind" => {
                let field = |key: &str| {
                    snapshot
                        .value
                        .get(key)
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("?")
                        .to_owned()
                };
                // The object is seeded once before the listener binds and
                // never republished, so it carries no state: a served
                // object is a serving daemon.
                let _ = writeln!(
                    text,
                    "odind on {} (listening on {})",
                    field("node"),
                    field("listener")
                );
            }
            "roster" => {
                let roster: live::SeatRoster =
                    serde_json::from_value(snapshot.value.get("data")?.clone()).ok()?;
                let _ = writeln!(text, "\nSeats (as of {})", stamp(roster.generated_at));
                for seat in &roster.seats {
                    let state = words(&format!("{:?}", seat.state));
                    let _ = writeln!(
                        text,
                        "  {:<10} {:<9} {}",
                        seat.display_name,
                        state,
                        match seat.active_sessions.len() {
                            0 => "no sessions".to_owned(),
                            1 => "1 session".to_owned(),
                            n => format!("{n} sessions"),
                        }
                    );
                    for session in &seat.active_sessions {
                        let title = session
                            .title
                            .as_deref()
                            .map(str::trim)
                            .filter(|title| !title.is_empty())
                            .unwrap_or("(untitled)");
                        let title: String = title.chars().take(48).collect();
                        let _ = writeln!(
                            text,
                            "    - {:<48}  {:<13} {}  updated {}",
                            title,
                            words(&format!("{:?}", session.state)),
                            session.model,
                            stamp(session.updated_at)
                        );
                    }
                }
            }
            _ => continue,
        }
    }
    Some(text)
}

/// `simulationMission` → `simulation mission`.
pub(crate) fn words(camel: &str) -> String {
    let mut out = String::with_capacity(camel.len() + 4);
    for character in camel.chars() {
        if character.is_ascii_uppercase() && !out.is_empty() {
            out.push(' ');
        }
        out.push(character.to_ascii_lowercase());
    }
    out
}
