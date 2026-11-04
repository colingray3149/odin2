//! The words a background job is told to the model in, and read back by:
//! `odin-omp`'s job board writes them, and the report turn, the ledger trace
//! and `odin view` read them from here.

/// The quiet-reply token lives in `odin_hermes::conversation::QUIET_REPLY`.
/// Opens the conversation turn that carries job reports.
pub const REPORT_TURN: &str = "[Job report from Odin";
/// Opens one job's report. Reports due together share one turn, each on its
/// own line.
pub const REPORT_PREFIX: &str = "Background job ";
/// Names the job in the tool result the model gets when a call detaches.
pub const STARTED: &str = "in the background as job ";

const FINISHED: &str = ") finished after ";
const FAILED: &str = ") failed after ";
/// Between a finished job's run time and its result.
const RESULT: &str = " s. Its result:\n";

/// One job's report: its title line, then the result or the cause it failed.
pub fn report(id: &str, title: &str, seconds: u64, outcome: Result<&str, &str>) -> String {
    match outcome {
        Ok(result) => {
            format!("{REPORT_PREFIX}{id} ({title}{FINISHED}{seconds}{RESULT}{result}")
        }
        Err(cause) => format!("{REPORT_PREFIX}{id} ({title}{FAILED}{seconds} s: {cause}"),
    }
}

/// Whether `report` says only that a launched workload was accepted
/// (`{"status":"accepted",…}`): the pod reports itself when it ends, so the
/// receipt tells the seat nothing it needs a turn for.
pub fn launch_receipt(report: &str) -> bool {
    report
        .split_once(RESULT)
        .and_then(|(_, result)| serde_json::from_str::<serde_json::Value>(result.trim()).ok())
        .is_some_and(|result| result["status"] == "accepted")
}

/// The job a tool result started.
pub fn started_job(text: &str) -> Option<&str> {
    let rest = text.split_once(STARTED)?.1;
    rest.split(|c: char| !c.is_ascii_alphanumeric()).next()
}

/// One job a report turn names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reported<'a> {
    pub job: &'a str,
    /// Whether it went through.
    pub ok: bool,
    /// How long it ran in whole seconds, by its own clock.
    pub seconds: Option<u64>,
    /// Its report's first line.
    pub line: &'a str,
}

/// Every job a report turn names, in order.
pub fn reported_jobs(text: &str) -> Vec<Reported<'_>> {
    let Some(at) = text.find(REPORT_TURN) else {
        return Vec::new();
    };
    let turn = &text[at..];
    turn.match_indices(REPORT_PREFIX)
        .enumerate()
        .filter(|(n, (start, _))| *n == 0 || turn[..*start].ends_with('\n'))
        .filter_map(|(_, (start, _))| reported(&turn[start..]))
        .collect()
}

/// One report, from its [`REPORT_PREFIX`] on.
fn reported(report: &str) -> Option<Reported<'_>> {
    let line = report.lines().next()?;
    let rest = &line[REPORT_PREFIX.len()..];
    let job = rest.split(|c: char| !c.is_ascii_alphanumeric()).next()?;
    // The first marker wins: a title can quote the other one.
    let (marker, at) = [FINISHED, FAILED]
        .into_iter()
        .filter_map(|marker| Some((marker, rest.find(marker)?)))
        .min_by_key(|(_, at)| *at)?;
    let seconds = rest[at + marker.len()..].split(' ').next()?.parse().ok();
    Some(Reported {
        job,
        ok: marker == FINISHED,
        seconds,
        line,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_report_in_a_turn_reads_back_as_written() {
        let turn = format!(
            "{REPORT_TURN} — not a message from the owner: {}\n\n{}\nTell the owner…]",
            report("j1", "calendar_read: school", 5, Ok("{}")),
            report("j2", "bash", 6, Err("timed out")),
        );
        assert_eq!(
            reported_jobs(&turn),
            [
                Reported {
                    job: "j1",
                    ok: true,
                    seconds: Some(5),
                    line:
                        "Background job j1 (calendar_read: school) finished after 5 s. Its result:",
                },
                Reported {
                    job: "j2",
                    ok: false,
                    seconds: Some(6),
                    line: "Background job j2 (bash) failed after 6 s: timed out",
                },
            ]
        );
    }
}
