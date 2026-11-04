//! A failed run in one sentence. Tool-specific tables live beside their callers;
//! tools shared across families, such as ffmpeg, use one kernel table.

use std::time::Duration;

use crate::sandbox::RunOutput;
use crate::Failure;

/// The characters of a stderr line or response body quoted in a failure.
pub(crate) const QUOTED_CHARS: usize = 200;

/// A byte limit as a message names it: "400 KiB", "8 MiB", "2 GiB".
pub fn limit_text(bytes: u64) -> String {
    const KIB: u64 = 1024;
    match bytes {
        b if b >= KIB.pow(3) && b % KIB.pow(3) == 0 => format!("{} GiB", b / KIB.pow(3)),
        b if b >= KIB.pow(2) && b % KIB.pow(2) == 0 => format!("{} MiB", b / KIB.pow(2)),
        b if b >= KIB && b % KIB == 0 => format!("{} KiB", b / KIB),
        b => format!("{b} bytes"),
    }
}

/// The cause of the first table marker found in stderr (case-insensitive).
pub fn marked<'a>(markers: &[(&str, &'a str)], out: &RunOutput) -> Option<&'a str> {
    let stderr = out.stderr_tail.to_lowercase();
    markers
        .iter()
        .find(|(marker, _)| stderr.contains(&marker.to_lowercase()))
        .map(|(_, cause)| *cause)
}

/// The first table marker found in stderr (case-insensitive) wins, then the
/// exit-code table, then "<tool> exited <code>: <last stderr line>".
pub fn explain(
    tool: &str,
    markers: &[(&str, &str)],
    codes: &[(i32, &str)],
    out: &RunOutput,
) -> String {
    if let Some(cause) = marked(markers, out) {
        return cause.to_owned();
    }
    if let Some((_, cause)) = codes.iter().find(|(code, _)| out.code == Some(*code)) {
        return (*cause).to_owned();
    }
    let ended = match out.code {
        Some(code) => format!("{tool} exited {code}"),
        None => format!("{tool} was stopped by a signal"),
    };
    match out
        .stderr_tail
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty())
    {
        Some(line) => format!(
            "{ended}: {}",
            line.chars().take(QUOTED_CHARS).collect::<String>()
        ),
        None => format!("{ended} without a message"),
    }
}

/// "<tool> ran past its <n> s limit and was stopped".
pub fn timed_out(tool: &str, limit: Duration) -> String {
    format!(
        "{tool} ran past its {} s limit and was stopped",
        limit.as_secs()
    )
}

/// `None` for a clean exit; otherwise the one-sentence upstream failure.
pub fn failure(
    tool: &str,
    markers: &[(&str, &str)],
    codes: &[(i32, &str)],
    out: &RunOutput,
    limit: Duration,
) -> Option<Failure> {
    if out.timed_out {
        return Some(Failure::upstream(timed_out(tool, limit)));
    }
    (!out.success()).then(|| Failure::upstream(explain(tool, markers, codes, out)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAUSES: &[(&str, &str)] = &[("Unsupported URL", "the link is not a page yt-dlp knows")];

    fn failed(code: i32, stderr: &str) -> RunOutput {
        RunOutput {
            code: Some(code),
            stderr_tail: stderr.to_owned(),
            ..RunOutput::default()
        }
    }

    #[test]
    fn marker_beats_exit_code() {
        let out = failed(2, "ERROR: unsupported url: a link\n");
        assert_eq!(
            explain("yt-dlp", CAUSES, &[(2, "usage error")], &out),
            "the link is not a page yt-dlp knows"
        );
        assert_eq!(
            explain("yt-dlp", &[], &[(2, "usage error")], &out),
            "usage error"
        );
    }
}
