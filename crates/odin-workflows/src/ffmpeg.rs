//! Shared ffmpeg and ffprobe failures, independent of the calling family.
use std::time::Duration;

use crate::sandbox::RunOutput;
use crate::{cause, Failure};

pub const CAUSES: &[(&str, &str)] = &[
    (
        "moov atom not found",
        "the media file is incomplete (recording stopped before it was closed)",
    ),
    (
        "invalid data found when processing input",
        "the file is not readable audio or video",
    ),
    (
        "does not contain any stream",
        "the file has no usable audio or video stream",
    ),
    (
        "matches no streams",
        "the file has no matching audio or video stream",
    ),
    (
        "error while opening encoder",
        "the encoder refused these settings (often 10-bit into an 8-bit codec)",
    ),
    (
        "unknown encoder",
        "this ffmpeg build lacks the requested encoder",
    ),
    ("no space left on device", "the output disk is full"),
    (
        "no such file or directory",
        "the input file or output folder is no longer there",
    ),
];

/// Checks an ffmpeg or ffprobe run, including its deadline.
pub fn check(tool: &str, out: &RunOutput, limit: Duration) -> Result<(), Failure> {
    match cause::failure(tool, CAUSES, &[], out, limit) {
        Some(failure) => Err(failure),
        None => Ok(()),
    }
}
