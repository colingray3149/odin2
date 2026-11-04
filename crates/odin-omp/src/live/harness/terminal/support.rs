use std::path::{Path, PathBuf};
use std::time::SystemTime;

use tokio::io::{AsyncReadExt, AsyncSeekExt};

pub(super) use super::super::transports::path_env;
use super::super::transports::program_path;

pub(super) fn find_program(name: &str, home: &Path) -> Option<PathBuf> {
    program_path(home)
        .into_iter()
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// The most recently modified `*.jsonl` in `dir`.
pub(super) async fn newest_transcript(dir: &Path) -> Option<PathBuf> {
    let mut entries = tokio::fs::read_dir(dir).await.ok()?;
    let mut newest: Option<(SystemTime, PathBuf)> = None;
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("jsonl") {
            continue;
        }
        let Ok(modified) = entry.metadata().await.and_then(|meta| meta.modified()) else {
            continue;
        };
        if newest.as_ref().is_none_or(|(at, _)| modified > *at) {
            newest = Some((modified, path));
        }
    }
    newest.map(|(_, path)| path)
}

/// The bytes written to `file` after `offset` (advanced past them).
pub(super) async fn read_from(file: &Path, offset: &mut u64) -> std::io::Result<String> {
    let mut handle = tokio::fs::File::open(file).await?;
    let length = handle.metadata().await?.len();
    if length < *offset {
        *offset = 0;
    }
    if length == *offset {
        return Ok(String::new());
    }
    handle.seek(std::io::SeekFrom::Start(*offset)).await?;
    let mut bytes = Vec::with_capacity(usize::try_from(length - *offset).unwrap_or(0));
    handle.read_to_end(&mut bytes).await?;
    // A character cut at the end of the file waits for the next read; an invalid byte inside it
    // is consumed lossily, so it cannot stall the follower.
    let consumed = match std::str::from_utf8(&bytes) {
        Err(error) if error.error_len().is_none() => error.valid_up_to(),
        _ => bytes.len(),
    };
    *offset += consumed as u64;
    Ok(String::from_utf8_lossy(&bytes[..consumed]).into_owned())
}
