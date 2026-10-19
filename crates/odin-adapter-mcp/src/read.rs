//! Window converted PDF text to avoid returning an entire document in one response.

use std::io::{ErrorKind, Read};
use std::process::{Child, ChildStdout, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use rustix::event::PollFlags;
use serde_json::{json, Value};

use crate::{nonblocking, note, ready, BridgeError, READ_CHUNK};

const EXIT_POLL: Duration = Duration::from_millis(20);

/// Request the whole page before selecting a character window.
pub const PAGE_CHARS: usize = 2_000_000;

const DEFAULT_WINDOW_CHARS: usize = 4_000;

/// Read one extra byte to distinguish overflow from an exactly full page.
const PDF_TEXT_BYTES: u64 = 8 << 20;

/// Return the next offset when more text remains so callers can continue reading.
pub fn window(text: &str, input: &Value, field: &str) -> Result<Value, BridgeError> {
    let number = |name: &str| {
        input
            .get(name)
            .and_then(Value::as_u64)
            .map(|value| usize::try_from(value).unwrap_or(usize::MAX))
    };
    let offset = number("offset").unwrap_or(0);
    let size = number(field).unwrap_or(DEFAULT_WINDOW_CHARS).max(1);
    let total = text.chars().count();
    if offset >= total && offset > 0 {
        return Err(BridgeError::OffsetPastEnd { offset, total });
    }
    let end = offset.saturating_add(size).min(total);
    let mut served: String = text.chars().skip(offset).take(end - offset).collect();
    if end < total {
        served.push_str(&format!(
            "\n\n[characters {offset}-{end} of {total}; the rest follows from offset {end}]"
        ));
    }
    Ok(json!({"content": [{"type": "text", "text": served}]}))
}

/// Descendants retaining output pipes must not extend the converter's deadline.
pub fn pdf_text(converter: &str, url: &str, deadline: Instant) -> Result<String, BridgeError> {
    let started = Instant::now();
    let mut child = Command::new(converter)
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            BridgeError::Spawn(format!(
                "the declared PDF converter could not be started: {error}"
            ))
        })?;
    let mut stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let mut stderr = match crate::capture_stderr(stderr, url) {
        Ok(stderr) => stderr,
        Err(error) => {
            stop(&mut child);
            return Err(BridgeError::Spawn(format!(
                "the converter's stderr could not be captured: {error}"
            )));
        }
    };
    let outcome = converted(&mut child, &mut stdout, deadline);
    stop(&mut child);
    let stderr_note = stderr.finish();
    let outcome = outcome.map_err(|error| crate::with_stderr(error, &stderr_note))?;
    let (bytes, status) = outcome;
    let ms = started.elapsed().as_millis();
    match status.code() {
        _ if status.success() => {}
        // Exit 65 means the raw document exceeded the converter's download limit.
        Some(65) => {
            note(&format!("pdf raw rejected reason=over_cap ms={ms}"));
            return Err(crate::with_stderr(
                BridgeError::PdfText("the raw PDF exceeds the converter's download limit".into()),
                &stderr_note,
            ));
        }
        Some(code) => {
            return Err(crate::with_stderr(
                BridgeError::PdfText(format!("the converter exited with code {code}")),
                &stderr_note,
            ))
        }
        None => {
            return Err(crate::with_stderr(
                BridgeError::PdfText("the converter was stopped by a signal".into()),
                &stderr_note,
            ))
        }
    }
    note(&format!("pdf converted text_bytes={} ms={ms}", bytes.len()));
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Check the deadline even while output arrives so a productive converter cannot extend it.
fn converted(
    child: &mut Child,
    stdout: &mut ChildStdout,
    deadline: Instant,
) -> Result<(Vec<u8>, ExitStatus), BridgeError> {
    let unreadable = |error: std::io::Error| {
        BridgeError::PdfText(format!("the converter's output could not be read: {error}"))
    };
    let late = || BridgeError::Timeout("converting the PDF".into());
    nonblocking(&*stdout).map_err(unreadable)?;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; READ_CHUNK];
    let mut closed = false;
    loop {
        let status = child.try_wait().map_err(unreadable)?;
        while !closed {
            if Instant::now() >= deadline {
                return Err(late());
            }
            match stdout.read(&mut chunk) {
                Ok(0) => closed = true,
                Ok(count) => {
                    bytes.extend_from_slice(&chunk[..count]);
                    if bytes.len() as u64 > PDF_TEXT_BYTES {
                        note(&format!(
                            "pdf text rejected reason=over_limit limit={PDF_TEXT_BYTES}"
                        ));
                        return Err(BridgeError::PdfText(format!(
                            "the converter printed more than the {PDF_TEXT_BYTES}-byte cap"
                        )));
                    }
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => return Err(unreadable(error)),
            }
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(late());
        }
        if let Some(status) = status {
            return Ok((bytes, status));
        }
        let slice = deadline.min(now + EXIT_POLL);
        if closed {
            std::thread::sleep(slice.saturating_duration_since(now));
        } else {
            ready(&*stdout, PollFlags::IN, slice).map_err(unreadable)?;
        }
    }
}

fn stop(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}
