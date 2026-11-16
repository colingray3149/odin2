//! Window converted PDF text to avoid returning an entire document in one response.

use std::io::{ErrorKind, Read, Write};
use std::process::{Child, ChildStdout, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use odin_adapter_core::{FETCH_REFUSED, FETCH_TIMED_OUT};
use rustix::event::PollFlags;
use serde_json::{json, Value};

use crate::{nonblocking, note, ready, BridgeError, READ_CHUNK};

const EXIT_POLL: Duration = Duration::from_millis(20);

/// The most of a page the browser is asked for, so its answer stays within the line bound.
const PAGE_CHARS: usize = 2_000_000;

/// The head of a page a bot check is looked for in; a read always asks for at least this much.
const SCAN_CHARS: usize = 16_384;

/// How the browser ends a page it cut short: `<head>\n...(truncated, <n> more chars)`.
const TRUNCATED: (&str, &str) = ("\n...(truncated, ", " more chars)");

/// The line a page read with the plain reader leads with.
const ALTERNATE_NOTE: &str = "Read with the alternate plain-HTTP engine.";

const DEFAULT_WINDOW_CHARS: usize = 4_000;

/// Read one extra byte to distinguish overflow from an exactly full page.
const PDF_TEXT_BYTES: u64 = 8 << 20;

/// Wayback's closest-replay lookup, as requested by the public research route.
const ARCHIVE_HOST: &str = "web.archive.org";
const ARCHIVE_RAW: &str = "/web/2/";
/// A snapshot id is fourteen digits, then an optional status code.
const SNAPSHOT_DIGITS: usize = 14;

/// One read of a public page: the document URL the load check recorded, and
/// the text the read tool returned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageRead {
    pub url: String,
    pub text: String,
}

/// Why a public read is trying again. A challenge page that answered 200 is
/// the same stop as a refused document: the reader did not get the page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadStop {
    Blocked,
    Challenged,
}

impl ReadStop {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::Challenged => "challenged",
        }
    }
}

/// A page the reader could not get. `stop` is why; `cause` is the load
/// check's own words, which name the status and never the URL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoppedRead {
    pub stop: ReadStop,
    pub cause: String,
}

/// The fixed public archive host, retaining the original page's own query.
pub fn archive_url(url: &str) -> String {
    format!("https://{ARCHIVE_HOST}{ARCHIVE_RAW}{url}")
}

/// Parse the actual replay redirect `/web/<timestamp>[id_]/<original>`.
/// The `/web/2/` request alias itself contains no snapshot date.
pub fn archive_date(url: &str) -> Option<String> {
    let url = reqwest::Url::parse(url).ok()?;
    if url.host_str()? != ARCHIVE_HOST {
        return None;
    }
    let mut parts = url.path_segments()?;
    if parts.next()? != "web" {
        return None;
    }
    let id = parts.next()?;
    let digits = id.get(..SNAPSHOT_DIGITS)?;
    if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let year = digits[..4].parse().ok()?;
    let month = time::Month::try_from(digits[4..6].parse::<u8>().ok()?).ok()?;
    let day = digits[6..8].parse().ok()?;
    time::Time::from_hms(
        digits[8..10].parse().ok()?,
        digits[10..12].parse().ok()?,
        digits[12..14].parse().ok()?,
    )
    .ok()?;
    Some(
        time::Date::from_calendar_date(year, month, day)
            .ok()?
            .to_string(),
    )
}

/// The line a successful archive read leads with. The date is the snapshot's,
/// and the original page is named so a citation can tell the two apart.
pub fn archive_note(date: &str, original: &str) -> String {
    format!("Read the archived copy of {original} from {date}.")
}

/// Put that note in front of the archived text. The page itself stays
/// untrusted content after the note.
pub fn with_archive_note(text: &str, date: &str, original: &str) -> String {
    format!("{}\n\n{text}", archive_note(date, original))
}

/// Both independent readers and the archive failed. No snapshot date is invented.
pub fn no_archive(stop: &StoppedRead) -> String {
    format!(
        "the page was {} ({}); the same session's other read engine failed too, and no archived copy was found",
        stop.stop.as_str(),
        stop.cause
    )
}

/// Put the plain reader's note in front of its text.
pub(crate) fn with_alternate_note(mut page: PageRead) -> PageRead {
    page.text = format!("{ALTERNATE_NOTE}\n\n{}", page.text);
    page
}

/// Whether the plain reader's page, with its note, fits in `chars`.
pub(crate) fn fits_with_note(page: &PageRead, chars: usize) -> bool {
    ALTERNATE_NOTE.len() + 2 + page.text.chars().count() <= chars
}

/// Keep fallback order explicit and testable without contacting public services.
pub(crate) fn public_fallback(
    original: &str,
    stop: &StoppedRead,
    alternate: impl FnOnce() -> Option<PageRead>,
    archive: impl FnOnce(&str) -> Option<PageRead>,
) -> Result<PageRead, BridgeError> {
    if let Some(page) = alternate() {
        return Ok(with_alternate_note(page));
    }
    if let Some(mut page) = archive(&archive_url(original)) {
        if let Some(date) = archive_date(&page.url) {
            page.text = with_archive_note(&page.text, &date, original);
            return Ok(page);
        }
    }
    Err(BridgeError::PageLoad(no_archive(stop)).refused())
}

/// The path a Cloudflare bot challenge loads its script from. Seeing it is
/// how a block is told from a missing page; nothing here tries to pass it.
const BOT_CHALLENGE: &str = "/cdn-cgi/challenge-platform/";
/// A 200 document whose body is the challenge interstitial, not the page.
const CHALLENGE_MARKERS: &[&str] = &[
    "cf-challenge",
    "cf-browser-verification",
    "just a moment",
    "checking your browser",
    "verify you are human",
    "verify that you are human",
    "complete the captcha",
    "please solve the captcha",
    "enable javascript and cookies to continue",
    "checking if the site connection is secure",
    "incapsula incident id",
    "perimeterx",
    "datadome",
    "akamai reference",
];

/// What the request log says about the document, read against the page text.
pub enum DocumentVerdict {
    Loaded(String),
    /// A block or a challenge, including one that answered HTTP 200.
    Stopped(StoppedRead),
    /// A missing log or a refused document that is not a bot check.
    Failed(String),
}

/// The first request-log entry is the document. A 200 is not enough: a
/// challenge interstitial answers 200 and then loads its script, or says so
/// in the body.
pub fn document_verdict(log: &str, text: &str) -> DocumentVerdict {
    let mut requests = log.lines().filter_map(|line| {
        let (status, rest) = line.strip_prefix('[')?.split_once("] ")?;
        let url = rest.split_whitespace().nth(1)?;
        Some((status.parse::<u16>().ok()?, url.to_owned()))
    });
    let Some(mut document) = requests.next() else {
        return DocumentVerdict::Failed("no document was fetched".to_owned());
    };
    while (300..400).contains(&document.0) {
        let Some(redirected) = requests.next() else {
            break;
        };
        document = redirected;
    }
    let (status, url) = document;
    let challenged = log.contains(BOT_CHALLENGE) || challenge_text(text);
    if !(200..400).contains(&status) {
        let cause = format!("the document answered HTTP {status}");
        return if challenged || matches!(status, 401 | 403 | 407 | 429 | 451 | 503) {
            DocumentVerdict::Stopped(StoppedRead {
                stop: ReadStop::Blocked,
                cause,
            })
        } else {
            DocumentVerdict::Failed(cause)
        };
    }
    if challenged {
        return DocumentVerdict::Stopped(StoppedRead {
            stop: ReadStop::Challenged,
            cause: format!("the document answered HTTP {status} with a bot check"),
        });
    }
    DocumentVerdict::Loaded(url)
}

fn challenge_text(text: &str) -> bool {
    let said = text
        .chars()
        .take(SCAN_CHARS)
        .collect::<String>()
        .to_ascii_lowercase();
    CHALLENGE_MARKERS.iter().any(|marker| said.contains(marker))
        || said
            .trim_start_matches(['#', ' ', '\n'])
            .starts_with("access denied")
}

/// The words a stop uses when nothing retries it.
pub fn stop_cause(stopped: &StoppedRead) -> String {
    format!(
        "the site blocked this reader with its bot check ({}, {})",
        stopped.stop.as_str(),
        stopped.cause
    )
}
/// The offset and size of the window `input` asks for.
fn window_of(input: &Value, field: &str) -> (usize, usize) {
    let number = |name: &str| {
        input
            .get(name)
            .and_then(Value::as_u64)
            .map(|value| usize::try_from(value).unwrap_or(usize::MAX))
    };
    (
        number("offset").unwrap_or(0),
        number(field).unwrap_or(DEFAULT_WINDOW_CHARS).max(1),
    )
}

/// The characters a read asks the browser for: through the end of the window, and never less
/// than the head a bot check is looked for in.
pub(crate) fn asked_chars(input: &Value, field: &str) -> usize {
    let (offset, size) = window_of(input, field);
    offset.saturating_add(size).clamp(SCAN_CHARS, PAGE_CHARS)
}

/// The size of the first window when `input` starts at the top of the page, else `None`.
pub(crate) fn first_window(input: &Value, field: &str) -> Option<usize> {
    let (offset, size) = window_of(input, field);
    (offset == 0).then_some(size)
}

/// The text without the browser's truncation mark, and the characters the mark says were left
/// out. Only a text at least as long as the read asked for was cut short.
fn unread(text: &str, asked: usize) -> (&str, usize) {
    let Some((head, mark)) = text.rsplit_once(TRUNCATED.0) else {
        return (text, 0);
    };
    match mark.strip_suffix(TRUNCATED.1).map(str::parse) {
        Some(Ok(count)) if head.chars().count() >= asked => (head, count),
        _ => (text, 0),
    }
}

/// Return the next offset when more text remains so callers can continue reading. A page the
/// browser cut short counts the characters it left out in its total.
pub fn window(text: &str, input: &Value, field: &str) -> Result<Value, BridgeError> {
    let (offset, size) = window_of(input, field);
    let (text, unread) = unread(text, asked_chars(input, field));
    let read = text.chars().count();
    if offset >= read && offset > 0 {
        return Err(BridgeError::OffsetPastEnd {
            offset,
            total: read,
        });
    }
    let total = read + unread;
    let end = offset.saturating_add(size).min(read);
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
            let failed = crate::with_stderr(
                BridgeError::PdfText(format!("the converter exited with code {code}")),
                &stderr_note,
            );
            // The converter's own fetch timed out or the site refused it.
            return Err(if matches!(code, FETCH_TIMED_OUT | FETCH_REFUSED) {
                failed.refused()
            } else {
                failed
            });
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

/// The article an HTML page holds, from the declared extractor reading the page on stdin.
/// `None` when it fails, prints nothing, overruns the byte cap or the deadline, so the
/// caller keeps html2text. A descendant holding the pipe does not extend the deadline.
pub(crate) fn article_text(converter: &str, html: &[u8], deadline: Instant) -> Option<String> {
    let mut child = Command::new(converter)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut stdout = child.stdout.take().expect("piped stdout");
    let page = html.to_vec();
    // A page larger than the pipe needs a writer beside the reader; killing the child ends it.
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&page);
        drop(stdin);
    });
    let outcome = converted(&mut child, &mut stdout, deadline);
    stop(&mut child);
    let _ = writer.join();
    let (bytes, status) = outcome.ok()?;
    let text = String::from_utf8_lossy(&bytes).into_owned();
    (status.success() && !text.trim().is_empty()).then_some(text)
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
