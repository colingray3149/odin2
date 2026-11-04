//! Flipper Zero USB serial CLI.
//!
//! Transfers use the firmware storage CLI, not a text dump. `storage
//! read_chunks` prints `Size: N`, then `Ready?` before each raw chunk, and
//! the host answers `y`. `storage write_chunk` prints `Ready` and then
//! consumes exactly the declared number of raw bytes, appending. `update
//! install` verifies an `.fuf` already on the device and reboots into the
//! updater.
//!
//! One serial read can return the delimiter and the next frame together.
//! The receive buffer consumes exactly through each delimiter and keeps the
//! remainder for the next line or raw-byte read.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rustix::termios;

pub const BAUD: u32 = 230400;
const PROMPT: &[u8] = b">: ";
const EOL: &[u8] = b"\r\n";
/// Firmware `storage_cli_write_chunk` reads its pipe in 1024-byte slices.
const CHUNK: usize = 1024;
const CHUNK_WAIT: Duration = Duration::from_secs(60);
const PROMPT_WAIT: Duration = Duration::from_secs(8);
const INSTALL_WAIT: Duration = Duration::from_secs(30);
const READ_POLL: Duration = Duration::from_millis(20);

#[derive(Debug, thiserror::Error)]
pub enum FlipperError {
    #[error("flipper unavailable")]
    Unavailable,
    #[error("flipper timed out")]
    Timeout,
    #[error("flipper storage: {0}")]
    Storage(String),
    #[error("flipper protocol: {0}")]
    Protocol(String),
}

pub struct FlipperCli {
    port_path: PathBuf,
    install_wait: Duration,
    port: Option<File>,
    /// Bytes already read past a consumed delimiter. Cleared when the port
    /// is dropped or a new command drains stale CLI output.
    rx: Vec<u8>,
}

impl FlipperCli {
    pub fn new(port_path: impl Into<PathBuf>) -> Self {
        Self {
            port_path: port_path.into(),
            install_wait: INSTALL_WAIT,
            port: None,
            rx: Vec::new(),
        }
    }

    /// How long `update install` may stay silent. The updater reboots the device without a
    /// prompt, so a good install normally ends by this wait running out.
    pub fn with_install_wait(mut self, wait: Duration) -> Self {
        self.install_wait = wait;
        self
    }

    /// Open the node at 230400 8N1 and wait until the CLI prompt is current.
    pub fn connect(&mut self) -> Result<(), FlipperError> {
        if !self.port_path.exists() {
            return Err(FlipperError::Unavailable);
        }
        let mut file = File::options()
            .read(true)
            .write(true)
            .open(&self.port_path)
            .map_err(|_| FlipperError::Unavailable)?;
        let mut termios = termios::tcgetattr(&file).map_err(|_| FlipperError::Unavailable)?;
        termios.make_raw();
        termios.special_codes[termios::SpecialCodeIndex::VMIN] = 0;
        termios.special_codes[termios::SpecialCodeIndex::VTIME] = 1;
        termios.control_modes |= termios::ControlModes::CS8
            | termios::ControlModes::CREAD
            | termios::ControlModes::CLOCAL;
        termios
            .set_speed(BAUD)
            .map_err(|_| FlipperError::Unavailable)?;
        termios::tcsetattr(&file, termios::OptionalActions::Now, &termios)
            .map_err(|_| FlipperError::Unavailable)?;
        file.write_all(b"\r\n")
            .map_err(|_| FlipperError::Unavailable)?;
        let mut pending = std::mem::take(&mut self.rx);
        match read_until(&mut file, &mut pending, PROMPT, PROMPT_WAIT) {
            Ok(_) => {
                self.rx = pending;
                self.port = Some(file);
                Ok(())
            }
            Err(error) => {
                self.rx.clear();
                Err(error)
            }
        }
    }

    fn opened(&mut self) -> Result<(&mut File, &mut Vec<u8>), FlipperError> {
        if self.port.is_none() {
            self.connect()?;
        }
        match self {
            Self {
                port: Some(port),
                rx,
                ..
            } => Ok((port, rx)),
            _ => Err(FlipperError::Unavailable),
        }
    }

    fn drop_port(&mut self) {
        self.port = None;
        self.rx.clear();
    }

    /// One typed command. The body excludes the echo and the trailing prompt.
    pub fn command(&mut self, cmd: &str, timeout: Duration) -> Result<String, FlipperError> {
        let outcome = {
            let (port, rx) = self.opened()?;
            drain_stale(port, rx);
            write_line(port, cmd)?;
            read_until(port, rx, PROMPT, timeout)
        };
        match outcome {
            Ok(buf) => Ok(strip_exchange(&buf, cmd)),
            Err(error) => {
                self.drop_port();
                Err(error)
            }
        }
    }

    /// `storage read_chunks`: the file's raw bytes, not printable `storage read`.
    pub fn read_file(&mut self, device_path: &str) -> Result<Vec<u8>, FlipperError> {
        require_storage_path(device_path)?;
        let read = self.read_chunks(device_path);
        self.dropping_the_port_on_error(read)
    }

    /// A failed transfer leaves the device at an unknown point in it, so the next command
    /// reconnects instead of reading from the middle.
    fn dropping_the_port_on_error<T>(
        &mut self,
        result: Result<T, FlipperError>,
    ) -> Result<T, FlipperError> {
        if result.is_err() {
            self.drop_port();
        }
        result
    }

    fn read_chunks(&mut self, device_path: &str) -> Result<Vec<u8>, FlipperError> {
        {
            let (port, rx) = self.opened()?;
            drain_stale(port, rx);
            write_line(
                port,
                &format!("storage read_chunks \"{device_path}\" {CHUNK}"),
            )?;
        }
        // Command echo ends at the first CRLF. Bytes after that delimiter
        // stay in `rx` for the size line, the readiness line, and the raw chunk.
        let _echo = self.take_until(EOL, CHUNK_WAIT)?;
        let size_line = self.take_until(EOL, CHUNK_WAIT)?;
        let size_text = String::from_utf8_lossy(&size_line);
        if size_text.contains("Storage error:") {
            let _ = self.take_until(PROMPT, CHUNK_WAIT);
            return Err(FlipperError::Storage(size_text.trim().to_owned()));
        }
        let size = parse_size(&size_text)?;
        let mut file = Vec::with_capacity(size);
        while file.len() < size {
            let ready = self.take_until(b"Ready?\r\n", CHUNK_WAIT)?;
            if ready
                .windows(b"Storage error:".len())
                .any(|window| window == b"Storage error:")
            {
                let _ = self.take_until(PROMPT, CHUNK_WAIT);
                return Err(FlipperError::Storage(
                    String::from_utf8_lossy(&ready).trim().to_owned(),
                ));
            }
            // Firmware waits for one byte (`getchar`), then writes the chunk raw.
            // A coalesced read may already hold the start of that chunk.
            let (port, _) = self.opened()?;
            port.write_all(b"y")
                .map_err(|_| FlipperError::Unavailable)?;
            let want = (size - file.len()).min(CHUNK);
            let mut chunk = vec![0_u8; want];
            self.take_exact(&mut chunk, CHUNK_WAIT)?;
            file.extend_from_slice(&chunk);
        }
        let _ = self.take_until(PROMPT, CHUNK_WAIT)?;
        Ok(file)
    }

    /// `storage write_chunk` until `local` is on the device. An existing
    /// file is removed first, because write_chunk appends.
    pub fn write_file(&mut self, local: &Path, device_path: &str) -> Result<(), FlipperError> {
        require_storage_path(device_path)?;
        let written = self.write_chunks(local, device_path);
        self.dropping_the_port_on_error(written)
    }

    fn write_chunks(&mut self, local: &Path, device_path: &str) -> Result<(), FlipperError> {
        let bytes = std::fs::read(local).map_err(|error| {
            FlipperError::Protocol(format!("cannot read {}: {error}", local.display()))
        })?;
        let stat = self.command(&format!("storage stat \"{device_path}\""), CHUNK_WAIT)?;
        if stat.contains("File, size:") {
            let removed = self.command(&format!("storage remove \"{device_path}\""), CHUNK_WAIT)?;
            if removed.contains("Storage error:") {
                return Err(FlipperError::Storage(removed));
            }
        }
        if bytes.is_empty() {
            return self.write_chunk(device_path, &[]);
        }
        for chunk in bytes.chunks(CHUNK) {
            self.write_chunk(device_path, chunk)?;
        }
        Ok(())
    }

    fn write_chunk(&mut self, device_path: &str, chunk: &[u8]) -> Result<(), FlipperError> {
        {
            let (port, rx) = self.opened()?;
            drain_stale(port, rx);
            write_line(
                port,
                &format!("storage write_chunk \"{device_path}\" {}", chunk.len()),
            )?;
        }
        let _echo = self.take_until(EOL, CHUNK_WAIT)?;
        let answer = self.take_until(EOL, CHUNK_WAIT)?;
        let answer_text = String::from_utf8_lossy(&answer);
        if answer_text.contains("Storage error:") {
            let _ = self.take_until(PROMPT, CHUNK_WAIT);
            return Err(FlipperError::Storage(answer_text.trim().to_owned()));
        }
        if !answer_text.contains("Ready") {
            return Err(FlipperError::Protocol(format!(
                "write_chunk answered {answer_text:?}, want Ready"
            )));
        }
        if !chunk.is_empty() {
            let (port, _) = self.opened()?;
            port.write_all(chunk)
                .map_err(|_| FlipperError::Unavailable)?;
        }
        let _ = self.take_until(PROMPT, CHUNK_WAIT)?;
        Ok(())
    }

    /// Stage a `.fuf` at `/ext/update/<name>.fuf` and run `update install`.
    /// Success is only the firmware's own affirmative line (`Verifying` and
    /// `OK` / `Update complete`, or an explicit reboot into the updater).
    /// A timeout, a dropped port, `Error:`, or silence is a failure: the
    /// device has not confirmed the package, so this does not report success.
    pub fn flash_fuf(&mut self, local: &Path) -> Result<(), FlipperError> {
        let name = local
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| name.ends_with(".fuf") && is_single_token(name))
            .ok_or_else(|| {
                FlipperError::Protocol(format!("{} is not a single-token .fuf", local.display()))
            })?;
        let mkdir = self.command("storage mkdir \"/ext/update\"", CHUNK_WAIT)?;
        if mkdir.contains("Storage error:") && !mkdir.contains("already exist") {
            return Err(FlipperError::Storage(mkdir));
        }
        let device_path = format!("/ext/update/{name}");
        self.write_file(local, &device_path)?;
        let install_wait = self.install_wait;
        let exchange = {
            let (port, rx) = self.opened()?;
            drain_stale(port, rx);
            write_line(port, &format!("update install \"{device_path}\""))?;
            // The port drops when the updater reboots. That is transport evidence
            // only after the CLI has already affirmed the package.
            read_until(port, rx, PROMPT, install_wait)
        };
        let text = match &exchange {
            Ok(frame) => String::from_utf8_lossy(frame).into_owned(),
            Err(_) => String::from_utf8_lossy(&self.rx).into_owned(),
        };
        let affirmed = install_affirmed(&text);
        self.drop_port();
        if text.contains("Error:") || text.contains("Stopping update.") {
            return Err(FlipperError::Storage(text.trim().to_owned()));
        }
        if let Err(error) = exchange {
            if affirmed {
                return Ok(());
            }
            return Err(error);
        }
        if affirmed {
            return Ok(());
        }
        Err(FlipperError::Protocol(format!(
            "update install did not affirm the package: {}",
            text.trim()
        )))
    }

    fn take_until(&mut self, marker: &[u8], timeout: Duration) -> Result<Vec<u8>, FlipperError> {
        let (port, rx) = self.opened()?;
        read_until(port, rx, marker, timeout)
    }

    fn take_exact(&mut self, buf: &mut [u8], timeout: Duration) -> Result<(), FlipperError> {
        let (port, rx) = self.opened()?;
        read_exact(port, rx, buf, timeout)
    }
}

fn is_single_token(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('"')
        && !name.contains(' ')
        && !name.bytes().any(|byte| byte.is_ascii_control())
}

/// The firmware affirms an install only by saying so. Silence, a timeout,
/// and `Error:` are not affirmation. `Stopping update.` is the CLI refusing
/// the package, so it is never affirmative even if another line says OK.
fn install_affirmed(text: &str) -> bool {
    if text.contains("Error:") || text.contains("Stopping update.") {
        return false;
    }
    let starts = |prefix: &str| {
        text.lines()
            .any(|line| line.trim_start().starts_with(prefix))
    };
    let ok = text
        .lines()
        .any(|line| line.trim().trim_end_matches('.') == "OK");
    let verified = starts("Verifying") && (ok || starts("Update complete"));
    verified || starts("Rebooting") || starts("Update complete")
}

fn require_storage_path(path: &str) -> Result<(), FlipperError> {
    let ok = (path.starts_with("/ext/") || path.starts_with("/int/"))
        && !path.contains('"')
        && !path.contains("..")
        && !path.bytes().any(|byte| byte.is_ascii_control());
    if ok {
        Ok(())
    } else {
        Err(FlipperError::Protocol(format!(
            "{path:?} is not an /ext or /int storage path"
        )))
    }
}

fn parse_size(line: &str) -> Result<usize, FlipperError> {
    let Some(rest) = line.trim().strip_prefix("Size:") else {
        return Err(FlipperError::Protocol(format!(
            "read_chunks size line was {line:?}"
        )));
    };
    rest.trim()
        .parse::<usize>()
        .map_err(|_| FlipperError::Protocol(format!("read_chunks size was not a number: {line:?}")))
}

fn strip_exchange(buf: &[u8], cmd: &str) -> String {
    String::from_utf8_lossy(buf)
        .replace("\r\n", "\n")
        .lines()
        .filter(|line| !line.is_empty() && *line != cmd && *line != ">: ")
        .collect::<Vec<_>>()
        .join("\n")
}

fn write_line(port: &mut File, cmd: &str) -> Result<(), FlipperError> {
    port.write_all(cmd.as_bytes())
        .map_err(|_| FlipperError::Unavailable)?;
    port.write_all(EOL).map_err(|_| FlipperError::Unavailable)
}

fn drain_stale(port: &mut File, pending: &mut Vec<u8>) {
    pending.clear();
    let _ = rustix::fs::fcntl_setfl(port.as_fd(), rustix::fs::OFlags::NONBLOCK);
    let mut stale = [0_u8; 4096];
    while matches!(port.read(&mut stale), Ok(n) if n > 0) {}
    let _ = rustix::fs::fcntl_setfl(port.as_fd(), rustix::fs::OFlags::empty());
}

/// Read until `marker`, returning exactly the bytes through that delimiter.
/// Bytes after it stay in `pending` for the next line or raw read. On
/// timeout the partial stays in `pending` and is not returned.
fn read_until<R: Read>(
    port: &mut R,
    pending: &mut Vec<u8>,
    marker: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, FlipperError> {
    let deadline = Instant::now() + timeout;
    let mut chunk = [0_u8; 1024];
    loop {
        if let Some(frame) = take_through(pending, marker) {
            return Ok(frame);
        }
        if Instant::now() >= deadline {
            return Err(FlipperError::Timeout);
        }
        match port.read(&mut chunk) {
            Ok(0) => std::thread::sleep(READ_POLL),
            Ok(n) => pending.extend_from_slice(&chunk[..n]),
            Err(error) if is_wait(error.kind()) => std::thread::sleep(READ_POLL),
            Err(_) => return Err(FlipperError::Unavailable),
        }
    }
}

fn read_exact<R: Read>(
    port: &mut R,
    pending: &mut Vec<u8>,
    buf: &mut [u8],
    timeout: Duration,
) -> Result<(), FlipperError> {
    let deadline = Instant::now() + timeout;
    let mut filled = 0;
    if !pending.is_empty() {
        let n = pending.len().min(buf.len());
        buf[..n].copy_from_slice(&pending[..n]);
        pending.drain(..n);
        filled = n;
    }
    while filled < buf.len() {
        if Instant::now() >= deadline {
            return Err(FlipperError::Timeout);
        }
        match port.read(&mut buf[filled..]) {
            Ok(0) => std::thread::sleep(READ_POLL),
            Ok(n) => filled += n,
            Err(error) if is_wait(error.kind()) => std::thread::sleep(READ_POLL),
            Err(_) => return Err(FlipperError::Unavailable),
        }
    }
    Ok(())
}

fn take_through(pending: &mut Vec<u8>, marker: &[u8]) -> Option<Vec<u8>> {
    let end = pending
        .windows(marker.len())
        .position(|window| window == marker)?
        + marker.len();
    let frame = pending[..end].to_vec();
    pending.drain(..end);
    Some(frame)
}

fn is_wait(kind: std::io::ErrorKind) -> bool {
    kind == std::io::ErrorKind::WouldBlock || kind == std::io::ErrorKind::TimedOut
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_paths_stay_on_ext_or_int() {
        assert!(require_storage_path("/ext/update/app.fuf").is_ok());
        assert!(require_storage_path("/int/name").is_ok());
        assert!(require_storage_path("/ext/../etc/passwd").is_err());
        assert!(require_storage_path("ext/nope").is_err());
        assert!(require_storage_path("/ext/quote\".fuf").is_err());
    }

    #[test]
    fn install_success_requires_affirmative_firmware_evidence() {
        assert!(install_affirmed("Verifying\r\nOK\r\nRebooting\r\n"));
        assert!(install_affirmed("Update complete\r\n"));
        assert!(!install_affirmed(""));
        assert!(!install_affirmed("Verifying\r\n"));
        assert!(!install_affirmed("Error: bad package\r\n"));
        assert!(!install_affirmed("Verifying\r\nOK\r\nStopping update.\r\n"));
        assert!(install_affirmed("Verifying update package\r\nOK.\r\n"));
        assert!(!install_affirmed("Verifying\r\nTOKEN BROKEN\r\n"));
    }

    #[test]
    fn a_coalesced_read_keeps_bytes_after_each_delimiter() {
        // One USB read returns the echo, the size, the readiness line, the
        // raw chunk, and the prompt. Each consumer takes only its frame.
        let blob = b"storage read_chunks \"/ext/a\"\r\nSize: 4\r\nReady?\r\nWXYZ>: ";
        let mut port = std::io::Cursor::new(&blob[..]);
        let mut pending = Vec::new();
        let timeout = Duration::from_secs(2);
        let echo = read_until(&mut port, &mut pending, EOL, timeout).expect("echo");
        assert!(echo.ends_with(EOL), "{echo:?}");
        assert!(
            !echo
                .windows(b"Size:".len())
                .any(|window| window == b"Size:"),
            "echo consumed the size line: {echo:?}"
        );
        let size = read_until(&mut port, &mut pending, EOL, timeout).expect("size");
        assert_eq!(parse_size(std::str::from_utf8(&size).unwrap()).unwrap(), 4);
        let ready = read_until(&mut port, &mut pending, b"Ready?\r\n", timeout).expect("ready");
        assert!(ready.ends_with(b"Ready?\r\n"), "{ready:?}");
        let mut raw = [0_u8; 4];
        read_exact(&mut port, &mut pending, &mut raw, timeout).expect("chunk");
        assert_eq!(&raw, b"WXYZ");
        let prompt = read_until(&mut port, &mut pending, PROMPT, timeout).expect("prompt");
        assert_eq!(prompt, b">: ");
        assert!(pending.is_empty(), "leftover {pending:?}");
    }
}
