//! Xvfb authentication and readiness probes shared by local sessions and the pod relay.

use std::fs;
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use uuid::Uuid;

pub(crate) const DISPLAY_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

pub(crate) struct XvfbAuthority {
    pub path: PathBuf,
    pub cookie: [u8; 16],
}

/// Creates a mode-0600 file containing one MIT-MAGIC-COOKIE-1 record for the display.
pub(crate) fn write_xauthority(directory: &Path, display: u16) -> Result<XvfbAuthority, io::Error> {
    let path = directory.join(format!("Xauthority-{display}"));
    let cookie = Uuid::new_v4();
    let number = display.to_string();
    let mut record = Vec::with_capacity(64);
    record.extend_from_slice(&u16::MAX.to_be_bytes());
    append_xauthority_field(&mut record, &[]);
    append_xauthority_field(&mut record, number.as_bytes());
    append_xauthority_field(&mut record, b"MIT-MAGIC-COOKIE-1");
    append_xauthority_field(&mut record, cookie.as_bytes());

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(&record)?;
    file.sync_all()?;
    Ok(XvfbAuthority {
        path,
        cookie: cookie.into_bytes(),
    })
}

fn append_xauthority_field(record: &mut Vec<u8>, value: &[u8]) {
    let length = u16::try_from(value.len()).expect("fixed Xauthority field is bounded");
    record.extend_from_slice(&length.to_be_bytes());
    record.extend_from_slice(value);
}

/// Parses a `:<number>` display name.
pub(crate) fn display_number(display: &str) -> Result<u16, ()> {
    display
        .strip_prefix(':')
        .and_then(|number| number.parse::<u16>().ok())
        .ok_or(())
}

pub(crate) fn x_socket_path(number: u16) -> PathBuf {
    PathBuf::from(format!("/tmp/.X11-unix/X{number}"))
}

pub(crate) fn x_lock_path(number: u16) -> PathBuf {
    PathBuf::from(format!("/tmp/.X{number}-lock"))
}

/// Both launch paths use screen 0 with TCP disabled and Xauthority authentication.
pub(crate) fn xvfb_argv(
    binary: &Path,
    display: &str,
    screen: &str,
    authority: &Path,
) -> Vec<std::ffi::OsString> {
    use std::ffi::OsString;
    let mut argv = vec![binary.as_os_str().to_owned(), OsString::from(display)];
    argv.extend(
        ["-screen", "0", screen, "-nolisten", "tcp", "-auth"]
            .iter()
            .map(OsString::from),
    );
    argv.push(authority.as_os_str().to_owned());
    argv
}

/// One bounded readiness probe: the display socket accepts a connection and,
/// when a cookie is supplied, authenticates it with the X11 initial
/// handshake.
pub(crate) fn display_accepts(number: u16, cookie: Option<&[u8; 16]>) -> bool {
    let Ok(stream) = UnixStream::connect(x_socket_path(number)) else {
        return false;
    };
    let Some(cookie) = cookie else {
        return true;
    };
    authenticate_display(stream, cookie).is_ok()
}

fn authenticate_display(mut stream: UnixStream, cookie: &[u8; 16]) -> Result<(), io::Error> {
    stream.set_read_timeout(Some(DISPLAY_PROBE_TIMEOUT))?;
    stream.set_write_timeout(Some(DISPLAY_PROBE_TIMEOUT))?;
    const PROTOCOL_NAME: &[u8] = b"MIT-MAGIC-COOKIE-1";
    let mut request = Vec::with_capacity(12 + PROTOCOL_NAME.len() + cookie.len() + 2);
    request.extend_from_slice(&[b'l', 0, 11, 0, 0, 0]);
    request.extend_from_slice(&(PROTOCOL_NAME.len() as u16).to_le_bytes());
    request.extend_from_slice(&(cookie.len() as u16).to_le_bytes());
    request.extend_from_slice(&[0, 0]);
    request.extend_from_slice(PROTOCOL_NAME);
    request.extend_from_slice(&[0; 2]);
    request.extend_from_slice(cookie);
    stream.write_all(&request)?;
    let mut reply = [0_u8; 8];
    stream.read_exact(&mut reply)?;
    if reply[0] != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "display rejected this runtime's authority",
        ));
    }
    Ok(())
}
