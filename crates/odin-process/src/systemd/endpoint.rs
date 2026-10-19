//! Require an explicit Unix socket instead of discovering a manager endpoint.

use std::path::{Path, PathBuf};

const NO_SUCH_UNIT: &str = "org.freedesktop.systemd1.NoSuchUnit";
const UNKNOWN_INTERFACE: &str = "org.freedesktop.DBus.Error.UnknownInterface";
pub(super) const IO_ERROR_NAME: &str = "org.odin.process.Io";
pub(super) const PROTOCOL_ERROR_NAME: &str = "org.odin.process.Protocol";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BusAddress {
    UnixSocket(PathBuf),
}

impl BusAddress {
    /// Require an absolute path so the endpoint cannot depend on the working directory.
    pub fn unix_socket(path: PathBuf) -> Result<Self, String> {
        if path.as_os_str().is_empty() {
            return Err("bus address path must not be empty".to_owned());
        }
        if !path.is_absolute() {
            return Err(format!(
                "bus address path {} must be absolute",
                path.display()
            ));
        }
        Ok(Self::UnixSocket(path))
    }

    /// Accept only an absolute path or `unix:path=` so configuration cannot enable another transport.
    pub fn parse(raw: &str) -> Result<Self, String> {
        if let Some(rest) = raw.strip_prefix("unix:") {
            let mut path = None;
            for part in rest.split(',') {
                if let Some(value) = part.strip_prefix("path=") {
                    if path.is_some() {
                        return Err("unix bus address carries more than one path=".to_owned());
                    }
                    path = Some(value.to_owned());
                } else if part.starts_with("dir=")
                    || part.starts_with("abstract=")
                    || part.starts_with("tmpdir=")
                {
                    return Err(format!(
                        "bus address scheme {part:?} is not a registered unix path"
                    ));
                }
            }
            let path =
                path.ok_or_else(|| "unix bus address must carry exactly one path=".to_owned())?;
            return Self::unix_socket(PathBuf::from(path));
        }
        if raw.contains(':') || raw.contains("://") {
            return Err(format!("bus address scheme {raw:?} is not registered"));
        }
        Self::unix_socket(PathBuf::from(raw))
    }

    pub fn socket_path(&self) -> &Path {
        match self {
            Self::UnixSocket(path) => path,
        }
    }
}

impl std::fmt::Display for BusAddress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnixSocket(path) => write!(formatter, "unix:path={}", path.display()),
        }
    }
}

/// Preserve remote D-Bus error names; local failures use Io or Protocol names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BusError {
    pub name: String,
    pub message: String,
}

impl BusError {
    pub(crate) fn new(name: &str, message: impl Into<String>) -> Self {
        Self {
            name: name.to_owned(),
            message: message.into(),
        }
    }

    pub fn is_no_such_unit(&self) -> bool {
        self.name == NO_SUCH_UNIT
    }

    /// Missing interfaces depend on unit type; callers decide whether their absence is expected.
    pub fn is_unknown_interface(&self) -> bool {
        self.name == UNKNOWN_INTERFACE
    }

    pub fn is_transport(&self) -> bool {
        self.name == IO_ERROR_NAME || self.name == PROTOCOL_ERROR_NAME
    }
}

impl std::fmt::Display for BusError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.name, self.message)
    }
}

impl std::error::Error for BusError {}
