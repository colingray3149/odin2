//! Stable error classes for confined filesystem operations.

use std::error::Error;
use std::fmt;
use std::io;

use crate::Identity;

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConfinedError {
    AbsolutePath,
    RootNotAbsolute,
    EmptyPath,
    /// A path contained an empty component, such as `a//b` or `a/`.
    EmptyComponent,
    DotSegment,
    DotDotSegment,
    NulByte,
    /// The requested mode contained bits outside `0o777`.
    InvalidMode(u32),
    SymlinkEncountered {
        component: String,
    },
    NotADirectory {
        component: String,
    },
    NotARegularFile {
        component: String,
    },
    ComponentMissing {
        component: String,
    },
    PermissionDenied {
        component: String,
    },
    AlreadyExists {
        component: String,
    },
    /// The absolute root name resolved to a different object after a barrier.
    RootSwapped {
        expected: Identity,
        actual: Identity,
    },
    RenameRace {
        path: String,
    },
    FinalLeafRace {
        path: String,
    },
    /// A private root was not mode `0700` (subject to the process umask when created).
    PrivateRootNotPrivate {
        mode: u32,
    },
    /// Cleanup could not remove the temporary file or restore the retained replaced leaf.
    AtomicCleanupFailed {
        component: String,
        reason: String,
    },
    Io {
        component: String,
        reason: String,
    },
}

impl ConfinedError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::AbsolutePath => "absolute_path",
            Self::RootNotAbsolute => "root_not_absolute",
            Self::EmptyPath => "empty_path",
            Self::EmptyComponent => "empty_component",
            Self::DotSegment => "dot_segment",
            Self::DotDotSegment => "dot_dot_segment",
            Self::NulByte => "nul_byte",
            Self::InvalidMode(_) => "invalid_mode",
            Self::SymlinkEncountered { .. } => "symlink_encountered",
            Self::NotADirectory { .. } => "not_a_directory",
            Self::NotARegularFile { .. } => "not_a_regular_file",
            Self::ComponentMissing { .. } => "component_missing",
            Self::PermissionDenied { .. } => "permission_denied",
            Self::AlreadyExists { .. } => "already_exists",
            Self::RootSwapped { .. } => "root_swapped",
            Self::RenameRace { .. } => "rename_race",
            Self::FinalLeafRace { .. } => "final_leaf_race",
            Self::PrivateRootNotPrivate { .. } => "private_root_not_private",
            Self::AtomicCleanupFailed { .. } => "atomic_cleanup_failed",
            Self::Io { .. } => "io",
        }
    }
}

impl fmt::Display for ConfinedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AbsolutePath => f.write_str("child path is absolute"),
            Self::RootNotAbsolute => f.write_str("root path is not absolute"),
            Self::EmptyPath => f.write_str("child path is empty"),
            Self::EmptyComponent => f.write_str("path contains an empty component"),
            Self::DotSegment => f.write_str("path contains a `.` component"),
            Self::DotDotSegment => f.write_str("path contains a `..` component"),
            Self::NulByte => f.write_str("path contains a NUL byte"),
            Self::InvalidMode(mode) => write!(f, "invalid permission mode {mode:#o}"),
            Self::SymlinkEncountered { component } => {
                write!(f, "symlink encountered at `{component}`")
            }
            Self::NotADirectory { component } => {
                write!(f, "`{component}` is not a directory")
            }
            Self::NotARegularFile { component } => {
                write!(f, "`{component}` is not a regular file")
            }
            Self::ComponentMissing { component } => write!(f, "`{component}` is missing"),
            Self::PermissionDenied { component } => {
                write!(f, "permission denied at `{component}`")
            }
            Self::AlreadyExists { component } => write!(f, "`{component}` already exists"),
            Self::RootSwapped { expected, actual } => write!(
                f,
                "root identity changed from ({}, {}) to ({}, {})",
                expected.dev, expected.ino, actual.dev, actual.ino
            ),
            Self::RenameRace { path } => write!(f, "parent changed while opening `{path}`"),
            Self::FinalLeafRace { path } => write!(f, "leaf changed while opening `{path}`"),
            Self::PrivateRootNotPrivate { mode } => {
                write!(
                    f,
                    "private root mode must be 0700, found {:#o}",
                    mode & 0o777
                )
            }
            Self::AtomicCleanupFailed { component, reason } => {
                write!(f, "could not remove temporary `{component}`: {reason}")
            }
            Self::Io { component, reason } => write!(f, "I/O error at `{component}`: {reason}"),
        }
    }
}

impl Error for ConfinedError {}

pub fn map_io_error(error: io::Error, component: Option<&str>) -> ConfinedError {
    let component = component.unwrap_or("<root>").to_owned();
    match error.raw_os_error() {
        Some(2) => ConfinedError::ComponentMissing { component },
        Some(13 | 1) => ConfinedError::PermissionDenied { component },
        Some(17) => ConfinedError::AlreadyExists { component },
        Some(20 | 21) => ConfinedError::NotADirectory { component },
        Some(40 | 18) => ConfinedError::SymlinkEncountered { component },
        _ => ConfinedError::Io {
            component,
            reason: error.to_string(),
        },
    }
}

pub(crate) fn map_errno(error: rustix::io::Errno, component: &str) -> ConfinedError {
    map_io_error(io::Error::from(error), Some(component))
}
