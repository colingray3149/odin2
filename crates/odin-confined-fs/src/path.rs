//! Inspect original path bytes because `Path::components` normalizes interior `.` components.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::ConfinedError;

pub fn validate_relative_path(path: &Path) -> Result<(), ConfinedError> {
    relative_components(path).map(|_| ())
}

pub(crate) fn relative_components(path: &Path) -> Result<Vec<&OsStr>, ConfinedError> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() {
        return Err(ConfinedError::EmptyPath);
    }
    if bytes[0] == b'/' {
        return Err(ConfinedError::AbsolutePath);
    }
    split_components(bytes)
}

pub(crate) fn absolute_components(path: &Path) -> Result<Vec<&OsStr>, ConfinedError> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.first() != Some(&b'/') {
        return Err(ConfinedError::RootNotAbsolute);
    }
    if bytes == b"/" {
        return Ok(Vec::new());
    }
    split_components(&bytes[1..])
}

fn split_components(bytes: &[u8]) -> Result<Vec<&OsStr>, ConfinedError> {
    bytes
        .split(|byte| *byte == b'/')
        .map(|component| match component {
            b"" => Err(ConfinedError::EmptyComponent),
            b"." => Err(ConfinedError::DotSegment),
            b".." => Err(ConfinedError::DotDotSegment),
            value if value.contains(&0) => Err(ConfinedError::NulByte),
            value => Ok(OsStr::from_bytes(value)),
        })
        .collect()
}

pub(crate) fn display_component(component: &OsStr) -> String {
    component.to_string_lossy().into_owned()
}

pub(crate) fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
