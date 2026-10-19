use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;

use crate::{ProcessError, ProcessErrorCode};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenArgv(Arc<[OsString]>);

impl FrozenArgv {
    pub fn new<I, S>(items: I, max_items: usize, max_bytes: usize) -> Result<Self, ProcessError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let values = items.into_iter().map(Into::into).collect::<Vec<_>>();
        if values.is_empty() {
            return Err(ProcessError::new(
                ProcessErrorCode::EmptyArgv,
                "argv must contain an executable",
            ));
        }
        if values.len() > max_items {
            return Err(ProcessError::new(
                ProcessErrorCode::ArgvItemLimit,
                format!("argv has {} items; ceiling is {max_items}", values.len()),
            ));
        }
        let mut bytes = 0_usize;
        for item in &values {
            let raw = item.as_os_str().as_bytes();
            if raw.contains(&0) {
                return Err(ProcessError::new(
                    ProcessErrorCode::NulByte,
                    "argv contains a NUL byte",
                ));
            }
            bytes = bytes.checked_add(raw.len()).ok_or_else(|| {
                ProcessError::new(ProcessErrorCode::ArgvByteLimit, "argv byte count overflow")
            })?;
        }
        if bytes > max_bytes {
            return Err(ProcessError::new(
                ProcessErrorCode::ArgvByteLimit,
                format!("argv is {bytes} bytes; ceiling is {max_bytes}"),
            ));
        }
        if !Path::new(&values[0]).is_absolute() {
            return Err(ProcessError::new(
                ProcessErrorCode::RelativeExecutable,
                "argv[0] must be an absolute path; PATH lookup is forbidden",
            ));
        }
        Ok(Self(values.into()))
    }

    pub fn executable(&self) -> &OsStr {
        &self.0[0]
    }

    pub fn arguments(&self) -> &[OsString] {
        &self.0[1..]
    }

    pub fn items(&self) -> &[OsString] {
        &self.0
    }
}
