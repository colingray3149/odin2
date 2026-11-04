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

/// POSIX single-quote one word for a remote shell.
pub fn shell_quote(word: &str) -> String {
    format!("'{}'", word.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::FrozenArgv;
    use crate::{EnvironmentBuilder, ProcessErrorCode, ProcessLimits};

    #[test]
    fn exec_inputs_are_refused_by_their_named_cause() {
        let argv = |items: &[&str], max_items, max_bytes| {
            FrozenArgv::new(items.iter().copied(), max_items, max_bytes)
                .expect_err("refused")
                .code()
        };
        assert_eq!(argv(&[], 4, 64), ProcessErrorCode::EmptyArgv);
        assert_eq!(
            argv(&["/bin/a", "b", "c"], 2, 64),
            ProcessErrorCode::ArgvItemLimit
        );
        assert_eq!(
            argv(&["/bin/a", "bcdef"], 4, 8),
            ProcessErrorCode::ArgvByteLimit
        );
        assert_eq!(argv(&["/bin/a", "b\0"], 4, 64), ProcessErrorCode::NulByte);
        assert_eq!(
            argv(&["sh", "-c"], 4, 64),
            ProcessErrorCode::RelativeExecutable
        );

        let not_listed = EnvironmentBuilder::new(["LANG"])
            .expect("keys")
            .set("PATH", "/bin")
            .expect_err("PATH was not allowlisted");
        assert_eq!(not_listed.code(), ProcessErrorCode::EnvironmentNotAllowed);

        let limits = ProcessLimits {
            timeout: std::time::Duration::ZERO,
            ..ProcessLimits::default()
        };
        assert_eq!(
            limits.validate().expect_err("zero timeout").code(),
            ProcessErrorCode::InvalidLimits
        );
    }
}
