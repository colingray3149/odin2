use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessErrorCode {
    EmptyArgv,
    ArgvItemLimit,
    ArgvByteLimit,
    RelativeExecutable,
    NulByte,
    EnvironmentKey,
    EnvironmentNotAllowed,
    EnvironmentValue,
    InvalidLimits,
    Spawn,
    Identity,
    Io,
}

#[derive(Debug)]
pub struct ProcessError {
    code: ProcessErrorCode,
    message: String,
}

impl ProcessError {
    pub(crate) fn new(code: ProcessErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> ProcessErrorCode {
        self.code
    }
}

impl fmt::Display for ProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ProcessError {}
