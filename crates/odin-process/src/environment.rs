use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;

use crate::{ProcessError, ProcessErrorCode};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AllowlistedEnvironment(BTreeMap<OsString, OsString>);

impl AllowlistedEnvironment {
    pub fn iter(&self) -> impl Iterator<Item = (&OsStr, &OsStr)> {
        self.0
            .iter()
            .map(|(key, value)| (key.as_os_str(), value.as_os_str()))
    }

    pub fn get(&self, key: impl AsRef<OsStr>) -> Option<&OsStr> {
        self.0.get(key.as_ref()).map(OsString::as_os_str)
    }
}

#[derive(Clone, Debug)]
pub struct EnvironmentBuilder {
    allowed: BTreeSet<OsString>,
    values: BTreeMap<OsString, OsString>,
}

impl EnvironmentBuilder {
    pub fn new<I, S>(allowed: I) -> Result<Self, ProcessError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let mut keys = BTreeSet::new();
        for key in allowed {
            let key = key.into();
            validate_key(&key)?;
            keys.insert(key);
        }
        Ok(Self {
            allowed: keys,
            values: BTreeMap::new(),
        })
    }

    pub fn capture_current(mut self) -> Result<Self, ProcessError> {
        for key in &self.allowed {
            if let Some(value) = std::env::var_os(key) {
                validate_value(&value)?;
                self.values.insert(key.clone(), value);
            }
        }
        Ok(self)
    }

    pub fn set(
        mut self,
        key: impl Into<OsString>,
        value: impl Into<OsString>,
    ) -> Result<Self, ProcessError> {
        let key = key.into();
        let value = value.into();
        validate_key(&key)?;
        validate_value(&value)?;
        if !self.allowed.contains(&key) {
            return Err(ProcessError::new(
                ProcessErrorCode::EnvironmentNotAllowed,
                format!("environment key {key:?} is not allowlisted"),
            ));
        }
        self.values.insert(key, value);
        Ok(self)
    }

    pub fn build(self) -> AllowlistedEnvironment {
        AllowlistedEnvironment(self.values)
    }
}

fn validate_key(key: &OsStr) -> Result<(), ProcessError> {
    let bytes = key.as_bytes();
    if bytes.is_empty()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
        || bytes[0].is_ascii_digit()
    {
        return Err(ProcessError::new(
            ProcessErrorCode::EnvironmentKey,
            format!("invalid environment key {key:?}"),
        ));
    }
    Ok(())
}

fn validate_value(value: &OsStr) -> Result<(), ProcessError> {
    if value.as_bytes().contains(&0) {
        return Err(ProcessError::new(
            ProcessErrorCode::EnvironmentValue,
            "environment value contains a NUL byte",
        ));
    }
    Ok(())
}
