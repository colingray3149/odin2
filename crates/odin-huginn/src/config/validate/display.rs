//! The browser display a declared browser runs against.

use super::super::odind::{BrowserDisplaySource, OdindDisplayConfig};
use super::{require_absolute, ConfigError};

impl OdindDisplayConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        match self.source {
            BrowserDisplaySource::Xvfb => match (&self.xvfb_binary, &self.display) {
                (Some(binary), None) => require_absolute("browser.display.xvfb_binary", binary),
                _ => Err(ConfigError::Invalid(
                    "browser display source `xvfb` requires exactly an absolute xvfb_binary"
                        .to_owned(),
                )),
            },
            BrowserDisplaySource::Existing => match (&self.display, &self.xvfb_binary) {
                (Some(name), None) if !name.trim().is_empty() => Ok(()),
                _ => Err(ConfigError::Invalid(
                    "browser display source `existing` requires exactly a display name".to_owned(),
                )),
            },
        }
    }
}
