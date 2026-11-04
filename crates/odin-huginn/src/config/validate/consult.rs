//! Validation for official-client consultation configuration.

use super::super::huginn::ConfigError;
use super::super::odind::OdindConsultConfig;
use super::require_absolute;

pub(super) fn validate_consult(consult: &OdindConsultConfig) -> Result<(), ConfigError> {
    if let Some(agy) = &consult.agy {
        if agy.profile.trim().is_empty() || agy.profile.len() > 32 {
            return Err(ConfigError::Invalid(
                "hermes.consult.agy.profile must be the aisw antigravity profile \
                 name (1..=32 characters)"
                    .to_owned(),
            ));
        }
        for (field, path) in [
            ("hermes.consult.agy.binary", &agy.binary),
            ("hermes.consult.agy.aisw", &agy.aisw),
        ] {
            require_absolute(field, path)?;
        }
    }
    Ok(())
}
