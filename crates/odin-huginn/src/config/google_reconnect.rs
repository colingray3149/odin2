//! Validation of phone-reachable Google consent declarations.

use std::collections::BTreeSet;

use super::huginn::{range, ConfigError};
use super::odind::OdindGoogleReconnectConfig;
use super::validate::require_absolute;

impl OdindGoogleReconnectConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        consent_url(
            "hermes.accounts.reconnect.authorization_url",
            &self.authorization_url,
        )?;
        consent_url("hermes.accounts.reconnect.redirect_uri", &self.redirect_uri)?;
        require_absolute(
            "hermes.accounts.reconnect.client_config",
            &self.client_config,
        )?;
        if self.scopes.is_empty() || self.scopes.len() > 16 {
            return Err(ConfigError::Invalid(
                "hermes.accounts.reconnect.scopes must contain 1..=16 entries".to_owned(),
            ));
        }
        let mut seen = BTreeSet::new();
        for scope in &self.scopes {
            let url = url::Url::parse(scope).map_err(|error| {
                ConfigError::Invalid(format!("invalid Google reconnect scope: {error}"))
            })?;
            if url.scheme() != "https"
                || url.host_str().is_none()
                || scope.chars().count() > 256
                || scope.chars().any(char::is_whitespace)
            {
                return Err(ConfigError::Invalid("hermes.accounts.reconnect.scopes must be HTTPS URLs of at most 256 characters without whitespace".to_owned()));
            }
            if !seen.insert(scope) {
                return Err(ConfigError::Invalid(format!(
                    "hermes.accounts.reconnect.scopes repeats {scope:?}"
                )));
            }
        }
        range(
            "hermes.accounts.reconnect.timeout_seconds",
            self.timeout_seconds as i64,
            1,
            600,
        )?;
        if self.application_name.trim().is_empty()
            || self.application_name.chars().count() > 128
            || self.application_name.chars().any(char::is_control)
        {
            return Err(ConfigError::Invalid("hermes.accounts.reconnect.application_name must be 1..=128 characters without control characters".to_owned()));
        }
        Ok(())
    }
}

fn consent_url(field: &'static str, value: &str) -> Result<(), ConfigError> {
    let url = url::Url::parse(value)
        .map_err(|error| ConfigError::Invalid(format!("{field} must be an HTTPS URL: {error}")))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(ConfigError::Invalid(format!(
            "{field} must be HTTPS with a host and no credentials, query or fragment"
        )));
    }
    Ok(())
}
