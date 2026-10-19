//! Resolve handles only through `[gateway_host_credentials]`, without
//! undeclared environment fallbacks. Values reach the transport as redacted,
//! zeroized bytes and must never be logged or surfaced.

use std::collections::BTreeMap;

use odin_huginn::config::OdindGatewayHostCredential;

/// Errors identify the handle and source, never the secret value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum HostCredentialError {
    /// The route's credential handle has no declared source.
    UndeclaredHandle { handle: String },
    /// The declared source holds no usable (present, non-empty) value.
    MissingValue { handle: String, environment: String },
}

impl std::fmt::Display for HostCredentialError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UndeclaredHandle { handle } => write!(
                formatter,
                "gateway credential handle {handle:?} has no declared host custody; refusing \
                 before any gateway use"
            ),
            Self::MissingValue {
                handle,
                environment,
            } => write!(
                formatter,
                "gateway credential handle {handle:?} declares host source {environment:?}, \
                 which holds no value; refusing before any gateway use"
            ),
        }
    }
}

/// The injected environment reader resolves declared variable names only;
/// unset or empty values are rejected.
pub(crate) fn resolve_gateway_credential(
    custody: &BTreeMap<String, OdindGatewayHostCredential>,
    requested_handle: &str,
    environment: &mut dyn FnMut(&str) -> Option<String>,
) -> Result<Vec<u8>, HostCredentialError> {
    let Some(source) = custody.get(requested_handle) else {
        return Err(HostCredentialError::UndeclaredHandle {
            handle: requested_handle.to_owned(),
        });
    };
    let value = environment(source.environment())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| HostCredentialError::MissingValue {
            handle: requested_handle.to_owned(),
            environment: source.environment().to_owned(),
        })?;
    Ok(value.into_bytes())
}
