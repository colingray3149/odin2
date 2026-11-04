//! The VPN transport kube workloads use for VPN-required egress.

use super::super::odind::OdindVpnTransport;
use super::{require_absolute, ConfigError};

pub(super) fn validate(transport: &OdindVpnTransport) -> Result<(), ConfigError> {
    if transport.port == 0 {
        return Err(ConfigError::Invalid(
            "kube.vpn_transport.port must be a UDP port".to_owned(),
        ));
    }
    if !transport.endpoint.is_ipv4()
        || transport.endpoint.is_unspecified()
        || transport.endpoint.is_multicast()
    {
        return Err(ConfigError::Invalid(format!(
            "kube.vpn_transport.endpoint {} must be a reachable IPv4 address",
            transport.endpoint
        )));
    }
    if !odin_registry::schema::valid_pod_path(&transport.launcher.display().to_string()) {
        return Err(ConfigError::Invalid(
            "kube.vpn_transport.launcher must be an absolute in-image path".to_owned(),
        ));
    }
    if let Some(resolver) = &transport.resolver {
        require_absolute("kube.vpn_transport.resolver", resolver)?;
    }
    Ok(())
}
