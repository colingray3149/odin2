//! Node placement and gateway endpoints reachable by workloads.

use std::collections::BTreeSet;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::object::RegistryKind;
use super::workload::valid_allow_host;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeToml {
    pub schema: String,
    pub kind: RegistryKind,
    pub enabled: bool,
    pub description: String,
    pub host: String,
    pub role: String,
    pub capabilities: BTreeSet<String>,
    pub allow_workloads: bool,
    pub authoritative_state: bool,
    /// Workload nodes require a non-loopback HTTP(S) endpoint because pods cannot reach host loopback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_endpoint: Option<String>,
}

/// Preserve the declared URI while exposing its effective host and port for egress rules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeGatewayEndpoint {
    endpoint: String,
    host: String,
    port: u16,
}

/// Do not echo malformed endpoint input because it may contain credentials.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum NodeGatewayEndpointError {
    #[error("the declared node gateway endpoint is empty")]
    Empty,
    #[error("the declared node gateway endpoint is not an absolute URL")]
    NotAbsolute,
    #[error("the declared node gateway endpoint must be an http(s) URL, found scheme {scheme:?}")]
    Scheme { scheme: String },
    #[error(
        "the declared node gateway endpoint must not carry embedded credentials; credential \
         custody is the declared Secret binding"
    )]
    Credentials,
    #[error("the declared node gateway endpoint names no host authority")]
    HostMissing,
    #[error("the declared node gateway host {host:?} is not a declared host name or IP literal")]
    HostInvalid { host: String },
    #[error(
        "the declared node gateway endpoint binds {host:?} ({class}), an authority no pod on the \
         node can reach"
    )]
    UnreachableAuthority { host: String, class: &'static str },
    #[error("the declared node gateway endpoint has no usable effective TCP port")]
    Port,
}

impl NodeGatewayEndpoint {
    pub fn parse(endpoint: &str) -> Result<Self, NodeGatewayEndpointError> {
        let endpoint = endpoint.trim();
        if endpoint.is_empty() {
            return Err(NodeGatewayEndpointError::Empty);
        }
        let url = url::Url::parse(endpoint).map_err(|_| NodeGatewayEndpointError::NotAbsolute)?;
        if url.scheme() != "http" && url.scheme() != "https" {
            return Err(NodeGatewayEndpointError::Scheme {
                scheme: url.scheme().to_owned(),
            });
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(NodeGatewayEndpointError::Credentials);
        }
        let (host, inadmissible) = match url.host().ok_or(NodeGatewayEndpointError::HostMissing)? {
            // Use normalized hosts so endpoint resolution and egress rules agree.
            url::Host::Domain(domain) => {
                if !valid_allow_host(domain) {
                    return Err(NodeGatewayEndpointError::HostInvalid {
                        host: domain.to_owned(),
                    });
                }
                let refusal = domain
                    .eq_ignore_ascii_case("localhost")
                    .then_some("loopback");
                (domain.to_owned(), refusal)
            }
            url::Host::Ipv4(address) => (
                address.to_string(),
                node_gateway_address_class(&IpAddr::V4(address)),
            ),
            url::Host::Ipv6(address) => (
                address.to_string(),
                node_gateway_address_class(&IpAddr::V6(address)),
            ),
        };
        if let Some(class) = inadmissible {
            return Err(NodeGatewayEndpointError::UnreachableAuthority { host, class });
        }
        let port = url
            .port_or_known_default()
            .filter(|port| *port != 0)
            .ok_or(NodeGatewayEndpointError::Port)?;
        Ok(Self {
            endpoint: endpoint.to_owned(),
            host,
            port,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.endpoint
    }

    /// IPv6 hosts omit brackets so egress rules receive a canonical address.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Use the scheme default when no explicit port is declared.
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// Share address rejection with egress resolution, including IPv4-mapped IPv6 addresses.
pub fn node_gateway_address_class(address: &IpAddr) -> Option<&'static str> {
    if let Some(v4) = match address {
        IpAddr::V4(v4) => Some(*v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    } {
        if v4.is_loopback() {
            return Some("loopback");
        }
        if v4.is_unspecified() {
            return Some("unspecified");
        }
        if v4.is_broadcast() {
            return Some("broadcast");
        }
        if v4.is_multicast() {
            return Some("multicast");
        }
        return None;
    }
    let IpAddr::V6(v6) = address else {
        return None;
    };
    if v6.is_loopback() {
        return Some("loopback");
    }
    if v6.is_unspecified() {
        return Some("unspecified");
    }
    if v6.is_multicast() {
        return Some("multicast");
    }
    None
}

impl std::fmt::Display for NodeGatewayEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.endpoint)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostToml {
    pub schema: String,
    pub kind: RegistryKind,
    pub enabled: bool,
    pub description: String,
    pub hardware: String,
    pub role: String,
    pub tailscale: String,
    pub enrolled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The accepted declaration: the URI is carried VERBATIM for the staged
    /// model config, and the pin derives the bare host plus the endpoint's
    /// effective port — for a host name and for canonical IP literals
    /// (IPv6 without brackets), which the site-host grammar cannot express.
    #[test]
    fn parse_keeps_the_declared_uri_and_derives_the_effective_port() {
        let named = NodeGatewayEndpoint::parse("http://mini:14000/v1")
            .expect("a declared node gateway endpoint");
        assert_eq!(named.as_str(), "http://mini:14000/v1");
        assert_eq!(named.host(), "mini");
        assert_eq!(named.port(), 14000);

        let v6 = NodeGatewayEndpoint::parse("http://[fd7a:115c:a1e0::5]:14000/v1")
            .expect("a canonical IPv6 literal host");
        assert_eq!(v6.host(), "fd7a:115c:a1e0::5");
        assert_eq!(v6.port(), 14000);
    }

    /// Invalid endpoints are rejected without echoing input that may contain credentials.
    #[test]
    fn parse_refuses_unreachable_credentialed_and_malformed_declarations() {
        for (declared, expected) in [
            (
                "http://localhost:14000/v1",
                NodeGatewayEndpointError::UnreachableAuthority {
                    host: "localhost".to_owned(),
                    class: "loopback",
                },
            ),
            (
                "http://127.0.0.1:14000/v1",
                NodeGatewayEndpointError::UnreachableAuthority {
                    host: "127.0.0.1".to_owned(),
                    class: "loopback",
                },
            ),
            (
                "http://[::ffff:127.0.0.1]:14000/v1",
                NodeGatewayEndpointError::UnreachableAuthority {
                    host: "::ffff:127.0.0.1".to_owned(),
                    class: "loopback",
                },
            ),
            (
                "http://0.0.0.0:14000/v1",
                NodeGatewayEndpointError::UnreachableAuthority {
                    host: "0.0.0.0".to_owned(),
                    class: "unspecified",
                },
            ),
            (
                "http://[::]:14000/v1",
                NodeGatewayEndpointError::UnreachableAuthority {
                    host: "::".to_owned(),
                    class: "unspecified",
                },
            ),
            (
                "http://224.0.0.1:14000/v1",
                NodeGatewayEndpointError::UnreachableAuthority {
                    host: "224.0.0.1".to_owned(),
                    class: "multicast",
                },
            ),
            (
                "http://user:secret@mini:14000/v1",
                NodeGatewayEndpointError::Credentials,
            ),
            (
                "ftp://mini:14000/v1",
                NodeGatewayEndpointError::Scheme {
                    scheme: "ftp".to_owned(),
                },
            ),
            (
                "//user:secret@mini/v1",
                NodeGatewayEndpointError::NotAbsolute,
            ),
        ] {
            assert_eq!(
                NodeGatewayEndpoint::parse(declared),
                Err(expected),
                "{declared:?} must refuse typed"
            );
        }
        // A malformed declaration can carry credentials: the refusal must not
        // echo any part of it.
        assert!(
            !NodeGatewayEndpointError::NotAbsolute
                .to_string()
                .contains("secret"),
            "the not-absolute refusal must never echo the declaration"
        );
    }
}
