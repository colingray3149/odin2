//! Recheck the selected node and host before startup; registry flags do not establish availability.

use odin_registry::{ObjectConfig, RegistryKind, RegistryObject};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NodeConfigError {
    #[error("node {node:?} is absent from the registry snapshot")]
    NodeMissing { node: String },
    #[error("node {node:?} is disabled in the registry snapshot")]
    NodeDisabled { node: String },
    #[error("node {node:?} references host {host:?} that is absent from the registry snapshot")]
    HostMissing { node: String, host: String },
    #[error("node {node:?} references host {host:?} that is not both enabled and enrolled")]
    HostUnavailable { node: String, host: String },
    #[error(
        "node {node:?} role {node_role:?} does not match host {host:?} deployment role \
         {host_role:?}"
    )]
    RoleMismatch {
        node: String,
        host: String,
        node_role: String,
        host_role: String,
    },
    #[error(
        "node {node:?} declares no node-local gateway endpoint; the pods placed on it cannot \
         reach a declared model gateway"
    )]
    GatewayEndpointMissing { node: String },
    #[error("node {node:?} declares an invalid node-local gateway endpoint: {source}")]
    GatewayEndpointInvalid {
        node: String,
        #[source]
        source: odin_registry::schema::NodeGatewayEndpointError,
    },
}

/// Accessors expose declared registry state, not live node observations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeIdentity {
    node_id: String,
    gateway_endpoint: Option<String>,
}

impl NodeIdentity {
    /// Require an enabled node and enrolled host with matching roles before startup.
    pub fn from_snapshot(
        node_id: &str,
        registry: &[RegistryObject],
    ) -> Result<Self, NodeConfigError> {
        let node = registry
            .iter()
            .find(|object| object.kind() == RegistryKind::Node && object.id == node_id)
            .ok_or_else(|| NodeConfigError::NodeMissing {
                node: node_id.to_owned(),
            })?;
        if !node.enabled() {
            return Err(NodeConfigError::NodeDisabled {
                node: node_id.to_owned(),
            });
        }
        let ObjectConfig::Node(node_config) = &node.config else {
            return Err(NodeConfigError::NodeMissing {
                node: node_id.to_owned(),
            });
        };
        let host = registry
            .iter()
            .find(|object| object.kind() == RegistryKind::Host && object.id == node_config.host)
            .ok_or_else(|| NodeConfigError::HostMissing {
                node: node_id.to_owned(),
                host: node_config.host.clone(),
            })?;
        let ObjectConfig::Host(host_config) = &host.config else {
            return Err(NodeConfigError::HostMissing {
                node: node_id.to_owned(),
                host: node_config.host.clone(),
            });
        };
        if !host.enabled() || !host_config.enrolled {
            return Err(NodeConfigError::HostUnavailable {
                node: node_id.to_owned(),
                host: node_config.host.clone(),
            });
        }
        if node_config.role != host_config.role {
            return Err(NodeConfigError::RoleMismatch {
                node: node_id.to_owned(),
                host: node_config.host.clone(),
                node_role: node_config.role.clone(),
                host_role: host_config.role.clone(),
            });
        }
        Ok(Self {
            node_id: node_id.to_owned(),
            gateway_endpoint: node_config.gateway_endpoint.clone(),
        })
    }

    pub fn node(&self) -> &str {
        &self.node_id
    }

    /// Pods need the declared non-loopback gateway; a missing endpoint cannot use a local default.
    pub fn gateway_endpoint(
        &self,
    ) -> Result<odin_registry::schema::NodeGatewayEndpoint, NodeConfigError> {
        let declared = self.gateway_endpoint.as_deref().ok_or_else(|| {
            NodeConfigError::GatewayEndpointMissing {
                node: self.node_id.clone(),
            }
        })?;
        odin_registry::schema::NodeGatewayEndpoint::parse(declared).map_err(|source| {
            NodeConfigError::GatewayEndpointInvalid {
                node: self.node_id.clone(),
                source,
            }
        })
    }
}
