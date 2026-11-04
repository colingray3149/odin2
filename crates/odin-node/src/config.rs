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

#[cfg(test)]
mod tests {
    use odin_registry::schema::parse_object_toml;

    use super::*;

    const NODE: &str = r#"
schema = "odin.registry.v1"
kind = "node"
enabled = true
description = "test node"
host = "mini"
role = "control"
capabilities = ["operator"]
allow_workloads = true
authoritative_state = true
"#;

    const HOST: &str = r#"
schema = "odin.registry.v1"
kind = "host"
enabled = true
description = "test host"
hardware = "test"
role = "control"
tailscale = "mini"
enrolled = true
"#;

    fn declared(kind: RegistryKind, id: &str, toml: &str) -> RegistryObject {
        parse_object_toml(kind, id, format!("registry/{id}.toml"), toml)
            .expect("the fixture parses under the registry's own schema")
    }

    fn startup(node: &str, host: &str) -> Result<NodeIdentity, NodeConfigError> {
        let registry = [
            declared(RegistryKind::Node, "mini", node),
            declared(RegistryKind::Host, "mini", host),
        ];
        NodeIdentity::from_snapshot("mini", &registry)
    }

    #[test]
    fn startup_needs_an_enabled_node_on_an_enrolled_host_with_the_same_role() {
        let identity = startup(NODE, HOST).expect("a consistent snapshot starts");
        assert_eq!(identity.node(), "mini");

        let disabled = NODE.replace("enabled = true", "enabled = false");
        assert!(matches!(
            startup(&disabled, HOST),
            Err(NodeConfigError::NodeDisabled { .. })
        ));
        let unenrolled = HOST.replace("enrolled = true", "enrolled = false");
        assert!(matches!(
            startup(NODE, &unenrolled),
            Err(NodeConfigError::HostUnavailable { .. })
        ));
        let other_role = HOST.replace(r#"role = "control""#, r#"role = "worker""#);
        assert!(matches!(
            startup(NODE, &other_role),
            Err(NodeConfigError::RoleMismatch { .. })
        ));
        assert!(matches!(
            NodeIdentity::from_snapshot("mini", &[declared(RegistryKind::Host, "mini", HOST)]),
            Err(NodeConfigError::NodeMissing { .. })
        ));
        assert!(matches!(
            NodeIdentity::from_snapshot("mini", &[declared(RegistryKind::Node, "mini", NODE)]),
            Err(NodeConfigError::HostMissing { .. })
        ));
    }

    #[test]
    fn pods_need_the_declared_gateway_endpoint() {
        let identity = startup(NODE, HOST).expect("starts");
        assert!(matches!(
            identity.gateway_endpoint(),
            Err(NodeConfigError::GatewayEndpointMissing { .. })
        ));
        let declared = format!("{NODE}gateway_endpoint = \"http://100.64.0.9:14000/v1\"\n");
        startup(&declared, HOST)
            .expect("starts")
            .gateway_endpoint()
            .expect("a declared endpoint parses");
        let loopback = format!("{NODE}gateway_endpoint = \"http://127.0.0.1:14000/v1\"\n");
        assert!(matches!(
            startup(&loopback, HOST).expect("starts").gateway_endpoint(),
            Err(NodeConfigError::GatewayEndpointInvalid { .. })
        ));
    }
}
