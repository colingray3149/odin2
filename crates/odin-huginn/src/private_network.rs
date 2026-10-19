use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

use async_trait::async_trait;
use odin_domain::huginn::TailnetNodeId;
use thiserror::Error;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TailnetError {
    #[error("peer {addr} was rejected: {reason}")]
    PeerRejected {
        addr: SocketAddr,
        reason: &'static str,
    },
    #[error("listener {addr} was rejected: {reason}")]
    ListenerRejected {
        addr: SocketAddr,
        reason: &'static str,
    },
    #[error("tailnet peer verification is unavailable: {0}")]
    Unavailable(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedTailnetPeer {
    peer: SocketAddr,
    tailnet_node_id: Option<TailnetNodeId>,
}

impl VerifiedTailnetPeer {
    pub const fn local(peer: SocketAddr) -> Self {
        Self {
            peer,
            tailnet_node_id: None,
        }
    }

    pub const fn tailnet(peer: SocketAddr, tailnet_node_id: Option<TailnetNodeId>) -> Self {
        Self {
            peer,
            tailnet_node_id,
        }
    }

    pub const fn addr(&self) -> SocketAddr {
        self.peer
    }

    pub const fn tailnet_node_id(&self) -> Option<&TailnetNodeId> {
        self.tailnet_node_id.as_ref()
    }

    pub fn is_loopback(&self) -> bool {
        self.peer.ip().is_loopback()
    }
}

#[async_trait]
pub trait TailnetVerifier: Send + Sync {
    async fn verify_peer(&self, peer: SocketAddr) -> Result<VerifiedTailnetPeer, TailnetError>;

    /// Node configured for a tailnet address. `tailscale serve` stamps that
    /// address in `X-Forwarded-For`; an unknown address is not a local client.
    fn node_for_addr(&self, ip: IpAddr) -> Option<TailnetNodeId>;
}

pub fn is_tailnet_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets[0] == 100 && (64..=127).contains(&octets[1])
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            segments[0] == 0xfd7a && segments[1] == 0x115c && segments[2] == 0xa1e0
        }
    }
}

pub fn classify_listener(ip: IpAddr) -> Result<crate::config::BindScope, TailnetError> {
    if ip.is_loopback() {
        return Ok(crate::config::BindScope::Loopback);
    }
    if is_tailnet_address(ip) {
        return Ok(crate::config::BindScope::Tailnet);
    }
    Err(TailnetError::ListenerRejected {
        addr: SocketAddr::new(ip, 0),
        reason: "address is neither loopback nor an explicit tailscale address",
    })
}

#[derive(Clone, Debug, Default)]
pub struct InterfaceTailnetVerifier {
    node_by_addr: BTreeMap<IpAddr, TailnetNodeId>,
}

impl InterfaceTailnetVerifier {
    pub fn new(node_by_addr: BTreeMap<IpAddr, TailnetNodeId>) -> Self {
        Self { node_by_addr }
    }
}

#[async_trait]
impl TailnetVerifier for InterfaceTailnetVerifier {
    async fn verify_peer(&self, peer: SocketAddr) -> Result<VerifiedTailnetPeer, TailnetError> {
        let ip = peer.ip();
        if ip.is_loopback() {
            // Serve also arrives as loopback. The router binds a node from
            // X-Forwarded-For before the device check. A bare loopback peer
            // is a process on this host.
            return Ok(VerifiedTailnetPeer::local(peer));
        }
        if is_tailnet_address(ip) {
            let tailnet_node_id =
                self.node_by_addr
                    .get(&ip)
                    .cloned()
                    .ok_or(TailnetError::PeerRejected {
                        addr: peer,
                        reason: "tailscale peer identity is not configured",
                    })?;
            return Ok(VerifiedTailnetPeer::tailnet(peer, Some(tailnet_node_id)));
        }
        Err(TailnetError::PeerRejected {
            addr: peer,
            reason: "source is neither loopback nor a tailscale address",
        })
    }

    fn node_for_addr(&self, ip: IpAddr) -> Option<TailnetNodeId> {
        self.node_by_addr.get(&ip).cloned()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use odin_domain::huginn::TailnetNodeId;

    use super::{classify_listener, InterfaceTailnetVerifier, TailnetError, TailnetVerifier};
    use crate::config::BindScope;

    #[test]
    fn listener_accepts_only_loopback_and_explicit_tailnet_ranges() {
        for ip in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(127, 42, 1, 9)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            assert_eq!(classify_listener(ip), Ok(BindScope::Loopback));
        }
        for ip in [
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(100, 127, 255, 254)),
            "fd7a:115c:a1e0::7".parse().expect("tailscale ula"),
        ] {
            assert_eq!(classify_listener(ip), Ok(BindScope::Tailnet));
        }
    }

    #[test]
    fn listener_rejects_wildcard_lan_public_and_discovery_addresses() {
        for ip in [
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 1, 2)),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
            IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250)),
            IpAddr::V4(Ipv4Addr::BROADCAST),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            "fe80::1".parse().expect("link local"),
            "ff02::fb".parse().expect("mdns multicast"),
        ] {
            assert!(matches!(
                classify_listener(ip),
                Err(TailnetError::ListenerRejected { .. })
            ));
        }
    }

    #[tokio::test]
    async fn peer_verification_ignores_non_tailnet_sources() {
        let node = TailnetNodeId::new("node.phone").expect("node id");
        let tailnet_ip = IpAddr::V4(Ipv4Addr::new(100, 100, 1, 9));
        let verifier = InterfaceTailnetVerifier::new(BTreeMap::from([(tailnet_ip, node.clone())]));

        let local = verifier
            .verify_peer(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234))
            .await
            .expect("loopback");
        assert!(local.is_loopback());
        assert_eq!(local.tailnet_node_id(), None);

        let remote = verifier
            .verify_peer(SocketAddr::new(tailnet_ip, 443))
            .await
            .expect("tailnet peer");
        assert_eq!(remote.tailnet_node_id(), Some(&node));
        assert_eq!(verifier.node_for_addr(tailnet_ip), Some(node));
        assert_eq!(
            verifier.node_for_addr(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            None
        );

        assert!(matches!(
            verifier
                .verify_peer(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 7)),
                    443,
                ))
                .await,
            Err(TailnetError::PeerRejected { .. })
        ));
    }
}
