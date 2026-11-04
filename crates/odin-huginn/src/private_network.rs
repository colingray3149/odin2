use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

use async_trait::async_trait;
use odin_domain::huginn::TailnetNodeId;
use thiserror::Error;

pub use odin_huginn_client::VerifiedTailnetPeer;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TailnetError {
    #[error("peer {addr} was rejected: {reason}")]
    PeerRejected {
        addr: SocketAddr,
        reason: &'static str,
    },
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
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use odin_domain::huginn::TailnetNodeId;

    use super::{InterfaceTailnetVerifier, TailnetError, TailnetVerifier};

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
