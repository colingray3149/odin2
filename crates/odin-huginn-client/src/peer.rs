use std::net::SocketAddr;

use odin_domain::huginn::TailnetNodeId;

/// A connecting peer after Huginn checked it is loopback or on the tailnet.
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
