use serde::{Deserialize, Serialize};

use super::ids::{ConnectionId, DeviceId, TailnetNodeId};

/// Device identity established by the Huginn authentication boundary for one connection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedOwnerDevice {
    pub device_id: DeviceId,
    pub tailnet_node_id: TailnetNodeId,
    pub connection_id: ConnectionId,
}
