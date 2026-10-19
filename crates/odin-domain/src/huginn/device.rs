use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::Digest;

use super::ids::{ConnectionId, DeviceId, TailnetNodeId};

/// Only the credential digest crosses this domain boundary; plaintext credentials are never part
/// of the durable or wire model.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ColinDevice {
    pub device_id: DeviceId,
    pub tailnet_node_id: TailnetNodeId,
    pub label: String,
    pub credential_digest: Digest,
    pub created_at: OffsetDateTime,
    pub last_seen_at: Option<OffsetDateTime>,
    pub revoked_at: Option<OffsetDateTime>,
}

/// Device identity established by the Huginn authentication boundary for one connection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedColinDevice {
    pub device_id: DeviceId,
    pub tailnet_node_id: TailnetNodeId,
    pub connection_id: ConnectionId,
}
