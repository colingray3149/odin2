//! Durable semantic session identity.

use serde::{Deserialize, Serialize};

use super::ids::{LiveSessionId, ModelName, ProviderName};
use crate::{NodeId, ProjectId, SeatId, SliceId};

/// The typed workload identity one live session carries when it was opened
/// as a declared workload environment pod: the exact published profile id,
/// the snapshot revision the launch admitted the profile from, and the
/// existing operation identity that drove the launch. The binding is
/// durable manifest state — stop/restart and daemon discovery preserve the
/// exact identity, and every projection surface observes it verbatim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkloadSessionBinding {
    pub profile: String,
    pub snapshot_revision: u64,
    pub operation: String,
    /// The declared input artifacts the launch staged read-only into the
    /// agent pod, in staging order. Empty (and absent on the wire) for a
    /// launch without inputs, so earlier durable manifests stay exact.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<WorkloadInputBinding>,
    /// The run of the session that launched this pod (`run:live:<session>`).
    /// The pod agent's plan inherits that run's accepted plan, exactly like
    /// a delegated child: the launch was the accepted work. Absent on older
    /// manifests (and on the wire), which then keep no plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launching_run: Option<String>,
}

/// One staged launch input of an agent pod: the ledger artifact and the
/// exact read-only in-pod path its verified bytes are mounted at.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkloadInputBinding {
    pub artifact_id: String,
    pub path: String,
}

/// Immutable inputs used to open and recover a live session.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionManifest {
    pub session_id: LiveSessionId,
    pub seat_id: SeatId,
    pub slice_id: SliceId,
    pub project_id: ProjectId,
    pub provider: ProviderName,
    pub model: ModelName,
    /// The admitted node the session is placed against: the exact node id
    /// the open validated against the seat binding's allowed-node set.
    /// Required manifest state — the runtime refuses a launch on any node
    /// the runtime does not itself admit.
    pub target_node: NodeId,
    pub title: Option<String>,
    pub open_tab: bool,
    /// Present exactly for workload environment sessions; `None` keeps the
    /// seat conversation manifest byte-identical, and older durable rows
    /// (serialized before this field existed) read back as `None`.
    #[serde(default)]
    pub workload: Option<WorkloadSessionBinding>,
    /// Snapshot revision recorded at admission; missing revisions resolve from
    /// retained publications, never default to current.
    #[serde(default)]
    pub served_revision: Option<u64>,
    /// Non-OMP harness and environment; `None` selects pinned OMP and is omitted from its wire manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<HarnessBinding>,
}

/// The declared harness and environment of one non-OMP session.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HarnessBinding {
    pub harness: String,
    pub environment: String,
    /// The account the agent signs in with (a handle of the harness's account kind); absent: the project's, else
    /// `default`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}
