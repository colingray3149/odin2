//! Durable semantic session identity.

use std::collections::BTreeMap;

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
    /// Declared egress hosts that did not resolve at launch, with the
    /// cause: the pod cannot reach them. Empty (and absent on the wire)
    /// when every host resolved.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unresolved_hosts: BTreeMap<String, String>,
    /// The run limits the launch resolved: the profile's declared values
    /// with the launch's overrides applied. Absent when none was declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<WorkloadLimits>,
    /// What the run is about: odin-recon runs on these once the pod is up.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub seeds: Vec<String>,
}

/// One workload run's resolved limits. A field is `None` when neither the
/// profile nor the launch declared it, and then nothing enforces it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkloadLimits {
    /// Hard wall-clock lifetime of the run, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_seconds: Option<u32>,
    /// Output tokens the context guard keeps free for the model's answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_reserve_tokens: Option<u32>,
    /// Percent of the context window at which the run checkpoints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_percent: Option<u8>,
    /// Context rollovers the run may take before it stops.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_rollovers: Option<u8>,
    /// Largest tool result, in bytes, the run keeps inline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_result_bytes: Option<u32>,
}

/// One staged launch input of an agent pod: the ledger artifact and the
/// exact read-only in-pod path its verified bytes are mounted at.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkloadInputBinding {
    pub artifact_id: String,
    pub path: String,
    /// The launch prompt, staged last: the opening message quotes it and
    /// names this input when it is cut. Absent on earlier manifests.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub prompt: bool,
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

/// The whole answer of an unprompted turn (wake, routine, report, incident)
/// with nothing for the owner: nothing is sent. The one definition.
pub const QUIET_REPLY: &str = "[quiet]";

/// Removes the quiet control token and adjacent punctuation, leaving only owner-facing text.
pub fn without_quiet_token(answer: &str) -> &str {
    let mut text = answer.trim();
    if let Some(rest) = text.strip_prefix(QUIET_REPLY) {
        text = rest.trim_start_matches(|character: char| {
            character.is_whitespace()
                || matches!(character, '\u{2014}' | '\u{2013}' | '-' | ':' | ',' | '.')
        });
    }
    if let Some(rest) = text.strip_suffix(QUIET_REPLY) {
        text = rest.trim_end();
    }
    text
}

/// Title prefix of the seat session that reviews one pod; the pod's uid follows.
pub const POD_REVIEW_TITLE_PREFIX: &str = "Pod review ";

impl SessionManifest {
    /// A pod reviewer works from the launch input and digest it is sent, not the seat's memory.
    pub fn is_pod_review(&self) -> bool {
        self.title
            .as_deref()
            .is_some_and(|title| title.starts_with(POD_REVIEW_TITLE_PREFIX))
    }
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
