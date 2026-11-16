//! Live lane artifacts and transfer manager composition.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use odin_domain::SeatId;
use odin_huginn::NodePosture;
use odin_omp::live::lane_artifacts::{FsLaneArtifactPort, LaneArtifactPort, LaneTransferBridge};
use odin_omp::live::ledger::LiveLedger;
use odin_omp::live::transfer::{
    RegistryTransferLaneResolver, SeatTransferLanes, TransferLaneResolver, TransferManager,
};

pub(super) fn compose(
    huginn_root: &Path,
    state_root: &Path,
    live_ledger: &Arc<dyn LiveLedger>,
    posture: NodePosture,
    transfer_lanes: BTreeMap<SeatId, SeatTransferLanes>,
) -> Result<(Arc<LaneTransferBridge>, Arc<TransferManager>), String> {
    let lane_port: Arc<dyn LaneArtifactPort> = Arc::new(crate::upload_share::SharedUploads {
        inner: Arc::new(
            FsLaneArtifactPort::open(huginn_root.join("lane-artifacts"))
                .map_err(|error| error.to_string())?,
        ),
        ledger: Arc::clone(live_ledger),
        state_root: state_root.to_path_buf(),
    });
    let lane_artifacts = Arc::new(LaneTransferBridge::new(lane_port));
    // A seatless follower has no transfer lanes; its lookups remain typed denials.
    let lane_resolver: Arc<dyn TransferLaneResolver> =
        if posture == NodePosture::Follower && transfer_lanes.is_empty() {
            Arc::new(RegistryTransferLaneResolver::read_only(Arc::clone(
                live_ledger,
            )))
        } else {
            Arc::new(
                RegistryTransferLaneResolver::new(Arc::clone(live_ledger), transfer_lanes)
                    .map_err(|error| error.to_string())?,
            )
        };
    let transfers = Arc::new(
        TransferManager::open(
            huginn_root.join("live-transfers"),
            Arc::clone(live_ledger),
            lane_resolver,
            Arc::clone(&lane_artifacts),
        )
        .map_err(|error| error.to_string())?,
    );
    Ok((lane_artifacts, transfers))
}
