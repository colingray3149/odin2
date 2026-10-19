//! Session sidecar helpers shared by the live authority pool: worker
//! launch, capsule provisioning, receipt observation, and private-state
//! file helpers.
//!
//! Implementation is split by responsibility under `eval_daemon/`; this file
//! stays the thin canonical facade (every public path above is a re-export)
//! and owns only the shared path-text helper.

#[path = "eval_daemon/bindings.rs"]
mod bindings;
#[path = "eval_daemon/lifecycle.rs"]
mod lifecycle;
#[path = "eval_daemon/provisioning.rs"]
mod provisioning;
#[path = "eval_daemon/receipts.rs"]
mod receipts;

pub(crate) use bindings::{WorkerLaunchSpec, WorkerLauncher};
pub(crate) use lifecycle::bounded_retirement;
pub use lifecycle::{
    launch_session_sidecar, session_extension_policy, SessionSidecarCapsule,
    SessionSidecarLifecycle, SessionSidecarRoots, SessionWorkerLauncher,
};
pub use provisioning::{
    apply_mergiraf_attributes, create_private_dir, mergiraf_driver, mergiraf_program, publish_exact,
};
pub(crate) use provisioning::{
    projection_and_token_session, verify_or_clone_capsule_project, RegisteredGit, SeatTokenIssuance,
};
pub(crate) use receipts::strict_arguments;
pub use receipts::{
    CanonicalEffectReceiptReader, CanonicalV2SidecarOwner, PersistentEffectReceiptReader,
};

use std::path::Path;

fn path_text(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("path {} is not valid UTF-8", path.display()))
}
