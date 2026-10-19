//! Give each effector exchange a separate broker and executable allowlist.

use odin_kernel::stop::WorkerChannel;
use odin_kernel::{ExecutorFault, ParentBrokerServer};
use odin_sidecar_protocol::EffectRequest;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::{EffectorExecutor, BROKER_RUNTIME_ROOT_PREFIX, ROUNDTRIP_BROKER_SHUTDOWN};

pub(super) struct RoundTripBroker {
    server: ParentBrokerServer,
    runtime_root: PathBuf,
}

impl RoundTripBroker {
    pub(super) fn open(
        executor: &EffectorExecutor,
        channel: &WorkerChannel,
        request: &EffectRequest,
    ) -> Result<Self, ExecutorFault> {
        // Validate executable contents before creating resources.
        let allowed = executor.round_trip_catalog(request)?;
        let owner_store = executor.stop_authority()?.store();
        let scope_store_root = executor.scope_store_root()?.to_path_buf();
        let runtime_root = round_trip_runtime_root()?;
        let bound = ParentBrokerServer::bind(
            &runtime_root,
            &scope_store_root,
            channel.clone(),
            allowed,
            owner_store,
        )
        .and_then(|server| server.start().map(|()| server));
        match bound {
            Ok(server) => Ok(Self {
                server,
                runtime_root,
            }),
            Err(error) => {
                let removal = std::fs::remove_dir(&runtime_root);
                Err(ExecutorFault::Rejected {
                    detail: match removal {
                        Ok(()) => format!("parent broker rejected: {error}"),
                        Err(removal) => format!(
                            "parent broker rejected: {error}; runtime root removal failed: {removal}"
                        ),
                    },
                })
            }
        }
    }

    /// Issue a descriptor usable only by this worker with this broker.
    pub(super) fn prepare(
        &self,
        worker_id: &odin_types::WorkerId,
    ) -> Result<String, ExecutorFault> {
        let descriptor =
            self.server
                .prepare_scope(worker_id)
                .map_err(|error| ExecutorFault::Rejected {
                    detail: format!("parent broker scope preparation failed: {error}"),
                })?;
        Ok(descriptor.to_environment_value())
    }

    /// Require the launched identity before accepting requests from the effector.
    pub(super) fn activate(
        &self,
        worker_id: &odin_types::WorkerId,
        identity: &odin_kernel::stop::WorkerIdentity,
    ) -> Result<(), String> {
        self.server
            .activate_scope(worker_id, identity)
            .map_err(|error| error.to_string())
    }

    /// Remove temporary resources but retain worker ledgers for recovery.
    pub(super) fn dispose(self) -> Result<(), String> {
        let shutdown = self.server.shutdown(ROUNDTRIP_BROKER_SHUTDOWN);
        let removed = std::fs::remove_dir(&self.runtime_root);
        match (shutdown, removed) {
            (Ok(summary), Ok(())) if summary.scopes_handed_off == 0 => Ok(()),
            (Ok(_), Ok(())) => Err("effector broker left a handed-off scope".to_owned()),
            (Ok(_), Err(error)) => Err(format!("broker runtime root removal failed: {error}")),
            (Err(error), Ok(())) => Err(format!("broker shutdown failed: {error}")),
            (Err(error), Err(removal)) => Err(format!(
                "broker shutdown failed: {error}; runtime root removal failed: {removal}"
            )),
        }
    }
}

impl Drop for RoundTripBroker {
    fn drop(&mut self) {
        let _ = self.server.shutdown(ROUNDTRIP_BROKER_SHUTDOWN);
        let _ = std::fs::remove_dir(&self.runtime_root);
    }
}

/// Use a short runtime path to fit the Unix socket length limit.
fn round_trip_runtime_root() -> Result<PathBuf, ExecutorFault> {
    let base = match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(value) if Path::new(&value).is_absolute() => PathBuf::from(value),
        Some(_) => {
            return Err(ExecutorFault::Rejected {
                detail: "XDG_RUNTIME_DIR must be an absolute path".to_owned(),
            })
        }
        None => {
            return Err(ExecutorFault::Rejected {
                detail: "XDG_RUNTIME_DIR is required to host the round-trip parent broker"
                    .to_owned(),
            })
        }
    };
    let runtime_root = base.join(format!(
        "{BROKER_RUNTIME_ROOT_PREFIX}-{}-{}",
        std::process::id(),
        broker_runtime_serial()
    ));
    std::fs::create_dir(&runtime_root).map_err(|error| ExecutorFault::Rejected {
        detail: format!(
            "round-trip broker runtime root {} creation failed: {error}",
            runtime_root.display()
        ),
    })?;
    if let Err(error) =
        std::fs::set_permissions(&runtime_root, std::fs::Permissions::from_mode(0o700))
    {
        let _ = std::fs::remove_dir(&runtime_root);
        return Err(ExecutorFault::Rejected {
            detail: format!(
                "round-trip broker runtime root {} protection failed: {error}",
                runtime_root.display()
            ),
        });
    }
    Ok(runtime_root)
}

fn broker_runtime_serial() -> u64 {
    static SERIAL: AtomicU64 = AtomicU64::new(1);
    SERIAL.fetch_add(1, Ordering::Relaxed)
}
