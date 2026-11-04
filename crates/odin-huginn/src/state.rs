//! Service state composition and the shared error conversions used by dispatch,
//! service, and client surfaces.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use odin_domain::huginn::{ContentTicketIssuer, HuginnProtocolError, LiveError};

use crate::dispatch::{ConnectionRegistry, DispatchGuard};

/// The file in the state root whose presence closes dispatch.
pub const STOP_FILE: &str = "STOP";

pub struct FsDispatchGuard {
    stop_path: PathBuf,
}

impl FsDispatchGuard {
    pub fn new(state_root: impl AsRef<Path>) -> Result<Self, std::io::Error> {
        std::fs::create_dir_all(state_root.as_ref())?;
        let state_root = state_root.as_ref().canonicalize()?;
        Ok(Self {
            stop_path: state_root.join(STOP_FILE),
        })
    }
}

#[async_trait]
impl DispatchGuard for FsDispatchGuard {
    async fn check_stop(&self) -> Result<(), HuginnProtocolError> {
        match self.stop_path.try_exists() {
            Ok(false) => Ok(()),
            Ok(true) => Err(HuginnProtocolError::Conflict {
                code: "controllerStopped".to_owned(),
                message: "controller STOP is present; dispatch is closed".to_owned(),
            }),
            Err(error) => Err(HuginnProtocolError::unavailable(
                "controllerStopGuard",
                format!("checking {}: {error}", self.stop_path.display()),
            )),
        }
    }
}

/// Derived at startup from the verified snapshot; followers reject mutations before dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodePosture {
    Authoritative,
    Follower,
}

impl NodePosture {
    /// The dispatcher supplies its exhaustive read-only classification.
    pub fn admits(&self, read_only: bool) -> bool {
        match self {
            Self::Authoritative => true,
            Self::Follower => read_only,
        }
    }
}

/// The composed service state. Generic over the concrete gateway
/// implementations; every port is shared behind an `Arc`. `commands` carries the
/// command plane; live-plane operations route through the composed
/// `OmpLivePlane` behind it in `service`.
pub struct HuginnLiveState<R, C, S, F, V, D, T> {
    pub read_model: Arc<R>,
    pub commands: Arc<C>,
    pub streams: Arc<S>,
    pub files: Arc<F>,
    pub renders: Arc<V>,
    pub devices: Arc<D>,
    pub tailnet: Arc<T>,
    pub guard: Arc<dyn DispatchGuard>,
    pub posture: NodePosture,
    pub tickets: Arc<dyn ContentTicketIssuer>,
    pub connections: ConnectionRegistry,
}

pub struct HuginnPorts<R, C, S, F, V, D, T> {
    pub read_model: Arc<R>,
    pub commands: Arc<C>,
    pub streams: Arc<S>,
    pub files: Arc<F>,
    pub renders: Arc<V>,
    pub devices: Arc<D>,
    pub tailnet: Arc<T>,
    pub guard: Arc<dyn DispatchGuard>,
    pub posture: NodePosture,
    pub tickets: Arc<dyn ContentTicketIssuer>,
    pub connections: ConnectionRegistry,
}

impl<R, C, S, F, V, D, T> HuginnLiveState<R, C, S, F, V, D, T> {
    pub fn new(ports: HuginnPorts<R, C, S, F, V, D, T>) -> Self {
        Self {
            read_model: ports.read_model,
            commands: ports.commands,
            streams: ports.streams,
            files: ports.files,
            renders: ports.renders,
            devices: ports.devices,
            tailnet: ports.tailnet,
            guard: ports.guard,
            posture: ports.posture,
            tickets: ports.tickets,
            connections: ports.connections,
        }
    }
}

/// Live-plane failures surface on the transport-neutral client API as protocol
/// errors; epoch, revision, and cursor distinctions survive via typed variants
/// and stable codes.
pub fn live_error_into_protocol(error: LiveError) -> HuginnProtocolError {
    match error {
        LiveError::UnsupportedVersion {
            received,
            supported,
        } => HuginnProtocolError::UnsupportedVersion {
            received,
            supported,
        },
        LiveError::InvalidRequest { code, message } => {
            HuginnProtocolError::InvalidRequest { code, message }
        }
        LiveError::Unauthenticated => HuginnProtocolError::Unauthenticated,
        LiveError::Unauthorized | LiveError::DeviceRevoked => HuginnProtocolError::Unauthorized,
        LiveError::NotFound {
            object_kind,
            object_id,
        } => HuginnProtocolError::NotFound {
            object_kind,
            object_id,
        },
        LiveError::EpochMismatch { expected, actual } => HuginnProtocolError::Conflict {
            code: "epoch-mismatch".to_owned(),
            message: format!("session epoch {actual} does not match expected {expected}"),
        },
        LiveError::RevisionMismatch { expected, actual } => {
            HuginnProtocolError::RevisionMismatch { expected, actual }
        }
        LiveError::Conflict { code, message } => HuginnProtocolError::Conflict { code, message },
        LiveError::CursorExpired => HuginnProtocolError::CursorExpired,
        LiveError::SubscriptionOverflow => HuginnProtocolError::ResourceLimit {
            limit: "subscription-buffer".to_owned(),
        },
        LiveError::Transfer { code, message } => HuginnProtocolError::Conflict { code, message },
        LiveError::ResourceLimit { limit } => HuginnProtocolError::ResourceLimit { limit },
        LiveError::Unsupported { operation } => HuginnProtocolError::Unsupported { operation },
        LiveError::Unavailable { code, detail } => {
            HuginnProtocolError::Unavailable { code, detail }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::{FsDispatchGuard, STOP_FILE};
    use crate::dispatch::DispatchGuard as _;
    use odin_domain::huginn::HuginnProtocolError;

    #[tokio::test]
    async fn a_stop_file_closes_dispatch_until_it_is_removed() {
        let root = tempfile::tempdir().unwrap();
        let guard = FsDispatchGuard::new(root.path()).unwrap();
        guard.check_stop().await.unwrap();
        std::fs::write(root.path().join(STOP_FILE), b"").unwrap();
        let error = guard.check_stop().await.unwrap_err();
        assert!(
            matches!(error, HuginnProtocolError::Conflict { ref code, .. } if code == "controllerStopped"),
            "{error}"
        );
        std::fs::remove_file(root.path().join(STOP_FILE)).unwrap();
        guard.check_stop().await.unwrap();
    }

    #[tokio::test]
    async fn an_unreadable_state_root_is_reported_not_read_as_running() {
        let root = tempfile::tempdir().unwrap();
        let guard = FsDispatchGuard::new(root.path()).unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o000)).unwrap();
        let result = guard.check_stop().await;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let error = result.unwrap_err();
        assert!(
            matches!(error, HuginnProtocolError::Unavailable { ref code, .. } if code == "controllerStopGuard"),
            "{error}"
        );
    }
}
