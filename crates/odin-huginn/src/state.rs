//! Service state composition and the shared error conversions used by dispatch,
//! service, and client surfaces.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use odin_domain::huginn::{ContentTicketIssuer, HuginnProtocolError, LiveError};
use thiserror::Error;

use crate::auth::AuthError;
use crate::config::ConfigError;
use crate::devices::DeviceStoreError;
use crate::dispatch::{ConnectionRegistry, DispatchGuard};
use crate::private_network::TailnetError;

pub struct FsDispatchGuard {
    stop_path: PathBuf,
}

impl FsDispatchGuard {
    pub fn new(state_root: impl AsRef<Path>) -> Result<Self, std::io::Error> {
        std::fs::create_dir_all(state_root.as_ref())?;
        let state_root = state_root.as_ref().canonicalize()?;
        Ok(Self {
            stop_path: state_root.join("STOP"),
        })
    }

    pub fn stop_path(&self) -> &Path {
        &self.stop_path
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
            Err(_) => Err(HuginnProtocolError::Unavailable {
                code: "controllerStopGuard".to_owned(),
            }),
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

/// Service failures map to protocol errors through [`HuginnError::into_protocol`].
#[derive(Debug, Error)]
pub enum HuginnError {
    #[error("configuration: {0}")]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Protocol(#[from] HuginnProtocolError),
    #[error(transparent)]
    Live(#[from] LiveError),
    #[error("authentication: {0}")]
    Auth(#[from] AuthError),
    #[error("device trust store: {0}")]
    DeviceStore(#[from] DeviceStoreError),
    #[error("tailnet verification: {0}")]
    Tailnet(#[from] TailnetError),
}

impl HuginnError {
    /// Maps onto the protocol error surface for a wire response. Internal detail
    /// (store, tailnet, config) never leaks beyond a typed unavailability code.
    pub fn into_protocol(self) -> HuginnProtocolError {
        match self {
            Self::Config(_) => HuginnProtocolError::Unavailable {
                code: "config".to_owned(),
            },
            Self::Protocol(error) => error,
            Self::Live(error) => live_error_into_protocol(error),
            Self::Auth(_) => HuginnProtocolError::Unauthenticated,
            Self::DeviceStore(_) => HuginnProtocolError::Unavailable {
                code: "device-store".to_owned(),
            },
            Self::Tailnet(_) => HuginnProtocolError::Unavailable {
                code: "tailnet".to_owned(),
            },
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
        LiveError::Unavailable { code } => HuginnProtocolError::Unavailable { code },
    }
}
