//! Wire contract of the local device-admin socket: one bounded request
//! (revoke this `DeviceId`), one typed response. Shared by the daemon's
//! accept loop and the CLI dialer so the two sides cannot drift. The
//! caller is trusted by uid over SO_PEERCRED, never by tailnet identity —
//! no paired device can reach this socket, and no tailnet endpoint exists.

use std::path::{Path, PathBuf};
use std::time::Duration;

use odin_domain::huginn::DeviceId;
use serde::{Deserialize, Serialize};

/// Socket file under the Huginn state root. The daemon binds it 0600
/// inside a 0700 directory, so only the daemon's own uid can even reach it.
pub const ADMIN_SOCKET_FILE: &str = "admin.sock";

/// One revoke request is a device id; anything larger is refused without
/// parsing. Excess bytes are discarded during memory- and time-bounded
/// response teardown, never admitted as another request.
pub const MAX_ADMIN_REQUEST_BYTES: usize = 1024;

/// Upper bound for one admin response; a chatty daemon is a protocol
/// failure, not a stream.
pub const MAX_ADMIN_RESPONSE_BYTES: usize = 4096;

/// A local exchange that cannot finish in this window is a wedged peer,
/// not a reason to hold the accept loop or the CLI.
pub const ADMIN_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);

pub fn admin_socket_path(state_root: &Path) -> PathBuf {
    state_root.join("huginn").join(ADMIN_SOCKET_FILE)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminRevokeRequest {
    pub device_id: DeviceId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminRefusal {
    pub code: String,
    pub detail: String,
}

/// Exactly one field is set: `streamsClosed` on success, `refusal`
/// otherwise.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminRevokeResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams_closed: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<AdminRefusal>,
}

impl AdminRevokeResponse {
    pub fn revoked(streams_closed: usize) -> Self {
        Self {
            streams_closed: Some(streams_closed),
            refusal: None,
        }
    }

    pub fn refused(code: &str, detail: impl Into<String>) -> Self {
        Self {
            streams_closed: None,
            refusal: Some(AdminRefusal {
                code: code.to_owned(),
                detail: detail.into(),
            }),
        }
    }
}
