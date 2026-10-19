//! Pass launch credentials over stdin rather than the request socket or environment.

use odin_domain::SeatToken;
use odin_sidecar_protocol::{read_payload, write_payload};
use odin_strict_json::{canonicalize, decode};
use serde::{Deserialize, Serialize};

use crate::{SidecarError, SidecarErrorCode};

const PROVISIONING_SCHEMA: &str = "OdinSidecarProvisioning/v1";
const PROVISIONING_MAX_BYTES: usize = 65_536;

/// The host supplies the seat token and verification key; the sidecar does not mint either.
pub struct Provisioning {
    pub(super) seat_token: SeatToken,
    signing_key: Vec<u8>,
    post_effect_uncertainty_once: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProvisioningDto {
    schema: String,
    seat_token: SeatToken,
    signing_key_hex: String,
    post_effect_uncertainty_once: bool,
}

impl Provisioning {
    pub fn new(seat_token: SeatToken, signing_key: Vec<u8>) -> Result<Self, SidecarError> {
        if signing_key.is_empty() || signing_key.len() > 16_384 {
            return Err(SidecarError::new(
                SidecarErrorCode::State,
                "provisioning signing key must be within 1..=16384 bytes",
            ));
        }
        Ok(Self {
            seat_token,
            signing_key,
            post_effect_uncertainty_once: false,
        })
    }

    /// Inject one post-effect failure through launch configuration, not the request protocol.
    pub fn with_post_effect_uncertainty_once(mut self) -> Self {
        self.post_effect_uncertainty_once = true;
        self
    }

    /// Decode a four-byte length prefix followed by canonical JSON.
    pub fn read_from(reader: &mut impl std::io::Read) -> Result<Self, SidecarError> {
        let payload = read_payload(reader, PROVISIONING_MAX_BYTES)?.ok_or_else(|| {
            SidecarError::new(
                SidecarErrorCode::State,
                "sealed provisioning channel closed without a record",
            )
        })?;
        let dto: ProvisioningDto = decode(&payload, PROVISIONING_MAX_BYTES).map_err(|error| {
            SidecarError::new(
                SidecarErrorCode::State,
                format!("sealed provisioning record rejected: {error}"),
            )
        })?;
        if dto.schema != PROVISIONING_SCHEMA {
            return Err(SidecarError::new(
                SidecarErrorCode::State,
                format!(
                    "provisioning schema {:?} is not {PROVISIONING_SCHEMA}",
                    dto.schema
                ),
            ));
        }
        let signing_key = odin_types::hash::hex_decode(&dto.signing_key_hex).map_err(|error| {
            SidecarError::new(
                SidecarErrorCode::State,
                format!("provisioning signing_key_hex rejected: {error}"),
            )
        })?;
        let post_effect_uncertainty_once = dto.post_effect_uncertainty_once;
        let mut provisioning = Self::new(dto.seat_token, signing_key)?;
        provisioning.post_effect_uncertainty_once = post_effect_uncertainty_once;
        Ok(provisioning)
    }

    /// Keep the signing key on the one-shot stdin channel, out of argv and the environment.
    pub fn write_to(&self, writer: &mut impl std::io::Write) -> Result<(), SidecarError> {
        let dto = ProvisioningDto {
            schema: PROVISIONING_SCHEMA.to_owned(),
            seat_token: self.seat_token.clone(),
            signing_key_hex: odin_types::hash::hex_encode(&self.signing_key),
            post_effect_uncertainty_once: self.post_effect_uncertainty_once,
        };
        let raw = serde_json::to_vec(&dto).map_err(|error| {
            SidecarError::new(
                SidecarErrorCode::Protocol,
                format!("provisioning record is not representable: {error}"),
            )
        })?;
        let strict: odin_strict_json::Value =
            decode(&raw, PROVISIONING_MAX_BYTES).map_err(|error| {
                SidecarError::new(
                    SidecarErrorCode::Protocol,
                    format!("provisioning record is not strict JSON: {error}"),
                )
            })?;
        let payload = canonicalize(&strict).map_err(|error| {
            SidecarError::new(
                SidecarErrorCode::Protocol,
                format!("provisioning record is not canonicalizable: {error}"),
            )
        })?;
        write_payload(writer, &payload, PROVISIONING_MAX_BYTES).map_err(SidecarError::from)
    }

    pub(super) fn signing_key(&self) -> &[u8] {
        &self.signing_key
    }

    pub(super) fn post_effect_uncertainty_once(&self) -> bool {
        self.post_effect_uncertainty_once
    }
}

/// SO_PEERCRED restricts socket access but does not authorize operations.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PeerCredentials {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

impl PeerCredentials {
    pub fn current() -> Self {
        Self {
            pid: rustix::process::getpid().as_raw_pid(),
            uid: rustix::process::getuid().as_raw(),
            gid: rustix::process::getgid().as_raw(),
        }
    }
}
