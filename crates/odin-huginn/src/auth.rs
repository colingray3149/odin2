use std::fmt;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use odin_domain::huginn::{ConnectionId, DeviceId, VerifiedColinDevice};
use odin_domain::Digest;
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::{Zeroize as _, Zeroizing};

use crate::devices::{DeviceStoreError, DeviceTrustStore};
use crate::private_network::VerifiedTailnetPeer;

const CREDENTIAL_BYTES: usize = 48;
const SECRET_BYTES: usize = 32;
const ABSENT_CREDENTIAL_DIGEST: Digest = Digest::from_bytes([
    0x81, 0x7d, 0x4b, 0xc6, 0x47, 0xdf, 0x38, 0xf0, 0x0b, 0x66, 0x4e, 0x5a, 0x4d, 0x4e, 0x84, 0x43,
    0xc7, 0x57, 0x3b, 0x7d, 0x60, 0x56, 0xd8, 0x53, 0xa4, 0x0f, 0xb2, 0x6d, 0xb5, 0x27, 0x47, 0x73,
]);

pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes([redacted])")
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("credential is malformed")]
    MalformedCredential,
    #[error("authentication failed")]
    InvalidCredential,
    #[error("the device has been revoked")]
    DeviceRevoked,
    #[error("the authenticated device is not valid for this network peer")]
    TailnetNodeMismatch,
    #[error("the device is being revoked")]
    DeviceRevocationPending,
    #[error("device {0} revocation was never begun")]
    RevokeNotBegun(DeviceId),
    #[error("ledger revocation failed for device {device}: {message}")]
    LedgerRevoke { device: DeviceId, message: String },
    #[error("device {0} is not enrolled")]
    UnknownDevice(DeviceId),
    #[error("invalid local pairing request: {message}")]
    InvalidPairing { message: String },
    #[error("device store: {0}")]
    Store(#[from] DeviceStoreError),
    #[error("connection registry: {0}")]
    Registry(#[from] crate::dispatch::RegistryError),
}

pub fn constant_time_digest_eq(left: &Digest, right: &Digest) -> bool {
    bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}

pub struct DeviceCredential {
    device_id: DeviceId,
    secret: [u8; SECRET_BYTES],
}

impl fmt::Debug for DeviceCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceCredential")
            .field("device_id", &self.device_id)
            .field("secret", &"[redacted]")
            .finish()
    }
}

impl Drop for DeviceCredential {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl DeviceCredential {
    pub fn generate(device_id: DeviceId) -> Self {
        let mut secret = [0_u8; SECRET_BYTES];
        secret[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        secret[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        Self { device_id, secret }
    }

    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    pub fn digest(&self) -> Digest {
        Digest::hash(&self.secret)
    }

    pub fn encode(&self) -> String {
        let mut payload = Zeroizing::new([0_u8; CREDENTIAL_BYTES]);
        payload[..16].copy_from_slice(self.device_id.as_uuid().as_bytes());
        payload[16..].copy_from_slice(&self.secret);
        URL_SAFE_NO_PAD.encode(payload.as_slice())
    }

    fn parse(encoded: &[u8]) -> Result<Self, AuthError> {
        let payload = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| AuthError::MalformedCredential)?,
        );
        if payload.len() != CREDENTIAL_BYTES {
            return Err(AuthError::MalformedCredential);
        }
        let uuid = Uuid::from_slice(&payload[..16]).map_err(|_| AuthError::MalformedCredential)?;
        let device_id = DeviceId::new(uuid).map_err(|_| AuthError::MalformedCredential)?;
        let mut secret = [0_u8; SECRET_BYTES];
        secret.copy_from_slice(&payload[16..]);
        Ok(Self { device_id, secret })
    }
}

pub struct TailnetAuthenticator<D> {
    store: Arc<D>,
}

impl<D> Clone for TailnetAuthenticator<D> {
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
        }
    }
}

impl<D> TailnetAuthenticator<D> {
    pub fn new(store: Arc<D>) -> Self {
        Self { store }
    }
}

impl<D: DeviceTrustStore> TailnetAuthenticator<D> {
    pub async fn authenticate(
        &self,
        peer: VerifiedTailnetPeer,
        presented_credential: SecretBytes,
    ) -> Result<VerifiedColinDevice, AuthError> {
        let credential = DeviceCredential::parse(presented_credential.as_slice())?;
        let record = self.store.get(credential.device_id()).await?;
        let expected = record.as_ref().map_or(&ABSENT_CREDENTIAL_DIGEST, |record| {
            &record.credential_digest
        });
        let digest_matches = constant_time_digest_eq(&credential.digest(), expected);
        let Some(record) = record else {
            return Err(AuthError::InvalidCredential);
        };
        if !digest_matches {
            return Err(AuthError::InvalidCredential);
        }
        if record.revoked_at.is_some() {
            return Err(AuthError::DeviceRevoked);
        }
        if record.revoking_at.is_some() {
            return Err(AuthError::DeviceRevocationPending);
        }
        // Loopback with no node id is a process on this host. Serve also
        // arrives as loopback; the router has already bound that peer to the
        // node for its forwarded source address.
        let unbound_local = peer.is_loopback() && peer.tailnet_node_id().is_none();
        if !unbound_local && peer.tailnet_node_id() != Some(&record.tailnet_node_id) {
            return Err(AuthError::TailnetNodeMismatch);
        }

        self.store
            .touch(record.device_id, OffsetDateTime::now_utc())
            .await?;
        let connection_id =
            ConnectionId::new(Uuid::new_v4()).map_err(|_| AuthError::MalformedCredential)?;
        Ok(VerifiedColinDevice {
            device_id: record.device_id,
            tailnet_node_id: record.tailnet_node_id,
            connection_id,
        })
    }
}
