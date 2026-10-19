use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use odin_domain::huginn::{DeviceId, HuginnProtocolError, LiveProtocolError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::protocol::{CodecError, PROTOCOL_VERSION};

pub const DEVICE_CREDENTIAL_BYTES: usize = 48;

#[derive(Clone, Eq, PartialEq)]
pub struct DeviceCredential {
    bytes: [u8; DEVICE_CREDENTIAL_BYTES],
}

impl DeviceCredential {
    pub fn new(bytes: Vec<u8>) -> Result<Self, ClientError> {
        let bytes: [u8; DEVICE_CREDENTIAL_BYTES] = bytes.try_into().map_err(|_| {
            ClientError::InvalidInput(format!(
                "device credential must contain exactly {DEVICE_CREDENTIAL_BYTES} bytes"
            ))
        })?;
        let credential = Self { bytes };
        if credential.device_uuid().is_nil() {
            return Err(ClientError::InvalidInput(
                "device credential contains a nil device UUID".to_owned(),
            ));
        }
        Ok(credential)
    }

    pub fn from_parts(device_id: uuid::Uuid, secret: [u8; 32]) -> Result<Self, ClientError> {
        if device_id.is_nil() {
            return Err(ClientError::InvalidInput(
                "device credential contains a nil device UUID".to_owned(),
            ));
        }
        let mut bytes = [0u8; DEVICE_CREDENTIAL_BYTES];
        bytes[..16].copy_from_slice(device_id.as_bytes());
        bytes[16..].copy_from_slice(&secret);
        Ok(Self { bytes })
    }

    pub fn device_uuid(&self) -> uuid::Uuid {
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&self.bytes[..16]);
        uuid::Uuid::from_bytes(bytes)
    }
    pub fn device_id(&self) -> Result<DeviceId, ClientError> {
        DeviceId::new(self.device_uuid())
            .map_err(|error| ClientError::InvalidInput(error.to_string()))
    }

    pub fn parse_base64url(value: &str) -> Result<Self, ClientError> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| {
                ClientError::InvalidInput("invalid device credential encoding".to_owned())
            })?;
        Self::new(bytes)
    }

    pub(crate) fn bearer_token(&self) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.bytes)
    }
}

impl fmt::Debug for DeviceCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeviceCredential([redacted])")
    }
}

impl Drop for DeviceCredential {
    fn drop(&mut self) {
        for byte in &mut self.bytes {
            *byte = 0;
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapInfo {
    pub protocol_version: u16,
    pub connect_path: String,
    pub max_frame_bytes: usize,
}

impl BootstrapInfo {
    pub fn local(max_frame_bytes: usize) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            connect_path: "/colinremote/v1/connect".to_owned(),
            max_frame_bytes,
        }
    }

    pub fn validate(&self) -> Result<(), ClientError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(ClientError::Protocol(
                HuginnProtocolError::UnsupportedVersion {
                    received: self.protocol_version,
                    supported: PROTOCOL_VERSION,
                },
            ));
        }
        if self.connect_path != "/colinremote/v1/connect" || self.max_frame_bytes == 0 {
            return Err(ClientError::InvalidInput(
                "invalid ColinRemote bootstrap metadata".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum ClientError {
    #[error("no ColinRemote device credential is stored")]
    CredentialUnavailable,
    #[error("the ColinRemote device was revoked")]
    DeviceRevoked,
    #[error("the Huginn connection closed")]
    ConnectionClosed,
    #[error("transport error: {0}")]
    Transport(String),
    #[error(transparent)]
    Protocol(#[from] HuginnProtocolError),
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error(transparent)]
    LiveProtocol(#[from] LiveProtocolError),
    #[error("unsupported operation: {0}")]
    Unsupported(&'static str),
    #[error("resource limit exceeded: {0}")]
    Limit(String),
    #[error("invalid client input: {0}")]
    InvalidInput(String),
    #[error("I/O error: {0}")]
    Io(String),
}

pub trait DeviceCredentialStore: Send + Sync + 'static {
    fn load(&self) -> Result<Option<DeviceCredential>, ClientError>;
    fn store(&self, credential: &DeviceCredential) -> Result<(), ClientError>;
    fn clear(&self) -> Result<(), ClientError>;
}

#[derive(Clone, Debug)]
pub struct MemoryCredentialStore {
    inner: Arc<Mutex<Option<DeviceCredential>>>,
}

impl MemoryCredentialStore {
    pub fn new(credential: DeviceCredential) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(credential))),
        }
    }

    pub fn empty() -> Self {
        Self {
            inner: Arc::new(Mutex::new(None)),
        }
    }
}

impl DeviceCredentialStore for MemoryCredentialStore {
    fn load(&self) -> Result<Option<DeviceCredential>, ClientError> {
        self.inner
            .lock()
            .map(|credential| credential.clone())
            .map_err(|_| ClientError::Io("credential store lock was poisoned".to_owned()))
    }

    fn store(&self, credential: &DeviceCredential) -> Result<(), ClientError> {
        *self
            .inner
            .lock()
            .map_err(|_| ClientError::Io("credential store lock was poisoned".to_owned()))? =
            Some(credential.clone());
        Ok(())
    }

    fn clear(&self) -> Result<(), ClientError> {
        *self
            .inner
            .lock()
            .map_err(|_| ClientError::Io("credential store lock was poisoned".to_owned()))? = None;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct FileCredentialStore {
    path: PathBuf,
}

impl FileCredentialStore {
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, ClientError> {
        let dir = dir.as_ref();
        fs::create_dir_all(dir).map_err(io_error)?;
        let metadata = fs::metadata(dir).map_err(io_error)?;
        if !metadata.is_dir() {
            return Err(ClientError::InvalidInput(
                "credential store path is not a directory".to_owned(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
        }
        Ok(Self {
            path: dir.join("device.credential"),
        })
    }
}

impl DeviceCredentialStore for FileCredentialStore {
    fn load(&self) -> Result<Option<DeviceCredential>, ClientError> {
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(error)),
        };
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(ClientError::Io(
                "credential path is not a regular file".to_owned(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(ClientError::Io(
                    "credential file permissions are broader than 0600".to_owned(),
                ));
            }
        }
        DeviceCredential::parse_base64url(fs::read_to_string(&self.path).map_err(io_error)?.trim())
            .map(Some)
    }

    fn store(&self, credential: &DeviceCredential) -> Result<(), ClientError> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| ClientError::Io("credential path has no parent".to_owned()))?;
        let temporary_path =
            parent.join(format!(".device.credential-{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary_path).map_err(io_error)?;
            file.write_all(credential.bearer_token().as_bytes())
                .map_err(io_error)?;
            file.sync_all().map_err(io_error)?;
            fs::rename(&temporary_path, &self.path).map_err(io_error)?;
            std::fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(io_error)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        result
    }

    fn clear(&self) -> Result<(), ClientError> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io_error(error)),
        }
    }
}

pub(crate) fn io_error(error: std::io::Error) -> ClientError {
    ClientError::Io(error.to_string())
}
