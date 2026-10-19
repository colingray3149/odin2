use std::fs::{self, OpenOptions};
use std::future::Future;
use std::path::Path;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use odin_domain::huginn::{DeviceId, TailnetNodeId, VerifiedColinDevice};
use odin_domain::Digest;
use odin_domain::{SeatTokenId, SessionId};
use rusqlite::{params, Connection, OptionalExtension as _};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::auth::{AuthError, DeviceCredential};
use crate::dispatch::{ConnectionRegistration, ConnectionRegistry};

const MIGRATIONS: &[odin_ledger::migration::Migration<'_>] = &[
    odin_ledger::migration::Migration::register(
        1,
        "schemas/huginn/0001_trusted_devices.sql",
        "88fb06ad38bd3a881b9e8ee9db3aa66cf50c5adecd7bb62f4ef1232d8394a8ec",
        include_str!("../../../schemas/huginn/0001_trusted_devices.sql"),
    ),
    odin_ledger::migration::Migration::register(
        2,
        "schemas/huginn/0002_device_session_grants.sql",
        "55547f1c295006dcfc48d417d3c68f1ecfddc9cb25a2d02aa312e0ea5d958b81",
        include_str!("../../../schemas/huginn/0002_device_session_grants.sql"),
    ),
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRecord {
    pub device_id: DeviceId,
    pub tailnet_node_id: TailnetNodeId,
    pub label: String,
    pub credential_digest: Digest,
    pub created_at: OffsetDateTime,
    pub last_seen_at: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoking_at: Option<OffsetDateTime>,
    pub revoked_at: Option<OffsetDateTime>,
}

/// Outcome of claiming authority over a session token for a device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantClaim {
    /// A new grant was inserted for this device and session.
    Claimed,
    /// The same device and session already hold a live grant for the token.
    Held,
    /// The token is bound to another device, another session, or a dead grant.
    Foreign,
    /// The device is revoked or pending revocation; nothing was written.
    Inactive,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewDeviceGrant {
    pub device_id: DeviceId,
    pub session_id: SessionId,
    pub token_id: SeatTokenId,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceGrant {
    pub device_id: DeviceId,
    pub session_id: SessionId,
    pub token_id: SeatTokenId,
    pub created_at: OffsetDateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewDeviceRecord {
    pub device_id: DeviceId,
    pub tailnet_node_id: TailnetNodeId,
    pub label: String,
    pub credential_digest: Digest,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Error)]
pub enum DeviceStoreError {
    #[error("device database I/O failed: {0}")]
    Io(String),
    #[error("device database failed: {0}")]
    Database(String),
    #[error("device database contains an invalid {field}: {message}")]
    Corrupt {
        field: &'static str,
        message: String,
    },
    #[error("device {0} already exists")]
    AlreadyExists(DeviceId),
    #[error("device {device} holds {grants} live session grant(s); revoke it through the ledger-first path")]
    LedgerRevocationRequired { device: DeviceId, grants: usize },
    #[error("device store lock was poisoned")]
    Poisoned,
}

impl From<std::io::Error> for DeviceStoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

#[async_trait]
pub trait DeviceTrustStore: Send + Sync {
    async fn insert(&self, record: NewDeviceRecord) -> Result<DeviceRecord, DeviceStoreError>;
    async fn get(&self, id: DeviceId) -> Result<Option<DeviceRecord>, DeviceStoreError>;
    async fn list(&self) -> Result<Vec<DeviceRecord>, DeviceStoreError>;
    async fn touch(&self, id: DeviceId, at: OffsetDateTime) -> Result<(), DeviceStoreError>;
    /// Rechecks the durable device gate and registers atomically against revocation.
    /// Implementations must hold the device-state lock through registry insertion,
    /// always acquiring device state before the registry, never in reverse order.
    async fn register_connection(
        &self,
        device: &VerifiedColinDevice,
        connections: &ConnectionRegistry,
        limit: usize,
    ) -> Result<ConnectionRegistration, AuthError>;
    async fn revoke(&self, id: DeviceId, at: OffsetDateTime) -> Result<bool, DeviceStoreError>;
    async fn claim_grant(&self, grant: NewDeviceGrant) -> Result<GrantClaim, DeviceStoreError>;
    /// Live grants only: the rows a ledger-first revocation must retire.
    async fn grants(&self, device: DeviceId) -> Result<Vec<DeviceGrant>, DeviceStoreError>;
    async fn grant_snapshot(
        &self,
        token_id: &SeatTokenId,
    ) -> Result<Option<DeviceGrant>, DeviceStoreError>;
    /// Releases a live claim for an active device; revoking devices use the revocation path.
    /// Revoke the token in the ledger before releasing its claim.
    async fn release_grant(
        &self,
        token_id: &SeatTokenId,
        device: DeviceId,
        at: OffsetDateTime,
    ) -> Result<bool, DeviceStoreError>;
    /// Flips an active device to the persisted revoking gate: authentication
    /// and grant claims fail closed from this commit onward. False when the
    /// device is unknown, already revoking, or already revoked.
    async fn begin_revoke(
        &self,
        id: DeviceId,
        at: OffsetDateTime,
    ) -> Result<bool, DeviceStoreError>;
    /// Revoking -> revoked: tombstones every live grant atomically with the
    /// device row. Only reachable after `begin_revoke`; false otherwise.
    async fn finalize_revoke(
        &self,
        id: DeviceId,
        at: OffsetDateTime,
    ) -> Result<bool, DeviceStoreError>;
    /// Devices stuck between begin and finalize: the crash-resume set.
    async fn pending_revokes(&self) -> Result<Vec<DeviceRecord>, DeviceStoreError>;
}

pub struct SqliteDeviceTrustStore {
    connection: Arc<Mutex<Connection>>,
}

impl std::fmt::Debug for SqliteDeviceTrustStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteDeviceTrustStore")
            .finish_non_exhaustive()
    }
}

impl SqliteDeviceTrustStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DeviceStoreError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            set_mode(parent, 0o700)?;
        }
        let _file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)?;
        set_mode(path, 0o600)?;
        Self::initialize(path)
    }

    pub fn open_in_memory() -> Result<Self, DeviceStoreError> {
        Self::initialize(Path::new(":memory:"))
    }

    fn initialize(path: &Path) -> Result<Self, DeviceStoreError> {
        let connection = odin_ledger::open_database(path, MIGRATIONS)
            .map_err(|error| DeviceStoreError::Database(error.to_string()))?;
        connection
            .pragma_update(None, "trusted_schema", "OFF")
            .map_err(database_error)?;
        // Trust revocations must survive power loss, not only process crashes.
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(database_error)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    /// Claims without an await boundary so cancellation guards can record
    /// ownership before cancellation can interrupt the caller.
    pub fn claim_grant_sync(&self, grant: NewDeviceGrant) -> Result<GrantClaim, DeviceStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| DeviceStoreError::Poisoned)?;
        claim_grant_on(&connection, &grant)
    }

    /// Relinquishes a newly claimed, pre-existing token when admission did
    /// not commit. Unlike revoked fresh authority, this token remains usable.
    /// Call only for this open's Claimed result, never Held or committed opens.
    pub fn relinquish_grant_sync(
        &self,
        token_id: &SeatTokenId,
        device: DeviceId,
        session: &SessionId,
    ) -> Result<bool, DeviceStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| DeviceStoreError::Poisoned)?;
        // The guarded delete is atomic with the device gate: once revocation
        // begins its ledger pass owns this row, even if admission later fails.
        let removed = connection
            .execute(
                "DELETE FROM device_session_grants
             WHERE token_id = ?1 AND device_id = ?2 AND session_id = ?3
             AND revoked_at IS NULL AND EXISTS (
                 SELECT 1 FROM trusted_devices
                 WHERE device_id = ?2 AND revoking_at IS NULL AND revoked_at IS NULL
             )",
                params![token_id.as_str(), device.to_string(), session.as_str()],
            )
            .map_err(database_error)?;
        Ok(removed != 0)
    }

    /// Cancellation cleanup for freshly minted authority after its ledger
    /// revocation. The persisted device gate still wins over cleanup: a
    /// revoking device retains the grant for its ledger-first revoke pass.
    pub fn release_grant_sync(
        &self,
        token_id: &SeatTokenId,
        device: DeviceId,
        at: OffsetDateTime,
    ) -> Result<bool, DeviceStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| DeviceStoreError::Poisoned)?;
        release_grant_on(&connection, token_id, device, at)
    }

    // The sqlite lock is taken on the blocking thread and dropped before the join.
    async fn with_connection<T, F>(&self, body: F) -> Result<T, DeviceStoreError>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> Result<T, DeviceStoreError> + Send + 'static,
    {
        let connection = Arc::clone(&self.connection);
        tokio::task::spawn_blocking(move || {
            let connection = connection.lock().map_err(|_| DeviceStoreError::Poisoned)?;
            body(&connection)
        })
        .await
        .map_err(|error| DeviceStoreError::Database(error.to_string()))?
    }
}

fn claim_grant_on(
    connection: &Connection,
    grant: &NewDeviceGrant,
) -> Result<GrantClaim, DeviceStoreError> {
    // Reserve the writer before reading either row: another process cannot
    // begin revocation between the active check and an existing-grant decision.
    let transaction =
        rusqlite::Transaction::new_unchecked(connection, rusqlite::TransactionBehavior::Immediate)
            .map_err(database_error)?;
    let active: bool = transaction
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM trusted_devices
         WHERE device_id = ?1 AND revoking_at IS NULL AND revoked_at IS NULL)",
            [grant.device_id.to_string()],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    if !active {
        return Ok(GrantClaim::Inactive);
    }
    if let Some(existing) = query_grant(&transaction, &grant.token_id)? {
        return Ok(classify_grant(parse_grant(existing)?, grant));
    }
    transaction
        .execute(
            "INSERT INTO device_session_grants
            (token_id, device_id, session_id, created_at, revoked_at)
         VALUES (?1, ?2, ?3, ?4, NULL)",
            params![
                grant.token_id.as_str(),
                grant.device_id.to_string(),
                grant.session_id.as_str(),
                grant.created_at.unix_timestamp()
            ],
        )
        .map_err(database_error)?;
    transaction.commit().map_err(database_error)?;
    Ok(GrantClaim::Claimed)
}

fn release_grant_on(
    connection: &Connection,
    token_id: &SeatTokenId,
    device: DeviceId,
    at: OffsetDateTime,
) -> Result<bool, DeviceStoreError> {
    let released = connection
        .execute(
            "UPDATE device_session_grants SET revoked_at = ?3
         WHERE token_id = ?1 AND device_id = ?2 AND revoked_at IS NULL
         AND EXISTS (
             SELECT 1 FROM trusted_devices
             WHERE device_id = ?2 AND revoking_at IS NULL AND revoked_at IS NULL
         )",
            params![token_id.as_str(), device.to_string(), at.unix_timestamp()],
        )
        .map_err(database_error)?;
    Ok(released != 0)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), DeviceStoreError> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), DeviceStoreError> {
    Ok(())
}

#[cfg(unix)]
trait OpenOptionsMode {
    fn mode(&mut self, mode: u32) -> &mut Self;
}

#[cfg(unix)]
impl OpenOptionsMode for OpenOptions {
    fn mode(&mut self, mode: u32) -> &mut Self {
        std::os::unix::fs::OpenOptionsExt::mode(self, mode)
    }
}

#[cfg(not(unix))]
trait OpenOptionsMode {
    fn mode(&mut self, _mode: u32) -> &mut Self;
}

#[cfg(not(unix))]
impl OpenOptionsMode for OpenOptions {
    fn mode(&mut self, _mode: u32) -> &mut Self {
        self
    }
}

#[async_trait]
impl DeviceTrustStore for SqliteDeviceTrustStore {
    async fn register_connection(
        &self,
        device: &VerifiedColinDevice,
        connections: &ConnectionRegistry,
        limit: usize,
    ) -> Result<ConnectionRegistration, AuthError> {
        let device = device.clone();
        let connections = connections.clone();
        self.with_connection(move |connection| {
            // The writer reservation also fences revocation through independent
            // SQLite opens. A snapshot read or the local mutex alone cannot.
            let transaction = rusqlite::Transaction::new_unchecked(
                connection,
                rusqlite::TransactionBehavior::Immediate,
            )
            .map_err(database_error)?;
            let state = transaction
                .query_row(
                    "SELECT revoking_at IS NOT NULL, revoked_at IS NOT NULL
                     FROM trusted_devices WHERE device_id = ?1",
                    [device.device_id.to_string()],
                    |row| Ok((row.get::<_, bool>(0)?, row.get::<_, bool>(1)?)),
                )
                .optional()
                .map_err(database_error)?;
            match state {
                None => return Ok(Err(AuthError::UnknownDevice(device.device_id))),
                Some((_, true)) => return Ok(Err(AuthError::DeviceRevoked)),
                Some((true, false)) => return Ok(Err(AuthError::DeviceRevocationPending)),
                Some((false, false)) => {}
            }
            let registration = connections
                .register_with_limit(&device, limit)
                .map_err(AuthError::from);
            // Keep ownership here until commit succeeds. On failure (or caller
            // cancellation), Drop removes any registration rather than leaking it.
            transaction.commit().map_err(database_error)?;
            Ok(registration)
        })
        .await?
    }

    async fn insert(&self, record: NewDeviceRecord) -> Result<DeviceRecord, DeviceStoreError> {
        validate_label(&record.label).map_err(|message| DeviceStoreError::Corrupt {
            field: "label",
            message: message.to_owned(),
        })?;
        self.with_connection(move |connection| {
            let changed = connection
                .execute(
                    "INSERT OR IGNORE INTO trusted_devices (
                     device_id, tailnet_node_id, label, credential_digest, created_at,
                     last_seen_at, revoking_at, revoked_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, NULL)",
                    params![
                        record.device_id.to_string(),
                        record.tailnet_node_id.to_string(),
                        record.label,
                        record.credential_digest.as_bytes().as_slice(),
                        record.created_at.unix_timestamp(),
                    ],
                )
                .map_err(database_error)?;
            if changed == 0 {
                return Err(DeviceStoreError::AlreadyExists(record.device_id));
            }
            Ok(DeviceRecord {
                device_id: record.device_id,
                tailnet_node_id: record.tailnet_node_id,
                label: record.label,
                credential_digest: record.credential_digest,
                created_at: record.created_at,
                last_seen_at: None,
                revoking_at: None,
                revoked_at: None,
            })
        })
        .await
    }

    async fn get(&self, id: DeviceId) -> Result<Option<DeviceRecord>, DeviceStoreError> {
        self.with_connection(move |connection| {
            let raw = connection
                .query_row(
                    "SELECT device_id, tailnet_node_id, label, credential_digest,
                        created_at, last_seen_at, revoking_at, revoked_at
                 FROM trusted_devices WHERE device_id = ?1",
                    [id.to_string()],
                    raw_record,
                )
                .optional()
                .map_err(database_error)?;
            raw.map(parse_record).transpose()
        })
        .await
    }

    async fn list(&self) -> Result<Vec<DeviceRecord>, DeviceStoreError> {
        self.with_connection(move |connection| {
            let mut statement = connection
                .prepare(
                    "SELECT device_id, tailnet_node_id, label, credential_digest,
                        created_at, last_seen_at, revoking_at, revoked_at
                 FROM trusted_devices ORDER BY created_at, device_id",
                )
                .map_err(database_error)?;
            let rows = statement
                .query_map([], raw_record)
                .map_err(database_error)?;
            let mut records = Vec::new();
            for row in rows {
                records.push(parse_record(row.map_err(database_error)?)?);
            }
            Ok(records)
        })
        .await
    }

    async fn touch(&self, id: DeviceId, at: OffsetDateTime) -> Result<(), DeviceStoreError> {
        self.with_connection(move |connection| {
            connection
                .execute(
                    "UPDATE trusted_devices
                 SET last_seen_at = CASE
                     WHEN last_seen_at IS NULL OR last_seen_at < ?2 THEN ?2
                     ELSE last_seen_at
                 END
                 WHERE device_id = ?1 AND revoking_at IS NULL AND revoked_at IS NULL",
                    params![id.to_string(), at.unix_timestamp()],
                )
                .map_err(database_error)?;
            Ok(())
        })
        .await
    }

    async fn revoke(&self, id: DeviceId, at: OffsetDateTime) -> Result<bool, DeviceStoreError> {
        self.with_connection(move |connection| {
            let transaction = connection.unchecked_transaction().map_err(database_error)?;
            // The simple revoke never touches the token ledger, so a device
            // with live grants must go through the ledger-first path instead.
            let grants: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM device_session_grants
                 WHERE device_id = ?1 AND revoked_at IS NULL",
                    [id.to_string()],
                    |row| row.get(0),
                )
                .map_err(database_error)?;
            if grants > 0 {
                return Err(DeviceStoreError::LedgerRevocationRequired {
                    device: id,
                    grants: grants.try_into().unwrap_or(usize::MAX),
                });
            }
            let changed = transaction
                .execute(
                    "UPDATE trusted_devices SET revoked_at = ?2
                 WHERE device_id = ?1 AND revoked_at IS NULL",
                    params![id.to_string(), at.unix_timestamp()],
                )
                .map_err(database_error)?;
            transaction.commit().map_err(database_error)?;
            Ok(changed != 0)
        })
        .await
    }

    async fn claim_grant(&self, grant: NewDeviceGrant) -> Result<GrantClaim, DeviceStoreError> {
        self.with_connection(move |connection| claim_grant_on(connection, &grant))
            .await
    }

    async fn grants(&self, device: DeviceId) -> Result<Vec<DeviceGrant>, DeviceStoreError> {
        self.with_connection(move |connection| {
            let mut statement = connection
                .prepare(
                    "SELECT token_id, device_id, session_id, created_at, revoked_at
                 FROM device_session_grants
                 WHERE device_id = ?1 AND revoked_at IS NULL
                 ORDER BY created_at, token_id",
                )
                .map_err(database_error)?;
            let rows = statement
                .query_map([device.to_string()], raw_grant)
                .map_err(database_error)?;
            let mut grants = Vec::new();
            for row in rows {
                grants.push(parse_grant(row.map_err(database_error)?)?);
            }
            Ok(grants)
        })
        .await
    }

    async fn grant_snapshot(
        &self,
        token_id: &SeatTokenId,
    ) -> Result<Option<DeviceGrant>, DeviceStoreError> {
        let token_id = token_id.clone();
        self.with_connection(move |connection| {
            query_grant(connection, &token_id)?
                .map(parse_grant)
                .transpose()
        })
        .await
    }

    async fn release_grant(
        &self,
        token_id: &SeatTokenId,
        device: DeviceId,
        at: OffsetDateTime,
    ) -> Result<bool, DeviceStoreError> {
        let token_id = token_id.clone();
        self.with_connection(move |connection| release_grant_on(connection, &token_id, device, at))
            .await
    }

    async fn begin_revoke(
        &self,
        id: DeviceId,
        at: OffsetDateTime,
    ) -> Result<bool, DeviceStoreError> {
        self.with_connection(move |connection| {
            let changed = connection
                .execute(
                    "UPDATE trusted_devices SET revoking_at = ?2
                 WHERE device_id = ?1 AND revoking_at IS NULL AND revoked_at IS NULL",
                    params![id.to_string(), at.unix_timestamp()],
                )
                .map_err(database_error)?;
            Ok(changed != 0)
        })
        .await
    }

    async fn finalize_revoke(
        &self,
        id: DeviceId,
        at: OffsetDateTime,
    ) -> Result<bool, DeviceStoreError> {
        self.with_connection(move |connection| {
            let transaction = connection.unchecked_transaction().map_err(database_error)?;
            // Grant tombstones commit atomically with the device row, so a
            // resume never finds live grants behind a revoked device.
            transaction
                .execute(
                    "UPDATE device_session_grants SET revoked_at = ?2
                 WHERE device_id = ?1 AND revoked_at IS NULL",
                    params![id.to_string(), at.unix_timestamp()],
                )
                .map_err(database_error)?;
            let changed = transaction
                .execute(
                    "UPDATE trusted_devices SET revoked_at = ?2
                 WHERE device_id = ?1 AND revoking_at IS NOT NULL AND revoked_at IS NULL",
                    params![id.to_string(), at.unix_timestamp()],
                )
                .map_err(database_error)?;
            if changed == 0 {
                transaction.rollback().map_err(database_error)?;
                return Ok(false);
            }
            transaction.commit().map_err(database_error)?;
            Ok(true)
        })
        .await
    }

    async fn pending_revokes(&self) -> Result<Vec<DeviceRecord>, DeviceStoreError> {
        self.with_connection(|connection| {
            let mut statement = connection
                .prepare(
                    "SELECT device_id, tailnet_node_id, label, credential_digest,
                        created_at, last_seen_at, revoking_at, revoked_at
                 FROM trusted_devices
                 WHERE revoking_at IS NOT NULL AND revoked_at IS NULL
                 ORDER BY revoking_at, device_id",
                )
                .map_err(database_error)?;
            let rows = statement
                .query_map([], raw_record)
                .map_err(database_error)?;
            let mut records = Vec::new();
            for row in rows {
                records.push(parse_record(row.map_err(database_error)?)?);
            }
            Ok(records)
        })
        .await
    }
}

type RawRecord = (
    String,
    String,
    String,
    Vec<u8>,
    i64,
    Option<i64>,
    Option<i64>,
    Option<i64>,
);

fn raw_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawRecord> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
    ))
}
fn parse_record(raw: RawRecord) -> Result<DeviceRecord, DeviceStoreError> {
    let (
        device_id,
        tailnet_node_id,
        label,
        digest,
        created_at,
        last_seen_at,
        revoking_at,
        revoked_at,
    ) = raw;
    validate_label(&label).map_err(|message| DeviceStoreError::Corrupt {
        field: "label",
        message: message.to_owned(),
    })?;
    let device_id = DeviceId::parse(&device_id).map_err(|error| corrupt("device_id", error))?;
    let tailnet_node_id = TailnetNodeId::parse(&tailnet_node_id)
        .map_err(|error| corrupt("tailnet_node_id", error))?;
    let digest: [u8; 32] = digest.try_into().map_err(|_| DeviceStoreError::Corrupt {
        field: "credential_digest",
        message: "must contain exactly 32 bytes".to_owned(),
    })?;
    Ok(DeviceRecord {
        device_id,
        tailnet_node_id,
        label,
        credential_digest: Digest::from_bytes(digest),
        created_at: parse_time("created_at", created_at)?,
        last_seen_at: last_seen_at
            .map(|value| parse_time("last_seen_at", value))
            .transpose()?,
        revoking_at: revoking_at
            .map(|value| parse_time("revoking_at", value))
            .transpose()?,
        revoked_at: revoked_at
            .map(|value| parse_time("revoked_at", value))
            .transpose()?,
    })
}

type RawGrant = (String, String, String, i64, Option<i64>);

fn raw_grant(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawGrant> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
    ))
}

fn query_grant(
    connection: &Connection,
    token_id: &SeatTokenId,
) -> Result<Option<RawGrant>, DeviceStoreError> {
    connection
        .query_row(
            "SELECT token_id, device_id, session_id, created_at, revoked_at
             FROM device_session_grants WHERE token_id = ?1",
            [token_id.as_str()],
            raw_grant,
        )
        .optional()
        .map_err(database_error)
}

fn parse_grant(raw: RawGrant) -> Result<DeviceGrant, DeviceStoreError> {
    let (token_id, device_id, session_id, created_at, revoked_at) = raw;
    Ok(DeviceGrant {
        token_id: SeatTokenId::parse(&token_id).map_err(|error| corrupt("token_id", error))?,
        device_id: DeviceId::parse(&device_id).map_err(|error| corrupt("device_id", error))?,
        session_id: SessionId::parse(&session_id).map_err(|error| corrupt("session_id", error))?,
        created_at: parse_time("created_at", created_at)?,
        revoked_at: revoked_at
            .map(|value| parse_time("revoked_at", value))
            .transpose()?,
    })
}

fn classify_grant(existing: DeviceGrant, claim: &NewDeviceGrant) -> GrantClaim {
    if existing.device_id == claim.device_id
        && existing.session_id == claim.session_id
        && existing.revoked_at.is_none()
    {
        GrantClaim::Held
    } else {
        GrantClaim::Foreign
    }
}

fn parse_time(field: &'static str, value: i64) -> Result<OffsetDateTime, DeviceStoreError> {
    OffsetDateTime::from_unix_timestamp(value).map_err(|error| DeviceStoreError::Corrupt {
        field,
        message: error.to_string(),
    })
}

fn corrupt(field: &'static str, error: impl std::fmt::Display) -> DeviceStoreError {
    DeviceStoreError::Corrupt {
        field,
        message: error.to_string(),
    }
}

fn database_error(error: rusqlite::Error) -> DeviceStoreError {
    DeviceStoreError::Database(error.to_string())
}

fn validate_label(label: &str) -> Result<(), &'static str> {
    if label.is_empty() {
        return Err("must not be empty");
    }
    if label.len() > 128 {
        return Err("must not exceed 128 bytes");
    }
    if label.chars().any(char::is_control) {
        return Err("must not contain control characters");
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalPairRequest {
    pub label: String,
    pub tailnet_node_id: TailnetNodeId,
}

pub struct PairingBundle {
    record: DeviceRecord,
    credential: DeviceCredential,
}

impl std::fmt::Debug for PairingBundle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairingBundle")
            .field("record", &self.record)
            .field("credential", &"[redacted]")
            .finish()
    }
}

impl PairingBundle {
    pub fn record(&self) -> &DeviceRecord {
        &self.record
    }

    pub fn device_id(&self) -> DeviceId {
        self.record.device_id
    }

    pub fn credential(&self) -> &DeviceCredential {
        &self.credential
    }
}

pub struct DeviceAdmin<D> {
    store: Arc<D>,
    connections: ConnectionRegistry,
}

impl<D> DeviceAdmin<D> {
    pub fn new(store: Arc<D>, connections: ConnectionRegistry) -> Self {
        Self { store, connections }
    }
}

impl<D: DeviceTrustStore> DeviceAdmin<D> {
    pub async fn list(&self) -> Result<Vec<DeviceRecord>, AuthError> {
        self.store.list().await.map_err(AuthError::from)
    }

    pub async fn pair_local(&self, request: LocalPairRequest) -> Result<PairingBundle, AuthError> {
        validate_label(&request.label).map_err(|message| AuthError::InvalidPairing {
            message: message.to_owned(),
        })?;
        let device_id =
            DeviceId::new(Uuid::new_v4()).map_err(|error| AuthError::InvalidPairing {
                message: error.to_string(),
            })?;
        let credential = DeviceCredential::generate(device_id);
        let record = self
            .store
            .insert(NewDeviceRecord {
                device_id,
                tailnet_node_id: request.tailnet_node_id,
                label: request.label,
                credential_digest: credential.digest(),
                created_at: OffsetDateTime::now_utc(),
            })
            .await?;
        Ok(PairingBundle { record, credential })
    }

    pub async fn revoke(&self, device: DeviceId) -> Result<(), AuthError> {
        if !self.store.revoke(device, OffsetDateTime::now_utc()).await? {
            return Err(AuthError::UnknownDevice(device));
        }
        self.connections.close_device(device)?;
        Ok(())
    }

    /// Persists the revoking gate only: the device stops authenticating and
    /// claiming grants from this commit onward, before any ledger work.
    pub async fn begin_revoke(&self, device: DeviceId) -> Result<(), AuthError> {
        if self.store.get(device).await?.is_none() {
            return Err(AuthError::UnknownDevice(device));
        }
        self.store
            .begin_revoke(device, OffsetDateTime::now_utc())
            .await?;
        Ok(())
    }

    /// Finalizes a begun revocation: tombstones the device's live grants with
    /// the device row, then closes its live connections. Returns the number
    /// of closed connections. Redrive-safe: after a crash between the durable
    /// finalize and the close, the store write no-ops and the close reruns.
    pub async fn finalize_revoke(&self, device: DeviceId) -> Result<usize, AuthError> {
        let finalized = self
            .store
            .finalize_revoke(device, OffsetDateTime::now_utc())
            .await?;
        if !finalized {
            let record = self
                .store
                .get(device)
                .await?
                .ok_or(AuthError::UnknownDevice(device))?;
            if record.revoked_at.is_none() {
                return Err(AuthError::RevokeNotBegun(device));
            }
        }
        self.connections
            .close_device(device)
            .map_err(AuthError::from)
    }

    /// Devices stuck between begin and finalize; redrive each through
    /// `revoke_ledger_first`.
    pub async fn pending_revokes(&self) -> Result<Vec<DeviceRecord>, AuthError> {
        self.store.pending_revokes().await.map_err(AuthError::from)
    }

    /// The only revoke path for a device holding session grants: persist the
    /// revoking gate, hand every live grant to `ledger_revoke` (the token
    /// ledger lives with the caller), then finalize and close. Resumable —
    /// calling it again on a pending or failed device redrives the sequence.
    pub async fn revoke_ledger_first<F, Fut>(
        &self,
        device: DeviceId,
        ledger_revoke: F,
    ) -> Result<usize, AuthError>
    where
        F: FnOnce(Vec<DeviceGrant>) -> Fut + Send,
        Fut: Future<Output = Result<(), String>> + Send,
    {
        let record = self
            .store
            .get(device)
            .await?
            .ok_or(AuthError::UnknownDevice(device))?;
        if record.revoked_at.is_some() {
            return Err(AuthError::UnknownDevice(device));
        }
        self.store
            .begin_revoke(device, OffsetDateTime::now_utc())
            .await?;
        let grants = self.store.grants(device).await?;
        ledger_revoke(grants)
            .await
            .map_err(|message| AuthError::LedgerRevoke { device, message })?;
        self.finalize_revoke(device).await
    }
}

/// Publishes every paired device's live activity into the read model:
/// the trust store's `lastSeenAt` (stamped at each authentication) and the
/// number of open connections the registry holds for it right now. An
/// unchanged device is a no-op; a changed one moves to the next object
/// revision. Returns how many device objects changed.
pub async fn publish_device_activity<D: DeviceTrustStore + ?Sized>(
    store: &D,
    connections: &ConnectionRegistry,
    read_model: &crate::read_model::MaterializedReadModel,
    observed_at: OffsetDateTime,
) -> Result<usize, String> {
    use odin_domain::huginn::{
        Freshness, FreshnessState, ObjectKind, ObjectRef, ObjectSnapshot, Revision, RevisionSource,
    };
    let mut changed = 0;
    for device in store.list().await.map_err(|error| error.to_string())? {
        let value = serde_json::json!({
            "deviceId": device.device_id,
            "tailnetNodeId": device.tailnet_node_id,
            "label": device.label,
            "createdAt": device.created_at,
            "lastSeenAt": device.last_seen_at,
            "revokingAt": device.revoking_at,
            "revokedAt": device.revoked_at,
            "activeConnections": connections.active_for_device(device.device_id),
        });
        let object = ObjectRef {
            kind: ObjectKind::Device,
            id: device.device_id.to_string(),
        };
        let current = read_model.get(&object).map_err(|error| error.to_string())?;
        if current
            .as_ref()
            .is_some_and(|current| current.value == value)
        {
            continue;
        }
        let revision = current.map_or(1, |current| current.revision.get().saturating_add(1));
        let encoded = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
        read_model
            .upsert(ObjectSnapshot {
                object,
                revision: Revision::new(revision),
                revision_source: RevisionSource::Ledger,
                freshness: Freshness {
                    state: FreshnessState::Fresh,
                    observed_at,
                    source_updated_at: device.last_seen_at.or(Some(device.created_at)),
                    stale_after_seconds: None,
                },
                content_digest: Digest::hash(&encoded),
                value,
            })
            .map_err(|error| error.to_string())?;
        changed += 1;
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::auth::{SecretBytes, TailnetAuthenticator};
    use crate::private_network::VerifiedTailnetPeer;

    #[tokio::test]
    async fn device_activity_publishes_last_seen_and_open_connections() {
        let store = SqliteDeviceTrustStore::open_in_memory().unwrap();
        let connections = ConnectionRegistry::new();
        let model = crate::read_model::MaterializedReadModel::new(64, OffsetDateTime::now_utc());
        let device = DeviceId::new(Uuid::new_v4()).unwrap();
        let node = TailnetNodeId::parse("node.pc").unwrap();
        store
            .insert(NewDeviceRecord {
                device_id: device,
                tailnet_node_id: node.clone(),
                label: "pc".to_owned(),
                credential_digest: Digest::hash(b"credential"),
                created_at: OffsetDateTime::UNIX_EPOCH,
            })
            .await
            .unwrap();
        let at = OffsetDateTime::now_utc();
        assert_eq!(
            publish_device_activity(&store, &connections, &model, at)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            publish_device_activity(&store, &connections, &model, at)
                .await
                .unwrap(),
            0
        );

        let seen = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1);
        store.touch(device, seen).await.unwrap();
        let _registration = connections
            .register(&odin_domain::huginn::VerifiedColinDevice {
                device_id: device,
                tailnet_node_id: node,
                connection_id: odin_domain::huginn::ConnectionId::new(Uuid::new_v4()).unwrap(),
            })
            .unwrap();
        assert_eq!(
            publish_device_activity(&store, &connections, &model, at)
                .await
                .unwrap(),
            1
        );
        let object = model
            .get(&odin_domain::huginn::ObjectRef {
                kind: odin_domain::huginn::ObjectKind::Device,
                id: device.to_string(),
            })
            .unwrap()
            .unwrap();
        assert_eq!(object.revision.get(), 2);
        assert_eq!(object.value["activeConnections"], 1);
        assert_eq!(
            object.value["lastSeenAt"],
            serde_json::to_value(seen).unwrap()
        );
    }

    #[tokio::test]
    async fn legacy_devices_survive_migration_and_revocation_with_a_reader() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("devices.sqlite");
        let legacy = Connection::open(&path).unwrap();
        // The old store had this device schema but no migration metadata.
        let schema = MIGRATIONS[0].sql;
        legacy
            .execute_batch(
                &schema[schema
                    .find("CREATE TABLE IF NOT EXISTS trusted_devices")
                    .unwrap()..],
            )
            .unwrap();
        let device = DeviceId::new(Uuid::new_v4()).unwrap();
        legacy
            .execute(
                "INSERT INTO trusted_devices VALUES (?1, 'node.phone', 'phone', ?2, 1, NULL, NULL)",
                params![
                    device.to_string(),
                    Digest::hash(b"credential").as_bytes().as_slice()
                ],
            )
            .unwrap();
        drop(legacy);

        let store = SqliteDeviceTrustStore::open(&path).unwrap();
        assert_eq!(store.get(device).await.unwrap().unwrap().label, "phone");
        let reader = Connection::open(&path).unwrap();
        reader.execute_batch("BEGIN").unwrap();
        let revoked: Option<i64> = reader
            .query_row(
                "SELECT revoked_at FROM trusted_devices WHERE device_id=?1",
                [device.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(revoked, None);
        assert!(store
            .revoke(device, OffsetDateTime::UNIX_EPOCH)
            .await
            .unwrap());
        // Revocation commits even while a client retains its earlier snapshot.
        drop(store);
        let reopened = SqliteDeviceTrustStore::open(&path).unwrap();
        assert_eq!(
            reopened.get(device).await.unwrap().unwrap().revoked_at,
            Some(OffsetDateTime::UNIX_EPOCH),
        );
        reader.execute_batch("ROLLBACK").unwrap();
    }

    async fn paired_device(
        store: &SqliteDeviceTrustStore,
        label: &str,
    ) -> (DeviceId, DeviceCredential) {
        let device = DeviceId::new(Uuid::new_v4()).unwrap();
        let credential = DeviceCredential::generate(device);
        store
            .insert(NewDeviceRecord {
                device_id: device,
                tailnet_node_id: TailnetNodeId::parse("node.pc").unwrap(),
                label: label.to_owned(),
                credential_digest: credential.digest(),
                created_at: OffsetDateTime::UNIX_EPOCH,
            })
            .await
            .unwrap();
        (device, credential)
    }

    fn grant_for(device: DeviceId, session: SessionId, token: SeatTokenId) -> NewDeviceGrant {
        NewDeviceGrant {
            device_id: device,
            session_id: session,
            token_id: token,
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[tokio::test]
    async fn revoked_device_cannot_register_previously_authenticated_connection() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("devices.sqlite");
        let store = Arc::new(SqliteDeviceTrustStore::open(&path).unwrap());
        let revoker = Arc::new(SqliteDeviceTrustStore::open(&path).unwrap());
        let connections = ConnectionRegistry::new();
        let admin = DeviceAdmin::new(revoker, connections.clone());
        let authenticator = TailnetAuthenticator::new(store.clone());
        let (device, credential) = paired_device(&store, "phone").await;
        let (other, other_credential) = paired_device(&store, "tablet").await;
        let peer =
            || VerifiedTailnetPeer::local(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
        let admitted = authenticator
            .authenticate(peer(), SecretBytes::new(credential.encode().into_bytes()))
            .await
            .unwrap();
        let stale = authenticator
            .authenticate(peer(), SecretBytes::new(credential.encode().into_bytes()))
            .await
            .unwrap();
        let unaffected = authenticator
            .authenticate(
                peer(),
                SecretBytes::new(other_credential.encode().into_bytes()),
            )
            .await
            .unwrap();
        let admitted_registration = store
            .register_connection(&admitted, &connections, 2)
            .await
            .unwrap();
        let unaffected_registration = store
            .register_connection(&unaffected, &connections, 2)
            .await
            .unwrap();
        let other_token = SeatTokenId::new("seat-token:1:unaffected").unwrap();
        let other_grant = grant_for(
            other,
            SessionId::new("other-session").unwrap(),
            other_token.clone(),
        );
        assert_eq!(
            store.claim_grant(other_grant.clone()).await.unwrap(),
            GrantClaim::Claimed
        );
        let snapshot = store.grant_snapshot(&other_token).await.unwrap();

        // Force the exact route seam: authentication completes, then revocation
        // closes the admitted connection before the stale request registers.
        admin.revoke(device).await.unwrap();
        assert!(*admitted_registration.revocation().borrow());
        assert!(!*unaffected_registration.revocation().borrow());
        assert_eq!(connections.active_for_device(device), 0);
        assert_eq!(connections.active_for_device(other), 1);

        let reconnected = authenticator
            .authenticate(
                peer(),
                SecretBytes::new(other_credential.encode().into_bytes()),
            )
            .await
            .unwrap();
        let _reconnected_registration = store
            .register_connection(&reconnected, &connections, 2)
            .await
            .unwrap();
        assert_eq!(
            store.claim_grant(other_grant).await.unwrap(),
            GrantClaim::Held
        );
        assert_eq!(store.grant_snapshot(&other_token).await.unwrap(), snapshot);
        assert!(matches!(
            store.register_connection(&stale, &connections, 2).await,
            Err(AuthError::DeviceRevoked)
        ));
        assert_eq!(connections.active_for_device(device), 0);
        assert_eq!(connections.active_for_device(other), 2);
    }

    #[tokio::test]
    async fn pending_revoke_refuses_stale_admission_until_finalize_closes_existing() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("devices.sqlite");
        let store = Arc::new(SqliteDeviceTrustStore::open(&path).unwrap());
        let connections = ConnectionRegistry::new();
        let (device, credential) = paired_device(&store, "phone").await;
        let authenticator = TailnetAuthenticator::new(store.clone());
        let authenticate = || {
            authenticator.authenticate(
                VerifiedTailnetPeer::local(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
                SecretBytes::new(credential.encode().into_bytes()),
            )
        };
        let admitted = authenticate().await.unwrap();
        let stale = authenticate().await.unwrap();
        let registration = store
            .register_connection(&admitted, &connections, 1)
            .await
            .unwrap();
        assert!(matches!(
            store.register_connection(&stale, &connections, 1).await,
            Err(AuthError::Registry(
                crate::dispatch::RegistryError::ConnectionLimit { limit: 1 }
            ))
        ));
        let token = SeatTokenId::new("seat-token:1:admission-pending").unwrap();
        let grant = grant_for(
            device,
            SessionId::new("pending-session").unwrap(),
            token.clone(),
        );
        assert_eq!(store.claim_grant(grant).await.unwrap(), GrantClaim::Claimed);
        let snapshot = store.grant_snapshot(&token).await.unwrap();
        let revoker = Arc::new(SqliteDeviceTrustStore::open(&path).unwrap());
        let admin = DeviceAdmin::new(revoker, connections.clone());
        admin.begin_revoke(device).await.unwrap();
        assert!(matches!(
            store.register_connection(&stale, &connections, 2).await,
            Err(AuthError::DeviceRevocationPending)
        ));
        assert_eq!(connections.active_for_device(device), 1);
        assert_eq!(connections.served_connections(), 1);
        assert!(!*registration.revocation().borrow());
        assert_eq!(store.grant_snapshot(&token).await.unwrap(), snapshot);
        assert_eq!(admin.finalize_revoke(device).await.unwrap(), 1);
        assert!(*registration.revocation().borrow());
        assert!(matches!(
            store.register_connection(&stale, &connections, 2).await,
            Err(AuthError::DeviceRevoked)
        ));
        assert_eq!(connections.active_connections(), 0);
        drop(registration);
        assert_eq!(connections.served_connections(), 0);
        assert!(store
            .grant_snapshot(&token)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some());
    }

    /// Idempotent for the owning (device, session); foreign to every other
    /// device, every other session, and every dead grant.
    #[tokio::test]
    async fn claim_is_idempotent_for_the_owner_and_foreign_to_everyone_else() {
        let store = SqliteDeviceTrustStore::open_in_memory().unwrap();
        let (owner, _) = paired_device(&store, "phone").await;
        let (other, _) = paired_device(&store, "tablet").await;
        let token = SeatTokenId::new("seat-token:1:shared").unwrap();
        let session = SessionId::new("session-one").unwrap();
        assert_eq!(
            store
                .claim_grant(grant_for(owner, session.clone(), token.clone()))
                .await
                .unwrap(),
            GrantClaim::Claimed
        );
        let held = store.grant_snapshot(&token).await.unwrap().unwrap();
        assert_eq!(
            store
                .claim_grant(grant_for(owner, session.clone(), token.clone()))
                .await
                .unwrap(),
            GrantClaim::Held
        );
        assert_eq!(store.grant_snapshot(&token).await.unwrap().unwrap(), held);
        // The token is bound to one session; re-binding is refused.
        let other_session = SessionId::new("session-two").unwrap();
        assert_eq!(
            store
                .claim_grant(grant_for(owner, other_session, token.clone()))
                .await
                .unwrap(),
            GrantClaim::Foreign
        );
        // Another device cannot claim or release this token.
        assert_eq!(
            store
                .claim_grant(grant_for(other, session.clone(), token.clone()))
                .await
                .unwrap(),
            GrantClaim::Foreign
        );
        assert!(!store
            .release_grant(&token, other, OffsetDateTime::UNIX_EPOCH)
            .await
            .unwrap());
        assert_eq!(store.grants(other).await.unwrap(), []);
        assert_eq!(store.grant_snapshot(&token).await.unwrap().unwrap(), held);
        assert!(!store
            .release_grant_sync(&token, other, OffsetDateTime::UNIX_EPOCH)
            .unwrap());
        assert_eq!(store.grant_snapshot(&token).await.unwrap().unwrap(), held);
        assert!(store
            .release_grant_sync(&token, owner, OffsetDateTime::UNIX_EPOCH)
            .unwrap());
        assert!(!store
            .release_grant_sync(&token, owner, OffsetDateTime::UNIX_EPOCH)
            .unwrap());
        let released = store.grant_snapshot(&token).await.unwrap().unwrap();
        assert_eq!(released.revoked_at, Some(OffsetDateTime::UNIX_EPOCH));
        assert_eq!(released.device_id, owner);
        assert_eq!(released.session_id, session);
        assert_eq!(
            store
                .claim_grant(grant_for(owner, session, token))
                .await
                .unwrap(),
            GrantClaim::Foreign
        );
    }

    #[tokio::test]
    async fn tentative_relinquishment_allows_retry_but_never_erases_revocation() {
        let store = SqliteDeviceTrustStore::open_in_memory().unwrap();
        let (device, _) = paired_device(&store, "phone").await;
        let (other, _) = paired_device(&store, "tablet").await;
        let token = SeatTokenId::new("seat-token:10:tentative").unwrap();
        let session = SessionId::new("session-tentative").unwrap();
        let other_session = SessionId::new("session-unrelated").unwrap();
        let claim = grant_for(device, session.clone(), token.clone());
        assert_eq!(
            store.claim_grant_sync(claim.clone()).unwrap(),
            GrantClaim::Claimed
        );
        assert!(!store
            .relinquish_grant_sync(&token, other, &session)
            .unwrap());
        assert!(!store
            .relinquish_grant_sync(&token, device, &other_session)
            .unwrap());
        assert_eq!(
            store.claim_grant_sync(claim.clone()).unwrap(),
            GrantClaim::Held
        );
        assert!(store
            .relinquish_grant_sync(&token, device, &session)
            .unwrap());
        assert!(!store
            .relinquish_grant_sync(&token, device, &session)
            .unwrap());
        assert!(store.grant_snapshot(&token).await.unwrap().is_none());
        assert_eq!(
            store.claim_grant_sync(claim.clone()).unwrap(),
            GrantClaim::Claimed
        );
        // Fresh-token rollback leaves a real tombstone, never tentative state.
        assert!(store
            .release_grant_sync(&token, device, OffsetDateTime::UNIX_EPOCH)
            .unwrap());
        assert!(!store
            .relinquish_grant_sync(&token, device, &session)
            .unwrap());
        assert_eq!(store.claim_grant_sync(claim).unwrap(), GrantClaim::Foreign);
        assert_eq!(
            store
                .grant_snapshot(&token)
                .await
                .unwrap()
                .unwrap()
                .revoked_at,
            Some(OffsetDateTime::UNIX_EPOCH)
        );
        let pending_token = SeatTokenId::new("seat-token:11:pending-tentative").unwrap();
        let pending_claim = grant_for(device, session.clone(), pending_token.clone());
        assert_eq!(
            store.claim_grant_sync(pending_claim.clone()).unwrap(),
            GrantClaim::Claimed
        );
        assert!(store
            .begin_revoke(device, OffsetDateTime::UNIX_EPOCH)
            .await
            .unwrap());
        assert!(!store
            .relinquish_grant_sync(&pending_token, device, &session)
            .unwrap());
        assert_eq!(store.grants(device).await.unwrap().len(), 1);
        assert!(store
            .finalize_revoke(device, OffsetDateTime::UNIX_EPOCH)
            .await
            .unwrap());
        assert!(!store
            .relinquish_grant_sync(&pending_token, device, &session)
            .unwrap());
        assert_eq!(
            store.claim_grant_sync(pending_claim).unwrap(),
            GrantClaim::Inactive
        );
        assert_eq!(
            store
                .grant_snapshot(&pending_token)
                .await
                .unwrap()
                .unwrap()
                .revoked_at,
            Some(OffsetDateTime::UNIX_EPOCH)
        );
    }

    #[tokio::test]
    async fn pending_revoke_blocks_authentication_claims_and_releases() {
        let store = Arc::new(SqliteDeviceTrustStore::open_in_memory().unwrap());
        let (device, credential) = paired_device(&store, "phone").await;
        let token = SeatTokenId::new("seat-token:2:pending").unwrap();
        let session = SessionId::new("session-one").unwrap();
        assert_eq!(
            store
                .claim_grant(grant_for(device, session.clone(), token.clone()))
                .await
                .unwrap(),
            GrantClaim::Claimed
        );

        assert!(store
            .begin_revoke(device, OffsetDateTime::UNIX_EPOCH)
            .await
            .unwrap());
        let record = store.get(device).await.unwrap().unwrap();
        assert_eq!(record.revoking_at, Some(OffsetDateTime::UNIX_EPOCH),);
        assert_eq!(record.revoked_at, None);

        let authenticator = TailnetAuthenticator::new(store.clone());
        let peer = VerifiedTailnetPeer::local(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
        let presented = SecretBytes::new(credential.encode().into_bytes());
        assert!(matches!(
            authenticator.authenticate(peer, presented).await,
            Err(AuthError::DeviceRevocationPending)
        ));
        // A rejected handshake must not move last_seen_at.
        store
            .touch(
                device,
                OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1),
            )
            .await
            .unwrap();
        assert_eq!(store.get(device).await.unwrap().unwrap().last_seen_at, None);

        assert_eq!(
            store
                .claim_grant(grant_for(device, session.clone(), token.clone()))
                .await
                .unwrap(),
            GrantClaim::Inactive
        );
        assert!(!store
            .release_grant(&token, device, OffsetDateTime::UNIX_EPOCH)
            .await
            .unwrap());
        assert_eq!(store.grants(device).await.unwrap().len(), 1);

        assert!(store
            .finalize_revoke(device, OffsetDateTime::UNIX_EPOCH)
            .await
            .unwrap());
        let peer = VerifiedTailnetPeer::local(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
        let presented = SecretBytes::new(credential.encode().into_bytes());
        assert!(matches!(
            authenticator.authenticate(peer, presented).await,
            Err(AuthError::DeviceRevoked)
        ));
        assert_eq!(
            store
                .claim_grant(grant_for(device, session.clone(), token.clone()))
                .await
                .unwrap(),
            GrantClaim::Inactive
        );
        assert!(store.pending_revokes().await.unwrap().is_empty());
        assert!(store.grants(device).await.unwrap().is_empty());
        assert!(store
            .grant_snapshot(&token)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some());
    }

    /// Grant metadata and the pending revoke state survive a close/reopen:
    /// the crash-resume set is durable.
    #[tokio::test]
    async fn grant_metadata_and_pending_revokes_survive_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("devices.sqlite");
        let store = SqliteDeviceTrustStore::open(&path).unwrap();
        let (device, _) = paired_device(&store, "phone").await;
        let token = SeatTokenId::new("seat-token:3:durable").unwrap();
        let session = SessionId::new("session-one").unwrap();
        assert_eq!(
            store
                .claim_grant(grant_for(device, session.clone(), token.clone()))
                .await
                .unwrap(),
            GrantClaim::Claimed
        );
        assert!(store
            .begin_revoke(device, OffsetDateTime::UNIX_EPOCH)
            .await
            .unwrap());
        drop(store);

        let reopened = SqliteDeviceTrustStore::open(&path).unwrap();
        assert_eq!(
            reopened.grant_snapshot(&token).await.unwrap().unwrap(),
            DeviceGrant {
                device_id: device,
                session_id: session,
                token_id: token.clone(),
                created_at: OffsetDateTime::UNIX_EPOCH,
                revoked_at: None,
            }
        );
        let pending = reopened.pending_revokes().await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].device_id, device);
        assert_eq!(pending[0].revoking_at, Some(OffsetDateTime::UNIX_EPOCH));
        assert_eq!(reopened.grants(device).await.unwrap().len(), 1);
        assert!(reopened
            .finalize_revoke(device, OffsetDateTime::UNIX_EPOCH)
            .await
            .unwrap());
        drop(reopened);

        let reopened = SqliteDeviceTrustStore::open(&path).unwrap();
        assert_eq!(
            reopened.get(device).await.unwrap().unwrap().revoked_at,
            Some(OffsetDateTime::UNIX_EPOCH)
        );
        assert!(reopened.pending_revokes().await.unwrap().is_empty());
        assert!(reopened.grants(device).await.unwrap().is_empty());
        assert!(reopened
            .grant_snapshot(&token)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some());
    }

    /// Finalize is reachable only through begin: an active device cannot be
    /// pushed to revoked, so the revoking gate cannot be bypassed silently.
    #[tokio::test]
    async fn finalize_requires_a_begun_revocation() {
        let store = Arc::new(SqliteDeviceTrustStore::open_in_memory().unwrap());
        let (device, _) = paired_device(&store, "phone").await;
        assert!(!store
            .finalize_revoke(device, OffsetDateTime::UNIX_EPOCH)
            .await
            .unwrap());
        assert_eq!(store.get(device).await.unwrap().unwrap().revoked_at, None);

        let admin = DeviceAdmin::new(store.clone(), ConnectionRegistry::new());
        assert!(matches!(
            admin.finalize_revoke(device).await,
            Err(AuthError::RevokeNotBegun(_))
        ));
        let unknown = DeviceId::new(Uuid::new_v4()).unwrap();
        assert!(matches!(
            admin.finalize_revoke(unknown).await,
            Err(AuthError::UnknownDevice(_))
        ));
        assert!(matches!(
            admin
                .revoke_ledger_first(unknown, |_| async { Ok::<(), String>(()) })
                .await,
            Err(AuthError::UnknownDevice(_))
        ));

        let before = OffsetDateTime::now_utc().unix_timestamp();
        admin.begin_revoke(device).await.unwrap();
        assert_eq!(admin.finalize_revoke(device).await.unwrap(), 0);
        let record = store.get(device).await.unwrap().unwrap();
        let revoked_at = record.revoked_at.expect("finalize stamps revocation");
        assert!(revoked_at.unix_timestamp() >= before);
        assert!(revoked_at.unix_timestamp() <= OffsetDateTime::now_utc().unix_timestamp());
        assert!(record.revoking_at.unwrap() <= revoked_at);
        assert_eq!(admin.finalize_revoke(device).await.unwrap(), 0);
        assert_eq!(
            store.get(device).await.unwrap().unwrap().revoked_at,
            Some(revoked_at)
        );
    }

    /// The simple revoke never touches the token ledger: a device holding
    /// live grants is refused until it goes through the ledger-first path.
    #[tokio::test]
    async fn simple_revoke_refuses_devices_with_live_grants() {
        let store = Arc::new(SqliteDeviceTrustStore::open_in_memory().unwrap());
        let (device, _) = paired_device(&store, "phone").await;
        let token = SeatTokenId::new("seat-token:4:gated").unwrap();
        store
            .claim_grant(grant_for(
                device,
                SessionId::new("session-one").unwrap(),
                token.clone(),
            ))
            .await
            .unwrap();
        let admin = DeviceAdmin::new(store.clone(), ConnectionRegistry::new());
        assert!(matches!(
            admin.revoke(device).await,
            Err(AuthError::Store(
                DeviceStoreError::LedgerRevocationRequired { grants: 1, .. }
            ))
        ));
        assert_eq!(store.get(device).await.unwrap().unwrap().revoked_at, None);
        assert_eq!(
            store
                .claim_grant(grant_for(
                    device,
                    SessionId::new("session-two").unwrap(),
                    token
                ))
                .await
                .unwrap(),
            GrantClaim::Foreign
        );
    }

    /// Ledger-first order is structural: the gate is durable before the
    /// closure runs, finalize waits for it, and the close follows finalize.
    #[tokio::test]
    async fn revoke_ledger_first_orders_gate_ledger_finalize_close() {
        let store = Arc::new(SqliteDeviceTrustStore::open_in_memory().unwrap());
        let (device, _) = paired_device(&store, "phone").await;
        let token = SeatTokenId::new("seat-token:5:ordered").unwrap();
        store
            .claim_grant(grant_for(
                device,
                SessionId::new("session-one").unwrap(),
                token.clone(),
            ))
            .await
            .unwrap();
        let connections = ConnectionRegistry::new();
        let registration = connections
            .register(&odin_domain::huginn::VerifiedColinDevice {
                device_id: device,
                tailnet_node_id: TailnetNodeId::parse("node.pc").unwrap(),
                connection_id: odin_domain::huginn::ConnectionId::new(Uuid::new_v4()).unwrap(),
            })
            .unwrap();
        let admin = DeviceAdmin::new(store.clone(), connections);

        let gate = store.clone();
        let expected_token = token.clone();
        let closed = admin
            .revoke_ledger_first(device, move |grants: Vec<DeviceGrant>| {
                let gate = gate.clone();
                async move {
                    assert_eq!(grants.len(), 1);
                    assert_eq!(grants[0].token_id, expected_token);
                    let record = gate.get(grants[0].device_id).await.unwrap().unwrap();
                    assert!(record.revoking_at.is_some());
                    assert_eq!(record.revoked_at, None);
                    assert_eq!(gate.grants(grants[0].device_id).await.unwrap().len(), 1);
                    Ok(())
                }
            })
            .await
            .unwrap();
        assert_eq!(closed, 1);
        assert!(*registration.revocation().borrow());
        let record = store.get(device).await.unwrap().unwrap();
        assert!(record.revoked_at.is_some());
        assert!(store.grants(device).await.unwrap().is_empty());
        assert!(store
            .grant_snapshot(&token)
            .await
            .unwrap()
            .is_none_or(|grant| { grant.revoked_at.is_some() }));
    }

    /// A failed ledger pass leaves the device pending and its grants visible
    /// for the resume; the redrive finalizes and closes exactly once more.
    #[tokio::test]
    async fn failed_ledger_revoke_stays_pending_until_the_redrive() {
        let store = Arc::new(SqliteDeviceTrustStore::open_in_memory().unwrap());
        let (device, _) = paired_device(&store, "phone").await;
        let token = SeatTokenId::new("seat-token:6:redrive").unwrap();
        store
            .claim_grant(grant_for(
                device,
                SessionId::new("session-one").unwrap(),
                token,
            ))
            .await
            .unwrap();
        let connections = ConnectionRegistry::new();
        let registration = connections
            .register(&odin_domain::huginn::VerifiedColinDevice {
                device_id: device,
                tailnet_node_id: TailnetNodeId::parse("node.pc").unwrap(),
                connection_id: odin_domain::huginn::ConnectionId::new(Uuid::new_v4()).unwrap(),
            })
            .unwrap();
        let admin = DeviceAdmin::new(store.clone(), connections);

        let error = admin
            .revoke_ledger_first(device, |_| async {
                Err::<(), String>("ledger down".to_owned())
            })
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            AuthError::LedgerRevoke { device: _, message } if message == "ledger down"
        ));
        let record = store.get(device).await.unwrap().unwrap();
        assert!(record.revoking_at.is_some());
        assert_eq!(record.revoked_at, None);
        assert_eq!(store.grants(device).await.unwrap().len(), 1);
        assert_eq!(store.pending_revokes().await.unwrap().len(), 1);
        assert!(!registration.revocation().has_changed().unwrap());

        assert_eq!(
            admin
                .revoke_ledger_first(device, |_| async { Ok::<(), String>(()) })
                .await
                .unwrap(),
            1
        );
        assert!(*registration.revocation().borrow());
        assert!(store
            .get(device)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some());
        assert!(store.pending_revokes().await.unwrap().is_empty());
        assert!(store.grants(device).await.unwrap().is_empty());
    }

    /// Claim and begin_revoke serialize on the store: a claim either commits
    /// ahead of the gate and reaches the revoke pass, or is refused outright.
    #[tokio::test]
    async fn claim_and_revoke_serialize_onto_one_outcome() {
        for round in 0..25_u32 {
            let store = SqliteDeviceTrustStore::open_in_memory().unwrap();
            let (device, _) = paired_device(&store, "phone").await;
            let token = SeatTokenId::new(format!("seat-token:{round}:race")).unwrap();
            let session = SessionId::new("session-one").unwrap();
            let (claim, begun) = tokio::join!(
                store.claim_grant(grant_for(device, session.clone(), token.clone())),
                store.begin_revoke(device, OffsetDateTime::UNIX_EPOCH)
            );
            let claim = claim.unwrap();
            let begun = begun.unwrap();
            assert!(begun);
            let live = store.grants(device).await.unwrap();
            match claim {
                GrantClaim::Claimed => {
                    assert_eq!(live.len(), 1, "claimed grants must reach the revoke pass");
                }
                GrantClaim::Inactive => assert!(live.is_empty()),
                other => panic!("unexpected claim outcome {other:?} in round {round}"),
            }
            assert!(store
                .finalize_revoke(device, OffsetDateTime::UNIX_EPOCH)
                .await
                .unwrap());
            assert!(store.grants(device).await.unwrap().is_empty());
            let snapshot = store.grant_snapshot(&token).await.unwrap();
            assert_eq!(snapshot.is_some(), claim == GrantClaim::Claimed);
            if let Some(snapshot) = snapshot {
                assert!(snapshot.revoked_at.is_some());
            }
            assert_eq!(
                store
                    .claim_grant(grant_for(device, session.clone(), token))
                    .await
                    .unwrap(),
                GrantClaim::Inactive
            );
        }
    }

    /// A separate connection models CLI revocation against daemon reuse.
    #[tokio::test]
    async fn existing_grant_claim_observes_another_connections_revoking_gate() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("devices.sqlite");
        let daemon = SqliteDeviceTrustStore::open(&path).unwrap();
        let cli = SqliteDeviceTrustStore::open(&path).unwrap();
        let (device, _) = paired_device(&daemon, "phone").await;
        let token = SeatTokenId::new("seat-token:8:cross-process").unwrap();
        let session = SessionId::new("session-cross-process").unwrap();
        let claim = grant_for(device, session, token.clone());
        assert_eq!(
            daemon.claim_grant_sync(claim.clone()).unwrap(),
            GrantClaim::Claimed
        );
        let original = daemon.grant_snapshot(&token).await.unwrap().unwrap();
        assert_eq!(
            cli.claim_grant(claim.clone()).await.unwrap(),
            GrantClaim::Held
        );
        assert_eq!(
            daemon.claim_grant_sync(claim.clone()).unwrap(),
            GrantClaim::Held
        );
        assert!(cli
            .begin_revoke(device, OffsetDateTime::UNIX_EPOCH)
            .await
            .unwrap());
        assert_eq!(
            daemon.claim_grant(claim.clone()).await.unwrap(),
            GrantClaim::Inactive
        );
        assert_eq!(
            daemon.claim_grant_sync(claim.clone()).unwrap(),
            GrantClaim::Inactive
        );
        let unclaimed = SeatTokenId::new("seat-token:9:inactive-new").unwrap();
        assert_eq!(
            daemon
                .claim_grant_sync(grant_for(
                    device,
                    SessionId::new("session-inactive-new").unwrap(),
                    unclaimed.clone()
                ))
                .unwrap(),
            GrantClaim::Inactive
        );
        assert!(daemon.grant_snapshot(&unclaimed).await.unwrap().is_none());
        assert_eq!(
            daemon.grant_snapshot(&token).await.unwrap().unwrap(),
            original
        );
        assert!(!daemon
            .release_grant_sync(&token, device, OffsetDateTime::UNIX_EPOCH)
            .unwrap());
        assert!(cli
            .finalize_revoke(device, OffsetDateTime::UNIX_EPOCH)
            .await
            .unwrap());
        assert_eq!(
            daemon.claim_grant(claim).await.unwrap(),
            GrantClaim::Inactive
        );
        assert_eq!(
            daemon
                .grant_snapshot(&token)
                .await
                .unwrap()
                .unwrap()
                .revoked_at,
            Some(OffsetDateTime::UNIX_EPOCH)
        );
    }

    #[tokio::test]
    async fn device_activity_publishes_revoking_state() {
        let store = SqliteDeviceTrustStore::open_in_memory().unwrap();
        let connections = ConnectionRegistry::new();
        let model = crate::read_model::MaterializedReadModel::new(64, OffsetDateTime::now_utc());
        let (device, _) = paired_device(&store, "phone").await;
        assert!(store
            .begin_revoke(device, OffsetDateTime::UNIX_EPOCH)
            .await
            .unwrap());
        let at = OffsetDateTime::now_utc();
        assert_eq!(
            publish_device_activity(&store, &connections, &model, at)
                .await
                .unwrap(),
            1
        );
        let object = model
            .get(&odin_domain::huginn::ObjectRef {
                kind: odin_domain::huginn::ObjectKind::Device,
                id: device.to_string(),
            })
            .unwrap()
            .unwrap();
        assert_eq!(
            object.value["revokingAt"],
            serde_json::to_value(store.get(device).await.unwrap().unwrap().revoking_at).unwrap()
        );
        assert!(object.value["revokedAt"].is_null());
        let finalized_at = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1);
        assert!(store.finalize_revoke(device, finalized_at).await.unwrap());
        assert_eq!(
            publish_device_activity(&store, &connections, &model, at)
                .await
                .unwrap(),
            1
        );
        let finalized = model.get(&object.object).unwrap().unwrap();
        assert_eq!(finalized.revision.get(), object.revision.get() + 1);
        assert_eq!(
            finalized.value["revokedAt"],
            serde_json::to_value(finalized_at).unwrap()
        );
        assert_eq!(finalized.value["revokingAt"], object.value["revokingAt"]);
        assert_eq!(
            publish_device_activity(&store, &connections, &model, at)
                .await
                .unwrap(),
            0
        );
    }
}
