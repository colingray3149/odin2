//! Connection/device ownership: the authenticated device registry, its
//! registration lifetimes, and the framed transport seam a served
//! connection speaks.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use odin_domain::huginn::{DeviceId, VerifiedColinDevice};
use thiserror::Error;
use tokio::sync::watch;

#[derive(Clone)]
pub struct ConnectionRegistry {
    inner: Arc<Mutex<RegistryState>>,
    max_connections: usize,
    stopping: Arc<watch::Sender<bool>>,
    served: Arc<watch::Sender<usize>>,
}

#[derive(Default)]
struct RegistryState {
    by_device: HashMap<DeviceId, HashMap<odin_domain::huginn::ConnectionId, watch::Sender<bool>>>,
    total: usize,
}

impl std::fmt::Debug for ConnectionRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectionRegistry")
            .field("active", &self.active_connections())
            .field("limit", &self.max_connections)
            .finish()
    }
}

impl Default for ConnectionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionRegistry {
    pub fn new() -> Self {
        Self::with_limit(usize::MAX)
    }

    pub fn with_limit(max_connections: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(RegistryState::default())),
            max_connections: max_connections.max(1),
            stopping: Arc::new(watch::channel(false).0),
            served: Arc::new(watch::channel(0).0),
        }
    }

    #[cfg(test)]
    pub(crate) fn register(
        &self,
        device: &VerifiedColinDevice,
    ) -> Result<ConnectionRegistration, RegistryError> {
        self.register_with_limit(device, self.max_connections)
    }

    // Call only while holding the durable device gate; external admission goes
    // through DeviceTrustStore::register_connection.
    pub(crate) fn register_with_limit(
        &self,
        device: &VerifiedColinDevice,
        configured_limit: usize,
    ) -> Result<ConnectionRegistration, RegistryError> {
        let limit = self.max_connections.min(configured_limit.max(1));
        let mut state = self.inner.lock().map_err(|_| RegistryError::Poisoned)?;
        if *self.stopping.borrow() {
            return Err(RegistryError::Stopping);
        }
        // The cap is per device: one busy laptop never locks the phone out.
        if state
            .by_device
            .get(&device.device_id)
            .is_some_and(|connections| connections.len() >= limit)
        {
            return Err(RegistryError::ConnectionLimit { limit });
        }
        if state
            .by_device
            .get(&device.device_id)
            .is_some_and(|connections| connections.contains_key(&device.connection_id))
        {
            return Err(RegistryError::DuplicateConnection);
        }
        let (sender, receiver) = watch::channel(false);
        state
            .by_device
            .entry(device.device_id)
            .or_default()
            .insert(device.connection_id, sender);
        state.total += 1;
        self.served.send_modify(|served| *served += 1);
        Ok(ConnectionRegistration {
            registry: self.clone(),
            device_id: device.device_id,
            connection_id: device.connection_id,
            revoked: receiver,
            stopping: self.stopping.subscribe(),
        })
    }

    /// Refuses new connections and tells every served one to close; no
    /// device is told it was revoked, so its client reconnects to the next
    /// daemon.
    pub fn stop_all(&self) {
        self.stopping.send_replace(true);
    }

    /// Resolves once every registered connection's serve loop has ended
    /// (its registration dropped).
    pub async fn drained(&self) {
        let mut served = self.served.subscribe();
        loop {
            let _ = served.wait_for(|served| *served == 0).await;
            // `register_with_limit` passes its stopping check and counts
            // itself inside one critical section on `inner`; taking that
            // section here orders this observation after any admission that
            // raced `stop_all`, which the zero above cannot see yet.
            drop(self.inner.lock());
            if *served.borrow_and_update() == 0 {
                return;
            }
        }
    }

    /// Registrations whose serve loop has not ended yet.
    pub fn served_connections(&self) -> usize {
        *self.served.borrow()
    }

    pub fn close_device(&self, device: DeviceId) -> Result<usize, RegistryError> {
        let mut state = self.inner.lock().map_err(|_| RegistryError::Poisoned)?;
        let Some(connections) = state.by_device.remove(&device) else {
            return Ok(0);
        };
        let count = connections.len();
        state.total = state.total.saturating_sub(count);
        drop(state);
        for sender in connections.into_values() {
            let _ = sender.send(true);
        }
        Ok(count)
    }

    pub fn active_connections(&self) -> usize {
        self.inner.lock().map_or(0, |state| state.total)
    }

    pub fn active_for_device(&self, device: DeviceId) -> usize {
        self.inner
            .lock()
            .ok()
            .and_then(|state| state.by_device.get(&device).map(HashMap::len))
            .unwrap_or(0)
    }

    fn unregister(&self, device_id: DeviceId, connection_id: odin_domain::huginn::ConnectionId) {
        let Ok(mut state) = self.inner.lock() else {
            return;
        };
        let mut removed = false;
        let mut empty = false;
        if let Some(connections) = state.by_device.get_mut(&device_id) {
            removed = connections.remove(&connection_id).is_some();
            empty = connections.is_empty();
        }
        if empty {
            state.by_device.remove(&device_id);
        }
        if removed {
            state.total = state.total.saturating_sub(1);
        }
    }
}

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error(
        "this device already holds {limit} Huginn connections, its limit \
         (limits.connections.max_connections)"
    )]
    ConnectionLimit { limit: usize },
    #[error("connection identifier is already registered")]
    DuplicateConnection,
    #[error("connection registry lock was poisoned")]
    Poisoned,
    #[error("odind is stopping")]
    Stopping,
}

pub struct ConnectionRegistration {
    registry: ConnectionRegistry,
    device_id: DeviceId,
    connection_id: odin_domain::huginn::ConnectionId,
    revoked: watch::Receiver<bool>,
    stopping: watch::Receiver<bool>,
}

impl ConnectionRegistration {
    pub fn revocation(&self) -> watch::Receiver<bool> {
        self.revoked.clone()
    }

    pub fn stopping(&self) -> watch::Receiver<bool> {
        self.stopping.clone()
    }
}

impl Drop for ConnectionRegistration {
    fn drop(&mut self) {
        self.registry.unregister(self.device_id, self.connection_id);
        self.registry
            .served
            .send_modify(|served| *served = served.saturating_sub(1));
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionFrame {
    Binary(Bytes),
    Ping(Bytes),
    Pong(Bytes),
    Text,
    Close,
}

/// A served connection, split so its frames are read while a write is
/// outstanding: a peer that stops reading never holds receive, credit or
/// revocation.
pub trait ServerConnection: Send + 'static {
    type Reader: FrameReader;
    type Writer: FrameWriter;
    fn split(self) -> (Self::Reader, Self::Writer);
}

#[async_trait]
pub trait FrameReader: Send {
    async fn receive(&mut self) -> Result<Option<ConnectionFrame>, String>;
}

#[async_trait]
pub trait FrameWriter: Send + 'static {
    async fn send(&mut self, frame: ConnectionFrame) -> Result<(), String>;
}

impl ServerConnection for WebSocket {
    type Reader = SplitStream<WebSocket>;
    type Writer = SplitSink<WebSocket, Message>;

    fn split(self) -> (Self::Reader, Self::Writer) {
        let (writer, reader) = StreamExt::split(self);
        (reader, writer)
    }
}

#[async_trait]
impl FrameReader for SplitStream<WebSocket> {
    async fn receive(&mut self) -> Result<Option<ConnectionFrame>, String> {
        match StreamExt::next(self).await {
            Some(Ok(Message::Binary(bytes))) => Ok(Some(ConnectionFrame::Binary(bytes))),
            Some(Ok(Message::Ping(bytes))) => Ok(Some(ConnectionFrame::Ping(bytes))),
            Some(Ok(Message::Pong(bytes))) => Ok(Some(ConnectionFrame::Pong(bytes))),
            Some(Ok(Message::Text(_))) => Ok(Some(ConnectionFrame::Text)),
            Some(Ok(Message::Close(_))) => Ok(Some(ConnectionFrame::Close)),
            Some(Err(error)) => Err(error.to_string()),
            None => Ok(None),
        }
    }
}

#[async_trait]
impl FrameWriter for SplitSink<WebSocket, Message> {
    async fn send(&mut self, frame: ConnectionFrame) -> Result<(), String> {
        let message = match frame {
            ConnectionFrame::Binary(bytes) => Message::Binary(bytes),
            ConnectionFrame::Ping(bytes) => Message::Ping(bytes),
            ConnectionFrame::Pong(bytes) => Message::Pong(bytes),
            ConnectionFrame::Close => Message::Close(None),
            ConnectionFrame::Text => return Err("server text frames are forbidden".to_owned()),
        };
        SinkExt::send(self, message)
            .await
            .map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod limit_tests {
    use odin_domain::huginn::{ConnectionId, DeviceId, TailnetNodeId, VerifiedColinDevice};
    use uuid::Uuid;

    use super::{ConnectionRegistry, RegistryError};

    fn connection(device: DeviceId) -> VerifiedColinDevice {
        VerifiedColinDevice {
            device_id: device,
            tailnet_node_id: TailnetNodeId::parse("node.laptop").unwrap(),
            connection_id: ConnectionId::new(Uuid::new_v4()).unwrap(),
        }
    }

    #[test]
    fn the_connection_cap_is_per_device_and_says_why() {
        let registry = ConnectionRegistry::with_limit(2);
        let laptop = DeviceId::new(Uuid::new_v4()).unwrap();
        let phone = DeviceId::new(Uuid::new_v4()).unwrap();
        let held: Vec<_> = (0..2)
            .map(|_| registry.register(&connection(laptop)).expect("admitted"))
            .collect();
        let refused = registry
            .register(&connection(laptop))
            .err()
            .expect("capped");
        assert!(matches!(
            refused,
            RegistryError::ConnectionLimit { limit: 2 }
        ));
        assert!(refused.to_string().contains("max_connections"), "{refused}");
        let _phone = registry
            .register(&connection(phone))
            .expect("another device is not locked out");
        assert_eq!(registry.active_connections(), 3);
        drop(held);
    }
}

#[cfg(test)]
mod revoke_tests {
    use super::*;
    use crate::auth::AuthError;
    use crate::devices::{
        DeviceAdmin, DeviceTrustStore, NewDeviceGrant, NewDeviceRecord, SqliteDeviceTrustStore,
    };
    use odin_domain::{Digest, SeatTokenId, SessionId};
    use time::OffsetDateTime;

    #[tokio::test]
    async fn poisoned_registry_refuses_only_after_ledger_and_store_revocation() {
        let registry = ConnectionRegistry::new();
        let device = DeviceId::new(uuid::Uuid::new_v4()).unwrap();
        let registration = registry
            .register(&VerifiedColinDevice {
                device_id: device,
                tailnet_node_id: odin_domain::huginn::TailnetNodeId::parse("node.phone").unwrap(),
                connection_id: odin_domain::huginn::ConnectionId::new(uuid::Uuid::new_v4())
                    .unwrap(),
            })
            .unwrap();
        let inner = registry.inner.clone();
        assert!(std::thread::spawn(move || {
            let _guard = inner.lock().expect("registry initially healthy");
            panic!("poison registry");
        })
        .join()
        .is_err());
        let store = Arc::new(SqliteDeviceTrustStore::open_in_memory().unwrap());
        store
            .insert(NewDeviceRecord {
                device_id: device,
                tailnet_node_id: odin_domain::huginn::TailnetNodeId::parse("node.phone").unwrap(),
                label: "phone".to_owned(),
                credential_digest: Digest::hash(b"credential"),
                created_at: OffsetDateTime::UNIX_EPOCH,
            })
            .await
            .unwrap();
        let token = SeatTokenId::new("seat-token:7:poison").unwrap();
        store
            .claim_grant(NewDeviceGrant {
                device_id: device,
                session_id: SessionId::new("session-poison").unwrap(),
                token_id: token.clone(),
                created_at: OffsetDateTime::UNIX_EPOCH,
            })
            .await
            .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let ledger_path = directory.path().join("ledger.sqlite");
        let ledger = odin_ledger::Ledger::open(&ledger_path).unwrap();
        let expected_token = token.clone();
        let admin = DeviceAdmin::new(store.clone(), registry);
        let result = admin.revoke_ledger_first(device, move |grants| async move {
            assert_eq!(grants.len(), 1);
            assert_eq!(grants[0].token_id, expected_token);
            for grant in grants {
                let status = serde_json::json!({
                    "token_id": grant.token_id.as_str(), "revoked_at_ms": 0,
                }).to_string();
                let source = format!("seat-token-revocation:{}", grant.token_id.as_str());
                ledger.connection().execute(
                    "INSERT INTO materialized_status
                     (object_kind, object_id, revision, status_json, source_event_id, updated_at, stale_after)
                     VALUES ('seat_token_revocation', ?1, 1, ?2, ?3, '1970-01-01T00:00:00Z', NULL)
                     ON CONFLICT(object_kind, object_id) DO NOTHING",
                    (grant.token_id.as_str(), status.as_str(), source.as_str()),
                ).map_err(|error| error.to_string())?;
            }
            Ok(())
        }).await;
        assert!(matches!(
            result,
            Err(AuthError::Registry(RegistryError::Poisoned))
        ));
        assert!(
            !*registration.revocation().borrow(),
            "poison must not claim a successful close"
        );
        let reopened = odin_ledger::Ledger::open(&ledger_path).unwrap();
        let revoked: bool = reopened
            .connection()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM materialized_status
             WHERE object_kind = 'seat_token_revocation' AND object_id = ?1)",
                [token.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            revoked,
            "registry failure must not precede durable ledger revocation"
        );
        assert!(store
            .get(device)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some());
        assert!(store.grants(device).await.unwrap().is_empty());
    }
}
