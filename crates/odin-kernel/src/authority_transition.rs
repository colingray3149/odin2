//! Sole kernel authority-transition and dispatch controller.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use odin_domain::{Actor, CommandId, Digest, EventId, NodeId, Redaction, Scope};
use odin_ledger::audit::{append_audit_event_in_tx, AuditEvent, NewAuditEvent, RedactedPayload};
use odin_ledger::idempotency::{self, IdempotencyClaim};
use odin_ledger::{Ledger, LedgerError};
use odin_registry::{ObjectConfig, Snapshot, SnapshotError, SnapshotStore};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorityAuditKind {
    RegistryPublication,
    ProcessReplacement,
    OldAuthorityDenied,
    NewAuthorityAccepted,
}

impl AuthorityAuditKind {
    fn label(self) -> &'static str {
        match self {
            Self::RegistryPublication => "registry-publication",
            Self::ProcessReplacement => "process-replacement",
            Self::OldAuthorityDenied => "old-authority-denied",
            Self::NewAuthorityAccepted => "new-authority-accepted",
        }
    }
    fn event_kind(self) -> String {
        format!("authority.{}", self.label())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityState {
    pub local_node: NodeId,
    pub authoritative_node: NodeId,
    pub authoritative_host: String,
    pub snapshot_revision: u64,
    pub snapshot_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityTransitionPlan {
    pub old_node: NodeId,
    pub new_node: NodeId,
    pub old_host: String,
    pub new_host: String,
    pub before_revision: u64,
    pub after_revision: u64,
    pub before_hash: String,
    pub after_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityDispatchRequest {
    pub idempotency_key: String,
    pub command_digest: Digest,
    pub observed_at: OffsetDateTime,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityDispatchReceipt {
    pub command_id: CommandId,
    pub command_digest: Digest,
    pub inserted: bool,
    pub audit_sequence: Option<i64>,
    pub authority_node: NodeId,
    pub snapshot_revision: u64,
    pub snapshot_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityTransitionReceipt {
    pub plan: AuthorityTransitionPlan,
    pub transition_audit_sequence: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityAuditRecord {
    pub sequence: i64,
    pub event_id: String,
    pub kind: AuthorityAuditKind,
    pub publication_revision: Option<u64>,
    pub snapshot_hash: Option<String>,
    pub old_node: Option<NodeId>,
    pub new_node: Option<NodeId>,
    pub command_id: Option<CommandId>,
    pub command_digest: Option<Digest>,
    pub idempotency_key: Option<String>,
    pub occurred_at: OffsetDateTime,
}

#[derive(Debug, Error)]
pub enum AuthorityTransitionError {
    #[error(transparent)]
    Snapshot(#[from] SnapshotError),
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("invalid authority transition: {0}")]
    Invalid(String),
    #[error("node {local} is not authoritative; authority is {authoritative}")]
    AuthorityMismatch {
        local: NodeId,
        authoritative: NodeId,
        audit_sequence: Option<i64>,
    },
    #[error("follower node {local} cannot {operation}; authority is {authoritative}")]
    FollowerRefusal {
        local: NodeId,
        authoritative: NodeId,
        operation: &'static str,
    },
    #[error("idempotency key {key:?} already binds digest {expected_digest}, not {actual_digest}")]
    DispatchConflict {
        key: String,
        expected_digest: Digest,
        actual_digest: Digest,
    },
}

/// Followers reject mutations before store access or audit writes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorityMode {
    Authoritative,
    Follower,
}

pub struct AuthorityTransitionController {
    state_root: PathBuf,
    ledger_path: PathBuf,
    store: SnapshotStore,
    snapshot: Arc<Snapshot>,
    local_node: NodeId,
    authoritative_node: NodeId,
    pinned: bool,
    mode: AuthorityMode,
    ledger: Ledger,
}

impl AuthorityTransitionController {
    pub fn open_published(
        state_root: impl Into<PathBuf>,
        store: SnapshotStore,
        local_node: NodeId,
    ) -> Result<Self, AuthorityTransitionError> {
        let snapshot = Arc::new(store.load_verified()?);
        Self::open_with_store(
            state_root.into(),
            store,
            snapshot,
            local_node,
            AuthorityMode::Authoritative,
        )
    }

    pub fn open_snapshot(
        state_root: impl Into<PathBuf>,
        snapshot: Arc<Snapshot>,
        local_node: NodeId,
    ) -> Result<Self, AuthorityTransitionError> {
        snapshot.verify()?;
        let state_root = state_root.into();
        let store = SnapshotStore::new(state_root.join("pinned-registry-unavailable"));
        let mut controller = Self::open_with_store(
            state_root,
            store,
            snapshot,
            local_node,
            AuthorityMode::Authoritative,
        )?;
        controller.pinned = true;
        Ok(controller)
    }

    /// Require a different authoritative node in the snapshot before opening read-only access.
    pub fn open_snapshot_follower(
        state_root: impl Into<PathBuf>,
        snapshot: Arc<Snapshot>,
        local_node: NodeId,
    ) -> Result<Self, AuthorityTransitionError> {
        snapshot.verify()?;
        let state_root = state_root.into();
        let store = SnapshotStore::new(state_root.join("pinned-registry-unavailable"));
        let view = authority_state(&snapshot, &local_node)?;
        if view.local_node == view.authoritative_node {
            return Err(AuthorityTransitionError::Invalid(
                "the authoritative node must open through the strict authoritative \
                 open, never as a follower"
                    .to_owned(),
            ));
        }
        let mut controller = Self::open_with_store(
            state_root,
            store,
            snapshot,
            local_node,
            AuthorityMode::Follower,
        )?;
        controller.pinned = true;
        Ok(controller)
    }

    fn open_with_store(
        state_root: PathBuf,
        store: SnapshotStore,
        snapshot: Arc<Snapshot>,
        local_node: NodeId,
        mode: AuthorityMode,
    ) -> Result<Self, AuthorityTransitionError> {
        let view = authority_state(&snapshot, &local_node)?;
        if mode == AuthorityMode::Authoritative && view.local_node != view.authoritative_node {
            return Err(AuthorityTransitionError::AuthorityMismatch {
                local: view.local_node,
                authoritative: view.authoritative_node,
                audit_sequence: None,
            });
        }
        std::fs::create_dir_all(&state_root)?;
        let ledger_path = state_root.join("ledger.sqlite3");
        let ledger = Ledger::open(&ledger_path)?;
        Ok(Self {
            state_root,
            ledger_path,
            store,
            snapshot,
            local_node,
            authoritative_node: view.authoritative_node,
            pinned: false,
            mode,
            ledger,
        })
    }

    pub fn refresh_pinned(
        &mut self,
        snapshot: Arc<Snapshot>,
    ) -> Result<AuthorityState, AuthorityTransitionError> {
        if self.mode == AuthorityMode::Follower {
            return Err(self.refuse_follower("refresh the pinned snapshot"));
        }
        snapshot.verify()?;
        let state = authority_state(&snapshot, &self.local_node)?;
        self.snapshot = snapshot;
        self.authoritative_node = state.authoritative_node.clone();
        self.pinned = true;
        Ok(state)
    }
    pub fn startup(&mut self) -> Result<AuthorityState, AuthorityTransitionError> {
        self.reload_if_published()?;
        authority_state(&self.snapshot, &self.local_node)
    }

    pub fn plan_transition(
        before: &Snapshot,
        after: &Snapshot,
        old_node: &NodeId,
        new_node: &NodeId,
    ) -> Result<AuthorityTransitionPlan, AuthorityTransitionError> {
        before.verify()?;
        after.verify()?;
        let before_view = authority_view(before)?;
        let after_view = authority_view(after)?;
        if &before_view.0 != old_node || &after_view.0 != new_node || old_node == new_node {
            return Err(AuthorityTransitionError::Invalid(
                "snapshots do not move authority between the requested nodes".to_owned(),
            ));
        }
        if after.revision
            != before
                .revision
                .checked_add(1)
                .ok_or_else(|| AuthorityTransitionError::Invalid("revision overflow".to_owned()))?
        {
            return Err(AuthorityTransitionError::Invalid(
                "transition requires consecutive published revisions".to_owned(),
            ));
        }
        Ok(AuthorityTransitionPlan {
            old_node: old_node.clone(),
            new_node: new_node.clone(),
            old_host: before_view.1,
            new_host: after_view.1,
            before_revision: before.revision,
            after_revision: after.revision,
            before_hash: before.hash.clone(),
            after_hash: after.hash.clone(),
        })
    }

    pub fn apply_transition(
        &mut self,
        next_store: SnapshotStore,
        expected_before_revision: u64,
        expected_after_revision: u64,
        new_node: NodeId,
        idempotency_key: &str,
    ) -> Result<AuthorityTransitionReceipt, AuthorityTransitionError> {
        if self.mode == AuthorityMode::Follower {
            return Err(self.refuse_follower("apply an authority transition"));
        }
        if idempotency_key.trim().is_empty() {
            return Err(AuthorityTransitionError::Invalid(
                "transition idempotency key is empty".to_owned(),
            ));
        }
        if self.snapshot.revision != expected_before_revision {
            return Err(AuthorityTransitionError::Invalid(
                "pinned before revision changed".to_owned(),
            ));
        }
        let after = Arc::new(next_store.load_verified()?);
        if after.revision != expected_after_revision {
            return Err(AuthorityTransitionError::Invalid(
                "published after revision differs from expectation".to_owned(),
            ));
        }
        let plan = Self::plan_transition(&self.snapshot, &after, &self.local_node, &new_node)?;
        let audit = self.append_audit(AuthorityAuditRecord {
            sequence: 0,
            event_id: String::new(),
            kind: AuthorityAuditKind::ProcessReplacement,
            publication_revision: Some(after.revision),
            snapshot_hash: Some(after.hash.clone()),
            old_node: Some(self.local_node.clone()),
            new_node: Some(new_node),
            command_id: None,
            command_digest: None,
            idempotency_key: Some(idempotency_key.to_owned()),
            occurred_at: OffsetDateTime::now_utc(),
        })?;
        self.authoritative_node = authority_view(&after)?.0;
        self.store = next_store;
        self.snapshot = after;
        Ok(AuthorityTransitionReceipt {
            plan,
            transition_audit_sequence: audit.sequence,
        })
    }

    /// Pinned snapshots have no store to swap; production uses `apply_transition`.
    pub fn apply_transition_pinned(
        &mut self,
        after: Arc<Snapshot>,
        new_node: NodeId,
        idempotency_key: &str,
    ) -> Result<AuthorityTransitionReceipt, AuthorityTransitionError> {
        if self.mode == AuthorityMode::Follower {
            return Err(self.refuse_follower("apply a pinned authority transition"));
        }
        if idempotency_key.trim().is_empty() {
            return Err(AuthorityTransitionError::Invalid(
                "transition idempotency key is empty".to_owned(),
            ));
        }
        after.verify()?;
        let plan = Self::plan_transition(&self.snapshot, &after, &self.local_node, &new_node)?;
        let audit = self.append_audit(AuthorityAuditRecord {
            sequence: 0,
            event_id: String::new(),
            kind: AuthorityAuditKind::ProcessReplacement,
            publication_revision: Some(after.revision),
            snapshot_hash: Some(after.hash.clone()),
            old_node: Some(self.local_node.clone()),
            new_node: Some(new_node),
            command_id: None,
            command_digest: None,
            idempotency_key: Some(idempotency_key.to_owned()),
            occurred_at: OffsetDateTime::now_utc(),
        })?;
        self.authoritative_node = authority_view(&after)?.0;
        self.snapshot = after;
        self.pinned = true;
        Ok(AuthorityTransitionReceipt {
            plan,
            transition_audit_sequence: audit.sequence,
        })
    }

    pub fn guard_dispatch(
        &mut self,
        request: &AuthorityDispatchRequest,
    ) -> Result<AuthorityDispatchReceipt, AuthorityTransitionError> {
        if request.idempotency_key.trim().is_empty() {
            return Err(AuthorityTransitionError::Invalid(
                "dispatch idempotency key is empty".to_owned(),
            ));
        }
        if self.mode == AuthorityMode::Follower {
            return Err(self.refuse_follower("claim an authority dispatch"));
        }
        self.reload_if_published()?;
        let (authority, _) = authority_view(&self.snapshot)?;
        let command_id = command_id(&request.idempotency_key, request.command_digest)?;
        if authority != self.local_node {
            let denied = self.append_audit(AuthorityAuditRecord {
                sequence: 0,
                event_id: String::new(),
                kind: AuthorityAuditKind::OldAuthorityDenied,
                publication_revision: Some(self.snapshot.revision),
                snapshot_hash: Some(self.snapshot.hash.clone()),
                old_node: Some(self.local_node.clone()),
                new_node: Some(authority.clone()),
                command_id: Some(command_id),
                command_digest: Some(request.command_digest),
                idempotency_key: Some(request.idempotency_key.clone()),
                occurred_at: request.observed_at,
            })?;
            return Err(AuthorityTransitionError::AuthorityMismatch {
                local: self.local_node.clone(),
                authoritative: authority,
                audit_sequence: Some(denied.sequence),
            });
        }
        let key = request.idempotency_key.clone();
        let digest = request.command_digest;
        let local = self.local_node.clone();
        let revision = self.snapshot.revision;
        let hash = self.snapshot.hash.clone();
        let occurred = request.observed_at;
        let result = self.ledger.with_tx(|transaction| {
            match idempotency::claim(transaction, &key, &command_id, occurred)? {
                IdempotencyClaim::Inserted => {
                    let record = AuthorityAuditRecord {
                        sequence: 0,
                        event_id: String::new(),
                        kind: AuthorityAuditKind::NewAuthorityAccepted,
                        publication_revision: Some(revision),
                        snapshot_hash: Some(hash.clone()),
                        old_node: None,
                        new_node: Some(local.clone()),
                        command_id: Some(command_id.clone()),
                        command_digest: Some(digest),
                        idempotency_key: Some(key.clone()),
                        occurred_at: occurred,
                    };
                    let event = to_new_audit_event(&record).map_err(|error| {
                        LedgerError::invalid_data_caused_by("invalid authority audit event", error)
                    })?;
                    Ok((true, Some(append_audit_event_in_tx(transaction, event)?)))
                }
                IdempotencyClaim::Existing {
                    command_id: existing,
                } if existing == command_id => Ok((false, None)),
                IdempotencyClaim::Existing { .. } => Err(LedgerError::Conflict(
                    "authority dispatch digest conflict".to_owned(),
                )),
            }
        });
        let (inserted, audit_sequence) = match result {
            Ok((true, sequence)) => (true, sequence),
            Ok((false, _)) => (false, None),
            Err(LedgerError::Conflict(message))
                if message == "authority dispatch digest conflict" =>
            {
                let expected_digest = self
                    .existing_dispatch_digest(&request.idempotency_key)?
                    .unwrap_or(digest);
                return Err(AuthorityTransitionError::DispatchConflict {
                    key: request.idempotency_key.clone(),
                    expected_digest,
                    actual_digest: digest,
                });
            }
            Err(error) => return Err(error.into()),
        };
        Ok(AuthorityDispatchReceipt {
            command_id,
            command_digest: digest,
            inserted,
            audit_sequence,
            authority_node: local,
            snapshot_revision: revision,
            snapshot_hash: hash,
        })
    }

    pub fn authority_audit(&self) -> Result<Vec<AuthorityAuditRecord>, AuthorityTransitionError> {
        let mut records = Vec::new();
        let mut after = 0i64;
        loop {
            let batch = self.ledger.audit_events_after(after, 1000)?;
            if batch.is_empty() {
                break;
            }
            after = batch.last().map_or(after, |event| event.sequence);
            for event in batch {
                if event.kind.starts_with("authority.") {
                    records.push(decode_audit_event(event)?);
                }
            }
        }
        Ok(records)
    }

    pub fn ledger_path(&self) -> &Path {
        &self.ledger_path
    }
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }
    /// Follower status cannot change without reopening the controller.
    pub fn is_authoritative(&self) -> bool {
        self.mode == AuthorityMode::Authoritative
    }

    /// Refuse follower mutations before any store access or audit write.
    fn refuse_follower(&self, operation: &'static str) -> AuthorityTransitionError {
        AuthorityTransitionError::FollowerRefusal {
            local: self.local_node.clone(),
            authoritative: self.authoritative_node.clone(),
            operation,
        }
    }

    fn reload_if_published(&mut self) -> Result<(), AuthorityTransitionError> {
        if !self.pinned && self.store.path().try_exists()? {
            self.snapshot = Arc::new(self.store.load_verified()?);
        }
        Ok(())
    }

    fn append_audit(
        &mut self,
        mut record: AuthorityAuditRecord,
    ) -> Result<AuthorityAuditRecord, AuthorityTransitionError> {
        let event = to_new_audit_event(&record)?;
        record.event_id = event.event_id.to_string();
        let sequence = self
            .ledger
            .with_tx(|transaction| append_audit_event_in_tx(transaction, event))?;
        record.sequence = sequence;
        Ok(record)
    }

    fn existing_dispatch_digest(
        &self,
        key: &str,
    ) -> Result<Option<Digest>, AuthorityTransitionError> {
        Ok(self.authority_audit()?.into_iter().find_map(|record| {
            (record.kind == AuthorityAuditKind::NewAuthorityAccepted
                && record.idempotency_key.as_deref() == Some(key))
            .then_some(record.command_digest)
            .flatten()
        }))
    }
}

fn authority_view(snapshot: &Snapshot) -> Result<(NodeId, String), AuthorityTransitionError> {
    let mut found = None;
    for object in &snapshot.objects {
        let ObjectConfig::Node(node) = &object.config else {
            continue;
        };
        if !node.enabled || !node.authoritative_state {
            continue;
        }
        if found.is_some() {
            return Err(AuthorityTransitionError::Invalid(
                "snapshot has multiple authoritative enabled nodes".to_owned(),
            ));
        }
        let host = snapshot
            .objects
            .iter()
            .find_map(|candidate| {
                if candidate.id != node.host {
                    return None;
                }
                match &candidate.config {
                    ObjectConfig::Host(host) if host.enabled && host.enrolled => Some(host),
                    _ => None,
                }
            })
            .ok_or_else(|| {
                AuthorityTransitionError::Invalid(format!(
                    "authority node {} has no enabled enrolled host {}",
                    object.id, node.host
                ))
            })?;
        if host.role != node.role {
            return Err(AuthorityTransitionError::Invalid(
                "authority node and host roles differ".to_owned(),
            ));
        }
        found = Some((
            NodeId::new(object.id.clone())
                .map_err(|error| AuthorityTransitionError::Invalid(error.to_string()))?,
            node.host.clone(),
        ));
    }
    found.ok_or_else(|| {
        AuthorityTransitionError::Invalid("snapshot has no authoritative enabled node".to_owned())
    })
}

fn authority_state(
    snapshot: &Snapshot,
    local: &NodeId,
) -> Result<AuthorityState, AuthorityTransitionError> {
    let (authority, host) = authority_view(snapshot)?;
    Ok(AuthorityState {
        local_node: local.clone(),
        authoritative_node: authority,
        authoritative_host: host,
        snapshot_revision: snapshot.revision,
        snapshot_hash: snapshot.hash.clone(),
    })
}

fn command_id(key: &str, digest: Digest) -> Result<CommandId, AuthorityTransitionError> {
    let encoded = Digest::hash(format!("{key}\0{digest}").as_bytes()).to_string();
    let suffix = encoded
        .trim_start_matches("blake3:")
        .get(..32)
        .ok_or_else(|| AuthorityTransitionError::Invalid("short digest".to_owned()))?;
    CommandId::new(format!("authority:{suffix}"))
        .map_err(|error| AuthorityTransitionError::Invalid(error.to_string()))
}

fn event_id(
    kind: AuthorityAuditKind,
    record: &AuthorityAuditRecord,
) -> Result<String, AuthorityTransitionError> {
    let bytes = serde_json::to_vec(&(
        kind,
        record.publication_revision,
        &record.snapshot_hash,
        &record.old_node,
        &record.new_node,
        &record.command_id,
        record.command_digest,
        &record.idempotency_key,
    ))
    .map_err(|error| AuthorityTransitionError::Invalid(error.to_string()))?;
    let encoded = Digest::hash(&bytes).to_string();
    let suffix = encoded
        .trim_start_matches("blake3:")
        .get(..32)
        .ok_or_else(|| AuthorityTransitionError::Invalid("short digest".to_owned()))?;
    Ok(format!("authority:{}:{suffix}", kind.label()))
}

fn to_new_audit_event(
    record: &AuthorityAuditRecord,
) -> Result<NewAuditEvent, AuthorityTransitionError> {
    let event_id = EventId::new(event_id(record.kind, record)?)
        .map_err(|error| AuthorityTransitionError::Invalid(error.to_string()))?;
    let actor = if let Some(node) = record.old_node.as_ref().or(record.new_node.as_ref()) {
        Actor::Node { node: node.clone() }
    } else {
        Actor::system("authority-transition")
            .map_err(|error| AuthorityTransitionError::Invalid(error.to_string()))?
    };
    let scope = Scope {
        node: record.new_node.clone().or_else(|| record.old_node.clone()),
        ..Scope::default()
    };
    let payload = serde_json::to_value(record)
        .map_err(|error| AuthorityTransitionError::Invalid(error.to_string()))?;
    Ok(NewAuditEvent {
        event_id,
        kind: record.kind.event_kind(),
        actor,
        scope,
        evidence: Vec::new(),
        payload: RedactedPayload::new(payload, Redaction::None)?,
        occurred_at: record.occurred_at,
    })
}

fn decode_audit_event(event: AuditEvent) -> Result<AuthorityAuditRecord, AuthorityTransitionError> {
    let mut record: AuthorityAuditRecord = serde_json::from_value(event.payload)
        .map_err(|error| AuthorityTransitionError::Invalid(error.to_string()))?;
    if event.kind != record.kind.event_kind() {
        return Err(AuthorityTransitionError::Invalid(
            "authority audit kind/payload mismatch".to_owned(),
        ));
    }
    record.sequence = event.sequence;
    record.event_id = event.event_id.to_string();
    record.occurred_at = event.occurred_at;
    Ok(record)
}
