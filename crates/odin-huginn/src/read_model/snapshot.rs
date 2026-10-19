use std::collections::{btree_map::Entry, BTreeMap, VecDeque};
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use async_trait::async_trait;
use odin_domain::huginn::{
    Freshness, HuginnProtocolError, HuginnReadModel, ObjectDelta, ObjectDeltaBatch,
    ObjectDeltaBody, ObjectKind, ObjectRef, ObjectSnapshot, QueryScope, Revision, RevisionSource,
    SearchHit, SearchPage, SearchQuery, SnapshotPage, SnapshotQuery,
};
use odin_domain::Digest;
use serde::Serialize;
#[cfg(test)]
use serde_json::json;
use serde_json::Value;
use time::OffsetDateTime;
use tokio::sync::watch;

use super::delta::{apply_merge_patch, DeltaBatch};
use super::query::{
    decode_delta_cursor, decode_page_cursor, encode_delta_cursor, encode_page_cursor,
    includes_freshness, matches_kinds, matches_scope, normalized_search_text, page_query_digest,
    ProjectionMetadata, SEARCH_CURSOR, SNAPSHOT_CURSOR,
};
use super::search::relevance_micros;

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReadModelError {
    #[error("materialized object limit {limit} reached")]
    ObjectLimit { limit: usize },
    #[error("object {object_id} has stale revision {received}; current revision is {current}")]
    StaleRevision {
        object_id: String,
        received: Revision,
        current: Revision,
    },
    #[error("object {object_id} revision {revision} conflicts with existing content")]
    RevisionConflict {
        object_id: String,
        revision: Revision,
    },
    #[error("object {object_id} was not found")]
    NotFound { object_id: String },
    #[error("delta for {object_id} starts at {received}, current revision is {current}")]
    DeltaBaseMismatch {
        object_id: String,
        received: Revision,
        current: Revision,
    },
    #[error("revision overflow")]
    RevisionOverflow,
    #[error("cursor {message}")]
    InvalidCursor { message: String },
    #[error("cursor revision {requested} is no longer current; current revision is {current}")]
    CursorRevision {
        requested: Revision,
        current: Revision,
    },
    #[error("requested delta cursor is no longer retained")]
    CursorExpired,
    #[error(
        "delta at revision {revision} encodes to {bytes} bytes, over the {budget}-byte page \
         budget; take a snapshot"
    )]
    DeltaTooLarge {
        revision: Revision,
        bytes: usize,
        budget: usize,
    },
    #[error("projection serialization failed: {message}")]
    Serialization { message: String },
    #[error("read model state lock poisoned")]
    LockPoisoned,
}

impl From<PoisonError<RwLockReadGuard<'_, State>>> for ReadModelError {
    fn from(_: PoisonError<RwLockReadGuard<'_, State>>) -> Self {
        Self::LockPoisoned
    }
}

impl From<PoisonError<RwLockWriteGuard<'_, State>>> for ReadModelError {
    fn from(_: PoisonError<RwLockWriteGuard<'_, State>>) -> Self {
        Self::LockPoisoned
    }
}

impl From<ReadModelError> for HuginnProtocolError {
    fn from(error: ReadModelError) -> Self {
        match error {
            ReadModelError::LockPoisoned => Self::Unavailable {
                code: "read-model".to_owned(),
            },
            ReadModelError::ObjectLimit { limit } => Self::ResourceLimit {
                limit: format!("max materialized objects: {limit}"),
            },
            ReadModelError::NotFound { object_id } => Self::NotFound {
                object_kind: "object".to_owned(),
                object_id,
            },
            ReadModelError::CursorExpired => Self::CursorExpired,
            ReadModelError::DeltaTooLarge { .. } => Self::ResourceLimit {
                limit: error.to_string(),
            },
            ReadModelError::StaleRevision {
                received, current, ..
            }
            | ReadModelError::DeltaBaseMismatch {
                received, current, ..
            } => Self::RevisionMismatch {
                expected: received,
                actual: current,
            },
            other => Self::InvalidRequest {
                code: "read-model".to_owned(),
                message: other.to_string(),
            },
        }
    }
}

#[derive(Clone)]
pub struct MaterializedReadModel {
    inner: Arc<RwLock<State>>,
}

struct State {
    objects: BTreeMap<ObjectRef, IndexedObject>,
    deltas: VecDeque<RecordedDelta>,
    revision: Revision,
    /// Names this model in its page cursors. Revisions restart at zero
    /// with every model, so a cursor must also say which model issued it.
    incarnation: String,
    head_events: watch::Sender<u64>,
    generated_at: OffsetDateTime,
    max_objects: usize,
    max_deltas: usize,
}

struct IndexedObject {
    snapshot: ObjectSnapshot,
    metadata: Arc<ProjectionMetadata>,
}

struct RecordedDelta {
    revision: Revision,
    delta: ObjectDelta,
    /// Scope of the object just before this record took effect; `None`
    /// when the record created the object. The first covered record's
    /// pre-scope is the subscriber's membership at its cursor, so retained
    /// records stay self-sufficient however far the window slides.
    scope_pre: Option<Arc<ProjectionMetadata>>,
    /// Scope after this record took effect; `None` when it removed the
    /// object. A move carries the post scope only, so the old scope's
    /// subscriber sees the object leave and the new scope's see it arrive.
    scope_post: Option<Arc<ProjectionMetadata>>,
    /// The object's resolved value after this record; `None` when removed.
    post_state: Option<Arc<Value>>,
    /// CBOR size captured when the delta was recorded. `None` only when that
    /// encode failed; the page then retries and surfaces the same error.
    encoded_len: Option<usize>,
}

/// Atomic head capture: the model revision and the exact object set observed
/// in the same read-lock acquisition. A concurrent mutation can never pair a
/// new revision with stale objects, so consumers pinning a head and its items
/// can never tear.
#[derive(Clone, Debug)]
pub struct ReadModelCapture {
    /// Monotonic model revision at capture time.
    pub revision: Revision,
    /// Observation timestamp of the latest mutation before the capture.
    pub generated_at: OffsetDateTime,
    /// Every materialized object, in the deterministic `(kind, id)` order of
    /// the index map.
    pub objects: Vec<ObjectSnapshot>,
}

impl MaterializedReadModel {
    pub fn new(max_objects: usize, generated_at: OffsetDateTime) -> Self {
        let max_objects = max_objects.max(1);
        Self::with_limits(
            max_objects,
            max_objects.saturating_mul(2).max(1),
            generated_at,
        )
    }

    pub fn with_limits(
        max_objects: usize,
        max_deltas: usize,
        generated_at: OffsetDateTime,
    ) -> Self {
        let (head_events, _) = watch::channel(0);
        Self {
            inner: Arc::new(RwLock::new(State {
                objects: BTreeMap::new(),
                deltas: VecDeque::new(),
                revision: Revision::new(0),
                incarnation: uuid::Uuid::new_v4().simple().to_string(),
                head_events,
                generated_at,
                max_objects: max_objects.max(1),
                max_deltas: max_deltas.max(1),
            })),
        }
    }

    pub fn revision(&self) -> Result<Revision, ReadModelError> {
        let state = self.inner.read()?;
        Ok(state.revision)
    }

    pub fn len(&self) -> Result<usize, ReadModelError> {
        let state = self.inner.read()?;
        Ok(state.objects.len())
    }

    pub fn is_empty(&self) -> Result<bool, ReadModelError> {
        Ok(self.len()? == 0)
    }

    /// Captures the model head atomically: the returned revision and object
    /// set are the exact state after one lock acquisition, so pinning a head
    /// and projecting its items can never observe a torn pairing.
    pub fn capture(&self) -> Result<ReadModelCapture, ReadModelError> {
        let state = self.inner.read()?;
        Ok(ReadModelCapture {
            revision: state.revision,
            generated_at: state.generated_at,
            objects: state
                .objects
                .values()
                .map(|entry| entry.snapshot.clone())
                .collect(),
        })
    }

    /// Like [`Self::capture`], but clones only objects of `kinds`, still
    /// under one read lock. No scope filter: daemon-internal objects have
    /// empty projection scopes, and [`Self::snapshot_page`] would hide them.
    /// The revision is the model head, not a per-kind counter, so a fence
    /// that compares it to [`Self::revision`] still detects a torn read.
    /// Order matches `capture()`: `(kind, id)`.
    pub fn capture_kinds(&self, kinds: &[ObjectKind]) -> Result<ReadModelCapture, ReadModelError> {
        let state = self.inner.read()?;
        let mut objects = Vec::new();
        for kind in kinds {
            let start = ObjectRef {
                kind: *kind,
                id: String::new(),
            };
            for (key, entry) in state.objects.range(start..) {
                if key.kind != *kind {
                    break;
                }
                objects.push(entry.snapshot.clone());
            }
        }
        objects.sort_by(|left, right| left.object.cmp(&right.object));
        Ok(ReadModelCapture {
            revision: state.revision,
            generated_at: state.generated_at,
            objects,
        })
    }

    /// Subscribes to head-revision movements. The receiver observes the
    /// current revision immediately and is notified on every mutation that
    /// moves the model revision; a no-op write (an identical upsert) never
    /// emits. Values are the raw `Revision` counter as `u64`.
    pub fn subscribe_head(&self) -> Result<watch::Receiver<u64>, ReadModelError> {
        let state = self.inner.read()?;
        Ok(state.head_events.subscribe())
    }

    /// Test-only fault injection: poisons the state lock, the one
    /// failure mode of the read-only queries.
    #[cfg(test)]
    pub(crate) fn poison_state_lock_for_tests(&self) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = self
                .inner
                .write()
                .expect("lock unpoisoned before injection");
            panic!("poison the read-model state lock");
        }));
    }

    pub fn current_revision(&self, object: &ObjectRef) -> Result<Option<Revision>, ReadModelError> {
        let state = self.inner.read()?;
        Ok(state
            .objects
            .get(object)
            .map(|entry| entry.snapshot.revision))
    }

    pub fn get(&self, object: &ObjectRef) -> Result<Option<ObjectSnapshot>, ReadModelError> {
        let state = self.inner.read()?;
        Ok(state
            .objects
            .get(object)
            .map(|entry| entry.snapshot.clone()))
    }

    pub fn objects_of_kind(
        &self,
        kind: odin_domain::huginn::ObjectKind,
    ) -> Result<Vec<ObjectRef>, ReadModelError> {
        let state = self.inner.read()?;
        Ok(state
            .objects
            .keys()
            .filter(|object| object.kind == kind)
            .cloned()
            .collect())
    }

    pub fn upsert(&self, snapshot: ObjectSnapshot) -> Result<Option<ObjectDelta>, ReadModelError> {
        let metadata = metadata_from_snapshot(&snapshot);
        self.upsert_indexed(snapshot, metadata)
    }

    /// Materialize one snapshot under caller-supplied projection metadata.
    /// A scope move must bump the object revision: an equal-revision write
    /// whose snapshot is unchanged swaps metadata in place and records no
    /// delta, so subscribers learn of it only from the next revision.
    pub fn upsert_indexed(
        &self,
        snapshot: ObjectSnapshot,
        metadata: ProjectionMetadata,
    ) -> Result<Option<ObjectDelta>, ReadModelError> {
        let metadata = Arc::new(metadata);
        let mut state = self.inner.write()?;
        let existing_revision = state
            .objects
            .get(&snapshot.object)
            .map(|entry| entry.snapshot.revision);
        if let Some(current) = existing_revision {
            if snapshot.revision < current {
                return Err(ReadModelError::StaleRevision {
                    object_id: snapshot.object.id.clone(),
                    received: snapshot.revision,
                    current,
                });
            }
            if snapshot.revision == current {
                let existing = state.objects.get(&snapshot.object).expect("entry exists");
                if snapshot == existing.snapshot {
                    state
                        .objects
                        .get_mut(&snapshot.object)
                        .expect("entry exists")
                        .metadata = metadata;
                    return Ok(None);
                }
                return Err(ReadModelError::RevisionConflict {
                    object_id: snapshot.object.id.clone(),
                    revision: snapshot.revision,
                });
            }
        } else if state.objects.len() >= state.max_objects {
            return Err(ReadModelError::ObjectLimit {
                limit: state.max_objects,
            });
        }
        let scope_pre = state
            .objects
            .get(&snapshot.object)
            .map(|entry| entry.metadata.clone());
        let post_state = Arc::new(snapshot.value.clone());
        let delta = ObjectDelta {
            object: snapshot.object.clone(),
            from_revision: existing_revision.unwrap_or_else(|| Revision::new(0)),
            to_revision: snapshot.revision,
            revision_source: snapshot.revision_source.clone(),
            freshness: snapshot.freshness.clone(),
            body: ObjectDeltaBody::Replace(snapshot.value.clone()),
        };
        state.generated_at = snapshot.freshness.observed_at;
        state.objects.insert(
            snapshot.object.clone(),
            IndexedObject {
                snapshot,
                metadata: metadata.clone(),
            },
        );
        record_delta(
            &mut state,
            delta.clone(),
            scope_pre,
            Some(metadata),
            Some(post_state),
        )?;
        Ok(Some(delta))
    }

    pub fn apply(&self, delta: ObjectDelta) -> Result<(), ReadModelError> {
        let mut state = self.inner.write()?;
        let current = state
            .objects
            .get(&delta.object)
            .map(|entry| entry.snapshot.revision);
        if current.is_none()
            && (delta.from_revision != Revision::new(0)
                || !matches!(&delta.body, ObjectDeltaBody::Replace(_)))
        {
            return Err(ReadModelError::NotFound {
                object_id: delta.object.id.clone(),
            });
        }
        if let Some(current) = current {
            if current != delta.from_revision {
                return Err(ReadModelError::DeltaBaseMismatch {
                    object_id: delta.object.id.clone(),
                    received: delta.from_revision,
                    current,
                });
            }
        }
        if delta.to_revision <= delta.from_revision {
            return Err(ReadModelError::StaleRevision {
                object_id: delta.object.id.clone(),
                received: delta.to_revision,
                current: delta.from_revision,
            });
        }
        let (scope_pre, scope_post, post_state) = if current.is_none() {
            if state.objects.len() >= state.max_objects {
                return Err(ReadModelError::ObjectLimit {
                    limit: state.max_objects,
                });
            }
            let ObjectDeltaBody::Replace(value) = &delta.body else {
                unreachable!("missing objects accept only replacement deltas");
            };
            let encoded = serde_json::to_vec(value).map_err(serialization_error)?;
            let post_state = Arc::new(value.clone());
            let snapshot = ObjectSnapshot {
                object: delta.object.clone(),
                revision: delta.to_revision,
                revision_source: delta.revision_source.clone(),
                freshness: delta.freshness.clone(),
                content_digest: Digest::hash(&encoded),
                value: value.clone(),
            };
            let metadata = Arc::new(metadata_from_snapshot(&snapshot));
            state.objects.insert(
                delta.object.clone(),
                IndexedObject {
                    snapshot,
                    metadata: metadata.clone(),
                },
            );
            (None, Some(metadata), Some(post_state))
        } else {
            let scope_pre = state
                .objects
                .get(&delta.object)
                .map(|entry| entry.metadata.clone());
            match &delta.body {
                ObjectDeltaBody::Remove => {
                    state.objects.remove(&delta.object).expect("entry exists");
                    (scope_pre, None, None)
                }
                ObjectDeltaBody::Replace(value) => {
                    let entry = state.objects.get_mut(&delta.object).expect("entry exists");
                    entry.snapshot.value = value.clone();
                    update_snapshot_metadata(&mut entry.snapshot, &delta)?;
                    let post_state = Arc::new(entry.snapshot.value.clone());
                    let scope_post = Some(entry.metadata.clone());
                    (scope_post.clone(), scope_post, Some(post_state))
                }
                ObjectDeltaBody::MergePatch(patch) => {
                    let entry = state.objects.get_mut(&delta.object).expect("entry exists");
                    apply_merge_patch(&mut entry.snapshot.value, patch);
                    update_snapshot_metadata(&mut entry.snapshot, &delta)?;
                    let post_state = Arc::new(entry.snapshot.value.clone());
                    let scope_post = Some(entry.metadata.clone());
                    (scope_post.clone(), scope_post, Some(post_state))
                }
            }
        };
        state.generated_at = delta.freshness.observed_at;
        record_delta(&mut state, delta, scope_pre, scope_post, post_state)
    }

    pub fn remove(
        &self,
        object: ObjectRef,
        to_revision: Revision,
        revision_source: RevisionSource,
        freshness: Freshness,
    ) -> Result<Option<ObjectDelta>, ReadModelError> {
        let Some(current) = self.current_revision(&object)? else {
            return Ok(None);
        };
        let delta = ObjectDelta {
            object,
            from_revision: current,
            to_revision,
            revision_source,
            freshness,
            body: ObjectDeltaBody::Remove,
        };
        self.apply(delta.clone())?;
        Ok(Some(delta))
    }

    pub fn deltas_after(&self, after: Revision) -> Result<DeltaBatch, ReadModelError> {
        let state = self.inner.read()?;
        if after > state.revision {
            return Err(ReadModelError::CursorRevision {
                requested: after,
                current: state.revision,
            });
        }
        if let Some(first) = state.deltas.front() {
            if after.get() < first.revision.get().saturating_sub(1) {
                return Err(ReadModelError::CursorExpired);
            }
        }
        Ok(DeltaBatch {
            from_revision: after,
            to_revision: state.revision,
            deltas: state
                .deltas
                .iter()
                .filter(|entry| entry.revision > after)
                .map(|entry| entry.delta.clone())
                .collect(),
        })
    }

    /// One bounded page of [`Self::deltas_after`]: at most `limit` deltas
    /// whose CBOR encodings total at most `max_bytes`, so the response
    /// always fits the connection's frame. When deltas remain, the page ends
    /// at the last delivered revision and names it as `next_after`. A single
    /// delta over the budget is refused typed, never sent oversized.
    ///
    /// `after` is an opaque delta cursor: `"0"` for the empty model, or one
    /// this model issued. Another model's cursor — an earlier daemon's, at
    /// a revision this model may also hold — fails `CursorExpired`; a
    /// malformed or bare numeric one fails as an invalid cursor.
    pub fn deltas_page(
        &self,
        after: &str,
        limit: usize,
        max_bytes: usize,
    ) -> Result<odin_domain::huginn::DeltaPage, ReadModelError> {
        let state = self.inner.read()?;
        let after = match decode_delta_cursor(after)
            .map_err(|message| ReadModelError::InvalidCursor { message })?
        {
            None => Revision::new(0),
            Some((incarnation, revision)) => {
                if incarnation != state.incarnation {
                    return Err(ReadModelError::CursorExpired);
                }
                revision
            }
        };
        if after > state.revision {
            return Err(ReadModelError::CursorRevision {
                requested: after,
                current: state.revision,
            });
        }
        if let Some(first) = state.deltas.front() {
            if after.get() < first.revision.get().saturating_sub(1) {
                return Err(ReadModelError::CursorExpired);
            }
        }
        let mut deltas = Vec::new();
        let mut to_revision = after;
        let mut used = 0usize;
        let mut remaining = state
            .deltas
            .iter()
            .filter(|entry| entry.revision > after)
            .peekable();
        while let Some(entry) = remaining.peek() {
            if deltas.len() >= limit.max(1) {
                break;
            }
            let bytes = match entry.encoded_len {
                Some(bytes) => bytes,
                None => encoded_len(&entry.delta)?,
            };
            if used.saturating_add(bytes) > max_bytes {
                if deltas.is_empty() {
                    return Err(ReadModelError::DeltaTooLarge {
                        revision: entry.revision,
                        bytes,
                        budget: max_bytes,
                    });
                }
                break;
            }
            used += bytes;
            to_revision = entry.revision;
            deltas.push(entry.delta.clone());
            remaining.next();
        }
        let more = remaining.peek().is_some();
        let to_revision = if more { to_revision } else { state.revision };
        let checkpoint = encode_delta_cursor(&state.incarnation, to_revision);
        Ok(odin_domain::huginn::DeltaPage {
            from_revision: after,
            to_revision,
            deltas,
            next_after: more.then(|| checkpoint.clone()),
            checkpoint,
        })
    }

    /// One coalesced subscription page: every object matching `kinds` and
    /// `scope` at most once, resolved to its state inside the covered
    /// global-revision range. Membership comes from the records' own pre
    /// and post scopes, so a scope move delivers `Remove` to the old
    /// scope's subscriber and `Replace` of the full post state to the new
    /// scope's, deletions and metadata-only moves included, and nothing is
    /// delivered for objects the subscriber never held and does not hold
    /// at the range end. The page cuts on a global-revision boundary at
    /// the item and byte budget — never comparing an object's own revision
    /// to the global cursor — and a single object whose coalesced delta
    /// alone exceeds the byte budget is refused typed.
    pub fn object_deltas_page(
        &self,
        after: Revision,
        kinds: &[ObjectKind],
        scope: &QueryScope,
        limit: usize,
        max_bytes: usize,
    ) -> Result<ObjectDeltaBatch, ReadModelError> {
        let state = self.inner.read()?;
        if after > state.revision {
            return Err(ReadModelError::CursorRevision {
                requested: after,
                current: state.revision,
            });
        }
        if let Some(first) = state.deltas.front() {
            if after.get() < first.revision.get().saturating_sub(1) {
                return Err(ReadModelError::CursorExpired);
            }
        }
        let limit = limit.clamp(1, DELTA_PAGE_ITEMS);
        let start = state
            .deltas
            .iter()
            .position(|record| record.revision > after);
        let Some(start) = start else {
            return Ok(ObjectDeltaBatch {
                from_revision: after,
                to_revision: state.revision,
                deltas: Vec::new(),
                next_after: None,
            });
        };
        // Every draft evaluates exactly at its covered range end, so a
        // fitting draft is a sound page and a refused one names the record
        // that starts the next, smaller range. Range ends only move down —
        // coalescing sizes are not monotonic in the range, so nothing may
        // assume that a fitting prefix implies a fitting extension.
        let mut end = state.deltas.len();
        let draft = loop {
            let draft =
                subscription_page_draft(&state.deltas, start, end, kinds, scope, limit, max_bytes)?;
            if draft.fits {
                break draft;
            }
            match draft.boundary {
                Some(boundary) if boundary > start => end = boundary,
                _ => {
                    let (revision, bytes) = draft
                        .overflow
                        .expect("a refused draft reports its overflow");
                    return Err(ReadModelError::DeltaTooLarge {
                        revision,
                        bytes,
                        budget: max_bytes,
                    });
                }
            }
        };
        let full = draft.covered == state.deltas.len();
        let to_revision = if full {
            state.revision
        } else {
            state.deltas[draft.covered - 1].revision
        };
        Ok(ObjectDeltaBatch {
            from_revision: after,
            to_revision,
            deltas: draft.deltas,
            next_after: (!full).then_some(to_revision),
        })
    }

    /// Whether any record past `after` is urgent for the subscription —
    /// sessions and approvals, or incident status (exact grammar in
    /// [`urgent_object`](odin_domain::huginn::urgent_object)) — inside its
    /// kinds and scope, scanning only the retained records after the
    /// cursor. The flush-now signal for a coalescing push, answered
    /// without building a page, so urgency past a cut page still flushes
    /// the page the subscriber already holds.
    pub fn has_urgent_objects_since(
        &self,
        after: Revision,
        kinds: &[ObjectKind],
        scope: &QueryScope,
    ) -> Result<bool, ReadModelError> {
        let state = self.inner.read()?;
        Ok(state
            .deltas
            .iter()
            .rev()
            .take_while(|record| record.revision > after)
            .any(|record| {
                let urgent = odin_domain::huginn::urgent_object(
                    record.delta.object.kind,
                    &record.delta.object.id,
                );
                // A record that leaves the scope or deletes the object is
                // urgent for the scope losing it: the pre-scope is the
                // subscriber's view before the record, the post-scope the
                // view after it.
                let in_scope = record
                    .scope_pre
                    .as_ref()
                    .is_some_and(|metadata| matches_scope(metadata, scope))
                    || record
                        .scope_post
                        .as_ref()
                        .is_some_and(|metadata| matches_scope(metadata, scope));
                urgent && matches_kinds(record.delta.object.kind, kinds) && in_scope
            }))
    }

    /// One snapshot page. Its cursor binds this model, the query identity
    /// and the revision; the final page of an unfiltered snapshot — every
    /// scope and kind, stale objects included, the whole state raw sync
    /// applies deltas to — also names the raw delta cursor at its revision.
    pub fn snapshot_page(&self, query: SnapshotQuery) -> Result<SnapshotPage, ReadModelError> {
        let state = self.inner.read()?;
        let identity = page_query_digest(
            SNAPSHOT_CURSOR,
            &query.scope,
            &query.kinds,
            query.include_stale,
            None,
        )
        .map_err(serialization_error)?;
        let unfiltered =
            matches!(query.scope, QueryScope::All) && query.kinds.is_empty() && query.include_stale;
        let delta_cursor = |complete: bool| {
            (complete && unfiltered)
                .then(|| encode_delta_cursor(&state.incarnation, state.revision))
        };
        if query.if_revision == Some(state.revision) && query.cursor.is_none() {
            return Ok(SnapshotPage {
                revision: state.revision,
                generated_at: state.generated_at,
                objects: Vec::new(),
                next_cursor: None,
                delta_cursor: delta_cursor(true),
            });
        }
        let offset = checked_offset(
            query.cursor.as_deref(),
            SNAPSHOT_CURSOR,
            &identity,
            &state.incarnation,
            state.revision,
        )?;
        let matching: Vec<_> = state
            .objects
            .values()
            .filter(|entry| matches_scope(&entry.metadata, &query.scope))
            .filter(|entry| matches_kinds(entry.snapshot.object.kind, &query.kinds))
            .filter(|entry| includes_freshness(entry.snapshot.freshness.state, query.include_stale))
            .collect();
        if offset > matching.len() {
            return Err(ReadModelError::InvalidCursor {
                message: "offset lies beyond result set".to_owned(),
            });
        }
        let limit = usize::from(query.limit.get());
        let objects = matching
            .iter()
            .skip(offset)
            .take(limit)
            .map(|entry| entry.snapshot.clone())
            .collect();
        let next_offset = offset.saturating_add(limit);
        let next_cursor = (next_offset < matching.len()).then(|| {
            encode_page_cursor(
                SNAPSHOT_CURSOR,
                &state.incarnation,
                &identity,
                state.revision,
                next_offset,
            )
        });
        let delta_cursor = delta_cursor(next_cursor.is_none());
        Ok(SnapshotPage {
            revision: state.revision,
            generated_at: state.generated_at,
            objects,
            next_cursor,
            delta_cursor,
        })
    }

    pub fn search_page(&self, query: SearchQuery) -> Result<SearchPage, ReadModelError> {
        let state = self.inner.read()?;
        let identity = page_query_digest(
            SEARCH_CURSOR,
            &query.scope,
            &query.kinds,
            query.include_stale,
            Some(&query.text),
        )
        .map_err(serialization_error)?;
        let offset = checked_offset(
            query.cursor.as_deref(),
            SEARCH_CURSOR,
            &identity,
            &state.incarnation,
            state.revision,
        )?;
        let needle = normalized_search_text(&query.text);
        let mut ranked: Vec<_> = state
            .objects
            .values()
            .filter(|entry| matches_scope(&entry.metadata, &query.scope))
            .filter(|entry| matches_kinds(entry.snapshot.object.kind, &query.kinds))
            .filter(|entry| includes_freshness(entry.snapshot.freshness.state, query.include_stale))
            .filter_map(|entry| {
                let relevance_micros = if needle.is_empty() {
                    Some(1)
                } else {
                    relevance_micros(
                        &needle,
                        &entry.metadata.title,
                        &entry.metadata.summary,
                        &entry.snapshot.object.id,
                    )
                }?;
                Some((entry, relevance_micros))
            })
            .collect();
        ranked.sort_by(|left, right| {
            right
                .1
                .cmp(&left.1)
                .then_with(|| left.0.snapshot.object.cmp(&right.0.snapshot.object))
        });
        if offset > ranked.len() {
            return Err(ReadModelError::InvalidCursor {
                message: "offset lies beyond result set".to_owned(),
            });
        }
        let limit = usize::from(query.limit.get());
        let page_end = offset.saturating_add(limit);
        // The slot past the page is the extra hit. Truncating to `limit`
        // before this check would report a full page as the last page.
        let next_cursor = ranked.get(page_end).map(|_| {
            encode_page_cursor(
                SEARCH_CURSOR,
                &state.incarnation,
                &identity,
                state.revision,
                page_end,
            )
        });
        let hits = ranked
            .iter()
            .skip(offset)
            .take(limit)
            .map(|(entry, relevance_micros)| SearchHit {
                object: entry.snapshot.object.clone(),
                revision: entry.snapshot.revision,
                freshness: entry.snapshot.freshness.clone(),
                title: entry.metadata.title.clone(),
                summary: entry.metadata.summary.clone(),
                relevance_micros: *relevance_micros,
            })
            .collect();
        Ok(SearchPage { hits, next_cursor })
    }
}

#[async_trait]
impl HuginnReadModel for MaterializedReadModel {
    async fn snapshot(&self, query: SnapshotQuery) -> Result<SnapshotPage, HuginnProtocolError> {
        self.snapshot_page(query).map_err(Into::into)
    }

    async fn search(&self, query: SearchQuery) -> Result<SearchPage, HuginnProtocolError> {
        self.search_page(query).map_err(Into::into)
    }

    async fn deltas(
        &self,
        query: odin_domain::huginn::DeltaQuery,
        max_bytes: usize,
    ) -> Result<odin_domain::huginn::DeltaPage, HuginnProtocolError> {
        let limit = query
            .limit
            .map_or(DELTA_PAGE_ITEMS, |limit| usize::from(limit.get()))
            .min(DELTA_PAGE_ITEMS);
        self.deltas_page(&query.after, limit, max_bytes)
            .map_err(Into::into)
    }

    async fn object_deltas_page(
        &self,
        after: Revision,
        kinds: &[ObjectKind],
        scope: &QueryScope,
        limit: usize,
        max_bytes: usize,
    ) -> Result<ObjectDeltaBatch, HuginnProtocolError> {
        self.object_deltas_page(after, kinds, scope, limit, max_bytes)
            .map_err(Into::into)
    }

    async fn has_urgent_objects_since(
        &self,
        after: Revision,
        kinds: &[ObjectKind],
        scope: &QueryScope,
    ) -> Result<bool, HuginnProtocolError> {
        self.has_urgent_objects_since(after, kinds, scope)
            .map_err(Into::into)
    }

    async fn object_head_after(&self, known: Revision) -> Result<Revision, HuginnProtocolError> {
        let mut head = self
            .inner
            .read()
            .map_err(ReadModelError::from)?
            .head_events
            .subscribe();
        loop {
            let current = *head.borrow_and_update();
            if current > known.get() {
                return Ok(Revision::new(current));
            }
            head.changed()
                .await
                .map_err(|_| HuginnProtocolError::Unavailable {
                    code: "read-model".to_owned(),
                })?;
        }
    }
}

pub fn project_object<T: Serialize>(
    object: ObjectRef,
    revision: Revision,
    revision_source: RevisionSource,
    freshness: Freshness,
    value: &T,
    metadata: &ProjectionMetadata,
) -> Result<ObjectSnapshot, ReadModelError> {
    let data = serde_json::to_value(value).map_err(serialization_error)?;
    let mut wrapped = serde_json::Map::new();
    wrapped.insert("data".to_owned(), data);
    wrapped.insert(
        "evidenceLinks".to_owned(),
        serde_json::to_value(&metadata.evidence_links).map_err(serialization_error)?,
    );
    let wrapped = Value::Object(wrapped);
    let encoded = serde_json::to_vec(&wrapped).map_err(serialization_error)?;
    Ok(ObjectSnapshot {
        object,
        revision,
        revision_source,
        freshness,
        content_digest: Digest::hash(&encoded),
        value: wrapped,
    })
}

fn update_snapshot_metadata(
    snapshot: &mut ObjectSnapshot,
    delta: &ObjectDelta,
) -> Result<(), ReadModelError> {
    snapshot.revision = delta.to_revision;
    snapshot.revision_source = delta.revision_source.clone();
    snapshot.freshness = delta.freshness.clone();
    let encoded = serde_json::to_vec(&snapshot.value).map_err(serialization_error)?;
    snapshot.content_digest = Digest::hash(&encoded);
    Ok(())
}

/// Most deltas one `Deltas` page carries; the frame budget may cut it
/// shorter.
pub const DELTA_PAGE_ITEMS: usize = 256;

/// The CBOR-encoded size of one delta: the wire codec's own encoding.
fn encoded_len(delta: &ObjectDelta) -> Result<usize, ReadModelError> {
    let mut buffer = Vec::new();
    ciborium::ser::into_writer(delta, &mut buffer).map_err(|error| {
        ReadModelError::Serialization {
            message: error.to_string(),
        }
    })?;
    Ok(buffer.len())
}

fn record_delta(
    state: &mut State,
    delta: ObjectDelta,
    scope_pre: Option<Arc<ProjectionMetadata>>,
    scope_post: Option<Arc<ProjectionMetadata>>,
    post_state: Option<Arc<Value>>,
) -> Result<(), ReadModelError> {
    let encoded_len = encoded_len(&delta).ok();
    let revision = state
        .revision
        .checked_next()
        .ok_or(ReadModelError::RevisionOverflow)?;
    state.revision = revision;
    state.deltas.push_back(RecordedDelta {
        revision,
        delta,
        scope_pre,
        scope_post,
        post_state,
        encoded_len,
    });
    while state.deltas.len() > state.max_deltas {
        state.deltas.pop_front();
    }
    // Broadcast only after the head actually moved. The no-op upsert path
    // returns before reaching this point, so identical writes never emit.
    state.head_events.send_replace(revision.get());
    Ok(())
}

/// One coalescing pass over a global-revision-ordered record window. The
/// candidate map holds at most `limit` distinct objects — records for
/// objects already in the map keep updating it, and the walk stops at the
/// first record for a new object once it is full — so the pass is bounded
/// by the page cap, not by the retained window. Records carry their own
/// pre and post scopes, so the decision per object needs nothing but its
/// first and last covered record, evaluated exactly at the covered range
/// end.
struct PageDraft {
    deltas: Vec<ObjectDelta>,
    /// Index past the last walked record: the range this draft decided.
    covered: usize,
    /// When the draft does not fit, the record index that must start the
    /// next, smaller range: the byte-blocking object's first record, or
    /// the first record beyond the item cap.
    boundary: Option<usize>,
    /// The refused delta's revision and encoded size when the byte budget
    /// was the reason.
    overflow: Option<(Revision, usize)>,
    fits: bool,
}

fn subscription_page_draft(
    records: &VecDeque<RecordedDelta>,
    start: usize,
    end: usize,
    kinds: &[ObjectKind],
    scope: &QueryScope,
    limit: usize,
    max_bytes: usize,
) -> Result<PageDraft, ReadModelError> {
    let mut entries: BTreeMap<&ObjectRef, (usize, &RecordedDelta, &RecordedDelta)> =
        BTreeMap::new();
    let mut covered = start;
    let mut boundary = None;
    for (index, record) in records.iter().enumerate().skip(start).take(end - start) {
        if !matches_kinds(record.delta.object.kind, kinds) {
            // Excluded by the subscription itself: covered by the filter.
            covered = index + 1;
            continue;
        }
        let page_full = entries.len() >= limit;
        match entries.entry(&record.delta.object) {
            Entry::Occupied(mut slot) => {
                slot.get_mut().2 = record;
                covered = index + 1;
            }
            Entry::Vacant(slot) if !page_full => {
                slot.insert((index, record, record));
                covered = index + 1;
            }
            Entry::Vacant(_) => {
                // The page is full: this record is NOT covered — the cut
                // stays at the last decided record and the next range
                // starts here, so the checkpoint can never skip it.
                boundary = Some(index);
                break;
            }
        }
    }
    // First covered record per object, in first-revision order: distinct
    // records have distinct global revisions, so this sort is total and
    // the page order deterministic.
    let mut ordered: Vec<(usize, &RecordedDelta, &RecordedDelta)> = entries.into_values().collect();
    ordered.sort_unstable_by_key(|(first_index, first, _)| (*first_index, first.revision));
    let mut draft = PageDraft {
        deltas: Vec::with_capacity(ordered.len()),
        covered,
        boundary,
        overflow: None,
        fits: true,
    };
    let mut bytes = 0usize;
    for (first_index, first, last) in ordered {
        let held = first
            .scope_pre
            .as_ref()
            .is_some_and(|metadata| matches_scope(metadata, scope));
        let present = last
            .scope_post
            .as_ref()
            .is_some_and(|metadata| matches_scope(metadata, scope));
        let delta = if !held && !present {
            // Never inside the subscriber's view in this window: the
            // endpoints at both ends of the range agree it is absent.
            continue;
        } else if held && !present {
            // Left the scope or was deleted: one Remove based at the
            // earliest covered revision.
            ObjectDelta {
                object: first.delta.object.clone(),
                from_revision: first.delta.from_revision,
                to_revision: last.delta.to_revision,
                revision_source: last.delta.revision_source.clone(),
                freshness: last.delta.freshness.clone(),
                body: ObjectDeltaBody::Remove,
            }
        } else if std::ptr::eq(first, last) && held {
            // One covered record over a held base: the recorded delta
            // applies verbatim.
            first.delta.clone()
        } else {
            let Some(post_state) = &last.post_state else {
                continue;
            };
            ObjectDelta {
                object: first.delta.object.clone(),
                from_revision: first.delta.from_revision,
                to_revision: last.delta.to_revision,
                revision_source: last.delta.revision_source.clone(),
                freshness: last.delta.freshness.clone(),
                body: ObjectDeltaBody::Replace((**post_state).clone()),
            }
        };
        let encoded = encoded_len(&delta)?;
        if bytes + encoded > max_bytes {
            draft.fits = false;
            draft.overflow = Some((first.revision, encoded));
            draft.boundary = Some(first_index);
            break;
        }
        bytes += encoded;
        draft.deltas.push(delta);
    }
    Ok(draft)
}

fn checked_offset(
    cursor: Option<&str>,
    tag: &str,
    query: &str,
    incarnation: &str,
    revision: Revision,
) -> Result<usize, ReadModelError> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    let cursor = decode_page_cursor(tag, cursor)
        .map_err(|message| ReadModelError::InvalidCursor { message })?;
    // Another model's cursor — an earlier daemon's, at a revision this
    // model may also hold — pages nothing here: start a fresh query.
    if cursor.incarnation != incarnation {
        return Err(ReadModelError::CursorExpired);
    }
    // Another query's offset indexes another result set.
    if cursor.query != query {
        return Err(ReadModelError::InvalidCursor {
            message: "cursor belongs to another query".to_owned(),
        });
    }
    if cursor.revision != revision {
        return Err(ReadModelError::CursorRevision {
            requested: cursor.revision,
            current: revision,
        });
    }
    Ok(cursor.offset)
}

fn metadata_from_snapshot(snapshot: &ObjectSnapshot) -> ProjectionMetadata {
    let title = snapshot
        .value
        .get("title")
        .or_else(|| snapshot.value.get("displayName"))
        .and_then(Value::as_str)
        .unwrap_or(&snapshot.object.id)
        .to_owned();
    let summary = snapshot
        .value
        .get("summary")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    ProjectionMetadata::new(title, summary)
}

fn serialization_error(error: serde_json::Error) -> ReadModelError {
    ReadModelError::Serialization {
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use odin_domain::huginn::{Freshness, FreshnessState, ObjectDeltaBody, ObjectKind};

    fn freshness() -> Freshness {
        Freshness {
            state: FreshnessState::Fresh,
            observed_at: OffsetDateTime::UNIX_EPOCH,
            source_updated_at: None,
            stale_after_seconds: None,
        }
    }

    fn snapshot(kind: ObjectKind, id: &str, revision: u64, value: Value) -> ObjectSnapshot {
        ObjectSnapshot {
            object: ObjectRef {
                kind,
                id: id.to_owned(),
            },
            revision: Revision::new(revision),
            revision_source: RevisionSource::Registry,
            freshness: freshness(),
            content_digest: Digest::hash(value.to_string().as_bytes()),
            value,
        }
    }

    /// The raw delta cursor an unfiltered snapshot hands out at the head.
    fn held_delta_cursor(model: &MaterializedReadModel) -> String {
        model
            .snapshot_page(SnapshotQuery {
                scope: QueryScope::All,
                kinds: Vec::new(),
                if_revision: None,
                cursor: None,
                limit: std::num::NonZeroU16::new(64).expect("limit"),
                include_stale: true,
            })
            .unwrap()
            .delta_cursor
            .expect("an unfiltered final page names its delta cursor")
    }

    #[tokio::test]
    async fn deltas_request_serves_the_changes_after_a_known_revision() {
        let model = MaterializedReadModel::new(8, OffsetDateTime::UNIX_EPOCH);
        model
            .upsert(snapshot(
                ObjectKind::Device,
                "a",
                1,
                serde_json::json!({"n": 1}),
            ))
            .unwrap();
        let held = model.capture().unwrap().revision;
        let held_cursor = held_delta_cursor(&model);
        model
            .upsert(snapshot(
                ObjectKind::Device,
                "b",
                1,
                serde_json::json!({"n": 2}),
            ))
            .unwrap();
        model
            .upsert(snapshot(
                ObjectKind::Device,
                "a",
                2,
                serde_json::json!({"n": 3}),
            ))
            .unwrap();
        let page = HuginnReadModel::deltas(
            &model,
            odin_domain::huginn::DeltaQuery {
                after: held_cursor,
                limit: None,
            },
            1 << 20,
        )
        .await
        .unwrap();
        assert_eq!(page.from_revision, held);
        assert_eq!(page.deltas.len(), 2);
        assert_eq!(page.deltas[0].object.id, "b");
        assert_eq!(page.deltas[1].object.id, "a");
        assert_eq!(page.next_after, None);
        let caught_up = HuginnReadModel::deltas(
            &model,
            odin_domain::huginn::DeltaQuery {
                after: page.checkpoint.clone(),
                limit: None,
            },
            1 << 20,
        )
        .await
        .unwrap();
        assert!(caught_up.deltas.is_empty());
        assert_eq!(
            caught_up.checkpoint, page.checkpoint,
            "caught up resumes in place"
        );
        let incarnation = model.inner.read().unwrap().incarnation.clone();
        let forged_ahead =
            encode_delta_cursor(&incarnation, Revision::new(page.to_revision.get() + 5));
        for after in [forged_ahead, held.get().to_string()] {
            let refused = HuginnReadModel::deltas(
                &model,
                odin_domain::huginn::DeltaQuery { after, limit: None },
                1 << 20,
            )
            .await
            .unwrap_err();
            assert!(
                matches!(refused, HuginnProtocolError::InvalidRequest { .. }),
                "{refused:?}"
            );
        }
    }

    /// Delta pages must fit both byte and item limits without skipping revisions.
    #[tokio::test]
    async fn deltas_page_within_the_frame_budget_and_chain_to_the_head() {
        let model = MaterializedReadModel::new(64, OffsetDateTime::UNIX_EPOCH);
        let bulk = "x".repeat(4_000);
        for index in 0..40 {
            model
                .upsert(snapshot(
                    ObjectKind::Device,
                    &format!("d{index}"),
                    1,
                    serde_json::json!({ "n": index, "bulk": bulk }),
                ))
                .unwrap();
        }
        let head = model.revision().unwrap();
        let budget = 20_000;
        let mut after = "0".to_owned();
        let mut from = Revision::new(0);
        let mut seen = Vec::new();
        let mut pages = 0;
        loop {
            let page = HuginnReadModel::deltas(
                &model,
                odin_domain::huginn::DeltaQuery { after, limit: None },
                budget,
            )
            .await
            .unwrap();
            pages += 1;
            assert_eq!(page.from_revision, from);
            let mut encoded = Vec::new();
            ciborium::ser::into_writer(&page.deltas, &mut encoded).unwrap();
            assert!(encoded.len() <= budget + 16, "page {pages} stays in budget");
            seen.extend(page.deltas.iter().map(|delta| delta.object.id.clone()));
            match page.next_after {
                Some(next) => {
                    assert_eq!(next, page.checkpoint);
                    from = page.to_revision;
                    after = next;
                }
                None => {
                    assert_eq!(page.to_revision, head);
                    break;
                }
            }
        }
        assert!(pages > 1, "the window needed several pages");
        assert_eq!(seen.len(), 40);
        assert_eq!(seen.first().map(String::as_str), Some("d0"));
        assert_eq!(seen.last().map(String::as_str), Some("d39"));

        // The item cap pages too.
        let capped = HuginnReadModel::deltas(
            &model,
            odin_domain::huginn::DeltaQuery {
                after: "0".to_owned(),
                limit: std::num::NonZeroU16::new(3),
            },
            1 << 20,
        )
        .await
        .unwrap();
        assert_eq!(capped.deltas.len(), 3);
        assert_eq!(capped.to_revision, Revision::new(3));
        assert_eq!(capped.next_after.as_ref(), Some(&capped.checkpoint));

        let refused = HuginnReadModel::deltas(
            &model,
            odin_domain::huginn::DeltaQuery {
                after: "0".to_owned(),
                limit: None,
            },
            1_000,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(refused, HuginnProtocolError::ResourceLimit { .. }),
            "{refused:?}"
        );
    }

    #[test]
    fn capture_pairs_head_revision_with_exact_objects() {
        let model = MaterializedReadModel::new(8, OffsetDateTime::UNIX_EPOCH);
        model
            .upsert(snapshot(
                ObjectKind::Session,
                "s1",
                1,
                json!({"state": "running"}),
            ))
            .unwrap();
        model
            .upsert(snapshot(
                ObjectKind::Node,
                "n1",
                2,
                json!({"state": "ready"}),
            ))
            .unwrap();

        let capture = model.capture().unwrap();
        assert_eq!(capture.revision, Revision::new(2));
        assert_eq!(capture.objects.len(), 2);
        // Deterministic (kind, id) ordering: Session precedes Node.
        assert_eq!(capture.objects[0].object.id, "s1");
        assert_eq!(capture.objects[1].object.id, "n1");
    }

    /// Kind filter clones only the asked kinds and does not apply the
    /// scope filter `snapshot_page` uses. An unscoped session (the
    /// daemon-internal shape) stays visible; a seat-scoped page drops it.
    #[test]
    fn capture_kinds_clones_matching_entries_without_a_scope_filter() {
        use std::num::NonZeroU16;

        use odin_domain::huginn::QueryScope;
        use odin_domain::SeatId;

        let model = MaterializedReadModel::new(8, OffsetDateTime::UNIX_EPOCH);
        model
            .upsert(snapshot(
                ObjectKind::Session,
                "s1",
                1,
                json!({"state": "running"}),
            ))
            .unwrap();
        model
            .upsert(snapshot(
                ObjectKind::KubeResource,
                "pod-1",
                2,
                json!({"name": "pod-1"}),
            ))
            .unwrap();
        model
            .upsert(snapshot(
                ObjectKind::Node,
                "n1",
                3,
                json!({"state": "ready"}),
            ))
            .unwrap();

        let filtered = model
            .capture_kinds(&[ObjectKind::KubeResource, ObjectKind::Session])
            .unwrap();
        assert_eq!(filtered.revision, model.revision().unwrap());
        assert_eq!(filtered.objects.len(), 2);
        assert_eq!(filtered.objects[0].object.kind, ObjectKind::Session);
        assert_eq!(filtered.objects[0].object.id, "s1");
        assert_eq!(filtered.objects[1].object.kind, ObjectKind::KubeResource);

        let page = model
            .snapshot_page(SnapshotQuery {
                scope: QueryScope::Seat(SeatId::new("architect").expect("seat")),
                kinds: vec![ObjectKind::Session],
                if_revision: None,
                cursor: None,
                limit: NonZeroU16::new(8).expect("limit"),
                include_stale: true,
            })
            .unwrap();
        assert!(
            page.objects.is_empty(),
            "a seat scope hides the unscoped session snapshot_page would drop"
        );
    }

    #[test]
    fn capture_sees_merge_patch_mutation() {
        let model = MaterializedReadModel::new(8, OffsetDateTime::UNIX_EPOCH);
        model
            .upsert(snapshot(
                ObjectKind::Session,
                "s1",
                1,
                json!({"state": "running"}),
            ))
            .unwrap();

        model
            .apply(ObjectDelta {
                object: ObjectRef {
                    kind: ObjectKind::Session,
                    id: "s1".to_owned(),
                },
                from_revision: Revision::new(1),
                to_revision: Revision::new(2),
                revision_source: RevisionSource::Omp,
                freshness: freshness(),
                body: ObjectDeltaBody::MergePatch(json!({"state": "ended"})),
            })
            .unwrap();

        let capture = model.capture().unwrap();
        assert_eq!(capture.revision, Revision::new(2));
        assert_eq!(capture.objects.len(), 1);
        assert_eq!(capture.objects[0].value.get("state"), Some(&json!("ended")));
    }

    #[test]
    fn subscribe_head_tracks_revision_moves_and_skips_no_ops() {
        let model = MaterializedReadModel::new(8, OffsetDateTime::UNIX_EPOCH);
        let mut receiver = model.subscribe_head().unwrap();
        assert_eq!(*receiver.borrow(), 0);
        assert!(!receiver.has_changed().unwrap());

        model
            .upsert(snapshot(
                ObjectKind::Session,
                "s1",
                1,
                json!({"state": "running"}),
            ))
            .unwrap();
        assert!(receiver.has_changed().unwrap());
        assert_eq!(*receiver.borrow(), 1);
        receiver.borrow_and_update();

        // Identical content at the same object revision: a no-op write.
        model
            .upsert(snapshot(
                ObjectKind::Session,
                "s1",
                1,
                json!({"state": "running"}),
            ))
            .unwrap();
        assert!(!receiver.has_changed().unwrap());

        model
            .remove(
                ObjectRef {
                    kind: ObjectKind::Session,
                    id: "s1".to_owned(),
                },
                Revision::new(2),
                RevisionSource::Registry,
                freshness(),
            )
            .unwrap();
        assert!(receiver.has_changed().unwrap());
        assert_eq!(*receiver.borrow(), 2);
    }

    #[test]
    fn search_page_ranks_exact_title_ahead_of_prefix() {
        use std::num::NonZeroU16;

        use odin_domain::huginn::QueryScope;

        let model = MaterializedReadModel::new(8, OffsetDateTime::UNIX_EPOCH);
        model
            .upsert(snapshot(
                ObjectKind::Session,
                "b",
                1,
                json!({"title": "alphabet", "summary": ""}),
            ))
            .unwrap();
        model
            .upsert(snapshot(
                ObjectKind::Session,
                "a",
                2,
                json!({"title": "alpha", "summary": ""}),
            ))
            .unwrap();
        let query = SearchQuery {
            text: "Alpha".to_owned(),
            scope: QueryScope::All,
            kinds: Vec::new(),
            cursor: None,
            limit: NonZeroU16::new(1).expect("limit"),
            include_stale: true,
        };
        let page = model.search_page(query.clone()).unwrap();
        assert_eq!(page.hits.len(), 1);
        assert_eq!(page.hits[0].object.id, "a");
        assert_eq!(page.hits[0].title, "alpha");
        assert_eq!(page.hits[0].relevance_micros, 700_000);
        let cursor = page.next_cursor.expect("prefix hit remains past the limit");
        let next = model
            .search_page(SearchQuery {
                cursor: Some(cursor),
                ..query
            })
            .unwrap();
        assert_eq!(next.hits.len(), 1);
        assert_eq!(next.hits[0].object.id, "b");
        assert_eq!(next.hits[0].title, "alphabet");
        assert_eq!(next.hits[0].relevance_micros, 500_000);
        assert!(next.next_cursor.is_none());
    }

    use odin_domain::LaneId;

    fn lane(id: &str) -> QueryScope {
        QueryScope::Lane(LaneId::new(id).expect("lane id"))
    }

    fn upsert_scoped(
        model: &MaterializedReadModel,
        kind: ObjectKind,
        id: &str,
        revision: u64,
        value: Value,
        scope: QueryScope,
    ) {
        model
            .upsert_indexed(
                snapshot(kind, id, revision, value),
                ProjectionMetadata::new(id, "").in_scope(scope),
            )
            .unwrap();
    }

    fn delta_for(object: &ObjectRef, from: u64, to: u64, body: ObjectDeltaBody) -> ObjectDelta {
        ObjectDelta {
            object: object.clone(),
            from_revision: Revision::new(from),
            to_revision: Revision::new(to),
            revision_source: RevisionSource::Registry,
            freshness: freshness(),
            body,
        }
    }

    /// A subscription page serves only the subscription's kinds; the batch
    /// cursor is the global model revision, not an object revision.
    #[test]
    fn subscribe_objects_filters_kinds_and_carries_the_global_cursor() {
        let model = MaterializedReadModel::new(8, OffsetDateTime::UNIX_EPOCH);
        model
            .upsert(snapshot(
                ObjectKind::Session,
                "s1",
                1,
                json!({"state": "running"}),
            ))
            .unwrap();
        model
            .upsert(snapshot(
                ObjectKind::KubeResource,
                "k1",
                1,
                json!({"cpu": 1}),
            ))
            .unwrap();
        let batch = model
            .object_deltas_page(
                Revision::new(0),
                &[ObjectKind::Session, ObjectKind::Approval],
                &QueryScope::All,
                64,
                1 << 20,
            )
            .unwrap();
        assert_eq!(batch.deltas.len(), 1);
        assert_eq!(batch.deltas[0].object.id, "s1");
        assert_eq!(batch.deltas[0].to_revision, Revision::new(1));
        assert_eq!(batch.to_revision, model.revision().unwrap());
        assert_eq!(batch.next_after, None);
        let caught_up = model
            .object_deltas_page(
                batch.to_revision,
                &[ObjectKind::Session, ObjectKind::Approval],
                &QueryScope::All,
                64,
                1 << 20,
            )
            .unwrap();
        assert!(caught_up.deltas.is_empty());
    }

    /// Precise scope transitions: the subscriber holding the old lane gets
    /// one Remove based at the earliest covered revision; the new lane's
    /// subscriber gets the full post state; a cursor before the object
    /// existed gets nothing (entered and left inside one window); a cursor
    /// past the move gets nothing.
    #[test]
    fn scope_move_removes_from_old_scope_and_replaces_in_new() {
        let model = MaterializedReadModel::new(8, OffsetDateTime::UNIX_EPOCH);
        let old_lane = lane("lane-one");
        let new_lane = lane("lane-two");
        upsert_scoped(
            &model,
            ObjectKind::Session,
            "s1",
            1,
            json!({"state": "running"}),
            old_lane.clone(),
        );
        let held = model.revision().unwrap();
        upsert_scoped(
            &model,
            ObjectKind::Session,
            "s1",
            2,
            json!({"state": "running", "lane": "two"}),
            new_lane.clone(),
        );

        let old_view = model
            .object_deltas_page(held, &[ObjectKind::Session], &old_lane, 64, 1 << 20)
            .unwrap();
        assert_eq!(old_view.deltas.len(), 1);
        assert_eq!(old_view.deltas[0].object.id, "s1");
        assert_eq!(old_view.deltas[0].body, ObjectDeltaBody::Remove);
        assert_eq!(old_view.deltas[0].from_revision, Revision::new(1));
        assert_eq!(old_view.deltas[0].to_revision, Revision::new(2));

        let new_view = model
            .object_deltas_page(held, &[ObjectKind::Session], &new_lane, 64, 1 << 20)
            .unwrap();
        assert_eq!(new_view.deltas.len(), 1);
        assert_eq!(
            new_view.deltas[0].body,
            ObjectDeltaBody::Replace(json!({"state": "running", "lane": "two"}))
        );

        let from_zero = model
            .object_deltas_page(
                Revision::new(0),
                &[ObjectKind::Session],
                &old_lane,
                64,
                1 << 20,
            )
            .unwrap();
        assert!(from_zero.deltas.is_empty());

        let after_head = model
            .object_deltas_page(
                model.revision().unwrap(),
                &[ObjectKind::Session],
                &old_lane,
                64,
                1 << 20,
            )
            .unwrap();
        assert!(after_head.deltas.is_empty());
    }

    /// Deletions deliver Remove; a base record already evicted from the
    /// window still resolves membership from the covered records' own
    /// pre/post scopes; records outside the window never deliver.
    #[test]
    fn deletion_and_evicted_base_still_resolve_scope_transitions() {
        let model = MaterializedReadModel::with_limits(8, 2, OffsetDateTime::UNIX_EPOCH);
        let old_lane = lane("lane-one");
        let new_lane = lane("lane-two");
        upsert_scoped(
            &model,
            ObjectKind::Session,
            "s1",
            1,
            json!({"state": "running"}),
            old_lane.clone(),
        );
        // Churn pushes the creation record out of the two-record window.
        upsert_scoped(
            &model,
            ObjectKind::Session,
            "s2",
            1,
            json!({"state": "running"}),
            new_lane.clone(),
        );
        upsert_scoped(
            &model,
            ObjectKind::Session,
            "s1",
            2,
            json!({"state": "running", "lane": "two"}),
            new_lane.clone(),
        );
        let held = model.revision().unwrap();
        let old_view = model
            .object_deltas_page(held, &[ObjectKind::Session], &old_lane, 64, 1 << 20)
            .unwrap();
        assert!(old_view.deltas.is_empty(), "move is outside the window");

        // The move (r3) is past a cursor taken after r2: the new lane's
        // subscriber sees the arrival with r3's object revision.
        let before_move = Revision::new(2);
        let new_view = model
            .object_deltas_page(before_move, &[ObjectKind::Session], &new_lane, 64, 1 << 20)
            .unwrap();
        assert_eq!(new_view.deltas.len(), 1);
        assert_eq!(new_view.deltas[0].to_revision, Revision::new(2));

        model
            .remove(
                ObjectRef {
                    kind: ObjectKind::Session,
                    id: "s1".to_owned(),
                },
                Revision::new(3),
                RevisionSource::Registry,
                freshness(),
            )
            .unwrap();
        let before_removal = Revision::new(3);
        let removal = model
            .object_deltas_page(
                before_removal,
                &[ObjectKind::Session],
                &new_lane,
                64,
                1 << 20,
            )
            .unwrap();
        assert_eq!(removal.deltas.len(), 1);
        assert_eq!(removal.deltas[0].body, ObjectDeltaBody::Remove);
        assert_eq!(removal.deltas[0].to_revision, Revision::new(3));
        let after_removal = model
            .object_deltas_page(
                model.revision().unwrap(),
                &[ObjectKind::Session],
                &new_lane,
                64,
                1 << 20,
            )
            .unwrap();
        assert!(after_removal.deltas.is_empty());
    }

    /// Merge-patch chains coalesce to one delta carrying the resolved
    /// post state; a single patch over a held base stays verbatim.
    #[test]
    fn merge_patch_records_coalesce_to_the_resolved_state() {
        let model = MaterializedReadModel::new(8, OffsetDateTime::UNIX_EPOCH);
        model
            .upsert(snapshot(
                ObjectKind::KubeResource,
                "k1",
                1,
                json!({"cpu": 1, "mem": 2}),
            ))
            .unwrap();
        let held = model.revision().unwrap();
        let object = ObjectRef {
            kind: ObjectKind::KubeResource,
            id: "k1".to_owned(),
        };
        model
            .apply(delta_for(
                &object,
                1,
                2,
                ObjectDeltaBody::MergePatch(json!({"cpu": 5})),
            ))
            .unwrap();
        model
            .apply(delta_for(
                &object,
                2,
                3,
                ObjectDeltaBody::MergePatch(json!({"mem": null, "gpu": 1})),
            ))
            .unwrap();
        let batch = model
            .object_deltas_page(
                held,
                &[ObjectKind::KubeResource],
                &QueryScope::All,
                64,
                1 << 20,
            )
            .unwrap();
        assert_eq!(batch.deltas.len(), 1);
        assert_eq!(batch.deltas[0].from_revision, Revision::new(1));
        assert_eq!(batch.deltas[0].to_revision, Revision::new(3));
        assert_eq!(
            batch.deltas[0].body,
            ObjectDeltaBody::Replace(json!({"cpu": 5, "gpu": 1}))
        );

        model
            .apply(delta_for(
                &object,
                3,
                4,
                ObjectDeltaBody::MergePatch(json!({"cpu": 7})),
            ))
            .unwrap();
        let verbatim = model
            .object_deltas_page(
                Revision::new(3),
                &[ObjectKind::KubeResource],
                &QueryScope::All,
                64,
                1 << 20,
            )
            .unwrap();
        assert_eq!(verbatim.deltas.len(), 1);
        assert_eq!(
            verbatim.deltas[0].body,
            ObjectDeltaBody::MergePatch(json!({"cpu": 7}))
        );
        assert_eq!(verbatim.deltas[0].from_revision, Revision::new(3));
        assert_eq!(verbatim.deltas[0].to_revision, Revision::new(4));
    }

    /// The batch cursor advances over object revisions without confusing
    /// the two: a resume from the delivered checkpoint carries exactly the
    /// records past it, and the item cap cuts on the same boundary.
    #[test]
    fn resume_from_the_global_checkpoint_carries_only_the_remainder() {
        let model = MaterializedReadModel::new(8, OffsetDateTime::UNIX_EPOCH);
        for index in 0..3 {
            model
                .upsert(snapshot(
                    ObjectKind::Device,
                    &format!("d{index}"),
                    1,
                    json!({"n": index}),
                ))
                .unwrap();
        }
        let kinds: &[ObjectKind] = &[ObjectKind::Device];
        let batch = model
            .object_deltas_page(Revision::new(0), kinds, &QueryScope::All, 64, 1 << 20)
            .unwrap();
        assert_eq!(batch.deltas.len(), 3);
        assert_eq!(batch.to_revision, Revision::new(3));
        assert!(batch
            .deltas
            .iter()
            .all(|delta| delta.to_revision.get() < batch.to_revision.get()));

        model
            .upsert(snapshot(ObjectKind::Device, "d1", 2, json!({"n": 10})))
            .unwrap();
        let resumed = model
            .object_deltas_page(batch.to_revision, kinds, &QueryScope::All, 64, 1 << 20)
            .unwrap();
        assert_eq!(resumed.deltas.len(), 1);
        assert_eq!(resumed.deltas[0].object.id, "d1");
        assert_eq!(resumed.to_revision, Revision::new(4));
        assert_eq!(resumed.next_after, None);

        let item_capped = model
            .object_deltas_page(Revision::new(0), kinds, &QueryScope::All, 2, 1 << 20)
            .unwrap();
        assert_eq!(item_capped.deltas.len(), 2);
        assert_eq!(item_capped.next_after, Some(item_capped.to_revision));
        assert_eq!(item_capped.to_revision, Revision::new(2));
    }

    /// The byte budget cuts on a global-revision boundary and a resume
    /// completes the window; one object alone over the budget is refused
    /// typed instead of sending oversized.
    #[test]
    fn byte_budget_cuts_at_a_revision_boundary_or_refuses_typed() {
        let model = MaterializedReadModel::new(8, OffsetDateTime::UNIX_EPOCH);
        let bulk = "x".repeat(4_000);
        for index in 0..3 {
            model
                .upsert(snapshot(
                    ObjectKind::Device,
                    &format!("d{index}"),
                    1,
                    json!({"n": index, "bulk": bulk}),
                ))
                .unwrap();
        }
        let kinds: &[ObjectKind] = &[ObjectKind::Device];
        let cut = model
            .object_deltas_page(Revision::new(0), kinds, &QueryScope::All, 64, 9_000)
            .unwrap();
        assert_eq!(cut.deltas.len(), 2);
        assert_eq!(cut.next_after, Some(Revision::new(2)));
        assert_eq!(cut.to_revision, Revision::new(2));
        let rest = model
            .object_deltas_page(cut.to_revision, kinds, &QueryScope::All, 64, 9_000)
            .unwrap();
        assert_eq!(rest.deltas.len(), 1);
        assert_eq!(rest.deltas[0].object.id, "d2");
        assert_eq!(rest.next_after, None);

        let refused = model
            .object_deltas_page(Revision::new(0), kinds, &QueryScope::All, 64, 1_000)
            .unwrap_err();
        assert!(
            matches!(refused, ReadModelError::DeltaTooLarge { .. }),
            "{refused:?}"
        );
    }

    /// Cursors below the retained window fail `CursorExpired` (snapshot
    /// and resubscribe), cursors ahead of the head fail the existing
    /// cursor mapping.
    #[test]
    fn stale_and_ahead_subscription_cursors_fail_typed() {
        let model = MaterializedReadModel::with_limits(8, 2, OffsetDateTime::UNIX_EPOCH);
        for index in 0..3 {
            model
                .upsert(snapshot(
                    ObjectKind::Device,
                    &format!("d{index}"),
                    1,
                    json!({"n": index}),
                ))
                .unwrap();
        }
        let kinds: &[ObjectKind] = &[ObjectKind::Device];
        let expired = model
            .object_deltas_page(Revision::new(0), kinds, &QueryScope::All, 64, 1 << 20)
            .unwrap_err();
        assert!(
            matches!(expired, ReadModelError::CursorExpired),
            "{expired:?}"
        );
        let ahead = model
            .object_deltas_page(Revision::new(9), kinds, &QueryScope::All, 64, 1 << 20)
            .unwrap_err();
        assert!(
            matches!(ahead, ReadModelError::CursorRevision { .. }),
            "{ahead:?}"
        );
    }

    /// Urgency is exact: kind, scope and the `incident` id prefix all gate
    /// it, and only records past the cursor are consulted.
    #[test]
    fn urgent_scan_filters_kind_scope_and_incident_prefix() {
        let model = MaterializedReadModel::new(8, OffsetDateTime::UNIX_EPOCH);
        let old_lane = lane("lane-one");
        model
            .upsert(snapshot(
                ObjectKind::Session,
                "s1",
                1,
                json!({"state": "running"}),
            ))
            .unwrap();
        model
            .upsert(snapshot(
                ObjectKind::KubeResource,
                "k1",
                1,
                json!({"cpu": 1}),
            ))
            .unwrap();
        upsert_scoped(
            &model,
            ObjectKind::Status,
            "incident:1725000000000:a1b2",
            1,
            json!({"severity": "error"}),
            old_lane.clone(),
        );
        upsert_scoped(
            &model,
            ObjectKind::Status,
            "roster",
            1,
            json!({"seats": []}),
            old_lane.clone(),
        );
        let after_kube = Revision::new(2);

        assert!(model
            .has_urgent_objects_since(Revision::new(0), &[ObjectKind::Session], &QueryScope::All)
            .unwrap());
        assert!(!model
            .has_urgent_objects_since(
                Revision::new(0),
                &[ObjectKind::KubeResource],
                &QueryScope::All
            )
            .unwrap());
        assert!(!model
            .has_urgent_objects_since(after_kube, &[ObjectKind::Session], &QueryScope::All)
            .unwrap());
        assert!(model
            .has_urgent_objects_since(after_kube, &[ObjectKind::Status], &QueryScope::All)
            .unwrap());
        assert!(model
            .has_urgent_objects_since(after_kube, &[ObjectKind::Status], &old_lane)
            .unwrap());
        assert!(!model
            .has_urgent_objects_since(after_kube, &[ObjectKind::Status], &lane("lane-two"))
            .unwrap());
        // The cursor is exclusive: roster alone, a full revision past the
        // incident record, is not urgent.
        assert!(!model
            .has_urgent_objects_since(Revision::new(3), &[ObjectKind::Status], &QueryScope::All)
            .unwrap());
        assert!(!model
            .has_urgent_objects_since(Revision::new(4), &[ObjectKind::Status], &QueryScope::All)
            .unwrap());
        // A record whose post-scope leaves the subscription is urgent for
        // the scope losing it, on the pre-scope alone; so is a deletion.
        upsert_scoped(
            &model,
            ObjectKind::Session,
            "s2",
            1,
            json!({"state": "running"}),
            old_lane.clone(),
        );
        let held = model.revision().unwrap();
        upsert_scoped(
            &model,
            ObjectKind::Session,
            "s2",
            2,
            json!({"state": "running", "lane": "two"}),
            lane("lane-two"),
        );
        assert!(model
            .has_urgent_objects_since(held, &[ObjectKind::Session], &old_lane)
            .unwrap());
        model
            .remove(
                ObjectRef {
                    kind: ObjectKind::Session,
                    id: "s2".to_owned(),
                },
                Revision::new(model.revision().unwrap().get() + 1),
                RevisionSource::Registry,
                freshness(),
            )
            .unwrap();
        assert!(model
            .has_urgent_objects_since(held, &[ObjectKind::Session], &old_lane)
            .unwrap());
    }
}
