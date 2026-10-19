use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use odin_domain::{ArtifactId, Digest, RunId};
use odin_ledger::kube::{
    Identity, Journal as StoredJournal, Operation as Entry, Scope, Settlement,
};
use odin_ledger::{Ledger, LedgerError};
use odin_types::{OperationId, WorkerId};
#[cfg(test)]
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::client::KubeError;
use crate::job::{JobAction, JobLaunch, JobObservation, KubeOperationKind};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Progress {
    pub prior: Option<JobObservation>,
    pub stop_worker: Option<WorkerId>,
    pub next_launch: Option<JobLaunch>,
    /// Rehome checkpoint persisted before deleting the old volume.
    pub carried: Option<ArtifactId>,
}

#[derive(Debug)]
pub(crate) struct Started {
    pub operation_id: String,
    pub request: Value,
    pub progress: Progress,
    pub replay: Option<Result<JobObservation, KubeError>>,
}

pub(crate) struct Journal {
    pub ledger: Arc<Mutex<Ledger>>,
    cluster: String,
    namespace: String,
}

impl Journal {
    pub(crate) fn new(ledger: Arc<Mutex<Ledger>>, cluster: String, namespace: String) -> Self {
        Self {
            ledger,
            cluster,
            namespace,
        }
    }

    fn scope(&self) -> Scope<'_> {
        Scope {
            cluster: &self.cluster,
            namespace: &self.namespace,
        }
    }

    pub(crate) fn begin(
        &self,
        operation: &OperationId,
        run: &RunId,
        kind: KubeOperationKind,
        digest: &Digest,
        request: &impl Serialize,
    ) -> Result<Started, KubeError> {
        let value = serde_json::to_value(request).map_err(storage)?;
        let request = serde_json::to_string(&value).map_err(storage)?;
        let fingerprint = fingerprint(value, kind)?;
        let now = odin_ledger::encode_utc(time::OffsetDateTime::now_utc()).map_err(storage)?;
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| storage("operation ledger lock poisoned"))?;
        enum Admission {
            Resolved(Entry, bool),
            Refused(&'static str),
        }
        let resolution = ledger.with_tx(|tx| {
            let stored = StoredJournal(tx);
            let identity = Identity { run, kind: kind_name(kind), digest };
            let existing = stored.operation(operation.as_str())?;
            let existing = if let Some(record) = existing {
                Some(record)
            } else {
                // An admitted alias keeps its original canonical operation, including rejections.
                let bound = stored.bindings(operation.as_str())?;
                match bound.as_slice() {
                    [canonical] => {
                        let record = stored.operation(canonical)?;
                        if record.is_none() {
                            return Ok(Admission::Refused(
                                "bound canonical operation record is missing for an admitted identity",
                            ));
                        }
                        record
                    }
                    [] => {
                        // The unique index selects the pending or applied row; rejections allow fresh attempts.
                        stored.current(&identity)?
                    }
                    [..] => {
                        return Ok(Admission::Refused(
                            "operation identity was already admitted under conflicting canonical operations",
                        ))
                    }
                }
            };
            let record = match existing {
                Some(mut record) => {
                    // Matching retries may refresh only a pending row's resource-version precondition.
                    if record.fingerprint == fingerprint {
                        if let Some(refreshed) = refresh_pending_precondition(&record, &request) {
                            stored.refresh_request(&record.id, &refreshed, &now)?;
                            record.request = refreshed;
                        }
                    }
                    record
                }
                None => {
                    let record = Entry { id: operation.to_string(), fingerprint: fingerprint.clone(), request: request.clone(), progress: "{}".to_owned(), state: "pending".to_owned(), result: None, failure_kind: None, failure_reason: None };
                    stored.insert(&record, &identity, &self.scope(), &now)?;
                    record
                }
            };
            let conflict = record.fingerprint != fingerprint;
            stored.attempt(operation.as_str(), &record, &fingerprint, conflict, &now)?;
            Ok(Admission::Resolved(record, conflict))
        }).map_err(storage)?;
        let (record, conflict) = match resolution {
            Admission::Refused(reason) => {
                return Err(KubeError::Conflict {
                    reason: reason.to_owned(),
                })
            }
            Admission::Resolved(record, conflict) => (record, conflict),
        };
        if conflict {
            return Err(KubeError::Conflict {
                reason:
                    "operation identity or idempotency digest was reused with different arguments"
                        .to_owned(),
            });
        }
        let replay = decode_outcome(&record)?;
        Ok(Started {
            operation_id: record.id,
            request: serde_json::from_str(&record.request).map_err(storage)?,
            progress: serde_json::from_str(&record.progress).map_err(storage)?,
            replay,
        })
    }

    pub(crate) fn progress(&self, operation: &str, progress: &Progress) -> Result<(), KubeError> {
        let text = serde_json::to_string(progress).map_err(storage)?;
        let ledger = self
            .ledger
            .lock()
            .map_err(|_| storage("operation ledger lock poisoned"))?;
        let changed = StoredJournal(ledger.connection())
            .progress(
                operation,
                &text,
                &odin_ledger::encode_utc(time::OffsetDateTime::now_utc()).map_err(storage)?,
            )
            .map_err(storage)?;
        if !changed {
            return Err(KubeError::Conflict {
                reason: "operation already settled".to_owned(),
            });
        }
        Ok(())
    }

    /// Transient failures stay pending for recovery; other outcomes are persisted and replayed.
    pub(crate) fn finish(
        &self,
        operation: &str,
        outcome: Result<JobObservation, KubeError>,
    ) -> Result<JobObservation, KubeError> {
        let outcome = match outcome {
            Err(error) if unproved(&error) => return Err(error),
            other => other,
        };
        let (state, result, failure_kind, failure_reason) = match &outcome {
            Ok(value) => (
                "applied",
                Some(serde_json::to_string(value).map_err(storage)?),
                None,
                None,
            ),
            Err(error) => (
                "rejected",
                None,
                Some(error_kind(error)),
                Some(error.to_string()),
            ),
        };
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| storage("operation ledger lock poisoned"))?;
        let record = ledger
            .with_tx(|tx| {
                StoredJournal(tx).finish(
                    operation,
                    &Settlement {
                        state,
                        result: result.as_deref(),
                        failure_kind,
                        failure_reason: failure_reason.as_deref(),
                    },
                    &odin_ledger::encode_utc(time::OffsetDateTime::now_utc())?,
                )
            })
            .map_err(storage)?;
        decode_outcome(&record)?.ok_or_else(|| storage("operation did not settle"))?
    }

    pub(crate) fn pending_claim(&self, operation: &str) -> Result<bool, KubeError> {
        let ledger = self
            .ledger
            .lock()
            .map_err(|_| storage("operation ledger lock poisoned"))?;
        StoredJournal(ledger.connection())
            .pending_claim(operation)
            .map_err(storage)
    }

    /// Reads persisted outcomes without a cache; missing or pending operations return `None`.
    pub(crate) fn operation_outcome(
        &self,
        operation: &str,
    ) -> Result<Option<Result<JobObservation, KubeError>>, KubeError> {
        let ledger = self
            .ledger
            .lock()
            .map_err(|_| storage("operation ledger lock poisoned"))?;
        let record = StoredJournal(ledger.connection())
            .operation(operation)
            .map_err(storage)?;
        match record {
            Some(record) => decode_outcome(&record),
            None => Ok(None),
        }
    }

    /// Recovers only accepted attempts for this id; matching another command's digest is insufficient.
    /// A mismatched scope conflicts rather than permitting a new admission.
    pub(crate) fn admitted_action(
        &self,
        operation: &OperationId,
        run: &RunId,
        kind: KubeOperationKind,
        digest: &Digest,
    ) -> Result<Option<JobAction>, KubeError> {
        let ledger = self
            .ledger
            .lock()
            .map_err(|_| storage("operation ledger lock poisoned"))?;
        let stored = StoredJournal(ledger.connection());
        let admitted = stored
            .admitted(
                operation.as_str(),
                &Identity {
                    run,
                    kind: kind_name(kind),
                    digest,
                },
                &self.scope(),
            )
            .map_err(storage)?;
        let Some((canonical, request)) = admitted else {
            // An accepted attempt in another scope must not be treated as a fresh request.
            if stored.has_admission(operation.as_str()).map_err(storage)? {
                return Err(KubeError::Conflict { reason: "admitted operation belongs to another cluster, namespace, run, kind, or digest".to_owned() });
            }
            return Ok(None);
        };
        let action: JobAction = serde_json::from_str(&request).map_err(storage)?;
        if action.run_id != *run
            || action.kind != kind
            || action.idempotency_digest != *digest
            || action.operation_id.as_str() != canonical
        {
            return Err(storage(
                "stored operation request disagrees with its admission record",
            ));
        }
        Ok(Some(action))
    }

    /// Uses the stored operation, excluding conflicting attempts and other scopes.
    pub(crate) fn operation_run(&self, operation: &str) -> Result<Option<RunId>, KubeError> {
        let ledger = self
            .ledger
            .lock()
            .map_err(|_| storage("operation ledger lock poisoned"))?;
        let value = StoredJournal(ledger.connection())
            .operation_run(operation)
            .map_err(storage)?;
        match value {
            Some(run) => RunId::new(run).map(Some).map_err(storage),
            None => Ok(None),
        }
    }

    /// Filters the inventory to this journal's cluster and namespace.
    pub(crate) fn operation_runs(&self) -> Result<Vec<(String, RunId)>, KubeError> {
        let ledger = self
            .ledger
            .lock()
            .map_err(|_| storage("operation ledger lock poisoned"))?;
        let mut statement = ledger
            .connection()
            .prepare(
                "SELECT operation_id, run_id FROM kube_job_operations \
                 WHERE cluster=?1 AND namespace=?2",
            )
            .map_err(storage)?;
        let rows = statement
            .query_map([&self.cluster, &self.namespace], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(storage)?;
        let mut mapped = Vec::new();
        for row in rows {
            let (operation, run) = row.map_err(storage)?;
            mapped.push((operation, RunId::new(run).map_err(storage)?));
        }
        Ok(mapped)
    }

    pub(crate) fn load_launch(&self, run: &RunId) -> Result<Option<JobLaunch>, KubeError> {
        let ledger = self
            .ledger
            .lock()
            .map_err(|_| storage("operation ledger lock poisoned"))?;
        StoredJournal(ledger.connection())
            .launch(run)
            .map_err(storage)?
            .map(|record| {
                if record.cluster != self.cluster || record.namespace != self.namespace {
                    return Err(KubeError::Conflict {
                        reason: "run belongs to another cluster or namespace".to_owned(),
                    });
                }
                serde_json::from_str(&record.json).map_err(storage)
            })
            .transpose()
    }

    /// The first valid definition persists; identical retries ignore per-attempt ids.
    /// A different definition conflicts without replacing the stored launch.
    pub(crate) fn save_launch(&self, launch: &JobLaunch) -> Result<(), KubeError> {
        launch
            .validate()
            .map_err(|reason| KubeError::Rejected { reason })?;
        let definition = run_definition(serde_json::to_value(launch).map_err(storage)?);
        let text = serde_json::to_string(launch).map_err(storage)?;
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| storage("operation ledger lock poisoned"))?;
        ledger
            .with_tx(|tx| {
                let stored = StoredJournal(tx);
                let existing = stored.launch(&launch.labels.run_id)?;
                match existing {
                    Some(record) => {
                        if record.cluster != self.cluster || record.namespace != self.namespace {
                            return Err(LedgerError::Conflict(
                                "run binding belongs to another cluster".to_owned(),
                            ));
                        }
                        if run_definition(serde_json::from_str(&record.json)?) != definition {
                            return Err(LedgerError::Conflict(
                                "run is already admitted with a different launch definition"
                                    .to_owned(),
                            ));
                        }
                    }
                    None => {
                        stored.insert_launch(
                            &launch.labels.run_id,
                            &self.scope(),
                            &text,
                            &odin_ledger::encode_utc(time::OffsetDateTime::now_utc())?,
                        )?;
                    }
                }
                Ok(())
            })
            .map_err(|error| match error {
                // Preserve conflicts as terminal outcomes rather than storage failures.
                LedgerError::Conflict(reason) => KubeError::Conflict { reason },
                error => storage(error),
            })
    }

    /// A registered run still needs teardown checks after its Job disappears.
    /// Registration in another cluster or namespace conflicts rather than returning false.
    pub(crate) fn has_registered_launch(&self, run: &RunId) -> Result<bool, KubeError> {
        let ledger = self
            .ledger
            .lock()
            .map_err(|_| storage("operation ledger lock poisoned"))?;
        let scope = StoredJournal(ledger.connection())
            .launch_scope(run)
            .map_err(storage)?;
        match scope {
            None => Ok(false),
            Some((cluster, namespace))
                if cluster == self.cluster && namespace == self.namespace =>
            {
                Ok(true)
            }
            Some(_) => Err(KubeError::Conflict {
                reason: "run belongs to another cluster or namespace".to_owned(),
            }),
        }
    }

    /// Paths must remain unchanged because each run's staging definition is immutable.
    pub(crate) fn save_staged_paths(
        &self,
        run: &RunId,
        paths: &BTreeMap<ArtifactId, String>,
    ) -> Result<(), KubeError> {
        if paths.is_empty() {
            return Ok(());
        }
        let now = odin_ledger::encode_utc(time::OffsetDateTime::now_utc())
            .map_err(|error| storage(format!("staged-path timestamp encoding failed: {error}")))?;
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| storage("staged-path ledger lock poisoned"))?;
        ledger
            .with_tx(|tx| {
                for (artifact_id, staged_path) in paths {
                    let stored = StoredJournal(tx);
                    let existing = stored.staged_path(run, artifact_id)?;
                    match existing {
                        Some(prior) if prior == *staged_path => {}
                        Some(prior) => {
                            return Err(LedgerError::Conflict(format!(
                                "run {run} artifact {artifact_id} is already staged at {prior:?}"
                            )));
                        }
                        None => {
                            stored.insert_staged_path(
                                run,
                                artifact_id,
                                &self.scope(),
                                staged_path,
                                &now,
                            )?;
                        }
                    }
                }
                Ok(())
            })
            .map_err(|error| match error {
                LedgerError::Conflict(reason) => KubeError::Conflict { reason },
                error => storage(error),
            })
    }

    /// A run registered in another cluster or namespace conflicts rather than returning no paths.
    pub(crate) fn staged_paths(
        &self,
        run: &RunId,
    ) -> Result<BTreeMap<ArtifactId, String>, KubeError> {
        let ledger = self
            .ledger
            .lock()
            .map_err(|_| storage("staged-path ledger lock poisoned"))?;
        StoredJournal(ledger.connection())
            .staged_paths(run, &self.scope())
            .map_err(storage)
    }

    pub(crate) fn revision(&self, key: &str, value: &impl Serialize) -> Result<u64, KubeError> {
        let mut value = serde_json::to_value(value).map_err(storage)?;
        if let Some(workload) = value.get_mut("workload") {
            if let Some(object) = workload.as_object_mut() {
                object.remove("revision");
                object.remove("observedAt");
                object.remove("stale");
            }
        } else if let Some(object) = value.as_object_mut() {
            object.remove("revision");
            object.remove("observedAt");
            object.remove("stale");
        }
        let digest = Digest::hash(&serde_json::to_vec(&value).map_err(storage)?).to_string();
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| storage("projection ledger lock poisoned"))?;
        ledger
            .with_tx(|tx| StoredJournal(tx).revision(key, &digest))
            .map_err(storage)
    }

    pub(crate) fn pending(&self) -> Result<Vec<(String, Value)>, KubeError> {
        let ledger = self
            .ledger
            .lock()
            .map_err(|_| storage("operation ledger lock poisoned"))?;
        StoredJournal(ledger.connection())
            .pending(&self.scope())
            .map_err(storage)
    }

    pub(crate) fn registered_runs(&self) -> Result<Vec<RunId>, KubeError> {
        let ledger = self
            .ledger
            .lock()
            .map_err(|_| storage("operation ledger lock poisoned"))?;
        let mut statement = ledger
            .connection()
            .prepare("SELECT run_id FROM kube_job_runs WHERE cluster=?1 AND namespace=?2")
            .map_err(storage)?;
        let rows = statement
            .query_map([&self.cluster, &self.namespace], |row| {
                row.get::<_, String>(0)
            })
            .map_err(storage)?;
        let mut runs = Vec::new();
        for row in rows {
            runs.push(RunId::new(row.map_err(storage)?).map_err(storage)?);
        }
        Ok(runs)
    }
}

fn decode_outcome(record: &Entry) -> Result<Option<Result<JobObservation, KubeError>>, KubeError> {
    match record.state.as_str() {
        "pending" => Ok(None),
        "applied" => Ok(Some(Ok(serde_json::from_str(
            record
                .result
                .as_deref()
                .ok_or_else(|| storage("applied operation has no result"))?,
        )
        .map_err(storage)?))),
        "rejected" => {
            let reason = record
                .failure_reason
                .clone()
                .ok_or_else(|| storage("rejected operation has no reason"))?;
            let error = match record.failure_kind.as_deref() {
                Some("unavailable") => KubeError::Unavailable { reason },
                Some("conflict") => KubeError::Conflict { reason },
                Some("rejected") => KubeError::Rejected { reason },
                _ => KubeError::Storage { reason },
            };
            Ok(Some(Err(error)))
        }
        _ => Err(storage("unknown operation journal state")),
    }
}

/// Per-attempt ids must not make a resumed or restarted launch a different run definition.
fn run_definition(mut launch: Value) -> Value {
    if let Some(object) = launch.as_object_mut() {
        object.remove("worker_id");
        object.remove("operation_id");
        object.remove("idempotency_digest");
    }
    launch
}

/// Refreshes only a pending request's resource version, preserving its original operation id.
fn refresh_pending_precondition(record: &Entry, request: &str) -> Option<String> {
    if record.state != "pending" {
        return None;
    }
    let fresh: serde_json::Value = serde_json::from_str(request).ok()?;
    let fresh_version = fresh.get("expected_resource_version")?;
    let mut stored: serde_json::Value = serde_json::from_str(&record.request).ok()?;
    let slot = stored.get_mut("expected_resource_version")?;
    if *slot == *fresh_version {
        return None;
    }
    *slot = fresh_version.clone();
    serde_json::to_string(&stored).ok()
}

/// Reads the registered launch before worker creation, without requiring a Kubernetes client.
pub fn stored_launch(
    ledger: &Arc<Mutex<Ledger>>,
    cluster: &str,
    namespace: &str,
    run: &RunId,
) -> Result<Option<JobLaunch>, KubeError> {
    Journal::new(Arc::clone(ledger), cluster.to_owned(), namespace.to_owned()).load_launch(run)
}

fn fingerprint(mut request: Value, kind: KubeOperationKind) -> Result<String, KubeError> {
    if let Some(object) = request.as_object_mut() {
        object.remove("operation_id");
        object.remove("idempotency_digest");
        // A new resource-version precondition does not change the requested operation.
        object.remove("expected_resource_version");
        if kind == KubeOperationKind::Create {
            object.remove("worker_id");
        }
    }
    Ok(Digest::hash(&serde_json::to_vec(&request).map_err(storage)?).to_string())
}

fn error_kind(error: &KubeError) -> &'static str {
    match error {
        KubeError::Unavailable { .. } => "unavailable",
        KubeError::Conflict { .. } => "conflict",
        KubeError::Rejected { .. } => "rejected",
        KubeError::Storage { .. } => "storage",
        KubeError::Api(inner) if api_is_transient(inner) => "unavailable",
        KubeError::Api(_) => "rejected",
    }
}

fn unproved(error: &KubeError) -> bool {
    match error {
        KubeError::Unavailable { .. } => true,
        KubeError::Api(inner) => api_is_transient(inner),
        _ => false,
    }
}

fn api_is_transient(error: &kube::Error) -> bool {
    match error {
        kube::Error::HyperError(_) | kube::Error::Service(_) | kube::Error::ReadEvents(_) => true,
        kube::Error::Api(status) => matches!(status.code, 408 | 429 | 500 | 502 | 503 | 504),
        _ => false,
    }
}

pub(crate) fn kind_name(kind: KubeOperationKind) -> &'static str {
    match kind {
        KubeOperationKind::Create => "create",
        KubeOperationKind::Pause => "pause",
        KubeOperationKind::Resume => "resume",
        KubeOperationKind::Restart => "restart",
        KubeOperationKind::Cancel => "cancel",
        KubeOperationKind::Summarize => "summarize",
    }
}

pub(crate) fn storage(error: impl std::fmt::Display) -> KubeError {
    KubeError::Storage {
        reason: error.to_string(),
    }
}

#[cfg(test)]
mod tests;
