//! Kubernetes operation persistence; callers handle admission, serialization, and transactions.

use odin_domain::{ArtifactId, Digest, RunId};
use rusqlite::{params, Connection, OptionalExtension};

use crate::{LedgerError, LedgerResult};

pub struct Operation {
    pub id: String,
    pub fingerprint: String,
    pub request: String,
    pub progress: String,
    pub state: String,
    pub result: Option<String>,
    pub failure_kind: Option<String>,
    pub failure_reason: Option<String>,
}

fn operation(row: &rusqlite::Row<'_>) -> rusqlite::Result<Operation> {
    Ok(Operation {
        id: row.get(0)?,
        fingerprint: row.get(1)?,
        request: row.get(2)?,
        progress: row.get(3)?,
        state: row.get(4)?,
        result: row.get(5)?,
        failure_kind: row.get(6)?,
        failure_reason: row.get(7)?,
    })
}

pub struct Scope<'a> {
    pub cluster: &'a str,
    pub namespace: &'a str,
}

pub struct Identity<'a> {
    pub run: &'a RunId,
    pub kind: &'a str,
    pub digest: &'a Digest,
}

pub struct Launch {
    pub cluster: String,
    pub namespace: String,
    pub json: String,
}

pub struct Settlement<'a> {
    pub state: &'a str,
    pub result: Option<&'a str>,
    pub failure_kind: Option<&'a str>,
    pub failure_reason: Option<&'a str>,
}

/// Uses the supplied connection without starting or committing transactions.
pub struct Journal<'a>(pub &'a Connection);

impl Journal<'_> {
    pub fn operation(&self, id: &str) -> LedgerResult<Option<Operation>> {
        Ok(self.0.query_row(
            "SELECT operation_id,fingerprint,request_json,progress_json,state,result_json,failure_kind,failure_reason FROM kube_job_operations WHERE operation_id=?1",
            [id], operation,
        ).optional()?)
    }

    pub fn bindings(&self, id: &str) -> LedgerResult<Vec<String>> {
        Ok(self.0.prepare(
            "SELECT DISTINCT canonical_operation_id FROM kube_job_attempts WHERE operation_id=?1 AND verdict!='conflict' AND canonical_operation_id IS NOT NULL LIMIT 2",
        )?.query_map([id], |row| row.get(0))?.collect::<Result<_, _>>()?)
    }

    pub fn current(&self, identity: &Identity<'_>) -> LedgerResult<Option<Operation>> {
        Ok(self.0.query_row(
            "SELECT operation_id,fingerprint,request_json,progress_json,state,result_json,failure_kind,failure_reason FROM kube_job_operations WHERE run_id=?1 AND kind=?2 AND idempotency_digest=?3 AND state IN ('pending','applied')",
            params![identity.run.as_str(), identity.kind, identity.digest.to_string()], operation,
        ).optional()?)
    }

    pub fn refresh_request(&self, id: &str, request: &str, now: &str) -> LedgerResult<()> {
        self.0.execute("UPDATE kube_job_operations SET request_json=?1,updated_at=?2 WHERE operation_id=?3 AND state='pending'", params![request,now,id])?;
        Ok(())
    }

    pub fn insert(
        &self,
        record: &Operation,
        identity: &Identity<'_>,
        scope: &Scope<'_>,
        now: &str,
    ) -> LedgerResult<()> {
        self.0.execute(
            "INSERT INTO kube_job_operations(operation_id,run_id,cluster,namespace,kind,idempotency_digest,fingerprint,request_json,state,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'pending',?9,?9)",
            params![record.id,identity.run.as_str(),scope.cluster,scope.namespace,identity.kind,identity.digest.to_string(),record.fingerprint,record.request,now],
        )?;
        Ok(())
    }

    pub fn attempt(
        &self,
        requested: &str,
        record: &Operation,
        fingerprint: &str,
        conflict: bool,
        now: &str,
    ) -> LedgerResult<()> {
        let verdict = if conflict {
            "conflict"
        } else if record.state == "pending" {
            "requested"
        } else {
            "replayed"
        };
        self.0.execute(
            "INSERT INTO kube_job_attempts(operation_id,canonical_operation_id,request_fingerprint,verdict,reason,created_at) VALUES(?1,?2,?3,?4,?5,?6)",
            params![requested,record.id,fingerprint,verdict,conflict.then_some("operation identity reused with different arguments"),now],
        )?;
        Ok(())
    }

    pub fn progress(&self, id: &str, progress: &str, now: &str) -> LedgerResult<bool> {
        Ok(self.0.execute("UPDATE kube_job_operations SET progress_json=?1,updated_at=?2 WHERE operation_id=?3 AND state='pending'", params![progress,now,id])? == 1)
    }

    pub fn finish(&self, id: &str, verdict: &Settlement<'_>, now: &str) -> LedgerResult<Operation> {
        self.0.execute("UPDATE kube_job_operations SET state=?1,result_json=?2,failure_kind=?3,failure_reason=?4,updated_at=?5 WHERE operation_id=?6 AND state='pending'", params![verdict.state,verdict.result,verdict.failure_kind,verdict.failure_reason,now,id])?;
        let record = self.operation(id)?.ok_or_else(|| LedgerError::NotFound {
            kind: "kube operation",
            id: id.to_owned(),
        })?;
        self.0.execute("UPDATE kube_job_attempts SET verdict=?1,reason=?2 WHERE canonical_operation_id=?3 AND verdict='requested'", params![record.state,record.failure_reason,record.id])?;
        Ok(record)
    }

    pub fn pending_claim(&self, id: &str) -> LedgerResult<bool> {
        let state: Option<String> = self
            .0
            .query_row(
                "SELECT state FROM kube_job_operations WHERE operation_id=?1",
                [id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(state.as_deref() == Some("pending"))
    }

    pub fn admitted(
        &self,
        id: &str,
        identity: &Identity<'_>,
        scope: &Scope<'_>,
    ) -> LedgerResult<Option<(String, String)>> {
        Ok(self.0.query_row(
            "SELECT o.operation_id,o.request_json FROM kube_job_attempts a JOIN kube_job_operations o ON o.operation_id=a.canonical_operation_id WHERE a.operation_id=?1 AND a.request_fingerprint=o.fingerprint AND a.verdict!='conflict' AND o.cluster=?2 AND o.namespace=?3 AND o.run_id=?4 AND o.kind=?5 AND o.idempotency_digest=?6",
            params![id,scope.cluster,scope.namespace,identity.run.as_str(),identity.kind,identity.digest.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional()?)
    }

    pub fn has_admission(&self, id: &str) -> LedgerResult<bool> {
        Ok(self.0.query_row(
            "SELECT 1 FROM kube_job_attempts a JOIN kube_job_operations o ON o.operation_id=a.canonical_operation_id WHERE a.operation_id=?1 AND a.request_fingerprint=o.fingerprint AND a.verdict!='conflict' LIMIT 1",
            [id], |_| Ok(()),
        ).optional()?.is_some())
    }

    pub fn operation_run(&self, id: &str) -> LedgerResult<Option<String>> {
        Ok(self
            .0
            .query_row(
                "SELECT run_id FROM kube_job_operations WHERE operation_id=?1",
                [id],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn launch(&self, run: &RunId) -> LedgerResult<Option<Launch>> {
        Ok(self
            .0
            .query_row(
                "SELECT cluster,namespace,launch_json FROM kube_job_runs WHERE run_id=?1",
                [run.as_str()],
                |row| {
                    Ok(Launch {
                        cluster: row.get(0)?,
                        namespace: row.get(1)?,
                        json: row.get(2)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn insert_launch(
        &self,
        run: &RunId,
        scope: &Scope<'_>,
        json: &str,
        now: &str,
    ) -> LedgerResult<()> {
        self.0.execute("INSERT INTO kube_job_runs(run_id,cluster,namespace,launch_json,created_at) VALUES(?1,?2,?3,?4,?5)",params![run.as_str(),scope.cluster,scope.namespace,json,now])?;
        Ok(())
    }

    pub fn launch_scope(&self, run: &RunId) -> LedgerResult<Option<(String, String)>> {
        Ok(self
            .0
            .query_row(
                "SELECT cluster,namespace FROM kube_job_runs WHERE run_id=?1",
                [run.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }

    pub fn staged_path(&self, run: &RunId, artifact: &ArtifactId) -> LedgerResult<Option<String>> {
        Ok(self
            .0
            .query_row(
                "SELECT staged_path FROM kube_job_staged_paths WHERE run_id=?1 AND artifact_ref=?2",
                params![run.as_str(), artifact.as_str()],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn insert_staged_path(
        &self,
        run: &RunId,
        artifact: &ArtifactId,
        scope: &Scope<'_>,
        path: &str,
        now: &str,
    ) -> LedgerResult<()> {
        self.0.execute("INSERT INTO kube_job_staged_paths (run_id,artifact_ref,cluster,namespace,staged_path,created_at) VALUES(?1,?2,?3,?4,?5,?6)",params![run.as_str(),artifact.as_str(),scope.cluster,scope.namespace,path,now])?;
        Ok(())
    }

    pub fn staged_paths(
        &self,
        run: &RunId,
        scope: &Scope<'_>,
    ) -> LedgerResult<std::collections::BTreeMap<ArtifactId, String>> {
        let mut statement = self.0.prepare("SELECT artifact_ref,staged_path FROM kube_job_staged_paths WHERE run_id=?1 AND cluster=?2 AND namespace=?3")?;
        let rows = statement.query_map(
            params![run.as_str(), scope.cluster, scope.namespace],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )?;
        rows.map(|row| {
            let (artifact, path) = row?;
            let artifact = ArtifactId::new(&artifact).map_err(|error| {
                LedgerError::invalid_data_caused_by("invalid kube artifact id", error)
            })?;
            Ok((artifact, path))
        })
        .collect()
    }

    pub fn revision(&self, key: &str, digest: &str) -> LedgerResult<u64> {
        let prior: Option<(String, i64)> = self
            .0
            .query_row(
                "SELECT content_digest,revision FROM kube_projection_revisions WHERE object_key=?1",
                [key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let revision = match prior {
            Some((previous, revision)) if previous == digest => return Ok(revision as u64),
            Some((_, revision)) => revision.checked_add(1).ok_or_else(|| {
                LedgerError::invalid_data("projection revision exhausted".to_owned())
            })?,
            None => 1,
        };
        self.0.execute("INSERT INTO kube_projection_revisions(object_key,content_digest,revision) VALUES(?1,?2,?3) ON CONFLICT(object_key) DO UPDATE SET content_digest=excluded.content_digest,revision=excluded.revision",params![key,digest,revision])?;
        Ok(revision as u64)
    }

    pub fn pending(&self, scope: &Scope<'_>) -> LedgerResult<Vec<(String, serde_json::Value)>> {
        let mut statement = self.0.prepare("SELECT kind,request_json FROM kube_job_operations WHERE cluster=?1 AND namespace=?2 AND state='pending' ORDER BY created_at LIMIT 1024")?;
        let rows = statement.query_map(params![scope.cluster, scope.namespace], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.map(|row| {
            let (kind, request) = row?;
            Ok((kind, serde_json::from_str(&request)?))
        })
        .collect()
    }
}
