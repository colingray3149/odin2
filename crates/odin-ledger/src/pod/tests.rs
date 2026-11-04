use super::*;
use crate::Ledger;

const WORKER: &str = "wkr0123456789abcdef0123456789abcdea";
fn identity() -> PodWorkerIdentity {
    PodWorkerIdentity {
        cluster: "cluster".to_owned(),
        namespace: "namespace".to_owned(),
        pod_name: "terminal".to_owned(),
        pod_uid: None,
        policy_name: "terminal-egress".to_owned(),
        policy_uid: None,
        secret_name: None,
        secret_uid: None,
        correlation_id: "22222222222222222222222222222222".to_owned(),
    }
}

fn audit(identity: &PodWorkerIdentity, stopped: bool) -> PodStopAudit {
    PodStopAudit {
        verdict: if stopped {
            StopVerdictTag::Stopped
        } else {
            StopVerdictTag::Indeterminate
        },
        action: "delete".to_owned(),
        residue: None,
        missing: None,
        evidence: PodStopEvidenceBody {
            schema: "odin.pod-stop-evidence.v1".to_owned(),
            worker_id: WorkerId::new(WORKER).unwrap(),
            backend: "kube.pod".to_owned(),
            cluster: identity.cluster.clone(),
            namespace: identity.namespace.clone(),
            pod_name: identity.pod_name.clone(),
            pod_uid: identity.pod_uid.clone(),
            policy_name: identity.policy_name.clone(),
            policy_uid: identity.policy_uid.clone(),
            secret_name: identity.secret_name.clone(),
            secret_uid: identity.secret_uid.clone(),
            secret_absent: identity.secret_name.as_ref().map(|_| stopped),
            pod_absent: stopped,
            policy_absent: stopped,
            evidence_complete: stopped,
            pod_residue: Vec::new(),
            missing: None,
        },
    }
}

#[test]
fn pod_intent_precedes_creation_and_uid_proof_is_immutable() {
    let mut ledger = Ledger::open_in_memory().unwrap();
    let now = OffsetDateTime::now_utc();
    let mut intent = identity();
    intent.pod_uid = Some("created-too-early".to_owned());
    assert!(ledger
        .with_tx(|tx| register_worker(tx, WORKER, &intent, now))
        .is_err());
    intent.pod_uid = None;
    ledger
        .with_tx(|tx| register_worker(tx, WORKER, &intent, now))
        .unwrap();
    ledger
        .with_tx(|tx| register_worker(tx, WORKER, &intent, now))
        .unwrap();
    assert!(ledger.with_tx(|tx| mark_released(tx, WORKER, now)).is_err());
    ledger
        .with_tx(|tx| record_proof(tx, WORKER, Some("pod-1"), None, now))
        .unwrap();
    assert!(ledger.with_tx(|tx| mark_released(tx, WORKER, now)).is_err());
    assert!(ledger
        .with_tx(|tx| record_proof(tx, WORKER, Some("pod-replacement"), Some("policy-1"), now))
        .is_err());
    assert_eq!(
        worker_row(ledger.connection(), WORKER)
            .unwrap()
            .unwrap()
            .identity
            .policy_uid,
        None
    );
    ledger
        .with_tx(|tx| record_proof(tx, WORKER, None, Some("policy-1"), now))
        .unwrap();
    ledger.with_tx(|tx| mark_released(tx, WORKER, now)).unwrap();
    let row = worker_row(ledger.connection(), WORKER).unwrap().unwrap();
    assert_eq!(row.identity.pod_uid.as_deref(), Some("pod-1"));
    assert_eq!(row.phase, "released");
}

struct StopDemand {
    action: String,
    state: String,
    evidence_json: String,
    attempts: i64,
    settled_at: Option<String>,
}

fn stop_demands(conn: &Connection, worker: &str, correlation: &str) -> Vec<StopDemand> {
    conn.prepare(
        "SELECT action, state, evidence_json, attempts, settled_at
           FROM pod_stop_intent WHERE worker_id = ?1 AND correlation_id = ?2",
    )
    .unwrap()
    .query_map([worker, correlation], |row| {
        Ok(StopDemand {
            action: row.get(0)?,
            state: row.get(1)?,
            evidence_json: row.get(2)?,
            attempts: row.get(3)?,
            settled_at: row.get(4)?,
        })
    })
    .unwrap()
    .collect::<Result<Vec<_>, _>>()
    .unwrap()
}

#[test]
fn pod_stop_demand_is_durable_pending_and_settles_only_on_proof() {
    let mut ledger = Ledger::open_in_memory().unwrap();
    let now = OffsetDateTime::now_utc();
    let intent = identity();
    ledger
        .with_tx(|tx| register_worker(tx, WORKER, &intent, now))
        .unwrap();
    ledger
        .with_tx(|tx| record_proof(tx, WORKER, Some("pod"), Some("policy"), now))
        .unwrap();
    let proven = worker_row(ledger.connection(), WORKER)
        .unwrap()
        .unwrap()
        .identity;
    // The operator's demand is journaled before actuation, keyed by worker
    // and correlation exactly as the live acceptance observes it.
    ledger
        .with_tx(|tx| request_stop(tx, WORKER, &audit(&proven, false), now))
        .unwrap();
    let demand = stop_demands(ledger.connection(), WORKER, &proven.correlation_id);
    assert_eq!(demand.len(), 1);
    assert_eq!(demand[0].action, "delete");
    assert_eq!(demand[0].state, "requested");
    assert!(demand[0].settled_at.is_none());
    assert_eq!(demand[0].attempts, 0);
    // An indeterminate attempt replaces the pending evidence and retries;
    // the demand itself stays durably requested.
    ledger
        .with_tx(|tx| record_stop(tx, WORKER, &audit(&proven, false), now))
        .unwrap();
    let demand = stop_demands(ledger.connection(), WORKER, &proven.correlation_id);
    assert_eq!(demand[0].state, "requested");
    assert!(demand[0].settled_at.is_none());
    assert_eq!(demand[0].attempts, 1);
    // Only confirmed absence settles the stop request.
    ledger
        .with_tx(|tx| record_stop(tx, WORKER, &audit(&proven, true), now))
        .unwrap();
    let demand = stop_demands(ledger.connection(), WORKER, &proven.correlation_id);
    assert_eq!(demand[0].state, "stopped");
    assert!(demand[0].settled_at.is_some());
    assert_eq!(demand[0].attempts, 2);
    let settled: serde_json::Value = serde_json::from_str(&demand[0].evidence_json).unwrap();
    assert_eq!(settled["verdict"], "stopped");
    assert_eq!(settled["action"], "delete");
    assert_eq!(settled["evidence"]["schema"], "odin.pod-stop-evidence.v1");
}

#[test]
fn secret_intent_proof_and_absence_are_required_for_settlement() {
    let mut ledger = Ledger::open_in_memory().unwrap();
    let now = OffsetDateTime::now_utc();
    let mut intent = identity();
    intent.secret_name = Some("account-and-mcp".to_owned());
    intent.secret_uid = Some("premature".to_owned());
    assert!(ledger
        .with_tx(|tx| register_worker(tx, WORKER, &intent, now))
        .is_err());
    intent.secret_uid = None;
    ledger
        .with_tx(|tx| register_worker(tx, WORKER, &intent, now))
        .unwrap();
    ledger
        .with_tx(|tx| record_proof(tx, WORKER, Some("pod"), Some("policy"), now))
        .unwrap();
    assert!(ledger.with_tx(|tx| mark_released(tx, WORKER, now)).is_err());
    let unproven = worker_row(ledger.connection(), WORKER)
        .unwrap()
        .unwrap()
        .identity;
    ledger
        .with_tx(|tx| request_stop(tx, WORKER, &audit(&unproven, false), now))
        .unwrap();
    assert!(ledger
        .with_tx(|tx| record_stop(tx, WORKER, &audit(&unproven, true), now))
        .is_err());
    ledger
        .with_tx(|tx| record_secret_proof(tx, WORKER, Some("secret"), now))
        .unwrap();
    assert!(ledger
        .with_tx(|tx| record_secret_proof(tx, WORKER, Some("replacement"), now))
        .is_err());
    let proven = worker_row(ledger.connection(), WORKER)
        .unwrap()
        .unwrap()
        .identity;
    let mut stopped = audit(&proven, true);
    stopped.evidence.secret_absent = Some(false);
    assert!(ledger
        .with_tx(|tx| record_stop(tx, WORKER, &stopped, now))
        .is_err());
    stopped.evidence.secret_absent = None;
    assert!(ledger
        .with_tx(|tx| record_stop(tx, WORKER, &stopped, now))
        .is_err());
    stopped.evidence.secret_absent = Some(true);
    stopped.evidence.secret_uid = Some("replacement".to_owned());
    assert!(ledger
        .with_tx(|tx| record_stop(tx, WORKER, &stopped, now))
        .is_err());
    ledger
        .with_tx(|tx| record_stop(tx, WORKER, &audit(&proven, true), now))
        .unwrap();
    assert!(pending_rows(ledger.connection(), None).unwrap().is_empty());
}
