use super::*;
use odin_ledger::Ledger;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

fn authority(ledger: &Arc<Mutex<Ledger>>) -> StopAuthority {
    StopAuthority::new(
        Arc::clone(ledger),
        super::super::recovery_worker_channel("unix:path=/tmp/odin-pod-test-absent.sock").unwrap(),
    )
}

fn identity(correlation: &CorrelationId) -> PodWorkerIdentity {
    PodWorkerIdentity {
        cluster: "cluster".to_owned(),
        namespace: "namespace".to_owned(),
        pod_name: "terminal".to_owned(),
        pod_uid: None,
        policy_name: "terminal-egress".to_owned(),
        policy_uid: None,
        secret_name: None,
        secret_uid: None,
        correlation_id: correlation.as_str().to_owned(),
    }
}

struct Backend {
    ledger: Arc<Mutex<Ledger>>,
    failure: Option<PodWorkerBackendFault>,
    stops: AtomicUsize,
}

impl Backend {
    fn new(ledger: &Arc<Mutex<Ledger>>, failure: Option<PodWorkerBackendFault>) -> Self {
        Self {
            ledger: Arc::clone(ledger),
            failure,
            stops: AtomicUsize::new(0),
        }
    }
}

impl PodWorkerBackend for Backend {
    fn stop(
        &self,
        worker: &WorkerId,
        identity: &PodWorkerIdentity,
    ) -> Result<(), PodWorkerBackendFault> {
        let row = row(&self.ledger, worker);
        assert_eq!(row.phase, "stopping");
        assert_eq!(row.identity, *identity);
        self.stops.fetch_add(1, Ordering::SeqCst);
        match &self.failure {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }
}

fn row(ledger: &Arc<Mutex<Ledger>>, worker: &WorkerId) -> store::PodWorkerRow {
    store::worker_row(ledger.lock().unwrap().connection(), worker.as_str())
        .unwrap()
        .unwrap()
}

#[test]
fn pod_stop_persists_created_uids_and_replays_without_backend() {
    let ledger = Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()));
    let original = authority(&ledger);
    let worker = super::super::mint_worker_id().unwrap();
    let correlation = CorrelationId::new("22222222222222222222222222222222").unwrap();
    let mut identity = identity(&correlation);
    identity.secret_name = Some("credentials".to_owned());
    original
        .register_pod_worker(&worker, &identity, &correlation)
        .unwrap();
    identity.policy_uid = Some("policy".to_owned());
    original
        .update_pod_worker_identity(&worker, &identity)
        .unwrap();
    assert_eq!(row(&ledger, &worker).phase, "registered");
    identity.secret_uid = Some("secret".to_owned());
    identity.pod_uid = Some("pod".to_owned());
    original
        .update_pod_worker_identity(&worker, &identity)
        .unwrap();
    assert_eq!(row(&ledger, &worker).identity, identity);
    assert_eq!(row(&ledger, &worker).phase, "released");
    assert!(original.recover_pending_pod_stops().unwrap().is_empty());

    let backend = Arc::new(Backend::new(&ledger, None));
    original.register_pod_backend(backend.clone()).unwrap();
    let outcome = original.stop_pod_worker(&worker).unwrap();
    assert_eq!(outcome.worker_id, worker);
    assert_eq!(outcome.verdict, StopVerdictTag::Stopped);
    assert!(!outcome.replay);
    assert_eq!(row(&ledger, &worker).phase, "stopped");
    let audit = original.pod_stop_record(&worker).unwrap().unwrap();
    assert_eq!(audit.verdict, StopVerdictTag::Stopped);
    assert_eq!(audit.evidence, outcome.evidence);
    assert_eq!(backend.stops.load(Ordering::SeqCst), 1);
    drop(original);

    let restarted = authority(&ledger);
    assert!(restarted.stop_pod_worker(&worker).unwrap().replay);
    assert!(restarted.recover_pending_pods(None).unwrap().is_empty());
    assert_eq!(backend.stops.load(Ordering::SeqCst), 1);
}

#[test]
fn pod_stop_failure_returns_cause_and_survives_ledger_reopen() {
    let worker = super::super::mint_worker_id().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let path = scratch.path().join("ledger.sqlite3");
    let correlation = CorrelationId::new("22222222222222222222222222222222").unwrap();
    {
        let ledger = Arc::new(Mutex::new(Ledger::open(&path).unwrap()));
        let original = authority(&ledger);
        original
            .register_pod_worker(&worker, &identity(&correlation), &correlation)
            .unwrap();
        let cause = PodWorkerBackendFault::Unavailable {
            reason: "delete pod: API connection refused".to_owned(),
        };
        let backend = Arc::new(Backend::new(&ledger, Some(cause.clone())));
        original.register_pod_backend(backend.clone()).unwrap();
        let outcome = original.stop_pod_worker(&worker).unwrap();
        assert_eq!(outcome.verdict, StopVerdictTag::Indeterminate);
        assert_eq!(
            outcome.evidence.missing,
            Some(StopAuthorityError::PodBackend(cause.clone()).to_string())
        );
        assert_eq!(row(&ledger, &worker).phase, "stopping");
        let audit = original.pod_stop_record(&worker).unwrap().unwrap();
        assert_eq!(audit.verdict, StopVerdictTag::Indeterminate);
        assert_eq!(
            audit.missing,
            Some(StopAuthorityError::PodBackend(cause).to_string())
        );
        assert_eq!(audit.evidence.missing, audit.missing);
        assert_eq!(backend.stops.load(Ordering::SeqCst), 1);
    }
    {
        let ledger = Arc::new(Mutex::new(Ledger::open(&path).unwrap()));
        let restarted = authority(&ledger);
        let audit = restarted.pod_stop_record(&worker).unwrap().unwrap();
        assert_eq!(audit.verdict, StopVerdictTag::Indeterminate);
        assert!(audit.missing.unwrap().contains("API connection refused"));
        let backend = Arc::new(Backend::new(&ledger, None));
        restarted.register_pod_backend(backend.clone()).unwrap();
        let outcomes = restarted.recover_pending_pod_stops().unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].verdict, StopVerdictTag::Stopped);
        assert_eq!(row(&ledger, &worker).phase, "stopped");
        assert_eq!(backend.stops.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn pod_retained_stop_requires_admission_after_restart() {
    let worker = super::super::mint_worker_id().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let path = scratch.path().join("ledger.sqlite3");
    let correlation = CorrelationId::new("22222222222222222222222222222222").unwrap();
    let mut identity = identity(&correlation);
    {
        let ledger = Arc::new(Mutex::new(Ledger::open(&path).unwrap()));
        let original = authority(&ledger);
        original
            .register_retained_pod_worker(&worker, &identity, &correlation)
            .unwrap();
        identity.pod_uid = Some("pod".to_owned());
        identity.policy_uid = Some("policy".to_owned());
        original
            .update_pod_worker_identity(&worker, &identity)
            .unwrap();
    }
    {
        let ledger = Arc::new(Mutex::new(Ledger::open(&path).unwrap()));
        let restarted = authority(&ledger);
        let backend = Arc::new(Backend::new(&ledger, None));
        restarted.register_pod_backend(backend.clone()).unwrap();
        assert!(restarted.recover_pending_pods(None).unwrap().is_empty());
        assert!(restarted.recover_pending_pod_stops().unwrap().is_empty());
        assert!(restarted.request_pod_stop(&worker).is_err());
        assert!(restarted.stop_pod_worker(&worker).is_err());
        assert_eq!(backend.stops.load(Ordering::SeqCst), 0);
        restarted.admit_pod_stop(&worker, &identity).unwrap();
    }
    {
        let ledger = Arc::new(Mutex::new(Ledger::open(&path).unwrap()));
        let restarted = authority(&ledger);
        let backend = Arc::new(Backend::new(&ledger, None));
        restarted.register_pod_backend(backend.clone()).unwrap();
        let outcomes = restarted.recover_pending_pod_stops().unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].verdict, StopVerdictTag::Stopped);
        assert_eq!(backend.stops.load(Ordering::SeqCst), 1);
    }
}
