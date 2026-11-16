//! Recovery claims must exclude another authority and never replay an effect.

use super::*;
use std::sync::mpsc;

struct RecoveryExecutor {
    inner: Executor,
    calls: AtomicU64,
    entered: Mutex<Option<mpsc::Sender<()>>>,
    release: Mutex<Option<mpsc::Receiver<()>>>,
    receipt: Digest,
}

impl OperationExecutor for RecoveryExecutor {
    fn id(&self) -> &'static str {
        self.inner.id()
    }

    fn declared_pre_world(
        &self,
        contract: &CapabilityContract,
        payload: &Payload,
    ) -> Result<Option<PreWorld>, ExecutorFault> {
        self.inner.declared_pre_world(contract, payload)
    }

    fn observe(
        &self,
        contract: &CapabilityContract,
        payload: &Payload,
    ) -> Result<PreWorld, ExecutorFault> {
        self.inner.observe(contract, payload)
    }

    fn expected_post_world(
        &self,
        contract: &CapabilityContract,
        payload: &Payload,
    ) -> Result<Option<Digest>, ExecutorFault> {
        self.inner.expected_post_world(contract, payload)
    }

    fn execute(&self, effect: PreparedEffect) -> Result<EffectOutcome, ExecutorFault> {
        self.inner.execute(effect)
    }

    fn recover_cfd(&self, _row: &store::OperationRow) -> Result<Digest, ExecutorFault> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(entered) = self.entered.lock().unwrap().take() {
            entered.send(()).unwrap();
        }
        if let Some(release) = self.release.lock().unwrap().take() {
            release.recv().unwrap();
        }
        Ok(self.receipt)
    }
}

#[test]
fn recovery_claim_excludes_another_authority_and_preserves_the_receipt() {
    let path = lease_ledger_path("cfd-recovery-claim");
    let ledger = Arc::new(Mutex::new(Ledger::open(&path).unwrap()));
    let world = Arc::new(World::default());
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let receipt = receipt_digest("recovery-proof");
    let executor = Arc::new(RecoveryExecutor {
        inner: Executor(Arc::clone(&world)),
        calls: AtomicU64::new(0),
        entered: Mutex::new(Some(entered_tx)),
        release: Mutex::new(Some(release_rx)),
        receipt,
    });
    let first = fixture_with(Arc::clone(&world), executor.clone(), Arc::clone(&ledger));
    let second = fixture_with(
        Arc::clone(&world),
        executor.clone(),
        Arc::new(Mutex::new(Ledger::open(&path).unwrap())),
    );
    let correlation_id = correlation("cfd-recovery-claim");
    let arguments = write_arguments("recovered");
    let request = invoke_request(&correlation_id, 1);
    world.post_effect_uncertain.store(true, Ordering::SeqCst);
    assert!(first
        .authority
        .invoke_authorized(first.authorize(&arguments, 20), &request)
        .is_err());
    assert_eq!(
        first.row_state(correlation_id.as_str()),
        EffectState::InDoubt
    );
    let authority = Arc::clone(&first.authority);
    let recovery_correlation = correlation_id.clone();
    let recovery = std::thread::spawn(move || authority.recover_cfd(&recovery_correlation));
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("recovery entered executor");
    let competing_authority = Arc::clone(&second.authority);
    let competing_correlation = correlation_id.clone();
    let (result_tx, result_rx) = mpsc::channel();
    let competitor = std::thread::spawn(move || {
        let _ = result_tx.send(competing_authority.recover_cfd(&competing_correlation));
    });
    let competing = result_rx.recv_timeout(std::time::Duration::from_secs(5));
    release_tx.send(()).unwrap();
    let competing = competing.expect("competing recovery must not wait for the active effect");
    assert!(
        competing.is_err(),
        "a second authority must not enter the claimed recovery"
    );
    competitor.join().unwrap();
    let recovered = recovery.join().unwrap().expect("claimed recovery commits");
    assert_eq!(recovered.state, EffectState::Committed);
    assert_eq!(
        first.row_evidence(correlation_id.as_str()),
        Some(receipt_digest("recovered").to_string())
    );
    {
        let ledger = first.authority.store.lock().unwrap();
        let row = store::operation_row(ledger.connection(), correlation_id.as_str())
            .unwrap()
            .unwrap();
        assert_eq!(row.recovery_evidence_digest, Some(receipt.to_string()));
    }
    assert!(
        second.authority.recover_cfd(&correlation_id).is_err(),
        "committed rows are not uncertain"
    );
    let replay = second
        .authority
        .invoke_authorized(second.authorize(&arguments, 21), &request)
        .expect("replay uses recovered journal outcome");
    assert!(replay.replay);
    assert_eq!(replay.operation_id, recovered.operation_id);
    assert_eq!(
        second.row_evidence(correlation_id.as_str()),
        Some(receipt_digest("recovered").to_string())
    );
    {
        let ledger = second.authority.store.lock().unwrap();
        let row = store::operation_row(ledger.connection(), correlation_id.as_str())
            .unwrap()
            .unwrap();
        assert_eq!(row.recovery_evidence_digest, Some(receipt.to_string()));
    }
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    assert_eq!(world.executions.load(Ordering::SeqCst), 1);
    drop(first);
    drop(second);
    discard_ledger(&path);
}

#[test]
fn recovery_never_dispatches_a_prepared_or_committed_operation() {
    let world = Arc::new(World::default());
    let ledger = Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()));
    let executor = Arc::new(RecoveryExecutor {
        inner: Executor(Arc::clone(&world)),
        calls: AtomicU64::new(0),
        entered: Mutex::new(None),
        release: Mutex::new(None),
        receipt: receipt_digest("never"),
    });
    let fixture = fixture_with(Arc::clone(&world), executor.clone(), ledger);
    let prepared = correlation("cfd-recovery-prepared");
    let prepared_request = invoke_request(&prepared, 1);
    let arguments = write_arguments("prepared");
    fixture.seed_in_flight_operation(
        &prepared,
        &prepared_request.capsule_id,
        &fixture.authorize(&arguments, 20),
    );
    assert!(fixture.authority.recover_cfd(&prepared).is_err());
    assert_eq!(fixture.row_state(prepared.as_str()), EffectState::Prepared);

    let committed = correlation("cfd-recovery-committed");
    let request = invoke_request(&committed, 1);
    // The prepared row blocks its capsule, so use another fixture for this case.
    let other = fixture_with(
        Arc::clone(&world),
        executor.clone(),
        Arc::new(Mutex::new(Ledger::open_in_memory().unwrap())),
    );
    other
        .authority
        .invoke_authorized(other.authorize(&write_arguments("committed"), 20), &request)
        .unwrap();
    assert!(other.authority.recover_cfd(&committed).is_err());
    assert_eq!(other.row_state(committed.as_str()), EffectState::Committed);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
    assert_eq!(world.executions.load(Ordering::SeqCst), 1);
}
