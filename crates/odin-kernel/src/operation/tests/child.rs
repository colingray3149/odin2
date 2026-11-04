//! Child grants require successful admission, not synthetic permit fields.
use super::*;
use crate::operation::{ChildEffectGrant, ChildEffectRequest};
use crate::token::LedgerRevocations;

struct ChildExecutor {
    inner: Executor,
    ledger: Arc<Mutex<Ledger>>,
    child: std::sync::OnceLock<ChildEffectGrant>,
    handoffs: AtomicU64,
}

impl OperationExecutor for ChildExecutor {
    fn id(&self) -> &'static str {
        PreparedEffect::OMP_HOST_EXECUTOR
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
        self.handoffs.fetch_add(1, Ordering::SeqCst);
        {
            let ledger = self.ledger.lock().unwrap();
            let row =
                store::operation_row_by_id(ledger.connection(), effect.operation_id().as_str())
                    .unwrap()
                    .unwrap();
            assert_eq!(row.effect_state, EffectState::EffectStarted);
            // Admission hashes authority/cost/binding as well as arguments.
            assert_ne!(row.request_digest, effect.payload().digest.to_string());
        }
        let target = Target {
            kind: "publication".into(),
            id: "session/project/claude/one".into(),
        };
        let minted = ChildEffectGrant::from_prepared(&effect, target);
        assert!(self
            .child
            .set(minted.expect("real dispatched permit mints a child grant"))
            .is_ok());
        self.inner.execute(effect)
    }
}

fn child_fixture() -> (Fixture, Arc<ChildExecutor>, Arc<Mutex<Ledger>>) {
    let ledger = Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()));
    let world = Arc::new(World::default());
    let executor = Arc::new(ChildExecutor {
        inner: Executor(Arc::clone(&world)),
        ledger: Arc::clone(&ledger),
        child: std::sync::OnceLock::new(),
        handoffs: AtomicU64::new(0),
    });
    let mut contract = contract();
    contract.effect_class = EffectClass::R2;
    let fixture = fixture_with_contract(
        world,
        executor.clone(),
        Arc::clone(&ledger),
        b"policy",
        contract,
    );
    (fixture, executor, ledger)
}

fn child_request(grant: &ChildEffectGrant, tag: &str) -> ChildEffectRequest {
    ChildEffectRequest {
        correlation_id: correlation(tag),
        target: grant.target().clone(),
        arguments: serde_json::json!({"commit":"exact"}),
    }
}

#[test]
fn admitted_child_mints_runs_recovers_and_original_token_revocation_blocks_use() {
    let (fixture, executor, ledger) = child_fixture();
    let request = invoke_request(&correlation("child-parent"), 1);
    let decision = fixture
        .authority
        .invoke_authorized(fixture.authorize(&write_arguments("parent"), 20), &request)
        .unwrap();
    assert_eq!(decision.state, EffectState::Committed);
    let grant = executor.child.get().unwrap().clone();
    let clock: Clock = Arc::new(|| 20);
    let recovered = ChildEffectGrant::recover(
        Arc::clone(&ledger),
        Arc::clone(&clock),
        grant.registration_id(),
    )
    .unwrap();
    assert_eq!(
        recovered
            .run(child_request(&grant, "valid-child"), || Ok(
                serde_json::json!({"published":true})
            ))
            .unwrap(),
        serde_json::json!({"published":true})
    );
    {
        let ledger = ledger.lock().unwrap();
        let row = store::operation_row(ledger.connection(), request.correlation_id.as_str())
            .unwrap()
            .unwrap();
        let lease = store::lease_row(ledger.connection(), CAPSULE)
            .unwrap()
            .unwrap();
        assert_eq!(lease.state, "open");
        LedgerRevocations::new(&ledger)
            .revoke(&odin_domain::SeatTokenId::new(&row.token_id).unwrap(), 21)
            .unwrap();
    }
    assert!(
        ChildEffectGrant::recover(Arc::clone(&ledger), clock, grant.registration_id()).is_err()
    );
    for each_grant in [&grant, &recovered] {
        for tag in ["valid-child", "revoked-child"] {
            let error = each_grant
                .run(child_request(each_grant, tag), || {
                    panic!("revoked original token must not reach closure")
                })
                .unwrap_err();
            assert!(
                error.to_string().contains("original token revoked"),
                "{error}"
            );
        }
    }
    let ledger = ledger.lock().unwrap();
    let refused_id = format!(
        "child-request:{}:{}",
        grant.registration_id(),
        correlation("revoked-child").as_str()
    );
    assert!(store::operation_row(ledger.connection(), &refused_id)
        .unwrap()
        .is_none());
}
