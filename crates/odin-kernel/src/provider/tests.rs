//! Declared provider policy and durable accounting invariants.

use odin_domain::SeatId;
use odin_ledger::lane_run::{create_lane, NewLane};
use odin_registry::schema::parse_object_toml;

use super::*;

const GATEWAY_TOML: &str = concat!(
        "schema = \"odin.registry.v1\"\n",
        "kind = \"provider\"\n",
        "enabled = true\n",
        "description = \"The deployed LiteLLM loopback gateway with hard budgets; lanes resolve through it.\"\n",
        "adapter = \"litellm-gateway\"\n",
        "policy = { routes = [{ gateway_lane_id = \"zai-glm\", gateway_model_id = \"openai/glm-5.3\" }] }\n",
        "recovery = { allowed_rungs = [\"escalate\"], blocked_missing_decision = \"operator decision required\", max_attempts = { retry = 0, restart_worker = 0, checkpoint = 0, rehome = 0, escalate = 1 }, cooldown_seconds = { retry = 0, restart_worker = 0, checkpoint = 0, rehome = 0, escalate = 0 } }\n"
    );

fn gateway_objects(enabled: bool) -> Vec<RegistryObject> {
    let source = if enabled {
        GATEWAY_TOML.to_owned()
    } else {
        GATEWAY_TOML.replace("enabled = true", "enabled = false")
    };
    vec![parse_object_toml(
        RegistryKind::Provider,
        "gateway",
        "registry/providers/gateway/provider.toml",
        &source,
    )
    .unwrap()]
}

fn candidates() -> Vec<ProviderCandidate> {
    vec![
        ProviderCandidate::new(
            ProviderId::new("gateway").unwrap(),
            "gateway-primary",
            "kimi-k3",
            "primary",
            "project-a",
            0,
        )
        .unwrap(),
        ProviderCandidate::new(
            ProviderId::new("gateway").unwrap(),
            "gateway-storm",
            "kimi-k3",
            "primary",
            "other",
            1,
        )
        .unwrap(),
    ]
}

fn coordinator(lane: &LaneId) -> ProviderLeaseCoordinator {
    ProviderLeaseCoordinator::new(
        lane.clone(),
        &gateway_objects(true),
        Some("project-a".to_owned()),
        candidates(),
    )
    .unwrap()
}

fn seeded_ledger(lane: &LaneId) -> Ledger {
    let ledger = Ledger::open_in_memory().unwrap();
    seed_lane(&ledger, lane);
    ledger
}

fn seed_lane(ledger: &Ledger, lane: &LaneId) {
    create_lane(
        ledger.connection(),
        &NewLane {
            lane_id: lane.clone(),
            seat_id: SeatId::new("seat-a").unwrap(),
            project_id: None,
            template_id: "template-a".to_owned(),
            backend: "local_omp".to_owned(),
            created_by: "test".to_owned(),
            created_at: at(1),
            retained: false,
        },
    )
    .unwrap();
}

fn at(seconds: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(seconds).unwrap()
}

fn quota_fault(seconds: i64) -> ProviderFault {
    ProviderFault::QuotaExhausted {
        resets_at: at(seconds),
    }
}

#[test]
fn selection_precedence_is_priority_then_affinity() {
    let coordinator = ProviderLeaseCoordinator::new(
        LaneId::new("lane-a").unwrap(),
        &gateway_objects(true),
        Some("project-a".to_owned()),
        vec![
            ProviderCandidate::new(
                ProviderId::new("gateway").unwrap(),
                "gateway-affine",
                "kimi-k3",
                "primary",
                "project-a",
                1,
            )
            .unwrap(),
            ProviderCandidate::new(
                ProviderId::new("gateway").unwrap(),
                "gateway-top",
                "kimi-k3",
                "primary",
                "zzz",
                0,
            )
            .unwrap(),
            ProviderCandidate::new(
                ProviderId::new("gateway").unwrap(),
                "gateway-affine-2",
                "kimi-k3",
                "primary",
                "project-a",
                1,
            )
            .unwrap(),
        ],
    )
    .unwrap();

    let order: Vec<_> = coordinator
        .candidates()
        .iter()
        .map(|state| state.candidate.account_handle.as_str())
        .collect();
    // Priority 0 first; inside priority 1 the lane affinity "project-a" sorts
    // ahead and "gateway-affine" breaks the remaining tie before "-2".
    assert_eq!(order, ["gateway-top", "gateway-affine", "gateway-affine-2"]);
}

#[test]
fn in_flight_bindings_are_immutable_and_block_rotation() {
    let lane = LaneId::new("lane-a").unwrap();
    let mut ledger = seeded_ledger(&lane);
    let mut coordinator = coordinator(&lane);

    let first = coordinator
        .begin_request(&mut ledger, "req-1", at(10))
        .unwrap();
    let started = ledger
        .active_provider_lease_for_lane(&lane)
        .unwrap()
        .unwrap();
    assert_eq!(first.lease_id, started.lease_id);
    assert_eq!(first.provider.as_str(), "gateway");
    assert_eq!(first.account_handle, "gateway-primary");

    // Duplicate request ids suppress work and return the same binding.
    assert_eq!(
        coordinator
            .begin_request(&mut ledger, "req-1", at(11))
            .unwrap(),
        first
    );
    assert_eq!(
        ledger
            .active_provider_lease_for_lane(&lane)
            .unwrap()
            .unwrap()
            .lease_id,
        started.lease_id
    );

    // A quota storm is recorded against the binding, never switching it.
    let record = coordinator
        .record_fault("req-1", quota_fault(1_000), at(12))
        .unwrap();
    assert_eq!(record.binding, first);
    assert_eq!(
        record.snapshot.health,
        ProviderHealth::Exhausted {
            resets_at: at(1_000)
        }
    );
    assert_eq!(
        coordinator
            .begin_request(&mut ledger, "req-2", at(13))
            .unwrap()
            .lease_id,
        started.lease_id
    );

    // Rotation is rejected while any predecessor request is active.
    let end = ProviderLeaseEnd {
        boundary: ProviderLeaseBoundary::Quota,
        reason: "storm".to_owned(),
    };
    assert!(matches!(
        coordinator.rotate_at_boundary(&mut ledger, end.clone(), at(14)),
        Err(ProviderError::RequestsActive { count: 2, .. })
    ));
    coordinator.finish_request("req-1").unwrap();
    assert!(matches!(
        coordinator.rotate_at_boundary(&mut ledger, end.clone(), at(15)),
        Err(ProviderError::RequestsActive { count: 1, .. })
    ));

    let finished = coordinator.finish_request("req-2").unwrap();
    assert_eq!(finished.lease_id, started.lease_id);
    assert!(matches!(
        coordinator.finish_request("req-2"),
        Err(ProviderError::UnknownRequest { .. })
    ));
}

#[test]
fn quota_storm_rotates_only_at_the_next_boundary() {
    let lane = LaneId::new("lane-a").unwrap();
    let mut ledger = seeded_ledger(&lane);
    let mut coordinator = coordinator(&lane);

    let binding = coordinator
        .begin_request(&mut ledger, "req-1", at(10))
        .unwrap();
    let predecessor_id = binding.lease_id.clone();
    coordinator
        .record_fault(
            "req-1",
            ProviderFault::RateLimited { until: at(30) },
            at(11),
        )
        .unwrap();
    coordinator
        .record_fault("req-1", quota_fault(1_000), at(12))
        .unwrap();
    coordinator.finish_request("req-1").unwrap();

    // The boundary ends the predecessor and starts the fallback binding.
    let rotation = coordinator
        .rotate_at_boundary(
            &mut ledger,
            ProviderLeaseEnd {
                boundary: ProviderLeaseBoundary::Quota,
                reason: "quota storm".to_owned(),
            },
            at(20),
        )
        .unwrap();
    let ProviderRotation::Rotated {
        predecessor,
        successor,
    } = rotation
    else {
        panic!("expected rotation during a quota storm");
    };
    assert_eq!(predecessor.lease_id, predecessor_id);
    assert_eq!(predecessor.provider_id.as_str(), "gateway");
    assert_eq!(predecessor.account_handle, "gateway-primary");
    assert_eq!(
        predecessor.end.as_ref().unwrap().boundary,
        ProviderLeaseBoundary::Quota
    );
    assert_eq!(successor.predecessor_id, Some(predecessor_id.clone()));
    assert_eq!(successor.account_handle, "gateway-storm");
    assert_eq!(
        ledger
            .active_provider_lease_for_lane(&lane)
            .unwrap()
            .unwrap()
            .lease_id,
        successor.lease_id
    );
    // The predecessor row kept its binding fields: no in-place mutation.
    let stored = ledger
        .provider_lease_by_id(&predecessor_id)
        .unwrap()
        .unwrap();
    assert_eq!(stored.account_handle, "gateway-primary");
    assert_eq!(stored.ended_at, Some(at(20)));

    // The fallback binding is now the active one: nothing left to change.
    assert!(matches!(
        coordinator.rotate_at_boundary(
            &mut ledger,
            ProviderLeaseEnd {
                boundary: ProviderLeaseBoundary::Turn,
                reason: "no change".to_owned(),
            },
            at(21),
        ),
        Ok(ProviderRotation::Unchanged { .. })
    ));
}

#[test]
fn exhaustion_is_typed_and_never_loops() {
    let lane = LaneId::new("lane-a").unwrap();
    let mut ledger = seeded_ledger(&lane);
    let mut coordinator = coordinator(&lane);

    coordinator
        .begin_request(&mut ledger, "req-1", at(10))
        .unwrap();
    coordinator
        .record_fault("req-1", quota_fault(1_000), at(11))
        .unwrap();
    coordinator.finish_request("req-1").unwrap();
    coordinator
        .rotate_at_boundary(
            &mut ledger,
            ProviderLeaseEnd {
                boundary: ProviderLeaseBoundary::Quota,
                reason: "primary exhausted".to_owned(),
            },
            at(12),
        )
        .unwrap();

    // The active fallback binding still accepts requests while exhausted.
    let second = coordinator
        .begin_request(&mut ledger, "req-2", at(13))
        .unwrap();
    assert_eq!(second.account_handle, "gateway-storm");
    coordinator
        .record_fault("req-2", quota_fault(1_000), at(14))
        .unwrap();
    coordinator.finish_request("req-2").unwrap();

    // Every candidate exhausted: one typed blocked error, no rotation,
    // no retry loop, and the lease row is untouched.
    let error = coordinator
        .rotate_at_boundary(
            &mut ledger,
            ProviderLeaseEnd {
                boundary: ProviderLeaseBoundary::Quota,
                reason: "all exhausted".to_owned(),
            },
            at(15),
        )
        .unwrap_err();
    let ProviderError::NoEligibleCandidate { detail, .. } = error else {
        panic!("expected a typed blocked error");
    };
    assert_eq!(detail, "2 exhausted");
    assert_eq!(
        ledger
            .active_provider_lease_for_lane(&lane)
            .unwrap()
            .unwrap()
            .account_handle,
        "gateway-storm"
    );
}
