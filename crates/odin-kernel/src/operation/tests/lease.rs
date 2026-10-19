//! Lease renewal requires a newer token for the same seat and session,
//! no unresolved effects, and an open capsule.

use super::*;

#[test]
fn renewed_token_rebinds_open_lease_across_reopen_and_journals_once() {
    let path = lease_ledger_path("renew");
    let world = Arc::new(World::default());
    let ledger = Arc::new(Mutex::new(Ledger::open(&path).expect("file-backed ledger")));
    let session = "00000000-0000-4000-8000-000000000001";

    // Generation 1 opens the lease under the original policy digest.
    let first = fixture_with_policy(
        Arc::clone(&world),
        Arc::new(Executor(Arc::clone(&world))),
        Arc::clone(&ledger),
        b"policy",
    );
    let fresh1 = proof_with("seat.one", session, b"policy", 100, 100);
    let authorized1 = first.authorize_with(fresh1, &arguments_at("docs/one.md", "renewed"), 100);
    first
        .authority
        .invoke_authorized(authorized1, &invoke_request(&correlation("renew-open"), 1))
        .expect("first generation opens the lease");
    assert_eq!(rebind_events(&ledger.lock().unwrap()), 0);

    // A newer token for the same seat and session carries the updated policy digest.
    let renewed = fixture_with_policy(
        Arc::clone(&world),
        Arc::new(Executor(Arc::clone(&world))),
        Arc::clone(&ledger),
        b"policy-two",
    );
    let fresh2 = proof_with("seat.one", session, b"policy-two", 200, 200);
    let authorized2 = renewed.authorize_with(fresh2, &arguments_at("docs/two.md", "renewed"), 200);
    let decision = renewed
        .authority
        .invoke_authorized(
            authorized2,
            &invoke_request(&correlation("renew-rebind"), 1),
        )
        .expect("a strictly newer same-identity token rebinds the open lease");
    assert_eq!(decision.state, EffectState::Committed);
    {
        let lease = lease_snapshot(&renewed.authority);
        assert_eq!(lease.state, "open");
        assert_eq!(lease.token_issued_at_ms, Some(200));
        assert_eq!(lease.policy_digest, Digest::hash(b"policy-two").to_string());
        assert_eq!(rebind_events(&renewed.authority.lock_store().unwrap()), 1);
    }

    // The rebound lease accepts its own generation again with no second
    // rotation event: the rebind is once, not once per invoke.
    let fresh2_again = proof_with("seat.one", session, b"policy-two", 200, 200);
    let authorized2b =
        renewed.authorize_with(fresh2_again, &arguments_at("docs/three.md", "renewed"), 200);
    renewed
        .authority
        .invoke_authorized(
            authorized2b,
            &invoke_request(&correlation("renew-after"), 1),
        )
        .expect("the rebound lease binds its own authority");
    assert_eq!(rebind_events(&renewed.authority.lock_store().unwrap()), 1);

    // The rebind is durable: after a ledger reopen the session continues on
    // the rebound lease and the journal still holds exactly one event.
    drop(first);
    drop(renewed);
    let reopened = Arc::new(Mutex::new(Ledger::open(&path).expect("reopen ledger")));
    let continued = fixture_with_policy(
        Arc::clone(&world),
        Arc::new(Executor(Arc::clone(&world))),
        Arc::clone(&reopened),
        b"policy-two",
    );
    let fresh3 = proof_with("seat.one", session, b"policy-two", 200, 200);
    let authorized3 =
        continued.authorize_with(fresh3, &arguments_at("docs/four.md", "renewed"), 200);
    continued
        .authority
        .invoke_authorized(
            authorized3,
            &invoke_request(&correlation("renew-reopen"), 1),
        )
        .expect("the rebound lease survives the ledger reopen");
    assert_eq!(rebind_events(&reopened.lock().unwrap()), 1);
    drop(continued);
    drop(reopened);
    discard_ledger(&path);
}

/// A lease only changes hands to a provably newer generation of its own
/// seat and session. A stale generation replay and a foreign seat or
/// session are typed authority mismatches — never "closed" — and never
/// move the lease.
#[test]
fn stale_and_foreign_tokens_cannot_take_the_open_lease() {
    let fixture = fixture();
    let session = "00000000-0000-4000-8000-000000000001";
    let fresh1 = proof_with("seat.one", session, b"policy", 100, 100);
    let authorized1 = fixture.authorize_with(fresh1, &arguments_at("docs/one.md", "one"), 100);
    fixture
        .authority
        .invoke_authorized(authorized1, &invoke_request(&correlation("take-open"), 1))
        .expect("generation one opens the lease");

    // A TTL renewal: same identity, same policy, strictly newer issuance.
    let fresh2 = proof_with("seat.one", session, b"policy", 200, 200);
    let authorized2 = fixture.authorize_with(fresh2, &arguments_at("docs/two.md", "one"), 200);
    fixture
        .authority
        .invoke_authorized(authorized2, &invoke_request(&correlation("take-rebind"), 1))
        .expect("newer same-identity token rebinds");

    // The old generation replays while the lease is at the newer one.
    let stale = proof_with("seat.one", session, b"policy", 100, 250);
    let authorized3 = fixture.authorize_with(stale, &arguments_at("docs/three.md", "one"), 250);
    let rejected = fixture
        .authority
        .invoke_authorized(authorized3, &invoke_request(&correlation("take-stale"), 1))
        .expect_err("stale replay must not take the lease");
    assert!(
        matches!(
            rejected,
            OperationRejection::CapsuleAuthorityMismatch { .. }
        ),
        "stale replay is a typed mismatch, got {rejected:?}"
    );

    // A foreign session with strictly newer issuance is still a mismatch.
    let foreign = proof_with(
        "seat.one",
        "00000000-0000-4000-8000-000000000002",
        b"policy",
        300,
        300,
    );
    let authorized4 = fixture.authorize_with(foreign, &arguments_at("docs/four.md", "one"), 300);
    let rejected = fixture
        .authority
        .invoke_authorized(
            authorized4,
            &invoke_request(&correlation("take-foreign"), 1),
        )
        .expect_err("a foreign session must not take the lease");
    assert!(
        matches!(
            rejected,
            OperationRejection::CapsuleAuthorityMismatch { .. }
        ),
        "foreign session is a typed mismatch, got {rejected:?}"
    );

    let lease = lease_snapshot(&fixture.authority);
    assert_eq!(lease.token_issued_at_ms, Some(200));
    assert_eq!(rebind_events(&fixture.authority.lock_store().unwrap()), 1);
}

/// Unresolved effects must settle under the current generation before rotation.
#[test]
fn in_flight_effects_block_lease_rebind_until_settled() {
    let fixture = fixture();
    let capsule_id = CapsuleId::new(CAPSULE).unwrap();
    let session = "00000000-0000-4000-8000-000000000001";
    let fresh1 = proof_with("seat.one", session, b"policy", 100, 100);
    let authorized1 = fixture.authorize_with(fresh1, &arguments_at("docs/one.md", "one"), 100);
    fixture
        .authority
        .invoke_authorized(authorized1, &invoke_request(&correlation("block-open"), 1))
        .expect("generation one opens the lease");

    // Seed a Prepared row under generation one.
    let fresh_seed = proof_with("seat.one", session, b"policy", 100, 100);
    let authorized_seed =
        fixture.authorize_with(fresh_seed, &arguments_at("docs/seed.md", "one"), 100);
    fixture.seed_in_flight_operation(
        &correlation("block-inflight"),
        &capsule_id,
        &authorized_seed,
    );

    // The newer generation arrives while the effect is unresolved.
    let fresh2 = proof_with("seat.one", session, b"policy", 200, 200);
    let authorized2 = fixture.authorize_with(fresh2, &arguments_at("docs/two.md", "one"), 200);
    let rejected = fixture
        .authority
        .invoke_authorized(
            authorized2,
            &invoke_request(&correlation("block-rebind"), 1),
        )
        .expect_err("an in-flight effect must block the rebind");
    assert!(
        matches!(
            rejected,
            OperationRejection::CapsuleBlocked { blocked: 1, .. }
        ),
        "in-flight effect blocks as CapsuleBlocked, got {rejected:?}"
    );
    assert_eq!(
        lease_snapshot(&fixture.authority).token_issued_at_ms,
        Some(100)
    );
    assert_eq!(rebind_events(&fixture.authority.lock_store().unwrap()), 0);

    // The current generation settles its own row before rotation.
    let fresh1_settling = proof_with("seat.one", session, b"policy", 100, 150);
    let settled = fixture
        .authority
        .resume(
            fresh1_settling,
            &capsule_id,
            &correlation("block-inflight"),
            &fixture.operation_id(correlation("block-inflight").as_str()),
        )
        .expect("the bound authority settles its own row");
    assert_eq!(settled.state, EffectState::Aborted);

    let fresh2_after = proof_with("seat.one", session, b"policy", 200, 200);
    let authorized3 =
        fixture.authorize_with(fresh2_after, &arguments_at("docs/three.md", "one"), 200);
    fixture
        .authority
        .invoke_authorized(authorized3, &invoke_request(&correlation("block-after"), 1))
        .expect("a settled capsule rebinds to the newer generation");
    assert_eq!(
        lease_snapshot(&fixture.authority).token_issued_at_ms,
        Some(200)
    );
    assert_eq!(rebind_events(&fixture.authority.lock_store().unwrap()), 1);
}

#[test]
fn closed_capsule_stays_closed_under_newer_verified_token() {
    let fixture = fixture();
    let capsule_id = CapsuleId::new(CAPSULE).unwrap();
    let session = "00000000-0000-4000-8000-000000000001";
    let fresh1 = proof_with("seat.one", session, b"policy", 100, 100);
    let authorized1 = fixture.authorize_with(fresh1, &arguments_at("docs/one.md", "one"), 100);
    fixture
        .authority
        .invoke_authorized(authorized1, &invoke_request(&correlation("closed-open"), 1))
        .expect("generation one opens the lease");
    let fresh_close = proof_with("seat.one", session, b"policy", 100, 120);
    let outcome = fixture
        .authority
        .close_capsule(
            fresh_close,
            &capsule_id,
            &correlation("closed-close"),
            CloseMode::Drain,
        )
        .expect("the bound authority closes the capsule");
    assert!(!outcome.replay);

    // A strictly newer token can never revive the closed lease.
    let fresh2 = proof_with("seat.one", session, b"policy", 200, 200);
    let authorized2 = fixture.authorize_with(fresh2, &arguments_at("docs/two.md", "one"), 200);
    let rejected = fixture
        .authority
        .invoke_authorized(
            authorized2,
            &invoke_request(&correlation("closed-newer"), 1),
        )
        .expect_err("a newer token must not revive a closed capsule");
    assert!(
        matches!(rejected, OperationRejection::CapsuleClosed { .. }),
        "closed stays closed, got {rejected:?}"
    );
    assert_eq!(fixture.lease_state(CAPSULE), "closed");
    assert_eq!(rebind_events(&fixture.authority.lock_store().unwrap()), 0);
}

/// Renewal changes the lease, not existing operation authority or session usage.
#[test]
fn renewed_generation_cannot_inherit_pre_renewal_rows_and_replays_keep_their_identity() {
    let path = lease_ledger_path("renewal-nonwiden");
    let world = Arc::new(World::default());
    let ledger = Arc::new(Mutex::new(Ledger::open(&path).expect("file-backed ledger")));
    let fixture = fixture_with(
        Arc::clone(&world),
        Arc::new(Executor(Arc::clone(&world))),
        ledger,
    );
    let session = "00000000-0000-4000-8000-000000000001";
    let capsule_id = CapsuleId::new(CAPSULE).unwrap();

    // Generation 100 opens the lease and commits the correlation once.
    let fresh1 = proof_with("seat.one", session, b"policy", 100, 100);
    let authorized_a = fixture.authorize_with(fresh1, &arguments_at("docs/one.md", "one"), 100);
    let correlation_a = correlation("renew-retry");
    let request_a = invoke_request(&correlation_a, 1);
    let committed = fixture
        .authority
        .invoke_authorized(authorized_a, &request_a)
        .expect("generation one commits the correlation");
    assert_eq!(committed.state, EffectState::Committed);
    assert!(!committed.replay);
    let pre_renewal_token = lease_snapshot(&fixture.authority).token_id;

    // The strictly newer generation re-binds the lease through its own
    // invoke — the one renewal path — committing a second correlation.
    let fresh2 = proof_with("seat.one", session, b"policy", 200, 200);
    let authorized_b = fixture.authorize_with(fresh2, &arguments_at("docs/two.md", "two"), 200);
    fixture
        .authority
        .invoke_authorized(
            authorized_b,
            &invoke_request(&correlation("renew-retry-second"), 1),
        )
        .expect("the renewed generation re-binds and commits");
    let rebound = lease_snapshot(&fixture.authority);
    assert_eq!(rebound.token_issued_at_ms, Some(200));
    assert_ne!(rebound.token_id, pre_renewal_token);
    assert_eq!(rebind_events(&fixture.authority.lock_store().unwrap()), 1);

    // The renewed generation presenting the OLD correlation byte-exactly
    // is a typed duplicate conflict, never a replay or a second execution.
    let renewed_replay = fixture.authorize_with(
        proof_with("seat.one", session, b"policy", 200, 200),
        &arguments_at("docs/one.md", "one"),
        200,
    );
    let conflict = fixture
        .authority
        .invoke_authorized(renewed_replay, &request_a)
        .expect_err("the renewed generation cannot present the recorded authority");
    assert!(
        matches!(
            &conflict,
            OperationRejection::DuplicateConflict { correlation_id }
                if correlation_id == &correlation_a
        ),
        "unexpected rejection: {conflict:?}"
    );
    assert_eq!(fixture.world.executions.load(Ordering::SeqCst), 2);
    {
        let ledger = fixture.authority.lock_store().unwrap();
        let row =
            odin_ledger::operation::operation_row(ledger.connection(), correlation_a.as_str())
                .unwrap()
                .expect("the pre-renewal row survives");
        assert_eq!(row.effect_state, EffectState::Committed);
        assert_eq!(row.token_id, pre_renewal_token);
        assert_eq!(
            row.evidence_digest,
            Some(receipt_digest("one").to_string()),
            "the captured receipt evidence is untouched"
        );
    }

    // The old generation can replay its committed correlation without execution or charge.
    let old_retry = fixture.authorize_with(
        proof_with("seat.one", session, b"policy", 100, 100),
        &arguments_at("docs/one.md", "one"),
        100,
    );
    let retried = fixture
        .authority
        .invoke_authorized(old_retry, &request_a)
        .expect("the recorded authority replays its own row");
    assert!(retried.replay);
    assert_eq!(retried.state, EffectState::Committed);
    assert_eq!(retried.operation_id, committed.operation_id);
    assert_eq!(fixture.world.executions.load(Ordering::SeqCst), 2);

    // The earlier generation cannot stop the renewed lease; refusal records nothing.
    let refused_stop = fixture.authority.stop_intent(
        proof_with("seat.one", session, b"policy", 100, 250),
        &capsule_id,
        &correlation("renew-retry-stop"),
        Some(committed.operation_id.clone()),
    );
    assert!(
        matches!(
            refused_stop,
            Err(OperationRejection::CapsuleAuthorityMismatch { .. })
        ),
        "the pre-renewal generation must not stop the rebound lease, got {refused_stop:?}"
    );
    {
        let ledger = fixture.authority.lock_store().unwrap();
        assert!(
            odin_ledger::operation::stop_row(
                ledger.connection(),
                correlation("renew-retry-stop").as_str(),
            )
            .unwrap()
            .is_none(),
            "a refused cancel records no stop intent"
        );
    }

    // Renewal preserves session usage; replays and refusals do not charge.
    let usage = {
        let ledger = fixture.authority.lock_store().unwrap();
        store::usage(ledger.connection(), session).unwrap()
    };
    assert_eq!((usage.requests, usage.stops, usage.spend), (2, 0, 0));

    // Reopen: the terminal row replays for its recorded authority with no
    // re-execution, and the usage ledger persists.
    drop(fixture);
    let reopened = Arc::new(Mutex::new(Ledger::open(&path).expect("reopen ledger")));
    let after = fixture_with(
        Arc::clone(&world),
        Arc::new(Executor(Arc::clone(&world))),
        reopened,
    );
    let resumed = after
        .authority
        .resume(
            proof_with("seat.one", session, b"policy", 100, 500),
            &capsule_id,
            &correlation_a,
            &committed.operation_id,
        )
        .expect("the reopened authority replays the terminal row");
    assert!(resumed.replay);
    assert_eq!(resumed.state, EffectState::Committed);
    assert_eq!(resumed.operation_id, committed.operation_id);
    assert_eq!(after.world.executions.load(Ordering::SeqCst), 2);
    let reopened_usage = {
        let ledger = after.authority.lock_store().unwrap();
        store::usage(ledger.connection(), session).unwrap()
    };
    assert_eq!(
        reopened_usage,
        store::UsageRow {
            requests: 2,
            stops: 0,
            spend: 0
        },
        "usage persists across the reopen and the replay charges nothing"
    );
    drop(after);
    discard_ledger(&path);
}
