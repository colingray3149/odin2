//! Ledger-scheme scope invariants: lane session authority and its propagation.

use super::*;

#[test]
fn lane_resolution_proves_bound_session_ref() {
    let ledger = seeded_ledger();
    let router = test_router(ledger.clone(), artifact_root("lane-session-scope"));
    let url = "lane://lane-alpha";
    let unbound = UriContext::new(Scope::default());
    let matching = UriContext::new(Scope {
        session: Some("session-alpha".parse().unwrap()),
        ..Scope::default()
    });
    let mismatched = UriContext::new(Scope {
        session: Some("session-other".parse().unwrap()),
        ..Scope::default()
    });

    // A lane without session evidence remains operator-readable, but cannot satisfy a
    // session-bound caller.
    assert!(router.resolve(&unbound, url).is_ok());
    assert!(matches!(
        router.resolve(&matching, url),
        Err(UriError::ScopeDenied { reason, .. }) if reason.contains("\"session\"")
    ));

    set_alpha_lane_session_ref(&ledger, "session-alpha");
    let snapshot = router.resolve(&matching, url).unwrap();
    assert_eq!(spot_json(&snapshot)["sessionRef"], json!("session-alpha"));
    assert!(router.resolve(&unbound, url).is_ok());
    assert!(matches!(
        router.resolve(&mismatched, url),
        Err(UriError::ScopeDenied { reason, .. }) if reason.contains("\"session\"")
    ));

    set_alpha_lane_session_ref(&ledger, "-malformed");
    for context in [&matching, &unbound] {
        assert!(matches!(
            router.resolve(context, url),
            Err(UriError::Storage { detail })
                if detail.contains("lane lane-alpha stores malformed session_ref")
                    && detail.contains("SessionId")
        ));
    }
}

#[test]
fn lane_session_scope_propagates_through_run_and_reference_chains() {
    let ledger = seeded_ledger();
    let root = artifact_root("lane-session-propagation");
    let metadata = {
        let mut guard = ledger.lock().unwrap();
        let (metadata, _) = seed_artifact(&mut guard, &root);
        let requested_at = decode_utc("2026-01-01T00:00:00Z").unwrap();
        let expires_at = decode_utc("2026-01-01T00:01:00Z").unwrap();
        guard
            .request_approval(NewApproval {
                approval_id: "approval-lane-alpha".parse().unwrap(),
                issuer: "operator".to_owned(),
                scope: ApprovalScope {
                    target_kind: "lane".to_owned(),
                    target_id: "lane-alpha".to_owned(),
                    capability_id: "capability.alpha".parse().unwrap(),
                    arguments_digest: Digest::hash(b"lane arguments"),
                },
                requested_at,
                expires_at,
            })
            .unwrap();
        metadata
    };
    let router = test_router(ledger.clone(), root);
    let matching = UriContext::new(Scope {
        session: Some("session-alpha".parse().unwrap()),
        ..Scope::default()
    });
    let mismatched = UriContext::new(Scope {
        session: Some("session-other".parse().unwrap()),
        ..Scope::default()
    });
    let urls = [
        "run://run-alpha".to_owned(),
        "incident://incident-alpha".to_owned(),
        "approval://approval-alpha".to_owned(),
        format!("odin-artifact://{}", metadata.artifact_id),
        "approval://approval-lane-alpha".to_owned(),
    ];

    for url in &urls {
        assert!(
            matches!(
                router.resolve(&matching, url),
                Err(UriError::ScopeDenied { .. })
            ),
            "{url} must not infer an absent lane session"
        );
    }

    set_alpha_lane_session_ref(&ledger, "session-alpha");
    for url in &urls {
        assert!(
            router.resolve(&matching, url).is_ok(),
            "{url} must accept exact lane session evidence"
        );
        assert!(
            matches!(
                router.resolve(&mismatched, url),
                Err(UriError::ScopeDenied { .. })
            ),
            "{url} must deny mismatched lane session evidence"
        );
    }

    set_alpha_lane_session_ref(&ledger, "-malformed");
    for url in &urls {
        assert!(
            matches!(
                router.resolve(&matching, url),
                Err(UriError::Storage { detail })
                    if detail.contains("lane lane-alpha stores malformed session_ref")
                        && detail.contains("SessionId")
            ),
            "{url} must surface malformed lane session evidence as storage corruption"
        );
    }
}
