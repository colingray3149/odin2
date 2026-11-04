//! Canonical parse, dispatch, and cross-scope refusal invariants.

use super::*;

#[test]
fn every_registered_scheme_resolves_deterministically() {
    let ledger = seeded_ledger();
    let (root, _scratch) = artifact_root("all-schemes");
    let (metadata, payload) = {
        let mut guard = ledger.lock().unwrap();
        seed_artifact(&mut guard, &root)
    };
    let router = test_router(ledger, root);
    let global = UriContext::new(Scope::default());
    let scoped = UriContext::new(Scope {
        seat: Some("seat-alpha".parse().unwrap()),
        ..Scope::default()
    });

    let atlas = router.resolve(&global, "atlas://").unwrap();
    assert_eq!(atlas, router.resolve(&global, "atlas://").unwrap());
    assert_eq!(spot_json(&atlas)["nodes"].as_array().unwrap().len(), 2);

    let lane = router.resolve(&scoped, "lane://lane-alpha").unwrap();
    assert_eq!(lane, router.resolve(&scoped, "lane://lane-alpha").unwrap());
    let lane_value = spot_json(&lane);
    assert_eq!(lane_value["laneId"], json!("lane-alpha"));
    assert_eq!(lane_value["seatId"], json!("seat-alpha"));
    assert_eq!(lane_value["status"], json!("desired"));

    let run = router.resolve(&scoped, "run://run-alpha").unwrap();
    let run_value = spot_json(&run);
    assert_eq!(run_value["runId"], json!("run-alpha"));
    assert_eq!(run_value["laneId"], json!("lane-alpha"));
    assert_eq!(run_value["status"], json!("pending"));

    let approval = router
        .resolve(&scoped, "approval://approval-alpha")
        .unwrap();
    let approval_value = spot_json(&approval);
    assert_eq!(approval_value["scope"]["targetId"], json!("run-alpha"));
    assert_eq!(approval_value["status"], json!("requested"));

    let incident = router
        .resolve(&scoped, "incident://incident-alpha")
        .unwrap();
    let incident_value = spot_json(&incident);
    assert_eq!(incident_value["runId"], json!("run-alpha"));
    assert_eq!(incident_value["severity"], json!("warning"));

    let artifact_url = format!("odin-artifact://{}", metadata.artifact_id);
    let artifact = router.resolve(&scoped, &artifact_url).unwrap();
    assert_eq!(artifact, router.resolve(&scoped, &artifact_url).unwrap());
    assert_eq!(artifact.content_type, "text/plain");
    assert!(matches!(&artifact.body, UriBody::Bytes(bytes) if bytes == &payload));
    assert!(artifact
        .notes
        .iter()
        .any(|note| note.contains("BLAKE3-verified")));
}

#[test]
fn cross_scope_reads_fail_closed() {
    let ledger = seeded_ledger();
    let (root, _scratch) = artifact_root("cross-scope");
    let (metadata, _) = {
        let mut guard = ledger.lock().unwrap();
        seed_artifact(&mut guard, &root)
    };
    let router = test_router(ledger, root);
    let global = UriContext::new(Scope::default());
    let other_seat = UriContext::new(Scope {
        seat: Some("seat-other".parse().unwrap()),
        ..Scope::default()
    });

    assert!(matches!(
        router.resolve(&other_seat, "lane://lane-alpha"),
        Err(UriError::ScopeDenied { .. })
    ));
    let other_lane = UriContext::new(Scope {
        seat: Some("seat-alpha".parse().unwrap()),
        lane: Some("lane-beta".parse().unwrap()),
        ..Scope::default()
    });
    assert!(matches!(
        router.resolve(&other_lane, "lane://lane-alpha"),
        Err(UriError::ScopeDenied { .. })
    ));
    let bound_session = UriContext::new(Scope {
        session: Some("session-alpha".parse().unwrap()),
        ..Scope::default()
    });
    assert!(matches!(
        router.resolve(&bound_session, "lane://lane-alpha"),
        Err(UriError::ScopeDenied { .. })
    ));
    let bound_attempt = UriContext::new(Scope {
        run: Some("run-alpha".parse().unwrap()),
        attempt: Some("attempt-other".parse().unwrap()),
        ..Scope::default()
    });
    assert!(matches!(
        router.resolve(&bound_attempt, "run://run-alpha"),
        Err(UriError::ScopeDenied { .. })
    ));
    let other_project = UriContext::new(Scope {
        project: Some("project-other".parse().unwrap()),
        ..Scope::default()
    });
    assert!(matches!(
        router.resolve(&other_project, "run://run-alpha"),
        Err(UriError::ScopeDenied { .. })
    ));

    // An unlinked incident proves no dimension: denied under any bound scope, readable
    // only from the unbound operator scope.
    assert!(matches!(
        router.resolve(&other_seat, "incident://incident-global"),
        Err(UriError::ScopeDenied { .. })
    ));
    assert!(router
        .resolve(&global, "incident://incident-global")
        .is_ok());

    // Attempt evidence on the incident card proves a bound attempt dimension.
    let attempt_evidence = UriContext::new(Scope {
        run: Some("run-alpha".parse().unwrap()),
        attempt: Some("attempt-alpha".parse().unwrap()),
        ..Scope::default()
    });
    assert!(router
        .resolve(&attempt_evidence, "incident://incident-alpha")
        .is_ok());
    let wrong_attempt = UriContext::new(Scope {
        attempt: Some("attempt-other".parse().unwrap()),
        ..Scope::default()
    });
    assert!(matches!(
        router.resolve(&wrong_attempt, "incident://incident-alpha"),
        Err(UriError::ScopeDenied { .. })
    ));

    // Resolve scope through real approval and artifact reference chains.
    assert!(router
        .resolve(&scoped_of_seat("seat-alpha"), "approval://approval-alpha")
        .is_ok());
    assert!(matches!(
        router.resolve(&other_seat, "approval://approval-alpha"),
        Err(UriError::ScopeDenied { .. })
    ));
    let artifact_url = format!("odin-artifact://{}", metadata.artifact_id);
    assert!(router
        .resolve(&scoped_of_seat("seat-alpha"), &artifact_url)
        .is_ok());
    assert!(matches!(
        router.resolve(&other_seat, &artifact_url),
        Err(UriError::ScopeDenied { .. })
    ));
}

/// An approval proves the bound scope through whatever it targets; a target kind that proves
/// no dimension (a capability) is readable only from the unbound operator scope.
#[test]
fn approvals_prove_scope_through_every_kind_of_target() {
    let ledger = seeded_ledger();
    let (root, _scratch) = artifact_root("approval-targets");
    let artifact_id = {
        let mut guard = ledger.lock().unwrap();
        seed_artifact(&mut guard, &root).0.artifact_id.to_string()
    };
    let bound = |apply: &dyn Fn(&mut Scope)| {
        let mut scope = Scope::default();
        apply(&mut scope);
        scope
    };
    let seat = |id: &str| bound(&|s| s.seat = Some(id.parse().unwrap()));
    let project = |id: &str| bound(&|s| s.project = Some(id.parse().unwrap()));
    let node = |id: &str| bound(&|s| s.node = Some(id.parse().unwrap()));
    let session = |id: &str| bound(&|s| s.session = Some(id.parse().unwrap()));
    let run = |id: &str| bound(&|s| s.run = Some(id.parse().unwrap()));
    let attempt = |id: &str| bound(&|s| s.attempt = Some(id.parse().unwrap()));
    // (target kind, target id, a scope it proves, a scope it denies)
    let targets: Vec<(&str, String, Scope, Scope)> = vec![
        (
            "seat",
            "seat-alpha".into(),
            seat("seat-alpha"),
            seat("seat-other"),
        ),
        (
            "project",
            "project-alpha".into(),
            project("project-alpha"),
            project("project-other"),
        ),
        (
            "node",
            "node-alpha".into(),
            node("node-alpha"),
            node("node-other"),
        ),
        (
            "session",
            "session-alpha".into(),
            session("session-alpha"),
            session("session-other"),
        ),
        (
            "lane",
            "lane-alpha".into(),
            seat("seat-alpha"),
            seat("seat-other"),
        ),
        (
            "run",
            "run-alpha".into(),
            run("run-alpha"),
            run("run-other"),
        ),
        (
            "attempt",
            "attempt-alpha".into(),
            attempt("attempt-alpha"),
            attempt("attempt-other"),
        ),
        (
            "incident",
            "incident-alpha".into(),
            run("run-alpha"),
            run("run-other"),
        ),
        // A nested approval and an artifact reach their own targets one hop further.
        (
            "approval",
            "approval-alpha".into(),
            run("run-alpha"),
            run("run-other"),
        ),
        ("artifact", artifact_id, run("run-alpha"), run("run-other")),
        (
            "capability",
            "capability.alpha".into(),
            Scope::default(),
            seat("seat-alpha"),
        ),
    ];
    {
        let mut guard = ledger.lock().unwrap();
        for (index, (kind, id, ..)) in targets.iter().enumerate() {
            guard
                .request_approval(NewApproval {
                    approval_id: format!("approval-target-{index}").parse().unwrap(),
                    issuer: "operator".to_owned(),
                    scope: ApprovalScope {
                        target_kind: (*kind).to_owned(),
                        target_id: id.clone(),
                        capability_id: "capability.alpha".parse().unwrap(),
                        arguments_digest: Digest::hash(kind.as_bytes()),
                    },
                    requested_at: decode_utc("2026-01-01T00:00:00Z").unwrap(),
                    expires_at: decode_utc("2026-01-01T00:01:00Z").unwrap(),
                })
                .unwrap();
        }
    }
    let router = test_router(ledger, root);
    for (index, (kind, _, proves, denies)) in targets.into_iter().enumerate() {
        let url = format!("approval://approval-target-{index}");
        assert!(
            router.resolve(&UriContext::new(proves), &url).is_ok(),
            "{kind} target proves its own scope"
        );
        assert!(
            matches!(
                router.resolve(&UriContext::new(denies), &url),
                Err(UriError::ScopeDenied { .. })
            ),
            "{kind} target denies a foreign scope"
        );
    }
}

#[test]
fn malformed_uris_are_refused_by_the_grammar_before_storage() {
    let long_id = format!("lane://{}", "a".repeat(129));
    let long_url = format!("lane://{}", "a".repeat(1100));
    type Expects = fn(&UriError) -> bool;
    let cases: Vec<(&str, Expects)> = vec![
        ("s3://bucket", |e| {
            matches!(e, UriError::UnknownScheme { .. })
        }),
        ("ATLAS://", |e| matches!(e, UriError::UnknownScheme { .. })),
        ("atlas:x", |e| matches!(e, UriError::Malformed { .. })),
        ("lane://lane alpha", |e| {
            matches!(e, UriError::Malformed { .. })
        }),
        ("lane://la\nne", |e| {
            matches!(e, UriError::ControlByteRejected { .. })
        }),
        ("lane://-alpha", |e| {
            matches!(e, UriError::NonCanonicalId { .. })
        }),
        ("lane://alpha$", |e| {
            matches!(e, UriError::NonCanonicalId { .. })
        }),
        (&long_id, |e| matches!(e, UriError::NonCanonicalId { .. })),
        ("lane://", |e| matches!(e, UriError::Malformed { .. })),
        ("atlas://nodes", |e| matches!(e, UriError::Malformed { .. })),
        ("run://run-alpha#frag", |e| {
            matches!(e, UriError::FragmentRejected { .. })
        }),
        ("run://run-alpha?query", |e| {
            matches!(e, UriError::Malformed { .. })
        }),
        ("lane://user@host", |e| {
            matches!(e, UriError::CredentialsRejected { .. })
        }),
        ("lane://%2E%2E%2Fsecret", |e| {
            matches!(e, UriError::EncodedBytesRejected { .. })
        }),
        ("lane://alpha/../beta", |e| {
            matches!(e, UriError::TraversalRejected { .. })
        }),
        ("lane://alpha\\..\\beta", |e| {
            matches!(e, UriError::TraversalRejected { .. })
        }),
        ("lane://alpha/beta", |e| {
            matches!(e, UriError::Malformed { .. })
        }),
        ("brain://item%41", |e| {
            matches!(e, UriError::EncodedBytesRejected { .. })
        }),
        ("brain://-bundle", |e| {
            matches!(e, UriError::Malformed { .. })
        }),
        (&long_url, |e| matches!(e, UriError::Malformed { .. })),
    ];
    for (url, expected) in cases {
        let error = ScopedUriRouter::parse(url).expect_err(url);
        assert!(expected(&error), "{url}: {error:?}");
    }

    // Canonical identifiers that simply do not exist resolve to a typed miss.
    let (root, _scratch) = artifact_root("unknown-resource");
    let router = test_router(seeded_ledger(), root);
    let global = UriContext::new(Scope::default());
    assert_eq!(
        router.resolve(&global, "lane://lane-missing").unwrap_err(),
        UriError::UnknownResource {
            url: "lane://lane-missing".to_owned(),
            kind: "lane",
            id: "lane-missing".to_owned(),
        }
    );
}
