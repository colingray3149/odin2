//! Canonical parse, dispatch, and cross-scope refusal invariants.

use super::*;

#[test]
fn every_registered_scheme_resolves_deterministically() {
    assert_eq!(
        scheme_definitions()
            .iter()
            .map(|definition| definition.scheme)
            .collect::<Vec<_>>(),
        UriScheme::ALL.to_vec()
    );
    let ledger = seeded_ledger();
    let root = artifact_root("all-schemes");
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
    assert!(lane.immutable);

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
fn write_requests_never_reach_resolvers() {
    let router = test_router(seeded_ledger(), artifact_root("write-rejected"));
    let scoped = UriContext::new(Scope {
        seat: Some("seat-alpha".parse().unwrap()),
        ..Scope::default()
    });
    let mut request = ScopedUriRouter::parse("lane://lane-alpha").unwrap();
    request.operation = UriOperation::Write;
    assert_eq!(
        router.resolve_request(&scoped, request).unwrap_err(),
        UriError::WriteRejected {
            url: "lane://lane-alpha".to_owned()
        }
    );
}

#[test]
fn cross_scope_reads_fail_closed() {
    let ledger = seeded_ledger();
    let root = artifact_root("cross-scope");
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

#[test]
fn malformed_uris_never_reach_storage() {
    let cases = vec![
        (
            "s3://bucket",
            UriError::UnknownScheme {
                url: "s3://bucket".to_owned(),
                scheme: "s3".to_owned(),
            },
        ),
        (
            "ATLAS://",
            UriError::UnknownScheme {
                url: "ATLAS://".to_owned(),
                scheme: "ATLAS".to_owned(),
            },
        ),
        (
            "atlas:x",
            UriError::Malformed {
                url: "atlas:x".to_owned(),
                reason: "URI lacks the :// authority separator".to_owned(),
            },
        ),
        (
            "lane://lane alpha",
            UriError::Malformed {
                url: "lane://lane alpha".to_owned(),
                reason: "URI contains whitespace".to_owned(),
            },
        ),
        (
            "lane://la\nne",
            UriError::ControlByteRejected {
                url: "lane://la\nne".to_owned(),
            },
        ),
        (
            "lane://-alpha",
            UriError::NonCanonicalId {
                url: "lane://-alpha".to_owned(),
                value: "-alpha".to_owned(),
                reason: "must start with an ASCII alphanumeric character".to_owned(),
            },
        ),
        (
            "lane://",
            UriError::Malformed {
                url: "lane://".to_owned(),
                reason: "canonical URI requires exactly one identifier".to_owned(),
            },
        ),
        (
            "atlas://nodes",
            UriError::Malformed {
                url: "atlas://nodes".to_owned(),
                reason: "atlas URIs address the whole allowed scope and carry no identifier"
                    .to_owned(),
            },
        ),
        (
            "run://run-alpha#frag",
            UriError::FragmentRejected {
                url: "run://run-alpha#frag".to_owned(),
            },
        ),
        (
            "run://run-alpha?query",
            UriError::Malformed {
                url: "run://run-alpha?query".to_owned(),
                reason: "canonical URIs carry no query component".to_owned(),
            },
        ),
        (
            "lane://user@host",
            UriError::CredentialsRejected {
                url: "lane://user@host".to_owned(),
            },
        ),
        (
            "lane://%2E%2E%2Fsecret",
            UriError::EncodedBytesRejected {
                url: "lane://%2E%2E%2Fsecret".to_owned(),
            },
        ),
        (
            "lane://../secret",
            UriError::TraversalRejected {
                url: "lane://../secret".to_owned(),
            },
        ),
        (
            "lane://alpha/../beta",
            UriError::TraversalRejected {
                url: "lane://alpha/../beta".to_owned(),
            },
        ),
        (
            "lane://alpha\\..\\beta",
            UriError::TraversalRejected {
                url: "lane://alpha\\..\\beta".to_owned(),
            },
        ),
        (
            "lane://alpha/beta",
            UriError::Malformed {
                url: "lane://alpha/beta".to_owned(),
                reason: "canonical URIs address a single identifier".to_owned(),
            },
        ),
    ];
    for (url, expected) in cases {
        assert_eq!(ScopedUriRouter::parse(url), Err(expected));
    }
    let long_url = format!("lane://{}", "a".repeat(1100));
    assert!(matches!(
        ScopedUriRouter::parse(&long_url),
        Err(UriError::Malformed { .. })
    ));

    // Canonical identifiers that simply do not exist resolve to a typed miss.
    let router = test_router(seeded_ledger(), artifact_root("unknown-resource"));
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

#[test]
fn poisoned_ledger_surfaces_as_storage_error() {
    let ledger = seeded_ledger();
    let router = test_router(ledger.clone(), artifact_root("poisoned"));
    let global = UriContext::new(Scope::default());
    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = ledger.lock().unwrap();
        panic!("deliberate mutex poisoning");
    }));
    assert!(poisoned.is_err());
    assert!(matches!(
        router.resolve(&global, "lane://lane-alpha"),
        Err(UriError::Storage { .. })
    ));
}
