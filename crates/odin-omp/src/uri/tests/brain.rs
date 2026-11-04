//! Brain authority invariants: per-seat policies, typed unavailability, pinned snapshots.

use super::*;

fn brain_context(ledger: &Arc<Mutex<Ledger>>, seat: &str, project: &str) -> UriContext {
    let session = format!("brain-{seat}-{project}");
    let lane = format!("lane-{session}");
    let run = format!("run-{session}");
    let now = time::OffsetDateTime::UNIX_EPOCH;
    let mut ledger = ledger.lock().unwrap();
    lane_run::create_lane(
        ledger.connection(),
        &NewLane {
            lane_id: lane.parse().unwrap(),
            seat_id: seat.parse().unwrap(),
            project_id: Some(project.parse().unwrap()),
            template_id: "fixture".into(),
            backend: "local_omp".into(),
            created_by: "fixture".into(),
            created_at: now,
            retained: false,
        },
    )
    .unwrap();
    lane_run::create_run(
        ledger.connection(),
        &NewRun {
            run_id: run.parse().unwrap(),
            lane_id: lane.parse().unwrap(),
            attempt_number: 1,
            workflow_id: None,
            workflow_version: None,
            input_hash: "fixture".into(),
            accepted_capability_revision: None,
            lease_id: None,
            absolute_deadline: None,
            retry_budget: 0,
            created_at: now,
        },
    )
    .unwrap();
    let record = ledger
        .create_live_session(&odin_ledger::live::NewLiveSession {
            session_id: session.parse().unwrap(),
            seat_id: seat.into(),
            project_id: project.into(),
            slice_id: "slice-fixture".into(),
            lane_id: lane.clone(),
            target_node_id: "node-fixture".into(),
            provider: "fixture".into(),
            model: "fixture".into(),
            title: None,
            manifest: json!({}),
            open_tab: false,
            state: "ready".into(),
            created_at: now,
        })
        .unwrap();
    let scope = Scope {
        seat: Some(seat.parse().unwrap()),
        project: Some(project.parse().unwrap()),
        session: Some(session.parse().unwrap()),
        lane: Some(lane.parse().unwrap()),
        run: Some(run.parse().unwrap()),
        ..Scope::default()
    };
    let mut binding = crate::bridge::BridgeBinding::new(
        scope.clone(),
        session.parse().unwrap(),
        run.parse().unwrap(),
        lane.parse().unwrap(),
        "fixture",
    );
    binding.epoch = record.epoch;
    UriContext::with_execution(scope, ExecutionBinding::from_binding(&binding))
}

#[test]
fn brain_resolves_through_injected_service() {
    let ledger = seeded_ledger();
    let seated = brain_context(&ledger, "seat-alpha", "project-alpha");
    let (root, _scratch) = artifact_root("brain-resolution");
    let router = test_router_with_brain(ledger, root);
    let service = &router.brains[&SeatId::new("seat-alpha").unwrap()];
    // brain:// selects the service by the authenticated session scope's
    // seat, so the context carries the served seat explicitly.
    // The bare URI pins the live brain authority snapshot.
    let snapshot = router.resolve(&seated, "brain://").unwrap();
    assert_eq!(snapshot.content_type, JSON_CONTENT_TYPE);
    let value = spot_json(&snapshot);
    assert_eq!(value["authority"], "brain");
    assert_eq!(
        value["policyDigest"],
        service.policy().policy_digest.to_string()
    );
    assert_eq!(
        value["registryRevision"],
        service.policy().registry_revision
    );
    let status = service.status().unwrap();
    let (_, revision) = status
        .pinned
        .iter()
        .find(|(source, _)| source.as_str() == "atlas:uri-test")
        .expect("the composed source is pinned");
    assert_eq!(value["pinned"]["atlas:uri-test"], revision.to_string());
    // A non-canonical identifier is rejected by the grammar before any
    // resolver or storage runs.
    let miss = router
        .resolve(&seated, "brain://context-bundle-alpha")
        .unwrap_err();
    assert!(
        matches!(miss, UriError::Malformed { .. }),
        "non-canonical brain ids must fail grammar validation: {miss:?}"
    );
    // With empty stores a canonical, well-formed identifier is a typed miss:
    // no current generation serves it, and stale data is never substituted.
    let miss = router
        .resolve(
            &seated,
            "brain://blake3:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap_err();
    assert!(
        matches!(miss, UriError::UnknownResource { .. }),
        "a well-formed absent item must be a typed miss: {miss:?}"
    );
}

/// Seat policies isolate wired sources; lexical retrieval needs no embeddings backend.
#[test]
fn brain_serves_each_seat_its_own_policy_and_sources_only() {
    let ledger = seeded_ledger();
    let (root, _scratch) = artifact_root("brain-per-seat");
    let personal_id = AtlasId::new("atlas:personal").unwrap();
    let code_id = AtlasId::new("atlas:code").unwrap();
    // The slice is the delegation ceiling and each seat narrows it with its own scope. The
    // personal/code delegates are disjoint, so the two published policies must differ; a scope
    // naming ids the slice never delegates would collapse to the empty set, not widen.
    let policy_for = |id: &AtlasId| {
        let (slice, seat) = delegating(&BTreeSet::from([id.clone()]));
        resolve_policy(&slice, &seat, &BTreeMap::new())
    };
    let (sinmara_policy, architect_policy) = (policy_for(&personal_id), policy_for(&code_id));
    assert_ne!(
        sinmara_policy.policy_digest, architect_policy.policy_digest,
        "distinct seat scopes must yield distinct published policies"
    );
    let service_for = |name: &str, id: AtlasId, policy| {
        let source = BrainSourceConfig::Atlas {
            root: atlas_source_tree(&root, name, "demo"),
        };
        brain_service(
            &ledger,
            root.join(format!("brain-store-{name}")),
            BTreeMap::from([(id, source)]),
            policy,
            None,
        )
    };
    let personal_service = service_for("personal", personal_id, sinmara_policy);
    let code_service = service_for("code", code_id, architect_policy);
    let router = router_with_brains(
        Arc::clone(&ledger),
        root,
        BTreeMap::from([
            (SeatId::new("sinmara").unwrap(), personal_service),
            (SeatId::new("architect").unwrap(), code_service),
        ]),
    );
    let pinned = |seat: &str| {
        let snapshot = router
            .resolve(&brain_context(&ledger, seat, "project-alpha"), "brain://")
            .expect("seat-served brain authority snapshot");
        let value = spot_json(&snapshot);
        value["pinned"].as_object().expect("pinned map").clone()
    };
    // Sinmara pins exactly its authorized-and-wired source; the
    // disjoint delegation keeps research absent — never widened,
    // never a phantom root.
    let sinmara_pinned = pinned("sinmara");
    assert!(sinmara_pinned.contains_key("atlas:personal"));
    assert!(!sinmara_pinned.contains_key("atlas:research"));
    // Cross-seat isolation: architect never sees sinmara's source.
    let architect_pinned = pinned("architect");
    assert!(architect_pinned.contains_key("atlas:code"));
    assert!(!architect_pinned.contains_key("atlas:personal"));
    // A seat that serves no brain fails typed while the served seats keep resolving; a
    // context with no execution proof is refused before any seat is chosen.
    let error = router
        .resolve(
            &brain_context(&ledger, "kubert", "project-alpha"),
            "brain://",
        )
        .unwrap_err();
    assert!(
        matches!(error, UriError::ConfigurationRejected { .. }),
        "unserved seat brain:// must be typed-unavailable: {error:?}"
    );
    let error = router
        .resolve(&UriContext::new(Scope::default()), "brain://")
        .unwrap_err();
    assert!(
        matches!(error, UriError::ExecutionProof { .. }),
        "{error:?}"
    );
}

/// Project intersection on the URI leg of D2: one seat, two declared
/// projects with disjoint private namespaces, and one seat-general
/// source no project declares. The same indexed item resolves through
/// `brain://` only under a scope bound to the declaring project — the
/// other project's scope gets the typed miss, exactly as if the item did
/// not exist — while the general item resolves under every project scope.
/// A projectless scope carries no execution proof and is refused for that.
/// No default project exists anywhere on this path.
#[test]
fn brain_item_resolution_stays_inside_the_bound_projects_memory() {
    let ledger = seeded_ledger();
    let (root, _scratch) = artifact_root("brain-project-scope");
    let alpha_root = atlas_source_tree(&root, "alpha", "alpha_scope_fn");
    let beta_root = atlas_source_tree(&root, "beta", "beta_scope_fn");
    let general_root = atlas_source_tree(&root, "general", "general_scope_fn");
    let (alpha_id, beta_id, general_id) = (
        AtlasId::new("atlas:scope-alpha").unwrap(),
        AtlasId::new("atlas:scope-beta").unwrap(),
        AtlasId::new("atlas:scope-general").unwrap(),
    );
    let sources = atlas_ids(&[alpha_id.as_str(), beta_id.as_str(), general_id.as_str()]);
    let (slice, mut seat) = delegating(&sources);
    seat.project_scope = BTreeSet::from([
        odin_domain::ProjectId::new("alpha").unwrap(),
        odin_domain::ProjectId::new("beta").unwrap(),
    ]);
    let (alpha, beta) = (memory_project(&[&alpha_id]), memory_project(&[&beta_id]));
    let policy = resolve_policy(
        &slice,
        &seat,
        &BTreeMap::from([("alpha", &alpha), ("beta", &beta)]),
    );
    assert_eq!(
        policy.seat_global_sources,
        atlas_ids(&[general_id.as_str()]),
        "only the undeclared source stays seat-general"
    );
    let service = brain_service(
        &ledger,
        root.join("brain-store"),
        BTreeMap::from([
            (
                alpha_id.clone(),
                BrainSourceConfig::Atlas { root: alpha_root },
            ),
            (
                beta_id.clone(),
                BrainSourceConfig::Atlas { root: beta_root },
            ),
            (
                general_id.clone(),
                BrainSourceConfig::Atlas { root: general_root },
            ),
        ]),
        policy,
        None,
    );
    service.ensure_generation().unwrap();
    let router = router_with_brains(
        Arc::clone(&ledger),
        root,
        BTreeMap::from([(SeatId::new("sinmara").unwrap(), Arc::clone(&service))]),
    );
    let item_id_of = |marker: &str, project: Option<&odin_domain::ProjectId>| {
        service
            .retrieve(&lexical_query(marker, &sources), project, None)
            .unwrap()
            .hits
            .into_iter()
            .find(|hit| hit.content.contains(marker))
            .map(|hit| hit.item_id)
            .unwrap_or_else(|| panic!("the {marker} fixture must index and retrieve"))
    };
    let alpha_item = item_id_of(
        "alpha_scope_fn",
        Some(&odin_domain::ProjectId::new("alpha").unwrap()),
    );
    let beta_item = item_id_of(
        "beta_scope_fn",
        Some(&odin_domain::ProjectId::new("beta").unwrap()),
    );
    let general_item = item_id_of("general_scope_fn", None);
    let scope_of = |project: &str| brain_context(&ledger, "sinmara", project);
    let resolves = |context: &UriContext, item: &odin_domain::knowledge::KnowledgeItemId| {
        router
            .resolve(context, &format!("brain://{item}"))
            .map(|snapshot| spot_json(&snapshot).clone())
    };
    let alpha_scope = scope_of("alpha");
    let beta_scope = scope_of("beta");
    let projectless = UriContext::new(Scope {
        seat: Some("sinmara".parse().unwrap()),
        ..Scope::default()
    });
    assert!(
        resolves(&alpha_scope, &alpha_item).is_ok() && resolves(&beta_scope, &beta_item).is_ok(),
        "each project resolves its own declared memory"
    );
    let error = resolves(&beta_scope, &alpha_item).unwrap_err();
    assert!(
        matches!(error, UriError::UnknownResource { .. }),
        "alpha's item must be a typed miss under beta scope: {error:?}"
    );
    let error = resolves(&alpha_scope, &beta_item).unwrap_err();
    assert!(
        matches!(error, UriError::UnknownResource { .. }),
        "beta's item must be a typed miss under alpha scope: {error:?}"
    );
    for (context, label) in [(&alpha_scope, "alpha"), (&beta_scope, "beta")] {
        assert!(
            resolves(context, &general_item).is_ok(),
            "seat-general knowledge serves every session of the seat ({label})"
        );
    }
    assert!(matches!(
        resolves(&projectless, &general_item),
        Err(UriError::ExecutionProof { .. })
    ));
}

/// A brain URI read is BOUNDED and PAGEABLE end to end: one indexed item
/// larger than the default page is read across pages whose concatenation is
/// exactly the item's bytes — dense multi-byte scalars included — with
/// explicit continuation selectors, and every non-canonical window is refused
/// rather than clamped or silently shortened.
#[test]
fn brain_item_reads_are_paged_and_exact() {
    let unit = "漢字🙂é";
    // One archive message far past the default page; the marker scalar
    // sequence makes any lost or duplicated byte between pages visible.
    let message = format!("{}{}", unit.repeat(6_000), "PAGE-TAIL-MARKER");
    let (root, _scratch) = artifact_root("brain-pages");
    // Metadata only — the export ships no asset bytes, so the locator must name the
    // declaration site and position while claiming no member.
    let export_dir = write_claude_export(
        &root,
        "pages",
        &message,
        json!([{
            "file_name": "pages-origin.md",
            "file_size": "7",
            "file_type": "text/markdown"
        }]),
    );
    let ledger = seeded_ledger();
    let ArchiveFixture { service, sources } = ingest_archive(
        &ledger,
        &root,
        "pages",
        ArchiveFormat::ClaudeExport,
        export_dir.clone(),
        None,
        None,
    );
    let hits = service
        .retrieve(&lexical_query("PAGE-TAIL-MARKER", &sources), None, None)
        .unwrap()
        .hits;
    // The MESSAGE record, not the derived conversation summary the parser
    // also emits for the same fixture.
    let item_id = hits
        .iter()
        .find(|hit| {
            service
                .archive_citation(
                    &hit.citation.source,
                    &hit.citation.source_revision,
                    &hit.citation.item_id,
                )
                .unwrap()
                .is_some_and(|citation| citation.message_id.as_deref() == Some("msg-pages"))
        })
        .map(|hit| hit.item_id)
        .expect("the archived pageable message must serve");
    let router = router_with_brains(
        Arc::clone(&ledger),
        root,
        BTreeMap::from([(SeatId::new("seat-alpha").unwrap(), Arc::clone(&service))]),
    );
    let authorized = brain_context(&ledger, "seat-alpha", "project-alpha");
    let proof_scope = authorized.scope.clone();
    let page = router
        .resolve(&authorized, &format!("brain://{item_id}"))
        .unwrap();
    let value = spot_json(&page);
    assert_eq!(value["itemId"], item_id.to_string());
    assert_eq!(
        value["page"]["byteStart"], 0,
        "the authenticated execution proof must not change which page is served"
    );
    // The consumer seam — the served wire payload itself, not just the
    // service struct: the message window carries the declared export
    // root and stays origin-less (its record has no asset identity).
    assert_eq!(
        value["archive"]["exportRoot"].as_str(),
        export_dir.to_str(),
        "exportRoot is the persisted declaration's exact path"
    );
    assert!(value["archive"]["origin"].is_null());
    assert!(
        value["archive"]["naturalKey"].is_string(),
        "the payload names its record's natural key"
    );

    // The attachment's own record page carries the locator on the wire:
    // declaration site + position, member=null (bytes not exported),
    // against the same root — resolved through the real record selector.
    let asset_hits = service
        .retrieve(
            &lexical_query("pages-origin markdown", &sources),
            None,
            None,
        )
        .unwrap()
        .hits;
    let asset_item_id = asset_hits
        .iter()
        .find_map(|hit| {
            let citation = service
                .archive_citation(
                    &hit.citation.source,
                    &hit.citation.source_revision,
                    &hit.citation.item_id,
                )
                .unwrap()?;
            (citation.kind == odin_brain::source::archive::ArchiveRecordKind::AssetMetadata)
                .then_some(hit.item_id)
        })
        .expect("the attachment metadata record must serve");
    let record_page = router
        .resolve(&authorized, &format!("brain://{asset_item_id}"))
        .unwrap();
    let record_value = spot_json(&record_page);
    let origin = &record_value["archive"]["origin"];
    assert_eq!(origin["declaredIn"].as_str(), Some("conversations.json"));
    assert!(
        origin["member"].is_null(),
        "the bytes are not exported: no member is ever claimed"
    );
    assert_eq!(origin["position"], 1);
    assert_eq!(
        record_value["archive"]["exportRoot"].as_str(),
        export_dir.to_str()
    );
    // A node-bound session cannot read an item that proves no node identity.
    let node_bound = UriContext::with_execution(
        Scope {
            node: Some("node-alpha".parse().unwrap()),
            ..proof_scope
        },
        authorized.execution.clone().unwrap(),
    );
    let refused = router
        .resolve(&node_bound, &format!("brain://{item_id}"))
        .unwrap_err();
    assert!(
        matches!(refused, UriError::ScopeDenied { .. }),
        "{refused:?}"
    );

    let first_page = router
        .resolve(&authorized, &format!("brain://{item_id}"))
        .unwrap();
    let first = spot_json(&first_page);
    assert_eq!(first["kind"], "knowledge item window");
    assert_eq!(first["itemId"], item_id.to_string());
    assert_eq!(first["page"]["byteStart"], 0);
    let total = first["page"]["totalBytes"].as_u64().unwrap();
    assert!(
        total > 16 * 1024,
        "the indexed item must really be larger than one default page, got {total} bytes"
    );
    let mut assembled = String::new();
    // Page one is the bare item URI; every later page is the continuation
    // the previous one named.
    let mut next = Some(format!("brain://{item_id}"));
    let mut cursor = 0_u64;
    while cursor < total {
        let url = next
            .clone()
            .expect("every unfinished page names its continuation");
        let page = router.resolve(&authorized, &url).unwrap();
        let value = spot_json(&page);
        assert_eq!(
            value["page"]["byteStart"].as_u64().unwrap(),
            cursor,
            "a page starts exactly where the previous one ended"
        );
        let end = value["page"]["byteEnd"].as_u64().unwrap();
        assert!(end > cursor && end <= total);
        let text = value["page"]["text"].as_str().unwrap().to_owned();
        assembled.push_str(&text);
        assert_eq!(
            assembled.len() as u64,
            end,
            "pages concatenate exactly once, with no duplicated overlap"
        );
        cursor = end;
        next = value["page"]["continuation"].as_str().map(str::to_owned);
    }
    assert!(next.is_none(), "the last page ends the item");
    assert_eq!(
        assembled.len() as u64,
        total,
        "pages cover the item exactly"
    );
    assert!(
        assembled.ends_with("PAGE-TAIL-MARKER"),
        "the item's own tail is reachable through pages"
    );
    assert_eq!(
        assembled.matches(unit).count(),
        6_000,
        "no multi-byte scalar is lost or duplicated across page boundaries"
    );

    // Refusals: an edge inside a scalar, a past-end window, an oversized
    // window, and a malformed selector are all typed, never clamped.
    let inside_scalar = assembled.find(unit).unwrap() as u64 + 1;
    for url in [
        format!(
            "brain://{item_id}/bytes/{inside_scalar}/{}",
            inside_scalar + 3
        ),
        format!("brain://{item_id}/bytes/0/{}", total + 1),
        format!("brain://{item_id}/bytes/0/{}", 64 * 1024 + 1),
        format!("brain://{item_id}/bytes/0/notanumber"),
    ] {
        let error = router.resolve(&authorized, &url).unwrap_err();
        assert!(
            matches!(error, UriError::Malformed { .. }),
            "{url}: {error:?}"
        );
    }

    // Bare snapshots require active sessions just like item reads.
    let execution = authorized.execution.clone().unwrap();
    ledger
        .lock()
        .unwrap()
        .finish_live_session(
            execution.session_id(),
            execution.epoch(),
            odin_ledger::live::LiveSessionExit::Ended,
            time::OffsetDateTime::UNIX_EPOCH,
        )
        .unwrap();
    assert!(matches!(
        router
            .resolve(&authorized, &format!("brain://{item_id}"))
            .unwrap_err(),
        UriError::ExecutionProof { .. }
    ));
    assert!(matches!(
        router.resolve(&authorized, "brain://"),
        Err(UriError::ExecutionProof { .. })
    ));
}
