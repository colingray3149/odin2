//! Pinned source retrieval and confined filesystem invariants.

use super::*;
use std::io::BufRead;

#[test]
fn rejects_non_confinable_paths() {
    for bad in [
        "../etc/passwd.md",
        "/absolute.md",
        "sub/../page.md",
        "spáce.md",
        "page",
        "",
        "page#fragment.md",
        "a?b.md",
        "a//b.md",
    ] {
        assert!(encode_page_path(bad).is_err(), "{bad} must be rejected");
    }
    assert_eq!(
        encode_page_path("Brain/odin probe.md").unwrap(),
        "Brain/odin%20probe.md"
    );
    assert_eq!(encode_page_path("SETTINGS.md").unwrap(), "SETTINGS.md");
}

#[test]
fn typed_unavailable_when_service_is_down() {
    // Port 1 on loopback is guaranteed closed; the failure must be the
    // typed unavailable error, not an I/O panic.
    let source = SilverBulletSource::new(AtlasId::new("vault:test").unwrap(), 1, test_scope(&[]));
    let error = source.list_pages().unwrap_err();
    match &error {
        BrainError::Unavailable { component, .. } => {
            assert_eq!(*component, "silverbullet")
        }
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

/// The fixture scope: `knowledge` general, `generated/drafts` generated,
/// `finance` and `credentials` hard-excluded.
fn test_scope(extra_general: &[&str]) -> VaultScope {
    let mut general = vec!["knowledge".to_owned()];
    general.extend(extra_general.iter().map(|name| name.to_string()));
    VaultScope::new(
        &general,
        "generated/drafts",
        &names(&["finance", "credentials"]),
    )
    .expect("fixture scope must validate")
}

fn names(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

/// One synthetic loopback SilverBullet: canned `/.fs/` listing and page
/// bodies over real HTTP, reporting every requested path over a channel.
/// Serves exactly `requests` connections, then closes — any unexpected
/// fetch fails the client loudly (typed unavailable) instead of silently
/// passing. Never touches a real private vault.
fn serve_fixture(requests: usize) -> (u16, std::sync::mpsc::Receiver<String>) {
    let pages: Vec<(&'static str, &'static str)> = vec![
        (
            "knowledge/architecture.md",
            "deterministic architecture notes\n",
        ),
        (
            "generated/drafts/probe note.md",
            "machine draft in the generated namespace\n",
        ),
        (
            "finance/ledger.md",
            "PRIVATE FINANCE - MUST NEVER BE FETCHED\n",
        ),
        (
            "credentials/tokens.md",
            "PRIVATE CREDENTIALS - MUST NEVER BE FETCHED\n",
        ),
        (
            "personal/journal.md",
            "outside every namespace - never admitted\n",
        ),
    ];
    serve_pages(pages, requests)
}

fn serve_pages(
    pages: Vec<(&'static str, &'static str)>,
    requests: usize,
) -> (u16, std::sync::mpsc::Receiver<String>) {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(requests) {
            let mut stream = stream.unwrap();
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut buffer = Vec::new();
            loop {
                let mut line = Vec::new();
                if reader.read_until(b'\n', &mut line).unwrap_or(0) == 0 {
                    break;
                }
                let head_end = line == b"\r\n" || line == b"\n";
                buffer.extend_from_slice(&line);
                if head_end {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&buffer);
            let path = text.split_whitespace().nth(1).unwrap_or("").to_owned();
            let (status, body): (&str, Vec<u8>) = if path == "/.fs/" {
                let entries: Vec<String> = pages
                    .iter()
                    .map(|(name, text)| {
                        format!(
                            "{{\"name\": {name:?}, \"size\": {}, \
                                 \"lastModified\": 0, \"perm\": \"rw\"}}",
                            text.len()
                        )
                    })
                    .collect();
                ("200 OK", format!("[{}]", entries.join(",")).into_bytes())
            } else if let Some(rest) = path.strip_prefix("/.fs/") {
                let requested = rest.replace("%20", " ");
                match pages.iter().find(|(name, _)| *name == requested) {
                    Some((_, text)) => ("200 OK", text.as_bytes().to_vec()),
                    None => ("404 Not Found", Vec::new()),
                }
            } else {
                ("404 Not Found", Vec::new())
            };
            sender.send(path).ok();
            let mut response = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes();
            response.extend_from_slice(&body);
            stream.write_all(&response).unwrap();
        }
    });
    (port, receiver)
}

#[test]
fn scoped_pin_fetches_only_admitted_pages() {
    // One listing per pin, never one per page: pin_scoped lists once and
    // GETs the two admitted pages; the explicit re-pin does the same; a
    // repeated scoped pin of the unchanged space re-serves the pinned pages
    // after its one listing. (1 + 2) × 2 + 1 = 7 connections.
    let (port, receiver) = serve_fixture(7);
    let source = SilverBulletSource::new(
        AtlasId::new("vault:fixture").unwrap(),
        port,
        test_scope(&[]),
    )
    .with_limits(MAX_RESPONSE_BYTES, 64 * 1024, Duration::from_secs(2));

    let pinned = source.pin_scoped().unwrap();
    let pinned_names: Vec<&str> = pinned
        .pages()
        .iter()
        .map(|page| page.meta.name.as_str())
        .collect();
    // Excluded (`finance/…`, `credentials/…`) and unallowlisted
    // (`personal/…`) pages are absent; the scoped generated draft and
    // the general note are present, byte-exact.
    assert_eq!(
        pinned_names,
        [
            "generated/drafts/probe note.md",
            "knowledge/architecture.md"
        ]
    );
    assert_eq!(
        pinned.pages()[0].text,
        "machine draft in the generated namespace\n",
        "generated names accepted by the writer must stay retrievable"
    );
    assert_eq!(pinned.pages()[1].text, "deterministic architecture notes\n");

    // The scoped pin is exactly a pin of the admitted set: one
    // immutable revision digest over the same rows.
    let explicit = source
        .pin_pages(&[
            "knowledge/architecture.md",
            "generated/drafts/probe note.md",
        ])
        .unwrap();
    assert_eq!(explicit.revision(), pinned.revision());
    let repinned = source.pin_scoped().unwrap();
    assert_eq!(repinned.revision(), pinned.revision());

    // Items inherit the pinned revision and observed trust — the
    // budget/provenance projection is unchanged by scoping.
    let items = pinned.items().unwrap();
    assert_eq!(items.len(), 2);
    assert!(items.iter().all(
        |item| item.trust == TrustClass::Observed && item.source_revision == pinned.revision()
    ));

    // Expect three listings and two admitted page GETs twice, with no excluded paths.
    for expected in 0..7 {
        let path = receiver
            .recv()
            .unwrap_or_else(|_| panic!("fixture closed after {expected} requests"));
        assert!(
            !path.contains("finance"),
            "excluded page was fetched: {path}"
        );
        assert!(
            !path.contains("credentials"),
            "excluded page was fetched: {path}"
        );
        assert!(
            !path.contains("personal"),
            "unallowlisted page was fetched: {path}"
        );
    }
    assert!(
        receiver.recv_timeout(Duration::from_millis(50)).is_err(),
        "fixture served an unexpected extra request"
    );
}

#[test]
fn out_of_scope_reads_are_refused_without_any_fetch() {
    // Zero connections: the listener closes immediately, so any
    // attempted fetch fails typed Unavailable — which these refusals
    // must never be.
    let (port, _receiver) = serve_fixture(0);
    let source = SilverBulletSource::new(
        AtlasId::new("vault:fixture").unwrap(),
        port,
        test_scope(&[]),
    );
    for refused in [
        "finance/ledger.md",
        "credentials/tokens.md",
        "personal/journal.md",
        "../escape.md",
        "unscoped.md",
    ] {
        let error = source
            .read_page(refused)
            .expect_err("out-of-scope reads must be refused");
        assert!(
            matches!(error, BrainError::InvalidRequest(_)),
            "{refused} must be refused by the scope gate, not by I/O: {error:?}"
        );
    }
    // pin_pages cannot smuggle an excluded page past the same gate.
    let error = source
        .pin_pages(&["finance/ledger.md"])
        .expect_err("pin_pages must enforce the scope");
    assert!(matches!(error, BrainError::InvalidRequest(_)));
    // admits() is the same decision, pure and observable.
    assert!(!source.admits("finance/ledger.md"));
    assert!(source.admits("knowledge/architecture.md"));
}

#[test]
fn vault_scope_constructor_enforces_the_namespace_law() {
    // Empty allowlist.
    assert!(VaultScope::new(&[], "generated", &[]).is_err());
    // Allowlist ∩ exclusions.
    assert!(VaultScope::new(
        &names(&["knowledge", "finance"]),
        "generated",
        &names(&["finance"])
    )
    .is_err());
    // Generated namespace under an excluded class.
    assert!(VaultScope::new(
        &names(&["knowledge"]),
        "finance/generated",
        &names(&["finance"])
    )
    .is_err());
    // Escaping generated path.
    assert!(VaultScope::new(&names(&["knowledge"]), "../generated", &[]).is_err());
    // Multi-segment general entry.
    assert!(VaultScope::new(&names(&["a/b"]), "generated", &[]).is_err());
    // Repeated entries.
    assert!(VaultScope::new(&names(&["knowledge", "knowledge"]), "generated", &[]).is_err());
    // Above the namespace list bound.
    let many: Vec<String> = (0..NAMESPACE_LIST_MAX + 1)
        .map(|index| format!("ns{index}"))
        .collect();
    assert!(VaultScope::new(&many, "generated", &[]).is_err());
    // Valid: exclusions may be empty; generated may nest in a general
    // namespace; generated admits only strictly deeper pages, while
    // the general allowlist admits by first segment at any depth.
    let scope = VaultScope::new(&names(&["knowledge"]), "knowledge/generated", &[]).unwrap();
    assert!(scope.admits("knowledge/notes.md"));
    assert!(scope.admits("knowledge/generated/draft.md"));
    assert!(scope.admits("knowledge/generated.md"));
    assert!(!scope.admits("knowledge/generated"));
    assert!(!scope.admits("other/notes.md"));
    assert!(!scope.admits("knowledge/notes.txt"));
    assert!(!scope.admits("finance/ledger.md"));
}

#[test]
fn generated_only_memory_scope_confines_reads_to_the_declared_seat() {
    let scope =
        VaultScope::generated_only("generated/memories/sinmara", &names(&["private"])).unwrap();
    assert!(scope.admits("generated/memories/sinmara/preferences.md"));
    assert!(!scope.admits("generated/memories/architect/preferences.md"));
    assert!(!scope.admits("knowledge/preferences.md"));
    assert!(!scope.admits("generated/memories/sinmara/../architect/preferences.md"));
    assert!(!scope.admits("generated/memories/sinmara/private/key.md"));
}

#[test]
fn broad_vault_scopes_exclude_the_reserved_memory_tree() {
    // The ordinary fixture-shaped scope: one general namespace and the
    // vault's generated namespace. The reserved per-seat memory tree is
    // never eligible — through the generated arm or a general arm that
    // nests the generated namespace — while the rest of the generated
    // namespace and general content stay eligible (no blanket exclusion).
    let scope = VaultScope::new(&names(&["knowledge"]), "generated", &names(&[]))
        .expect("ordinary vault scope");
    assert!(!scope.admits("generated/memories/sinmara/preferences.md"));
    assert!(!scope.admits("generated/memories/preferences.md"));
    assert!(scope.admits("generated/drafts/preferences.md"));
    assert!(scope.admits("knowledge/preferences.md"));

    // A generated namespace nested inside the general allowlist — the
    // broad-source aliasing hazard — cannot leak the reserved tree
    // through the general arm either.
    let nested = VaultScope::new(&names(&["generated"]), "generated", &names(&[]))
        .expect("nested generated namespace");
    assert!(!nested.admits("generated/memories/architect/preferences.md"));
    assert!(nested.admits("generated/drafts/preferences.md"));
}

#[test]
fn generated_only_refuses_the_unscoped_memory_tree() {
    // A generated-only scope ending at the reserved segment would cover
    // every seat's memory at once; only a seat-scoped namespace composes.
    assert!(VaultScope::generated_only("generated/memories", &names(&[])).is_err());
    assert!(VaultScope::generated_only("generated/memories/sinmara", &names(&[])).is_ok());
}

#[test]
fn generated_knowledge_pages_are_refused_by_every_read_scope() {
    // The reserved generated-knowledge tree is the brain's own projection
    // output: refused through the generated arm of an ordinary scope while
    // sibling generated content stays eligible (no blanket exclusion).
    let scope = VaultScope::new(&names(&["knowledge"]), "generated", &names(&[]))
        .expect("ordinary vault scope");
    assert!(!scope.admits("generated/knowledge/state.repos/index.md"));
    assert!(!scope.admits("generated/knowledge/state.repos/items/abc.md"));
    assert!(scope.admits("generated/drafts/preferences.md"));

    // A generated namespace nested inside the general allowlist cannot leak
    // the reserved tree through the general arm either.
    let nested = VaultScope::new(&names(&["generated"]), "generated", &names(&[]))
        .expect("nested generated namespace");
    assert!(!nested.admits("generated/knowledge/state.registry/index.md"));
    assert!(nested.admits("generated/drafts/preferences.md"));

    // A seat memory scope never sees the knowledge root, and cannot ingest
    // a knowledge directory parked inside its own subtree.
    let memory = VaultScope::generated_only("generated/memories/sinmara", &names(&[]))
        .expect("seat memory scope");
    assert!(memory.admits("generated/memories/sinmara/preferences.md"));
    assert!(!memory.admits("generated/knowledge/state.repos/index.md"));
    assert!(!memory.admits("generated/memories/sinmara/knowledge/index.md"));

    // The write grammar stays permissive: the daemon's generated-write gate
    // is the only writer, and it can address the reserved pages.
    assert!(addressable_page_name(
        "generated/knowledge/state.repos/index.md"
    ));
}

#[test]
fn apl_restricted_note_is_refused_from_every_model_path_with_a_plain_sentence() {
    // One pin: one listing + three page GETs.
    let (port, _receiver) = serve_pages(
        vec![
            (
                "knowledge/apl review.md",
                "---\nprivacy: APL_RESTRICTED\n---\nRADAR WAVEFORM PARAMETERS\n",
            ),
            ("knowledge/secret plans.md", "launch codes #secret\n"),
            ("knowledge/groceries.md", "milk and eggs #errands\n"),
        ],
        4,
    );
    let source = SilverBulletSource::new(
        AtlasId::new("vault:fixture").unwrap(),
        port,
        test_scope(&[]),
    )
    .with_limits(MAX_RESPONSE_BYTES, 64 * 1024, Duration::from_secs(2));
    let pinned = source.pin_scoped().unwrap();
    let pages = pinned.pages();
    assert_eq!(pages.len(), 3);
    let apl = &pages[0];
    assert_eq!(apl.meta.name, "knowledge/apl review.md");
    let refusal = apl.withheld.as_ref().expect("typed refusal");
    assert_eq!(
        refusal.class,
        odin_domain::knowledge::PrivacyClass::AplRestricted
    );
    assert!(!apl.text.contains("RADAR"), "restricted bytes never served");
    assert!(apl
        .text
        .contains("\"knowledge/apl review.md\" is marked APL_RESTRICTED"));
    assert_eq!(apl.digest, Digest::hash(apl.text.as_bytes()));
    assert!(!pages[2].text.contains("launch codes"));
    assert!(pages[2].withheld.is_some());
    // Everything else is unaffected, byte-exact.
    assert_eq!(pages[1].text, "milk and eggs #errands\n");
    assert!(pages[1].withheld.is_none());
    // The indexed items carry the refusal, never the content.
    let items = pinned.items().unwrap();
    assert!(items
        .iter()
        .all(|item| !item.text.contains("RADAR") && !item.text.contains("launch codes")));
}

/// Listings include unadmitted pages and need a separate cap from page bodies.
#[test]
fn listing_larger_than_the_page_response_cap_still_pins() {
    let filler: Vec<(&'static str, &'static str)> = (0..64)
        .map(|index| {
            let name: &'static str = Box::leak(
                format!("generated/knowledge/state.repos/seat/file-{index:03}.md").into_boxed_str(),
            );
            (name, "unadmitted projection\n")
        })
        .chain([("knowledge/architecture.md", "deterministic notes\n")])
        .collect();
    let (port, _receiver) = serve_pages(filler.clone(), 2);
    let source = SilverBulletSource::new(
        AtlasId::new("vault:fixture").unwrap(),
        port,
        test_scope(&[]),
    )
    .with_limits(1_024, 1_024, Duration::from_secs(2));
    let pinned = source.pin_scoped().unwrap();
    let names: Vec<&str> = pinned
        .pages()
        .iter()
        .map(|page| page.meta.name.as_str())
        .collect();
    assert_eq!(names, ["knowledge/architecture.md"]);

    // The listing cap itself still bounds the listing, typed.
    let (port, _receiver) = serve_pages(filler, 1);
    let capped = SilverBulletSource::new(
        AtlasId::new("vault:fixture").unwrap(),
        port,
        test_scope(&[]),
    )
    .with_limits(1_024, 1_024, Duration::from_secs(2))
    .with_listing_cap(1_024);
    assert!(matches!(
        capped.pin_scoped(),
        Err(BrainError::Unavailable {
            component: "silverbullet",
            ..
        })
    ));
}
