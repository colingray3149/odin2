//! Pinned source retrieval and confined filesystem invariants.

use super::fake::serve;
use super::*;

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

/// The vault the scope tests read: general notes, a generated draft, and
/// private pages that must never be fetched. Serves exactly `requests`
/// connections.
fn serve_fixture(requests: usize) -> (u16, std::sync::mpsc::Receiver<String>) {
    serve(
        vec![
            (
                "knowledge/architecture.md",
                "deterministic architecture notes\n",
                0,
            ),
            (
                "generated/drafts/probe note.md",
                "machine draft in the generated namespace\n",
                0,
            ),
            (
                "finance/ledger.md",
                "PRIVATE FINANCE - MUST NEVER BE FETCHED\n",
                0,
            ),
            (
                "credentials/tokens.md",
                "PRIVATE CREDENTIALS - MUST NEVER BE FETCHED\n",
                0,
            ),
            (
                "personal/journal.md",
                "outside every namespace - never admitted\n",
                0,
            ),
        ],
        requests,
    )
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

    // Three listings and two admitted page GETs twice, no excluded path.
    let paths: Vec<String> = (0..7)
        .map(|expected| {
            receiver
                .recv_timeout(Duration::from_secs(5))
                .unwrap_or_else(|_| panic!("fixture closed after {expected} requests"))
        })
        .collect();
    for path in &paths {
        for private in ["finance", "credentials", "personal"] {
            assert!(
                !path.contains(private),
                "{private} page was fetched: {path}"
            );
        }
    }
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
            .pin_pages(&[refused])
            .expect_err("out-of-scope reads must be refused");
        assert!(
            matches!(error, BrainError::InvalidRequest(_)),
            "{refused} must be refused by the scope gate, not by I/O: {error:?}"
        );
    }
    // admits() is the same decision, pure and observable.
    assert!(!source.admits("finance/ledger.md"));
    assert!(source.admits("knowledge/architecture.md"));
}

#[test]
fn generated_only_memory_scope_confines_reads_to_the_declared_seat() {
    let scope = VaultScope::generated_only("memory/sinmara", &names(&["private"])).unwrap();
    assert!(scope.admits("memory/sinmara/preferences.md"));
    assert!(!scope.admits("memory/architect/preferences.md"));
    assert!(!scope.admits("knowledge/preferences.md"));
    assert!(!scope.admits("memory/sinmara/../architect/preferences.md"));
    assert!(!scope.admits("memory/sinmara/private/key.md"));
}

#[test]
fn generated_only_refuses_the_unscoped_memory_tree() {
    // A generated-only scope ending at the reserved segment would cover
    // every seat's memory at once; only a seat-scoped namespace composes.
    assert!(VaultScope::generated_only("memory", &names(&[])).is_err());
    assert!(VaultScope::generated_only("memory/sinmara", &names(&[])).is_ok());
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
    let memory =
        VaultScope::generated_only("memory/sinmara", &names(&[])).expect("seat memory scope");
    assert!(memory.admits("memory/sinmara/preferences.md"));
    assert!(!memory.admits("generated/knowledge/state.repos/index.md"));
    assert!(!memory.admits("memory/sinmara/knowledge/index.md"));

    // The write grammar stays permissive: the daemon's generated-write gate
    // is the only writer, and it can address the reserved pages.
    assert!(addressable_page_name(
        "generated/knowledge/state.repos/index.md"
    ));
}

#[test]
fn apl_restricted_note_is_refused_from_every_model_path_with_a_plain_sentence() {
    // One pin: one listing + three page GETs.
    let (port, _receiver) = serve(
        vec![
            (
                "knowledge/apl review.md",
                "---\nprivacy: APL_RESTRICTED\n---\nRADAR WAVEFORM PARAMETERS\n",
                0,
            ),
            ("knowledge/secret plans.md", "launch codes #secret\n", 0),
            ("knowledge/groceries.md", "milk and eggs #errands\n", 0),
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
