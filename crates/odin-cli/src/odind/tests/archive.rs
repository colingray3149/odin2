use super::*;

#[test]
fn the_declaration_decides_a_standing_archive_demand() {
    let mut ledger = Ledger::open_in_memory().expect("ledger opens");
    let plan = ArchiveIngestPlan {
        source: AtlasId::new("class-archive").expect("atlas id"),
        declaration_digest: Digest::hash(b"declaration"),
        content_revision: Digest::hash(b"content"),
        messages_parsed: 0,
        records: 0,
        bytes: 0,
        skip_reasons: BTreeMap::new(),
    };
    let source = AtlasId::new("class-archive").expect("atlas id");
    let binding = ArchiveBinding::derive(&source, &plan).expect("binding derives");
    let issuer = "device:0123456789abcdef";
    let now = OffsetDateTime::now_utc();

    let Disposition::Approved(decided) =
        standing_demand(&mut ledger, &binding, issuer, now).expect("the demand disposes")
    else {
        panic!(
            "a standing archive demand must be decided by the declaration, not await the operator"
        );
    };
    assert_eq!(
        decided.decided_by.as_deref(),
        Some("declaration:device:0123456789abcdef")
    );
    assert_eq!(decided.status, ApprovalStatus::Approved);
    assert_eq!(decided.scope, binding.scope);
    assert_eq!(
        decided.decision_evidence_ref.as_deref(),
        decided.decided_by.as_deref()
    );

    // Repeated requests reuse the standing decision.
    assert!(matches!(
        standing_demand(&mut ledger, &binding, issuer, now).expect("the demand disposes"),
        Disposition::Approved(_)
    ));
}
