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

#[test]
fn a_consumed_archive_demand_replays_and_resumes_for_a_re_paired_device() {
    let mut ledger = Ledger::open_in_memory().expect("ledger opens");
    let source = AtlasId::new("class-archive").expect("atlas id");
    let plan = ArchiveIngestPlan {
        source: source.clone(),
        declaration_digest: Digest::hash(b"declaration"),
        content_revision: Digest::hash(b"content"),
        messages_parsed: 0,
        records: 0,
        bytes: 0,
        skip_reasons: BTreeMap::new(),
    };
    let binding = ArchiveBinding::derive(&source, &plan).expect("binding derives");
    let (old, new) = ("device:0123456789abcdef", "device:fedcba9876543210");
    let now = OffsetDateTime::now_utc();

    let Disposition::Approved(approval) =
        standing_demand(&mut ledger, &binding, old, now).expect("the demand disposes")
    else {
        panic!("the declaration approves the demand");
    };
    // A demand that can still authorize work stays bound to the device that issued it.
    assert!(standing_demand(&mut ledger, &binding, new, now).is_err());

    let spec = binding.command_spec(old, now, 1);
    let recorded = ledger
        .record_command(&spec)
        .expect("the command journals")
        .into_recorded();
    let accepted = ledger
        .accept_command(&recorded, recorded.command().revision, now)
        .expect("the command is accepted");
    ApprovalGate::new(&mut ledger)
        .authorize_command(
            odin_domain::EffectClass::R3,
            ApprovalCommand {
                command_id: &binding.command_id,
                approval_id: Some(&binding.approval_id),
                scope: &binding.scope,
                expected_revision: Some(approval.revision),
                now,
            },
        )
        .expect("the approval is consumed");
    // Consumed, even unsettled (a crashed run to resume), is exactly bound: any paired device takes it.
    assert!(matches!(
        standing_demand(&mut ledger, &binding, new, now).expect("a consumed demand resumes"),
        Disposition::Consumed(_)
    ));

    let revision = accepted.command().revision;
    ledger
        .complete_command(
            &accepted,
            &CommandOutcome {
                status: odin_ledger::command::CommandTerminalStatus::Completed,
                result: serde_json::json!({ "seats": [], "resumed": false }),
            },
            revision,
            now,
        )
        .expect("the command settles");
    assert!(matches!(
        standing_demand(&mut ledger, &binding, new, now).expect("a settled ingest replays"),
        Disposition::Consumed(_)
    ));
}
