//! Confined artifact read invariants: byte bounds, digest binding, root identity.

use super::*;

#[test]
fn artifact_bytes_are_bounded_and_verified() {
    let ledger = seeded_ledger();
    let root = artifact_root("artifact-verification");
    let (metadata, payload, escape_metadata) = {
        let mut guard = ledger.lock().unwrap();
        let (metadata, payload) = seed_artifact(&mut guard, &root);
        std::fs::write(root.parent().unwrap().join("outside.txt"), b"escape").unwrap();
        let created = decode_utc("2026-01-01T00:00:00Z").unwrap();
        let escape_metadata = guard
            .register_artifact(ArtifactRegistration {
                bytes: b"escape",
                media_type: "text/plain",
                storage_path: "../outside.txt",
                retention: RetentionClass::Scratch,
                created_at: created,
            })
            .unwrap();
        guard
            .attach_artifact_reference(
                &escape_metadata.artifact_id,
                1,
                NewArtifactReference {
                    object_kind: "run",
                    object_id: "run-alpha",
                    relation: "output",
                    created_at: created,
                },
            )
            .unwrap();
        (metadata, payload, escape_metadata)
    };
    let router = test_router(ledger.clone(), root.clone());
    let scoped = scoped_of_seat("seat-alpha");
    let artifact_url = format!("odin-artifact://{}", metadata.artifact_id);

    // A same-length byte change must fail the BLAKE3 verification.
    std::fs::write(root.join("report.txt"), b"ARTIFACT payload for uri routing").unwrap();
    let error = router.resolve(&scoped, &artifact_url).unwrap_err();
    assert!(matches!(error, UriError::ArtifactMismatch { .. }));
    std::fs::write(root.join("report.txt"), &payload).unwrap();
    assert!(router.resolve(&scoped, &artifact_url).is_ok());

    // A router bound below the registered size refuses before reading.
    let tight = ScopedUriRouter::new(
        ledger,
        Arc::new(test_atlas()),
        allowed_atlas_scope(),
        root.clone(),
        8,
        BTreeMap::new(),
    )
    .unwrap();
    let error = tight.resolve(&scoped, &artifact_url).unwrap_err();
    assert!(matches!(error, UriError::ArtifactMismatch { .. }));

    // A registered storage path outside confinement is rejected by the sealed
    // capability's byte-level validation before any descriptor is opened.
    let escape_error = router
        .resolve(
            &scoped,
            &format!("odin-artifact://{}", escape_metadata.artifact_id),
        )
        .unwrap_err();
    assert!(matches!(escape_error, UriError::Storage { .. }));
}

#[test]
fn artifact_resolution_rejects_a_replaced_artifact_root() {
    let ledger = seeded_ledger();
    let root = artifact_root("root-replacement");
    let (metadata, payload) = {
        let mut guard = ledger.lock().unwrap();
        seed_artifact(&mut guard, &root)
    };
    let router = test_router(ledger, root.clone());
    let scoped = scoped_of_seat("seat-alpha");
    let artifact_url = format!("odin-artifact://{}", metadata.artifact_id);

    let resolved = router
        .resolve(&scoped, &artifact_url)
        .expect("resolve before the root is replaced");
    let UriBody::Bytes(bytes) = resolved.body else {
        panic!("expected artifact bytes");
    };
    assert_eq!(bytes, payload);

    // Replacing the declared root revokes the tree the capability sealed:
    // serving the orphaned object would read outside the declared root,
    // so the resolution must refuse with the confined root-swapped class.
    let revoked = root.with_extension("revoked");
    std::fs::rename(&root, &revoked).unwrap();
    std::fs::create_dir(&root).unwrap();
    let error = router.resolve(&scoped, &artifact_url).unwrap_err();
    assert!(matches!(error, UriError::Storage { .. }));

    // Restoring the declared tree re-proves the sealed capability, and the
    // valid in-root artifact resolves again through the same router.
    std::fs::remove_dir(&root).unwrap();
    std::fs::rename(&revoked, &root).unwrap();
    let restored = router.resolve(&scoped, &artifact_url).unwrap();
    let UriBody::Bytes(bytes) = restored.body else {
        panic!("expected artifact bytes after restoring the declared root");
    };
    assert_eq!(bytes, payload);
}
