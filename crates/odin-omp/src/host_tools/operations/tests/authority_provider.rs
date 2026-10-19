//! Follower providers deny token reads and verification without holding signing material.

use odin_domain::SessionId;

use crate::host_tools::operations::{HostToolOperationError, ProvisionedFreshAuthorityProvider};

use super::fixture::{Fixture, NOW_MS};

#[test]
fn denying_provider_denies_verification() {
    let provider = ProvisionedFreshAuthorityProvider::denying();
    let session = SessionId::new("00000000-0000-4000-8000-000000000707").expect("session id");

    let read_error = provider
        .read_token(&session)
        .expect_err("denied provider must deny token reads");
    assert!(matches!(
        read_error,
        HostToolOperationError::PublishedAuthorityUnavailable { .. }
    ));

    let fixture = Fixture::new();
    let binding = fixture.binding.clone();
    let ledger_guard = fixture.ledger.lock().expect("ledger lock");
    let verify_error = provider
        .verify(&binding, &session, &ledger_guard, NOW_MS)
        .err()
        .expect("denied provider must deny verification");
    assert!(matches!(
        verify_error,
        HostToolOperationError::PublishedAuthorityUnavailable { .. }
    ));
}
