//! Identity tests: capability descriptor parsing and the root-local client
//! that must never touch the broker channel.

use super::*;

#[test]
fn descriptor_parse_roundtrip_and_rejections() {
    let worker = mint_worker_id().expect("minted worker id");
    let socket = PathBuf::from("/run/user/1000/odin-broker/broker/authority.sock");
    let store_root = PathBuf::from("/run/user/1000/odin-broker/store");
    let descriptor =
        ParentAuthorityDescriptor::new(worker, socket, store_root.clone()).expect("descriptor");
    let raw = descriptor.to_environment_value();
    let parsed = ParentAuthorityDescriptor::parse(&raw).expect("round trip");
    assert_eq!(parsed, descriptor);
    assert_eq!(parsed.store_path(), store_root.join(SCOPE_LEDGER_NAME));

    // `pid=` is deliberately not an alias for an opaque WorkerId.
    assert!(ParentAuthorityDescriptor::parse(&raw.replacen("worker=", "pid=", 1)).is_err());
    assert!(ParentAuthorityDescriptor::parse("worker=abc").is_err());
    assert!(
        ParentAuthorityDescriptor::parse("worker=abc;socket=/tmp/s;store_root=/tmp/r;extra=1")
            .is_err()
    );
    assert!(
        ParentAuthorityDescriptor::parse("worker=abc;socket=relative;store_root=/tmp/r").is_err()
    );
    assert!(
        ParentAuthorityDescriptor::parse("worker=abc;socket=/tmp/s;store_root=../escape").is_err()
    );
    assert!(
        ParentAuthorityDescriptor::parse("worker=has space;socket=/tmp/s;store_root=/tmp/r")
            .is_err()
    );
}

#[test]
fn root_local_client_never_uses_broker() {
    let client = ParentAuthorityClient::root_local();
    assert!(!client.is_remote());
    assert!(client.descriptor().is_none());
    assert!(client.expected_store_path().is_err());
    assert!(matches!(
        client.call(BrokerRequest::HandoffScope {}),
        Err(ParentAuthorityError::Scope(_))
    ));
}
