//! Authenticated client transport and subscription invariants.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use odin_domain::huginn::{
    Freshness, FreshnessState, HuginnMessage, HuginnRequest, HuginnResponse, ObjectDelta,
    ObjectDeltaBatch, ObjectDeltaBody, ObjectKind, ObjectRef, QueryScope, RequestId, Revision,
    RevisionSource, TransferId,
};
use uuid::Uuid;

use super::*;
use crate::client::model::MemoryCredentialStore;
use crate::protocol::{decode_frame, encode_frame, ClientFrame, ServerFrame};

fn test_time() -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
}

fn object_delta(from: u64, to: u64) -> ObjectDelta {
    ObjectDelta {
        object: ObjectRef {
            kind: ObjectKind::KubeResource,
            id: "kube-1".to_owned(),
        },
        from_revision: Revision::new(from),
        to_revision: Revision::new(to),
        revision_source: RevisionSource::Registry,
        freshness: Freshness {
            state: FreshnessState::Fresh,
            observed_at: test_time(),
            source_updated_at: None,
            stale_after_seconds: None,
        },
        body: ObjectDeltaBody::Replace(serde_json::json!({"cpu": to})),
    }
}

fn message_frame(message: HuginnMessage, limits: &CodecLimits) -> Vec<u8> {
    encode_frame(&ServerFrame::General(message), limits).unwrap()
}

/// The object helper's ack discipline over a real framed connection:
/// arrival records the batch's checkpoint but adopts nothing, the
/// explicit ack sends `SubscribeObjects` at exactly the delivered
/// `to_revision`, and only its `Subscribed` adopts the checkpoint.
#[tokio::test]
async fn object_batch_arrival_adopts_nothing_until_the_explicit_ack() {
    let limits = CodecLimits::default();
    let (transport, mut hub) = memory_transport(16);
    let store = MemoryCredentialStore::new(test_credential());
    let client = ColinRemoteClient::new(transport, store);
    let mut connection = client.connect().await.unwrap();

    let server_task = tokio::spawn(async move {
        let mut server = hub.accept().await.unwrap();
        let frame = server.next_frame().await.unwrap().unwrap();
        match decode_frame::<ClientFrame>(&frame, &limits).unwrap().value {
            ClientFrame::General(HuginnRequest::SubscribeObjects(subscription)) => {
                assert_eq!(subscription.after, Revision::new(7));
            }
            other => panic!("expected the subscribe request, got {other:?}"),
        }
        server
            .send_frame(message_frame(
                HuginnMessage::Response {
                    request_id: RequestId::new(Uuid::new_v4()).unwrap(),
                    result: HuginnResponse::Subscribed,
                },
                &limits,
            ))
            .await
            .unwrap();
        // One pushed batch, cursor 7 -> 42.
        server
            .send_frame(message_frame(
                HuginnMessage::ObjectDeltaBatch(ObjectDeltaBatch {
                    from_revision: Revision::new(7),
                    to_revision: Revision::new(42),
                    deltas: vec![object_delta(7, 42)],
                    next_after: None,
                }),
                &limits,
            ))
            .await
            .unwrap();
        // The ack, at exactly the delivered checkpoint.
        let frame = server.next_frame().await.unwrap().unwrap();
        match decode_frame::<ClientFrame>(&frame, &limits).unwrap().value {
            ClientFrame::General(HuginnRequest::SubscribeObjects(subscription)) => {
                assert_eq!(subscription.after, Revision::new(42));
            }
            other => panic!("expected the ack request, got {other:?}"),
        }
        server
            .send_frame(message_frame(
                HuginnMessage::Response {
                    request_id: RequestId::new(Uuid::new_v4()).unwrap(),
                    result: HuginnResponse::Subscribed,
                },
                &limits,
            ))
            .await
            .unwrap();
    });

    connection
        .subscribe_objects(
            vec![ObjectKind::KubeResource],
            QueryScope::All,
            Revision::new(7),
        )
        .await
        .unwrap();
    assert_eq!(connection.object_checkpoint(), Some(Revision::new(7)));

    let HuginnMessage::ObjectDeltaBatch(batch) = connection.next().await.unwrap().unwrap() else {
        panic!("expected the delivered batch");
    };
    assert_eq!(batch.to_revision, Revision::new(42));
    // Arrival adopted nothing.
    assert_eq!(connection.object_checkpoint(), Some(Revision::new(7)));

    connection.ack_objects().await.unwrap();
    assert_eq!(connection.object_checkpoint(), Some(Revision::new(42)));
    assert!(
        connection.ack_objects().await.is_err(),
        "a second ack with nothing delivered is a typed refusal"
    );
    server_task.await.unwrap();
}

#[derive(Clone)]
struct MockSocket {
    send_count: Arc<AtomicUsize>,
    next_count: Arc<AtomicUsize>,
    close_count: Arc<AtomicUsize>,
    response_frame: Option<Vec<u8>>,
    close_error: bool,
}

#[async_trait]
impl TransportFrame for MockSocket {
    async fn send_frame(&mut self, _frame: Vec<u8>) -> Result<(), ClientError> {
        self.send_count.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn next_frame(&mut self) -> Result<Option<Vec<u8>>, ClientError> {
        self.next_count.fetch_add(1, Ordering::SeqCst);
        Ok(self.response_frame.clone())
    }

    async fn close(&mut self) -> Result<(), ClientError> {
        self.close_count.fetch_add(1, Ordering::SeqCst);
        if self.close_error {
            Err(ClientError::Transport("mock close failure".to_owned()))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone)]
struct MockTransport {
    socket: MockSocket,
}

#[async_trait]
impl HuginnTransport for MockTransport {
    type Socket = MockSocket;

    async fn bootstrap(
        &self,
        _credential: &DeviceCredential,
    ) -> Result<BootstrapInfo, ClientError> {
        Ok(BootstrapInfo::local(CodecLimits::default().max_frame_bytes))
    }

    async fn connect(&self, _credential: &DeviceCredential) -> Result<Self::Socket, ClientError> {
        Ok(self.socket.clone())
    }
}

fn test_credential() -> DeviceCredential {
    let id = Uuid::new_v4();
    let secret = [7u8; 32];
    DeviceCredential::from_parts(id, secret).unwrap()
}

fn test_request() -> HuginnRequest {
    HuginnRequest::CommitTransfer(TransferId::new(Uuid::new_v4()).unwrap())
}

fn test_response_frame(limits: &CodecLimits) -> Vec<u8> {
    let response_msg = HuginnMessage::Response {
        request_id: RequestId::new(Uuid::new_v4()).unwrap(),
        result: HuginnResponse::Ack,
    };
    encode_frame(&ServerFrame::General(response_msg), limits).unwrap()
}

#[tokio::test]
async fn request_closes_socket_on_success() {
    let limits = CodecLimits::default();
    let encoded = test_response_frame(&limits);

    let socket = MockSocket {
        send_count: Arc::new(AtomicUsize::new(0)),
        next_count: Arc::new(AtomicUsize::new(0)),
        close_count: Arc::new(AtomicUsize::new(0)),
        response_frame: Some(encoded),
        close_error: false,
    };
    let close_count = socket.close_count.clone();
    let transport = MockTransport { socket };
    let store = MemoryCredentialStore::new(test_credential());
    let client = ColinRemoteClient::new(transport, store);

    let response = client.request(test_request()).await.unwrap();
    assert_eq!(response, HuginnResponse::Ack);
    assert_eq!(close_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn request_closes_socket_and_preserves_error_on_failure() {
    let socket = MockSocket {
        send_count: Arc::new(AtomicUsize::new(0)),
        next_count: Arc::new(AtomicUsize::new(0)),
        close_count: Arc::new(AtomicUsize::new(0)),
        response_frame: None,
        close_error: true,
    };
    let close_count = socket.close_count.clone();
    let transport = MockTransport { socket };
    let store = MemoryCredentialStore::new(test_credential());
    let client = ColinRemoteClient::new(transport, store);

    let result = client.request(test_request()).await;
    assert_eq!(result, Err(ClientError::ConnectionClosed));
    assert_eq!(close_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn request_surfaces_close_error_after_successful_response() {
    let limits = CodecLimits::default();
    let encoded = test_response_frame(&limits);

    let socket = MockSocket {
        send_count: Arc::new(AtomicUsize::new(0)),
        next_count: Arc::new(AtomicUsize::new(0)),
        close_count: Arc::new(AtomicUsize::new(0)),
        response_frame: Some(encoded),
        close_error: true,
    };
    let close_count = socket.close_count.clone();
    let transport = MockTransport { socket };
    let store = MemoryCredentialStore::new(test_credential());
    let client = ColinRemoteClient::new(transport, store);

    let result = client.request(test_request()).await;
    assert_eq!(
        result,
        Err(ClientError::Transport("mock close failure".to_owned()))
    );
    assert_eq!(close_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn request_with_memory_transport_succeeds_and_closes() {
    let limits = CodecLimits::default();
    let (transport, mut hub) = memory_transport(16);
    let store = MemoryCredentialStore::new(test_credential());
    let client = ColinRemoteClient::new(transport, store);

    let server_task = tokio::spawn(async move {
        let mut server_end = hub.accept().await.unwrap();
        let frame = server_end.next_frame().await.unwrap().unwrap();
        let _request: ClientFrame = decode_frame(&frame, &limits).unwrap().value;
        let response_msg = HuginnMessage::Response {
            request_id: RequestId::new(Uuid::new_v4()).unwrap(),
            result: HuginnResponse::Ack,
        };
        let encoded = encode_frame(&ServerFrame::General(response_msg), &limits).unwrap();
        server_end.send_frame(encoded).await.unwrap();
        let after = server_end.next_frame().await.unwrap();
        assert!(after.is_none());
    });

    let response = client.request(test_request()).await.unwrap();
    assert_eq!(response, HuginnResponse::Ack);
    server_task.await.unwrap();
}

#[tokio::test]
async fn a_refused_request_keeps_the_device_credential() {
    let limits = CodecLimits::default();
    let refusal = encode_frame(
        &ServerFrame::General(HuginnMessage::ProtocolError(
            odin_domain::huginn::HuginnProtocolError::Unauthenticated,
        )),
        &limits,
    )
    .unwrap();
    let socket = MockSocket {
        send_count: Arc::new(AtomicUsize::new(0)),
        next_count: Arc::new(AtomicUsize::new(0)),
        close_count: Arc::new(AtomicUsize::new(0)),
        response_frame: Some(refusal),
        close_error: false,
    };
    let transport = MockTransport { socket };
    let store = MemoryCredentialStore::new(test_credential());
    let client = ColinRemoteClient::new(transport, store);
    let result = client.request(test_request()).await;
    assert_eq!(
        result,
        Err(ClientError::Protocol(
            odin_domain::huginn::HuginnProtocolError::Unauthenticated
        ))
    );
    assert!(
        client
            .request(test_request())
            .await
            .is_err_and(|error| error != ClientError::CredentialUnavailable),
        "the credential is still stored"
    );
}

#[derive(Clone)]
struct LoggedSocket {
    log: Arc<std::sync::Mutex<Vec<&'static str>>>,
    frame: Vec<u8>,
}

#[async_trait]
impl TransportFrame for LoggedSocket {
    async fn send_frame(&mut self, _frame: Vec<u8>) -> Result<(), ClientError> {
        Ok(())
    }

    async fn next_frame(&mut self) -> Result<Option<Vec<u8>>, ClientError> {
        Ok(Some(self.frame.clone()))
    }

    async fn close(&mut self) -> Result<(), ClientError> {
        self.log.lock().unwrap().push("close");
        Ok(())
    }
}

#[derive(Clone)]
struct LoggedTransport {
    socket: LoggedSocket,
}

#[async_trait]
impl HuginnTransport for LoggedTransport {
    type Socket = LoggedSocket;

    async fn bootstrap(
        &self,
        _credential: &DeviceCredential,
    ) -> Result<BootstrapInfo, ClientError> {
        Ok(BootstrapInfo::local(CodecLimits::default().max_frame_bytes))
    }

    async fn connect(&self, _credential: &DeviceCredential) -> Result<Self::Socket, ClientError> {
        self.socket.log.lock().unwrap().push("connect");
        Ok(self.socket.clone())
    }
}

/// Close the existing socket first so a one-connection cap permits the replacement.
#[tokio::test]
async fn a_reconnect_releases_the_old_socket_before_connecting() {
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let transport = LoggedTransport {
        socket: LoggedSocket {
            log: Arc::clone(&log),
            frame: test_response_frame(&CodecLimits::default()),
        },
    };
    let client = ColinRemoteClient::new(transport, MemoryCredentialStore::new(test_credential()));
    let mut connection = client.connect().await.unwrap();
    connection.reconnect_request(test_request()).await.unwrap();
    assert_eq!(*log.lock().unwrap(), ["connect", "close", "connect"]);
}

fn kube_limits() -> odin_domain::huginn::stream::StreamBackpressureLimits {
    odin_domain::huginn::stream::StreamBackpressureLimits {
        max_buffered_items: std::num::NonZeroU32::new(8).unwrap(),
        max_buffered_bytes: std::num::NonZeroU64::new(1 << 20).unwrap(),
        max_item_bytes: std::num::NonZeroU64::new(1 << 16).unwrap(),
        max_items_per_second: std::num::NonZeroU32::new(8).unwrap(),
        max_in_flight_bytes: std::num::NonZeroU64::new(1 << 20).unwrap(),
    }
}

fn kube_status(stream_id: StreamId, sequence: u64, lifecycle: StreamLifecycle) -> HuginnMessage {
    HuginnMessage::StreamStatus(odin_domain::huginn::stream::StreamStatus {
        stream_id,
        kind: LiveStreamKind::KubeEvents,
        mode: LiveStreamMode::Durable,
        lifecycle,
        durable_head: Some(Sequence::new(sequence)),
        last_delivered: Some(Sequence::new(sequence)),
        control_revision: 0,
        buffered_items: 0,
        buffered_bytes: 0,
        dropped_items: 0,
        limits: kube_limits(),
        updated_at: time::OffsetDateTime::UNIX_EPOCH,
        failure: None,
    })
}

/// Durable kube statuses advance the cursor once; duplicate events are skipped but closure is delivered.
#[tokio::test]
async fn delivered_kube_events_move_the_cursor_once() {
    let limits = CodecLimits::default();
    let transport = MockTransport {
        socket: MockSocket {
            send_count: Arc::new(AtomicUsize::new(0)),
            next_count: Arc::new(AtomicUsize::new(0)),
            close_count: Arc::new(AtomicUsize::new(0)),
            response_frame: Some(test_response_frame(&limits)),
            close_error: false,
        },
    };
    let client = ColinRemoteClient::new(transport, MemoryCredentialStore::new(test_credential()));
    let mut connection = client.connect().await.unwrap();
    let stream_id = StreamId::parse("00000000-0000-4000-8000-000000000007").unwrap();
    let set = SubscriptionSet {
        subscriptions: vec![odin_domain::huginn::stream::StreamSubscription {
            kind: LiveStreamKind::KubeEvents,
            cursor: StreamCursor::Durable {
                stream_id,
                after: None,
            },
            credit: odin_domain::huginn::stream::StreamCredit {
                items: std::num::NonZeroU32::new(8).unwrap(),
                bytes: std::num::NonZeroU64::new(1 << 20).unwrap(),
            },
            limits: kube_limits(),
        }],
    };
    connection.install_subscriptions(set);
    for sequence in [1, 2] {
        assert!(connection.prepare_delivery(&kube_status(
            stream_id,
            sequence,
            StreamLifecycle::Live
        )));
    }
    assert!(!connection.prepare_delivery(&kube_status(stream_id, 2, StreamLifecycle::Live)));
    assert_eq!(
        connection.cursors(),
        [StreamCursor::Durable {
            stream_id,
            after: Some(Sequence::new(2)),
        }]
    );
    assert!(connection.prepare_delivery(&kube_status(stream_id, 2, StreamLifecycle::Closed)));
}
