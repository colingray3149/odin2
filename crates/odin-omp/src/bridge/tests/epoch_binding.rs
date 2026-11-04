//! Requested epochs create or advance durable rows but never rewind them.
//! Without a requested epoch, launch creates at one or increments on reclaim.

use super::fixture::{fixture_context, row_for};
use super::remote_launch::{has_active_lease, retired_at};
use super::*;

#[tokio::test]
async fn a_requested_durable_epoch_reaches_the_real_launched_binding() {
    let root = tempfile::tempdir().unwrap();

    // Legacy shape: no requested epoch, missing row — created at 1.
    let context = fixture_context(root.path(), 1, "epoch-legacy").await;
    let bridge = OmpBridge::start(context.bridge_config(context.session_descriptor()).unwrap())
        .await
        .unwrap();
    assert_eq!(bridge.binding().unwrap().epoch, 1);
    bridge.stop().await.unwrap();

    // A row AHEAD of the request: a stale incarnation asking to rewind a
    // published epoch is refused typed, and no child ever spawns.
    let context = fixture_context(root.path(), 2, "epoch-stale").await;
    let descriptor = context.session_descriptor();
    {
        let ledger = context.ledger();
        let mut guard = ledger.lock().expect("case ledger lock");
        guard
            .create_live_session_at(&row_for(&context, &descriptor), 5)
            .unwrap();
    }
    let mut config = context.bridge_config(descriptor.clone()).unwrap();
    config.requested_epoch = Some(odin_domain::huginn::SessionEpoch::new(3));
    let error = match OmpBridge::start(config).await {
        Err(error) => error,
        Ok(_) => panic!("expected the typed stale-binding refusal"),
    };
    match error {
        BridgeError::StaleBinding { requested, actual } => {
            assert_eq!(requested, 3);
            assert_eq!(actual, 5);
        }
        error => panic!("expected the typed stale-binding refusal, got {error}"),
    }
    // A refused launch retires only what it owns: the newer incarnation's
    // publication and epoch stay exactly as published, and its lease is released.
    let session = context.ids().session.clone();
    {
        let ledger = context.ledger();
        let guard = ledger.lock().expect("case ledger lock");
        let row = guard.live_session(&session).unwrap();
        assert_eq!(
            (row.epoch, row.state.as_str()),
            (5, "ready"),
            "the refused rewind must not move the durable row"
        );
        assert!(retired_at(&guard, &session).is_none());
        assert!(!has_active_lease(&guard, &session));
    }

    // A row BEHIND the request: the launch corrects the binding forward to
    // EXACTLY the requested admission epoch — never row+1, never 1.
    let context = fixture_context(root.path(), 3, "epoch-lagging").await;
    let descriptor = context.session_descriptor();
    {
        let ledger = context.ledger();
        let mut guard = ledger.lock().expect("case ledger lock");
        guard
            .create_live_session_at(&row_for(&context, &descriptor), 1)
            .unwrap();
    }
    let mut config = context.bridge_config(descriptor).unwrap();
    config.requested_epoch = Some(odin_domain::huginn::SessionEpoch::new(3));
    let bridge = OmpBridge::start(config).await.unwrap();
    assert_eq!(
        bridge.binding().unwrap().epoch,
        3,
        "the real launched binding must carry the requested durable epoch"
    );
    bridge.stop().await.unwrap();

    // A MISSING row is created AT the requested epoch, never at 1.
    let context = fixture_context(root.path(), 4, "epoch-fresh").await;
    let mut config = context.bridge_config(context.session_descriptor()).unwrap();
    config.requested_epoch = Some(odin_domain::huginn::SessionEpoch::new(7));
    let bridge = OmpBridge::start(config).await.unwrap();
    assert_eq!(bridge.binding().unwrap().epoch, 7);
    bridge.stop().await.unwrap();
}
