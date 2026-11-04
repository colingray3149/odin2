//! Ordinary stop preserves a reclaimable `ready` session; session-ending stop
//! retires it as `Ended`, preventing later reclaim.

use super::fixture::fixture_context;
use super::*;

fn retired_at(ledger: &Ledger, session: &SessionId) -> Option<String> {
    ledger
        .connection()
        .query_row(
            "SELECT retired_at FROM live_sessions WHERE session_id=?1",
            [session.to_string()],
            |row| row.get(0),
        )
        .expect("live session row exists")
}

#[tokio::test]
async fn an_ordinary_stop_keeps_the_session_reclaimable_while_an_ending_stop_retires_it() {
    let root = tempfile::tempdir().unwrap();
    let context = fixture_context(root.path(), 16, "stop-disposition").await;
    let session = context.ids().session.clone();
    let descriptor = context.session_descriptor();

    // Ordinary daemon shutdown stops the child but preserves the resumable row.
    let bridge = OmpBridge::start(context.bridge_config(descriptor.clone()).unwrap())
        .await
        .unwrap();
    assert_eq!(bridge.binding().unwrap().epoch, 1);
    let stopped = bridge.stop().await.unwrap();
    assert!(
        stopped.exit.is_some(),
        "the ordinary stop proves the child exit"
    );
    {
        let ledger = context.ledger();
        let guard = ledger.lock().expect("case ledger lock");
        let row = guard.live_session(&session).expect("row after stop");
        assert_eq!(
            (row.epoch, row.state.as_str()),
            (1, "ready"),
            "an ordinary stop ends the run, never the session"
        );
        assert!(
            retired_at(&guard, &session).is_none(),
            "the resumable row is not retired"
        );
    }

    // The next daemon reclaims the SAME session row and reattaches a fresh
    // child under a new epoch: resumability is consumer-visible, not a
    // counter. Under the regressed stop this launch failed typed with the
    // ledger's SessionEnded refusal.
    let mut config = context.bridge_config(descriptor.clone()).unwrap();
    config.requested_epoch = Some(odin_domain::huginn::SessionEpoch::new(2));
    let bridge = OmpBridge::start(config).await.unwrap();
    assert_eq!(
        bridge.binding().unwrap().epoch,
        2,
        "a stopped-but-resumable row is reclaimed by the next launch"
    );

    // The explicit session-ending stop retires the row `Ended` — permanent:
    // the final launch is refused typed, the refusal the launcher maps to
    // the `session_ended` conflict.
    bridge.stop_ending_session().await.unwrap();
    {
        let ledger = context.ledger();
        let guard = ledger.lock().expect("case ledger lock");
        let row = guard.live_session(&session).expect("row after end");
        assert_eq!(
            (row.epoch, row.state.as_str()),
            (2, "ended"),
            "the ending stop retires the durable row"
        );
        assert!(
            retired_at(&guard, &session).is_some(),
            "the ended row leaves the live set"
        );
    }
    let mut config = context.bridge_config(descriptor).unwrap();
    config.requested_epoch = Some(odin_domain::huginn::SessionEpoch::new(3));
    let error = match OmpBridge::start(config).await {
        Err(error) => error,
        Ok(_) => panic!("an ended session is never reclaimed"),
    };
    assert!(
        matches!(
            error,
            BridgeError::Ledger(odin_ledger::LedgerError::SessionEnded { .. })
        ),
        "the ended row refuses the launch typed, got {error}"
    );
}
