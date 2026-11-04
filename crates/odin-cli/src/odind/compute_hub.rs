//! One demand-owned compute cadence for every open overview.
//!
//! A view's request is a subscriber only while it is waiting. The first
//! subscriber starts the only flight. Further subscribers join that flight
//! and the same snapshot. After a snapshot the flight waits one cadence and
//! collects again only while someone is still subscribed. Closing one view
//! drops only that subscriber. The last drop aborts an in-flight collect and
//! stops the cadence. Nothing runs while no overview is open.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use odin_cli::compute_sample::CADENCE;
use serde_json::Value;
use tokio::sync::{watch, Notify};
use tokio::task::AbortHandle;

/// How long the flight stays up after the last waiter leaves, so the bridge
/// can rejoin for the next tick without starting a second collector. A view
/// that actually closed does not rejoin, and the flight stops.
const REJOIN_GAP: Duration = Duration::from_millis(400);

type CollectFuture = Pin<Box<dyn Future<Output = Result<Value, String>> + Send>>;
type Collect = Arc<dyn Fn() -> CollectFuture + Send + Sync>;

struct Publish {
    generation: u64,
    result: Result<Value, String>,
}

struct Inner {
    live: BTreeSet<u64>,
    next_id: u64,
    flight: Option<(u64, AbortHandle)>,
    in_collect: bool,
    published: u64,
}

/// Shared sampler. Cheap to clone via [`Arc`]; the process keeps one.
pub struct ComputeHub {
    inner: Mutex<Inner>,
    stop: Notify,
    published: watch::Sender<Publish>,
}

struct Subscription {
    hub: Arc<ComputeHub>,
    id: u64,
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.hub.unsubscribe(self.id);
    }
}

impl ComputeHub {
    pub fn new() -> Self {
        let (published, _) = watch::channel(Publish {
            generation: 0,
            result: Err("no compute sample yet".to_owned()),
        });
        Self {
            inner: Mutex::new(Inner {
                live: BTreeSet::new(),
                next_id: 1,
                flight: None,
                in_collect: false,
                published: 0,
            }),
            stop: Notify::new(),
            published,
        }
    }

    /// The authority's one cadence. Tests build their own hub.
    pub fn shared() -> Arc<Self> {
        static HUB: LazyLock<Arc<ComputeHub>> = LazyLock::new(|| Arc::new(ComputeHub::new()));
        Arc::clone(&HUB)
    }

    /// Wait for the next snapshot from the single flight. `collect` runs only
    /// if no flight is already sampling. Dropping this future unsubscribes.
    pub async fn sample<F, Fut>(self: &Arc<Self>, collect: F) -> Result<Value, String>
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Value, String>> + Send + 'static,
    {
        let collect: Collect = Arc::new(move || Box::pin(collect()));
        let mut seen = self.published.subscribe();
        let joined = self.join(collect);
        let generation = joined.0;
        let _guard = joined.1;
        loop {
            if seen.borrow().generation > generation {
                return seen.borrow().result.clone();
            }
            if seen.changed().await.is_err() {
                return Err("compute cadence stopped".to_owned());
            }
        }
    }

    fn join(self: &Arc<Self>, collect: Collect) -> (u64, Subscription) {
        let mut inner = self.inner.lock().expect("compute hub lock");
        let id = inner.next_id;
        inner.next_id = inner.next_id.saturating_add(1);
        inner.live.insert(id);
        let generation = inner.published;
        if inner.flight.is_none() {
            let hub = Arc::clone(self);
            let handle = tokio::spawn(async move { hub.run(id, collect).await });
            inner.flight = Some((id, handle.abort_handle()));
        }
        drop(inner);
        (
            generation,
            Subscription {
                hub: Arc::clone(self),
                id,
            },
        )
    }

    fn unsubscribe(&self, id: u64) {
        let mut inner = self.inner.lock().expect("compute hub lock");
        if !inner.live.remove(&id) {
            return;
        }
        if !inner.live.is_empty() {
            return;
        }
        if inner.in_collect {
            if let Some((_, handle)) = inner.flight.take() {
                handle.abort();
            }
            inner.in_collect = false;
            return;
        }
        drop(inner);
        // A stored permit, so a notify that lands before the sleep select
        // still wakes it. notify_waiters would drop that permit.
        self.stop.notify_one();
    }

    fn start_collect(&self, flight: u64) -> bool {
        let mut inner = self.inner.lock().expect("compute hub lock");
        if inner.flight.as_ref().map(|(id, _)| *id) != Some(flight) {
            return false;
        }
        if inner.live.is_empty() {
            inner.flight = None;
            return false;
        }
        inner.in_collect = true;
        true
    }

    fn publish(&self, flight: u64, result: Result<Value, String>) -> bool {
        let mut inner = self.inner.lock().expect("compute hub lock");
        // An aborted collect can finish on another runtime thread after a
        // new overview has already started a replacement flight.
        if inner.flight.as_ref().map(|(id, _)| *id) != Some(flight) {
            return false;
        }
        inner.in_collect = false;
        inner.published = inner.published.saturating_add(1);
        // Joining and publishing use the same lock: a rejoining request
        // waits for the next generation, never the one just delivered.
        self.published.send_modify(|publish| {
            publish.generation = inner.published;
            publish.result = result;
        });
        true
    }

    fn try_finish(&self, flight: u64) -> bool {
        let mut inner = self.inner.lock().expect("compute hub lock");
        if inner.flight.as_ref().map(|(id, _)| *id) != Some(flight) {
            return true;
        }
        if !inner.live.is_empty() {
            return false;
        }
        inner.flight = None;
        true
    }

    async fn run(self: Arc<Self>, flight: u64, collect: Collect) {
        while self.start_collect(flight) {
            let result = collect().await;
            if !self.publish(flight, result) {
                return;
            }
            let next = tokio::time::Instant::now() + CADENCE;
            loop {
                tokio::select! {
                    () = tokio::time::sleep_until(next) => break,
                    () = self.stop.notified() => {
                        tokio::time::sleep(REJOIN_GAP).await;
                        if self.try_finish(flight) {
                            return;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn snapshot(node: &str) -> Value {
        serde_json::json!({ "hosts": [{ "node": node, "host": node }] })
    }

    #[tokio::test(start_paused = true)]
    async fn two_views_share_one_flight_and_the_last_close_stops_it() {
        let hub = Arc::new(ComputeHub::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let dropped = Arc::new(AtomicUsize::new(0));
        let collect = {
            let calls = Arc::clone(&calls);
            let started = Arc::clone(&started);
            let release = Arc::clone(&release);
            let dropped = Arc::clone(&dropped);
            move || {
                let calls = Arc::clone(&calls);
                let started = Arc::clone(&started);
                let release = Arc::clone(&release);
                let dropped = Arc::clone(&dropped);
                async move {
                    let _guard = scopeguard(dropped);
                    calls.fetch_add(1, Ordering::SeqCst);
                    started.notify_waiters();
                    release.notified().await;
                    Ok(snapshot("pc"))
                }
            }
        };
        let first = tokio::spawn({
            let hub = Arc::clone(&hub);
            let collect = collect.clone();
            async move { hub.sample(collect).await }
        });
        tokio::time::timeout(Duration::from_secs(1), started.notified())
            .await
            .expect("the first view starts the only flight");
        let second = tokio::spawn({
            let hub = Arc::clone(&hub);
            let collect = collect.clone();
            async move { hub.sample(collect).await }
        });
        tokio::task::yield_now().await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the second view joins the flight"
        );
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        assert_eq!(
            dropped.load(Ordering::SeqCst),
            0,
            "closing one view must not cancel the collect the other is waiting on"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        release.notify_waiters();
        let got = tokio::time::timeout(Duration::from_secs(1), second)
            .await
            .expect("the remaining view receives the snapshot")
            .unwrap()
            .unwrap();
        assert_eq!(got["hosts"][0]["node"], "pc");
        // The remaining view has its answer and has unsubscribed. The flight
        // is in its cadence sleep. Dropping that last interest stops it.
        tokio::time::sleep(REJOIN_GAP + Duration::from_millis(50)).await;
        tokio::task::yield_now().await;
        let before = calls.load(Ordering::SeqCst);
        tokio::time::sleep(CADENCE + Duration::from_millis(50)).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            before,
            "no overview open means no further collect"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn closing_the_last_view_cancels_and_reopening_waits_for_a_fresh_sample() {
        let hub = Arc::new(ComputeHub::new());
        let started = Arc::new(Notify::new());
        let dropped = Arc::new(AtomicUsize::new(0));
        let first = tokio::spawn({
            let hub = Arc::clone(&hub);
            let started = Arc::clone(&started);
            let dropped = Arc::clone(&dropped);
            async move {
                hub.sample(move || {
                    let started = Arc::clone(&started);
                    let dropped = Arc::clone(&dropped);
                    async move {
                        let _guard = scopeguard(dropped);
                        started.notify_one();
                        std::future::pending::<Result<Value, String>>().await
                    }
                })
                .await
            }
        });
        started.notified().await;
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        let fresh = hub
            .sample(|| std::future::ready(Ok(snapshot("reopened"))))
            .await
            .unwrap();
        assert_eq!(fresh["hosts"][0]["node"], "reopened");
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    fn scopeguard(dropped: Arc<AtomicUsize>) -> impl Drop {
        struct Guard(Arc<AtomicUsize>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        Guard(dropped)
    }
}
