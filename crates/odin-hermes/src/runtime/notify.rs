//! A dedicated worker drives the asynchronous Discord sink on its own Tokio
//! runtime; synchronous host-tool and reconcile callers wait for bounded,
//! typed completions instead of nesting a runtime.
//!
//! The bridge owns its worker. Callers wait a bounded time for one job; a
//! job still queued when the wait ends (or the bridge closes) is withdrawn and
//! never sent, while a job the worker already took is unknown — its durable
//! checkpoint, not this wait, decides what happened. Shutdown closes
//! admission first, then drains against the caller's one deadline. An unproved
//! drain keeps its handle; destroying that owner cannot claim the worker stopped.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};

use super::HermesRuntimeError;
use crate::discord::DiscordMessageRef;
use crate::egress::{DeliveryCheckpoint, EgressError, OutboundMessage, OutgoingSink, ReplyChunks};

/// How long one caller waits for its job before it stops waiting. A job the
/// worker already took stays in flight; only the wait ends.
const REPLY_WAIT: Duration = Duration::from_secs(120);
/// How often an async drain looks at the worker.
const DRAIN_POLL: Duration = Duration::from_millis(5);

/// Owns the sink's runtime and worker; callers receive a bounded completion.
pub(super) struct NotifyBridge {
    shared: Arc<Shared>,
    /// Kept through explicit drain until joined or reported unproved.
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
    wait: Duration,
}

struct Shared {
    core: Mutex<Core>,
    /// Wakes the worker (a job, or close) and every waiting caller (an
    /// outcome, a withdrawal, close, abort).
    changed: Condvar,
    /// Post-composition sink binding: the daemon (or a test) may bind an
    /// alternate governed outgoing sink after `open`; unbound, the worker
    /// sends through the sink composed at construction. Consulted per job.
    bound: Mutex<Option<Arc<dyn OutgoingSink>>>,
    composed: Arc<dyn OutgoingSink>,
    channel_id: String,
    /// Cancels the in-flight job's future at the shutdown deadline.
    abort: tokio::sync::watch::Sender<bool>,
}

#[derive(Default)]
struct Core {
    /// No new job is admitted; queued jobs were withdrawn.
    closed: bool,
    /// The shutdown deadline passed: callers stop waiting on in-flight jobs.
    aborted: bool,
    next_id: u64,
    queue: VecDeque<(u64, NotifyAction)>,
    /// The one job the worker took and has not finished.
    dispatched: Option<u64>,
    outcomes: BTreeMap<u64, Result<ReplyChunks, NotifyError>>,
    /// Dispatched jobs whose caller stopped waiting: the outcome is dropped.
    abandoned: BTreeSet<u64>,
    /// Queued jobs withdrawn by close: provably never sent.
    cancelled: BTreeSet<u64>,
}

/// `Egress` uses [`EgressError::may_have_posted`]; `Unresolved` has an unknown outcome,
/// while `Closed` and `Cancelled` never reached the sink.
#[derive(Debug, thiserror::Error)]
pub(crate) enum NotifyError {
    #[error("notify is closed for shutdown")]
    Closed,
    #[error("notify job was withdrawn before dispatch")]
    Cancelled,
    #[error("notify job was dispatched and its outcome is unknown")]
    Unresolved,
    #[error(transparent)]
    Egress(#[from] EgressError),
}

impl From<NotifyError> for EgressError {
    fn from(error: NotifyError) -> Self {
        match error {
            NotifyError::Closed => EgressError::InvalidState("notify is closed for shutdown"),
            NotifyError::Cancelled => {
                EgressError::InvalidState("notify job was withdrawn before dispatch")
            }
            NotifyError::Unresolved => EgressError::ReplyLost,
            NotifyError::Egress(egress) => egress,
        }
    }
}

/// What one job does on the owner channel.
pub(super) enum NotifyAction {
    Deliver {
        content: String,
        checkpoint: Arc<dyn DeliveryCheckpoint>,
    },
    Send(String),
    Typing,
}

/// Settles the books however the worker leaves, panics included: admission
/// closes, queued jobs are withdrawn, and the job in hand is unknown.
struct WorkerExit(Arc<Shared>);

impl Drop for WorkerExit {
    fn drop(&mut self) {
        let mut core = self.0.core.lock();
        core.closed = true;
        while let Some((id, _)) = core.queue.pop_front() {
            core.cancelled.insert(id);
        }
        if let Some(id) = core.dispatched.take() {
            if !core.abandoned.remove(&id) {
                core.outcomes.insert(id, Err(NotifyError::Unresolved));
            }
        }
        self.0.changed.notify_all();
    }
}

fn perform(
    shared: &Shared,
    action: NotifyAction,
) -> impl std::future::Future<Output = Result<ReplyChunks, EgressError>> + '_ {
    let target = shared
        .bound
        .lock()
        .clone()
        .unwrap_or_else(|| Arc::clone(&shared.composed));
    let channel_id = &shared.channel_id;
    async move {
        let message = |content| OutboundMessage {
            channel_id: channel_id.to_owned(),
            content,
        };
        match action {
            NotifyAction::Deliver {
                content,
                checkpoint,
            } => target.deliver(message(content), checkpoint).await,
            NotifyAction::Send(content) => target.send(message(content)).await,
            NotifyAction::Typing => target.typing(channel_id).await.map(|()| {
                ReplyChunks::single(DiscordMessageRef {
                    message_id: String::new(),
                    channel_id: channel_id.to_owned(),
                })
            }),
        }
    }
}

fn work(shared: Arc<Shared>, runtime: tokio::runtime::Runtime) {
    let _exit = WorkerExit(Arc::clone(&shared));
    loop {
        let (id, action) = {
            let mut core = shared.core.lock();
            loop {
                if let Some((id, action)) = core.queue.pop_front() {
                    core.dispatched = Some(id);
                    break (id, action);
                }
                if core.closed {
                    return;
                }
                shared.changed.wait(&mut core);
            }
        };
        let mut aborted = shared.abort.subscribe();
        let outcome = runtime.block_on(async {
            tokio::select! {
                outcome = perform(&shared, action) => outcome.map_err(NotifyError::Egress),
                _ = aborted.wait_for(|stop| *stop) => Err(NotifyError::Unresolved),
            }
        });
        let mut core = shared.core.lock();
        core.dispatched = None;
        if !core.abandoned.remove(&id) {
            core.outcomes.insert(id, outcome);
        }
        shared.changed.notify_all();
    }
}

impl NotifyBridge {
    pub(super) fn spawn(
        sink: Arc<dyn OutgoingSink>,
        channel_id: String,
    ) -> Result<Self, HermesRuntimeError> {
        Self::start(sink, channel_id, REPLY_WAIT)
    }

    fn start(
        sink: Arc<dyn OutgoingSink>,
        channel_id: String,
        wait: Duration,
    ) -> Result<Self, HermesRuntimeError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| {
                HermesRuntimeError::Composition(format!("notify runtime failed: {error}"))
            })?;
        let shared = Arc::new(Shared {
            core: Mutex::new(Core::default()),
            changed: Condvar::new(),
            bound: Mutex::new(None),
            composed: sink,
            channel_id,
            abort: tokio::sync::watch::channel(false).0,
        });
        let worker = {
            let shared = Arc::clone(&shared);
            std::thread::Builder::new()
                .name("odin-hermes-notify".to_owned())
                .spawn(move || work(shared, runtime))
                .map_err(|error| {
                    HermesRuntimeError::Composition(format!("notify worker spawn failed: {error}"))
                })?
        };
        Ok(Self {
            shared,
            worker: Mutex::new(Some(worker)),
            wait,
        })
    }

    pub(super) fn bind_sink(&self, sink: Arc<dyn OutgoingSink>) -> Result<(), String> {
        *self.shared.bound.lock() = Some(sink);
        Ok(())
    }

    /// Runs one job and waits for its outcome, a bounded time. Still queued
    /// at the end of the wait or at close: withdrawn, never sent
    /// ([`NotifyError::Cancelled`]). Already taken by the worker: the caller
    /// stops waiting and the outcome is unknown ([`NotifyError::Unresolved`]).
    pub(super) fn notify(&self, action: NotifyAction) -> Result<ReplyChunks, NotifyError> {
        let deadline = Instant::now() + self.wait;
        let shared = &self.shared;
        let mut core = shared.core.lock();
        if core.closed {
            return Err(NotifyError::Closed);
        }
        let id = core.next_id;
        core.next_id += 1;
        core.queue.push_back((id, action));
        shared.changed.notify_all();
        loop {
            if let Some(outcome) = core.outcomes.remove(&id) {
                return outcome;
            }
            if core.cancelled.remove(&id) {
                return Err(NotifyError::Cancelled);
            }
            if core.aborted || Instant::now() >= deadline {
                if let Some(position) = core.queue.iter().position(|(queued, _)| *queued == id) {
                    core.queue.remove(position);
                    return Err(NotifyError::Cancelled);
                }
                if core.dispatched == Some(id) {
                    core.abandoned.insert(id);
                }
                return Err(NotifyError::Unresolved);
            }
            let _ = shared.changed.wait_until(&mut core, deadline);
        }
    }

    /// Closes admission and withdraws everything still queued, waking every
    /// waiting caller. Synchronous and idempotent; the in-flight job, if any,
    /// keeps running until [`Self::drain_until`] or drop.
    pub(super) fn close(&self) {
        let mut core = self.shared.core.lock();
        if !core.closed {
            core.closed = true;
            while let Some((id, _)) = core.queue.pop_front() {
                core.cancelled.insert(id);
            }
        }
        self.shared.changed.notify_all();
    }

    /// Cancels the in-flight job's future and releases callers still waiting
    /// on it. A future that never yields (a blocked sink) is not cancelled.
    fn abort(&self) {
        self.shared.core.lock().aborted = true;
        self.shared.abort.send_replace(true);
        self.shared.changed.notify_all();
    }

    /// Closes admission, then waits for the worker to stop until `deadline`.
    /// A stopped worker is joined here and the handle released. At the
    /// deadline the in-flight job is cancelled where it can be, waiting
    /// callers are released, and the worker is reported as a straggler with
    /// its handle kept: a timeout is never a successful stop, and a later
    /// drain joins it.
    pub(super) async fn drain_until(&self, deadline: tokio::time::Instant) -> Result<(), String> {
        self.close();
        loop {
            {
                let mut slot = self.worker.lock();
                match slot.as_ref().map(std::thread::JoinHandle::is_finished) {
                    None => return Ok(()),
                    Some(true) => {
                        let handle = slot.take().expect("checked present");
                        drop(slot);
                        let _ = handle.join();
                        return Ok(());
                    }
                    Some(false) => {}
                }
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                self.abort();
                return Err(
                    "the notify worker did not stop before the shutdown deadline; \
                     unresolved delivery checkpoints remain held"
                        .to_owned(),
                );
            }
            tokio::time::sleep_until(deadline.min(now + DRAIN_POLL)).await;
        }
    }
}

/// Drop joins only finished workers; even an idle delivery loop may have blocking
/// runtime work. Explicit shutdown waits belong in [`NotifyBridge::drain_until`].
impl Drop for NotifyBridge {
    fn drop(&mut self) {
        self.close();
        let Some(handle) = self.worker.lock().take() else {
            return;
        };
        if handle.thread().id() == std::thread::current().id() {
            return;
        }
        if !handle.is_finished() {
            self.abort();
            tracing::warn!(
                "odin-hermes: unfinished notify worker abandoned at drop, not joined; \
                 unresolved delivery checkpoints remain held"
            );
            return;
        }
        let _ = handle.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    #[derive(Clone, Copy)]
    enum Mode {
        /// Answers at once.
        Pass,
        /// Blocks its thread until released: a sink that cannot be cancelled.
        Block,
        /// Awaits forever: a sink that cancellation reaches.
        Hang,
        /// Returns while a blocking runtime task is still finishing.
        RuntimeBlock,
    }

    struct TestSink {
        mode: Mode,
        released: Arc<Mutex<bool>>,
        entered: Arc<Mutex<usize>>,
        changed: Arc<Condvar>,
        sent: Mutex<Vec<String>>,
        blocking: Mutex<Option<tokio::task::JoinHandle<()>>>,
    }

    impl TestSink {
        fn new(mode: Mode) -> Arc<Self> {
            Arc::new(Self {
                mode,
                released: Arc::new(Mutex::new(false)),
                entered: Arc::new(Mutex::new(0)),
                changed: Arc::new(Condvar::new()),
                sent: Mutex::new(Vec::new()),
                blocking: Mutex::new(None),
            })
        }

        fn release(&self) {
            *self.released.lock() = true;
            self.changed.notify_all();
        }

        fn wait_entered(&self, count: usize) {
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut entered = self.entered.lock();
            while *entered < count {
                assert!(
                    !self.changed.wait_until(&mut entered, deadline).timed_out(),
                    "the sink was never entered"
                );
            }
        }

        fn sent(&self) -> Vec<String> {
            self.sent.lock().clone()
        }
    }

    #[async_trait]
    impl OutgoingSink for TestSink {
        async fn deliver(
            &self,
            _: OutboundMessage,
            _: Arc<dyn DeliveryCheckpoint>,
        ) -> Result<ReplyChunks, EgressError> {
            Err(EgressError::InvalidState("not used"))
        }

        async fn send(&self, message: OutboundMessage) -> Result<ReplyChunks, EgressError> {
            *self.entered.lock() += 1;
            self.changed.notify_all();
            match self.mode {
                Mode::Pass => {}
                Mode::Block => {
                    let deadline = Instant::now() + Duration::from_secs(30);
                    let mut released = self.released.lock();
                    while !*released {
                        if self.changed.wait_until(&mut released, deadline).timed_out() {
                            return Err(EgressError::InvalidState("release fuse cap elapsed"));
                        }
                    }
                }
                Mode::Hang => std::future::pending::<()>().await,
                Mode::RuntimeBlock => {
                    let released = Arc::clone(&self.released);
                    let entered = Arc::clone(&self.entered);
                    let changed = Arc::clone(&self.changed);
                    let task = tokio::task::spawn_blocking(move || {
                        *entered.lock() += 1;
                        changed.notify_all();
                        let deadline = Instant::now() + Duration::from_secs(30);
                        let mut released = released.lock();
                        while !*released {
                            if changed.wait_until(&mut released, deadline).timed_out() {
                                break;
                            }
                        }
                    });
                    *self.blocking.lock() = Some(task);
                }
            }
            self.sent.lock().push(message.content);
            Ok(ReplyChunks::single(DiscordMessageRef {
                message_id: "1".to_owned(),
                channel_id: message.channel_id,
            }))
        }

        async fn edit(
            &self,
            _: &ReplyChunks,
            _: OutboundMessage,
        ) -> Result<ReplyChunks, EgressError> {
            Err(EgressError::InvalidState("not used"))
        }

        async fn typing(&self, _: &str) -> Result<(), EgressError> {
            Ok(())
        }
    }

    /// A helper thread that releases the sink before it is joined, so a
    /// failing test can neither hang nor leave it running.
    struct Run<T: Send + 'static> {
        sink: Arc<TestSink>,
        handle: Option<std::thread::JoinHandle<T>>,
    }

    impl<T: Send + 'static> Run<T> {
        fn spawn(sink: &Arc<TestSink>, work: impl FnOnce() -> T + Send + 'static) -> Self {
            Self {
                sink: Arc::clone(sink),
                handle: Some(std::thread::spawn(work)),
            }
        }

        fn finish(mut self) -> T {
            self.handle
                .take()
                .expect("joined once")
                .join()
                .expect("helper panicked")
        }
    }

    impl<T: Send + 'static> Drop for Run<T> {
        fn drop(&mut self) {
            if let Some(handle) = self.handle.take() {
                self.sink.release();
                let _ = handle.join();
            }
        }
    }

    fn bridge(sink: &Arc<TestSink>, wait: Duration) -> Arc<NotifyBridge> {
        Arc::new(
            NotifyBridge::start(
                Arc::clone(sink) as Arc<dyn OutgoingSink>,
                "chan".into(),
                wait,
            )
            .expect("bridge"),
        )
    }

    fn send(bridge: &Arc<NotifyBridge>, text: &str) -> Result<ReplyChunks, NotifyError> {
        bridge.notify(NotifyAction::Send(text.to_owned()))
    }

    fn later(by: Duration) -> tokio::time::Instant {
        tokio::time::Instant::now() + by
    }

    #[test]
    fn a_wait_that_ends_cancels_the_queued_job_and_leaves_the_dispatched_one_unknown() {
        let sink = TestSink::new(Mode::Block);
        let bridge = bridge(&sink, Duration::from_millis(150));
        let dispatched = {
            let bridge = Arc::clone(&bridge);
            Run::spawn(&sink, move || send(&bridge, "first"))
        };
        sink.wait_entered(1);
        assert!(
            matches!(send(&bridge, "second"), Err(NotifyError::Cancelled)),
            "a job that never left the queue is cancelled"
        );
        assert!(
            matches!(dispatched.finish(), Err(NotifyError::Unresolved)),
            "a job the worker took is unknown, not cancelled"
        );
        sink.release();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime
            .block_on(bridge.drain_until(later(Duration::from_secs(10))))
            .expect("the released worker stops");
        let sent = sink.sent();
        assert!(sent.contains(&"first".to_owned()), "{sent:?}");
        assert!(
            !sent.contains(&"second".to_owned()),
            "a cancelled job is never sent later: {sent:?}"
        );
    }

    #[test]
    fn close_wakes_queued_waiters_and_refuses_new_jobs_and_is_idempotent() {
        let sink = TestSink::new(Mode::Block);
        let bridge = bridge(&sink, Duration::from_secs(30));
        let dispatched = {
            let bridge = Arc::clone(&bridge);
            Run::spawn(&sink, move || send(&bridge, "first"))
        };
        sink.wait_entered(1);
        let queued = {
            let bridge = Arc::clone(&bridge);
            let (done, finished) = std::sync::mpsc::channel();
            let run = Run::spawn(&sink, move || {
                let outcome = send(&bridge, "second");
                let _ = done.send(());
                outcome
            });
            (run, finished)
        };
        // Wait until the second job is really queued behind the first.
        let start = Instant::now();
        while bridge.shared.core.lock().queue.is_empty() {
            assert!(start.elapsed() < Duration::from_secs(30), "never queued");
            std::thread::sleep(Duration::from_millis(2));
        }
        bridge.close();
        bridge.close();
        queued
            .1
            .recv_timeout(Duration::from_secs(10))
            .expect("close wakes the queued waiter instead of holding it to its wait");
        assert!(matches!(queued.0.finish(), Err(NotifyError::Cancelled)));
        assert!(matches!(send(&bridge, "third"), Err(NotifyError::Closed)));
        sink.release();
        assert!(dispatched.finish().is_ok(), "the in-flight job still lands");
        assert_eq!(sink.sent(), vec!["first".to_owned()]);
    }

    #[tokio::test]
    async fn a_noncooperative_sink_is_a_reported_straggler_and_keeps_its_handle() {
        let sink = TestSink::new(Mode::Block);
        let bridge = bridge(&sink, Duration::from_secs(30));
        let waiting = {
            let bridge = Arc::clone(&bridge);
            let (done, finished) = std::sync::mpsc::channel();
            let run = Run::spawn(&sink, move || {
                let outcome = send(&bridge, "first");
                let _ = done.send(());
                outcome
            });
            (run, finished)
        };
        sink.wait_entered(1);
        bridge
            .drain_until(later(Duration::from_millis(100)))
            .await
            .expect_err("a blocked worker is not a stopped worker");
        assert!(
            bridge.worker.lock().is_some(),
            "the handle stays with its owner until joined"
        );
        waiting
            .1
            .recv_timeout(Duration::from_secs(10))
            .expect("the shared deadline releases the waiting caller");
        assert!(matches!(waiting.0.finish(), Err(NotifyError::Unresolved)));
        assert!(matches!(send(&bridge, "late"), Err(NotifyError::Closed)));

        sink.release();
        bridge
            .drain_until(later(Duration::from_secs(10)))
            .await
            .expect("once the sink answers the worker joins");
        assert!(bridge.worker.lock().is_none());
        assert_eq!(sink.sent(), vec!["first".to_owned()]);
    }

    #[tokio::test]
    async fn the_deadline_cancels_a_cooperative_in_flight_job_and_the_next_drain_joins() {
        let sink = TestSink::new(Mode::Hang);
        let bridge = bridge(&sink, Duration::from_secs(30));
        let waiting = {
            let bridge = Arc::clone(&bridge);
            Run::spawn(&sink, move || send(&bridge, "first"))
        };
        sink.wait_entered(1);
        bridge
            .drain_until(later(Duration::from_millis(100)))
            .await
            .expect_err("the job outlived the deadline");
        assert!(matches!(waiting.finish(), Err(NotifyError::Unresolved)));
        bridge
            .drain_until(later(Duration::from_secs(10)))
            .await
            .expect("a cancelled future lets the worker stop");
        assert!(sink.sent().is_empty(), "the cancelled job never completed");
    }

    #[tokio::test]
    async fn dropping_after_an_expired_drain_does_not_start_another_grace() {
        let sink = TestSink::new(Mode::Block);
        let bridge = bridge(&sink, Duration::from_millis(200));
        let waiting = {
            let bridge = Arc::clone(&bridge);
            Run::spawn(&sink, move || send(&bridge, "first"))
        };
        sink.wait_entered(1);
        bridge
            .drain_until(tokio::time::Instant::now())
            .await
            .expect_err("the noncooperative worker is an unproved straggler");
        assert!(matches!(waiting.finish(), Err(NotifyError::Unresolved)));
        let release = {
            let released = Arc::clone(&sink);
            Run::spawn(&sink, move || {
                std::thread::sleep(Duration::from_secs(1));
                released.release();
            })
        };
        let started = Instant::now();
        drop(bridge);
        let spent = started.elapsed();
        release.finish();
        assert!(
            spent < Duration::from_millis(250),
            "an already expired drain acquired a new destructor grace: {spent:?}"
        );
    }

    #[tokio::test]
    async fn an_idle_delivery_worker_with_runtime_work_cannot_restart_a_spent_drain() {
        struct Release(Arc<TestSink>);
        impl Drop for Release {
            fn drop(&mut self) {
                self.0.release();
            }
        }
        let sink = TestSink::new(Mode::RuntimeBlock);
        let bridge = bridge(&sink, Duration::from_secs(5));
        let _release_on_failure = Release(Arc::clone(&sink));
        assert!(send(&bridge, "first").is_ok());
        sink.wait_entered(2);
        bridge
            .drain_until(tokio::time::Instant::now())
            .await
            .expect_err("runtime work still prevents the worker from ending");
        let release = {
            let released = Arc::clone(&sink);
            Run::spawn(&sink, move || {
                std::thread::sleep(Duration::from_secs(1));
                released.release();
            })
        };
        let started = Instant::now();
        drop(bridge);
        let spent = started.elapsed();
        release.finish();
        let task = sink.blocking.lock().take().unwrap();
        task.await.expect("private blocking runtime task joined");
        assert!(
            spent < Duration::from_millis(250),
            "idle delivery state hid an unbounded runtime join: {spent:?}"
        );
    }

    #[tokio::test]
    async fn drain_joins_an_idle_worker_closes_admission_and_repeats() {
        let sink = TestSink::new(Mode::Pass);
        let bridge = bridge(&sink, Duration::from_secs(30));
        assert!(send(&bridge, "only").is_ok());
        bridge
            .drain_until(later(Duration::from_secs(10)))
            .await
            .expect("an idle worker stops");
        assert!(bridge.worker.lock().is_none(), "the worker was joined");
        bridge
            .drain_until(later(Duration::from_secs(10)))
            .await
            .expect("draining twice is the same stop");
        assert!(matches!(send(&bridge, "after"), Err(NotifyError::Closed)));
        assert_eq!(sink.sent(), vec!["only".to_owned()]);
    }
}
