//! `odin compute-sample`: one finite host reading, then exit.
//!
//! The daemon runs this on each declared host. Two collector readings produce
//! a real CPU delta; declared models come from this host's compute facts.
//! There is no loop and no background sampler.

use std::future::Future;
use std::io::{BufRead, Write};
use std::sync::Arc;
use std::time::Duration;

use clap::Args;
use odin_cli::compute_sample::CADENCE;
use odin_domain::huginn as live;
use serde_json::{json, Value};

use super::view::{cause, Client};

#[derive(Debug, Args)]
pub(crate) struct ComputeSampleArgs {
    /// Registry node id this reading is for.
    #[arg(long)]
    node: String,
    /// Registry host id whose compute facts supply model rows.
    #[arg(long)]
    host: String,
}

pub(crate) fn compute_sample(
    arguments: ComputeSampleArgs,
    output: &mut impl Write,
) -> Result<(), String> {
    let sample = odin_cli::compute_sample::take(&arguments.node, &arguments.host)?;
    serde_json::to_writer(&mut *output, &sample).map_err(|error| error.to_string())?;
    writeln!(output).map_err(|error| error.to_string())
}
/// The overview asks while it is open. The authority owns the one cadence;
/// this loop only holds the request, so closing the page drops it.
const COMPUTE_BOUND: Duration = Duration::from_secs(15);
/// Commands from the view, one JSON object per stdin line; `None` at EOF.
pub(super) fn read_commands(
    compute: tokio::sync::watch::Sender<bool>,
) -> tokio::sync::mpsc::Receiver<Value> {
    let (sender, receiver) = tokio::sync::mpsc::channel(64);
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            match serde_json::from_str::<Value>(&line) {
                Ok(command) => {
                    if command.get("t").and_then(Value::as_str) == Some("compute") {
                        if let Some(active) = command.get("active").and_then(Value::as_bool) {
                            compute.send_if_modified(|current| {
                                if *current == active {
                                    false
                                } else {
                                    *current = active;
                                    true
                                }
                            });
                        }
                        continue;
                    }
                    if sender.blocking_send(command).is_err() {
                        break;
                    }
                }
                Err(error) => tracing::warn!("view sent a line that is not JSON: {error}"),
            }
        }
        compute.send_replace(false);
    });
    receiver
}

/// The request future is dropped on deactivation, including while connecting
/// or waiting on a remote host. The authority's shared cadence is what
/// samples; this loop does not start a second collector, and it does not
/// sleep between successful snapshots.
pub(super) async fn compute_loop<F, Fut, E>(
    mut active: tokio::sync::watch::Receiver<bool>,
    mut sample: F,
    mut output: E,
) where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Value, String>>,
    E: FnMut(Value),
{
    loop {
        if !*active.borrow_and_update() {
            if active.changed().await.is_err() {
                break;
            }
            continue;
        }
        tokio::select! {
            biased;
            changed = active.changed() => if changed.is_err() { break; },
            result = sample() => match result {
                Ok(snapshot) if *active.borrow() => {
                    output(json!({ "t": "compute", "snapshot": snapshot }));
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!("compute sample unavailable: {error}");
                    // The overview says why its Computers section is empty,
                    // rather than showing a silent "none".
                    if *active.borrow() {
                        output(json!({ "t": "compute", "error": error }));
                        tokio::select! {
                            changed = active.changed() => if changed.is_err() { break; },
                            () = tokio::time::sleep(CADENCE) => {},
                        }
                    }
                }
            },
        }
    }
}

pub(super) async fn sample_compute(client: Arc<Client>) -> Result<Value, String> {
    tokio::time::timeout(COMPUTE_BOUND, async {
        let mut connection = client.connect().await.map_err(|error| cause(&error))?;
        match connection
            .request(live::HuginnRequest::Compute)
            .await
            .map_err(|error| cause(&error))?
        {
            live::HuginnResponse::Compute(snapshot) => Ok(snapshot),
            _ => Err("unexpected compute response".to_owned()),
        }
    })
    .await
    .map_err(|_| "compute request timed out".to_owned())?
}
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn compute_starts_only_when_open_and_drops_in_flight_sample_on_close() {
        struct Dropped(tokio::sync::mpsc::UnboundedSender<()>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                let _ = self.0.send(());
            }
        }
        let (active, state) = tokio::sync::watch::channel(false);
        let (started, mut starts) = tokio::sync::mpsc::unbounded_channel();
        let (dropped, mut drops) = tokio::sync::mpsc::unbounded_channel();
        let worker = tokio::spawn(compute_loop(
            state,
            move || {
                let started = started.clone();
                let dropped = dropped.clone();
                async move {
                    let _guard = Dropped(dropped);
                    let _ = started.send(());
                    std::future::pending::<Result<Value, String>>().await
                }
            },
            |_| panic!("a cancelled sample must not emit"),
        ));
        tokio::task::yield_now().await;
        assert!(starts.try_recv().is_err());
        active.send_replace(true);
        tokio::time::timeout(Duration::from_secs(1), starts.recv())
            .await
            .unwrap()
            .unwrap();
        active.send_replace(false);
        tokio::time::timeout(Duration::from_secs(1), drops.recv())
            .await
            .unwrap()
            .unwrap();
        tokio::task::yield_now().await;
        assert!(starts.try_recv().is_err());
        active.send_replace(true);
        tokio::time::timeout(Duration::from_secs(1), starts.recv())
            .await
            .unwrap()
            .unwrap();
        drop(active);
        tokio::time::timeout(Duration::from_secs(1), worker)
            .await
            .unwrap()
            .unwrap();
        drops.recv().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_sample_tells_the_view_why_and_retries() {
        let (active, state) = tokio::sync::watch::channel(true);
        let (emitted, mut emissions) = tokio::sync::mpsc::unbounded_channel();
        let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = std::sync::Arc::clone(&attempts);
        let worker = tokio::spawn(compute_loop(
            state,
            move || {
                let counted = std::sync::Arc::clone(&counted);
                async move {
                    counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Err::<Value, _>("authority unreachable".to_owned())
                }
            },
            move |message| {
                let _ = emitted.send(message);
            },
        ));
        let first = tokio::time::timeout(Duration::from_secs(1), emissions.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first["t"], "compute");
        assert_eq!(first["error"], "authority unreachable");
        assert!(first.get("snapshot").is_none());
        // The retry is one cadence later, not a tight loop.
        assert_eq!(
            attempts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the failed sample must wait one cadence before retrying"
        );
        let second = tokio::time::timeout(CADENCE + Duration::from_secs(2), emissions.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second["error"], "authority unreachable");
        drop(active);
        let _ = tokio::time::timeout(Duration::from_secs(2), worker).await;
    }
}
