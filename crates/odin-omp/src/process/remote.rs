//! Remote harness streams; forced stops use the registered job worker.

use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;

use async_trait::async_trait;
use odin_ledger::stop::JobStopAction;
use odin_types::WorkerId;
use tokio::io::AsyncRead;

/// The stdin half of one harness carrier: ordered framed writes and a
/// consuming shutdown. Local carriers write through the logical
/// StopAuthority worker; remote carriers write through the exec channel.
/// Nothing above this trait knows which one is running.
#[async_trait]
pub trait HarnessStdin: Send {
    /// Writes the complete frame buffer (already newline-terminated).
    /// A partial write is an error: JSONL framing cannot recover.
    async fn write_all(&mut self, bytes: Vec<u8>) -> io::Result<()>;

    /// Closes stdin so the harness observes EOF and can finish. Consuming:
    /// the local carrier closes the authority-owned pipe, the remote
    /// carrier drops the exec writer half. After this the stdin half is
    /// gone; further writes are refused by the process boundary.
    fn shutdown(self: Box<Self>) -> io::Result<()>;
}

/// Exact terminal evidence a remote transport observed. `clean` means the
/// transport closed with a terminal status (or exit code); `failure` is the
/// exact transport-level reason when the channel broke without one.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RemoteExit {
    /// The exit status the transport reported, when it carries one.
    /// (kube exec reports channel status; exit-code fidelity is
    /// transport-dependent and stays `None` when absent.)
    pub status: Option<i32>,
    /// Whether the carrier closed cleanly with terminal status evidence.
    pub clean: bool,
    /// The exact transport failure when the channel broke without status.
    pub failure: Option<String>,
}

/// One-shot waiter for the carrier's terminal status.
pub type RemoteExitWait = Pin<Box<dyn Future<Output = RemoteExit> + Send>>;

/// One open remote harness channel, decomposed by the factory at attach.
/// The launcher starts only when the factory attaches, so the consumer owns
/// the streams before the first startup frame can exist.
pub struct RemoteHarnessChannel {
    /// The stdin half (exec writer or equivalent).
    pub stdin: Box<dyn HarnessStdin>,
    /// The framed stdout byte stream.
    pub stdout: Box<dyn AsyncRead + Unpin + Send>,
    /// The bounded-drain stderr stream, when the carrier carries one.
    pub stderr: Option<Box<dyn AsyncRead + Unpin + Send>>,
    /// Resolves after stdout EOF so callers can distinguish exit from channel failure.
    pub exit: RemoteExitWait,
}

impl fmt::Debug for RemoteHarnessChannel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteHarnessChannel")
            .field("stderr", &self.stderr.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteHarnessAdmission {
    /// The exact published workload profile id.
    pub profile: String,
    /// The digest-pinned OCI image reference the carrier Job runs.
    pub image: String,
}

/// Typed failure to attach the admitted remote harness. The host factory
/// maps its transport's typed errors verbatim into `detail`; nothing here
/// retries silently.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("remote harness attach failed: {detail}")]
pub struct RemoteAttachError {
    /// The typed transport reason, verbatim from the host factory.
    pub detail: String,
}

/// Composes remote channels from host configuration, never model-provided arguments or environment.
#[async_trait]
pub trait RemoteHarnessFactory: Send + Sync {
    /// Attaches exactly one channel to the admitted carrier, composing the
    /// fixed launcher argv from the admitted profile plus these host-owned
    /// session arguments. Any stdin prelude the pinned launcher protocol
    /// requires (for example environment that cannot ride exec) is written
    /// here, before the channel is handed over — the first stdout frame the
    /// process boundary reads must still be the exact `ready` frame.
    async fn attach(
        &self,
        args: &[String],
        env: &[(String, String)],
    ) -> Result<RemoteHarnessChannel, RemoteAttachError>;

    /// The registered JobWorker id of the carrier Job in the bridge
    /// authority's durable store.
    fn job_worker_id(&self) -> &WorkerId;

    /// The destructive disposition bound for forced stops of this carrier.
    fn stop_action(&self) -> JobStopAction;

    fn admission(&self) -> &RemoteHarnessAdmission;

    /// The host-composed remote process spec this carrier launches in-pod:
    /// the carrier owns the in-image extension binding and the staged
    /// policy carriage, so the process boundary composes from THIS spec —
    /// never from the local harness spec whose paths do not exist in the
    /// confined image.
    fn process_spec(&self) -> super::OmpProcessSpec;
}
