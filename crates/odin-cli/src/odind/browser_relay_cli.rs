//! Thin odind surfaces for the pod browser relay: `browser-serve` is the
//! container init entry (odin-browser's relay supervisor does everything);
//! `browser-connect` is the host-exec'd one-use attach that speaks the
//! shared typed activation preface and then bridges byte-for-byte. Both
//! are dispatch wrappers only — every mechanism lives in odin-browser.

use std::path::PathBuf;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// Typed CLI input of `odind browser-serve`: the exact argv the admitted
/// launch composes into the browser container. No field is inferred.
pub(crate) struct BrowserServeArgs {
    pub node: PathBuf,
    pub xvfb: PathBuf,
    pub screen: String,
    pub state_dir: PathBuf,
    pub socket: PathBuf,
}

/// Returning from container PID 1 tears down the namespace, even on supervisor failure.
pub(crate) fn serve_entry(args: BrowserServeArgs) -> Result<(), String> {
    let tokio = tokio::runtime::Runtime::new()
        .map_err(|error| format!("browser relay runtime: {error}"))?;
    let report = tokio
        .block_on(odin_browser::relay_supervisor::serve(
            odin_browser::relay_supervisor::ServeInput {
                node: args.node,
                xvfb: args.xvfb,
                screen: args.screen,
                state_dir: args.state_dir,
                socket: args.socket,
            },
        ))
        .map_err(|error| error.to_string())?;
    tracing::info!(
        "browser-serve: session {} ended on display :{} (worker_exit={:?}, xvfb_reaped={}, \
         display_residue_absent={})",
        report.session,
        report.display_number,
        report.worker_exit,
        report.xvfb_reaped,
        report.display_residue_absent
    );
    Ok(())
}

/// Typed CLI input of `odind browser-connect`: the one-use attach command
/// the host execs. The session identity rides the activation preface on
/// the private socket, never on the protocol channel.
pub(crate) struct BrowserConnectArgs {
    pub socket: PathBuf,
    pub session: String,
}

/// Runs the one-use attach under this entry's own runtime. Both bridge
/// halves are cancelable async tasks: whichever side of the relay ends
/// first ends the attach, the other half is aborted and awaited, and this
/// entry then EXITS THE PROCESS explicitly — tokio's stdin bridge parks on
/// a blocking read, so the bounded drain is followed by `process::exit`
/// instead of a runtime drop that would wait on it. The supervisor owns
/// the truth about the session: either relay ending is a clean exit
/// unless a real IO error occurred.
pub(crate) fn connect_entry(args: BrowserConnectArgs) -> ! {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!("browser-connect: browser relay runtime: {error}");
            std::process::exit(1);
        }
    };
    let outcome = runtime.block_on(connect(args));
    match outcome {
        Ok(()) => {
            tracing::info!("browser-connect: relay ended");
            std::process::exit(0);
        }
        Err(detail) => {
            tracing::error!("browser-connect: {detail}");
            std::process::exit(1);
        }
    }
}

/// The bounded wait for the worker's tail after stdin EOF. The supervisor
/// closes its half promptly once the relay ends; anything longer is a lost
/// stream and fails the attach.
const RELAY_DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(30);

async fn connect(args: BrowserConnectArgs) -> Result<(), String> {
    let preface = odin_browser::relay_supervisor::ActivationPreface {
        v: odin_browser::relay_supervisor::ACTIVATION_VERSION,
        session: args.session,
    }
    .encode()?;
    let mut socket = tokio::net::UnixStream::connect(&args.socket)
        .await
        .map_err(|error| {
            format!(
                "cannot connect to the relay socket {}: {error}",
                args.socket.display()
            )
        })?;
    socket
        .write_all(&preface)
        .await
        .map_err(|error| format!("cannot send the activation preface: {error}"))?;

    bridge(tokio::io::stdin(), tokio::io::stdout(), socket).await
}

/// Relay EOF cancels and awaits input; stdin EOF half-closes the socket and
/// drains output within [`RELAY_DRAIN_GRACE`]. Copy, join, and flush failures
/// fail the attach; only deliberate cancellation of pending input is ignored.
async fn bridge<R, W, S>(mut input: R, mut output: W, relay: S) -> Result<(), String>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut relay_read, mut relay_write) = tokio::io::split(relay);
    let mut upstream = tokio::spawn(async move {
        // stdin EOF ends this half: the worker's stdin closes, which is
        // the host's half of the graceful stop. The half-close below is
        // that signal, sent whichever way the copy itself ended.
        let copied = tokio::io::copy(&mut input, &mut relay_write).await;
        let _ = relay_write.shutdown().await;
        copied
    });
    let mut downstream = tokio::spawn(async move {
        // The worker's tail rides this half; it is drained to real EOF
        // and flushed BEFORE the attach ends, so no final bytes are lost.
        let copied = tokio::io::copy(&mut relay_read, &mut output).await?;
        output.flush().await?;
        Ok(copied)
    });
    let (upstream_result, downstream_result) = tokio::select! {
        biased;
        result = &mut downstream => {
            upstream.abort();
            let upstream_result = match upstream.await {
                Ok(copied) => Some(copied),
                Err(join) if join.is_cancelled() => None,
                Err(join) => Some(Err(std::io::Error::other(join.to_string()))),
            };
            (
                upstream_result,
                result.unwrap_or_else(|join| Err(std::io::Error::other(join.to_string()))),
            )
        }
        result = &mut upstream => {
            let upstream_result =
                result.unwrap_or_else(|join| Err(std::io::Error::other(join.to_string())));
            let downstream_result = if upstream_result.is_err() {
                // A broken input stream ends the attach promptly: the
                // tail is only ever the residue of a stream that already
                // failed, so the pending downstream is cancelled and
                // awaited; the upstream error decides the exit.
                downstream.abort();
                let _ = downstream.await;
                Ok(0)
            } else {
                match tokio::time::timeout(RELAY_DRAIN_GRACE, &mut downstream).await {
                    Ok(joined) => joined.unwrap_or_else(|join| {
                        Err(std::io::Error::other(join.to_string()))
                    }),
                    Err(_) => {
                        tracing::error!("browser-connect: the relay tail never drained");
                        // The expired timeout only borrowed the handle:
                        // reap the abandoned tail so no task outlives
                        // the selection.
                        downstream.abort();
                        let _ = downstream.await;
                        Err(std::io::Error::other(
                            "the final downstream drain exceeded its bound",
                        ))
                    }
                }
            };
            (Some(upstream_result), downstream_result)
        }
    };
    match (upstream_result, downstream_result) {
        (Some(Err(error)), _) => Err(format!("upstream copy failed: {error}")),
        (_, Err(error)) => Err(format!("downstream copy failed: {error}")),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::bridge;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

    /// The bridge must end on its own well inside this bound: hanging
    /// fails the test instead of waiting forever.
    const TEST_GUARD: Duration = Duration::from_secs(10);

    fn socket_pair() -> (tokio::net::UnixStream, tokio::net::UnixStream) {
        tokio::net::UnixStream::pair().expect("socket pair")
    }

    /// Accepts every byte the copy loop writes, then loses the tail at
    /// the final stdout flush.
    struct FlushBreaker;

    impl AsyncWrite for FlushBreaker {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Err(std::io::Error::other("the stdout flush lost the tail")))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn relay_side_eof_ends_the_attach_while_stdin_is_held_open() {
        let (relay, mut worker) = socket_pair();
        let (input, input_peer) = socket_pair();
        let (output, mut output_peer) = socket_pair();
        let tail = b"tail: worker ended\n";

        // The relay side delivers its final tail and ends; stdin stays
        // open with no data for the whole attach.
        worker.write_all(tail).await.expect("tail write");
        drop(worker);

        let bridged = tokio::time::timeout(TEST_GUARD, bridge(input, output, relay))
            .await
            .expect("relay-side EOF must end the attach instead of hanging on open stdin");
        assert!(
            bridged.is_ok(),
            "a clean relay-side end is a clean attach: {bridged:?}"
        );

        // The tail reached real stdout before the attach ended.
        let mut delivered = Vec::new();
        output_peer
            .read_to_end(&mut delivered)
            .await
            .expect("tail read");
        assert_eq!(delivered, tail);
        let _stdin_still_open = input_peer;
    }

    #[tokio::test]
    async fn upstream_copy_failure_fails_the_attach_instead_of_exit_zero() {
        // Only the worker's READ half is shut down: relay writes fail
        // with a real EPIPE, and the retained worker write half keeps
        // the downstream pending for the WHOLE assertion — the upstream
        // failure is the attach's only possible completion, with no
        // timer ordering anywhere.
        let (relay_std, worker_std) = std::os::unix::net::UnixStream::pair().expect("socket pair");
        relay_std.set_nonblocking(true).expect("nonblocking relay");
        worker_std
            .set_nonblocking(true)
            .expect("nonblocking worker");
        worker_std
            .shutdown(std::net::Shutdown::Read)
            .expect("shutdown worker read half");
        let relay = tokio::net::UnixStream::from_std(relay_std).expect("relay stream");
        let _worker_writer = tokio::net::UnixStream::from_std(worker_std).expect("worker stream");

        let (input, mut input_peer) = socket_pair();
        let (output, _output_peer) = socket_pair();

        // The host still has one byte on an open stdin.
        input_peer.write_all(b"q").await.expect("input byte");

        let bridged = tokio::time::timeout(TEST_GUARD, bridge(input, output, relay))
            .await
            .expect("a broken relay must fail fast instead of hanging");
        let detail = bridged.expect_err("a lost upstream stream must fail, never exit 0");
        assert!(
            detail.starts_with("upstream copy failed:"),
            "unexpected attach detail: {detail}"
        );
    }

    #[tokio::test]
    async fn stdout_flush_failure_fails_the_attach_instead_of_exit_zero() {
        let (relay, mut worker) = socket_pair();
        let (input, _input_peer) = socket_pair();

        // The relay side ends cleanly after one tail write, but the
        // host's stdout accepts the bytes and then fails the flush.
        worker.write_all(b"tail").await.expect("tail write");
        drop(worker);

        let bridged = tokio::time::timeout(TEST_GUARD, bridge(input, FlushBreaker, relay))
            .await
            .expect("a failing flush must fail fast instead of hanging");
        let detail = bridged.expect_err("a lost stdout flush must fail, never exit 0");
        assert!(
            detail.starts_with("downstream copy failed:"),
            "unexpected attach detail: {detail}"
        );
    }

    /// The host's graceful stop: stdin EOF must half-close the relay
    /// write half — the worker observes EOF after exactly the host's
    /// bytes — and the worker's final tail must survive to real stdout.
    #[tokio::test]
    async fn graceful_stdin_eof_halfcloses_the_relay_and_preserves_the_tail() {
        let (relay, worker) = socket_pair();
        let (input, mut input_peer) = socket_pair();
        let (output, mut output_peer) = socket_pair();
        let host_input = b"host typing\n";
        let tail = b"tail: final report\n";

        // The host writes its session input and closes stdin.
        input_peer.write_all(host_input).await.expect("host input");
        drop(input_peer);

        // The worker reads up to the half-closed relay write half, then
        // answers with its final tail.
        let worker = tokio::spawn(async move {
            let mut worker = worker;
            let mut received = Vec::new();
            worker.read_to_end(&mut received).await?;
            assert_eq!(
                received, host_input,
                "half-close must deliver exactly the host bytes"
            );
            worker.write_all(tail).await?;
            worker.flush().await?;
            Ok::<_, std::io::Error>(())
        });

        let bridged = tokio::time::timeout(TEST_GUARD, bridge(input, output, relay))
            .await
            .expect("a graceful stop must end within the bounded drain");
        assert!(
            bridged.is_ok(),
            "graceful stdin EOF is a clean attach: {bridged:?}"
        );
        worker.await.expect("worker task").expect("worker relay");

        let mut delivered = Vec::new();
        output_peer
            .read_to_end(&mut delivered)
            .await
            .expect("tail read");
        assert_eq!(delivered, tail);
    }
}
