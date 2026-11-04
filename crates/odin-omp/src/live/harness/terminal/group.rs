//! A tmux client run as its own process group: a cancellation or drop takes the whole group down.

use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use rustix::process::{kill_process_group, Pid, Signal};
use tokio::io::AsyncReadExt;
use tokio::process::Command;

/// How long a cancelled client's drop waits to reap the group-killed
/// child before surfacing that it could not.
const GROUP_REAP_WINDOW: Duration = Duration::from_millis(500);
/// The reap poll inside [`GROUP_REAP_WINDOW`].
const GROUP_REAP_POLL: Duration = Duration::from_millis(5);

/// The tmux client command against the session's socket.
pub(super) fn tmux_command(tmux: &Path, socket: &Path, path: &str) -> Command {
    let mut command = Command::new(tmux);
    command
        .arg("-S")
        .arg(socket)
        .env("PATH", path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command
}

/// A tmux client child in its own process group. `process_group(0)` is
/// set before spawn, so the child's PID is its group's: a cancellation or
/// drop takes the whole group down (`tmux` may have forked while
/// connecting to the server), and the builder's `kill_on_drop` stays as
/// the direct-child backstop. Output is drained before reaping, keeping
/// the group leader's PID reserved until group cleanup is disarmed.
pub(super) struct GroupChild {
    pub(super) child: Option<tokio::process::Child>,
    pub(super) group: u32,
}

impl GroupChild {
    pub(super) fn spawn(client: &mut Command) -> Result<Self, std::io::Error> {
        client.process_group(0);
        let child = client.spawn()?;
        let group = child
            .id()
            .ok_or_else(|| std::io::Error::other("client exited before its group was known"))?;
        Ok(Self {
            child: Some(child),
            group,
        })
    }

    /// Waits for exit and collects the output. Normal completion never
    /// signals the group: the child was reaped, and the pid may belong to
    /// an unrelated group by now.
    pub(super) async fn output(mut self) -> std::io::Result<std::process::Output> {
        let child = self
            .child
            .as_mut()
            .expect("client present until completion");
        // Do not transfer the child into wait_with_output: cancellation
        // would drop it outside this guard and leave its descendants alive.
        // Drain both pipes before waiting so even an exited leader stays
        // unreaped (and its group id cannot be reused) while reads are pending.
        drop(child.stdin.take());
        let mut stdout = child.stdout.take();
        let mut stderr = child.stderr.take();
        let mut stdout_bytes = Vec::new();
        let mut stderr_bytes = Vec::new();
        tokio::try_join!(
            async {
                if let Some(pipe) = stdout.as_mut() {
                    pipe.read_to_end(&mut stdout_bytes).await?;
                }
                Ok::<_, std::io::Error>(())
            },
            async {
                if let Some(pipe) = stderr.as_mut() {
                    pipe.read_to_end(&mut stderr_bytes).await?;
                }
                Ok::<_, std::io::Error>(())
            }
        )?;
        let status = child.wait().await?;
        // No await between the reap and disarming the group cleanup.
        self.child = None;
        Ok(std::process::Output {
            status,
            stdout: stdout_bytes,
            stderr: stderr_bytes,
        })
    }
}

impl Drop for GroupChild {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        // The child owns this group (it was grouped before spawn), so the
        // kill reaches every process tmux forked and cannot reach ours.
        if let Some(group) = i32::try_from(self.group).ok().and_then(Pid::from_raw) {
            let _ = kill_process_group(group, Signal::KILL);
        }
        // Bounded reap: the cancellation must produce evidence, not hand
        // a killed group to the orphan queue unseen. A SIGKILL'd client is
        // reaped here unless the kernel holds it uninterruptibly.
        let deadline = Instant::now() + GROUP_REAP_WINDOW;
        loop {
            match child.try_wait() {
                Ok(Some(_status)) => return,
                Ok(None) if Instant::now() < deadline => std::thread::sleep(GROUP_REAP_POLL),
                Ok(None) => break,
                Err(_error) => break,
            }
        }
        tracing::error!(
            "odind: terminal client group={} was killed but not reaped within its bound",
            self.group
        );
    }
}
