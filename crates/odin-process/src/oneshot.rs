use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rustix::io::Errno;
use rustix::process::{kill_process_group, waitid, Pid, Signal, WaitId, WaitIdOptions};

use crate::output::OutputCollector;
use crate::CapturedOutput;

/// How often a running child and its pipes are checked.
const POLL: Duration = Duration::from_millis(10);
/// How long a descendant may hold the output pipes after the leader exits.
const DRAIN_GRACE: Duration = Duration::from_secs(2);
/// How long a killed group's leader gets to be reaped (a D-state child cannot hang the caller).
const REAP_GRACE: Duration = Duration::from_secs(2);
/// How long to wait before retrying a text-file-busy spawn.
const SPAWN_RETRY: Duration = Duration::from_millis(5);

/// The bounds of one plain child: a wall-clock limit and a byte ceiling per captured stream.
#[derive(Clone, Copy, Debug)]
pub struct ChildBounds {
    pub timeout: Duration,
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
}

#[derive(Debug)]
pub struct ChildOutput {
    /// `None` when the group was killed: at the timeout, or when a
    /// descendant still held the output pipes after the leader exited.
    pub status: Option<ExitStatus>,
    pub stdout: CapturedOutput,
    pub stderr: CapturedOutput,
}

impl ChildOutput {
    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(self.stdout.as_bytes()).into_owned()
    }

    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(self.stderr.as_bytes()).into_owned()
    }
}

/// Runs one child to completion in its own process group: stdin carries
/// `input` (or nothing), both output streams are captured up to their
/// ceilings (the rest is read and discarded so the child never blocks), and
/// at the timeout the whole group is killed. Output is complete only at end
/// of file, so a descendant still holding the pipes after the leader exits
/// gets a short grace and is then killed with the group. The leader stays
/// unreaped until then, so its group id cannot be reused.
pub fn run_bounded(
    command: &mut Command,
    input: Option<Vec<u8>>,
    bounds: ChildBounds,
) -> io::Result<ChildOutput> {
    let deadline = Instant::now() + bounds.timeout;
    command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = spawn_past_busy_text(command, deadline)?;
    let leader = Pid::from_child(&child);
    let outcome = supervise(&mut child, leader, input, bounds, deadline);
    if outcome.is_err() {
        // The leader is still unreaped here, so its group id is still its own.
        let _ = kill_process_group(leader, Signal::KILL);
        let _ = reap(&mut child);
    }
    outcome
}

fn supervise(
    child: &mut Child,
    leader: Pid,
    input: Option<Vec<u8>>,
    bounds: ChildBounds,
    deadline: Instant,
) -> io::Result<ChildOutput> {
    if let (Some(input), Some(mut pipe)) = (input, child.stdin.take()) {
        // Detached: a child that never reads its input must not hold the caller.
        thread::spawn(move || pipe.write_all(&input));
    }
    let (Some(mut stdout), Some(mut stderr)) = (child.stdout.take(), child.stderr.take()) else {
        unreachable!("both output streams are piped");
    };
    crate::runner::set_nonblocking(&stdout).map_err(io::Error::other)?;
    crate::runner::set_nonblocking(&stderr).map_err(io::Error::other)?;
    let mut out = OutputCollector::new(bounds.max_stdout_bytes);
    let mut err = OutputCollector::new(bounds.max_stderr_bytes);
    let (mut out_done, mut err_done, mut exited) = (false, false, false);
    let mut limit = deadline;
    loop {
        out_done = out_done || out.drain(&mut stdout)?;
        err_done = err_done || err.drain(&mut stderr)?;
        if !exited
            && waitid(
                WaitId::Pid(leader),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
            )?
            .is_some()
        {
            exited = true;
            limit = limit.min(Instant::now() + DRAIN_GRACE);
        }
        if exited && out_done && err_done {
            return Ok(ChildOutput {
                status: Some(child.wait()?),
                stdout: out.finish(),
                stderr: err.finish(),
            });
        }
        let left = limit.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        thread::sleep(POLL.min(left));
    }
    match kill_process_group(leader, Signal::KILL) {
        Ok(()) | Err(Errno::SRCH) => {}
        Err(error) => {
            let group = child.id();
            return Err(io::Error::other(format!(
                "process group {group} kill: {error}"
            )));
        }
    }
    out.drain(&mut stdout)?;
    err.drain(&mut stderr)?;
    reap(child)?;
    Ok(ChildOutput {
        status: None,
        stdout: out.finish(),
        stderr: err.finish(),
    })
}

fn reap(child: &mut Child) -> io::Result<()> {
    let until = Instant::now() + REAP_GRACE;
    while child.try_wait()?.is_none() && Instant::now() < until {
        thread::sleep(POLL);
    }
    Ok(())
}

/// Spawns, retrying `ETXTBSY` until the deadline. Exec refuses an executable
/// some process still holds open for writing, and that holder can be any
/// fork that inherited the writer's descriptor for the instant before its
/// own exec — a script just written, or a binary being replaced during
/// activation. The window closes in microseconds; any other spawn error is
/// final.
fn spawn_past_busy_text(command: &mut Command, deadline: Instant) -> io::Result<Child> {
    loop {
        match command.spawn() {
            Err(error)
                if error.kind() == io::ErrorKind::ExecutableFileBusy
                    && Instant::now() < deadline =>
            {
                thread::sleep(SPAWN_RETRY);
            }
            outcome => return outcome,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::{env, fs};

    const BOUNDS: ChildBounds = ChildBounds {
        timeout: Duration::from_millis(400),
        max_stdout_bytes: 1024,
        max_stderr_bytes: 1024,
    };

    #[test]
    fn a_descendant_holding_the_pipes_cannot_outlive_the_deadline() {
        let sleep = env::split_paths(&env::var_os("PATH").unwrap_or_default())
            .map(|dir| dir.join("sleep"))
            .find(|candidate| candidate.is_file())
            .expect("sleep is on PATH");
        let root = tempfile::tempdir().expect("tempdir");
        let script = root.path().join("detach");
        fs::write(
            &script,
            format!("#!/bin/sh\n'{}' 5 &\necho started\n", sleep.display()),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let started = Instant::now();
        let outcome =
            run_bounded(&mut Command::new(&script), None, BOUNDS).expect("the bounded child runs");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "returned after {:?}",
            started.elapsed()
        );
        assert!(
            outcome.status.is_none(),
            "a held pipe past the deadline is a timeout"
        );
    }

    #[test]
    fn a_child_past_its_deadline_dies_with_its_whole_group() {
        let sleep = env::split_paths(&env::var_os("PATH").unwrap_or_default())
            .map(|dir| dir.join("sleep"))
            .find(|candidate| candidate.is_file())
            .expect("sleep is on PATH");
        let root = tempfile::tempdir().expect("tempdir");
        let pid_file = root.path().join("descendant.pid");
        let script = root.path().join("hang");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\n'{}' 60 &\necho $! > '{}'\nwait\n",
                sleep.display(),
                pid_file.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let outcome =
            run_bounded(&mut Command::new(&script), None, BOUNDS).expect("the bounded child runs");
        assert!(outcome.status.is_none());
        let descendant = fs::read_to_string(&pid_file).expect("descendant pid");
        let proc_dir = format!("/proc/{}", descendant.trim());
        let gone = Instant::now() + Duration::from_secs(5);
        while Path::new(&proc_dir).exists()
            && fs::read_to_string(format!("{proc_dir}/stat"))
                .is_ok_and(|stat| !stat.contains(") Z "))
            && Instant::now() < gone
        {
            thread::sleep(Duration::from_millis(50));
        }
        let alive =
            fs::read_to_string(format!("{proc_dir}/stat")).is_ok_and(|stat| !stat.contains(") Z "));
        assert!(
            !alive,
            "the descendant {descendant} outlived the group kill"
        );
    }
}
