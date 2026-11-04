//! Write outside the worker mutex so a non-reading payload cannot block a concurrent stop.

use std::fs::File;
use std::io::{ErrorKind, Write};
use std::sync::{Arc, Mutex, TryLockError};
use std::time::{Duration, Instant};

use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};
use rustix::io::fcntl_dupfd_cloexec;

use super::{WorkerAuthority, WorkerError, WorkerErrorCode};

pub const STDIN_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// A separate writer lock prevents frame interleaving without blocking stop.
#[derive(Debug)]
pub struct WorkerStdinWriter {
    pipe: File,
    serial: Arc<Mutex<()>>,
}

impl WorkerStdinWriter {
    pub fn write_timeout(&mut self, bytes: &[u8], timeout: Duration) -> Result<usize, WorkerError> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let deadline = Instant::now() + timeout;
        let _serial = loop {
            match self.serial.try_lock() {
                Ok(guard) => break guard,
                Err(TryLockError::Poisoned(_)) => {
                    return Err(WorkerError::new(
                        WorkerErrorCode::Io,
                        "worker stdin serialization lock is poisoned",
                    ));
                }
                Err(TryLockError::WouldBlock) => {
                    if Instant::now() >= deadline {
                        return Err(stdin_timeout_error(0, bytes.len()));
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        };
        enable_stdin_nonblocking(&mut self.pipe)?;
        let mut written = 0;
        while written < bytes.len() {
            match self.pipe.write(&bytes[written..]) {
                Ok(0) => {
                    return Err(WorkerError::new(
                        WorkerErrorCode::Io,
                        format!("worker stdin pipe accepted zero bytes after {written} written"),
                    ));
                }
                Ok(count) => written += count,
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    if !poll_stdin_writable(&mut self.pipe, deadline)? {
                        return Err(stdin_timeout_error(written, bytes.len()));
                    }
                }
                Err(error) => {
                    return Err(WorkerError::new(
                        WorkerErrorCode::Io,
                        format!(
                            "worker stdin write failed after {written} of {} bytes: {error}",
                            bytes.len()
                        ),
                    ));
                }
            }
        }
        Ok(written)
    }
}

impl WorkerAuthority {
    /// Duplicate stdin so callers can release the worker mutex before polling.
    pub fn stdin_writer(&mut self) -> Result<WorkerStdinWriter, WorkerError> {
        if !self.payload_released {
            return Err(WorkerError::new(
                WorkerErrorCode::PayloadGate,
                "worker stdin is unavailable before payload release",
            ));
        }
        let serial = Arc::clone(&self.stdin_serial);
        let stdin =
            self.held_leader_mut()?.stdin.as_ref().ok_or_else(|| {
                WorkerError::new(WorkerErrorCode::Io, "worker stdin pipe is closed")
            })?;
        let duplicated = fcntl_dupfd_cloexec(stdin, 0).map_err(|error| {
            WorkerError::new(
                WorkerErrorCode::Io,
                format!("cannot duplicate worker stdin pipe: {error}"),
            )
        })?;
        Ok(WorkerStdinWriter {
            pipe: File::from(duplicated),
            serial,
        })
    }

    /// StopAuthority callers use `stdin_writer` to write outside the worker mutex.
    pub fn write_stdin_timeout(
        &mut self,
        bytes: &[u8],
        timeout: Duration,
    ) -> Result<usize, WorkerError> {
        self.stdin_writer()?.write_timeout(bytes, timeout)
    }

    pub fn close_stdin(&mut self) -> Result<(), WorkerError> {
        if !self.payload_released {
            return Err(WorkerError::new(
                WorkerErrorCode::PayloadGate,
                "worker stdin cannot close before payload release",
            ));
        }
        self.held_leader_mut()?.stdin.take();
        Ok(())
    }
}

fn stdin_timeout_error(written: usize, requested: usize) -> WorkerError {
    WorkerError::new(
        WorkerErrorCode::WriteTimeout,
        format!("worker stdin write timed out: wrote {written} of {requested} bytes"),
    )
}

/// Shared file-status flags keep every duplicated writer nonblocking so writes cannot delay stop.
fn enable_stdin_nonblocking(pipe: &mut File) -> Result<(), WorkerError> {
    let flags = fcntl_getfl(&*pipe)
        .map_err(|error| WorkerError::new(WorkerErrorCode::Io, error.to_string()))?;
    if flags.contains(OFlags::NONBLOCK) {
        return Ok(());
    }
    fcntl_setfl(&*pipe, flags | OFlags::NONBLOCK)
        .map_err(|error| WorkerError::new(WorkerErrorCode::Io, error.to_string()))
}

/// Waits for duplicated-pipe writability until `deadline`. `Ok(false)` is a
/// clean expiry; a poll error is surfaced, never treated as writability.
fn poll_stdin_writable(pipe: &mut File, deadline: Instant) -> Result<bool, WorkerError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Ok(false);
    }
    let timeout = poll_timeout(&remaining);
    let mut polled = [PollFd::new(&*pipe, PollFlags::OUT)];
    match poll(&mut polled, Some(&timeout)) {
        Ok(0) => Ok(false),
        // Writable, or an error condition the next write surfaces honestly.
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::Interrupted => Ok(true),
        Err(error) => Err(WorkerError::new(WorkerErrorCode::Io, error.to_string())),
    }
}

fn poll_timeout(remaining: &Duration) -> Timespec {
    let nanos = remaining.as_nanos();
    Timespec {
        tv_sec: (nanos / 1_000_000_000).try_into().unwrap_or(i64::MAX),
        tv_nsec: (nanos % 1_000_000_000) as _,
    }
}
