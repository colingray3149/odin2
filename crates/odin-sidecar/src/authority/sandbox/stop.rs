//! Retire workers through StopAuthority and join readers before returning the effector result.

use std::io::Read;
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use odin_domain::StopVerdict;
use odin_kernel::stop::StopAuthority;
use odin_types::WorkerId;
use rustix::event::{poll, PollFd, PollFlags, Timespec};

use super::{EFFECT_POLL, ROUNDTRIP_BROKER_SHUTDOWN};

#[derive(Default)]
pub(super) struct EffectReaders {
    pub(super) stdout: Option<std::thread::JoinHandle<()>>,
    pub(super) stderr: Option<std::thread::JoinHandle<()>>,
    stop: Arc<AtomicBool>,
}

impl EffectReaders {
    pub(super) fn stoppable<R>(&self, pipe: R) -> StoppablePipe<R> {
        StoppablePipe {
            pipe,
            stop: Arc::clone(&self.stop),
        }
    }

    /// Stop polling at the deadline so a surviving process holding a pipe cannot keep readers alive.
    pub(super) fn join(self) -> Result<(), String> {
        let deadline = std::time::Instant::now() + ROUNDTRIP_BROKER_SHUTDOWN;
        let mut outcome = Ok(());
        for (name, reader) in [("stdout", self.stdout), ("stderr", self.stderr)] {
            let Some(reader) = reader else { continue };
            while !reader.is_finished() && std::time::Instant::now() < deadline {
                std::thread::sleep(EFFECT_POLL);
            }
            if !reader.is_finished() {
                self.stop.store(true, Ordering::Release);
                outcome = outcome.and(Err(format!(
                    "effector {name} reader did not close after cleanup"
                )));
            }
            if reader.join().is_err() {
                outcome = outcome.and(Err(format!("effector {name} reader panicked")));
            }
        }
        outcome
    }
}

pub(super) struct StoppablePipe<R> {
    pipe: R,
    stop: Arc<AtomicBool>,
}

impl<R: Read + AsFd> Read for StoppablePipe<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let interval = Timespec {
            tv_sec: 0,
            tv_nsec: 50_000_000,
        };
        loop {
            if self.stop.load(Ordering::Acquire) {
                return Err(std::io::Error::other("the effect reader was stopped"));
            }
            let mut polled = [PollFd::new(&self.pipe, PollFlags::IN)];
            match poll(&mut polled, Some(&interval)) {
                Ok(0) | Err(rustix::io::Errno::INTR) => {}
                Ok(_) => return self.pipe.read(buf),
                Err(error) => return Err(error.into()),
            }
        }
    }
}

/// Process-group observations supplement the worker identity but do not authorize signaling.
pub(super) fn in_flight_identity(
    worker: &odin_kernel::stop::WorkerIdentity,
) -> Option<odin_kernel::ProcessIdentity> {
    let pid = i32::try_from(worker.leader_pid).ok()?;
    let raw = std::fs::read_to_string(format!("/proc/{}/stat", worker.leader_pid)).ok()?;
    let mut fields = raw.rsplit(')').next()?.split_whitespace();
    let pgrp = fields.nth(2)?.parse::<i32>().ok()?;
    Some(odin_kernel::ProcessIdentity {
        pid,
        start_time_ticks: worker.leader_start_ticks,
        process_group: pgrp,
    })
}

pub(super) fn retire_effector(stop: &StopAuthority, worker_id: &WorkerId) -> Result<(), String> {
    let outcome = stop
        .stop_worker(worker_id)
        .map_err(|error| error.to_string())?;
    if outcome.verdict == StopVerdict::Stopped {
        Ok(())
    } else {
        Err(format!(
            "effector {worker_id} stop was not proved: {:?}",
            outcome.verdict
        ))
    }
}
