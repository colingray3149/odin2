//! Internal in-pod passive carrier boundary: `odind workload-park`.
//!
//! A confined workload pod starts no workload process of its own — the host
//! execs the carrier argv only at session open ([`super::workload_exec`]) —
//! so between pod start and that attach its init must stay alive, start
//! nothing, and reap whatever the runtime reparents to it. This mode is that
//! carrier: the image identity's own declared odind entrypoint, the same
//! in-image bytes the host-side exec transport launches later, composed by
//! the admitted workload launch (`kube_runtime::launch::workload_profile_launch`)
//! with exactly [`PASSIVE_ARGV`] — admitted material, never a fabricated
//! shell idiom and never a new runtime dependency.
//!
//! Invariants:
//!
//! * Signal delivery is the only wake-up: no timer, no poll loop, no sleep,
//!   and never a launcher, model, or OMP process.
//! * `SIGTERM`/`SIGINT` (the pod-level stop) return `Ok(())`; the clean exit
//!   is the whole shutdown. Installing that handler is mandatory, because
//!   the kernel never forcibly delivers a signal whose default action is
//!   termination to a PID-namespace init from inside its own namespace —
//!   the rule that defeated the previous self-`SIGSTOP` shell carrier.
//! * `SIGCHLD` drains `waitpid(-1)`, so no reparented child lingers as a
//!   zombie under this init.

use std::io::{self, Write as _};

use rustix::io::Errno;
use rustix::process::{wait, WaitOptions};
use signal_hook::consts::{SIGCHLD, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

/// The exact argv the admitted workload launch composes as the carrier pod's
/// init argument list: the odind clap surface declares exactly this hidden
/// subcommand, so the mechanism has one spelling on both sides.
pub(crate) const PASSIVE_ARGV: &str = "workload-park";

/// Runs the passive carrier until a stop signal arrives. `Ok(())` is the
/// clean exit the pod-level stop produces; every arming or servicing failure
/// is typed, never a silent exit.
pub(crate) fn park() -> Result<(), String> {
    let signals = arm()?;
    // Diagnostic only and never load-bearing: a closed control pipe must not
    // be able to turn a log line into a silent exit.
    let _ = writeln!(
        io::stderr(),
        "odind: passive carrier idle; no launcher runs before attach"
    );
    serve(signals)
}

/// Arms the signal registration, then drains anything that already exited.
/// A signal received before the registration has no handler to run it, so an
/// adopted child that exited first is collected by the drain instead of
/// being awaited for ever.
fn arm() -> Result<Signals, String> {
    let signals = Signals::new([SIGTERM, SIGINT, SIGCHLD])
        .map_err(|error| format!("could not arm the carrier stop signals: {error}"))?;
    reap_adopted_children()?;
    Ok(signals)
}

fn serve(mut signals: Signals) -> Result<(), String> {
    // `wait` blocks on the registration's own channel until a registered
    // signal arrives; the outer loop only covers its documented
    // empty-batch case.
    loop {
        for signal in signals.wait() {
            match signal {
                SIGCHLD => reap_adopted_children()?,
                // The pod-level stop: nothing else runs here, so the clean
                // return is the whole shutdown.
                SIGTERM | SIGINT => return Ok(()),
                // The registration admits exactly the signals above.
                _ => {}
            }
        }
    }
}

/// Drains the children this init has adopted: `wait(-1)` without blocking
/// until no reapable child remains (`wait` is rustix's "any child" form —
/// `waitpid(None, ..)` would select only the caller's own process group and
/// a reparented child keeps the group it was born in). `ECHILD` is the
/// drained terminal state (nothing has exited), `EINTR` resumes the drain.
fn reap_adopted_children() -> Result<(), String> {
    loop {
        match wait(WaitOptions::NOHANG) {
            Ok(Some(_)) => {}
            Ok(None) => return Ok(()),
            Err(error) if error == Errno::CHILD => return Ok(()),
            Err(error) if error == Errno::INTR => {}
            Err(error) => {
                return Err(format!(
                    "the passive carrier could not reap an adopted child: {error}"
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt as _;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// Re-exec in a separate process so waitpid(-1) cannot reap sibling tests' children.
    /// This covers signal/reap/stop behavior, not PID-namespace adoption.
    const PARK_TEST_PATH: &str =
        "workload_park::tests::the_passive_carrier_idles_reaps_and_exits_on_stop";
    /// `carrier` runs the lifecycle, `leaf` exits at once (its exit is the
    /// SIGCHLD the parked carrier must reap without stopping).
    const PARK_MODE_VAR: &str = "ODIN_WORKLOAD_PARK_TEST_MODE";
    /// No arm trusts libtest's filter to have selected it: each writes an ack
    /// file, so a stale test path fails loudly instead of passing vacuously
    /// with zero tests run.
    const CARRIER_ACK_VAR: &str = "ODIN_WORKLOAD_PARK_CARRIER_ACK";
    const LEAF_ACK_VAR: &str = "ODIN_WORKLOAD_PARK_LEAF_ACK";
    /// The parent's guard: the carrier child must settle inside it, or the
    /// parent kills it and fails instead of hanging the suite.
    const CARRIER_BOUND: Duration = Duration::from_secs(30);

    /// A per-process marker path under the test system's temporary dir.
    fn ack_path(arm: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("odin-workload-park-{arm}-{}", std::process::id()))
    }

    fn harness_child(mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().expect("test harness path"));
        command.args(["--exact", PARK_TEST_PATH, "--test-threads", "1"]);
        command.env(PARK_MODE_VAR, mode);
        command
    }

    /// The state of one pid read from `/proc`, so an exit is observed without
    /// a second wait: `None` once the pid is gone, which for a child of this
    /// process only its parent's reap can have produced.
    fn proc_state(pid: u32) -> Option<char> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let (_, rest) = stat.rsplit_once(')')?;
        rest.split_whitespace().next()?.chars().next()
    }

    #[test]
    fn the_passive_carrier_idles_reaps_and_exits_on_stop() {
        match std::env::var(PARK_MODE_VAR).as_deref() {
            Ok("leaf") => leaf_case(),
            Ok("carrier") => {
                std::fs::write(
                    std::env::var(CARRIER_ACK_VAR).expect("carrier ack path"),
                    b"carrier",
                )
                .expect("carrier ack");
                carrier_case()
            }
            _ => {
                let ack = ack_path("carrier");
                let _ = std::fs::remove_file(&ack);
                let mut child = harness_child("carrier")
                    .env(CARRIER_ACK_VAR, &ack)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .expect("carrier child");
                let deadline = Instant::now() + CARRIER_BOUND;
                let status = loop {
                    if let Some(status) = child.try_wait().expect("carrier child state") {
                        break status;
                    }
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        panic!("the carrier child outlived its bound and was killed");
                    }
                    std::thread::sleep(Duration::from_millis(20));
                };
                // Both streams are piped and read only after the child is
                // gone: one test's libtest output is far below the pipe
                // bound, and neither stream is ever inherited (a spawned
                // child's fd writes would escape libtest's capture).
                let mut output = String::new();
                if let Some(mut pipe) = child.stdout.take() {
                    let _ = std::io::Read::read_to_string(&mut pipe, &mut output);
                }
                if let Some(mut pipe) = child.stderr.take() {
                    let _ = std::io::Read::read_to_string(&mut pipe, &mut output);
                }
                assert!(
                    ack.is_file(),
                    "the carrier arm never ran (the harness filter matched nothing): {output}"
                );
                let _ = std::fs::remove_file(&ack);
                assert!(
                    status.success(),
                    "the isolated carrier must reap and exit cleanly: {output}"
                );
            }
        }
    }

    /// Acknowledge execution before exiting so an incorrect test filter cannot pass.
    fn leaf_case() -> ! {
        std::fs::write(std::env::var(LEAF_ACK_VAR).expect("leaf ack path"), b"leaf")
            .expect("leaf ack");
        std::process::exit(0)
    }

    /// The real lifecycle, in its own process. Evidence is recorded, never
    /// panicked mid-flight: the stop below must run under every outcome, or
    /// a parked carrier would outlive the test.
    ///
    /// The leaf child is deliberately never `wait`ed on from here: the reap
    /// under test is what must collect it, and waiting on it here would both
    /// steal that evidence and hide the defect this test exists to catch.
    #[allow(clippy::zombie_processes)]
    fn carrier_case() {
        let signals = arm().expect("carrier signal registration");
        let leaf_ack = ack_path("leaf");
        let _ = std::fs::remove_file(&leaf_ack);
        let leaf = harness_child("leaf")
            .env(LEAF_ACK_VAR, &leaf_ack)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            // Its own process group is the point: a child adopted across the
            // runtime keeps the group it was born in, so a drain narrowed to
            // the carrier's own group must fail here rather than pass.
            .process_group(0)
            .spawn()
            .expect("leaf child");
        let leaf_pid = leaf.id();
        let parked = Arc::new(AtomicBool::new(false));
        let complaint: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let stop_watch = {
            let parked = Arc::clone(&parked);
            let complaint = Arc::clone(&complaint);
            std::thread::spawn(move || {
                // A zombie is normal between the child's exit and the
                // scheduled reap, so the child is a defect only once its
                // exit has gone unreaped for the whole bound.
                let deadline = Instant::now() + Duration::from_secs(10);
                let mut gone = false;
                let mut zombie_seen = false;
                while Instant::now() < deadline {
                    match proc_state(leaf_pid) {
                        None => {
                            gone = true;
                            break;
                        }
                        Some('Z') => zombie_seen = true,
                        Some(_) => {}
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                let mut defect = if gone {
                    if leaf_ack.is_file() {
                        None
                    } else {
                        Some(
                            "the leaf arm never ran (the harness filter matched nothing)"
                                .to_owned(),
                        )
                    }
                } else if zombie_seen {
                    Some(format!(
                        "the carrier left its exited child unreaped for the whole bound \
                         (zombie {leaf_pid})"
                    ))
                } else {
                    Some("the leaf child never exited".to_owned())
                };
                let _ = std::fs::remove_file(&leaf_ack);
                // Reaping a child is not a stop: the carrier stays parked.
                if defect.is_none() && parked.load(Ordering::SeqCst) {
                    defect = Some(
                        "the passive carrier must stay parked after reaping a child".to_owned(),
                    );
                }
                // The stop signal, exactly as the pod runtime delivers it. A
                // carrier that ignored it is killed on the bound so the test
                // fails rather than hangs.
                let _ = rustix::process::kill_process(
                    rustix::process::getpid(),
                    rustix::process::Signal::TERM,
                );
                let deadline = Instant::now() + Duration::from_secs(5);
                while !parked.load(Ordering::SeqCst) && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(10));
                }
                if !parked.load(Ordering::SeqCst) {
                    let _ = rustix::process::kill_process(
                        rustix::process::getpid(),
                        rustix::process::Signal::KILL,
                    );
                }
                *complaint.lock().expect("complaint slot") = defect;
            })
        };
        let outcome = serve(signals);
        parked.store(true, Ordering::SeqCst);
        stop_watch.join().expect("stop watch thread");
        if let Some(defect) = complaint.lock().expect("complaint slot").take() {
            panic!("{defect}");
        }
        outcome.expect("the passive carrier exits cleanly on a stop signal");
    }
}
