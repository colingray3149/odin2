//! Killable malware-scanner process adapter.
//!
//! The executable and its arguments are supplied by production composition.
//! Each scan streams the staged file through StopAuthority stdin in bounded
//! chunks, discards both output streams, and interprets only the exit status.
//! Stop and reap go through the opaque WorkerId; this adapter never signals
//! PID, PGID, unit, or process name. The adapter therefore exposes no engine
//! diagnostics or downloaded content through browser projections.

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use odin_kernel::stop::{CorrelationId, WorkerId};
use odin_kernel::StopAuthority;
use odin_process::{
    mint_worker_id, CommandSpec, EnvironmentBuilder, FrozenArgv, ScopeLifetime, ScopeLimits,
    WorkerNaming, CORRELATION_ENV,
};
use thiserror::Error;

use crate::config::BrowserStopHost;
use crate::safety::{MalwareScan, MalwareScanner, MalwareVerdict, ScanControl, ScanFailure};

/// Metadata-safe signature used for every exit-status-1 malware verdict.
///
/// Scanner output is deliberately ignored, so an engine cannot inject file
/// content or unbounded diagnostics into projected metadata.
pub const EXECUTABLE_SCANNER_MALICIOUS_SIGNATURE: &str = "executable-scanner-detected-malware";

const MONITOR_INTERVAL: Duration = Duration::from_millis(10);
const STDIN_CHUNK_BYTES: usize = 64 * 1024;
const DRAIN_CHUNK_BYTES: usize = 4096;
const DRAIN_BYTE_CEILING: u64 = 1024 * 1024;
const ARGV_ITEM_CEILING: usize = 64;
const ARGV_BYTE_CEILING: usize = 64 * 1024;

type ScanResult = Result<MalwareVerdict, ScanFailure>;

/// Configuration failure for an executable malware scanner.
#[derive(Debug, Error)]
pub enum ExecutableScannerConfigError {
    #[error("scanner executable path must be absolute: {path}")]
    NotAbsolute { path: PathBuf },
    #[error("scanner executable is unreadable at {path}: {source}")]
    Unreadable {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("scanner executable is not a regular file: {path}")]
    NotAFile { path: PathBuf },
    #[error("scanner executable is not executable: {path}")]
    NotExecutable { path: PathBuf },
}

/// A malware scanner backed by one explicitly declared executable.
///
/// No shell is involved. The configured arguments are passed verbatim, and
/// the staged download is streamed through StopAuthority stdin. Exit 0
/// means clean, exit 1 means malicious, and every other termination is a typed
/// fail-closed scanner failure.
#[derive(Clone)]
pub struct ExecutableMalwareScanner {
    executable: PathBuf,
    arguments: Vec<OsString>,
    host: BrowserStopHost,
}

impl std::fmt::Debug for ExecutableMalwareScanner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecutableMalwareScanner")
            .field("executable", &self.executable)
            .field("argument_count", &self.arguments.len())
            .finish_non_exhaustive()
    }
}

impl ExecutableMalwareScanner {
    /// Validates an absolute executable path and records arguments verbatim.
    pub fn new<I, S>(
        executable: impl Into<PathBuf>,
        arguments: I,
        host: BrowserStopHost,
    ) -> Result<Self, ExecutableScannerConfigError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let executable = executable.into();
        validate_executable(&executable)?;
        Ok(Self {
            executable,
            arguments: arguments.into_iter().map(Into::into).collect(),
            host,
        })
    }

    /// Declared executable used for every scan.
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    /// Verbatim argument vector passed without a shell.
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }
}

impl MalwareScanner for ExecutableMalwareScanner {
    fn start_download_scan(
        &self,
        file: File,
        _byte_len: u64,
        control: ScanControl,
    ) -> Result<Arc<dyn MalwareScan>, ScanFailure> {
        if Instant::now() >= control.deadline() {
            return Err(ScanFailure::DeadlineExceeded);
        }
        if control.is_cancelled() {
            return Err(ScanFailure::Cancelled);
        }

        let worker_id = mint_worker_id().map_err(|_| ScanFailure::Unavailable)?;
        let correlation = scan_correlation(&self.host, &worker_id)?;
        let naming = WorkerNaming::new(
            self.host.tx_id.clone(),
            self.host.wp_id.clone(),
            self.host.attempt,
            worker_id.clone(),
        )
        .map_err(|_| ScanFailure::Unavailable)?;
        let mut argv = Vec::with_capacity(self.arguments.len().saturating_add(1));
        argv.push(self.executable.as_os_str().to_owned());
        argv.extend(self.arguments.iter().cloned());
        let argv = FrozenArgv::new(argv, ARGV_ITEM_CEILING, ARGV_BYTE_CEILING)
            .map_err(|_| ScanFailure::Unavailable)?;
        let environment = EnvironmentBuilder::new([CORRELATION_ENV])
            .and_then(|builder| builder.set(CORRELATION_ENV, correlation.as_str()))
            .map_err(|_| ScanFailure::Unavailable)?
            .build();
        let spec = CommandSpec {
            argv,
            environment,
            current_dir: PathBuf::from("/"),
        };
        let remaining = control.remaining().max(Duration::from_millis(1));
        let limits = ScopeLimits {
            lifetime: ScopeLifetime::Bounded(remaining),
            timeout_stop: Duration::from_secs(2),
            memory_high: None,
            memory_max: None,
            tasks_max: None,
        };
        let launch = self
            .host
            .authority
            .launch_worker(naming, &correlation, &spec, limits)
            .map_err(|_| ScanFailure::Unavailable)?;
        drain_output(launch.stdout);
        drain_output(launch.stderr);
        let scan = ExecutableMalwareScan::start(
            Arc::clone(&self.host.authority),
            worker_id,
            file,
            control,
        )?;
        Ok(Arc::new(scan))
    }
}

/// One running executable scan.
///
/// The monitor owns stdin streaming, wait, and StopAuthority teardown. `kill`
/// only signals the monitor and is non-blocking; dropping the last scan handle
/// requests stop and joins the monitor so the worker cannot be orphaned.
struct ExecutableMalwareScan {
    state: Arc<ScanState>,
    monitor: Mutex<Option<JoinHandle<()>>>,
}

impl ExecutableMalwareScan {
    fn start(
        authority: Arc<StopAuthority>,
        worker_id: WorkerId,
        file: File,
        control: ScanControl,
    ) -> Result<Self, ScanFailure> {
        let state = Arc::new(ScanState::new());
        let monitor_state = Arc::clone(&state);
        let monitor_authority = Arc::clone(&authority);
        let monitor_worker = worker_id.clone();
        let monitor = thread::Builder::new()
            .name("odin-malware-scan".to_owned())
            .spawn(move || {
                monitor_scan(
                    monitor_authority,
                    monitor_worker,
                    file,
                    control,
                    monitor_state,
                )
            });

        match monitor {
            Ok(monitor) => Ok(Self {
                state,
                monitor: Mutex::new(Some(monitor)),
            }),
            Err(_) => {
                let _ = authority.stop_worker(&worker_id);
                Err(ScanFailure::Unavailable)
            }
        }
    }

    fn join_monitor(&self) {
        if let Some(monitor) = lock_unpoisoned(&self.monitor).take() {
            let _join_result = monitor.join();
        }
    }
}

impl MalwareScan for ExecutableMalwareScan {
    fn wait(&self) -> ScanResult {
        let result = self.state.wait_result();
        self.join_monitor();
        result
    }

    fn kill(&self) {
        self.state.request_kill();
    }
}

impl Drop for ExecutableMalwareScan {
    fn drop(&mut self) {
        self.state.request_kill();
        self.join_monitor();
    }
}

struct ScanState {
    result: Mutex<Option<ScanResult>>,
    wake: Condvar,
    kill_requested: AtomicBool,
}

impl ScanState {
    fn new() -> Self {
        Self {
            result: Mutex::new(None),
            wake: Condvar::new(),
            kill_requested: AtomicBool::new(false),
        }
    }

    fn request_kill(&self) {
        self.kill_requested.store(true, Ordering::Release);
        self.wake.notify_all();
    }

    fn kill_requested(&self) -> bool {
        self.kill_requested.load(Ordering::Acquire)
    }

    fn complete(&self, result: ScanResult) {
        let mut completed = lock_unpoisoned(&self.result);
        if completed.is_none() {
            *completed = Some(result);
            self.wake.notify_all();
        }
    }

    fn wait_result(&self) -> ScanResult {
        let mut completed = lock_unpoisoned(&self.result);
        loop {
            if let Some(result) = completed.as_ref() {
                return result.clone();
            }
            completed = self
                .wake
                .wait(completed)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn wait_for_monitor(&self, duration: Duration) {
        let completed = lock_unpoisoned(&self.result);
        if completed.is_some() || self.kill_requested() {
            return;
        }
        let (completed, _timeout) = self
            .wake
            .wait_timeout(completed, duration)
            .unwrap_or_else(PoisonError::into_inner);
        drop(completed);
    }
}

fn monitor_scan(
    authority: Arc<StopAuthority>,
    worker_id: WorkerId,
    mut file: File,
    control: ScanControl,
    state: Arc<ScanState>,
) {
    if Instant::now() >= control.deadline() {
        let _ = authority.stop_worker(&worker_id);
        state.complete(Err(ScanFailure::DeadlineExceeded));
        return;
    }
    if control.is_cancelled() || state.kill_requested() {
        let _ = authority.stop_worker(&worker_id);
        state.complete(Err(ScanFailure::Cancelled));
        return;
    }

    if let Err(failure) = stream_stdin(&authority, &worker_id, &mut file, &control, &state) {
        let _ = authority.stop_worker(&worker_id);
        state.complete(Err(failure));
        return;
    }

    loop {
        if Instant::now() >= control.deadline() {
            let _ = authority.stop_worker(&worker_id);
            state.complete(Err(ScanFailure::DeadlineExceeded));
            return;
        }
        if control.is_cancelled() || state.kill_requested() {
            let _ = authority.stop_worker(&worker_id);
            state.complete(Err(ScanFailure::Cancelled));
            return;
        }

        match authority.try_wait_worker(&worker_id) {
            Ok(Some(status)) => {
                let _ = authority.stop_worker(&worker_id);
                state.complete(verdict_from_status(status));
                return;
            }
            Ok(None) => {}
            Err(_) => {
                let _ = authority.stop_worker(&worker_id);
                state.complete(Err(ScanFailure::Unavailable));
                return;
            }
        }

        let sleep = control.remaining().min(MONITOR_INTERVAL);
        if !sleep.is_zero() {
            state.wait_for_monitor(sleep);
        }
    }
}

fn stream_stdin(
    authority: &StopAuthority,
    worker_id: &WorkerId,
    file: &mut File,
    control: &ScanControl,
    state: &ScanState,
) -> Result<(), ScanFailure> {
    let mut buf = vec![0_u8; STDIN_CHUNK_BYTES];
    loop {
        if Instant::now() >= control.deadline() {
            return Err(ScanFailure::DeadlineExceeded);
        }
        if control.is_cancelled() || state.kill_requested() {
            return Err(ScanFailure::Cancelled);
        }
        let read = file.read(&mut buf).map_err(|_| ScanFailure::Unavailable)?;
        if read == 0 {
            authority
                .close_worker_stdin(worker_id)
                .map_err(|_| ScanFailure::Unavailable)?;
            return Ok(());
        }
        authority
            .write_worker_stdin(worker_id, &buf[..read])
            .map_err(|_| ScanFailure::Unavailable)?;
    }
}

fn drain_output<R: Read + Send + 'static>(mut reader: R) {
    let _ = thread::Builder::new()
        .name("odin-malware-scan-drain".to_owned())
        .spawn(move || {
            let mut buf = [0_u8; DRAIN_CHUNK_BYTES];
            let mut total = 0_u64;
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => return,
                    Ok(count) => {
                        total = total.saturating_add(count as u64);
                        if total >= DRAIN_BYTE_CEILING {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        });
}

fn scan_correlation(
    host: &BrowserStopHost,
    worker_id: &WorkerId,
) -> Result<CorrelationId, ScanFailure> {
    let material = format!(
        "{}\0{}\0{}\0{}\0scanner",
        host.tx_id,
        host.wp_id,
        host.attempt,
        worker_id.as_str()
    );
    let hex = blake3::hash(material.as_bytes()).to_hex();
    CorrelationId::new(&hex.as_str()[..32]).map_err(|_| ScanFailure::Unavailable)
}

fn verdict_from_status(status: ExitStatus) -> ScanResult {
    match status.code() {
        Some(0) => Ok(MalwareVerdict::Clean),
        Some(1) => Ok(MalwareVerdict::Malicious {
            signature: EXECUTABLE_SCANNER_MALICIOUS_SIGNATURE.to_owned(),
        }),
        _ => Err(ScanFailure::InvalidVerdict),
    }
}

fn validate_executable(path: &Path) -> Result<(), ExecutableScannerConfigError> {
    if !path.is_absolute() {
        return Err(ExecutableScannerConfigError::NotAbsolute {
            path: path.to_path_buf(),
        });
    }
    let metadata =
        std::fs::metadata(path).map_err(|source| ExecutableScannerConfigError::Unreadable {
            path: path.to_path_buf(),
            source,
        })?;
    if !metadata.is_file() {
        return Err(ExecutableScannerConfigError::NotAFile {
            path: path.to_path_buf(),
        });
    }
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(ExecutableScannerConfigError::NotExecutable {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use odin_kernel::StopAuthority;
    use odin_ledger::Ledger;
    use odin_process::{BusAddress, RegisteredServiceBinding, WorkerChannel};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex as StdMutex;

    fn fixture_executable() -> PathBuf {
        let executable = std::env::current_exe().expect("test executable path");
        std::fs::canonicalize(executable).expect("canonical test executable path")
    }

    fn recovery_host(executable: &Path) -> BrowserStopHost {
        let bus = BusAddress::parse("/tmp/odin-browser-scanner-stop-test.sock")
            .expect("absolute unix bus path");
        let channel = WorkerChannel::for_recovery(bus).expect("recovery channel");
        let ledger = Ledger::open_in_memory().expect("in-memory stop ledger");
        let digest = blake3::hash(
            &std::fs::read(executable).expect("read test executable for binding digest"),
        )
        .to_hex()
        .to_string();
        let binding = RegisteredServiceBinding::new(executable.to_path_buf(), digest)
            .expect("fixture binding");
        BrowserStopHost {
            authority: Arc::new(StopAuthority::new(Arc::new(StdMutex::new(ledger)), channel)),
            tx_id: "odintx".to_owned(),
            wp_id: "browser-scan".to_owned(),
            attempt: 1,
            worker_binding: binding,
        }
    }

    #[test]
    fn scanner_stop_authority() {
        let executable = fixture_executable();
        let relative = ExecutableMalwareScanner::new(
            "true",
            Vec::<OsString>::new(),
            recovery_host(&executable),
        );
        assert!(matches!(
            relative,
            Err(ExecutableScannerConfigError::NotAbsolute { .. })
        ));

        let scanner = ExecutableMalwareScanner::new(
            executable.clone(),
            Vec::<OsString>::new(),
            recovery_host(&executable),
        )
        .expect("absolute scanner executable");
        let staged = std::env::temp_dir().join(format!(
            "odin-browser-scanner-stop-{}.bin",
            std::process::id()
        ));
        std::fs::write(&staged, b"fixture").expect("staged scan bytes");
        let file = File::open(&staged).expect("staged scan file");
        let control = ScanControl::new(Instant::now() + Duration::from_secs(2));
        let started = scanner.start_download_scan(file, 7, control);
        let _ = std::fs::remove_file(&staged);
        assert!(
            matches!(started, Err(ScanFailure::Unavailable)),
            "a recovery-only StopAuthority channel must not fall back to raw spawn"
        );
    }
}
