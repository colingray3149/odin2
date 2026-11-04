//! One finite host sample shared by `odin compute-sample` and the daemon.
//!
//! Two collector readings produce a real CPU delta. Declared models and the
//! GPU probe come from this host's compute facts. There is no loop and no
//! background sampler: the caller polls, and a dropped caller stops reading.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use odin_compute::{Collector, ComputeModel, ComputeSample, GpuProbe, CPU_DELTA, CPU_WAIT};

/// Gap between two fleet samples while an overview is waiting; the view
/// retries a failed sample after the same gap.
pub const CADENCE: Duration = Duration::from_secs(4);
const UNIT_WAIT: Duration = Duration::from_millis(400);
const UNIT_POLL: Duration = Duration::from_millis(10);
const FACTS_SCHEMA: &str = "odin.compute-facts.v1";

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ComputeFacts {
    schema: String,
    host: String,
    gpu: String,
    /// Absolute `libnvidia-ml.so.1` from Nix. Absent on a host that does not open NVML.
    #[serde(default)]
    nvml_library: Option<String>,
    #[serde(default)]
    models: Vec<DeclaredModel>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeclaredModel {
    name: String,
    runtime: String,
    unit: String,
    /// Direct backend origin (`http://ip:port`). Never a socket-activating proxy.
    #[serde(default)]
    backend: Option<String>,
}

/// `~/.config/odin/compute-facts.json`, or `$XDG_CONFIG_HOME/odin/compute-facts.json`,
/// the path dotfiles' `compute-facts.nix` renders.
fn facts_path() -> Option<PathBuf> {
    let config = std::env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty());
    let home = std::env::var_os("HOME").filter(|value| !value.is_empty());
    let root = config
        .map(PathBuf::from)
        .or_else(|| home.map(|home| PathBuf::from(home).join(".config")))?;
    Some(root.join("odin").join("compute-facts.json"))
}

/// This host's declared probe and model rows.
///
/// Absence of the facts file is a typed error, not an empty model list: an
/// empty `models` array is only what a valid file declared. A malformed file,
/// the wrong schema, or a host that is not this host fails the same way.
fn host_facts(
    host: &str,
    stop: &AtomicBool,
) -> Result<(GpuProbe, Option<PathBuf>, Vec<ComputeModel>), String> {
    let path = facts_path().ok_or_else(|| {
        "compute facts path is unavailable: HOME and XDG_CONFIG_HOME are unset".to_owned()
    })?;
    let bytes = std::fs::read(&path)
        .map_err(|error| format!("compute facts {} are unreadable: {error}", path.display()))?;
    let facts = serde_json::from_slice::<ComputeFacts>(&bytes)
        .map_err(|error| format!("compute facts {} are malformed: {error}", path.display()))?;
    if facts.schema != FACTS_SCHEMA {
        return Err(format!(
            "compute facts {} declare schema {}, want {FACTS_SCHEMA}",
            path.display(),
            facts.schema
        ));
    }
    if facts.host != host {
        return Err(format!(
            "compute facts {} declare host {}, sampling {host}",
            path.display(),
            facts.host
        ));
    }
    let probe = facts.gpu.parse::<GpuProbe>().map_err(|error| {
        format!(
            "compute facts {} declare an unknown probe: {error}",
            path.display()
        )
    })?;
    let library = facts
        .nvml_library
        .filter(|path| !path.is_empty())
        .map(PathBuf::from);
    let mut models = Vec::with_capacity(facts.models.len());
    for model in facts.models {
        if stop.load(std::sync::atomic::Ordering::Relaxed) {
            return Err("compute sample cancelled".to_owned());
        }
        let unit = active_state(&model.unit, stop);
        let (loaded, ready) = observe_backend(&model.backend, &unit, stop);
        models.push(model_row(model.name, model.runtime, unit, loaded, ready));
    }
    Ok((probe, library, models))
}

/// The lenient form every sampler uses: facts name their failure instead of
/// dropping the host's gauges, and no declaration means no NVML attempt.
/// `stop` abandons a unit query instead of waiting out its bound.
pub fn resolve(
    host: &str,
    stop: &AtomicBool,
) -> (GpuProbe, Option<PathBuf>, Vec<ComputeModel>, Option<String>) {
    if stop.load(std::sync::atomic::Ordering::Relaxed) {
        return (
            GpuProbe::None,
            None,
            Vec::new(),
            Some("compute sample cancelled".to_owned()),
        );
    }
    match host_facts(host, stop) {
        Ok((probe, library, models)) => (probe, library, models, None),
        Err(error) => (GpuProbe::None, None, Vec::new(), Some(error)),
    }
}

/// Two readings, then stop. `stop` is set when the request future drops, so
/// the next iteration does not open the host root again; the child passes a
/// flag nobody sets. The first sample has no CPU delta, so the loop waits
/// until the counters move; a host whose counters never move inside
/// [`CPU_WAIT`] still returns the gauges, with CPU null, rather than hanging
/// the tick.
pub fn sample_until_delta(
    collector: &mut Collector,
    node: &str,
    stop: &AtomicBool,
) -> Result<ComputeSample, String> {
    collector
        .sample(node)
        .map_err(|error| format!("first reading on {node} failed: {error}"))?;
    let deadline = std::time::Instant::now() + CPU_WAIT;
    loop {
        if stop.load(std::sync::atomic::Ordering::Relaxed) {
            return Err("compute sample cancelled".to_owned());
        }
        std::thread::sleep(CPU_DELTA);
        let sample = collector
            .sample(node)
            .map_err(|error| format!("second reading on {node} failed: {error}"))?;
        if sample.cpu_percent.is_some() || std::time::Instant::now() >= deadline {
            return Ok(sample);
        }
    }
}

const PROBE_WAIT: Duration = Duration::from_millis(250);
const PROBE_CAP: usize = 65_536;

/// Unit activity is not readiness. `ready` is a 200 from the backend's own
/// `/health`. `loaded` is the id that backend listed. An idle on-demand model
/// is not contacted: only `active` or `activating` units are probed, and only
/// at the declared backend address, never the socket that would start one.
fn observe_backend(
    backend: &Option<String>,
    unit: &str,
    stop: &AtomicBool,
) -> (Option<String>, bool) {
    if !matches!(unit, "active" | "activating") {
        return (None, false);
    }
    let Some(backend) = backend.as_deref().and_then(parse_backend) else {
        return (None, false);
    };
    let health = http_status(&backend, "/health", stop);
    let listed = http_body(&backend, "/v1/models", stop).and_then(|body| served_id(&body));
    let ready = health == Some(200) && listed.is_some();
    (listed, ready)
}

fn model_row(
    declared: String,
    runtime: String,
    unit: String,
    loaded: Option<String>,
    ready: bool,
) -> ComputeModel {
    let state = if ready {
        "ready".to_owned()
    } else if loaded.is_some() {
        "loaded".to_owned()
    } else {
        unit.clone()
    };
    let name = loaded.clone().unwrap_or(declared);
    ComputeModel {
        name,
        loaded,
        runtime,
        unit,
        ready,
        state,
    }
}

/// `http://ip:port` only. A name, a path, or a userinfo would not be the
/// backend Nix declared, and dialing it could be the socket proxy.
fn parse_backend(url: &str) -> Option<SocketAddr> {
    let rest = url.strip_prefix("http://")?;
    if rest.contains(['/', '?', '@', ' ', '#']) {
        return None;
    }
    let (host, port) = rest.rsplit_once(':')?;
    let port = port.parse::<u16>().ok().filter(|port| *port != 0)?;
    let ip = host.parse::<IpAddr>().ok()?;
    Some(SocketAddr::new(ip, port))
}

fn served_id(body: &str) -> Option<String> {
    let start = body.find('{')?;
    let value: serde_json::Value = serde_json::from_str(body[start..].trim()).ok()?;
    value.get("data")?.as_array()?.iter().find_map(|row| {
        row.get("id")
            .and_then(serde_json::Value::as_str)
            .filter(|id| !id.is_empty())
            .map(str::to_owned)
    })
}

fn http_status(addr: &SocketAddr, path: &str, stop: &AtomicBool) -> Option<u16> {
    let bytes = http_bytes(addr, path, stop)?;
    let text = String::from_utf8_lossy(&bytes);
    let mut parts = text.lines().next()?.split_whitespace();
    let _version = parts.next()?;
    parts.next()?.parse().ok()
}

fn http_body(addr: &SocketAddr, path: &str, stop: &AtomicBool) -> Option<String> {
    let bytes = http_bytes(addr, path, stop)?;
    String::from_utf8(bytes).ok()
}

fn http_bytes(addr: &SocketAddr, path: &str, stop: &AtomicBool) -> Option<Vec<u8>> {
    if stop.load(std::sync::atomic::Ordering::Relaxed) {
        return None;
    }
    let mut stream = TcpStream::connect_timeout(addr, PROBE_WAIT).ok()?;
    stream.set_read_timeout(Some(PROBE_WAIT)).ok()?;
    stream.set_write_timeout(Some(PROBE_WAIT)).ok()?;
    let request = format!("GET {path} HTTP/1.0\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).ok()?;
    let mut kept = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        if stop.load(std::sync::atomic::Ordering::Relaxed) || kept.len() >= PROBE_CAP {
            break;
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                let room = PROBE_CAP - kept.len();
                kept.extend_from_slice(&chunk[..read.min(room)]);
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::TimedOut
                    || error.kind() == std::io::ErrorKind::WouldBlock =>
            {
                break;
            }
            Err(_) => return None,
        }
    }
    Some(kept)
}

/// ActiveState of one user unit. A missing or unreadable unit is `absent`.
/// The D-Bus read runs on a helper thread and is abandoned after [`UNIT_WAIT`] or
/// once `stop` is set, so a stuck user manager cannot keep a cancelled sample alive.
fn active_state(unit: &str, stop: &AtomicBool) -> String {
    if !unit.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | '@')
    }) || !unit.ends_with(".service")
    {
        return "absent".to_owned();
    }
    let (sender, receiver) = std::sync::mpsc::channel();
    let unit = unit.to_owned();
    std::thread::spawn(move || {
        let _ = sender.send(odin_process::unit_state(
            odin_process::ManagerScope::User,
            &unit,
        ));
    });
    let deadline = std::time::Instant::now() + UNIT_WAIT;
    let state = loop {
        match receiver.try_recv() {
            Ok(read) => break read.ok(),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => break None,
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
        if stop.load(std::sync::atomic::Ordering::Relaxed) || std::time::Instant::now() >= deadline
        {
            return "absent".to_owned();
        }
        std::thread::sleep(UNIT_POLL);
    };
    match state
        .as_ref()
        .and_then(|properties| properties.get("ActiveState"))
    {
        Some(state)
            if matches!(
                state.as_str(),
                "active" | "inactive" | "failed" | "activating" | "deactivating"
            ) =>
        {
            state.clone()
        }
        _ => "absent".to_owned(),
    }
}

/// One sample for `node`, with this host's declared model rows attached.
///
/// A facts failure costs its model rows and the NVML probe, never the gauges:
/// the note says why, and the overview shows it. The child passes a flag
/// nobody sets; the daemon passes the flag set when the requesting view drops.
pub fn take(node: &str, host: &str) -> Result<ComputeSample, String> {
    let stop = AtomicBool::new(false);
    take_stopped(node, host, &stop)
}

/// Same as [`take`], abandoned when `stop` is set. A cancelled read is an
/// error, never a sample with invented rows.
pub fn take_stopped(node: &str, host: &str, stop: &AtomicBool) -> Result<ComputeSample, String> {
    if stop.load(std::sync::atomic::Ordering::Relaxed) {
        return Err("compute sample cancelled".to_owned());
    }
    let (probe, library, models, note) = resolve(host, stop);
    if stop.load(std::sync::atomic::Ordering::Relaxed) {
        return Err("compute sample cancelled".to_owned());
    }
    let mut collector = Collector::system_with_library(probe, library);
    let mut sample = sample_until_delta(&mut collector, node, stop)?;
    sample.models = models;
    sample.models_note = note;
    Ok(sample)
}

#[cfg(test)]
mod tests {
    use super::{sample_until_delta, CPU_WAIT};
    use odin_compute::{Collector, GpuProbe, HostRoot};
    use std::fs;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    fn still_host() -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("fixture root");
        fs::create_dir_all(root.path().join("proc")).unwrap();
        fs::create_dir_all(root.path().join("sys")).unwrap();
        // Counters that never move: no CPU delta will ever exist.
        fs::write(root.path().join("proc/stat"), "cpu 1 0 0 10 0 0 0 0 0 0\n").unwrap();
        root
    }

    #[test]
    fn a_stopped_sampler_returns_before_the_wait_bound() {
        let root = still_host();
        let mut collector = Collector::new(HostRoot::under(root.path()), GpuProbe::None);
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let sampler = std::thread::spawn(move || {
            let started = Instant::now();
            let result = sample_until_delta(&mut collector, "pc", &flag);
            (result.is_err(), started.elapsed())
        });
        std::thread::sleep(Duration::from_millis(40));
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let (cancelled, elapsed) = sampler.join().expect("sampler thread");
        assert!(cancelled, "a cancelled sampler must not answer a sample");
        assert!(
            elapsed < CPU_WAIT,
            "cancellation must beat the {CPU_WAIT:?} bound, took {elapsed:?}"
        );
    }
}
