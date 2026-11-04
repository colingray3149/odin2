//! Independent persistent desk channels for every declared desktop node.
//! Device selection never falls back to the authority or the first host.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use odin_hermes::runtime::desktop::{DesktopRoute, Direction, TransferRequest};
use odin_workflows::desk::Transfer;
use serde_json::Value;

/// The node capability naming where the owner's desktop is.
const DESKTOP_CAPABILITY: &str = "desktop";
/// How often a running transfer updates its progress line.
const TRANSFER_PROGRESS_EVERY: Duration = Duration::from_secs(5);
/// The stderr characters a transfer keeps for its failure sentence.
const TRANSFER_STDERR_TAIL: usize = 2000;
/// How often a transfer checks that rsync has exited after its output stops.
const TRANSFER_POLL: Duration = Duration::from_millis(50);
/// Stderr and one progress line kept; a descendant holding the pipe cannot grow this.
const TRANSFER_STDERR_CAP: usize = 8 * 1024;

pub(crate) struct DeskChannel {
    pin: Arc<odin_registry::SnapshotHandle>,
    channels: Channels,
}

struct Channels {
    /// The runtime manifest's declared ssh.
    ssh: std::path::PathBuf,
    links: Mutex<BTreeMap<String, ChannelCell>>,
}

type ChannelCell = Arc<Mutex<Option<Link>>>;

/// A desk host that does not answer is dropped quickly; ssh keeps the first value it is given, so
/// these precede the fleet's shared options.
const CONNECT_OPTIONS: [&str; 4] = ["-o", "ConnectTimeout=3", "-o", "ConnectionAttempts=1"];

struct Link {
    host: String,
    tailscale: String,
    child: Child,
    stdin: ChildStdin,
    replies: Receiver<String>,
    stderr: Arc<Mutex<String>>,
    stderr_reader: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Link {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl DeskChannel {
    pub(crate) fn new(pin: Arc<odin_registry::SnapshotHandle>, ssh: std::path::PathBuf) -> Self {
        Self {
            pin,
            channels: Channels::new(ssh),
        }
    }

    /// Resolve friendly names only against enabled desktop declarations.
    fn targets(&self, request: &Value) -> Result<Vec<(String, String)>, String> {
        let registry = self.pin.current();
        let nodes: BTreeSet<String> = registry
            .listed_objects(odin_registry::RegistryKind::Node)
            .filter_map(|object| match &object.config {
                odin_registry::ObjectConfig::Node(node)
                    if node.enabled && node.capabilities.contains(DESKTOP_CAPABILITY) =>
                {
                    Some(node.host.clone())
                }
                _ => None,
            })
            .collect();
        if nodes.is_empty() {
            return Err("no enabled node declares the desktop capability".to_owned());
        }
        let display = request["steps"].as_array().is_some_and(|steps| {
            !steps.is_empty() && steps.iter().all(|step| step["do"] == "display")
        });
        let device = request["device"]
            .as_str()
            .filter(|device| !device.is_empty());
        if device.is_some_and(|device| device.eq_ignore_ascii_case("all")) && !display {
            return Err("device=all is only supported for display operations".to_owned());
        }
        odin_desk::DeviceMap::from_environment()?
            .desktop_targets(device, &nodes, display)?
            .into_iter()
            .map(|host| {
                let tailscale = registry
                    .listed_objects(odin_registry::RegistryKind::Host)
                    .find_map(|object| match &object.config {
                        odin_registry::ObjectConfig::Host(declared)
                            if object.id == host && declared.enabled && declared.enrolled =>
                        {
                            Some(declared.tailscale.clone())
                        }
                        _ => None,
                    })
                    .filter(|name| !name.is_empty() && !name.starts_with('-'))
                    .ok_or_else(|| {
                        format!("desktop device {host} is not an enabled, enrolled fleet host")
                    })?;
                Ok((host, tailscale))
            })
            .collect()
    }
}

impl Channels {
    fn new(ssh: std::path::PathBuf) -> Self {
        Self {
            ssh,
            links: Mutex::new(BTreeMap::new()),
        }
    }

    fn open(&self, host: &str, tailscale: &str) -> Result<Link, String> {
        let mut child = Command::new(&self.ssh)
            .args(CONNECT_OPTIONS)
            .args(odin_omp::live::harness::SSH_OPTIONS)
            .args(["-o", "ServerAliveInterval=3", "-o", "ServerAliveCountMax=1"])
            .args([tailscale, "exec odin desk serve"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("ssh to the desktop host {host} could not start: {error}"))?;
        let stdin = child.stdin.take().ok_or("ssh gave no stdin")?;
        let stdout = child.stdout.take().ok_or("ssh gave no stdout")?;
        let mut stderr_pipe = child.stderr.take().ok_or("ssh gave no stderr")?;
        let (send, replies) = mpsc::channel();
        std::thread::Builder::new()
            .name("odin-desk-replies".to_owned())
            .spawn(move || {
                for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                    if send.send(line).is_err() {
                        break;
                    }
                }
            })
            .map_err(|error| format!("the desk reply reader could not start: {error}"))?;
        // The helper's own refusal (no session, unreadable mouse) arrives on stderr.
        let stderr = Arc::new(Mutex::new(String::new()));
        let tail = Arc::clone(&stderr);
        let stderr_reader = std::thread::Builder::new()
            .name("odin-desk-stderr".to_owned())
            .spawn(move || {
                let mut text = String::new();
                let _ = stderr_pipe.read_to_string(&mut text);
                if let Ok(mut tail) = tail.lock() {
                    *tail = text
                        .trim()
                        .chars()
                        .rev()
                        .take(500)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect();
                }
            })
            .map_err(|error| format!("the desk stderr reader could not start: {error}"))?;
        tracing::info!("odind: desk channel opened to {host}");
        Ok(Link {
            host: host.to_owned(),
            tailscale: tailscale.to_owned(),
            child,
            stdin,
            replies,
            stderr,
            stderr_reader: Some(stderr_reader),
        })
    }

    fn call_one(
        &self,
        host: &str,
        tailscale: &str,
        request: &Value,
        bound: Duration,
    ) -> Result<Value, String> {
        let cell = self
            .links
            .lock()
            .map_err(|error| format!("the desk channel map lock: {error}"))?
            .entry(host.to_owned())
            .or_default()
            .clone();
        let mut slot = cell
            .lock()
            .map_err(|error| format!("{host}'s desk channel lock: {error}"))?;
        if slot.as_mut().is_some_and(|link| {
            link.tailscale != tailscale || !matches!(link.child.try_wait(), Ok(None))
        }) {
            *slot = None;
        }
        if slot.is_none() {
            *slot = Some(self.open(host, tailscale)?);
        }
        let link = slot.as_mut().ok_or("the desk channel is missing")?;
        let host = link.host.clone();
        let sent = writeln!(link.stdin, "{request}").and_then(|()| link.stdin.flush());
        let reply = match sent {
            Ok(()) => link.replies.recv_timeout(bound),
            Err(_) => Err(RecvTimeoutError::Disconnected),
        };
        match reply {
            Ok(line) => serde_json::from_str(&line).map_err(|error| {
                format!("{host}'s desk helper sent an unreadable reply ({error})")
            }),
            Err(RecvTimeoutError::Timeout) => {
                *slot = None;
                Err(format!(
                    "{host}'s desk helper did not answer within {} s; the channel was closed",
                    bound.as_secs()
                ))
            }
            Err(RecvTimeoutError::Disconnected) => {
                let detail = slot
                    .take()
                    .map(|mut link| {
                        // Ending ssh closes its stderr, which ends the reader.
                        let _ = link.child.kill();
                        let _ = link.child.wait();
                        if let Some(reader) = link.stderr_reader.take() {
                            let _ = reader.join();
                        }
                        link.stderr
                            .lock()
                            .map(|text| text.clone())
                            .unwrap_or_default()
                    })
                    .unwrap_or_default();
                Err(format!(
                    "the desk channel to {host} closed: {}",
                    if detail.is_empty() {
                        "no message".to_owned()
                    } else {
                        detail
                    }
                ))
            }
        }
    }
}

impl Channels {
    fn call_targets(
        &self,
        targets: Vec<(String, String)>,
        request: &Value,
        bound: Duration,
    ) -> Result<Value, String> {
        let started = std::time::Instant::now();
        let mut wire = request.clone();
        if let Some(object) = wire.as_object_mut() {
            object.remove("device");
        }
        if targets.len() == 1 {
            let (host, tailscale) = &targets[0];
            let mut reply = self.call_one(host, tailscale, &wire, bound)?;
            reply["device"] = serde_json::json!(host);
            for key in ["error", "stopped"] {
                if let Some(reason) = reply[key].as_str() {
                    reply[key] = serde_json::json!(format!("{host}: {reason}"));
                }
            }
            return Ok(reply);
        }
        // All devices start together: an absent laptop cannot delay the others.
        std::thread::scope(|scope| {
            let calls: Vec<_> = targets
                .iter()
                .map(|(host, tailscale)| {
                    let wire = &wire;
                    (
                        host,
                        scope.spawn(move || self.call_one(host, tailscale, wire, bound)),
                    )
                })
                .collect();
            let mut devices = BTreeMap::new();
            let mut did = Vec::new();
            let mut errors = Vec::new();
            for (host, call) in calls {
                let reply = call
                    .join()
                    .unwrap_or_else(|_| Err(format!("{host}'s desk channel panicked")))
                    .unwrap_or_else(|error| serde_json::json!({"error": error}));
                if let Some(lines) = reply["did"].as_array() {
                    did.extend(
                        lines
                            .iter()
                            .filter_map(Value::as_str)
                            .map(|line| format!("{host}: {line}")),
                    );
                }
                if let Some(error) = reply["error"].as_str().or(reply["stopped"].as_str()) {
                    errors.push(format!("{host}: {error}"));
                }
                devices.insert(host, reply);
            }
            let mut reply = serde_json::json!({"ok": errors.is_empty(), "did": did, "devices": devices, "stepsMs": started.elapsed().as_millis()});
            if !errors.is_empty() {
                reply["error"] = serde_json::json!(errors.join("; "));
            }
            Ok(reply)
        })
    }
}

impl Channels {
    /// One rsync over ssh with the desk channel's options; the file list goes
    /// on stdin, progress is reported every few seconds, and it is killed at
    /// the bound. Returns the files and bytes `--stats` counted.
    fn transfer(
        &self,
        host: &str,
        tailscale: &str,
        request: &TransferRequest<'_>,
    ) -> Result<Transfer, String> {
        let list = files_from(request.files)?;
        if tailscale.is_empty()
            || tailscale.contains([' ', '\n', '\t', ':'])
            || tailscale.starts_with('-')
        {
            return Err(format!("{tailscale:?} is not a desk host name"));
        }
        let ssh = ssh_for_rsync(&self.ssh);
        let remote = |path: &std::path::Path| format!("{tailscale}:{}", dir_slash(path));
        let local = |path: &std::path::Path| dir_slash(path);
        let (source, target) = match request.direction {
            Direction::Pull => (remote(request.from), local(request.to)),
            Direction::Push => (local(request.from), remote(request.to)),
        };
        let deadline = std::time::Instant::now() + request.bound;
        let mut child = Command::new(request.rsync)
            .args([
                "-a",
                "--partial",
                "--mkpath",
                "--protect-args",
                "--info=progress2",
                "--stats",
            ])
            .args(["--files-from=-", "-e", &ssh, &source, &target])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("rsync to {host} could not start: {error}"))?;
        let mut stdin = child.stdin.take().ok_or("rsync gave no stdin")?;
        let stdout = child.stdout.take().ok_or("rsync gave no stdout")?;
        let stderr_pipe = child.stderr.take().ok_or("rsync gave no stderr")?;
        let (err_send, stderr) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = err_send.send(read_tail(stderr_pipe, TRANSFER_STDERR_CAP));
        });
        let (send, lines) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = stdin.write_all(list.as_bytes());
            drop(stdin);
            let mut line = Vec::new();
            for byte in BufReader::new(stdout).bytes().map_while(Result::ok) {
                if byte == b'\n' || byte == b'\r' {
                    if send
                        .send(String::from_utf8_lossy(&line).into_owned())
                        .is_err()
                    {
                        return;
                    }
                    line.clear();
                } else if line.len() < TRANSFER_STDERR_CAP {
                    line.push(byte);
                }
            }
        });
        let mut reported = std::time::Instant::now();
        let mut stats = Transfer::default();
        let mut timed_out = false;
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                timed_out = true;
                let _ = child.kill();
                break;
            }
            match lines.recv_timeout(left.min(TRANSFER_POLL)) {
                Ok(line) => {
                    read_stat(&line, &mut stats);
                    let percent = line.split_whitespace().find(|word| word.ends_with('%'));
                    if let Some(percent) = percent {
                        if reported.elapsed() >= TRANSFER_PROGRESS_EVERY {
                            let verb = match request.direction {
                                Direction::Pull => "copying from",
                                Direction::Push => "copying to",
                            };
                            odin_domain::progress::report(format!("{verb} {host}: {percent}"));
                            reported = std::time::Instant::now();
                        }
                    }
                }
                Err(RecvTimeoutError::Timeout) => match child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) => {}
                    Err(error) => {
                        let _ = child.kill();
                        return Err(format!("rsync to {host} was lost: {error}"));
                    }
                },
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        let status = wait_until(&mut child, deadline);
        let text = stderr
            .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
            .unwrap_or_default();
        if timed_out || status.is_none() {
            return Err(format!(
                "the copy with {host} ran past its {} and was stopped",
                bound_text(request.bound)
            ));
        }
        match status.and_then(|status| status.code()) {
            Some(0) => Ok(stats),
            code => Err(rsync_cause(code, host, &text)),
        }
    }
}

/// `--stats` lines: the regular files and bytes transferred.
fn read_stat(line: &str, stats: &mut Transfer) {
    let number = |rest: &str| {
        rest.split_whitespace()
            .next()
            .map(|word| word.replace(',', ""))
            .and_then(|word| word.parse::<u64>().ok())
    };
    if let Some(rest) = line.strip_prefix("Number of regular files transferred:") {
        stats.files = number(rest).map_or(stats.files, |files| files as usize);
    } else if let Some(rest) = line.strip_prefix("Total transferred file size:") {
        stats.bytes = number(rest).unwrap_or(stats.bytes);
    }
}

/// rsync's exit code as a sentence naming the desk host.
fn rsync_cause(code: Option<i32>, host: &str, stderr: &str) -> String {
    match code {
        Some(23) => format!("some files could not be read from {host} (partial transfer)"),
        Some(24) => format!("files vanished on {host} while copying (the card was removed?)"),
        Some(11) => "writing to staging failed (disk full?)".to_owned(),
        Some(12 | 255) => format!("the connection to {host} dropped"),
        Some(30) => format!("the copy from {host} stalled and timed out"),
        code => {
            let last = stderr
                .lines()
                .rev()
                .map(str::trim)
                .find(|line| !line.is_empty())
                .unwrap_or("no message");
            let tail: String = last.chars().take(TRANSFER_STDERR_TAIL).collect();
            match code {
                Some(code) => format!("rsync exited {code}: {tail}"),
                None => format!("rsync was stopped by a signal: {tail}"),
            }
        }
    }
}

/// rsync splits `-e` on spaces and keeps a single-quoted word whole. A quote
/// inside that word is doubled; a backslash is not an escape (rsync(1)).
fn rsync_quote(word: &str) -> String {
    format!("'{}'", word.replace('\'', "''"))
}

fn dir_slash(path: &std::path::Path) -> String {
    let text = path.display().to_string();
    if text.ends_with('/') {
        text
    } else {
        format!("{text}/")
    }
}

fn bound_text(bound: Duration) -> String {
    if bound.as_secs() == 0 {
        format!("{} ms", bound.as_millis())
    } else {
        format!("{} s", bound.as_secs())
    }
}

/// The desk channel's ssh as one `-e` argument, quoted for rsync's parser.
fn ssh_for_rsync(ssh: &std::path::Path) -> String {
    std::iter::once(rsync_quote(&ssh.display().to_string()))
        .chain(CONNECT_OPTIONS.into_iter().map(rsync_quote))
        .chain(odin_omp::live::harness::SSH_OPTIONS.map(rsync_quote))
        .collect::<Vec<_>>()
        .join(" ")
}

fn read_tail(mut pipe: impl std::io::Read, cap: usize) -> String {
    let mut tail = Vec::new();
    let mut chunk = [0; 1024];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                tail.extend_from_slice(&chunk[..n]);
                if tail.len() > cap {
                    tail.drain(..tail.len() - cap);
                }
            }
        }
    }
    String::from_utf8_lossy(&tail).into_owned()
}

/// Waits until `deadline`, killing the child if it is still running. None means
/// the bound won.
fn wait_until(child: &mut Child, deadline: std::time::Instant) -> Option<std::process::ExitStatus> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => std::thread::sleep(TRANSFER_POLL),
        }
    }
}

/// Relative names for `--files-from=-`: no absolute path, `..`, `.` or blank.
fn files_from(files: &[std::path::PathBuf]) -> Result<String, String> {
    files
        .iter()
        .map(|file| {
            let name = file.to_string_lossy();
            let plain = !file.is_absolute()
                && !name.is_empty()
                && !name.contains('\n')
                && !name.contains('\0')
                && file
                    .components()
                    .all(|component| matches!(component, std::path::Component::Normal(_)));
            if !plain {
                return Err(format!("{name:?} is not a plain relative file name"));
            }
            Ok(format!("{name}\n"))
        })
        .collect()
}

impl DesktopRoute for DeskChannel {
    fn call(&self, request: &Value, bound: Duration) -> Result<Value, String> {
        self.channels
            .call_targets(self.targets(request)?, request, bound)
    }

    fn transfer(&self, request: &TransferRequest<'_>) -> Result<Transfer, String> {
        let (host, tailscale) = self
            .targets(&serde_json::json!({ "device": request.device }))?
            .into_iter()
            .next()
            .ok_or("no desktop device matched")?;
        self.channels.transfer(&host, &tailscale, request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt as _;

    fn fixture() -> (tempfile::TempDir, Channels) {
        let directory = tempfile::tempdir().unwrap();
        let ssh = directory.path().join("ssh");
        // This executable is only a transport fixture: no compositor or real ssh.
        std::fs::write(
            &ssh,
            r#"#!/bin/sh
host=
for arg do
    case "$arg" in pc|mini|laptop) host=$arg ;; esac
done
if [ "$host" = laptop ]; then
    echo "device is asleep or away" >&2
    exit 255
fi
while IFS= read -r request; do
    case "$request" in
      *stop-mini*)
        if [ "$host" = mini ]; then
            printf '{"did":[],"stopped":"the owner pressed the stop keys"}\n'
            continue
        fi ;;
    esac
    printf '{"did":["%s action"],"helperPid":%s,"request":%s}\n' "$host" "$$" "$request"
done
"#,
        )
        .unwrap();
        std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700)).unwrap();
        (directory, Channels::new(ssh))
    }

    #[test]
    fn every_host_has_its_own_persistent_channel_and_offline_errors_name_the_device() {
        let (_directory, channels) = fixture();
        let request =
            json!({"ask":"owner","device":"mini","steps":[{"do":"launch","app":"Dolphin"}]});
        let mini = channels
            .call_targets(
                vec![("mini".into(), "mini".into())],
                &request,
                Duration::from_secs(2),
            )
            .unwrap();
        assert_eq!(mini["device"], "mini");
        assert_eq!(mini["did"][0], "mini action");
        assert!(mini["request"].get("device").is_none());
        assert_eq!(mini["request"]["steps"][0]["app"], "Dolphin");
        let pc = channels
            .call_targets(
                vec![("pc".into(), "pc".into())],
                &request,
                Duration::from_secs(2),
            )
            .unwrap();
        assert_ne!(pc["helperPid"], mini["helperPid"]);
        let again = channels
            .call_targets(
                vec![("mini".into(), "mini".into())],
                &request,
                Duration::from_secs(2),
            )
            .unwrap();
        assert_eq!(again["helperPid"], mini["helperPid"]);
        let rebound = channels
            .call_one("mini", "pc", &request, Duration::from_secs(2))
            .unwrap();
        assert_ne!(
            rebound["helperPid"], mini["helperPid"],
            "a changed declaration must replace the old endpoint"
        );
        let away = channels
            .call_targets(
                vec![("laptop".into(), "laptop".into())],
                &request,
                Duration::from_secs(2),
            )
            .unwrap_err();
        assert!(away.contains("laptop"), "{away}");
        let stopped = json!({"ask":"stop-mini","steps":[{"do":"display","on":false}]});
        let mini = channels
            .call_targets(
                vec![("mini".into(), "mini".into())],
                &stopped,
                Duration::from_secs(2),
            )
            .unwrap();
        assert!(mini["stopped"]
            .as_str()
            .unwrap()
            .contains("mini: the owner pressed"));
        let pc = channels
            .call_targets(
                vec![("pc".into(), "pc".into())],
                &stopped,
                Duration::from_secs(2),
            )
            .unwrap();
        assert!(pc.get("stopped").is_none());
    }

    #[test]
    fn only_plain_relative_names_reach_rsyncs_file_list() {
        let name = |text: &str| vec![std::path::PathBuf::from(text)];
        assert_eq!(
            files_from(&name("DCIM/100CANON/IMG_0001.JPG")).unwrap(),
            "DCIM/100CANON/IMG_0001.JPG\n"
        );
        for refused in ["/etc/passwd", "../x", "a/../../x", "", "two\nlines", "."] {
            assert!(files_from(&name(refused)).is_err(), "{refused:?}");
        }
        assert_eq!(rsync_quote("it's"), "'it''s'");
    }

    #[test]
    fn display_all_starts_each_device_and_preserves_success_when_laptop_is_offline() {
        let (_directory, channels) = fixture();
        let request = json!({"ask":"owner","device":"all","steps":[{"do":"display","on":false}]});
        let targets = ["pc", "mini", "laptop"]
            .map(|host| (host.to_owned(), host.to_owned()))
            .to_vec();
        let reply = channels
            .call_targets(targets, &request, Duration::from_secs(2))
            .unwrap();
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["did"].as_array().unwrap().len(), 2);
        assert!(reply["error"].as_str().unwrap().contains("laptop"));
        for host in ["pc", "mini"] {
            assert_eq!(
                reply["devices"][host]["request"]["steps"][0],
                json!({"do":"display","on":false})
            );
        }
        // Laptop-only display still uses that channel; never substitute pc.
        assert!(channels
            .call_targets(
                vec![("laptop".into(), "laptop".into())],
                &request,
                Duration::from_secs(2)
            )
            .unwrap_err()
            .contains("laptop"));
    }
}
