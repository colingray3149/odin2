use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use odin_kernel::StopAuthority;
use odin_types::WorkerId;
use serde_json::Value;

use super::{newest_transcript, workspace_slug, ProcessStamp};

/// What Claude itself has recorded about Remote Control. Argv never
/// produces `Active`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum BridgeRegistration {
    /// `--remote-control` was named; Claude has not recorded a bridge yet.
    Requested,
    /// No request was seen and no record confirms a bridge.
    Unknown,
    /// Claude recorded a bridge. `session_url` is set only when that
    /// registration itself supplied one; an id is never turned into a URL.
    Active { session_url: Option<String> },
    /// Claude recorded a rejected or failed registration.
    Failed { reason: String },
}

pub(super) fn bridge_session_id(value: &Value) -> Option<&str> {
    value
        .get("bridgeSessionId")
        .or_else(|| value.get("bridge_session_id"))
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty() && !id.contains('/') && !id.contains('\\') && !id.contains(' '))
}

pub(super) fn supplied_session_url(value: &Value) -> Option<String> {
    ["sessionUrl", "session_url"]
        .into_iter()
        .find_map(|key| value.get(key).and_then(Value::as_str))
        .or_else(|| {
            value
                .pointer("/response/session_url")
                .and_then(Value::as_str)
        })
        .filter(|url| url.starts_with("https://") && !url.contains(' '))
        .map(str::to_owned)
}

pub(super) fn registration_from_record(value: &Value) -> BridgeRegistration {
    if bridge_session_id(value).is_some() {
        return BridgeRegistration::Active {
            session_url: supplied_session_url(value),
        };
    }
    let failed = value
        .get("remoteControlError")
        .or_else(|| value.get("remote_control_error"))
        .and_then(Value::as_str)
        .filter(|reason| !reason.is_empty());
    if let Some(reason) = failed {
        return BridgeRegistration::Failed {
            reason: reason.to_owned(),
        };
    }
    let subtype = value.get("subtype").and_then(Value::as_str);
    let request = value.get("request").and_then(Value::as_object);
    let remote_request = request.is_some_and(|request| {
        request.get("subtype").and_then(Value::as_str) == Some("remote_control")
    }) || subtype == Some("remote_control");
    if remote_request && subtype == Some("error") {
        let reason = value
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("Claude rejected Remote Control");
        return BridgeRegistration::Failed {
            reason: reason.to_owned(),
        };
    }
    if let Some(url) = value
        .pointer("/response/session_url")
        .and_then(Value::as_str)
        .filter(|url| url.starts_with("https://") && !url.contains(' '))
    {
        if value
            .pointer("/response/bridge_session_id")
            .and_then(Value::as_str)
            .is_some_and(|id| !id.is_empty())
            && subtype == Some("success")
        {
            return BridgeRegistration::Active {
                session_url: Some(url.to_owned()),
            };
        }
    }
    BridgeRegistration::Requested
}

pub(super) fn registration_from_line(line: &str) -> Option<BridgeRegistration> {
    let value: Value = serde_json::from_str(line).ok()?;
    let found = registration_from_record(&value);
    match found {
        BridgeRegistration::Active { .. } | BridgeRegistration::Failed { .. } => Some(found),
        BridgeRegistration::Requested | BridgeRegistration::Unknown => None,
    }
}

/// Claude's per-process session record and the newest transcript under the
/// selected account directory. A bridge id there is the registration only
/// when the record names this workspace or session and belongs to a live
/// descendant of the process this session started. Argv is not proof, and
/// a record under `~/.claude` is not proof for a named account.
pub(super) async fn claude_bridge_registration(
    claude_dir: &Path,
    workspace: &Path,
    session: &str,
    session_process: Option<ProcessStamp>,
    registration_since: SystemTime,
) -> BridgeRegistration {
    let live = live_session_pids(session_process);
    let mut found = BridgeRegistration::Requested;
    if let Ok(mut entries) = tokio::fs::read_dir(claude_dir.join("sessions")).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            if !record_is_fresh(&entry.path(), registration_since).await {
                continue;
            }
            let Ok(text) = tokio::fs::read_to_string(entry.path()).await else {
                continue;
            };
            let Ok(value) = serde_json::from_str::<Value>(&text) else {
                continue;
            };
            if !record_belongs(&value, workspace, session, session_process, &live) {
                continue;
            }
            match registration_from_record(&value) {
                BridgeRegistration::Active { session_url } => {
                    return BridgeRegistration::Active { session_url };
                }
                BridgeRegistration::Failed { reason } => {
                    found = BridgeRegistration::Failed { reason };
                }
                BridgeRegistration::Requested | BridgeRegistration::Unknown => {}
            }
        }
    }
    if matches!(found, BridgeRegistration::Failed { .. }) {
        return found;
    }
    let slug = workspace_slug(workspace);
    let projects = claude_dir.join("projects").join(&slug);
    if let Some(file) = newest_transcript(&projects).await {
        if record_is_fresh(&file, registration_since).await {
            if let Ok(text) = tokio::fs::read_to_string(&file).await {
                for line in text.lines().rev().take(256) {
                    let Ok(value) = serde_json::from_str::<Value>(line) else {
                        continue;
                    };
                    if !record_belongs(&value, workspace, session, session_process, &live) {
                        continue;
                    }
                    if let Some(registration) = registration_from_line(line) {
                        return registration;
                    }
                }
            }
        }
    }
    found
}

async fn record_is_fresh(path: &Path, since: SystemTime) -> bool {
    tokio::fs::metadata(path)
        .await
        .and_then(|metadata| metadata.modified())
        .is_ok_and(|modified| modified >= since)
}

/// The record names this workspace or this session, and its pid is a live
/// descendant of the process this session started. A record with no pid, a
/// dead pid, or a pid from another process is stale and is not evidence.
pub(super) fn record_belongs(
    value: &Value,
    workspace: &Path,
    session: &str,
    session_process: Option<ProcessStamp>,
    live: &std::collections::BTreeSet<u32>,
) -> bool {
    let cwd = value.get("cwd").and_then(Value::as_str);
    let named = value
        .get("name")
        .or_else(|| value.get("sessionName"))
        .and_then(Value::as_str);
    let same_workspace = cwd.is_some_and(|cwd| Path::new(cwd) == workspace);
    let same_name = named.is_some_and(|name| name == session);
    if !same_workspace && !same_name {
        return false;
    }
    process_belongs(record_pid(value), session_process, live)
}

pub(super) fn record_pid(value: &Value) -> Option<u32> {
    value
        .get("pid")
        .and_then(Value::as_u64)
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 0)
}

/// A record is this session's only when its writer is still the process this
/// session started, or a live descendant of it. No captured identity means
/// there is no session to bind to, so the record is refused.
pub(super) fn process_belongs(
    pid: Option<u32>,
    session_process: Option<ProcessStamp>,
    live: &std::collections::BTreeSet<u32>,
) -> bool {
    let (Some(pid), Some(stamp)) = (pid, session_process) else {
        return false;
    };
    if !same_process(stamp) {
        return false;
    }
    pid == stamp.pid || live.contains(&pid)
}

/// Descendants of the session process that are still the same boot-time process.
pub(super) fn live_session_pids(
    session_process: Option<ProcessStamp>,
) -> std::collections::BTreeSet<u32> {
    let mut live = std::collections::BTreeSet::new();
    let Some(stamp) = session_process else {
        return live;
    };
    if !same_process(stamp) {
        return live;
    }
    live.insert(stamp.pid);
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return live;
    };
    let mut parents = std::collections::BTreeMap::new();
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        let Some(parent) = parent_pid(&stat) else {
            continue;
        };
        parents.insert(pid, parent);
    }
    let known: Vec<u32> = parents.keys().copied().collect();
    for pid in known {
        let mut cursor = pid;
        let mut guard = 0u32;
        while let Some(parent) = parents.get(&cursor).copied() {
            if parent == stamp.pid {
                live.insert(pid);
                break;
            }
            if parent == cursor || guard > 64 {
                break;
            }
            cursor = parent;
            guard += 1;
        }
    }
    live
}

pub(super) fn same_process(stamp: ProcessStamp) -> bool {
    std::fs::read_to_string(format!("/proc/{}/stat", stamp.pid))
        .ok()
        .and_then(|stat| start_ticks(&stat))
        == Some(stamp.start_ticks)
}

pub(super) fn parent_pid(stat: &str) -> Option<u32> {
    let command_end = stat.rfind(')')?;
    stat.get(command_end + 2..)?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

pub(super) fn start_ticks(stat: &str) -> Option<u64> {
    let command_end = stat.rfind(')')?;
    stat.get(command_end + 2..)?
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

/// The proved tmux server of this session, read back from its durable identity row.
pub(super) fn session_process(
    stops: &Arc<StopAuthority>,
    worker_id: &WorkerId,
) -> Option<ProcessStamp> {
    let store = stops.store();
    let ledger = store.lock().ok()?;
    let row = odin_ledger::worker::worker_row(ledger.connection(), worker_id.as_str())
        .ok()
        .flatten()?;
    Some(ProcessStamp {
        pid: row.leader_pid?,
        start_ticks: row.leader_start_ticks?,
    })
}
