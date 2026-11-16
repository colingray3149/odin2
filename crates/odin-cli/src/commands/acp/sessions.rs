//! The sessions an ACP client sees: the owner conversation, every live seat
//! session and every Odin pod, and a watcher that tells the client when one
//! starts, changes or ends, so its list follows Odin without a refresh.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use odin_domain::huginn as live;
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::{lock, Peer, LIVE_PREFIX, POD_PREFIX};

/// How often the watcher reads the sessions and the waiting approvals.
const WATCH_EVERY: Duration = Duration::from_secs(3);
/// How long a finished pod stays listed, so its end can be seen.
const ENDED_POD_LISTED: time::Duration = time::Duration::minutes(10);

/// One listed session.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Entry {
    pub(super) id: String,
    pub(super) title: String,
    /// conversation, seat or pod.
    pub(super) kind: &'static str,
    pub(super) state: String,
    pub(super) seat: String,
    pub(super) updated_at: Option<OffsetDateTime>,
    /// A pod's newest status report and its progress fraction.
    pub(super) summary: Option<String>,
    pub(super) progress: Option<f64>,
}

impl Entry {
    /// The entry as ACP `SessionInfo`; `cwd` is the client's own, since an
    /// Odin session has no working directory of the client's.
    pub(super) fn info(&self, cwd: &str) -> Value {
        json!({
            "sessionId": self.id,
            "cwd": cwd,
            "title": self.title,
            "updatedAt": self.updated_at.and_then(|at| at.format(&Rfc3339).ok()),
            "_meta": {"odin": {"kind": self.kind, "state": self.state, "seat": self.seat}},
        })
    }

    /// A pod's state and newest report, as one line.
    pub(super) fn pod_line(&self, name: &str) -> String {
        let mut line = format!("{} ({name}) is {}", self.title, self.state);
        if let Some(summary) = &self.summary {
            line.push_str(&format!(": {summary}"));
        }
        if let Some(progress) = self.progress {
            line.push_str(&format!(" ({:.0}%)", progress * 100.0));
        }
        line.push('\n');
        line
    }

    fn update(&self) -> Value {
        json!({
            "sessionUpdate": "session_info_update",
            "title": self.title,
            "updatedAt": self.updated_at.and_then(|at| at.format(&Rfc3339).ok()),
            "_meta": {"odin": {"kind": self.kind, "state": self.state, "seat": self.seat}},
        })
    }
}

fn word<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

impl Peer {
    /// Every object of one kind, all pages.
    pub(super) async fn snapshot_all(
        &self,
        kind: live::ObjectKind,
    ) -> Result<Vec<live::ObjectSnapshot>, String> {
        let mut objects = Vec::new();
        let mut cursor = None;
        loop {
            let query = live::HuginnRequest::Snapshot(live::SnapshotQuery {
                scope: live::QueryScope::All,
                kinds: vec![kind],
                if_revision: None,
                cursor: cursor.take(),
                limit: std::num::NonZeroU16::new(1000).expect("1000 is non-zero"),
                include_stale: false,
            });
            let live::HuginnResponse::Snapshot(page) = self.request(query).await? else {
                return Err(format!("the {kind:?} snapshot did not answer"));
            };
            objects.extend(page.objects);
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => return Ok(objects),
            }
        }
    }

    /// Every seat with its live sessions.
    pub(super) async fn roster(&self) -> Result<Vec<live::SeatRosterEntry>, String> {
        Ok(self
            .snapshot_all(live::ObjectKind::Seat)
            .await?
            .into_iter()
            .filter_map(|object| {
                serde_json::from_value(object.value.get("data").cloned().unwrap_or(Value::Null))
                    .ok()
            })
            .collect())
    }

    /// The listed sessions: the conversation first, then seat sessions, then pods.
    pub(super) async fn list(&self) -> Result<Vec<Entry>, String> {
        let live::HuginnResponse::Conversation(view) = self
            .request(live::HuginnRequest::ConversationStatus)
            .await?
        else {
            return Err("the conversation status did not answer".to_owned());
        };
        *lock(&self.conversation) = Some(view.conversation_id.clone());
        *lock(&self.vehicle) = view.vehicle_session;
        let roster = self.roster().await?;
        let mut entries = Vec::new();
        let mut conversation = Entry {
            id: view.conversation_id.clone(),
            title: "Conversation".to_owned(),
            kind: "conversation",
            state: "idle".to_owned(),
            seat: view.seat_id.to_string(),
            updated_at: None,
            summary: None,
            progress: None,
        };
        let mut seats = Vec::new();
        for entry in &roster {
            for session in &entry.active_sessions {
                if Some(session.session_id) == view.vehicle_session {
                    conversation.title = entry.display_name.clone();
                    conversation.state = word(&session.state);
                    conversation.updated_at = Some(session.updated_at);
                    continue;
                }
                let title = match session.title.as_deref().filter(|title| !title.is_empty()) {
                    Some(title) => format!("{} · {title}", entry.display_name),
                    None => entry.display_name.clone(),
                };
                seats.push(Entry {
                    id: format!("{LIVE_PREFIX}{}", session.session_id),
                    title,
                    kind: "seat",
                    state: word(&session.state),
                    seat: entry.seat_id.to_string(),
                    updated_at: Some(session.updated_at),
                    summary: None,
                    progress: None,
                });
            }
        }
        entries.push(conversation);
        entries.extend(seats);
        let now = OffsetDateTime::now_utc();
        for object in self.snapshot_all(live::ObjectKind::KubeResource).await? {
            let Ok(pod) = serde_json::from_value::<live::KubeWorkloadView>(object.value) else {
                continue;
            };
            let live::KubeResourceOwnership::Odin { seat_id, .. } = &pod.ownership else {
                continue;
            };
            let ended = matches!(
                pod.state,
                live::KubeWorkloadState::Succeeded | live::KubeWorkloadState::Failed
            );
            if ended && pod.finished_at.is_none_or(|at| now - at > ENDED_POD_LISTED) {
                continue;
            }
            let name = pod
                .label
                .as_deref()
                .or(pod.profile.as_deref())
                .unwrap_or(&pod.resource.name);
            entries.push(Entry {
                id: format!("{POD_PREFIX}{}", pod.resource.name),
                title: format!("pod · {name}"),
                kind: "pod",
                state: word(&pod.state),
                seat: seat_id.to_string(),
                updated_at: pod
                    .status
                    .as_ref()
                    .map(|status| status.at)
                    .or(pod.finished_at)
                    .or(pod.started_at),
                summary: pod
                    .status
                    .as_ref()
                    .and_then(|status| status.summary.clone()),
                progress: pod.status.as_ref().and_then(|status| status.progress),
            });
        }
        Ok(entries)
    }

    /// Starts the watcher once per connection.
    pub(super) fn watch(self: &Arc<Self>) {
        let mut watcher = lock(&self.watcher);
        if watcher.is_some() {
            return;
        }
        let peer = Arc::clone(self);
        *watcher = Some(tokio::spawn(async move {
            loop {
                match peer.list().await {
                    Ok(entries) => {
                        peer.changed(entries);
                        peer.hang_up_if_due();
                    }
                    Err(error) => tracing::warn!("odin acp: the sessions are unreadable: {error}"),
                }
                peer.ask_approvals().await;
                tokio::time::sleep(WATCH_EVERY).await;
            }
        }));
    }

    /// Hangs up a reconnecting client once sessions started or ended and
    /// nothing is in flight (no prompt waiting, no permission card open), so
    /// it lists them again on reconnect.
    fn hang_up_if_due(&self) {
        let idle = self.prompts.load(Ordering::Relaxed) == 0
            && lock(&self.tracks)
                .values()
                .all(|track| track.asking.load(Ordering::Relaxed) == 0);
        if self.reconnects && idle && self.relist.load(Ordering::Relaxed) {
            tracing::info!(
                "odin acp: sessions started or ended; hanging up so the client lists them again"
            );
            let _ = self.hang_up.send(true);
        }
    }

    /// Tells the client what started, changed or ended since the last read.
    fn changed(&self, entries: Vec<Entry>) {
        let now: BTreeMap<String, Entry> = entries
            .into_iter()
            .map(|entry| (entry.id.clone(), entry))
            .collect();
        let before = std::mem::replace(&mut *lock(&self.known), now.clone());
        let first = before.is_empty();
        let followed = |id: &str| lock(&self.followers).contains_key(id);
        let mut moved = false;
        for (id, entry) in &now {
            let previous = before.get(id);
            if previous == Some(entry) {
                continue;
            }
            moved = true;
            if first {
                continue;
            }
            self.update(id, entry.update());
            if let (Some(name), true) = (id.strip_prefix(POD_PREFIX), followed(id)) {
                if previous.is_none_or(|previous| {
                    previous.state != entry.state || previous.summary != entry.summary
                }) {
                    self.say_in(id, &entry.pod_line(name));
                }
            }
        }
        for (id, entry) in &before {
            if now.contains_key(id) {
                continue;
            }
            moved = true;
            let mut ended = entry.clone();
            ended.state = "ended".to_owned();
            self.update(id, ended.update());
            if followed(id) {
                self.say_in(id, "\n(this session has ended)\n");
                if let Some(task) = lock(&self.followers).remove(id) {
                    task.abort();
                }
            }
        }
        if !first && now.keys().ne(before.keys()) {
            self.relist.store(true, Ordering::Relaxed);
        }
        if moved && !first {
            let _ = self
                .out
                .send(json!({"jsonrpc": "2.0", "method": "_odin/sessions_changed",
                "params": {"sessions": now.len()}}));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_listed_session_carries_its_kind_state_and_the_clients_folder() {
        let entry = Entry {
            id: "pod:odin-1".to_owned(),
            title: "pod · rde-datasets".to_owned(),
            kind: "pod",
            state: "running".to_owned(),
            seat: "seat-a".to_owned(),
            updated_at: None,
            summary: Some("reading sources".to_owned()),
            progress: Some(0.4),
        };
        let info = entry.info("/home/owner");
        assert_eq!(info["cwd"], "/home/owner");
        assert_eq!(info["_meta"]["odin"]["kind"], "pod");
        assert_eq!(
            entry.pod_line("odin-1"),
            "pod · rde-datasets (odin-1) is running: reading sources (40%)\n"
        );
    }
}
