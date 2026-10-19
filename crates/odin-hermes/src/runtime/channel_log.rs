//! Serves owner-channel reads from locally observed messages and edits to avoid
//! Discord rate-gate latency. REST seeds the cache, fills older cursors and periodically resyncs it.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use odin_domain::huginn::ConversationLine;

const KEEP: usize = 200;
/// How old the last full read of the channel may get before a background
/// read refreshes it.
const RESYNC: Duration = Duration::from_secs(5 * 60);

#[derive(Default)]
pub(super) struct ChannelLog {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// By snowflake: Discord ids order by time.
    lines: BTreeMap<u64, ConversationLine>,
    synced_at: Option<Instant>,
    syncing: bool,
}

fn snowflake(id: &str) -> Option<u64> {
    id.parse().ok()
}

impl State {
    fn insert(&mut self, line: ConversationLine) {
        let Some(key) = snowflake(&line.id) else {
            return;
        };
        self.lines.insert(key, line);
        while self.lines.len() > KEEP {
            self.lines.pop_first();
        }
    }
}

impl ChannelLog {
    /// A line seen in the channel (sent, received or read back).
    pub(super) fn record(&self, line: ConversationLine) {
        if let Ok(mut state) = self.state.lock() {
            state.insert(line);
        }
    }

    pub(super) fn edit(&self, id: &str, text: &str) {
        let Some(key) = snowflake(id) else {
            return;
        };
        if let Ok(mut state) = self.state.lock() {
            if let Some(line) = state.lines.get_mut(&key) {
                line.text = text.to_owned();
            }
        }
    }

    /// A line the channel no longer holds: a reply edit deleted the chunk.
    pub(super) fn delete(&self, id: &str) {
        let Some(key) = snowflake(id) else {
            return;
        };
        if let Ok(mut state) = self.state.lock() {
            state.lines.remove(&key);
        }
    }

    /// A full read of the channel's newest window.
    pub(super) fn seed(&self, lines: Vec<ConversationLine>) {
        if let Ok(mut state) = self.state.lock() {
            for line in lines {
                state.insert(line);
            }
            state.synced_at = Some(Instant::now());
            state.syncing = false;
        }
    }

    pub(super) fn sync_failed(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.syncing = false;
        }
    }

    /// The lines after `after` (the newest `limit` when `None`), oldest
    /// first — `None` when the log cannot answer: never seeded, or the
    /// cursor is older than what it keeps.
    pub(super) fn after(&self, after: Option<&str>, limit: usize) -> Option<Vec<ConversationLine>> {
        let state = self.state.lock().ok()?;
        state.synced_at?;
        let lines: Vec<ConversationLine> = match after {
            None => {
                let skip = state.lines.len().saturating_sub(limit);
                state.lines.values().skip(skip).cloned().collect()
            }
            Some(after) => {
                let cursor = snowflake(after)?;
                let oldest = state.lines.keys().next().copied().unwrap_or(u64::MAX);
                if cursor < oldest && state.lines.len() == KEEP {
                    return None;
                }
                state
                    .lines
                    .range(cursor.saturating_add(1)..)
                    .take(limit)
                    .map(|(_, line)| line.clone())
                    .collect()
            }
        };
        Some(lines)
    }

    /// Claims the background refresh when the last full read is old.
    pub(super) fn claim_resync(&self) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        let due = state.synced_at.is_none_or(|at| at.elapsed() >= RESYNC);
        if due && !state.syncing {
            state.syncing = true;
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(id: u64, text: &str) -> ConversationLine {
        ConversationLine {
            id: id.to_string(),
            from_owner: false,
            text: text.to_owned(),
            files: Vec::new(),
        }
    }

    #[test]
    fn reads_are_served_from_what_the_runtime_saw() {
        let log = ChannelLog::default();
        assert_eq!(log.after(None, 50), None, "never seeded: read Discord");
        log.seed(vec![line(10, "a"), line(20, "b")]);
        log.record(line(30, "c"));
        log.record(line(25, "late catch-up"));
        log.edit("30", "c, finished");
        let after = log.after(Some("20"), 50).expect("served");
        assert_eq!(
            after
                .iter()
                .map(|line| line.text.as_str())
                .collect::<Vec<_>>(),
            ["late catch-up", "c, finished"]
        );
        assert_eq!(log.after(None, 2).expect("served").len(), 2);
        assert!(log.after(Some("30"), 50).expect("served").is_empty());
        log.delete("25");
        assert_eq!(
            log.after(Some("20"), 50).expect("served").len(),
            1,
            "a deleted chunk line leaves the log"
        );
        assert!(!log.claim_resync(), "fresh");
    }

    #[test]
    fn a_cursor_older_than_the_log_reads_discord() {
        let log = ChannelLog::default();
        log.seed(
            (1..=KEEP as u64 + 5)
                .map(|id| line(id + 100, "x"))
                .collect(),
        );
        assert_eq!(log.after(Some("1"), 50), None);
        assert!(log.after(Some("200"), 50).is_some());
    }
}
