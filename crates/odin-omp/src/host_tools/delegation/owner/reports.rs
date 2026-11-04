use super::CompletionEventObserver;

use odin_domain::huginn::LiveSessionId;
use odin_domain::Digest;

use super::{ChildLifecycleSnapshot, GovernedTaskOwner, SettledChild};

/// Every failed child's settled key starts with this.
pub(crate) const FAILED_KEY_PREFIX: &str = "failed-";
/// The settled key of a failure whose incarnation epoch was never proved.
pub(crate) const FAILED_UNPROVED_KEY: &str = "failed-unproved";
/// The settled key of a child whose history could not be read.
const HISTORY_UNREADABLE_KEY: &str = "history-unreadable";

/// The short key one answer text carries.
pub(super) fn answer_key(answer: &str) -> String {
    Digest::hash(answer.as_bytes()).hex()[..12].to_owned()
}

/// The typed key that names one settled turn: the answer's digest, or the
/// failed incarnation's epoch — never its partial text. The seat-ask
/// receipt and the child-report pump derive the same key, so an answer
/// delivered inline and its later report are one event, not two.
pub fn settled_key(answer: Option<&str>, failed_epoch: Option<i64>) -> String {
    match answer {
        Some(answer) => answer_key(answer),
        // A failure without a proved epoch is named once, never per scan.
        None => failed_epoch.map_or_else(
            || FAILED_UNPROVED_KEY.to_owned(),
            |epoch| format!("{FAILED_KEY_PREFIX}{epoch}"),
        ),
    }
}

impl CompletionEventObserver for GovernedTaskOwner {
    /// Durable result notification; not a final-task acknowledgment.
    fn result_persisted(&self, child: LiveSessionId, sequence: u64) {
        self.observe_result(&child, sequence);
        self.result_wake.notify_one();
    }
}

impl GovernedTaskOwner {
    /// One incremental last-answer read through the owner's per-child
    /// cursor: only events appended since the previous scan are paged, an
    /// epoch change resets to the whole history, and an unchanged range
    /// keeps the previously observed answer.
    fn paced_last_answer(
        &self,
        child: LiveSessionId,
        epoch: Option<i64>,
    ) -> Result<Option<String>, String> {
        let (after, prior) = {
            let scans = self.answer_scans.lock();
            match scans.get(&child) {
                Some(scan) if scan.epoch == epoch => (scan.head, scan.answer.clone()),
                _ => (0, None),
            }
        };
        let scan = self.control.last_answer_after(child, epoch, after)?;
        let head = scan.head;
        let answer = if scan.reset {
            scan.answer
        } else {
            scan.answer.or(prior)
        };
        let mut scans = self.answer_scans.lock();
        if scans.len() >= super::ANSWER_SCAN_CHILDREN && !scans.contains_key(&child) {
            scans.pop_first();
        }
        scans.insert(
            child,
            super::AnswerScan {
                epoch,
                head,
                answer: answer.clone(),
            },
        );
        Ok(answer)
    }
    /// Reports settled answers and failures, including failures without a known epoch.
    pub(crate) fn settled_turn(
        &self,
        child: LiveSessionId,
        snapshot: &ChildLifecycleSnapshot,
    ) -> Option<SettledChild> {
        use odin_domain::huginn::LiveSessionState::{Ended, Failed, Idle};
        let failed = snapshot.state == Some(Failed);
        if !matches!(snapshot.state, Some(Idle | Failed | Ended)) {
            return None;
        }
        if !failed {
            let answer = match self.paced_last_answer(child, snapshot.epoch) {
                Ok(Some(answer)) => answer,
                Ok(None) => return None,
                Err(error) => {
                    tracing::error!(
                        "odin-omp: delegated child history unreadable child={child} reason={error}"
                    );
                    return Some(SettledChild {
                        child,
                        key: HISTORY_UNREADABLE_KEY.to_owned(),
                        answer: format!("its history could not be read: {error}"),
                        failed: true,
                    });
                }
            };
            let key = settled_key(Some(answer.as_str()), None);
            return Some(SettledChild {
                child,
                key,
                answer,
                failed: false,
            });
        }
        // What a parent is told when the failed child's partial work cannot be read: the
        // cause, not an empty answer that would read as "it wrote nothing".
        let partial = |epoch: Option<i64>| match self.paced_last_answer(child, epoch) {
            Ok(answer) => answer.unwrap_or_default(),
            Err(error) => {
                tracing::error!(
                    "odin-omp: failed delegated child partial work unreadable child={child} \
                     reason={error}"
                );
                format!("(its partial work could not be read: {error})")
            }
        };
        let proved = snapshot.epoch.filter(|epoch| *epoch > 0);
        if proved.is_none() {
            tracing::error!(
                "odin-omp: failed delegated child reported without a proved epoch child={child} \
                 epoch={:?}",
                snapshot.epoch
            );
        }
        Some(SettledChild {
            child,
            key: settled_key(None, proved),
            answer: partial(snapshot.epoch),
            failed: true,
        })
    }
}
