use odin_domain::huginn::LiveSessionId;
use odin_domain::Digest;

use super::{ChildLifecycleSnapshot, GovernedTaskOwner, SettledChild};

impl GovernedTaskOwner {
    /// Reports settled answers and failures, including failures without a known epoch.
    pub(super) fn settled_turn(
        &self,
        child: LiveSessionId,
        snapshot: &ChildLifecycleSnapshot,
    ) -> Option<SettledChild> {
        use odin_domain::huginn::LiveSessionState::{Failed, Idle};
        let failed = snapshot.state == Some(Failed);
        if snapshot.active && snapshot.state != Some(Idle) && !failed {
            return None;
        }
        if !failed {
            let answer = match self.control.last_answer(child, snapshot.epoch) {
                Ok(Some(answer)) => answer,
                Ok(None) => return None,
                Err(error) => {
                    tracing::error!(
                        "odin-omp: delegated child history unreadable child={child} reason={error}"
                    );
                    return Some(SettledChild {
                        child,
                        key: "history-unreadable".to_owned(),
                        answer: format!("its history could not be read: {error}"),
                        failed: true,
                    });
                }
            };
            let digest = Digest::hash(answer.as_bytes()).to_string();
            let key = digest.trim_start_matches("blake3:")[..12].to_owned();
            return Some(SettledChild {
                child,
                key,
                answer,
                failed: false,
            });
        }
        let proved = snapshot.epoch.filter(|epoch| *epoch > 0);
        let Some(epoch) = proved else {
            tracing::error!(
                "odin-omp: failed delegated child reported without a proved epoch child={child} \
                 epoch={:?}",
                snapshot.epoch
            );
            let answer = match self.control.last_answer(child, snapshot.epoch) {
                Ok(answer) => answer.unwrap_or_default(),
                Err(error) => {
                    tracing::error!(
                        "odin-omp: failed delegated child partial work unreadable child={child} \
                         reason={error}"
                    );
                    String::new()
                }
            };
            return Some(SettledChild {
                child,
                key: "failed-unproved".to_owned(),
                answer,
                failed: true,
            });
        };
        let answer = match self.control.last_answer(child, Some(epoch)) {
            Ok(answer) => answer.unwrap_or_default(),
            Err(error) => {
                tracing::error!(
                    "odin-omp: failed delegated child partial work unreadable child={child} \
                     reason={error}"
                );
                String::new()
            }
        };
        Some(SettledChild {
            child,
            key: format!("failed-{epoch}"),
            answer,
            failed: true,
        })
    }
}
