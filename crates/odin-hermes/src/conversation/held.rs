//! Replies held behind the owner's yes/no. A turn that asks him settles with
//! its reply held, and the approval card stands in for it. Once he decides,
//! the held reply closes unsent: the decision's own continuation is what he
//! hears. If the approval expires unanswered, he is told in one line that it
//! lapsed and nothing was done.

use odin_domain::ApprovalStatus;

use super::delivery::ReplyDisposition;
use super::{ConversationRoot, HeldReply};
use crate::runtime::DeliveredApproval;

fn lapsed_line(asked: &str) -> String {
    format!("The yes/no for {asked} lapsed unanswered, so nothing was done.")
}

impl ConversationRoot {
    /// Holds `reply` behind each approval its turn put to the owner; `None`
    /// when the turn has no reply of its own to close (a wake still owns
    /// it, or a holding line already went out), so only a lapse is told.
    pub(super) fn hold_reply(
        &self,
        reply: Option<&str>,
        asked: &[DeliveredApproval],
    ) -> Result<(), String> {
        if asked.is_empty() {
            return Ok(());
        }
        let mut record = self.load_record()?;
        for approval in asked {
            let approval_id = approval.approval_id.to_string();
            if record
                .held
                .iter()
                .any(|held| held.reply.as_deref() == reply && held.approval_id == approval_id)
            {
                continue;
            }
            let asked = format!("\u{201c}{}\u{201d}", approval.label);
            record.held.push(HeldReply {
                reply: reply.map(str::to_owned),
                approval_id,
                asked,
            });
        }
        self.store_record(&mut record)
    }

    /// Settles every held reply whose approval no longer waits on the owner.
    /// A conversation busy with a turn is left for the next call.
    pub(super) async fn settle_held(&self) -> Result<(), String> {
        let Ok(_guard) = self.lock.try_lock() else {
            return Ok(());
        };
        let mut record = self.load_record()?;
        if record.held.is_empty() {
            return Ok(());
        }
        let mut kept = Vec::new();
        for held in std::mem::take(&mut record.held) {
            match self.settle_one(&held).await {
                Ok(true) => {}
                Ok(false) => kept.push(held),
                Err(error) => {
                    tracing::warn!(
                        approval = %held.approval_id,
                        "odind: held reply not settled approval={}: {error}",
                        held.approval_id
                    );
                    kept.push(held);
                }
            }
        }
        record.held = kept;
        self.store_record(&mut record)
    }

    /// Whether `held` is settled: closed, and told as lapsed if its
    /// approval expired. A still-requested approval keeps it held.
    async fn settle_one(&self, held: &HeldReply) -> Result<bool, String> {
        let status = self.approvals.approval_status(&held.approval_id).await?;
        if status == Some(ApprovalStatus::Requested) {
            return Ok(false);
        }
        if let Some(reply) = &held.reply {
            self.close_held(reply)
                .map_err(|error| format!("the held reply {reply} could not close: {error}"))?;
        }
        if status != Some(ApprovalStatus::Expired) {
            return Ok(true);
        }
        let key = format!("lapsed:{}", held.approval_id);
        match self.deliver_final(&key, &lapsed_line(&held.asked), None) {
            Ok(_) => Ok(true),
            // A send whose outcome is unknown is never repeated.
            Err(error) if matches!(self.reply_disposition(&key), Ok(ReplyDisposition::Unknown)) => {
                tracing::warn!(
                    key = %key,
                    "odind: lapsed line outcome unknown key={key}, not resent: {error}"
                );
                Ok(true)
            }
            Err(error) => Err(format!("the lapsed line was not sent: {error}")),
        }
    }
}
