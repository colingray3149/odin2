//! Approvals waiting on the owner, put to the client as permission requests in
//! the session that asked, or the owner conversation when that session is not
//! open (a project seat's campaign cards), at any time (not only during a prompt); the
//! answer is the `ApprovalDecision`.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use odin_cli::authority_provision;
use odin_domain::huginn as live;
use odin_domain::ApprovalStatus;
use odin_huginn::approvals::ApprovalView;
use serde_json::{json, Value};
use tokio::sync::oneshot;

use super::{lock, Peer, LIVE_PREFIX};

impl Peer {
    /// The open session an approval belongs to.
    fn approval_session(&self, view: &ApprovalView) -> Option<String> {
        let followers = lock(&self.followers);
        let conversation = lock(&self.conversation).clone();
        approval_session(&view.target_id, followers.keys(), conversation)
    }

    /// Puts every approval still waiting, and not yet asked on this
    /// connection, to the client in its session. A reconnect asks again what
    /// is still waiting.
    pub(super) async fn ask_approvals(self: &Arc<Self>) {
        let Ok(objects) = self.snapshot_all(live::ObjectKind::Approval).await else {
            return;
        };
        for object in objects {
            let Ok(view) = serde_json::from_value::<ApprovalView>(object.value) else {
                continue;
            };
            if view.status != ApprovalStatus::Requested {
                continue;
            }
            let Some(session) = self.approval_session(&view) else {
                continue;
            };
            if !lock(&self.approvals).insert(view.approval_id.to_string()) {
                continue;
            }
            let peer = Arc::clone(self);
            tokio::spawn(async move { peer.ask(&session, &view).await });
        }
    }

    /// One approval as an ACP permission request; the answer becomes the decision.
    async fn ask(&self, session: &str, view: &ApprovalView) {
        // An approval that has already lapsed is not put to the client.
        let Ok(wait) = Duration::try_from(view.expires_at - time::OffsetDateTime::now_utc()) else {
            return;
        };
        let track = self.track(session);
        track.asking.fetch_add(1, Ordering::Relaxed);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (answer, answered) = oneshot::channel();
        lock(&self.asked).insert(id, answer);
        // The card is the tool call that asked, with its arguments, when known.
        let approval = view.approval_id.to_string();
        let call = lock(&self.asked_by).get(&approval).cloned();
        let shown = call
            .as_ref()
            .and_then(|call| lock(&self.calls).get(call).cloned());
        let (tool_call_id, title, input) = match (call, shown) {
            (Some(call), Some((title, input))) => (
                call,
                format!("Approve {} ({title})?", view.capability_id),
                input,
            ),
            _ => (
                approval,
                format!("Approve {}?", view.capability_id),
                Value::Null,
            ),
        };
        let _ = self.out.send(
            json!({"jsonrpc": "2.0", "id": id, "method": "session/request_permission",
            "params": {"sessionId": session,
                "toolCall": {"toolCallId": tool_call_id, "title": title,
                    "kind": "other", "status": "pending", "rawInput": input},
                "options": [
                    {"optionId": "approve", "name": "Approve", "kind": "allow_once"},
                    {"optionId": "reject", "name": "Reject", "kind": "reject_once"},
                ]}}),
        );
        let answer = tokio::time::timeout(wait, answered).await;
        lock(&self.asked).remove(&id);
        let chosen = answer.ok().and_then(Result::ok).and_then(|reply| {
            let outcome = &reply["result"]["outcome"];
            (outcome["outcome"] == "selected")
                .then(|| outcome["optionId"].as_str().map(str::to_owned))
                .flatten()
        });
        let decided = match chosen {
            // Dismissed: the approval stays waiting for the owner's yes elsewhere.
            None => false,
            Some(chosen) => self.decide(session, view, chosen == "approve").await,
        };
        if decided {
            track.approved.send_modify(|count| *count += 1);
        }
        track.asking.fetch_sub(1, Ordering::Relaxed);
    }

    /// Records the decision; whether it approved.
    async fn decide(&self, session: &str, view: &ApprovalView, approve: bool) -> bool {
        let Ok(command_id) = authority_provision::random_command_uuid() else {
            return false;
        };
        let request = live::HuginnRequest::ApprovalDecision(live::ApprovalDecisionCommand {
            command_id,
            approval_id: view.approval_id.clone(),
            expected_revision: view.revision,
            decision: if approve {
                live::ApprovalDecision::Approve
            } else {
                live::ApprovalDecision::Reject
            },
        });
        match self.request(request).await {
            Ok(_) => approve,
            Err(error) => {
                self.say_in(
                    session,
                    &format!("\n(the decision was not recorded: {error})\n"),
                );
                false
            }
        }
    }
}

/// The seat session the approval's target names, when the client has it open,
/// else the owner conversation when that is open: every approval waits on
/// the owner, also one a project seat or Kubert raised in a session the client never opened.
fn approval_session<'a>(
    target: &str,
    open: impl Iterator<Item = &'a String>,
    conversation: Option<String>,
) -> Option<String> {
    let open: Vec<&String> = open.collect();
    open.iter()
        .find(|id| {
            id.strip_prefix(LIVE_PREFIX)
                .is_some_and(|session| target.contains(session))
        })
        .map(|id| (*id).clone())
        .or_else(|| conversation.filter(|conversation| open.contains(&conversation)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn another_seats_approval_is_asked_in_the_owner_conversation() {
        let conversation = "conversation".to_owned();
        let seat = format!("{LIVE_PREFIX}a84b3803");
        let target = "run:live:a84b3803-105d-40f7-877b-2f3f3cd90844";
        let only_conversation = [conversation.clone()];
        assert_eq!(
            approval_session(target, only_conversation.iter(), Some(conversation.clone())),
            Some(conversation.clone())
        );
        let both = [conversation.clone(), seat.clone()];
        assert_eq!(
            approval_session(target, both.iter(), Some(conversation.clone())),
            Some(seat)
        );
        assert_eq!(
            approval_session(target, [].iter(), Some(conversation)),
            None
        );
    }
}
