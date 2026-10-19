//! Operator decision ownership over the live approval surface: which
//! pending questions are displayed and eligible, how a short reply names
//! exactly one request, and the generation-bound authenticated decision
//! command — never a direct mutation of approval authority in this client.

use odin_cli::operator_prompt;
use odin_domain::huginn as live;
use odin_domain::ApprovalId;
use odin_ledger::Ledger;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use time::OffsetDateTime;

use super::{io_error, Client};
use crate::session::transport::{generated_command_id, send_prompt};

/// One approval the operator can decide from this prompt: either a live
/// permission request from the model's tool surface, or a durable
/// kernel-minted request row (carrying the ledger revision the decision
/// must name exactly).
#[derive(Clone)]
pub(super) struct PendingDecision {
    request_id: String,
    capability_id: String,
    kernel_revision: Option<i64>,
}

/// Which single pending approval the owner's reply names, when it does.
enum PendingSelection {
    Decided(PendingDecision),
    NotOne(String),
    NonePending,
}

/// Like the DM route, accept only full IDs or unambiguous prefixes.
fn select_pending(pending: &[PendingDecision], selector: Option<&str>) -> PendingSelection {
    if pending.is_empty() {
        return PendingSelection::NonePending;
    }
    match selector {
        Some(token) => {
            let matches: Vec<&PendingDecision> = pending
                .iter()
                .filter(|permission| {
                    permission.request_id == token || permission.request_id.starts_with(token)
                })
                .collect();
            match matches.as_slice() {
                [one] => PendingSelection::Decided((*one).clone()),
                _ => PendingSelection::NotOne(format!(
                    "\"{token}\" does not name exactly one pending approval. Pending: {}",
                    pending
                        .iter()
                        .map(|permission| {
                            format!("{} [{}]", permission.request_id, permission.capability_id)
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                )),
            }
        }
        None => match pending {
            [one] => PendingSelection::Decided(one.clone()),
            _ => PendingSelection::NotOne(format!(
                "Several approvals are pending; reply with yes/no plus one of: {}",
                pending
                    .iter()
                    .map(|permission| permission.request_id.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        },
    }
}

/// Reads only undecided, unexpired approvals of this exact session.
fn kernel_pending(
    ledger_path: &Path,
    session: live::LiveSessionId,
) -> Result<Vec<odin_ledger::approval::Approval>, String> {
    let ledger = Ledger::open(ledger_path)
        .map_err(|error| format!("could not open the approval ledger: {error}"))?;
    let run = operator_prompt::session_run_id(&session)?;
    let now = OffsetDateTime::now_utc();
    Ok(ledger
        .requested_approvals_for_target("run", run.as_str())
        .map_err(|error| format!("could not read session approvals: {error}"))?
        .into_iter()
        .filter(|approval| approval.expires_at > now)
        .collect())
}

/// A successful write AND flush precedes recording the displayed revision.
/// Merely discovering a row never makes it eligible for a short reply.
pub(super) fn render_kernel_pending(
    ledger_path: &Path,
    session: live::LiveSessionId,
    shown: &mut BTreeMap<String, PendingDecision>,
    output: &mut dyn Write,
) -> Result<(), String> {
    for approval in kernel_pending(ledger_path, session)? {
        if shown
            .get(approval.approval_id.as_str())
            .is_some_and(|seen| seen.kernel_revision == Some(approval.revision))
        {
            continue;
        }
        writeln!(
            output,
            "\n[approval required: {}] durable approval {} (revision {}) — {} {}, arguments \
             digest {}; reply yes or no, optionally followed by an id prefix, to decide",
            approval.scope.capability_id,
            approval.approval_id,
            approval.revision,
            approval.scope.target_kind,
            approval.scope.target_id,
            approval.scope.arguments_digest,
        )
        .map_err(io_error)?;
        output.flush().map_err(io_error)?;
        shown.insert(
            approval.approval_id.to_string(),
            PendingDecision {
                request_id: approval.approval_id.to_string(),
                capability_id: approval.scope.capability_id.to_string(),
                kernel_revision: Some(approval.revision),
            },
        );
    }
    Ok(())
}

fn displayed_pending(
    ledger_path: &Path,
    session: live::LiveSessionId,
    shown: &BTreeMap<String, PendingDecision>,
) -> Result<Vec<PendingDecision>, String> {
    Ok(kernel_pending(ledger_path, session)?
        .into_iter()
        .filter_map(|approval| {
            shown
                .get(approval.approval_id.as_str())
                .filter(|seen| seen.kernel_revision == Some(approval.revision))
                .cloned()
        })
        .collect())
}

/// Short decisions apply only to a displayed request in this session.
/// The authenticated live command performs the durable decision and wake;
/// this client never mutates approval authority directly.
#[allow(clippy::too_many_arguments)]
pub(super) fn try_owner_decision(
    runtime: &tokio::runtime::Runtime,
    client: &Client,
    ledger_path: &Path,
    session_id: live::LiveSessionId,
    epoch: live::SessionEpoch,
    live_pending: &BTreeMap<String, (live::SessionEpoch, live::PermissionRequest)>,
    shown_kernel: &BTreeMap<String, PendingDecision>,
    text: &str,
    output: &mut dyn Write,
) -> Result<bool, String> {
    let trimmed = text.trim();
    let mut words = trimmed.split_whitespace();
    let Some(head) = words.next() else {
        return Ok(false);
    };
    let decision = match head.to_ascii_lowercase().as_str() {
        "yes" | "approve" | "allow" | "ok" | "y" => live::PermissionDecision::AllowOnce,
        "no" | "deny" | "reject" | "stop" | "n" => live::PermissionDecision::Deny,
        _ => return Ok(false),
    };
    let selector = words.next();
    if words.next().is_some() {
        return Ok(false);
    }
    let mut pending = displayed_pending(ledger_path, session_id, shown_kernel)?;
    let now = OffsetDateTime::now_utc();
    pending.extend(
        live_pending
            .iter()
            .filter(|(_, (shown_epoch, permission))| {
                *shown_epoch == epoch && permission.expires_at > now
            })
            .map(|(request_id, (_, permission))| PendingDecision {
                request_id: request_id.clone(),
                capability_id: permission.capability_id.to_string(),
                kernel_revision: None,
            }),
    );
    let target = match select_pending(&pending, selector) {
        PendingSelection::Decided(target) => target,
        PendingSelection::NotOne(reply) => {
            writeln!(output, "{reply}").map_err(io_error)?;
            return Ok(true);
        }
        PendingSelection::NonePending => {
            writeln!(
                output,
                "There is no pending approval right now; your message was not sent to the \
                 assistant. Send it again as a normal message."
            )
            .map_err(io_error)?;
            return Ok(true);
        }
    };
    let body = if let Some(revision) = target.kernel_revision {
        live::LiveCommandBody::DecideApproval {
            approval_id: ApprovalId::new(target.request_id.clone())
                .map_err(|error| error.to_string())?,
            expected_revision: u64::try_from(revision)
                .map_err(|_| "displayed approval revision is invalid".to_owned())?,
            decision: match decision {
                live::PermissionDecision::AllowOnce => live::ApprovalDecision::Approve,
                live::PermissionDecision::Deny => live::ApprovalDecision::Reject,
            },
        }
    } else {
        live::LiveCommandBody::DecidePermission {
            request_id: live::PermissionRequestId::parse(&target.request_id)
                .map_err(|error| error.to_string())?,
            decision,
        }
    };
    let command_id = generated_command_id()?;
    // A decision remains bound to the generation whose question was
    // displayed. Never recover/rebind it onto a replacement generation.
    let receipt = send_prompt(
        runtime,
        client,
        live::LiveCommand {
            command_id,
            session_id,
            expected_epoch: epoch,
            expected_event_head: None,
            body,
        },
    )?;
    if let live::CommandReceipt::Rejected { reason, .. } = receipt {
        writeln!(
            output,
            "The displayed decision was refused by the controller: {reason:?}"
        )
        .map_err(io_error)?;
        return Ok(true);
    }
    writeln!(
        output,
        "Decision submitted; the controller will report its outcome."
    )
    .map_err(io_error)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use odin_huginn::client::{ColinRemoteClient, EndpointTransport, FileCredentialStore};

    fn pending(id: &str, capability: &str) -> PendingDecision {
        PendingDecision {
            request_id: id.to_owned(),
            capability_id: capability.to_owned(),
            kernel_revision: None,
        }
    }

    #[test]
    fn retired_or_expired_native_questions_do_not_send_decisions() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let root = tempfile::tempdir().unwrap();
        let ledger_path = root.path().join("ledger.sqlite3");
        drop(Ledger::open(&ledger_path).unwrap());
        let transport =
            EndpointTransport::new(url::Url::parse("http://127.0.0.1:9/").unwrap()).unwrap();
        let client = ColinRemoteClient::with_limits(
            transport,
            FileCredentialStore::open(root.path().join("credentials")).unwrap(),
            odin_huginn::protocol::CodecLimits::default(),
        );
        let session = live::LiveSessionId::parse("00000000-0000-4000-8000-000000000009").unwrap();
        let epoch = live::SessionEpoch::new(2);
        let now = OffsetDateTime::now_utc();
        let mut requests = BTreeMap::new();
        let permission = live::PermissionRequest {
            request_id: live::PermissionRequestId::new("native-question").unwrap(),
            tool_use_id: "native-tool".to_owned(),
            capability_id: odin_domain::CapabilityId::new("native.confirm").unwrap(),
            arguments_digest: odin_domain::Digest::hash(b"{}"),
            prompt: "Confirm the requested action?".to_owned(),
            expires_at: now + time::Duration::minutes(1),
        };
        for (shown_epoch, expires_at) in [
            (live::SessionEpoch::new(1), permission.expires_at),
            (epoch, now - time::Duration::seconds(1)),
        ] {
            let mut shown = permission.clone();
            shown.expires_at = expires_at;
            requests.insert(shown.request_id.to_string(), (shown_epoch, shown));
            assert!(try_owner_decision(
                &runtime,
                &client,
                &ledger_path,
                session,
                epoch,
                &requests,
                &BTreeMap::new(),
                "yes",
                &mut Vec::new(),
            )
            .unwrap());
        }
        requests.insert(permission.request_id.to_string(), (epoch, permission));
        // A current unexpired question reaches the real client and fails
        // without credentials; the two refused cases never attempt a send.
        assert!(try_owner_decision(
            &runtime,
            &client,
            &ledger_path,
            session,
            epoch,
            &requests,
            &BTreeMap::new(),
            "yes",
            &mut Vec::new(),
        )
        .is_err());
    }

    #[test]
    fn single_pending_approval_is_selected_without_a_selector() {
        let list = vec![pending(
            "approval:r3:seat.ask.kubert:abc",
            "seat.ask.kubert",
        )];
        match select_pending(&list, None) {
            PendingSelection::Decided(target) => {
                assert_eq!(target.request_id, "approval:r3:seat.ask.kubert:abc");
            }
            _ => panic!("a single pending approval must be selected without a selector"),
        }
    }

    #[test]
    fn several_pending_approvals_ask_for_an_id_instead_of_guessing() {
        let list = vec![
            pending("approval:r3:a:1", "seat.ask.kubert"),
            pending("approval:r3:b:2", "seat.ask.gungnir"),
        ];
        match select_pending(&list, None) {
            PendingSelection::NotOne(reply) => {
                assert!(reply.contains("approval:r3:a:1"));
                assert!(reply.contains("approval:r3:b:2"));
            }
            _ => panic!("several pending approvals must ask the owner to disambiguate"),
        }
    }

    #[test]
    fn unique_id_prefix_selects_exactly_one_approval() {
        let list = vec![
            pending("approval:r3:seat.ask.kubert:abc", "seat.ask.kubert"),
            pending("approval:r3:seat.ask.gungnir:def", "seat.ask.gungnir"),
        ];
        match select_pending(&list, Some("approval:r3:seat.ask.k")) {
            PendingSelection::Decided(target) => {
                assert_eq!(target.capability_id, "seat.ask.kubert");
            }
            _ => panic!("an unambiguous prefix must select the one approval it names"),
        }
    }

    #[test]
    fn ambiguous_id_prefix_is_refused() {
        let list = vec![
            pending("approval:r3:a:1", "seat.ask.kubert"),
            pending("approval:r3:a:2", "seat.ask.gungnir"),
        ];
        assert!(matches!(
            select_pending(&list, Some("approval:r3:a")),
            PendingSelection::NotOne(_)
        ));
    }

    fn seed_approval(ledger: &mut Ledger, session: live::LiveSessionId, kind: &str, id: &str) {
        let now = OffsetDateTime::now_utc();
        ledger
            .request_approval(odin_ledger::approval::NewApproval {
                approval_id: ApprovalId::new(id).unwrap(),
                issuer: "seat:fixture".to_owned(),
                scope: odin_ledger::approval::ApprovalScope {
                    target_kind: kind.to_owned(),
                    target_id: operator_prompt::session_run_id(&session)
                        .unwrap()
                        .to_string(),
                    capability_id: odin_domain::CapabilityId::new("fixture.action").unwrap(),
                    arguments_digest: odin_domain::Digest::hash(id.as_bytes()),
                },
                requested_at: now,
                expires_at: now + time::Duration::hours(1),
            })
            .unwrap();
    }

    #[test]
    fn kernel_pending_excludes_foreign_targets_and_settled_rows() {
        let root = tempfile::TempDir::new().unwrap();
        let path = root.path().join("ledger.sqlite3");
        let session = live::LiveSessionId::parse("00000000-0000-4000-8000-000000000001").unwrap();
        let other = live::LiveSessionId::parse("00000000-0000-4000-8000-000000000002").unwrap();
        let mut ledger = Ledger::open(&path).unwrap();
        seed_approval(&mut ledger, session, "run", "approval:owned");
        seed_approval(&mut ledger, other, "run", "approval:foreign");
        seed_approval(&mut ledger, session, "session", "approval:wrong-kind");
        seed_approval(&mut ledger, session, "run", "approval:settled");
        ledger
            .decide_approval(
                &ApprovalId::new("approval:settled").unwrap(),
                odin_ledger::approval::ApprovalDecision::Deny {
                    evidence_ref: "fixture".to_owned(),
                },
                "device:fixture",
                OffsetDateTime::now_utc(),
                1,
            )
            .unwrap();
        let ids: Vec<_> = kernel_pending(&path, session)
            .unwrap()
            .into_iter()
            .map(|approval| approval.approval_id.to_string())
            .collect();
        assert_eq!(ids, ["approval:owned"]);
    }

    #[test]
    fn failed_delivery_and_unseen_replacement_never_become_yes_targets() {
        struct FailedFlush;
        impl Write for FailedFlush {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
        }
        let root = tempfile::TempDir::new().unwrap();
        let path = root.path().join("ledger.sqlite3");
        let session = live::LiveSessionId::parse("00000000-0000-4000-8000-000000000001").unwrap();
        let mut ledger = Ledger::open(&path).unwrap();
        seed_approval(&mut ledger, session, "run", "approval:first");
        let mut shown = BTreeMap::new();
        assert!(render_kernel_pending(&path, session, &mut shown, &mut FailedFlush).is_err());
        assert!(matches!(
            select_pending(&displayed_pending(&path, session, &shown).unwrap(), None),
            PendingSelection::NonePending
        ));
        render_kernel_pending(&path, session, &mut shown, &mut Vec::new()).unwrap();
        assert!(matches!(
            select_pending(&displayed_pending(&path, session, &shown).unwrap(), None),
            PendingSelection::Decided(_)
        ));
        ledger
            .decide_approval(
                &ApprovalId::new("approval:first").unwrap(),
                odin_ledger::approval::ApprovalDecision::Deny {
                    evidence_ref: "fixture".to_owned(),
                },
                "device:fixture",
                OffsetDateTime::now_utc(),
                1,
            )
            .unwrap();
        seed_approval(&mut ledger, session, "run", "approval:unseen");
        assert!(matches!(
            select_pending(&displayed_pending(&path, session, &shown).unwrap(), None),
            PendingSelection::NonePending
        ));
        render_kernel_pending(&path, session, &mut shown, &mut Vec::new()).unwrap();
        let PendingSelection::Decided(target) =
            select_pending(&displayed_pending(&path, session, &shown).unwrap(), None)
        else {
            panic!("the successfully delivered replacement must be selectable")
        };
        assert_eq!(target.request_id, "approval:unseen");
    }
}
