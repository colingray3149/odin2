//! The durable receipt derivation, publication and repair of the life-effect
//! adapters: a derived receipt page is reported beside, never instead of, its
//! committed effect, and is repaired only from that original effect's durable
//! identity.

use odin_domain::Scope;
use odin_omp::host_tools::HostToolError;
use serde_json::{json, Value};

use super::{identity_key, resolve_draft_arguments, resolve_propose_arguments};
use crate::account::EffectIdentity;
use crate::calendar::{CalendarMutationReceipt, CalendarProposal};
use crate::runtime::HermesRuntime;
use crate::vault::{GeneratedReceiptWrite, VaultBridge, VaultWriteGeneratedInput};

/// The bounded one-line mutation summary the generated receipt page
/// carries: bounds and identifiers only.
fn mutation_summary(mutation: &crate::calendar::CalendarMutation) -> String {
    match mutation {
        crate::calendar::CalendarMutation::Create(draft) => {
            format!("create {} ({}..{})", draft.title, draft.start, draft.end)
        }
        crate::calendar::CalendarMutation::BatchCreate { drafts } => {
            format!("batchCreate {} events", drafts.len())
        }
        crate::calendar::CalendarMutation::Move {
            event_id,
            start,
            end,
        } => format!("move {event_id} to {start}..{end}"),
        crate::calendar::CalendarMutation::Cancel { event_id } => {
            format!("cancel {event_id}")
        }
    }
}

const RECEIPT_REPAIR_TOOL: &str = "vault_write_generated";

/// The longest failure detail one receipt page outcome carries.
const RECEIPT_DETAIL_MAX_CHARS: usize = 240;

/// The durable identity of the `email.draft` effect of one host operation:
/// one prepared request, not a lifetime content hash. The effect engine
/// binds this key to the complete draft, including recipients.
pub(super) fn draft_identity(correlation_id: &str) -> EffectIdentity {
    let key = format!("email-draft:{correlation_id}");
    EffectIdentity {
        idempotency_key: key.clone(),
        correlation_id: key,
    }
}

/// The durable identity of one booking. The hash binds the exact canonical
/// proposal — account AND mutation — so the same request on another
/// account, or a different mutation on this one, can never collide on one
/// durable intent.
pub(super) fn booking_identity(
    proposal: &CalendarProposal,
) -> Result<EffectIdentity, HostToolError> {
    let canonical = serde_json::to_vec(proposal).map_err(|error| HostToolError::Arguments {
        tool: "calendar_propose",
        detail: format!("proposal could not be canonicalized: {error}"),
    })?;
    let key = identity_key("calendar-propose", &canonical);
    Ok(EffectIdentity {
        idempotency_key: key.clone(),
        correlation_id: key,
    })
}

/// One derived receipt page: its exact generated page name and bytes, both
/// derived from the committed effect, never from a caller.
pub(super) struct ReceiptPage {
    page_name: String,
    content: String,
}

struct ReceiptPublication {
    report: Value,
    wrote_page: bool,
    uncertain: bool,
}

enum CompletedReceipt {
    Draft {
        command: odin_domain::CommandId,
        draft: crate::email::EmailDraft,
    },
    Booking {
        key: String,
        proposal: CalendarProposal,
        receipt: CalendarMutationReceipt,
    },
}

impl CompletedReceipt {
    fn pages(&self, namespace: &str) -> Vec<ReceiptPage> {
        match self {
            Self::Draft { command, draft } => {
                draft_receipt_pages(namespace, command.as_str(), draft)
            }
            Self::Booking {
                key,
                proposal,
                receipt,
            } => booking_receipt_pages(namespace, key, proposal, receipt),
        }
    }
}

// Keep the durable effect keys unchanged. Page addresses use only the
// SilverBullet alphabet, not the ':' in an effect key.
fn receipt_page_key(bytes: &[u8]) -> u64 {
    let digest = odin_domain::Digest::hash(bytes);
    u64::from_be_bytes(
        digest.as_bytes()[..8]
            .try_into()
            .expect("BLAKE3 has eight bytes"),
    )
}

/// The drafts-area page of one completed draft command.
pub(super) fn draft_receipt_pages(
    namespace: &str,
    command_id: &str,
    draft: &crate::email::EmailDraft,
) -> Vec<ReceiptPage> {
    vec![ReceiptPage {
        page_name: format!(
            "{namespace}/drafts/draft-{:016x}.md",
            receipt_page_key(command_id.as_bytes())
        ),
        content: format!(
            "# Draft {command_id}\n\nSubject: {}\n\n{}\n",
            draft.subject, draft.body_text
        ),
    }]
}

/// The calendar-area receipt page of one applied mutation and, for a
/// single created event, its appointments-area page.
pub(super) fn booking_receipt_pages(
    namespace: &str,
    booking_key: &str,
    proposal: &CalendarProposal,
    receipt: &CalendarMutationReceipt,
) -> Vec<ReceiptPage> {
    let page = receipt_page_key(booking_key.as_bytes());
    let mut pages = vec![ReceiptPage {
        page_name: format!("{namespace}/calendar/booking-{page:016x}.md"),
        content: format!(
            "# Calendar mutation receipt\n\n{}\n\nEvent ids: {}\n",
            mutation_summary(&proposal.mutation),
            receipt.event_ids.join(", ")
        ),
    }];
    if let crate::calendar::CalendarMutation::Create(draft) = &proposal.mutation {
        pages.push(ReceiptPage {
            page_name: format!("{namespace}/appointments/booking-{page:016x}.md"),
            content: format!(
                "# Appointment {}\n\nStart: {}\nEnd: {}\n",
                draft.title, draft.start, draft.end
            ),
        });
    }
    pages
}

fn bounded_detail(detail: &str) -> String {
    match detail.char_indices().nth(RECEIPT_DETAIL_MAX_CHARS) {
        Some((end, _)) => format!("{}…", &detail[..end]),
        None => detail.to_owned(),
    }
}

/// Publishes derived receipt pages without replacing bytes this producer
/// did not write, and reports each page's exact outcome. The publication is
/// `published` only when every promised page holds exactly its receipt
/// bytes; one failed or conflicting page makes it `failed`. Known writes and
/// possible publication before a filesystem failure remain distinct.
fn publish_receipt_pages(
    vault: &VaultBridge,
    correlation_id: &str,
    pages: Vec<ReceiptPage>,
) -> ReceiptPublication {
    let mut published = true;
    let mut written = false;
    let mut uncertain = false;
    let mut outcomes = Vec::with_capacity(pages.len());
    for page in pages {
        let input = VaultWriteGeneratedInput {
            page_name: page.page_name,
            content: page.content,
        };
        let outcome = match vault.publish_generated_receipt(&input) {
            Ok((GeneratedReceiptWrite::Conflict, _)) => {
                published = false;
                json!({
                    "pageName": input.page_name,
                    "outcome": "conflict",
                    "detail": "the page already holds other bytes; an owner's edit is never \
                               overwritten",
                })
            }
            Ok((write, output)) => {
                let label = if write == GeneratedReceiptWrite::Written {
                    written = true;
                    "written"
                } else {
                    "identical"
                };
                json!({
                    "pageName": output.page_name,
                    "outcome": label,
                    "contentDigest": output.content_digest,
                })
            }
            Err(error) => {
                published = false;
                uncertain |= matches!(&error, crate::vault::VaultError::PublicationUncertain(_));
                tracing::error!(
                    correlation = %correlation_id,
                    page = %input.page_name,
                    error = %error,
                    "odin-hermes: receipt page failed correlation={correlation_id} page={}: {error}",
                    input.page_name
                );
                json!({
                    "pageName": input.page_name,
                    "outcome": "failed",
                    "detail": bounded_detail(&error.to_string()),
                })
            }
        };
        outcomes.push(outcome);
    }
    let status = if published { "published" } else { "failed" };
    let publication = json!({
        "status": status,
        "correlationId": correlation_id,
        "pages": outcomes,
    });
    ReceiptPublication {
        report: publication,
        wrote_page: written,
        uncertain,
    }
}

/// The `receiptPublication` reported beside one committed effect. With no
/// vault composed nothing is promised or written, and it says so.
pub(super) fn receipt_publication(
    runtime: &HermesRuntime,
    correlation_id: &str,
    pages: impl FnOnce(&str) -> Vec<ReceiptPage>,
) -> Value {
    let Some(vault) = runtime.vault.as_ref() else {
        return json!({
            "status": "unavailable",
            "correlationId": correlation_id,
            "pages": [],
            "detail": "the vault adapter is not configured; no receipt page was written",
        });
    };
    publish_receipt_pages(
        vault,
        correlation_id,
        pages(&vault.config().generated_namespace),
    )
    .report
}

/// Maps a completed-effect read refusal onto the repair surface: the
/// original effect is not provably complete, so no receipt is derived.
fn original_not_completed(error: crate::account::LifeError) -> HostToolError {
    HostToolError::Unavailable {
        tool: RECEIPT_REPAIR_TOOL,
        reason: format!("the original effect has no completed receipt to publish: {error}"),
    }
}

/// Resolves the receipt pages of the committed life effect one original
/// host operation names, from the authority ledger alone. The operation
/// must be a committed `email.draft` or `calendar.propose` of the caller's
/// own seat and session — a session binds one seat, lane and project — and
/// its completed account command must be the exact effect of that
/// operation's durable arguments. Page names and bytes derive from that
/// durable input and the provider result only; nothing is dispatched, no
/// lease is issued, and nothing is written.
fn resolve_receipt_repair<'a>(
    runtime: &'a HermesRuntime,
    scope: &Scope,
    correlation_id: &str,
) -> Result<(&'a VaultBridge, CompletedReceipt), HostToolError> {
    let vault = runtime
        .vault
        .as_ref()
        .ok_or_else(|| HostToolError::Unavailable {
            tool: RECEIPT_REPAIR_TOOL,
            reason: "the vault adapter is not configured".to_owned(),
        })?;
    let seat = scope.seat.as_ref().ok_or(HostToolError::Scope {
        tool: RECEIPT_REPAIR_TOOL,
        reason: "a bound seat is required; a receipt is repaired only by the seat and \
                 session of its original effect",
    })?;
    let session = scope.session.as_ref().ok_or(HostToolError::Scope {
        tool: RECEIPT_REPAIR_TOOL,
        reason: "a bound session is required; a receipt is repaired only by the seat and \
                 session of its original effect",
    })?;
    let ledger = runtime.adapter_ledger.lock();
    let read = odin_ledger::operation::operation_row(ledger.connection(), correlation_id);
    // The account read helpers below take the same lock.
    drop(ledger);
    let row = read
        .map_err(|error| HostToolError::Unavailable {
            tool: RECEIPT_REPAIR_TOOL,
            reason: format!("the authority ledger could not be read: {error}"),
        })?
        .ok_or_else(|| HostToolError::Arguments {
            tool: RECEIPT_REPAIR_TOOL,
            detail: "receipt_correlation_id names no recorded operation".to_owned(),
        })?;
    let is_draft = row.capability == crate::email::EMAIL_DRAFT_OPERATION;
    if !is_draft && row.capability != crate::calendar::CALENDAR_PROPOSE_OPERATION {
        return Err(HostToolError::Arguments {
            tool: RECEIPT_REPAIR_TOOL,
            detail: "receipt_correlation_id names an operation that publishes no life receipt"
                .to_owned(),
        });
    }
    if row.seat_id != seat.as_str() || row.session_id != session.as_str() {
        return Err(HostToolError::Scope {
            tool: RECEIPT_REPAIR_TOOL,
            reason: "the original effect belongs to another seat or session; a receipt is \
                     repaired only by the seat and session of its original effect",
        });
    }
    if row.effect_state != odin_domain::operation::EffectState::Committed {
        return Err(HostToolError::Unavailable {
            tool: RECEIPT_REPAIR_TOOL,
            reason: format!(
                "the original operation is {}, not committed; an unsettled effect is \
                 reconciled, never given a receipt",
                row.effect_state.as_str()
            ),
        });
    }
    let request: Value =
        serde_json::from_str(&row.request_json).map_err(|_| HostToolError::Unavailable {
            tool: RECEIPT_REPAIR_TOOL,
            reason: "the original operation request is unreadable".to_owned(),
        })?;
    let arguments = &request["arguments"];
    let mismatch = || HostToolError::Unavailable {
        tool: RECEIPT_REPAIR_TOOL,
        reason: "the completed account effect does not match its original operation".to_owned(),
    };
    let source = if is_draft {
        let (account, subject, body, to) = resolve_draft_arguments(arguments)?;
        let draft = crate::email::EmailDraft {
            account,
            to,
            subject,
            body_text: body,
        };
        let identity = draft_identity(correlation_id);
        let (command_id, intent) =
            crate::email::completed_draft(&runtime.adapter_ledger, &identity)
                .map_err(original_not_completed)?;
        if intent.account != draft.account
            || intent.to != draft.to
            || intent.subject != draft.subject
            || intent.body_text != draft.body_text
        {
            return Err(mismatch());
        }
        CompletedReceipt::Draft {
            command: command_id,
            draft: intent,
        }
    } else {
        let (account, mutation) = resolve_propose_arguments(arguments)?;
        let proposal = CalendarProposal { account, mutation };
        let identity = booking_identity(&proposal)?;
        let (recorded, receipt) =
            crate::calendar::completed_booking(&runtime.adapter_ledger, &identity)
                .map_err(original_not_completed)?;
        if recorded != proposal {
            return Err(mismatch());
        }
        CompletedReceipt::Booking {
            key: identity.idempotency_key,
            proposal: recorded,
            receipt,
        }
    };
    Ok((vault, source))
}

/// The receipt-repair admissibility check: the complete read-only
/// resolution [`repair_receipt`] re-runs, so preflight and execution
/// cannot drift.
pub(in crate::runtime) fn admit_receipt_repair(
    runtime: &HermesRuntime,
    scope: &Scope,
    correlation_id: &str,
) -> Result<(), HostToolError> {
    resolve_receipt_repair(runtime, scope, correlation_id).map(|_| ())
}

/// Republishes the derived receipt pages of one committed life effect,
/// named by its original operation correlation: missing pages are written,
/// identical pages are an idempotent success, and an existing different
/// page stays the owner's. The provider is never contacted. A proven no-write
/// failure is a typed refusal; publication that may already have changed a page
/// stays uncertain rather than claiming an effect-free abort.
pub(in crate::runtime) fn repair_receipt(
    runtime: &HermesRuntime,
    scope: &Scope,
    correlation_id: &str,
) -> Result<Value, HostToolError> {
    let (vault, source) = resolve_receipt_repair(runtime, scope, correlation_id)?;
    let pages = source.pages(&vault.config().generated_namespace);
    let ReceiptPublication {
        report: publication,
        wrote_page: written,
        uncertain,
    } = publish_receipt_pages(vault, correlation_id, pages);
    if uncertain {
        return Err(HostToolError::Uncertain {
            tool: RECEIPT_REPAIR_TOOL,
            detail: format!(
                "derived receipt publication may have changed a page: {}",
                publication["pages"]
            ),
        });
    }
    if !written && publication["status"] != "published" {
        let outcomes = publication["pages"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|page| {
                let name = page["pageName"].as_str().unwrap_or_default();
                let outcome = page["outcome"].as_str().unwrap_or_default();
                match page["detail"].as_str() {
                    Some(detail) => format!("{name} {outcome}: {detail}"),
                    None => format!("{name} {outcome}"),
                }
            })
            .collect::<Vec<_>>()
            .join("; ");
        return Err(HostToolError::Unavailable {
            tool: RECEIPT_REPAIR_TOOL,
            reason: format!("no receipt page was written ({outcomes})"),
        });
    }
    Ok(json!({ "receiptPublication": publication }))
}
