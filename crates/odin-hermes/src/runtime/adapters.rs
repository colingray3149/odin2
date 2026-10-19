//! Email and calendar tools over the account router. Receipt pages supplement
//! committed effects and can be repaired only from the original effect's identity.

use std::sync::Arc;

use odin_domain::Scope;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition};
use serde_json::{json, Value};

use super::tools::{object_schema, parse_string, CapabilityTool};
use super::{now_utc, HermesRuntime};

mod receipts;

use receipts::{
    booking_identity, booking_receipt_pages, draft_identity, draft_receipt_pages,
    receipt_publication,
};

pub(super) use receipts::{admit_receipt_repair, repair_receipt};

fn identity_key(prefix: &str, bytes: &[u8]) -> String {
    let digest = odin_domain::Digest::hash(bytes);
    let mut key = String::with_capacity(prefix.len() + 18);
    key.push_str(prefix);
    key.push(':');
    for byte in digest.as_bytes().iter().take(8) {
        key.push_str(&format!("{byte:02x}"));
    }
    key
}

/// The explicit account selector every email/calendar tool carries. It
/// is required and bounded (1..=128): the handler routes exactly the
/// named account's provider, and the readiness gate observes credential
/// availability for THIS account, so the gate and the execution can
/// never disagree about which account they mean.
fn resolve_account(arguments: &Value) -> Result<String, HostToolError> {
    parse_string(arguments, "account", 128)
}

/// The `email_search` business-argument resolution, shared verbatim by
/// the readiness gate and the handler: one parse path, never two.
fn resolve_search_arguments(arguments: &Value) -> Result<(String, String, u32), HostToolError> {
    let account = resolve_account(arguments)?;
    let text = parse_string(arguments, "text", 400)?;
    let limit = arguments.get("limit").and_then(Value::as_u64).unwrap_or(10);
    Ok((account, text, u32::try_from(limit).unwrap_or(10)))
}

/// The `email_read` business-argument resolution, shared by the gate
/// and the handler.
fn resolve_read_arguments(arguments: &Value) -> Result<(String, String), HostToolError> {
    let account = resolve_account(arguments)?;
    let email_id = parse_string(arguments, "email_id", 128)?;
    Ok((account, email_id))
}

/// The `email_draft` business-argument resolution, shared by the gate
/// and the handler.
fn resolve_draft_arguments(
    arguments: &Value,
) -> Result<(String, String, String, Vec<String>), HostToolError> {
    let account = resolve_account(arguments)?;
    let subject = parse_string(arguments, "subject", 200)?;
    let body = parse_string(arguments, "body_text", 65_536)?;
    let to: Vec<String> = arguments
        .get("to")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    Ok((account, subject, body, to))
}

/// The `email_send` business-argument resolution, shared by the gate
/// and the handler. Phase one carries no `approvalId`: the first
/// dispatch mints the durable request, so readiness must never demand
/// the identity it exists to create.
pub(super) fn resolve_send_arguments(
    arguments: &Value,
) -> Result<(String, String, String), HostToolError> {
    let account = resolve_account(arguments)?;
    let draft_id = parse_string(arguments, "draft_id", 128)?;
    let draft_digest = parse_string(arguments, "draft_digest", 128)?;
    Ok((account, draft_id, draft_digest))
}

/// The `email_manage` business intent, reconstructed with the explicit
/// account and validated before anything is journaled or dispatched.
fn resolve_manage_arguments(
    arguments: &Value,
) -> Result<crate::email::EmailManagement, HostToolError> {
    let account = resolve_account(arguments)?;
    let actions = arguments
        .get("actions")
        .cloned()
        .ok_or_else(|| HostToolError::Arguments {
            tool: "email_manage",
            detail: "actions must be a non-empty array".to_owned(),
        })?;
    let management: crate::email::EmailManagement = serde_json::from_value(
        json!({ "account": account, "actions": actions }),
    )
    .map_err(|error| HostToolError::Arguments {
        tool: "email_manage",
        detail: format!("invalid management intent: {error}"),
    })?;
    management
        .validate()
        .map_err(|error| HostToolError::Arguments {
            tool: "email_manage",
            detail: error.to_string(),
        })?;
    Ok(management)
}

/// The window pair shared by the calendar read and every timed event
/// draft.
fn resolve_window_pair(arguments: &Value) -> Result<(String, String), HostToolError> {
    let start = parse_string(arguments, "start", 40)?;
    let end = parse_string(arguments, "end", 40)?;
    Ok((start, end))
}

/// The `calendar_read` business-argument resolution, shared by the gate
/// and the handler.
fn resolve_read_window_arguments(
    arguments: &Value,
) -> Result<(String, String, String), HostToolError> {
    let account = resolve_account(arguments)?;
    let (start, end) = resolve_window_pair(arguments)?;
    Ok((account, start, end))
}

/// One concrete event draft parsed from a flattened argument object:
/// `create`'s own fields and one `batchCreate` `drafts` entry share
/// this exact shape.
fn resolve_event_draft(
    tool: &'static str,
    arguments: &Value,
) -> Result<crate::calendar::CalendarEventDraft, HostToolError> {
    let title = parse_string(arguments, "title", 200)?;
    let (start, end) = resolve_window_pair(arguments)?;
    let location = parse_optional_string(arguments, "location", 512)?;
    let description = parse_optional_string(arguments, "description", 2000)?;
    let _ = tool;
    Ok(crate::calendar::CalendarEventDraft {
        title,
        start,
        end,
        location,
        description,
    })
}

/// The `calendar_propose` business-argument resolution, shared by the
/// gate and the handler: the explicit account plus ONE tagged mutation
/// under `type` — `create` (title/start/end plus optional
/// location/description), `move` (eventId/start/end), `cancel`
/// (eventId), or `batchCreate` (bounded `drafts` list). Phase one
/// carries no `approvalId`: the first dispatch mints the durable
/// request, so readiness must never demand the identity it exists to
/// create. The resolved mutation rides the recorded intent verbatim —
/// the applied effect must be exactly the mutation the operator
/// approved, never a reduced copy.
fn resolve_propose_arguments(
    arguments: &Value,
) -> Result<(String, crate::calendar::CalendarMutation), HostToolError> {
    const TOOL: &str = "calendar_propose";
    let account = resolve_account(arguments)?;
    let mutation = match arguments.get("type").and_then(Value::as_str) {
        Some("create") => {
            crate::calendar::CalendarMutation::Create(resolve_event_draft(TOOL, arguments)?)
        }
        Some("move") => {
            let event_id = parse_string(arguments, "eventId", 128)?;
            let (start, end) = resolve_window_pair(arguments)?;
            crate::calendar::CalendarMutation::Move {
                event_id,
                start,
                end,
            }
        }
        Some("cancel") => {
            let event_id = parse_string(arguments, "eventId", 128)?;
            crate::calendar::CalendarMutation::Cancel { event_id }
        }
        Some("batchCreate") => {
            let drafts = arguments
                .get("drafts")
                .and_then(Value::as_array)
                .ok_or_else(|| HostToolError::Arguments {
                    tool: TOOL,
                    detail: "batchCreate requires a drafts array".to_owned(),
                })?;
            if drafts.is_empty() || drafts.len() > crate::calendar::MAX_BATCH_EVENTS {
                return Err(HostToolError::Arguments {
                    tool: TOOL,
                    detail: format!(
                        "batchCreate drafts must hold 1..={} events",
                        crate::calendar::MAX_BATCH_EVENTS
                    ),
                });
            }
            let drafts = drafts
                .iter()
                .map(|draft| resolve_event_draft(TOOL, draft))
                .collect::<Result<Vec<_>, _>>()?;
            crate::calendar::CalendarMutation::BatchCreate { drafts }
        }
        _ => {
            return Err(HostToolError::Arguments {
                tool: TOOL,
                detail: "type must be one of create, move, cancel, batchCreate".to_owned(),
            })
        }
    };
    Ok((account, mutation))
}

/// The optional bounded string shared by the calendar proposal
/// resolver: absent stays absent; present must be a bounded string so
/// the recorded intent cannot smuggle an unbounded field past the
/// schema the dispatch already enforced.
fn parse_optional_string(
    arguments: &Value,
    field: &str,
    max_bytes: usize,
) -> Result<Option<String>, HostToolError> {
    match arguments.get(field) {
        None => Ok(None),
        Some(Value::String(value)) if value.len() <= max_bytes => Ok(Some(value.clone())),
        Some(_) => Err(HostToolError::Arguments {
            tool: "odin_hermes",
            detail: format!("{field} must be a string of at most {max_bytes} bytes"),
        }),
    }
}

/// Maps a typed credential-readiness refusal onto the host-tool
/// unavailability surface: one plain sentence, no credential material,
/// no upstream text.
fn credential_unavailable(tool: &'static str, error: crate::account::LifeError) -> HostToolError {
    HostToolError::Unavailable {
        tool,
        reason: error.to_string(),
    }
}

/// Maps a proposal the existing validator refuses onto the argument
/// surface: deterministically unexecutable, so nothing may decide it.
fn proposal_refused(error: crate::account::LifeError) -> HostToolError {
    HostToolError::Arguments {
        tool: "calendar_propose",
        detail: error.to_string(),
    }
}

/// Potentially applied dispatches remain uncertain rather than becoming effect-free aborts.
fn effect_failure(tool: &'static str, error: crate::account::LifeError) -> HostToolError {
    use crate::account::LifeError;
    match error {
        LifeError::InDoubt
        | LifeError::PartiallyApplied { .. }
        | LifeError::Timeout
        | LifeError::Protocol(_) => HostToolError::Uncertain {
            tool,
            detail: error.to_string(),
        },
        other => HostToolError::Unavailable {
            tool,
            reason: other.to_string(),
        },
    }
}

/// The `account` parameter: one of the declared accounts, never a guess.
pub(super) fn account_schema(settings: &crate::config::HermesSettings, calendar: bool) -> Value {
    json!({ "type": "string", "enum": settings.account_names(calendar) })
}

pub(super) fn email_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    let settings = runtime.settings();
    // -- email.* -----------------------------------------------------------
    // Credentials stay in scoped account leases, never model envelopes; adapters verify
    // the kernel's consumed approval without consuming it again.
    {
        let runtime = Arc::clone(runtime);
        // Declared-admissibility gate: the composed email adapter
        // presence, the handler's own business-argument resolution
        // (including the required account), and that account's
        // effect-free credential availability — observed before anything
        // is journaled or consumed. No lease is issued, no state is
        // written, no provider is contacted.
        let gate_runtime = Arc::clone(&runtime);
        let gate = std::sync::Arc::new(
            move |_scope: &Scope, arguments: &Value| -> Result<(), HostToolError> {
                let adapter =
                    gate_runtime
                        .email
                        .as_ref()
                        .ok_or_else(|| HostToolError::Unavailable {
                            tool: "email_search",
                            reason: "the email adapter is not configured".to_owned(),
                        })?;
                let (account, _text, _limit) = resolve_search_arguments(arguments)?;
                adapter
                    .credential_readiness(&account)
                    .map_err(|error| credential_unavailable("email_search", error))?;
                Ok(())
            },
        );
        let execute_gate = Arc::clone(&gate);
        let handler = move |_scope: Scope, arguments: Value| {
            execute_gate(&_scope, &arguments)?;
            let adapter = runtime
                .email
                .as_ref()
                .expect("the gate proved the email adapter is configured");
            let (account, text, limit) = resolve_search_arguments(&arguments)?;
            let summaries = adapter
                .search(
                    &crate::email::EmailSearchQuery {
                        account: account.clone(),
                        text: text.clone(),
                        limit,
                    },
                    now_utc(),
                )
                .map_err(|error| HostToolError::Unavailable {
                    tool: "email_search",
                    reason: error.to_string(),
                })?;
            tracing::debug!(
                account = %account,
                "odin-hermes: email.search account={account} hits={} newest={} text={text:?}",
                summaries.len(),
                summaries
                    .first()
                    .and_then(|hit| hit.received_at.as_deref())
                    .unwrap_or("-")
            );
            serde_json::to_value(&summaries).map_err(|error| HostToolError::Response {
                tool: "email_search",
                detail: error.to_string(),
            })
        };
        tools.push(Arc::new(CapabilityTool::plain(
            RpcHostToolDefinition {
                name: "email_search".into(),
                label: "Search email".into(),
                description: "Searches the explicitly selected account for bounded message \
                 summaries under a scoped opaque lease, newest first. Body text never leaves \
                 the adapter. \"The most recent\" email is the newest hit that matches what \
                 Colin asked for, with its receivedAt date; never call an older hit the latest \
                 when a newer matching one came back."
                    .into(),
                parameters: object_schema(
                    "email_search",
                    json!({
                        "account": account_schema(settings, false),
                        "text": { "type": "string", "minLength": 1, "maxLength": 400 },
                        "limit": { "type": "integer", "minimum": 1, "maximum": 20 }
                    }),
                    &["account", "text"],
                ),
                hidden: false,
                load_mode: odin_omp::host_tools::ToolLoadMode::Discoverable,
            },
            Box::new(handler),
            Box::new(move |scope: &Scope, arguments: &Value| gate(scope, arguments)),
        )));
    }
    {
        let runtime = Arc::clone(runtime);
        // Declared-admissibility gate: the composed email adapter
        // presence, the handler's own business-argument resolution
        // (including the required account), and that account's
        // effect-free credential availability — observed before anything
        // is journaled or consumed. No lease is issued, no state is
        // written, no provider is contacted.
        let gate_runtime = Arc::clone(&runtime);
        let gate = std::sync::Arc::new(
            move |_scope: &Scope, arguments: &Value| -> Result<(), HostToolError> {
                let adapter =
                    gate_runtime
                        .email
                        .as_ref()
                        .ok_or_else(|| HostToolError::Unavailable {
                            tool: "email_read",
                            reason: "the email adapter is not configured".to_owned(),
                        })?;
                let (account, _email_id) = resolve_read_arguments(arguments)?;
                adapter
                    .credential_readiness(&account)
                    .map_err(|error| credential_unavailable("email_read", error))?;
                Ok(())
            },
        );
        let execute_gate = Arc::clone(&gate);
        let handler = move |_scope: Scope, arguments: Value| {
            execute_gate(&_scope, &arguments)?;
            let adapter = runtime
                .email
                .as_ref()
                .expect("the gate proved the email adapter is configured");
            let (account, email_id) = resolve_read_arguments(&arguments)?;
            let message = adapter
                .read(&account, &email_id, now_utc())
                .map_err(|error| HostToolError::Unavailable {
                    tool: "email_read",
                    reason: error.to_string(),
                })?;
            Ok(match message {
                Some(message) => {
                    serde_json::to_value(&message).map_err(|error| HostToolError::Response {
                        tool: "email_read",
                        detail: error.to_string(),
                    })?
                }
                None => json!({ "found": false }),
            })
        };
        tools.push(Arc::new(CapabilityTool::plain(
            RpcHostToolDefinition {
                name: "email_read".into(),
                label: "Read email".into(),
                description: "Reads one bounded, sanitized message projection of the explicitly \
                 selected account by id through the scoped opaque lease."
                    .into(),
                parameters: object_schema(
                    "email_read",
                    json!({
                        "account": account_schema(settings, false),
                        "email_id": { "type": "string", "minLength": 1, "maxLength": 128 }
                    }),
                    &["account", "email_id"],
                ),
                hidden: false,
                load_mode: odin_omp::host_tools::ToolLoadMode::Discoverable,
            },
            Box::new(handler),
            Box::new(move |scope: &Scope, arguments: &Value| gate(scope, arguments)),
        )));
    }
    {
        let runtime = Arc::clone(runtime);
        // Declared-admissibility gate: the composed email adapter
        // presence, the handler's own business-argument resolution
        // (including the required account), and that account's
        // effect-free credential availability — observed before anything
        // is journaled or consumed. No lease is issued, no state is
        // written, no provider is contacted.
        let gate_runtime = Arc::clone(&runtime);
        let gate = std::sync::Arc::new(
            move |_scope: &Scope, arguments: &Value| -> Result<(), HostToolError> {
                let adapter =
                    gate_runtime
                        .email
                        .as_ref()
                        .ok_or_else(|| HostToolError::Unavailable {
                            tool: "email_draft",
                            reason: "the email adapter is not configured".to_owned(),
                        })?;
                let (_account, _subject, _body, _to) = resolve_draft_arguments(arguments)?;
                adapter
                    .credential_readiness(&_account)
                    .map_err(|error| credential_unavailable("email_draft", error))?;
                Ok(())
            },
        );
        let execute_gate = Arc::clone(&gate);
        let handler = move |effect: &odin_kernel::operation::PreparedEffect,
                            _scope: Scope,
                            arguments: Value| {
            if effect.contract().id.as_str() != crate::email::EMAIL_DRAFT_OPERATION
                || effect.payload().arguments != arguments
            {
                return Err(HostToolError::Catalog {
                    detail: "email_draft requires its exact prepared contract and payload"
                        .to_owned(),
                });
            }
            execute_gate(&_scope, &arguments)?;
            let adapter = runtime
                .email
                .as_ref()
                .expect("the gate proved the email adapter is configured");
            let (account, subject, body, to) = resolve_draft_arguments(&arguments)?;
            let draft = crate::email::EmailDraft {
                account,
                to,
                subject,
                body_text: body,
            };
            let correlation_id = effect.correlation_id().as_str();
            let identity = draft_identity(correlation_id);
            let settled = adapter
                .save_draft(&identity, &draft, now_utc())
                .map_err(|error| effect_failure("email_draft", error))?;
            let mut receipt = json!({
                "command_id": settled.command_id.to_string(),
                "result": settled.result,
                "replayed": settled.replayed,
            });
            // Generated-namespace producer: the drafts area becomes real
            // vault content under the only machine-writable namespace. The
            // saved draft stays the result whatever the page outcome.
            if settled.status == crate::account::EffectStatus::Completed {
                receipt["receiptPublication"] =
                    receipt_publication(&runtime, correlation_id, |namespace| {
                        draft_receipt_pages(namespace, settled.command_id.as_str(), &draft)
                    });
            }
            Ok(receipt)
        };
        tools.push(Arc::new(CapabilityTool::prepared(
            RpcHostToolDefinition {
                name: "email_draft".into(),
                label: "Save email draft".into(),
                description: "Saves a draft in the selected account without sending it. \
                 Returns draftId and draftDigest for email_send. The derived vault page's \
                 status is returned separately as receiptPublication; vault_write_generated \
                 with receipt_correlation_id republishes that page."
                    .into(),
                parameters: object_schema(
                    "email_draft",
                    json!({
                        "account": account_schema(settings, false),
                        "to": {
                            "type": "array",
                            "items": { "type": "string", "maxLength": 320 },
                            "minItems": 1,
                            "maxItems": 10
                        },
                        "subject": { "type": "string", "minLength": 1, "maxLength": 200 },
                        "body_text": { "type": "string", "minLength": 1, "maxLength": 20000 }
                    }),
                    &["account", "to", "subject", "body_text"],
                ),
                hidden: false,
                load_mode: odin_omp::host_tools::ToolLoadMode::Discoverable,
            },
            Box::new(handler),
            Box::new(move |scope: &Scope, arguments: &Value| gate(scope, arguments)),
        )));
    }
    {
        let runtime = Arc::clone(runtime);
        // Check arguments and credentials before requesting approval; this gate issues
        // no lease or provider call. The dispatch gate verifies approval separately.
        let gate_runtime = Arc::clone(&runtime);
        let gate = std::sync::Arc::new(
            move |_scope: &Scope, arguments: &Value| -> Result<(), HostToolError> {
                let adapter =
                    gate_runtime
                        .email
                        .as_ref()
                        .ok_or_else(|| HostToolError::Unavailable {
                            tool: "email_send",
                            reason: "the email adapter is not configured".to_owned(),
                        })?;
                let (account, draft_id, draft_digest) = resolve_send_arguments(arguments)?;
                adapter
                    .approved_draft(&account, &draft_id, &draft_digest)
                    .map_err(|error| HostToolError::Arguments {
                        tool: "email_send",
                        detail: error.to_string(),
                    })?;
                adapter
                    .credential_readiness(&account)
                    .map_err(|error| credential_unavailable("email_send", error))?;
                Ok(())
            },
        );
        let execute_gate = Arc::clone(&gate);
        let prepared_handler = move |_effect: &odin_kernel::operation::PreparedEffect,
                                     consumed: &odin_omp::host_tools::ConsumedHostCommand,
                                     _scope: Scope,
                                     arguments: Value| {
            execute_gate(&_scope, &arguments)?;
            let adapter = runtime
                .email
                .as_ref()
                .expect("the gate proved the email adapter is configured");
            let (account, draft_id, draft_digest) = resolve_send_arguments(&arguments)?;
            let approval_raw = parse_string(&arguments, "approvalId", 128)?;
            let approval_id = odin_domain::ApprovalId::new(approval_raw).map_err(|error| {
                HostToolError::Arguments {
                    tool: "email_send",
                    detail: format!("invalid approval id: {error}"),
                }
            })?;
            // The identity hash binds the account: two accounts' drafts
            // can never collide on one durable intent.
            let identity = crate::account::EffectIdentity {
                idempotency_key: identity_key(
                    "email-send",
                    format!("{account}\u{0}{draft_id}\u{0}{draft_digest}").as_bytes(),
                ),
                correlation_id: identity_key(
                    "email-send",
                    format!("{account}\u{0}{draft_id}\u{0}{draft_digest}").as_bytes(),
                ),
            };
            // The durable intent the settle verifies is recorded here, on
            // the dispatch path, from the consumed permit's exact business
            // arguments: the kernel gate owns the human decision (it minted
            // the request and consumed this approval), so no second
            // approval row is ever minted.
            adapter
                .record_send_intent(&account, &identity, &draft_id, &draft_digest, now_utc())
                .map_err(|error| HostToolError::Unavailable {
                    tool: "email_send",
                    reason: error.to_string(),
                })?;
            // Single consumption happened at the dispatch gate; the adapter
            // verifies the durable consumed record against the EXACT permit
            // scope and dispatches exactly once. Nothing here consumes.
            let command_id = consumed.command_id().clone();
            let scope = consumed.approval_scope();
            let proof = crate::account::HostConsumeProof {
                approval_id: Some(&approval_id),
                command_id: &command_id,
                scope: &scope,
            };
            let settled = adapter
                .settle_send(&account, &identity, &proof, now_utc())
                .map_err(|error| effect_failure("email_send", error))?;
            Ok(json!({
                "command_id": settled.command_id.to_string(),
                "result": settled.result,
                "replayed": settled.replayed,
            }))
        };
        tools.push(Arc::new(CapabilityTool::approved(
            RpcHostToolDefinition {
                name: "email_send".into(),
                label: "Send approved email".into(),
                description: "Two-phase operator-approved send. Phase one — the business request, \
             `account`, `draft_id` and `draft_digest` — asks the kernel gate to mint the exact-scope \
             approval request; nothing is sent. Phase two supplies the model-visible \
             `approvalId` selector of the minted request and reaches this handler only \
             through the kernel-consumed permit of that exact approval; the handler records \
             the durable send intent from the permit's exact arguments and the adapter \
             verifies the consumed record against the durable gate record before the \
             transport runs exactly once. A denial is durably recorded with its evidence \
             and never dispatches."
                    .into(),
                parameters: object_schema(
                    "email_send",
                    json!({
                        "account": account_schema(settings, false),
                        "draft_id": { "type": "string", "minLength": 1, "maxLength": 128 },
                        "draft_digest": { "type": "string", "minLength": 1, "maxLength": 128 },
                        "approvalId": { "type": "string", "minLength": 1, "maxLength": 128 }
                    }),
                    &["account", "draft_id", "draft_digest"],
                ),
                hidden: false,
                load_mode: odin_omp::host_tools::ToolLoadMode::Discoverable,
            },
            "email.send",
            Box::new(prepared_handler),
            Box::new(move |scope: &Scope, arguments: &Value| gate(scope, arguments)),
        )));
    }
    {
        let runtime = Arc::clone(runtime);
        // Declared-admissibility gate: the composed email adapter
        // presence, the handler's own business-argument resolution
        // (including the required account), and that account's
        // effect-free credential availability — observed before anything
        // is journaled. No lease is issued, no state is written, no
        // provider is contacted.
        let gate_runtime = Arc::clone(&runtime);
        let gate = std::sync::Arc::new(
            move |_scope: &Scope, arguments: &Value| -> Result<(), HostToolError> {
                let adapter =
                    gate_runtime
                        .email
                        .as_ref()
                        .ok_or_else(|| HostToolError::Unavailable {
                            tool: "email_manage",
                            reason: "the email adapter is not configured".to_owned(),
                        })?;
                let management = resolve_manage_arguments(arguments)?;
                adapter
                    .credential_readiness(&management.account)
                    .map_err(|error| credential_unavailable("email_manage", error))?;
                Ok(())
            },
        );
        let execute_gate = Arc::clone(&gate);
        let prepared_handler =
            move |effect: &odin_kernel::operation::PreparedEffect,
                  scope: Scope,
                  arguments: Value| {
                if effect.contract().id.as_str() != crate::email::EMAIL_MANAGE_OPERATION
                    || effect.payload().arguments != arguments
                {
                    return Err(HostToolError::Catalog {
                        detail: "email_manage requires its exact prepared contract and payload"
                            .to_owned(),
                    });
                }
                execute_gate(&scope, &arguments)?;
                let adapter = runtime
                    .email
                    .as_ref()
                    .expect("the gate proved the email adapter is configured");
                let management = resolve_manage_arguments(&arguments)?;
                // The prepared operation is the identity: the same request
                // replays its receipt or stays in doubt, while a fresh
                // request is a fresh explicit action. The recorded
                // canonical management binds the exact account and actions.
                let key = format!("email-manage:{}", effect.correlation_id().as_str());
                let identity = crate::account::EffectIdentity {
                    idempotency_key: key.clone(),
                    correlation_id: key,
                };
                let settled = adapter
                    .manage(&identity, &management, now_utc())
                    .map_err(|error| effect_failure("email_manage", error))?;
                let receipt = crate::email::EmailManagementReceipt::from_settled(&settled)
                    .map_err(|error| HostToolError::Unavailable {
                        tool: "email_manage",
                        reason: error.to_string(),
                    })?;
                Ok(json!({
                    "command_id": settled.command_id.to_string(),
                    "result": { "emailIds": receipt.email_ids },
                    "replayed": settled.replayed,
                }))
            };
        tools.push(Arc::new(CapabilityTool::prepared(RpcHostToolDefinition {
            name: "email_manage".into(),
            label: "Organize email".into(),
            description: "Applies one bounded, reversible batch of label, archive, or trash \
             actions to the explicitly selected account. Retrying the same request never \
             applies it twice; an uncertain outcome is reported, never retried. Permanent \
             deletion and unsubscribe are not representable."
                .into(),
            parameters: object_schema(
                "email_manage",
                json!({
                    "account": account_schema(settings, false),
                    "actions": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 25,
                        "items": {
                            "type": "object",
                            "required": ["action", "emailId"],
                            "properties": {
                                "action": { "enum": ["label", "archive", "trash"] },
                                "emailId": { "type": "string", "minLength": 1, "maxLength": 128 },
                                "addLabels": {
                                    "type": "array",
                                    "maxItems": 10,
                                    "items": { "type": "string", "minLength": 1, "maxLength": 64 }
                                },
                                "removeLabels": {
                                    "type": "array",
                                    "maxItems": 10,
                                    "items": { "type": "string", "minLength": 1, "maxLength": 64 }
                                }
                            },
                            "additionalProperties": false
                        }
                    }
                }),
                &["account", "actions"],
            ),
            hidden: false,
            load_mode: odin_omp::host_tools::ToolLoadMode::Discoverable,
        },
        Box::new(prepared_handler),
        Box::new(move |scope: &Scope, arguments: &Value| gate(scope, arguments)),)));
    }
}

pub(super) fn calendar_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    let settings = runtime.settings();
    // -- calendar.* --------------------------------------------------------
    {
        let runtime = Arc::clone(runtime);
        // Declared-admissibility gate: the composed calendar adapter
        // presence, the handler's own business-argument resolution
        // (including the required account), and that account's
        // effect-free credential availability — observed before anything
        // is journaled or consumed. No lease is issued, no state is
        // written, no provider is contacted.
        let gate_runtime = Arc::clone(&runtime);
        let gate =
            std::sync::Arc::new(
                move |_scope: &Scope, arguments: &Value| -> Result<(), HostToolError> {
                    let adapter = gate_runtime.calendar.as_ref().ok_or_else(|| {
                        HostToolError::Unavailable {
                            tool: "calendar_read",
                            reason: "the calendar adapter is not configured".to_owned(),
                        }
                    })?;
                    let (account, _start, _end) = resolve_read_window_arguments(arguments)?;
                    adapter
                        .credential_readiness(&account)
                        .map_err(|error| credential_unavailable("calendar_read", error))?;
                    Ok(())
                },
            );
        let execute_gate = Arc::clone(&gate);
        let handler = move |_scope: Scope, arguments: Value| {
            execute_gate(&_scope, &arguments)?;
            let adapter = runtime
                .calendar
                .as_ref()
                .expect("the gate proved the calendar adapter is configured");
            let (account, start, end) = resolve_read_window_arguments(&arguments)?;
            let events = adapter
                .read_window(
                    &crate::calendar::CalendarWindow {
                        account,
                        start,
                        end,
                    },
                    now_utc(),
                )
                .map_err(|error| HostToolError::Unavailable {
                    tool: "calendar_read",
                    reason: error.to_string(),
                })?;
            serde_json::to_value(&events).map_err(|error| HostToolError::Response {
                tool: "calendar_read",
                detail: error.to_string(),
            })
        };
        tools.push(Arc::new(CapabilityTool::plain(
            RpcHostToolDefinition {
                name: "calendar_read".into(),
                label: "Read calendar window".into(),
                description: "Reads one bounded calendar window of the explicitly selected \
                 account through the scoped opaque lease."
                    .into(),
                parameters: object_schema(
                    "calendar_read",
                    json!({
                        "account": account_schema(settings, true),
                        "start": { "type": "string", "minLength": 1, "maxLength": 40 },
                        "end": { "type": "string", "minLength": 1, "maxLength": 40 }
                    }),
                    &["account", "start", "end"],
                ),
                hidden: false,
                load_mode: odin_omp::host_tools::ToolLoadMode::Discoverable,
            },
            Box::new(handler),
            Box::new(move |scope: &Scope, arguments: &Value| gate(scope, arguments)),
        )));
    }
    {
        let runtime = Arc::clone(runtime);
        // Validate the proposal and account readiness before requesting approval,
        // without issuing a lease or contacting the provider.
        let gate_runtime = Arc::clone(&runtime);
        let gate =
            std::sync::Arc::new(
                move |_scope: &Scope, arguments: &Value| -> Result<(), HostToolError> {
                    let adapter = gate_runtime.calendar.as_ref().ok_or_else(|| {
                        HostToolError::Unavailable {
                            tool: "calendar_propose",
                            reason: "the calendar adapter is not configured".to_owned(),
                        }
                    })?;
                    let (account, mutation) = resolve_propose_arguments(arguments)?;
                    let proposal = crate::calendar::CalendarProposal { account, mutation };
                    proposal.validate().map_err(proposal_refused)?;
                    adapter
                        .credential_readiness(&proposal.account)
                        .map_err(|error| credential_unavailable("calendar_propose", error))?;
                    Ok(())
                },
            );
        let execute_gate = Arc::clone(&gate);
        let prepared_handler = move |effect: &odin_kernel::operation::PreparedEffect,
                                     consumed: &odin_omp::host_tools::ConsumedHostCommand,
                                     _scope: Scope,
                                     arguments: Value| {
            execute_gate(&_scope, &arguments)?;
            let adapter = runtime
                .calendar
                .as_ref()
                .expect("the gate proved the calendar adapter is configured");
            let (account, mutation) = resolve_propose_arguments(&arguments)?;
            let approval_raw = parse_string(&arguments, "approvalId", 128)?;
            let approval_id = odin_domain::ApprovalId::new(approval_raw).map_err(|error| {
                HostToolError::Arguments {
                    tool: "calendar_propose",
                    detail: format!("invalid approval id: {error}"),
                }
            })?;
            let proposal = crate::calendar::CalendarProposal { account, mutation };
            let identity = booking_identity(&proposal)?;
            // The durable intent the settle verifies is recorded here, on
            // the dispatch path, from the consumed permit's exact business
            // arguments (the exact tagged mutation included): the kernel
            // gate owns the human decision, so no second approval row is
            // ever minted.
            adapter
                .record_booking_intent(&identity, &proposal, now_utc())
                .map_err(|error| HostToolError::Unavailable {
                    tool: "calendar_propose",
                    reason: error.to_string(),
                })?;
            // Approval was consumed at dispatch; settlement verifies its scope without consuming again.
            let command_id = consumed.command_id().clone();
            let scope = consumed.approval_scope();
            let proof = crate::account::HostConsumeProof {
                approval_id: Some(&approval_id),
                command_id: &command_id,
                scope: &scope,
            };
            let settled = adapter
                .settle_booking(&identity, &proof, now_utc())
                .map_err(|error| effect_failure("calendar_propose", error))?;
            let receipt = crate::calendar::CalendarMutationReceipt::from_settled(&settled)
                .map_err(|error| HostToolError::Unavailable {
                    tool: "calendar_propose",
                    reason: error.to_string(),
                })?;
            let mut result = json!({
                "command_id": settled.command_id.to_string(),
                "result": { "eventIds": receipt.event_ids },
                "replayed": settled.replayed,
            });
            // Generated-namespace producers run ONLY for a successfully
            // applied mutation — a denial or a provably undispatched
            // failure never writes vault content. The receipt page lands
            // in the calendar area and a booked appointment page in the
            // appointments area; real derived content, confined writes
            // only. The applied event ids stay the result whatever the
            // page outcome, and either page failing fails the publication.
            if settled.status == crate::account::EffectStatus::Completed {
                result["receiptPublication"] =
                    receipt_publication(&runtime, effect.correlation_id().as_str(), |namespace| {
                        booking_receipt_pages(
                            namespace,
                            &identity.idempotency_key,
                            &proposal,
                            &receipt,
                        )
                    });
            }
            Ok(result)
        };
        tools.push(Arc::new(CapabilityTool::approved(
            RpcHostToolDefinition {
                name: "calendar_propose".into(),
                label: "Apply calendar mutation".into(),
                description:
                    "Changes the selected account's calendar. Use create with title, start, \
             end and optional location/description; move with eventId, start and end; \
             cancel with eventId; or batchCreate with up to 128 drafts. Returns the applied \
             eventIds. approvalId selects an existing approval. Derived vault page status \
             is returned separately as receiptPublication; vault_write_generated with \
             receipt_correlation_id republishes those pages."
                        .into(),
                parameters: object_schema(
                    "calendar_propose",
                    json!({
                        "account": account_schema(settings, true),
                        "type": { "enum": ["create", "move", "cancel", "batchCreate"] },
                        "title": { "type": "string", "minLength": 1, "maxLength": 200 },
                        "start": { "type": "string", "minLength": 1, "maxLength": 40 },
                        "end": { "type": "string", "minLength": 1, "maxLength": 40 },
                        "location": { "type": "string", "maxLength": 512 },
                        "description": { "type": "string", "maxLength": 2000 },
                        "eventId": { "type": "string", "minLength": 1, "maxLength": 128 },
                        "drafts": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": 128,
                            "items": {
                                "type": "object",
                                "required": ["title", "start", "end"],
                                "additionalProperties": false,
                                "properties": {
                                    "title": { "type": "string", "minLength": 1, "maxLength": 200 },
                                    "start": { "type": "string", "minLength": 1, "maxLength": 40 },
                                    "end": { "type": "string", "minLength": 1, "maxLength": 40 },
                                    "location": { "type": "string", "maxLength": 512 },
                                    "description": { "type": "string", "maxLength": 2000 }
                                }
                            }
                        },
                        "approvalId": { "type": "string", "minLength": 1, "maxLength": 128 }
                    }),
                    &["account", "type"],
                ),
                hidden: false,
                load_mode: odin_omp::host_tools::ToolLoadMode::Discoverable,
            },
            "calendar.propose",
            Box::new(prepared_handler),
            Box::new(move |scope: &Scope, arguments: &Value| gate(scope, arguments)),
        )));
    }
}
