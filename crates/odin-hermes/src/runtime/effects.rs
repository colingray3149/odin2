//! The governed consequential-effect surfaces: vault reads/writes, the
//! finance summary read, the kernel-gated purchase submit, and the
//! owner-channel Discord notify/intake tools.

use std::sync::Arc;

use odin_domain::{Actor, CommandTarget, Scope};
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition};
use serde_json::{json, Value};

use super::tools::{object_schema, parse_string, CapabilityTool};
use super::{
    now_utc, producer, unix_ms, HermesRuntime, PURCHASE_APPROVAL_TTL_HOURS, RUNTIME_ISSUER,
};
use crate::purchase::{PurchasePrepareInit, PurchaseRequest};

/// The `vault_write_generated` receipt-mode selector: the original effect's
/// operation correlation. It replaces caller page text entirely — a receipt
/// repair never takes a page name or content from its caller.
fn receipt_correlation(arguments: &Value) -> Result<Option<String>, HostToolError> {
    if arguments.get("receipt_correlation_id").is_none() {
        return Ok(None);
    }
    if arguments.get("page_name").is_some() || arguments.get("content").is_some() {
        return Err(HostToolError::Arguments {
            tool: "vault_write_generated",
            detail: "receipt_correlation_id replaces page_name and content; a receipt is \
                     rebuilt from its original effect, never from caller text"
                .to_owned(),
        });
    }
    parse_string(arguments, "receipt_correlation_id", 128).map(Some)
}

pub(super) fn vault_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    // -- vault.search / vault.write_generated -----------------------------
    {
        let runtime = Arc::clone(runtime);
        // Declared-admissibility gate: the composed vault adapter is the
        // handler's only effect surface, and its absence refuses
        // deterministically — the SAME check the handler runs first, so
        // preflight and execution cannot drift. The adapter handle is
        // composed once before serving and never replaced.
        let gate_runtime = Arc::clone(&runtime);
        let gate = std::sync::Arc::new(
            move |_scope: &Scope, _arguments: &Value| -> Result<(), HostToolError> {
                if gate_runtime.vault.is_none() {
                    return Err(HostToolError::Unavailable {
                        tool: "vault_search",
                        reason: "the vault adapter is not configured".to_owned(),
                    });
                }
                Ok(())
            },
        );
        let execute_gate = Arc::clone(&gate);
        let handler = move |_scope: Scope, arguments: Value| {
            execute_gate(&_scope, &arguments)?;
            let vault = runtime
                .vault
                .as_ref()
                .expect("the gate proved the vault adapter is configured");
            let max_pages = arguments.get("max_pages").and_then(Value::as_u64);
            let input = crate::vault::VaultSearchInput {
                max_pages: max_pages.map(|value| u32::try_from(value).unwrap_or(u32::MAX)),
            };
            let output = vault
                .search(&input)
                .map_err(|error| HostToolError::Unavailable {
                    tool: "vault_search",
                    reason: error.to_string(),
                })?;
            serde_json::to_value(&output).map_err(|error| HostToolError::Response {
                tool: "vault_search",
                detail: error.to_string(),
            })
        };
        tools.push(Arc::new(CapabilityTool::plain(
            RpcHostToolDefinition {
                name: "vault_search".into(),
                label: "Scoped vault search".into(),
                description:
                    "Lists the retrieval-eligible vault pages inside the operator allowlist. \
                 Excluded private namespaces are structurally unreachable; page text is \
                 never part of this listing."
                        .into(),
                parameters: object_schema(
                    "vault_search",
                    json!({
                        "max_pages": { "type": "integer", "minimum": 1, "maximum": 100000 }
                    }),
                    &[],
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
        let memory_runtime = Arc::downgrade(&runtime);
        // The generated-namespace grammar in the model-facing schema is the
        // configured namespace itself, read from the composed vault bridge —
        // declaration data, never a hardcoded name.
        let generated_namespace = runtime
            .vault
            .as_ref()
            .map(|vault| vault.config().generated_namespace.clone())
            .unwrap_or_else(|| "generated".to_owned());
        let intake_state_dir = runtime.settings.state_dir.clone();
        // Reuse the handler's read-only checks before requesting approval. Receipt repair
        // resolves the original effect without widening ordinary project-memory writes.
        let gate_runtime = Arc::clone(&runtime);
        let gate = std::sync::Arc::new(
            move |scope: &Scope, arguments: &Value| -> Result<(), HostToolError> {
                let vault =
                    gate_runtime
                        .vault
                        .as_ref()
                        .ok_or_else(|| HostToolError::Unavailable {
                            tool: "vault_write_generated",
                            reason: "the vault adapter is not configured".to_owned(),
                        })?;
                if let Some(correlation_id) = receipt_correlation(arguments)? {
                    return super::adapters::admit_receipt_repair(
                        &gate_runtime,
                        scope,
                        &correlation_id,
                    );
                }
                let page_name = parse_string(arguments, "page_name", 256)?;
                let _content = parse_string(arguments, "content", 1_048_576)?;
                let seat = scope.seat.as_ref().ok_or_else(|| HostToolError::Scope {
                    tool: "vault_write_generated",
                    reason: "a bound seat is required; generated writes are scoped to the \
                             calling session's declared project memory namespace",
                })?;
                let session = scope.session.as_ref().ok_or_else(|| HostToolError::Scope {
                    tool: "vault_write_generated",
                    reason: "a bound session is required; generated writes are scoped to the \
                             session's declared project memory namespace",
                })?;
                let gate =
                    gate_runtime
                        .vault_write_gate()
                        .ok_or_else(|| HostToolError::Unavailable {
                            tool: "vault_write_generated",
                            reason: "no vault scoping gate composed; a generated write cannot \
                                 prove its declared project memory namespace"
                                .to_owned(),
                        })?;
                gate.gate_generated_write(
                    seat,
                    session,
                    vault.config().source_id.as_str(),
                    &page_name,
                )
                .map_err(|error| HostToolError::Unavailable {
                    tool: "vault_write_generated",
                    reason: error.to_string(),
                })?;
                Ok(())
            },
        );
        let execute_gate = Arc::clone(&gate);
        let handler = move |scope: Scope, arguments: Value| {
            execute_gate(&scope, &arguments)?;
            if let Some(correlation_id) = receipt_correlation(&arguments)? {
                return super::adapters::repair_receipt(&runtime, &scope, &correlation_id);
            }
            let vault = runtime
                .vault
                .as_ref()
                .expect("the gate proved the vault adapter is configured");
            let page_name = parse_string(&arguments, "page_name", 256)?;
            let content = parse_string(&arguments, "content", 1_048_576)?;
            let input = crate::vault::VaultWriteGeneratedInput { page_name, content };
            let output =
                vault
                    .write_generated(&input)
                    .map_err(|error| HostToolError::Unavailable {
                        tool: "vault_write_generated",
                        reason: error.to_string(),
                    })?;
            let mut receipt =
                serde_json::to_value(&output).map_err(|error| HostToolError::Response {
                    tool: "vault_write_generated",
                    detail: error.to_string(),
                })?;
            if let (Some(seat), Some(session), Some(gate)) = (
                scope.seat.as_ref(),
                scope.session.as_ref(),
                runtime.vault_write_gate(),
            ) {
                if let Err(error) = gate.generated_written(
                    seat,
                    session,
                    vault.config().source_id.as_str(),
                    &output.page_name,
                ) {
                    // The write is durable. Do not report a pre-effect refusal or
                    // encourage blind retry when only projection is unavailable.
                    receipt["knowledgeRefreshUnavailable"] = Value::String(error.to_string());
                }
            }
            Ok(receipt)
        };
        let writer: Arc<dyn HostTool> = Arc::new(CapabilityTool::plain(
            RpcHostToolDefinition {
                name: "vault_write_generated".into(),
                label: "Write generated vault page".into(),
                description: format!(
                    "Writes one Markdown page strictly inside the generated namespace. \
                     page_name MUST be the full page path that begins with the \
                     generated namespace {generated_namespace:?}, for example \
                     \"{generated_namespace}/thesis-advisor-meeting\" — a bare page \
                     name, another namespace, traversal, or a symlink escape is \
                     refused typed. The page's text becomes retrievable through the \
                     seat's own memory context on later turns. Alternatively, \
                     receipt_correlation_id alone (no page_name or content) republishes \
                     the derived receipt pages of one committed email_draft or \
                     calendar_propose of this session whose receiptPublication was not \
                     published: the pages are rebuilt from that effect's own record, \
                     missing ones are written, identical ones are left alone, an edited \
                     one is never overwritten, and nothing is drafted, booked or sent again."
                )
                .into(),
                parameters: object_schema(
                    "vault_write",
                    json!({
                        "page_name": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 256,
                            "description": format!(
                                "Full vault-relative page path beginning with \
                                 {generated_namespace:?}, e.g. \
                                 \"{generated_namespace}/<page-name>\""
                            )
                        },
                        "content": { "type": "string", "minLength": 1, "maxLength": 1048576 },
                        "receipt_correlation_id": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 128,
                            "description": "receiptPublication.correlationId of the original \
                                            effect; replaces page_name and content"
                        }
                    }),
                    &[],
                ),
                hidden: false,
                load_mode: odin_omp::host_tools::ToolLoadMode::Discoverable,
            },
            Box::new(handler),
            Box::new(move |scope: &Scope, arguments: &Value| gate(scope, arguments)),
        ));
        tools.push(Arc::clone(&writer));
        tools.push(Arc::new(super::files::IntakeFileTool::new(
            Arc::clone(&writer),
            generated_namespace.clone(),
            intake_state_dir,
        )));
        tools.push(super::memory::memory_forget_tool(memory_runtime.clone()));
        tools.push(super::memory::memory_remember_tool(memory_runtime));
    }
}

pub(super) fn finance_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    // -- finance.read_summary ---------------------------------------------
    {
        let runtime = Arc::clone(runtime);
        // Declared-admissibility gate: the strict month parse is the
        // handler's entire pre-effect resolution; the summary read itself
        // is the execution and governs at the permit.
        let gate = std::sync::Arc::new(
            move |_scope: &Scope, arguments: &Value| -> Result<(), HostToolError> {
                let _month = parse_string(arguments, "month", 7)?;
                Ok(())
            },
        );
        let execute_gate = Arc::clone(&gate);
        let handler = move |_scope: Scope, arguments: Value| {
            execute_gate(&_scope, &arguments)?;
            let month = parse_string(&arguments, "month", 7)?;
            let summary =
                runtime
                    .finance_summary(&month)
                    .map_err(|reason| HostToolError::Unavailable {
                        tool: "finance_read_summary",
                        reason,
                    })?;
            let categories: Vec<Value> = summary
                .categories
                .iter()
                .map(|category| {
                    json!({
                        "name": category.name,
                        "budgeted_cents": category.budgeted_cents,
                        "spent_cents": category.spent_cents,
                    })
                })
                .collect();
            Ok(json!({
                "month": summary.month,
                "source": summary.source,
                "income_cents": summary.income_cents,
                "spent_cents": summary.spent_cents,
                "net_cents": summary.net_cents,
                "transaction_count": summary.transaction_count,
                "categories": categories,
            }))
        };
        tools.push(Arc::new(CapabilityTool::plain(
            RpcHostToolDefinition {
                name: "finance_read_summary".into(),
                label: "Finance month summary".into(),
                description: "Reads the local-first aggregate month summary from the configured \
                 Actual Budget database. Aggregate cents only: account names, numbers, \
                 notes, and payees are structurally excluded."
                    .into(),
                parameters: object_schema(
                    "finance_summary",
                    json!({
                        "month": {
                            "type": "string",
                            "pattern": "^[0-9]{4}-[0-9]{2}$",
                            "maxLength": 7
                        }
                    }),
                    &["month"],
                ),
                hidden: false,
                load_mode: odin_omp::host_tools::ToolLoadMode::Discoverable,
            },
            Box::new(handler),
            Box::new(move |scope: &Scope, arguments: &Value| gate(scope, arguments)),
        )));
    }
}

/// The model-facing shape of a [`crate::purchase::CheckoutPlan`].
fn checkout_plan_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "product_url": { "type": "string", "minLength": 9, "maxLength": 2048, "pattern": "^https://" },
            "add_to_cart": { "type": "string", "minLength": 1, "maxLength": 256 },
            "checkout_url": { "type": "string", "minLength": 9, "maxLength": 2048, "pattern": "^https://" },
            "place_order": { "type": "string", "minLength": 1, "maxLength": 256 }
        },
        "required": ["product_url", "add_to_cart", "checkout_url", "place_order"],
        "additionalProperties": false
    })
}

/// Shared decoding keeps readiness and execution on the same purchase request.
fn parse_purchase_request(arguments: &Value) -> Result<PurchaseRequest, HostToolError> {
    let invalid = |detail: String| HostToolError::Arguments {
        tool: "purchase_submit",
        detail,
    };
    let vendor = parse_string(arguments, "vendor", 128)?;
    let item = parse_string(arguments, "item_description", 256)?;
    let amount_value = arguments
        .get("amount")
        .ok_or_else(|| invalid("amount must be an object".to_owned()))?;
    let currency = amount_value
        .get("currency")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("amount.currency must be a string".to_owned()))?;
    let amount = amount_value
        .get("minor_units")
        .and_then(Value::as_i64)
        .ok_or_else(|| invalid("amount.minor_units must be an integer".to_owned()))?;
    let request = PurchaseRequest::new(vendor, item, amount, currency)
        .map_err(|error| invalid(error.to_string()))?;
    match arguments.get("checkout") {
        None | Some(Value::Null) => Ok(request),
        Some(plan) => {
            let plan: crate::purchase::CheckoutPlan = serde_json::from_value(plan.clone())
                .map_err(|error| invalid(format!("checkout is not a checkout plan: {error}")))?;
            request
                .with_checkout(plan)
                .map_err(|error| invalid(error.to_string()))
        }
    }
}

pub(super) fn purchase_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    // -- purchase.submit ---------------------------------------------------
    {
        let runtime = Arc::clone(runtime);
        // Validate arguments, caller seat, backend and checkout requirements before
        // requesting approval, without contacting the provider.
        let gate_runtime = Arc::clone(&runtime);
        let gate =
            std::sync::Arc::new(
                move |scope: &Scope, arguments: &Value| -> Result<(), HostToolError> {
                    let request = parse_purchase_request(arguments)?;
                    // Readiness validates the business arguments and declared
                    // prerequisites only; the approval proof is verified by the
                    // real consumed-command path at the permit, never here.
                    if scope.seat.is_none() {
                        return Err(HostToolError::Scope {
                            tool: "purchase_submit",
                            reason: "a bound seat is required; purchase preparation never \
                                 defaults the dispatch target",
                        });
                    }
                    let backend = gate_runtime.purchase_backend.lock().map_err(|_| {
                        HostToolError::Storage {
                            tool: "purchase_submit",
                            detail: "purchase backend state poisoned".to_owned(),
                        }
                    })?;
                    let Some((contract, _exchange)) = backend.as_ref() else {
                        return Err(HostToolError::Unavailable {
                            tool: "purchase_submit",
                            reason: "the purchase-submit backend deployment is not declared; \
                                 no provider contact is possible"
                                .to_owned(),
                        });
                    };
                    // Browser checkout requires a plan; vendor-API backends do not.
                    if contract.requires_checkout_plan() && request.checkout().is_none() {
                        return Err(HostToolError::Arguments {
                            tool: "purchase_submit",
                            detail: "the governed-browser checkout backend delivers only \
                                 requests carrying a checkout plan; research the product in \
                                 the governed browser and propose one"
                                .to_owned(),
                        });
                    }
                    Ok(())
                },
            );
        let execute_gate = Arc::clone(&gate);
        let prepared_handler = move |_effect: &odin_kernel::operation::PreparedEffect,
                                     consumed: &odin_omp::host_tools::ConsumedHostCommand,
                                     scope: Scope,
                                     arguments: Value| {
            // Recheck readiness against the consumed command's exact arguments.
            execute_gate(&scope, &arguments)?;
            let request = parse_purchase_request(&arguments)?;
            let now = now_utc();
            // The kernel journaled the durable intent row for the OUTER
            // command it consumed the operator approval into — identity,
            // approval binding, arguments and digest all live in that one
            // authority row; no second row is ever recorded here.
            let command_id = consumed.command_id().clone();
            // The dispatch target is the calling scope's real seat —
            // never a default owner: an unbound seat refuses preparation.
            let seat = scope.seat.clone().ok_or_else(|| HostToolError::Scope {
                tool: "purchase_submit",
                reason: "a bound seat is required; purchase preparation never \
                         defaults the dispatch target",
            })?;
            // The kernel gate owns the human decision: the journaled
            // command row and its approval are verified against the
            // consumed proof — never taken from the model's selector and
            // never synthesized — before anything is accepted or
            // exchanged.
            let approval_id = runtime
                .verify_consumed_purchase_approval(consumed)
                .map_err(|detail| HostToolError::Catalog {
                    detail: format!("the consumed purchase approval does not verify: {detail}"),
                })?;
            // The envelope supplies the canonical payload, idempotency key and consumed approval.
            let prepared = crate::purchase::prepare(
                &request,
                PurchasePrepareInit {
                    command_id: command_id.clone(),
                    sequence: 1,
                    issued_at_ms: unix_ms(now),
                    expires_at_ms: unix_ms(
                        now + time::Duration::hours(PURCHASE_APPROVAL_TTL_HOURS),
                    ),
                    actor: Actor::system(RUNTIME_ISSUER).map_err(|error| {
                        HostToolError::Arguments {
                            tool: "purchase_submit",
                            detail: error.to_string(),
                        }
                    })?,
                    scope: scope.clone(),
                    target: CommandTarget::Seat(seat),
                    producer: producer().map_err(|error| HostToolError::Arguments {
                        tool: "purchase_submit",
                        detail: error.to_string(),
                    })?,
                    approval_id,
                },
            )
            .map_err(|error| HostToolError::Arguments {
                tool: "purchase_submit",
                detail: error.to_string(),
            })?;
            // The journaled intent is ACCEPTED before any exchange: a
            // purchase that executes is accepted-and-nonterminal until a
            // provable outcome settles it, so an uncertain settlement
            // stays reconcilable.
            runtime
                .accept_purchase_intent(&command_id, now)
                .map_err(|error| HostToolError::Uncertain {
                    tool: "purchase_submit",
                    detail: format!(
                        "the durable intent could not be accepted before dispatch: {error}"
                    ),
                })?;
            // Relay the already-approved command without consuming approval again.
            let backend = runtime
                .purchase_backend
                .lock()
                .map_err(|_| HostToolError::Storage {
                    tool: "purchase_submit",
                    detail: "purchase backend state poisoned".to_owned(),
                })?
                .clone();
            let Some((contract, exchange)) = backend else {
                return Err(HostToolError::Unavailable {
                    tool: "purchase_submit",
                    reason: "the purchase-submit backend deployment is not declared; the \
                             consumed approval is recorded and no provider contact is possible"
                        .to_owned(),
                });
            };
            let submitter = crate::purchase::M10PurchaseSubmitter::new(contract, exchange);

            match crate::purchase::PurchaseSubmitter::submit(&submitter, &prepared.command) {
                Ok(receipt) => {
                    // The order was witnessed as placed: a terminal record
                    // that cannot be written leaves the outcome unsettled,
                    // which is uncertainty — never a submitted result.
                    runtime
                        .record_purchase_terminal(
                            &command_id,
                            odin_ledger::command::CommandTerminalStatus::Completed,
                            json!({
                                "status": "submitted",
                                "providerRef": receipt.provider_ref,
                                "idempotencyKey": receipt.idempotency_key,
                            }),
                            now,
                        )
                        .map_err(|error| HostToolError::Uncertain {
                            tool: "purchase_submit",
                            detail: format!(
                                "the order was placed but its durable terminal record could \
                                 not be written: {error}"
                            ),
                        })?;
                    Ok(json!({
                        "status": "submitted",
                        "command_id": receipt.command_id.to_string(),
                        "provider_ref": receipt.provider_ref,
                    }))
                }
                Err(crate::purchase::PurchaseFault::Uncertain) => {
                    // The dispatch may have landed: the accepted intent
                    // stays nonterminal for durable reconciliation —
                    // never a terminal Failed — and no success is claimed.
                    Err(HostToolError::Uncertain {
                        tool: "purchase_submit",
                        detail: "the dispatch outcome is unknowable; reconcile from durable \
                             evidence"
                            .to_owned(),
                    })
                }
                Err(fault) => {
                    // Accepted commands complete as Failed on effect-free refusal; inability
                    // to persist that settlement leaves the outcome uncertain.
                    let reason = match &fault {
                        crate::purchase::PurchaseFault::Rejected => {
                            "the governed submitter refused the frame before dispatch".to_owned()
                        }
                        crate::purchase::PurchaseFault::BackendRefused(code) => format!(
                            "the backend refused before any provider exchange (typed code {code:?})"
                        ),
                        crate::purchase::PurchaseFault::Uncertain => {
                            unreachable!("the uncertain fault returned early")
                        }
                    };
                    runtime
                        .record_purchase_terminal(
                            &command_id,
                            odin_ledger::command::CommandTerminalStatus::Failed,
                            json!({
                                "status": "failed",
                                "reason": reason,
                            }),
                            now,
                        )
                        .map_err(|error| HostToolError::Uncertain {
                            tool: "purchase_submit",
                            detail: format!(
                                "the refusal could not be recorded durably ({reason}): {error}"
                            ),
                        })?;
                    Err(HostToolError::Uncertain {
                        tool: "purchase_submit",
                        detail: reason,
                    })
                }
            }
        };
        tools.push(Arc::new(CapabilityTool::approved(RpcHostToolDefinition {
        name: "purchase_submit".into(),
        label: "Submit approved purchase".into(),
        description:
            "Executes one operator-approved purchase through the governed M10 submitter. \
             Reachable only through the kernel-minted permit of a dispatch whose exact \
             approval the kernel gate consumed; an undeclared backend is a typed missing \
             deployment, never a success. To buy on Colin's account, research the product \
             in the governed browser first (browser_observe sanitizedDom finds the controls) \
             and pass `checkout`: the product page, its add-to-cart control, the checkout \
             page and its place-order control. Colin's one approval covers exactly that \
             checkout; the order is placed only if the checkout page shows the approved \
             amount.".into(),
        parameters: object_schema(
            "purchase_submit",
            json!({
                "vendor": { "type": "string", "minLength": 1, "maxLength": 128 },
                "item_description": { "type": "string", "minLength": 1, "maxLength": 256 },
                "amount": {
                    "type": "object",
                    "properties": {
                        "currency": { "type": "string", "pattern": "^[A-Z]{3}$" },
                        "minor_units": { "type": "integer", "minimum": 1, "maximum": 1000000000 }
                    },
                    "required": ["currency", "minor_units"],
                    "additionalProperties": false
                },
                "checkout": checkout_plan_schema(),
                "approvalId": { "type": "string", "minLength": 1, "maxLength": 128 }
            }),
            &["vendor", "item_description", "amount", "approvalId"],
        ),
        hidden: false,
        load_mode: odin_omp::host_tools::ToolLoadMode::Discoverable,
        },
        "purchase.submit",
        Box::new(prepared_handler),
        Box::new(move |scope: &Scope, arguments: &Value| gate(scope, arguments)),)));
    }
}

pub(super) fn discord_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    tools.push(Arc::new(super::files::IntakeReadTool::new(
        runtime.settings.state_dir.clone(),
    )));
    // -- discord.notify / discord.intake ----------------------------------
    {
        let runtime = Arc::clone(runtime);
        // Declared-admissibility gate: the strict message parse is the
        // handler's entire pre-effect resolution; the governed REST
        // notification is the execution and governs at the permit.
        let gate = std::sync::Arc::new(
            move |_scope: &Scope, arguments: &Value| -> Result<(), HostToolError> {
                let _message = parse_string(arguments, "message", 2_000)?;
                Ok(())
            },
        );
        let execute_gate = Arc::clone(&gate);
        let handler = move |_scope: Scope, arguments: Value| {
            execute_gate(&_scope, &arguments)?;
            let message = parse_string(&arguments, "message", 2_000)?;
            runtime
                .notify(&message)
                .map_err(|reason| HostToolError::Unavailable {
                    tool: "discord_notify",
                    reason,
                })?;
            Ok(json!({ "status": "sent" }))
        };
        tools.push(Arc::new(CapabilityTool::plain(
            RpcHostToolDefinition {
                name: "discord_notify".into(),
                label: "Notify owner channel".into(),
                description: "Sends one bounded status notification to the owner-paired Discord \
                 channel over the governed REST transport. Credential values never \
                 appear in the message path."
                    .into(),
                parameters: object_schema(
                    "discord_notify",
                    json!({
                        "message": { "type": "string", "minLength": 1, "maxLength": 2000 }
                    }),
                    &["message"],
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
        // Declared-admissibility gate: the strict message-shape parse is
        // the handler's entire pre-effect resolution; the correlation
        // admission is the execution and governs at the permit.
        let gate = std::sync::Arc::new(
            move |_scope: &Scope, arguments: &Value| -> Result<(), HostToolError> {
                let _message = crate::discord::DiscordMessage {
                    id: parse_string(arguments, "message_id", 32)?,
                    channel_id: parse_string(arguments, "channel_id", 32)?,
                    author_id: parse_string(arguments, "author_id", 32)?,
                    guild_id: arguments
                        .get("guild_id")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    content: parse_string(arguments, "content", 4_096)?,
                    attachments: Vec::new(),
                };
                Ok(())
            },
        );
        let execute_gate = Arc::clone(&gate);
        let handler = move |_scope: Scope, arguments: Value| {
            execute_gate(&_scope, &arguments)?;
            let message = crate::discord::DiscordMessage {
                id: parse_string(&arguments, "message_id", 32)?,
                channel_id: parse_string(&arguments, "channel_id", 32)?,
                author_id: parse_string(&arguments, "author_id", 32)?,
                guild_id: arguments
                    .get("guild_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                content: parse_string(&arguments, "content", 4_096)?,
                attachments: Vec::new(),
            };
            let projection =
                runtime
                    .admit_message(&message)
                    .map_err(|error| HostToolError::Unavailable {
                        tool: "discord_intake",
                        reason: error.to_string(),
                    })?;
            Ok(projection)
        };
        tools.push(Arc::new(CapabilityTool::plain(
            RpcHostToolDefinition {
                name: "discord_intake".into(),
                label: "Record owner intent".into(),
                description:
                    "Runs one owner-paired Discord message through the correlation adapter: \
                 exactly one durable task per surface id, replays deduplicate, and R3 \
                 legs gate on the kernel approval flow. Non-owner authors are refused."
                        .into(),
                parameters: object_schema(
                    "discord_intake",
                    json!({
                        "message_id": { "type": "string", "minLength": 1, "maxLength": 32 },
                        "channel_id": { "type": "string", "minLength": 1, "maxLength": 32 },
                        "author_id": { "type": "string", "minLength": 1, "maxLength": 32 },
                        "content": { "type": "string", "minLength": 1, "maxLength": 4096 },
                        "guild_id": { "type": "string", "maxLength": 32 }
                    }),
                    &["message_id", "channel_id", "author_id", "content"],
                ),
                hidden: false,
                load_mode: odin_omp::host_tools::ToolLoadMode::Discoverable,
            },
            Box::new(handler),
            Box::new(move |scope: &Scope, arguments: &Value| gate(scope, arguments)),
        )));
    }
}
