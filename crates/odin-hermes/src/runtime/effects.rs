//! The governed consequential-effect surfaces: vault reads/writes, the
//! finance summary read, the kernel-gated purchase submit, and the
//! owner-channel Discord notify/intake tools.

use std::sync::Arc;

use odin_domain::Scope;
use odin_omp::capability_parameters;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition};
use serde_json::Value;

use super::tools::{parse_string, CapabilityTool};
use super::HermesRuntime;


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
                parameters: capability_parameters!("vault.search"),
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
                     \"{generated_namespace}/thesis-advisor-meeting.md\" (it ends in .md) — a bare page \
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
                parameters: {
                    let mut parameters = capability_parameters!("vault.write_generated");
                    if let Some(Value::String(text)) =
                        parameters.pointer_mut("/properties/page_name/description")
                    {
                        text.push_str(&format!(" Here: \"{generated_namespace}/<page-name>\"."));
                    }
                    parameters
                },
                hidden: false,
                load_mode: odin_omp::host_tools::ToolLoadMode::Discoverable,
            },
            Box::new(handler),
            Box::new(move |scope: &Scope, arguments: &Value| gate(scope, arguments)),
        ));
        tools.push(Arc::clone(&writer));
        tools.push(super::memory::memory_forget_tool(memory_runtime.clone()));
        tools.push(super::memory::memory_remember_tool(memory_runtime));
    }
}




pub(super) fn discord_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    tools.push(Arc::new(super::files::IntakeReadTool::new(
        runtime.settings.state_dir.clone(),
    )));
    // -- discord.intake ---------------------------------------------------
    {
        let runtime = Arc::clone(runtime);
        // The strict message-shape parse is the handler's entire pre-effect resolution; the
        // correlation admission is the execution and governs at the permit.
        let handler = move |_scope: Scope, arguments: Value| {
            let message = discord_message(&arguments)?;
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
                parameters: capability_parameters!("discord.intake"),
                hidden: false,
                load_mode: odin_omp::host_tools::ToolLoadMode::Discoverable,
            },
            Box::new(handler),
            Box::new(|_scope: &Scope, arguments: &Value| discord_message(arguments).map(|_| ())),
        )));
    }
}

/// The owner message a `discord_intake` call carries, parsed strictly.
fn discord_message(arguments: &Value) -> Result<crate::discord::DiscordMessage, HostToolError> {
    Ok(crate::discord::DiscordMessage {
        id: parse_string(arguments, "message_id", 32)?,
        channel_id: parse_string(arguments, "channel_id", 32)?,
        author_id: parse_string(arguments, "author_id", 32)?,
        guild_id: arguments
            .get("guild_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        content: parse_string(arguments, "content", 4_096)?,
        attachments: Vec::new(),
    })
}
