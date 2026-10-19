//! Draft workloads from skeleton declarations and publish the approved digest.
//! Neither tool launches workloads; stale revisions and mismatched digests refuse publication.

use std::sync::Arc;

use odin_domain::Scope;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition};
use serde_json::{json, Value};

use super::authority::{
    WorkloadAuthoringFailure, WorkloadDraftAnswers, WorkloadDraftRequest, WorkloadPublishRequest,
};
use super::tools::{object_schema, parse_string, CapabilityTool};
use super::HermesRuntime;

/// Upper bounds mirrored from the strict schema files; the route's skeleton
/// compiler owns the real grammars, these only bound the wire.
const MAX_ID_BYTES: usize = 128;
const MAX_PATH_BYTES: usize = 256;
const MAX_HOST_FOLDER_BYTES: usize = 1024;
const MAX_BRIEF_BYTES: usize = 16_384;
const MAX_DIGEST_BYTES: usize = 80;
const MAX_ALLOW_HOSTS: usize = 16;

fn opt_string(
    tool: &'static str,
    arguments: &Value,
    field: &str,
    max_bytes: usize,
) -> Result<Option<String>, HostToolError> {
    match arguments.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => {
            let text = value.as_str().ok_or_else(|| HostToolError::Arguments {
                tool,
                detail: format!("{field} must be a string"),
            })?;
            if text.trim().is_empty() || text.len() > max_bytes {
                return Err(HostToolError::Arguments {
                    tool,
                    detail: format!("{field} must be 1..={max_bytes} bytes"),
                });
            }
            Ok(Some(text.to_owned()))
        }
    }
}

fn opt_bool(
    tool: &'static str,
    arguments: &Value,
    field: &str,
) -> Result<Option<bool>, HostToolError> {
    match arguments.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_bool()
            .map(Some)
            .ok_or_else(|| HostToolError::Arguments {
                tool,
                detail: format!("{field} must be a boolean"),
            }),
    }
}

fn opt_allow_hosts(
    tool: &'static str,
    arguments: &Value,
) -> Result<Option<Vec<String>>, HostToolError> {
    match arguments.get("allowHosts") {
        None | Some(Value::Null) => Ok(None),
        Some(value) => {
            let items = value.as_array().ok_or_else(|| HostToolError::Arguments {
                tool,
                detail: "allowHosts must be an array of strings".to_owned(),
            })?;
            // An empty list permits only DNS and the agent's model gateway.
            if items.len() > MAX_ALLOW_HOSTS {
                return Err(HostToolError::Arguments {
                    tool,
                    detail: format!("allowHosts must hold at most {MAX_ALLOW_HOSTS} hosts"),
                });
            }
            let mut hosts = Vec::with_capacity(items.len());
            for item in items {
                let host = item.as_str().ok_or_else(|| HostToolError::Arguments {
                    tool,
                    detail: "allowHosts must be an array of strings".to_owned(),
                })?;
                if host.trim().is_empty() || host.len() > 253 {
                    return Err(HostToolError::Arguments {
                        tool,
                        detail: "each allowHosts entry must be 1..=253 bytes".to_owned(),
                    });
                }
                hosts.push(host.to_owned());
            }
            Ok(Some(hosts))
        }
    }
}

/// Reads one optional nonnegative integer argument.
fn opt_u64(
    tool: &'static str,
    arguments: &Value,
    field: &str,
) -> Result<Option<u64>, HostToolError> {
    match arguments.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| HostToolError::Arguments {
                tool,
                detail: format!("{field} must be a nonnegative integer"),
            }),
    }
}

/// Decodes the declared answers from the wire arguments.
fn decode_answers(
    tool: &'static str,
    arguments: &Value,
) -> Result<WorkloadDraftAnswers, HostToolError> {
    Ok(WorkloadDraftAnswers {
        description: opt_string(tool, arguments, "description", 512)?,
        enabled: opt_bool(tool, arguments, "enabled")?,
        seat: opt_string(tool, arguments, "seat", MAX_ID_BYTES)?,
        project: opt_string(tool, arguments, "project", MAX_ID_BYTES)?,
        gateway_lane: opt_string(tool, arguments, "gatewayLane", MAX_ID_BYTES)?,
        allow_hosts: opt_allow_hosts(tool, arguments)?,
        screen: opt_string(tool, arguments, "screen", 32)?,
        stream: opt_bool(tool, arguments, "stream")?,
        state_path: opt_string(tool, arguments, "statePath", MAX_PATH_BYTES)?,
        state_storage: opt_string(tool, arguments, "stateStorage", 16)?,
        export_pod_path: opt_string(tool, arguments, "exportPodPath", MAX_PATH_BYTES)?,
        export_host_folder: opt_string(tool, arguments, "exportHostFolder", MAX_HOST_FOLDER_BYTES)?,
        brief_text: opt_string(tool, arguments, "briefText", MAX_BRIEF_BYTES)?,
        memory_namespace: opt_string(tool, arguments, "memoryNamespace", MAX_ID_BYTES)?,
        deadline_seconds: opt_u64(tool, arguments, "deadlineSeconds")?,
        harness: opt_string(tool, arguments, "harness", 16)?,
        image_reference: opt_string(tool, arguments, "imageReference", 512)?,
        script_command: opt_strings(tool, arguments, "scriptCommand", 64, 4096)?,
        gpu_count: opt_u64(tool, arguments, "gpuCount")?,
        placement: opt_strings(tool, arguments, "placement", 8, 63)?,
        mode: opt_string(tool, arguments, "mode", 16)?,
        monitoring_cadence_seconds: opt_u64(tool, arguments, "monitoringCadenceSeconds")?,
        progress: opt_string(tool, arguments, "progress", 64)?,
        stall_seconds: opt_u64(tool, arguments, "stallSeconds")?,
        recovery: match arguments.get("recovery") {
            None | Some(Value::Null) => None,
            Some(value @ Value::Object(_)) => Some(value.clone()),
            Some(_) => {
                return Err(HostToolError::Arguments {
                    tool,
                    detail: "recovery must be an object".to_owned(),
                })
            }
        },
        tools: opt_strings(tool, arguments, "tools", 32, 128)?,
        watchdogs: match arguments.get("watchdogs") {
            None | Some(Value::Null) => None,
            Some(Value::Array(items))
                if items.len() <= 16 && items.iter().all(Value::is_object) =>
            {
                Some(items.clone())
            }
            Some(_) => {
                return Err(HostToolError::Arguments {
                    tool,
                    detail: "watchdogs must be an array of at most 16 objects".to_owned(),
                })
            }
        },
    })
}

/// Reads one optional bounded array of nonempty strings.
fn opt_strings(
    tool: &'static str,
    arguments: &Value,
    field: &str,
    max_items: usize,
    max_bytes: usize,
) -> Result<Option<Vec<String>>, HostToolError> {
    let invalid = || HostToolError::Arguments {
        tool,
        detail: format!(
            "{field} must be an array of 1..={max_items} nonempty strings of at most {max_bytes} \
             bytes"
        ),
    };
    match arguments.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) if !items.is_empty() && items.len() <= max_items => items
            .iter()
            .map(|item| match item.as_str() {
                Some(text) if !text.is_empty() && text.len() <= max_bytes => Ok(text.to_owned()),
                _ => Err(invalid()),
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        Some(_) => Err(invalid()),
    }
}

/// Shared by preflight and execution so both parse the same request.
fn parse_draft_request(
    tool: &'static str,
    arguments: &Value,
) -> Result<WorkloadDraftRequest, HostToolError> {
    Ok(WorkloadDraftRequest {
        profile_id: parse_string(arguments, "profileId", MAX_ID_BYTES)?,
        answers: decode_answers(tool, arguments)?,
        expected_registry_revision: opt_u64(tool, arguments, "expectedRegistryRevision")?,
    })
}

/// Requires the new publication revision; preflight and execution share this decoder.
fn parse_publish_request(arguments: &Value) -> Result<WorkloadPublishRequest, HostToolError> {
    Ok(WorkloadPublishRequest {
        profile_id: parse_string(arguments, "profileId", MAX_ID_BYTES)?,
        declaration_digest: parse_string(arguments, "declarationDigest", MAX_DIGEST_BYTES)?,
        expected_registry_revision: opt_u64(
            "workload_publish",
            arguments,
            "expectedRegistryRevision",
        )?
        .ok_or_else(|| HostToolError::Arguments {
            tool: "workload_publish",
            detail: "expectedRegistryRevision is required and must be the exact NEW registry \
                     revision this publication installs — the draft response's \
                     publishRevision, verbatim"
                .to_owned(),
        })?,
    })
}

/// Maps a typed authoring failure onto the governed tool vocabulary. Invalid
/// declarations and stale scopes are argument-level refusals the model can
/// correct with a fresh draft; worktree and publication faults are
/// unavailabilities that preserve the operation identity.
fn authoring_error(tool: &'static str, failure: WorkloadAuthoringFailure) -> HostToolError {
    match failure {
        WorkloadAuthoringFailure::InvalidDeclaration { issues } => HostToolError::Arguments {
            tool,
            detail: format!("the draft declaration is invalid: {}", issues.join("; ")),
        },
        WorkloadAuthoringFailure::DigestMismatch { approved, compiled } => {
            HostToolError::Arguments {
                tool,
                detail: format!(
                    "the compiled declaration is not the approved one (approved {approved}, \
                     compiled {compiled}); the old scope is dead — re-draft and re-approve"
                ),
            }
        }
        WorkloadAuthoringFailure::UnknownDraft {
            digest,
            bound_registry_revision,
        } => HostToolError::Arguments {
            tool,
            detail: format!(
                "no compiled draft {digest} is retained at bound registry revision \
                     {bound_registry_revision}; the approval scope is dead — re-draft and \
                     re-approve"
            ),
        },
        WorkloadAuthoringFailure::DraftRetention { reason } => HostToolError::Unavailable {
            tool,
            reason: format!("the retained-draft store refused: {reason}"),
        },
        WorkloadAuthoringFailure::StaleRevision { bound, next } => HostToolError::Arguments {
            tool,
            detail: format!(
                "the draft scope is stale: it bound registry revision {bound}, but the next \
                 revision is {next}; re-draft against the current registry"
            ),
        },
        WorkloadAuthoringFailure::BridgeTimeout { operation } => HostToolError::Uncertain {
            tool,
            detail: format!(
                "{operation} did not complete within its bound; the operation itself keeps \
                 running and is serialized by the publication lock — replay the IDENTICAL \
                 approved dispatch to reconcile to the same outcome"
            ),
        },
        WorkloadAuthoringFailure::WorktreeInvalid { reason } => {
            HostToolError::Unavailable { tool, reason }
        }
        WorkloadAuthoringFailure::PublicationRefused { reason } => {
            HostToolError::Unavailable { tool, reason }
        }
    }
}

/// Produces the durable draft/publication page in the vault's generated
/// namespace when the vault adapter is configured — a revisable private
/// artifact, never authority.
fn produce_vault_page(runtime: &HermesRuntime, area: &str, title: &str, body: &str) {
    let Some(vault) = runtime.vault.as_ref() else {
        return;
    };
    let digest = odin_domain::Digest::hash(body.as_bytes());
    let mut key = String::with_capacity(area.len() + 18);
    key.push_str(area);
    key.push(':');
    for byte in digest.as_bytes().iter().take(8) {
        key.push_str(&format!("{byte:02x}"));
    }
    let page = format!("{}/{}", vault.config().generated_namespace, key);
    let content = format!("# {title}\n\n{body}\n");
    let _ = vault.write_generated(&crate::vault::VaultWriteGeneratedInput {
        page_name: page,
        content,
    });
}

/// The `workload.draft` model surface, from its declared input schema.
fn draft_parameters() -> Value {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../../schemas/capability/workload.draft.input.json"
    ))
    .expect("the workload.draft input schema is committed JSON");
    let properties = schema
        .get("properties")
        .cloned()
        .unwrap_or_else(|| json!({}));
    object_schema("workload_draft", properties, &["profileId"])
}

/// The two model-facing workload authoring tools.
pub(super) fn workload_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    // -- workload.draft ----------------------------------------------------
    {
        let runtime = Arc::clone(runtime);
        // Check registry scope before journaling; execution checks it again.
        let gate_runtime = Arc::clone(&runtime);
        let gate = std::sync::Arc::new(
            move |_scope: &Scope, arguments: &Value| -> Result<(), HostToolError> {
                let route = gate_runtime.workload_authoring().ok_or_else(|| {
                    HostToolError::Unavailable {
                        tool: "workload_draft",
                        reason: "the daemon has not bound the workload authoring route; nothing \
                                 can be drafted"
                            .to_owned(),
                    }
                })?;
                route
                    .prepare_draft(&parse_draft_request("workload_draft", arguments)?)
                    .map_err(|failure| authoring_error("workload_draft", failure))?;
                Ok(())
            },
        );
        let execute_gate = Arc::clone(&gate);
        let handler = move |_scope: Scope, arguments: Value| {
            execute_gate(&_scope, &arguments)?;
            let route = runtime
                .workload_authoring()
                .expect("the gate proved the workload authoring route is bound");
            let request = parse_draft_request("workload_draft", &arguments)?;
            let draft = route
                .draft(request)
                .map_err(|failure| authoring_error("workload_draft", failure))?;
            if let Some(declaration) = draft.declaration.as_ref() {
                produce_vault_page(
                    runtime.as_ref(),
                    "workload-drafts",
                    &format!("Workload draft {}", draft.profile_id),
                    &declaration.rendered_toml,
                );
            }
            serde_json::to_value(&draft).map_err(|error| HostToolError::Response {
                tool: "workload_draft",
                detail: error.to_string(),
            })
        };
        tools.push(Arc::new(CapabilityTool::plain(
            RpcHostToolDefinition {
                name: "workload_draft".into(),
                label: "Draft workload profile".into(),
                description:
                    "Drafts a new pod type: a script pod (harness script: scriptCommand in your \
                     imageReference, a digest-pinned image) or an agent pod (the default: an \
                     agent with a brief on the platform image), as a finite job (deadlineSeconds) \
                     or a long-lived service (mode service), with GPUs, placement on node \
                     capabilities, egress hosts, monitoring watchdogs and the tools it may call. \
                     Validates every reference against the published registry and returns either \
                     the facts it still needs or the complete declaration with its exact digest \
                     and the registry revision (publishRevision) to publish with. Launches \
                     nothing."
                        .into(),
                // The one declared input contract: the model surface is the
                // capability's schema file, never a second hand-kept copy.
                parameters: draft_parameters(),
                hidden: false,
                load_mode: odin_omp::host_tools::ToolLoadMode::Discoverable,
            },
            Box::new(handler),
            Box::new(move |scope: &Scope, arguments: &Value| gate(scope, arguments)),
        )));
    }

    // -- workload.publish ---------------------------------------------------
    {
        let runtime = Arc::clone(runtime);
        // Read-only publication-readiness gate, observed BEFORE the
        // operator is asked or the approval is consumed: retained-draft
        // identity/integrity, current revision scope, exact-replay
        // eligibility, the worktree prerequisites, and the pure candidate
        // validation. Effectful work stays at execution.
        let gate_runtime = Arc::clone(&runtime);
        let gate = std::sync::Arc::new(
            move |_scope: &Scope, arguments: &Value| -> Result<(), HostToolError> {
                let route = gate_runtime.workload_authoring().ok_or_else(|| {
                    HostToolError::Unavailable {
                        tool: "workload_publish",
                        reason: "the daemon has not bound the workload authoring route; nothing \
                                 can be published"
                            .to_owned(),
                    }
                })?;
                route
                    .prepare_publish(&parse_publish_request(arguments)?)
                    .map_err(|failure| authoring_error("workload_publish", failure))?;
                Ok(())
            },
        );
        let execute_gate = Arc::clone(&gate);
        let prepared_handler = move |_effect: &odin_kernel::operation::PreparedEffect,
                                     _consumed: &odin_omp::host_tools::ConsumedHostCommand,
                                     _scope: Scope,
                                     arguments: Value| {
            execute_gate(&_scope, &arguments)?;
            let route = runtime
                .workload_authoring()
                .expect("the gate proved the workload authoring route is bound");
            let request = parse_publish_request(&arguments)?;
            let publication = route
                .publish(request)
                .map_err(|failure| authoring_error("workload_publish", failure))?;
            produce_vault_page(
                runtime.as_ref(),
                "workload-publications",
                &format!("Published workload profile {}", publication.profile_id),
                &format!(
                    "revision {}\ncommit {}\ndigest {}\n",
                    publication.published_revision,
                    publication.commit,
                    publication.declaration_digest
                ),
            );
            serde_json::to_value(&publication).map_err(|error| HostToolError::Response {
                tool: "workload_publish",
                detail: error.to_string(),
            })
        };
        tools.push(Arc::new(CapabilityTool::approved(
            RpcHostToolDefinition {
                name: "workload_publish".into(),
                label: "Publish approved workload profile".into(),
                description:
                    "Publishes the workload profile draft RETAINED by workload_draft — the \
                 exact compiled declaration that draft returned, looked up by profile \
                 and digest; nothing is re-derived from model answers. Reachable only \
                 through the kernel-minted permit of a dispatch whose exact approval \
                 the kernel gate consumed; an unknown profile or digest, or a stale \
                 target revision, refuses with the old scope dead."
                        .into(),
                parameters: object_schema(
                    "workload_publish",
                    json!({
                        "profileId": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 128,
                            "description": "The profile id the retained draft belongs to — \
                                            the exact identity this publication installs."
                        },
                        "declarationDigest": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 80,
                            "description": "The draft's blake3 declaration digest; the \
                                            publication consumes the retained compiled \
                                            declaration under exactly this digest."
                        },
                        "expectedRegistryRevision": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Exact NEW registry revision this publication \
                                            installs — the draft response's publishRevision, \
                                            verbatim (base revision + 1), not the base."
                        },
                        "approvalId": {
                            "type": "string", "minLength": 1, "maxLength": 128,
                            "description": "Only when Colin was asked and answered: the exact \
                                            approval he decided. Publication is decided by the \
                                            declaration, so omit it otherwise."
                        }
                    }),
                    &["profileId", "declarationDigest", "expectedRegistryRevision"],
                ),
                hidden: false,
                load_mode: odin_omp::host_tools::ToolLoadMode::Discoverable,
            },
            "workload.publish",
            Box::new(prepared_handler),
            Box::new(move |scope: &Scope, arguments: &Value| gate(scope, arguments)),
        )));
    }
}
