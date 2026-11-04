//! The ONE generic seat-ask dispatch behind every delegation contract, its
//! schema, and the model-facing/generated tool surfaces built over it.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use odin_domain::Scope;
use odin_kernel::CapabilityContract;
use odin_omp::capability_parameters;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition};
use serde_json::{json, Value};
use time::OffsetDateTime;

use super::tools::{parse_string, CapabilityTool};
use super::{unix_ms, EventWake, HermesRuntime};
use crate::conversation::QUIET_REPLY;

#[derive(Clone, Debug)]
struct AskArguments {
    project: String,
    subject: String,
    question: String,
    urgency: String,
    options: Vec<Value>,
    launch: Option<odin_omp::host_tools::delegation::WorkerLane>,
}

const TOOL: &str = "seat_ask";
const SUBJECT_MAX_BYTES: usize = 200;
const QUESTION_MAX_BYTES: usize = 8_192;
const URGENCIES: [&str; 3] = ["low", "medium", "high"];

fn subject_and_question(arguments: &Value) -> Result<(String, String), HostToolError> {
    Ok((
        parse_string(arguments, "subject", SUBJECT_MAX_BYTES)?,
        parse_string(arguments, "question", QUESTION_MAX_BYTES)?,
    ))
}

fn check_urgency(urgency: &str) -> Result<(), HostToolError> {
    if URGENCIES.contains(&urgency) {
        return Ok(());
    }
    Err(HostToolError::Arguments {
        tool: TOOL,
        detail: format!("urgency must be one of {}", URGENCIES.join("|")),
    })
}

/// Shared parsing keeps preflight and dispatch argument checks identical.
fn parse_ask_arguments(arguments: &Value) -> Result<AskArguments, HostToolError> {
    let (subject, question) = subject_and_question(arguments)?;
    let parsed = AskArguments {
        project: parse_string(arguments, "project", 64)?,
        subject,
        question,
        urgency: parse_string(arguments, "urgency", 16)?,
        options: arguments
            .get("options")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        launch: match (arguments.get("provider"), arguments.get("model")) {
            (None, None) => None,
            (Some(_), Some(_)) => Some(odin_omp::host_tools::delegation::WorkerLane {
                provider: parse_string(arguments, "provider", 128)?,
                model: parse_string(arguments, "model", 256)?,
            }),
            _ => {
                return Err(HostToolError::Arguments {
                    tool: TOOL,
                    detail: "provider and model name one launch option together".to_owned(),
                })
            }
        },
    };
    check_urgency(&parsed.urgency)?;
    let wait = arguments
        .get("wait_seconds")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if wait > 600 {
        return Err(HostToolError::Arguments {
            tool: TOOL,
            detail: "wait_seconds must be 0..=600".to_owned(),
        });
    }
    Ok(parsed)
}

/// Worker completion is reported automatically; polling wastes calls and re-asking starts another worker.
const RECORDED_ASK_NEXT: &str = "the worker is on it and its answer will be reported to you \
     automatically when it finishes: tell the owner in one sentence that it is underway and end \
     your turn — do not poll task_read or set a wake for it, and do not ask again (that starts \
     another worker)";

/// Share prompt construction so preflight checks the exact bytes before consuming approval.
fn build_ask_prompt(target: &odin_domain::SeatId, arguments: &AskArguments) -> String {
    let mut prompt = format!(
        "Subject: {}\nUrgency: {}\nTarget seat: {target}\n\n{}",
        arguments.subject, arguments.urgency, arguments.question
    );
    for option in &arguments.options {
        let label = option.get("label").and_then(Value::as_str).unwrap_or("");
        let action = option
            .get("action_ref")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !label.is_empty() {
            prompt.push_str(&format!("\n- option: {label} -> {action}"));
        }
    }
    prompt
}

/// Shared preparation lets preflight inspect the exact request dispatch will execute.
struct PreparedAsk {
    delegator: Arc<crate::delegation::SeatDelegator>,
    session: odin_domain::SessionId,
    run: odin_domain::RunId,
    caller_seat: odin_domain::SeatId,
    caller_lane: odin_domain::LaneId,
    target: odin_domain::SeatId,
    project: odin_domain::ProjectId,
    prompt: String,
    title: String,
    launch: Option<odin_omp::host_tools::delegation::WorkerLane>,
}

/// Resolves scope, arguments and project without effects. The target comes from the
/// admitted contract or its host-injected argument, never a model-selected seat.
fn prepare_ask(
    runtime: &Arc<HermesRuntime>,
    declared_target: Option<&odin_domain::SeatId>,
    scope: &Scope,
    arguments: &Value,
) -> Result<PreparedAsk, HostToolError> {
    let delegator = runtime
        .delegator
        .as_ref()
        .ok_or_else(|| HostToolError::Unavailable {
            tool: TOOL,
            reason: "delegation governance is not composed".to_owned(),
        })?
        .clone();
    let session = scope.session.clone().ok_or_else(|| HostToolError::Scope {
        tool: TOOL,
        reason: "a bound session is required",
    })?;
    let run = scope.run.clone().ok_or_else(|| HostToolError::Scope {
        tool: TOOL,
        reason: "a bound run is required",
    })?;
    let caller_seat = scope.seat.clone().ok_or_else(|| HostToolError::Scope {
        tool: TOOL,
        reason: "a bound seat is required",
    })?;
    let caller_lane = scope.lane.clone().ok_or_else(|| HostToolError::Scope {
        tool: TOOL,
        reason: "a bound lane is required",
    })?;
    let target = match declared_target {
        Some(target) => target.clone(),
        None => {
            let injected = arguments
                .get(CapabilityContract::DELEGATION_TARGET_ARGUMENT)
                .and_then(Value::as_str)
                .ok_or_else(|| HostToolError::Catalog {
                    detail: format!(
                        "the host-injected {} argument is missing; the dispatch never \
                         passed the governed preparation",
                        CapabilityContract::DELEGATION_TARGET_ARGUMENT
                    ),
                })?;
            odin_domain::SeatId::new(injected).map_err(|error| HostToolError::Catalog {
                detail: format!("the host-injected delegation target is invalid: {error}"),
            })?
        }
    };
    let parsed = parse_ask_arguments(arguments)?;
    let prompt = build_ask_prompt(&target, &parsed);
    let project =
        odin_domain::ProjectId::new(parsed.project).map_err(|error| HostToolError::Arguments {
            tool: TOOL,
            detail: format!("invalid project id: {error}"),
        })?;
    // The target's declared project bindings are the admission fact: a
    // project the daemon's configured lane bindings do not bind to the
    // target is refused typed, before any governed owner is consulted — no
    // delegation row, token, child, or prompt can exist for a guessed
    // project. A target with no binding refuses every project.
    let bound_projects = runtime.seat_bound_projects.get(&target);
    if !bound_projects.is_some_and(|projects| projects.contains(&project)) {
        return Err(HostToolError::Arguments {
            tool: TOOL,
            detail: format!(
                "project {project} is not bound to seat {target} by the daemon's \
                 configured lane bindings; bound projects {:?}",
                bound_projects
                    .map(|projects| {
                        projects
                            .iter()
                            .map(|project| project.as_str().to_owned())
                            .collect::<BTreeSet<String>>()
                    })
                    .unwrap_or_default()
            ),
        });
    }
    Ok(PreparedAsk {
        delegator,
        session,
        run,
        caller_seat,
        caller_lane,
        target,
        project,
        prompt,
        title: parsed.subject.clone(),
        launch: parsed.launch,
    })
}

/// Whether `target` is an owner-facing conversation seat (declares
/// `[conversation]` in the published registry): asking it is an escalation
/// into the one conversation, never a second session of that seat.
fn is_conversation_seat(runtime: &HermesRuntime, target: &odin_domain::SeatId) -> bool {
    runtime.registry_pin().is_some_and(|pin| {
        pin.current().objects.iter().any(|object| {
            object.id == target.as_str()
                && matches!(&object.config, odin_registry::ObjectConfig::Seat(seat) if seat.conversation.is_some())
        })
    })
}

/// Sends an idempotent question to the conversation as an unprompted turn;
/// escalation authorizes the coordinator's response through `task_steer`.
fn escalate(
    runtime: &Arc<HermesRuntime>,
    target: &odin_domain::SeatId,
    scope: &Scope,
    arguments: &Value,
) -> Result<Value, HostToolError> {
    let missing = |reason| HostToolError::Scope { tool: TOOL, reason };
    let session = scope
        .session
        .clone()
        .ok_or_else(|| missing("a bound session is required"))?;
    let seat = scope
        .seat
        .clone()
        .ok_or_else(|| missing("a bound seat is required"))?;
    let (subject, question) = subject_and_question(arguments)?;
    let urgency = arguments
        .get("urgency")
        .and_then(Value::as_str)
        .unwrap_or("medium");
    check_urgency(urgency)?;
    let options: Vec<String> = arguments
        .get("options")
        .and_then(Value::as_array)
        .map(|options| {
            options
                .iter()
                .filter_map(|option| option.get("label").and_then(Value::as_str))
                .filter(|label| !label.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let project = scope
        .project
        .as_ref()
        .map_or_else(|| "its project".to_owned(), |project| project.to_string());
    let digest = odin_domain::Digest::hash(format!("{subject}\n{question}").as_bytes()).to_string();
    let ask_id = format!("ask-{session}-{}", &digest[digest.len() - 16..]);
    let mut text = format!(
        "{seat} (worker session {session}, working on {project}) asks you a {urgency}-urgency \
         question and is waiting for the answer.\nSubject: {subject}\n{question}"
    );
    for (index, option) in options.iter().enumerate() {
        text.push_str(&format!("\nOption {}: {option}", index + 1));
    }
    text.push_str(&format!(
        "\nIf the answer is clearly yours to give, decide; otherwise ask the owner in one short \
         message with the options. Then deliver the decision with task_steer \
         (childSession {session}) — the worker continues on it. It stays blocked until \
         then, so this wake never ends {QUIET_REPLY}."
    ));
    // The same subject from the same seat is one question however many of its
    // sessions ask it: the repeats wait on the answer to the first.
    let subject_key = super::cause_of(&subject).to_lowercase();
    let stream = format!("ask:{seat}:{subject_key}");
    let unavailable = |reason| HostToolError::Unavailable {
        tool: TOOL,
        reason: format!("the escalation could not be queued for {target}: {reason}"),
    };
    let woke = runtime
        .wake_event(&ask_id, &text, &stream, &subject_key)
        .map_err(unavailable)?;
    if matches!(woke, EventWake::Quiet { .. }) {
        let first = runtime
            .quiet_wake_id(&stream)
            .map_err(unavailable)?
            .unwrap_or_default();
        return Ok(json!({
            "status": "already_asked",
            "ask_id": first,
            "session": session.to_string(),
            "target_seat": target.to_string(),
            "next": "the same question is already with the coordinator and its answer is not \
                     yet in; go on with other work, or end your turn with this item unmet",
        }));
    }
    let queued = woke == EventWake::Queued;
    if let Some(delegator) = runtime.delegator.as_ref() {
        if let Ok(child) = odin_domain::huginn::LiveSessionId::parse(session.as_str()) {
            if let Err(failure) = delegator.escalate(child, target.clone()) {
                tracing::error!(
                    ask = %ask_id,
                    seat = %seat,
                    "odind: escalation ask={ask_id} seat={seat} target={target} not recorded on the \
                     worker's task row: {}: {}",
                    failure.kind, failure.detail
                );
            }
        }
    }
    tracing::info!(
        ask = %ask_id,
        seat = %seat,
        session = %session,
        "odind: escalation ask={ask_id} seat={seat} session={session} target={target} queued={queued}"
    );
    Ok(json!({
        "status": "escalated",
        "ask_id": ask_id,
        "session": session.to_string(),
        "target_seat": target.to_string(),
        "next": "your question is with the coordinator (and the owner if needed): end your turn \
                 now; the decision arrives as your next instruction",
    }))
}

fn seat_ask_dispatch(
    runtime: &Arc<HermesRuntime>,
    effect: &odin_kernel::operation::PreparedEffect,
    consumed: &odin_omp::host_tools::ConsumedHostCommand,
    scope: Scope,
    arguments: Value,
) -> Result<Value, HostToolError> {
    // The dispatch consumes only the REAL unforgeable proof: the kernel
    // executor's consumed command must bind exactly the prepared effect's
    // admitted contract and version, whatever contract dispatched it.
    let contract = effect.contract();
    if consumed.capability_id() != &contract.id || consumed.capability_version() != contract.version
    {
        return Err(HostToolError::Catalog {
            detail: format!(
                "the consumed host command binds {} v{}, not the prepared effect's \
                 admitted contract {} v{}",
                consumed.capability_id(),
                consumed.capability_version(),
                contract.id,
                contract.version
            ),
        });
    }
    let Some(target) = contract.delegate_to.clone() else {
        return Err(HostToolError::Catalog {
            detail: format!(
                "the admitted contract {} declares no delegation target and cannot \
                 dispatch a seat ask",
                contract.id
            ),
        });
    };
    let injected = arguments
        .get(CapabilityContract::DELEGATION_TARGET_ARGUMENT)
        .and_then(Value::as_str)
        .ok_or_else(|| HostToolError::Catalog {
            detail: format!(
                "the host-injected {} argument is missing; the dispatch never passed \
                 the governed preparation",
                CapabilityContract::DELEGATION_TARGET_ARGUMENT
            ),
        })?;
    if injected != target.as_str() {
        return Err(HostToolError::Catalog {
            detail: format!(
                "the approved arguments name delegation target {injected}, but the \
                 admitted contract {} now delegates to {target}",
                contract.id
            ),
        });
    }
    // Only an R3 contract may dispatch a delegation.
    if !matches!(contract.effect_class, odin_domain::EffectClass::R3) {
        return Err(HostToolError::Catalog {
            detail: format!(
                "the admitted contract {} is not an R3 effect; seat delegation dispatches \
                 only through R3 contracts",
                contract.id
            ),
        });
    }
    if is_conversation_seat(runtime, &target) {
        return escalate(runtime, &target, &scope, &arguments);
    }
    // Reuse preflight preparation; consumed-command and R3 checks require the execution permit.
    let prepared = prepare_ask(runtime, Some(&target), &scope, &arguments)?;
    // The optional wait can never outrun the prepared operation's own
    // deadline: the effective wait is the requested bound clamped to the
    // time the permit still grants this operation. An omitted wait defaults
    // to the caller seat's `limits.inline_seconds`: a short ask answers in
    // this turn, a long one reports by wake.
    let requested_wait = arguments
        .get("wait_seconds")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| {
            u64::from(super::jobs::seat_inline_seconds(
                runtime,
                &prepared.caller_seat,
            ))
        });
    let wait_deadline = std::time::Instant::now() + Duration::from_secs(requested_wait);
    let target_label = prepared.target.to_string();
    match prepared.delegator.ask(&crate::delegation::SeatAskRequest {
        session: prepared.session.clone(),
        run: prepared.run.clone(),
        caller_seat: prepared.caller_seat.clone(),
        caller_lane: prepared.caller_lane.clone(),
        project: prepared.project.clone(),
        prompt: prepared.prompt.clone(),
        title: Some(prepared.title.clone()),
        target: prepared.target.clone(),
        launch: prepared.launch.clone(),
    }) {
        crate::delegation::SeatAskOutcome::Accepted(accepted) => {
            // The receipt names the admitted contract's exact declared
            // target — a bounded string carried by the admitted contract,
            // never an identity constant.
            let mut receipt = json!({
                "status": "recorded",
                "ask_id": accepted.command_id,
                "session": accepted.child_session,
                "child_run": accepted.child_run,
                "target_seat": target_label,
                "provider": accepted.provider,
                "model": accepted.model,
                "plan_accepted": accepted.plan_accepted,
                "prompt_bytes": accepted.prompt_bytes,
            });
            let wait = wait_deadline
                .saturating_duration_since(std::time::Instant::now())
                .min(Duration::from_millis(
                    effect
                        .expires_at_ms()
                        .saturating_sub(unix_ms(OffsetDateTime::now_utc())),
                ));
            if !wait.is_zero() {
                match prepared.delegator.await_answer(
                    &prepared.caller_seat,
                    &prepared.session,
                    &accepted.child_session,
                    wait,
                ) {
                    Ok(report) => {
                        if let Some(turn) = &report.latest_settled_turn {
                            receipt["status"] = json!("settled");
                            receipt["answer_key"] = json!(turn.key);
                            receipt["failed"] = json!(turn.failed);
                        }
                        receipt["phase"] =
                            serde_json::to_value(report.phase).unwrap_or(Value::Null);
                        receipt["child_state"] = match &report.state {
                            Some(state) => json!(state),
                            None => Value::Null,
                        };
                        receipt["active"] = json!(report.active);
                        // The authorized child's OWN last observed human
                        // answer, relayed verbatim from the governed
                        // task.read truth — never a parent-side summary
                        // and never another session's text. `null` is
                        // honest absence: no answer was observed yet.
                        receipt["answer"] = if report.latest_settled_turn.is_some() {
                            report
                                .answer
                                .as_ref()
                                .map_or(Value::Null, |text| json!(text))
                        } else {
                            Value::Null
                        };
                    }
                    Err(failure) => {
                        receipt["await_error"] =
                            json!(format!("{}: {}", failure.kind, failure.detail));
                    }
                }
            }
            if receipt["status"] == "recorded" {
                receipt["next"] = json!(RECORDED_ASK_NEXT);
            }
            Ok(receipt)
        }
        crate::delegation::SeatAskOutcome::Uncertain { kind, detail } => {
            Err(HostToolError::Uncertain {
                tool: TOOL,
                detail: format!("{kind}: {detail}"),
            })
        }
        crate::delegation::SeatAskOutcome::Rejected { kind, detail } => {
            Err(HostToolError::Delegation {
                tool: TOOL,
                detail: format!("{kind}: {detail}"),
            })
        }
    }
}

impl HermesRuntime {
    /// Acknowledge only a seat-ask receipt the transport has actually delivered inline.
    /// Merely constructing a receipt must leave the ordinary answer report available.
    pub fn acknowledge_inline_delegation(&self, receipt: &Value) -> Result<(), String> {
        if receipt.get("status").and_then(Value::as_str) != Some("settled") {
            return Ok(());
        }
        let (Some(child), Some(key)) = (
            receipt.get("session").and_then(Value::as_str),
            receipt.get("answer_key").and_then(Value::as_str),
        ) else {
            return Ok(());
        };
        if let Some(delegator) = &self.delegator {
            delegator.acknowledge_inline_answer(child, key)?;
        }
        self.schedule
            .acknowledge_wake_once(
                &super::reminders::child_turn_wake_id(child, key),
                jiff::Timestamp::now(),
            )
            .map(|_| ())
    }
}

/// Checks shared preparation and the declared terminal's readiness before approval,
/// without creating a link, token or child. Execution rechecks after obtaining its permit.
fn seat_ask_preflight(
    runtime: &Arc<HermesRuntime>,
    declared_target: Option<odin_domain::SeatId>,
    scope: &Scope,
    arguments: &Value,
) -> Result<(), HostToolError> {
    let target = match &declared_target {
        Some(target) => Some(target.clone()),
        None => arguments
            .get(CapabilityContract::DELEGATION_TARGET_ARGUMENT)
            .and_then(Value::as_str)
            .and_then(|seat| odin_domain::SeatId::new(seat).ok()),
    };
    if target
        .as_ref()
        .is_some_and(|target| is_conversation_seat(runtime, target))
    {
        // Escalation creates no child, so only argument validation is needed.
        subject_and_question(arguments)?;
        return Ok(());
    }
    let prepared = prepare_ask(runtime, declared_target.as_ref(), scope, arguments)?;
    prepared
        .delegator
        .preflight(&crate::delegation::SeatAskRequest {
            session: prepared.session,
            run: prepared.run,
            caller_seat: prepared.caller_seat,
            caller_lane: prepared.caller_lane,
            project: prepared.project,
            prompt: prepared.prompt,
            title: Some(prepared.title),
            target: prepared.target,
            launch: prepared.launch,
        })
        .map_err(|failure| HostToolError::Delegation {
            tool: TOOL,
            detail: format!("{}: {}", failure.kind, failure.detail),
        })
}

// Project bindings can change while a session runs, so they are a hint rather than an enum.
fn seat_ask_parameters(
    bound_projects: BTreeSet<String>,
    harness_launches: &[String],
    escalation: bool,
) -> Value {
    let mut parameters = capability_parameters!("seat.ask");
    if escalation {
        // An escalation concerns the asker's own project (its scope) and
        // opens no worker.
        if let Some(properties) = parameters["properties"].as_object_mut() {
            properties.remove("project");
            properties.remove("provider");
            properties.remove("model");
        }
        return parameters;
    }
    if let Some(Value::Array(required)) = parameters.get_mut("required") {
        required.push(json!("project"));
    }
    let bound_hint = if bound_projects.is_empty() {
        "none are bound to this target now".to_owned()
    } else {
        bound_projects
            .iter()
            .cloned()
            .collect::<Vec<String>>()
            .join(", ")
    };
    if !bound_projects.is_empty() {
        // A near-miss project resolves at the dispatch seam against the
        // same declaration this hint names.
        parameters = odin_omp::host_tools::schema_compat::resolve_ids(
            parameters,
            "/properties/project",
            bound_projects.iter().cloned(),
        );
    }
    if let Some(Value::String(description)) =
        parameters.pointer_mut("/properties/project/description")
    {
        description.push_str(&format!(
            " Currently bound projects: {bound_hint}. New bindings become available after \
             the daemon reloads."
        ));
    }
    if !harness_launches.is_empty() {
        if let Some(Value::String(description)) =
            parameters.pointer_mut("/properties/provider/description")
        {
            description.push_str(&format!(
                " Other declared harness/environment pairs: {}.",
                harness_launches.join("; ")
            ));
        }
    }
    parameters
}

pub(super) fn seat_ask_model_tool(
    runtime: &Arc<HermesRuntime>,
    contract: &CapabilityContract,
) -> Arc<dyn HostTool> {
    let target = contract
        .delegate_to
        .clone()
        .expect("the caller filters contracts without a declared target");
    // The model-facing project hint IS the deployment declaration: the
    // projects the daemon's configured lane bindings bind to this target
    // seat, named in the description. A target with no binding names none
    // and refuses every project typed at dispatch, never guessed.
    let bound_projects: BTreeSet<String> = runtime
        .seat_bound_projects
        .get(&target)
        .map(|projects| {
            projects
                .iter()
                .map(|project| project.as_str().to_owned())
                .collect()
        })
        .unwrap_or_default();
    let escalation = is_conversation_seat(runtime, &target);
    let harness_launches = runtime
        .model_launches()
        .map(|declared| declared.harness_launches(&target).to_vec())
        .unwrap_or_default();
    let runtime = Arc::clone(runtime);
    let gate_runtime = Arc::clone(&runtime);
    let consumed = Box::new(
        move |effect: &odin_kernel::operation::PreparedEffect,
              consumed: &odin_omp::host_tools::ConsumedHostCommand,
              scope: Scope,
              arguments: Value| {
            seat_ask_dispatch(&runtime, effect, consumed, scope, arguments)
        },
    );
    // The declared-readiness gate binds the admitted contract's exact
    // declared target — never an argument-supplied seat — and observes the
    // governed owner's readiness (the exact terminal surface the child
    // open will verify) before any approval row exists.
    let gate_target = target.clone();
    let preflight = Box::new(
        move |scope: &Scope, arguments: &Value| -> Result<(), HostToolError> {
            seat_ask_preflight(&gate_runtime, Some(gate_target.clone()), scope, arguments)
        },
    );
    let parameters = if escalation {
        seat_ask_parameters(BTreeSet::new(), &[], true)
    } else {
        seat_ask_parameters(bound_projects, &harness_launches, false)
    };
    Arc::new(
        CapabilityTool::approved_generic(
            RpcHostToolDefinition {
                // The declaration owns its surface metadata: the admitted
                // contract's tool name and description, never a compiled
                // literal, and never leaked — the wrapper clones them.
                name: contract.tool_name.as_str().to_owned().into(),
                label: contract.tool_name.as_str().to_owned().into(),
                description: contract.description.clone().into(),
                parameters: odin_omp::host_tools::schema_compat::model_parameters(&parameters),
                hidden: false,
                load_mode: odin_omp::host_tools::ToolLoadMode::Discoverable,
            },
            consumed,
            preflight,
        )
        .with_scoped_parameters(move |_scope| parameters.clone()),
    )
}

/// The internal owner of the compiled `seat_ask` handler binding: the one
/// generic primitive every admitted delegation contract resolves its
/// handler through. Hidden — the model-facing surfaces are the generated
/// per-contract tools, never this binding.
pub(super) fn seat_ask_binding(runtime: &Arc<HermesRuntime>) -> Arc<dyn HostTool> {
    let runtime = Arc::clone(runtime);
    let gate_runtime = Arc::clone(&runtime);
    let consumed = Box::new(
        move |effect: &odin_kernel::operation::PreparedEffect,
              consumed: &odin_omp::host_tools::ConsumedHostCommand,
              scope: Scope,
              arguments: Value| {
            seat_ask_dispatch(&runtime, effect, consumed, scope, arguments)
        },
    );
    // The generic binding is contract-agnostic, so its gate resolves the
    // target from the host-injected `CapabilityContract::DELEGATION_TARGET_ARGUMENT`
    // the trusted dispatch derives from the admitted contract before the
    // approval hash — never from a model-named seat.
    let preflight = Box::new(
        move |scope: &Scope, arguments: &Value| -> Result<(), HostToolError> {
            seat_ask_preflight(&gate_runtime, None, scope, arguments)
        },
    );
    Arc::new(CapabilityTool::approved_generic(
        RpcHostToolDefinition {
            name: TOOL.into(),
            label: "Seat delegation primitive".into(),
            description:
                "Internal generic seat-delegation handler: the dispatch target comes only \
             from the admitted contract's declared delegate_to, guarded by the \
             kernel-consumed proof. Never listed as a model surface."
                    .into(),
            parameters: seat_ask_parameters(BTreeSet::new(), &[], false),
            hidden: true,
            load_mode: odin_omp::host_tools::ToolLoadMode::Discoverable,
        },
        consumed,
        preflight,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two sessions of one seat asking the same subject make one wake; the
    /// second worker is told the first ask holds it.
    #[test]
    fn the_same_subject_from_two_sessions_is_asked_once() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = HermesRuntime::open(
            crate::config::HermesSettings::new(
                dir.path().join("state"),
                None,
                None,
                None,
                Vec::new(),
            )
            .unwrap(),
            crate::runtime::HermesLedgers {
                conversation: odin_ledger::Ledger::open_in_memory().unwrap(),
                adapter: Arc::new(parking_lot::Mutex::new(
                    odin_ledger::Ledger::open_in_memory().unwrap(),
                )),
                purchase: Arc::new(std::sync::Mutex::new(
                    odin_ledger::Ledger::open_in_memory().unwrap(),
                )),
            },
            &std::collections::BTreeMap::new(),
            None,
            8_192,
            std::collections::BTreeMap::new(),
            None,
        )
        .unwrap();
        let ask = |session: &str, question: &str| {
            let scope = Scope {
                seat: Some(odin_domain::SeatId::new("kubert").unwrap()),
                session: Some(odin_domain::SessionId::new(session).unwrap()),
                ..Scope::default()
            };
            let arguments = json!({ "subject": "Pod 7 hinge", "question": question });
            escalate(
                &runtime,
                &odin_domain::SeatId::new("sinmara").unwrap(),
                &scope,
                &arguments,
            )
            .unwrap()
        };
        let first = ask("sess-a", "may I restart it?");
        assert_eq!(first["status"], "escalated");
        let second = ask("sess-b", "may I restart it?");
        assert_eq!(second["status"], "already_asked");
        assert_eq!(second["ask_id"], first["ask_id"]);
    }
}
