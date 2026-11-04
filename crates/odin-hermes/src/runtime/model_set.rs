//! Approved model switching and persistent seat launch choices.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use odin_domain::huginn::{
    CommandReceipt, LiveSessionId, LiveSessionSummary, ModelName, ProviderName, SessionEpoch,
};
use odin_domain::{CommandId, SeatId};
use odin_omp::capability_parameters;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition};
use serde_json::{json, Value};

use super::models::local_family;
use super::tools::{parse_string, CapabilityTool};
use super::HermesRuntime;

pub const MODEL_SET_CAPABILITY: &str = "seat.model.set";

pub const MODEL_SET_TOOL: &str = "seat_model_set";

#[derive(Clone, Debug, Default)]
pub struct ModelLaunchDeclaration {
    launches: BTreeMap<SeatId, Vec<(ProviderName, ModelName)>>,
    /// Non-OMP launches formatted as provider/model = harness on environment.
    harness_launches: BTreeMap<SeatId, Vec<String>>,
}

impl ModelLaunchDeclaration {
    pub fn from_bindings<'a>(
        bindings: impl IntoIterator<Item = &'a odin_omp::live::supervisor::LiveSeatBinding>,
    ) -> Self {
        let mut launches = BTreeMap::new();
        let mut harness_launches = BTreeMap::new();
        for binding in bindings {
            let options = binding
                .launch_options
                .iter()
                .map(|option| (option.provider.clone(), option.model.clone()))
                .collect::<Vec<_>>();
            launches.insert(binding.seat_id.clone(), options);
            let harnessed: Vec<String> = binding
                .launch_options
                .iter()
                .filter_map(|option| {
                    let bound = option.harness.as_ref()?;
                    Some(format!(
                        "{}/{} = {} on {}",
                        option.provider.as_str(),
                        option.model.as_str(),
                        bound.harness,
                        bound.environment
                    ))
                })
                .collect();
            if !harnessed.is_empty() {
                harness_launches.insert(binding.seat_id.clone(), harnessed);
            }
        }
        Self {
            launches,
            harness_launches,
        }
    }

    pub fn harness_launches(&self, seat: &SeatId) -> &[String] {
        self.harness_launches.get(seat).map_or(&[], Vec::as_slice)
    }

    pub fn declared(&self, seat: &SeatId, provider: &ProviderName, model: &ModelName) -> bool {
        self.launches
            .get(seat)
            .is_some_and(|options| options.iter().any(|(p, m)| p == provider && m == model))
    }

    pub fn iter(&self) -> impl Iterator<Item = (&SeatId, &[(ProviderName, ModelName)])> {
        self.launches
            .iter()
            .map(|(seat, options)| (seat, options.as_slice()))
    }

    /// Capability seat tags authorize the caller, not the target seat.
    pub fn declared_tuples(&self) -> BTreeSet<(String, String, String)> {
        self.launches
            .iter()
            .flat_map(|(seat, options)| {
                options.iter().map(move |(provider, model)| {
                    (
                        seat.as_str().to_owned(),
                        provider.as_str().to_owned(),
                        model.as_str().to_owned(),
                    )
                })
            })
            .collect()
    }
}

/// Whether dispatch was refused or its outcome remains unknown.
#[derive(Debug)]
pub enum ModelRouteError {
    Refused(String),
    Uncertain(String),
}

#[derive(Clone, Debug, Default)]
pub struct SeatSessionSurvey {
    pub declared_vehicle: Option<LiveSessionId>,
    pub live_sessions: Vec<LiveSessionSummary>,
}

/// The consumed operation id also deduplicates the live command.
#[derive(Clone, Debug)]
pub struct ModelSetCommand {
    pub command_id: CommandId,
    pub session_id: odin_domain::huginn::LiveSessionId,
    pub expected_epoch: SessionEpoch,
    pub provider: ProviderName,
    pub model: ModelName,
}

pub trait ModelCommandRoute: Send + Sync {
    fn survey_seat(&self, seat: &SeatId) -> Result<SeatSessionSurvey, ModelRouteError>;

    fn command_set_model(
        &self,
        command: ModelSetCommand,
    ) -> Result<CommandReceipt, ModelRouteError>;

    /// Declare the pair as the seat's model in the registry (first in its
    /// `models`), committed as `by`; answers what was declared. Routes
    /// without an authoring repository refuse.
    fn persist_choice(
        &self,
        seat: &SeatId,
        provider: &ProviderName,
        model: &ModelName,
        by: &str,
    ) -> Result<String, ModelRouteError> {
        let _ = (provider, model, by);
        Err(ModelRouteError::Refused(format!(
            "seat {seat}'s model cannot be declared: this runtime has no authoring repository"
        )))
    }
}

/// Starting, aborting, and terminal sessions cannot accept SetModel.
fn is_switchable(summary: &LiveSessionSummary) -> bool {
    use odin_domain::huginn::LiveSessionState;
    matches!(
        summary.state,
        LiveSessionState::Idle
            | LiveSessionState::Running
            | LiveSessionState::RequiresAction
            | LiveSessionState::Detached
    )
}

/// A declared conversation vehicle takes precedence over other live sessions.
pub fn select_target_session<'a>(
    survey: &'a SeatSessionSurvey,
    seat: &SeatId,
) -> Result<&'a LiveSessionSummary, ModelRouteError> {
    let mut live = survey
        .live_sessions
        .iter()
        .filter(|summary| summary.seat_id == *seat && is_switchable(summary));
    if let Some(vehicle) = &survey.declared_vehicle {
        return live
            .find(|summary| summary.session_id == *vehicle)
            .ok_or_else(|| {
                ModelRouteError::Refused(format!(
                    "seat {seat}'s declared vehicle is not live; no other session was selected"
                ))
            });
    }
    let first = live.next().ok_or_else(|| {
        ModelRouteError::Refused(format!(
            "seat {seat} has no live session to switch; open or recover one first"
        ))
    })?;
    if live.next().is_some() {
        return Err(ModelRouteError::Refused(format!(
            "seat {seat} has multiple live sessions and no declared vehicle; the target assistant is ambiguous"
        )));
    }
    Ok(first)
}

struct PreparedSwitch {
    route: Arc<dyn ModelCommandRoute>,
    seat: SeatId,
    provider: ProviderName,
    model: ModelName,
}

/// Validate the bound caller and exact declared target before any effect.
fn prepare_switch(
    runtime: &Arc<HermesRuntime>,
    scope: &odin_domain::Scope,
    arguments: &Value,
) -> Result<PreparedSwitch, HostToolError> {
    if scope.seat.is_none() {
        return Err(HostToolError::Scope {
            tool: MODEL_SET_TOOL,
            reason: "a bound caller seat is required",
        });
    }
    prepare_pair(runtime, arguments)
}

/// Validate the exact declared target before any effect.
fn prepare_pair(
    runtime: &HermesRuntime,
    arguments: &Value,
) -> Result<PreparedSwitch, HostToolError> {
    const TOOL: &str = MODEL_SET_TOOL;
    let route = runtime
        .model_route()
        .ok_or_else(|| HostToolError::Unavailable {
            tool: TOOL,
            reason: "the daemon has not bound the live model command route; no assistant can \
                 be switched"
                .to_owned(),
        })?;
    let seat_raw = parse_string(arguments, "seat", 128)?;
    let provider_raw = parse_string(arguments, "provider", 128)?;
    let model_raw = parse_string(arguments, "model", 256)?;
    let seat = SeatId::new(&seat_raw).map_err(|error| HostToolError::Arguments {
        tool: TOOL,
        detail: format!("invalid seat id: {error}"),
    })?;
    let provider = ProviderName::new(&provider_raw).map_err(|error| HostToolError::Arguments {
        tool: TOOL,
        detail: format!("invalid provider name: {error}"),
    })?;
    let model = ModelName::new(&model_raw).map_err(|error| HostToolError::Arguments {
        tool: TOOL,
        detail: format!("invalid model name: {error}"),
    })?;
    // Use the same launch options that session admission enforces.
    let declaration = runtime
        .model_launches()
        .ok_or_else(|| HostToolError::Unavailable {
            tool: TOOL,
            reason: "the daemon pinned no live seat launch declaration; no pair is \
                     switchable"
                .to_owned(),
        })?;
    if !declaration.declared(&seat, &provider, &model)
        && !family_member_declared(&declaration, &seat, &provider, &model)?
    {
        let declared = declaration
            .iter()
            .find(|(declared_seat, _)| *declared_seat == &seat)
            .map(|(_, options)| {
                options
                    .iter()
                    .map(|(provider, model)| format!("{provider}/{model}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_else(|| "none declared".to_owned());
        return Err(HostToolError::Arguments {
            tool: TOOL,
            detail: format!(
                "{provider}/{model} is not a declared launch of seat {seat}; the pinned \
                 declaration offers: {declared}"
            ),
        });
    }
    Ok(PreparedSwitch {
        route,
        seat,
        provider,
        model,
    })
}

/// Whether a local family member is a launch of the seat: the seat lists its family
/// (`gateway/local/*`) and the member is on the local list now.
fn family_member_declared(
    declaration: &ModelLaunchDeclaration,
    seat: &SeatId,
    provider: &ProviderName,
    model: &ModelName,
) -> Result<bool, HostToolError> {
    let Some((family, member)) = model.as_str().split_once('/') else {
        return Ok(false);
    };
    let family_wildcard =
        ModelName::new(format!("{family}/*")).map_err(|error| HostToolError::Arguments {
            tool: MODEL_SET_TOOL,
            detail: format!("invalid model name: {error}"),
        })?;
    if !declaration.declared(seat, provider, &family_wildcard) {
        return Ok(false);
    }
    let members = local_family().map_err(|reason| HostToolError::Unavailable {
        tool: MODEL_SET_TOOL,
        reason,
    })?;
    Ok(members.iter().any(|candidate| candidate.id == member))
}

fn route_failure(error: ModelRouteError) -> HostToolError {
    match error {
        ModelRouteError::Refused(detail) => HostToolError::Arguments {
            tool: MODEL_SET_TOOL,
            detail,
        },
        ModelRouteError::Uncertain(detail) => HostToolError::Uncertain {
            tool: MODEL_SET_TOOL,
            detail,
        },
    }
}

fn project_receipt(
    prepared: &PreparedSwitch,
    declared: &str,
    target: &LiveSessionSummary,
    receipt: CommandReceipt,
) -> Result<Value, HostToolError> {
    match receipt {
        CommandReceipt::Accepted { .. } | CommandReceipt::Duplicate { .. } => Ok(json!({
            "seat": prepared.seat.as_str(),
            "provider": prepared.provider.as_str(),
            "model": prepared.model.as_str(),
            "declared": declared,
            "sessionId": target.session_id.to_string(),
            "receipt": receipt,
        })),
        CommandReceipt::Rejected { reason, .. } => Err(HostToolError::Arguments {
            tool: MODEL_SET_TOOL,
            detail: format!(
                "the live session rejected the model switch, so nothing was changed: \
                 {reason}"
            ),
        }),
    }
}

fn seat_model_set_dispatch(
    runtime: &Arc<HermesRuntime>,
    consumed: &odin_omp::host_tools::ConsumedHostCommand,
    scope: odin_domain::Scope,
    arguments: Value,
) -> Result<Value, HostToolError> {
    let prepared = prepare_switch(runtime, &scope, &arguments)?;
    let by = scope
        .seat
        .as_ref()
        .map_or_else(|| "by seat".to_owned(), |seat| format!("by seat {seat}"));
    declare_and_switch(&prepared, consumed.command_id().clone(), &by)
}

/// The one model change, for the tool and for Huginn: declare the pair in
/// the registry first (so it also holds when no live session can switch),
/// then switch the seat's live session under `command_id`.
fn declare_and_switch(
    prepared: &PreparedSwitch,
    command_id: odin_domain::CommandId,
    by: &str,
) -> Result<Value, HostToolError> {
    let declared = prepared
        .route
        .persist_choice(&prepared.seat, &prepared.provider, &prepared.model, by)
        .map_err(route_failure)?;
    let persisted_only = |reason: String| {
        json!({
            "seat": prepared.seat.as_str(),
            "provider": prepared.provider.as_str(),
            "model": prepared.model.as_str(),
            "declared": declared,
            "persisted": true,
            "liveSession": reason,
        })
    };
    let survey = prepared
        .route
        .survey_seat(&prepared.seat)
        .map_err(route_failure)?;
    let target = match select_target_session(&survey, &prepared.seat) {
        Ok(target) => target,
        Err(ModelRouteError::Refused(reason) | ModelRouteError::Uncertain(reason)) => {
            return Ok(persisted_only(format!(
                "{reason}; the seat's next session opens with this model"
            )))
        }
    };
    // Reuse the operation id for live-plane deduplication.
    let receipt = prepared
        .route
        .command_set_model(ModelSetCommand {
            command_id,
            session_id: target.session_id,
            expected_epoch: target.epoch,
            provider: prepared.provider.clone(),
            model: prepared.model.clone(),
        })
        .map_err(route_failure)?;
    match project_receipt(prepared, &declared, target, receipt) {
        // A rejected live switch does not undo the persisted choice.
        Err(HostToolError::Arguments { detail, .. }) => Ok(persisted_only(detail)),
        other => other,
    }
}

impl HermesRuntime {
    /// the owner's own model change from a paired device (Huginn `SeatModelSet`):
    /// the same declared pair check, registry declaration and live switch as
    /// `seat.model.set`, without an approval round — he is the operator.
    pub fn declare_seat_model(
        &self,
        command_id: odin_domain::CommandId,
        seat: &str,
        provider: &str,
        model: &str,
        by: &str,
    ) -> Result<Value, String> {
        let arguments = json!({ "seat": seat, "provider": provider, "model": model });
        prepare_pair(self, &arguments)
            .and_then(|prepared| declare_and_switch(&prepared, command_id, by))
            .map_err(|error| error.to_string())
    }
}

fn seat_model_set_preflight(
    runtime: &Arc<HermesRuntime>,
    scope: &odin_domain::Scope,
    arguments: &Value,
) -> Result<(), HostToolError> {
    prepare_switch(runtime, scope, arguments)?;
    Ok(())
}

fn seat_model_set_parameters(tuples: &BTreeSet<(String, String, String)>) -> Value {
    let branches: Vec<Value> = tuples
        .iter()
        .map(|(seat, provider, model)| {
            json!({
                "properties": {
                    "seat": { "const": seat },
                    "provider": { "const": provider },
                    "model": { "const": model },
                },
                "required": ["seat", "provider", "model"],
            })
        })
        .collect();
    let mut schema = capability_parameters!("seat.model.set");
    if branches.is_empty() {
        schema["not"] = json!({});
    } else {
        schema["allOf"] = json!([{ "oneOf": branches }]);
    }
    schema
}

pub(super) fn seat_model_set_tool(runtime: &Arc<HermesRuntime>) -> Option<Arc<dyn HostTool>> {
    let contract = runtime
        .contracts
        .get(&odin_domain::CapabilityId::new(MODEL_SET_CAPABILITY).ok()?)?;
    let tuples = runtime
        .model_launches()
        .map(|declaration| declaration.declared_tuples())
        .unwrap_or_default();
    let mut description = contract.description.clone();
    description.push_str(". Allowed provider/model choices by seat:");
    for (seat, provider, model) in &tuples {
        description.push('\n');
        description.push_str(seat);
        description.push_str(": ");
        description.push_str(provider);
        description.push('/');
        description.push_str(model);
    }
    if tuples.is_empty() {
        description.push_str(" none are bound on this host.");
    }
    let dispatch_runtime = Arc::clone(runtime);
    let consumed = Box::new(
        move |_effect: &odin_kernel::operation::PreparedEffect,
              consumed: &odin_omp::host_tools::ConsumedHostCommand,
              scope: odin_domain::Scope,
              arguments: Value| {
            seat_model_set_dispatch(&dispatch_runtime, consumed, scope, arguments)
        },
    );
    let gate_runtime = Arc::clone(runtime);
    let preflight = Box::new(
        move |scope: &odin_domain::Scope, arguments: &Value| -> Result<(), HostToolError> {
            seat_model_set_preflight(&gate_runtime, scope, arguments)
        },
    );
    Some(Arc::new(CapabilityTool::approved(
        RpcHostToolDefinition {
            name: contract.tool_name.as_str().to_owned().into(),
            label: contract.tool_name.as_str().to_owned().into(),
            description: description.into(),
            parameters: seat_model_set_parameters(&tuples),
            hidden: false,
            load_mode: odin_omp::host_tools::ToolLoadMode::Discoverable,
        },
        MODEL_SET_CAPABILITY,
        consumed,
        preflight,
    )))
}
