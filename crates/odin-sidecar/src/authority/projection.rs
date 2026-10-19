//! Load catalog, schema, and policy inputs once; authorization remains a kernel decision.

use super::PROJECTION_SCHEMA;
use crate::{SidecarError, SidecarErrorCode};
use odin_domain::knowledge::ToolSchema;
use odin_domain::status::EffectClass;
use odin_domain::{CapabilityId, Digest, PlanId, SessionId};
use odin_kernel::policy::{PlanGate, PolicyContext};
use odin_kernel::token::ExpectedBindings;
use odin_kernel::{
    AdmittedCapability, CapabilityContract, HandlerBinding, KernelError, OperationCatalog,
};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

pub struct TransportProjection {
    snapshot_revision: i64,
    snapshot_digest: Digest,
    pub(super) context: PolicyContext,
    pub(super) contracts: BTreeMap<CapabilityId, CapabilityContract>,
    schemas: BTreeMap<String, ToolSchema>,
    builtins: BTreeSet<String>,
    pub(super) plan_gate: PlanGate,
    pub(super) plan_id: Option<PlanId>,
    pub(super) expected: ExpectedBindingsValue,
}

pub(super) struct ExpectedBindingsValue {
    seat: odin_domain::SeatId,
    slice: odin_domain::SliceId,
    lane: odin_domain::LaneId,
    session: SessionId,
    seat_revision: Digest,
    slice_revision: Digest,
    capability_policy_digest: Digest,
    context_policy_digest: Digest,
}

impl ExpectedBindingsValue {
    pub(super) fn bindings(&self) -> odin_kernel::token::ExpectedBindings<'_> {
        ExpectedBindings {
            seat: &self.seat,
            slice: &self.slice,
            lane: &self.lane,
            session: &self.session,
            seat_revision: self.seat_revision,
            slice_revision: self.slice_revision,
            capability_policy_digest: self.capability_policy_digest,
            context_policy_digest: self.context_policy_digest,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectionDto {
    schema: String,
    snapshot_revision: i64,
    snapshot_digest: String,
    expected: ExpectedDto,
    plan: PlanDto,
    policy: PolicyDto,
    capabilities: Vec<CapabilityDto>,
    schemas: BTreeMap<String, serde_json::Value>,
    builtins: BTreeSet<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedDto {
    seat: String,
    slice: String,
    lane: String,
    session: String,
    seat_revision: String,
    slice_revision: String,
    capability_policy_digest: String,
    context_policy_digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanDto {
    gate: String,
    plan_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDto {
    seat_tool_refs: BTreeSet<String>,
    slice_capabilities: BTreeSet<String>,
    project_capabilities: BTreeSet<String>,
    lane_capabilities: BTreeSet<String>,
    #[serde(default)]
    denied_capabilities: BTreeSet<String>,
    #[serde(default)]
    denied_tools: BTreeSet<String>,
    #[serde(default)]
    seat_categories: BTreeSet<String>,
    #[serde(default)]
    adapter_health: BTreeMap<String, bool>,
    #[serde(default)]
    resource_constraints: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    seat_hints: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityDto {
    id: String,
    version: u16,
    tool_name: String,
    description: String,
    handler: HandlerDto,
    evidence_extractor: HandlerDto,
    input_schema_ref: String,
    output_schema_ref: String,
    effect_class: String,
    seat_tags: BTreeSet<String>,
    timeout_seconds: u32,
    idempotency: String,
    retry_max_attempts: u8,
    approval: String,
    #[serde(default)]
    adapter: Option<String>,
    #[serde(default)]
    delegate_to: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum HandlerDto {
    Builtin {
        name: String,
    },
    Exec {
        executable: String,
        argv: Vec<String>,
    },
}

fn parse_digest(field: &str, value: &str) -> Result<Digest, SidecarError> {
    Digest::parse(value).map_err(|error| {
        SidecarError::new(
            SidecarErrorCode::State,
            format!("projection {field} is not a canonical digest: {error}"),
        )
    })
}

fn parse_id<T>(
    field: &str,
    value: &str,
    mint: impl Fn(&str) -> Result<T, String>,
) -> Result<T, SidecarError> {
    mint(value).map_err(|error| {
        SidecarError::new(
            SidecarErrorCode::State,
            format!("projection {field} {value:?} is malformed: {error}"),
        )
    })
}

fn parse_handler(
    field: &str,
    id: &str,
    handler: &HandlerDto,
) -> Result<HandlerBinding, SidecarError> {
    match handler {
        HandlerDto::Builtin { name } => Ok(HandlerBinding::Builtin { name: name.clone() }),
        HandlerDto::Exec { executable, argv } => {
            if !Path::new(executable).is_absolute() {
                return Err(SidecarError::new(
                    SidecarErrorCode::State,
                    format!("capability {id} {field} executable must be an absolute store path"),
                ));
            }
            Ok(HandlerBinding::Exec {
                executable: executable.clone(),
                argv: argv.clone(),
            })
        }
    }
}

fn parse_capability_ids(
    field: &str,
    values: &BTreeSet<String>,
) -> Result<BTreeSet<CapabilityId>, SidecarError> {
    values
        .iter()
        .map(|value| {
            parse_id(field, value, |v| {
                CapabilityId::parse(v).map_err(|error| error.to_string())
            })
        })
        .collect()
}

impl TransportProjection {
    pub const fn snapshot_revision(&self) -> i64 {
        self.snapshot_revision
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SidecarError> {
        let dto: ProjectionDto = serde_json::from_slice(bytes).map_err(|error| {
            SidecarError::new(
                SidecarErrorCode::State,
                format!("projection rejected: {error}"),
            )
        })?;
        if dto.schema != PROJECTION_SCHEMA {
            return Err(SidecarError::new(
                SidecarErrorCode::State,
                format!(
                    "projection schema {:?} is not {PROJECTION_SCHEMA}",
                    dto.schema
                ),
            ));
        }
        let expected = ExpectedBindingsValue {
            seat: parse_id("expected seat", &dto.expected.seat, |v| {
                odin_domain::SeatId::parse(v).map_err(|error| error.to_string())
            })?,
            slice: parse_id("expected slice", &dto.expected.slice, |v| {
                odin_domain::SliceId::parse(v).map_err(|error| error.to_string())
            })?,
            lane: parse_id("expected lane", &dto.expected.lane, |v| {
                odin_domain::LaneId::parse(v).map_err(|error| error.to_string())
            })?,
            session: parse_id("expected session", &dto.expected.session, |v| {
                SessionId::parse(v).map_err(|error| error.to_string())
            })?,
            seat_revision: parse_digest("expected seat_revision", &dto.expected.seat_revision)?,
            slice_revision: parse_digest("expected slice_revision", &dto.expected.slice_revision)?,
            capability_policy_digest: parse_digest(
                "expected capability_policy_digest",
                &dto.expected.capability_policy_digest,
            )?,
            context_policy_digest: parse_digest(
                "expected context_policy_digest",
                &dto.expected.context_policy_digest,
            )?,
        };

        let plan_gate = match dto.plan.gate.as_str() {
            "accepted" => PlanGate::Accepted,
            "draft" => PlanGate::Draft,
            "missing" => PlanGate::Missing,
            other => {
                return Err(SidecarError::new(
                    SidecarErrorCode::State,
                    format!("projection plan gate {other:?} is not one of accepted,draft,missing"),
                ));
            }
        };
        let plan_id = dto
            .plan
            .plan_id
            .as_deref()
            .map(|raw| {
                parse_id("plan id", raw, |v| {
                    PlanId::parse(v).map_err(|error| error.to_string())
                })
            })
            .transpose()?;

        let mut schemas = BTreeMap::new();
        for (reference, schema_json) in &dto.schemas {
            let schema = ToolSchema::from_value(schema_json.clone()).map_err(|error| {
                SidecarError::new(
                    SidecarErrorCode::State,
                    format!("projection schema {reference:?} is malformed: {error}"),
                )
            })?;
            schemas.insert(reference.clone(), schema);
        }

        let mut contracts = BTreeMap::new();
        for capability in &dto.capabilities {
            let id = parse_id("capability id", &capability.id, |v| {
                CapabilityId::parse(v).map_err(|error| error.to_string())
            })?;
            let effect_class = match capability.effect_class.as_str() {
                "R0" => EffectClass::R0,
                "R1" => EffectClass::R1,
                "R2" => EffectClass::R2,
                "R3" => EffectClass::R3,
                other => {
                    return Err(SidecarError::new(
                        SidecarErrorCode::State,
                        format!(
                            "capability {} effect class {other:?} is not one of R0,R1,R2,R3",
                            capability.id
                        ),
                    ));
                }
            };
            let idempotency = match capability.idempotency.as_str() {
                "pure" => odin_kernel::IdempotencyPolicy::Pure,
                "required" => odin_kernel::IdempotencyPolicy::Required,
                other => {
                    return Err(SidecarError::new(
                        SidecarErrorCode::State,
                        format!(
                            "capability {} idempotency {other:?} is not one of pure,required",
                            capability.id
                        ),
                    ));
                }
            };
            let approval = match capability.approval.as_str() {
                "none" => odin_kernel::ApprovalRequirement::None,
                "operator" => odin_kernel::ApprovalRequirement::Operator,
                other => {
                    return Err(SidecarError::new(
                        SidecarErrorCode::State,
                        format!(
                            "capability {} approval {other:?} is not one of none,operator",
                            capability.id
                        ),
                    ));
                }
            };
            let timeout_seconds = std::num::NonZeroU32::new(capability.timeout_seconds)
                .ok_or_else(|| {
                    SidecarError::new(
                        SidecarErrorCode::State,
                        format!(
                            "capability {} timeout_seconds must be positive",
                            capability.id
                        ),
                    )
                })?;
            let contract = CapabilityContract {
                id: id.clone(),
                delegate_to: capability
                    .delegate_to
                    .as_deref()
                    .map(|target| {
                        parse_id("delegate_to", target, |value| {
                            odin_domain::SeatId::new(value).map_err(|error| error.to_string())
                        })
                    })
                    .transpose()?,
                version: capability.version,
                tool_name: parse_id("tool_name", &capability.tool_name, |v| {
                    odin_domain::knowledge::ToolName::new(v).map_err(|error| error.to_string())
                })?,
                description: capability.description.clone(),
                handler: parse_handler("handler", &capability.id, &capability.handler)?,
                input_schema_ref: capability.input_schema_ref.clone(),
                output_schema_ref: capability.output_schema_ref.clone(),
                effect_class,
                seat_tags: capability.seat_tags.clone(),
                timeout_seconds,
                idempotency,
                retry: odin_kernel::RetryPolicy {
                    max_attempts: capability.retry_max_attempts,
                },
                approval,
                evidence_extractor: parse_handler(
                    "evidence_extractor",
                    &capability.id,
                    &capability.evidence_extractor,
                )?,
                adapter: capability.adapter.clone(),
                preview: None,
                batchable: false,
                batch: None,
            };
            contracts.insert(id, contract);
        }

        let mut resource_constraints = BTreeMap::new();
        for (capability, constraints) in &dto.policy.resource_constraints {
            let parsed: Vec<odin_domain::knowledge::ResourceConstraint> =
                serde_json::from_value(constraints.clone()).map_err(|error| {
                    SidecarError::new(
                        SidecarErrorCode::State,
                        format!(
                        "projection resource constraints for {capability:?} are malformed: {error}"
                    ),
                    )
                })?;
            let capability_id = parse_id("resource constraint capability", capability, |v| {
                CapabilityId::parse(v).map_err(|error| error.to_string())
            })?;
            resource_constraints.insert(capability_id, parsed);
        }

        let context = PolicyContext {
            seat_id: expected.seat.clone(),
            slice_id: expected.slice.clone(),
            lane_id: expected.lane.clone(),
            seat_revision: expected.seat_revision,
            slice_revision: expected.slice_revision,
            capability_policy_digest: expected.capability_policy_digest,
            seat_tool_refs: parse_capability_ids("seat_tool_refs", &dto.policy.seat_tool_refs)?,
            slice_capabilities: parse_capability_ids(
                "slice_capabilities",
                &dto.policy.slice_capabilities,
            )?,
            project_capabilities: parse_capability_ids(
                "project_capabilities",
                &dto.policy.project_capabilities,
            )?,
            lane_capabilities: parse_capability_ids(
                "lane_capabilities",
                &dto.policy.lane_capabilities,
            )?,
            denied_capabilities: parse_capability_ids(
                "denied_capabilities",
                &dto.policy.denied_capabilities,
            )?,
            denied_tools: dto
                .policy
                .denied_tools
                .iter()
                .map(|name| {
                    parse_id("denied tool", name, |v| {
                        odin_domain::knowledge::ToolName::new(v).map_err(|error| error.to_string())
                    })
                })
                .collect::<Result<BTreeSet<_>, _>>()?,
            seat_categories: dto.policy.seat_categories.clone(),
            adapter_health: odin_kernel::AdapterHealth::new(dto.policy.adapter_health.clone()),
            resource_constraints,
            seat_hints: dto
                .policy
                .seat_hints
                .iter()
                .map(|(capability, seat)| {
                    Ok((
                        parse_id("seat hint capability", capability, |v| {
                            CapabilityId::parse(v).map_err(|error| error.to_string())
                        })?,
                        parse_id("seat hint seat", seat, |v| {
                            odin_domain::SeatId::parse(v).map_err(|error| error.to_string())
                        })?,
                    ))
                })
                .collect::<Result<BTreeMap<_, _>, SidecarError>>()?,
        };

        Ok(Self {
            snapshot_revision: dto.snapshot_revision,
            snapshot_digest: parse_digest("snapshot_digest", &dto.snapshot_digest)?,
            context,
            contracts,
            schemas,
            builtins: dto.builtins,
            plan_gate,
            plan_id,
            expected,
        })
    }
}

pub(super) fn projection_catalog(
    projection: &Arc<TransportProjection>,
) -> Arc<dyn OperationCatalog> {
    Arc::new(ProjectionCatalog {
        projection: Arc::clone(projection),
    })
}

pub(super) fn projection_schemas(
    projection: &Arc<TransportProjection>,
) -> Arc<dyn odin_kernel::SchemaCatalog + Send + Sync> {
    Arc::new(ProjectionSchemas {
        projection: Arc::clone(projection),
    })
}

struct ProjectionCatalog {
    projection: Arc<TransportProjection>,
}

impl OperationCatalog for ProjectionCatalog {
    fn admitted(&self, capability: &CapabilityId) -> Option<AdmittedCapability> {
        let contract = self.projection.contracts.get(capability)?.clone();
        Some(AdmittedCapability {
            contract,
            snapshot_revision: self.projection.snapshot_revision,
            snapshot_digest: self.projection.snapshot_digest,
        })
    }

    fn resolves(&self, binding: &HandlerBinding) -> bool {
        match binding {
            HandlerBinding::Builtin { name } => self.projection.builtins.contains(name),
            HandlerBinding::Exec { executable, argv } => {
                Path::new(executable).is_absolute()
                    && argv.iter().all(|argument| !argument.is_empty())
            }
        }
    }
}

struct ProjectionSchemas {
    projection: Arc<TransportProjection>,
}

impl odin_kernel::SchemaCatalog for ProjectionSchemas {
    fn schema(&self, reference: &str) -> Result<ToolSchema, KernelError> {
        self.projection
            .schemas
            .get(reference)
            .cloned()
            .ok_or_else(|| KernelError::NotFound {
                kind: "capability input schema",
                id: reference.to_owned(),
            })
    }
}
