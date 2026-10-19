//! Fresh capability policy calculation and pre-handler authorization.

use std::collections::{BTreeMap, BTreeSet};

use odin_domain::knowledge::{CapabilityListing, ResourceConstraint, ToolName};
use odin_domain::{
    ApprovalStatus, CapabilityId, Digest, EffectClass, LaneId, PlanId, Scope, SeatId, SliceId,
};
use odin_ledger::approval::{Approval, ApprovalScope};
use odin_ledger::{Ledger, LedgerError};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::approval::{ApprovalCommand, ApprovalGate, ApprovalRedirect, ConsumeOutcome};
use crate::capability::{
    live_session, resolve_tool, timestamp, AdapterHealth, ApprovalRequirement,
    AuthorizationRejection, AuthorizedInvocation, CapabilityContract, SchemaCatalog,
    ToolInvocation,
};
use crate::error::KernelResult;
use crate::token::SeatAuthority;

/// Explicit allow sets prevent missing project or lane policy from becoming implicit permission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyContext {
    pub seat_id: SeatId,
    pub slice_id: SliceId,
    pub lane_id: LaneId,
    pub seat_revision: Digest,
    pub slice_revision: Digest,
    pub capability_policy_digest: Digest,
    pub seat_tool_refs: BTreeSet<CapabilityId>,
    pub slice_capabilities: BTreeSet<CapabilityId>,
    pub project_capabilities: BTreeSet<CapabilityId>,
    pub lane_capabilities: BTreeSet<CapabilityId>,
    pub denied_capabilities: BTreeSet<CapabilityId>,
    pub denied_tools: BTreeSet<ToolName>,
    pub seat_categories: BTreeSet<String>,
    pub adapter_health: AdapterHealth,
    pub resource_constraints: BTreeMap<CapabilityId, Vec<ResourceConstraint>>,
    pub seat_hints: BTreeMap<CapabilityId, SeatId>,
}

impl PolicyContext {
    #[must_use]
    pub fn is_bound_to(&self, authority: &SeatAuthority) -> bool {
        self.seat_id == *authority.seat()
            && self.slice_id == *authority.slice()
            && self.lane_id == *authority.lane()
            && self.seat_revision == authority.seat_revision()
            && self.slice_revision == authority.slice_revision()
            && self.capability_policy_digest == authority.capability_policy_digest()
    }

    #[must_use]
    pub fn wrong_seat_hint(&self, capability_id: &CapabilityId) -> Option<&SeatId> {
        self.seat_hints.get(capability_id)
    }

    #[inline]
    pub fn is_capability_effective(
        &self,
        capability_id: &CapabilityId,
        contracts: &BTreeMap<CapabilityId, CapabilityContract>,
    ) -> bool {
        if !self.seat_tool_refs.contains(capability_id) {
            return false;
        }
        if !self.slice_capabilities.contains(capability_id) {
            return false;
        }
        if !self.project_capabilities.contains(capability_id) {
            return false;
        }
        if !self.lane_capabilities.contains(capability_id) {
            return false;
        }
        if self.denied_capabilities.contains(capability_id) {
            return false;
        }

        let Some(contract) = contracts.get(capability_id) else {
            return false;
        };
        if self.denied_tools.contains(&contract.tool_name) {
            return false;
        }
        if !contract.seat_tags.contains("*")
            && contract.seat_tags.is_disjoint(&self.seat_categories)
        {
            return false;
        }
        self.adapter_health.is_healthy(contract.adapter.as_deref())
    }
}

/// Durable planning state checked before any side-effecting capability can be authorized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanGate {
    Missing,
    Draft,
    Accepted,
}

impl PlanGate {
    #[must_use]
    pub const fn permits_side_effect(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

/// Apply denials last so they override every allow set.
#[must_use]
pub fn effective(
    context: &PolicyContext,
    contracts: &BTreeMap<CapabilityId, CapabilityContract>,
) -> BTreeSet<CapabilityId> {
    context
        .seat_tool_refs
        .intersection(&context.slice_capabilities)
        .filter(|id| context.project_capabilities.contains(*id))
        .filter(|id| context.lane_capabilities.contains(*id))
        .filter_map(|id| contracts.get(id).map(|contract| (id, contract)))
        .filter(|(id, contract)| {
            !context.denied_capabilities.contains(*id)
                && !context.denied_tools.contains(&contract.tool_name)
        })
        .filter(|(_, contract)| {
            contract.seat_tags.contains("*")
                || !contract.seat_tags.is_disjoint(&context.seat_categories)
        })
        .filter(|(_, contract)| {
            context
                .adapter_health
                .is_healthy(contract.adapter.as_deref())
        })
        .map(|(id, _)| id.clone())
        .collect()
}

#[derive(Debug, Eq, PartialEq)]
pub enum AuthorizationOutcome {
    Authorized(Box<AuthorizedInvocation>),
    Rejected(AuthorizationRejection),
}

impl AuthorizationOutcome {
    fn rejected(reason: AuthorizationRejection) -> Self {
        Self::Rejected(reason)
    }
}

pub struct AuthorizationEnvironment<'a> {
    pub authority: &'a SeatAuthority,
    pub policy: &'a PolicyContext,
    pub contracts: &'a BTreeMap<CapabilityId, CapabilityContract>,
    pub schemas: &'a dyn SchemaCatalog,
    pub listing: &'a CapabilityListing,
}

/// Complete every check before consuming approval or constructing an authorized invocation.
pub fn authorize(
    env: AuthorizationEnvironment<'_>,
    invocation: &ToolInvocation,
    plan: PlanGate,
    approval_gate: &mut ApprovalGate<'_>,
    now_ms: u64,
) -> KernelResult<AuthorizationOutcome> {
    let (contract, now) = match admit(&env, invocation, now_ms)? {
        Ok(admitted) => admitted,
        Err(rejection) => return Ok(AuthorizationOutcome::Rejected(rejection)),
    };
    if let Some(rejection) = reject_unplanned_side_effect(contract, invocation, plan) {
        return Ok(AuthorizationOutcome::Rejected(rejection));
    }
    let approval = consume(approval_gate, contract, invocation, now)?;
    Ok(conclude(env.authority, contract, invocation, approval))
}

/// Retried host commands must match their recorded approval and pass all fresh checks.
pub fn authorize_host_command(
    env: AuthorizationEnvironment<'_>,
    invocation: &ToolInvocation,
    scope: &Scope,
    plan: PlanGate,
    ledger: &mut Ledger,
    now_ms: u64,
) -> KernelResult<AuthorizationOutcome> {
    let (contract, now) = match admit(&env, invocation, now_ms)? {
        Ok(admitted) => admitted,
        Err(rejection) => return Ok(AuthorizationOutcome::Rejected(rejection)),
    };
    if let Some(rejection) = reject_unplanned_side_effect(contract, invocation, plan) {
        return Ok(AuthorizationOutcome::Rejected(rejection));
    }
    finish_host_command(env, invocation, scope, contract, now, ledger)
}

/// Plan writers bypass the plan prerequisite so they can create the required plan.
pub fn authorize_plan_management(
    env: AuthorizationEnvironment<'_>,
    invocation: &ToolInvocation,
    scope: &Scope,
    ledger: &mut Ledger,
    now_ms: u64,
) -> KernelResult<AuthorizationOutcome> {
    let (contract, now) = match admit(&env, invocation, now_ms)? {
        Ok(admitted) => admitted,
        Err(rejection) => return Ok(AuthorizationOutcome::Rejected(rejection)),
    };
    finish_host_command(env, invocation, scope, contract, now, ledger)
}

fn finish_host_command(
    env: AuthorizationEnvironment<'_>,
    invocation: &ToolInvocation,
    scope: &Scope,
    contract: &CapabilityContract,
    now: OffsetDateTime,
    ledger: &mut Ledger,
) -> KernelResult<AuthorizationOutcome> {
    let gated = contract.effect_class == EffectClass::R3
        || contract.approval == ApprovalRequirement::Operator;
    if let (true, Some(approval_id)) = (gated, &invocation.approval_id) {
        let binding = HostCommandBinding::of(invocation, scope);
        match ledger.approval(approval_id)? {
            Some(approval) if approval.status == ApprovalStatus::Consumed => {
                let exact = recovers(ledger, env.authority, invocation, &approval, &binding, now)?;
                let outcome = if exact {
                    ConsumeOutcome::Consumed(approval)
                } else {
                    ConsumeOutcome::Redirect(ApprovalRedirect::NeedsApproval {
                        approval_id: Some(approval.approval_id),
                    })
                };
                return Ok(conclude(env.authority, contract, invocation, outcome));
            }
            // Record only approvals this command can consume, so refused callers claim nothing.
            Some(approval)
                if approval.status == ApprovalStatus::Approved
                    && approval.scope == approval_scope(invocation)
                    && invocation.expected_revision == Some(approval.revision)
                    && now < approval.expires_at =>
            {
                ledger.record_host_command_binding(&invocation.command_id, &binding.encode()?)?;
            }
            _ => {}
        }
    }
    let approval = consume(&mut ApprovalGate::new(ledger), contract, invocation, now)?;
    Ok(conclude(env.authority, contract, invocation, approval))
}

/// Records host facts absent from the command columns for exact retry comparison.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HostCommandBinding {
    version: u32,
    scope: Scope,
    resource: Option<ResourceConstraint>,
    executor_binding: Option<serde_json::Value>,
    plan_id: Option<PlanId>,
}

impl HostCommandBinding {
    const VERSION: u32 = 1;

    fn of(invocation: &ToolInvocation, scope: &Scope) -> Self {
        Self {
            version: Self::VERSION,
            scope: scope.clone(),
            resource: invocation.resource.clone(),
            executor_binding: invocation.executor_binding.clone(),
            plan_id: invocation.plan_id.clone(),
        }
    }

    fn encode(&self) -> KernelResult<serde_json::Value> {
        serde_json::to_value(self).map_err(|error| {
            LedgerError::invalid_data_caused_by("host command binding is not encodable", error)
                .into()
        })
    }

    fn decode(recorded: serde_json::Value) -> KernelResult<Self> {
        let binding: Self = serde_json::from_value(recorded).map_err(|error| {
            LedgerError::invalid_data_caused_by("recorded host command binding is invalid", error)
        })?;
        if binding.version != Self::VERSION {
            return Err(LedgerError::invalid_data(format!(
                "recorded host command binding version {} is not {}",
                binding.version,
                Self::VERSION
            ))
            .into());
        }
        Ok(binding)
    }
}

fn recovers(
    ledger: &Ledger,
    authority: &SeatAuthority,
    invocation: &ToolInvocation,
    approval: &Approval,
    binding: &HostCommandBinding,
    now: OffsetDateTime,
) -> KernelResult<bool> {
    if approval.consumed_by_command_id.as_ref() != Some(&invocation.command_id)
        || approval.scope != approval_scope(invocation)
        || invocation.expected_revision != Some(approval.revision)
        || now >= approval.expires_at
    {
        return Ok(false);
    }
    let Some(command) = ledger.command(&invocation.command_id)? else {
        return Ok(false);
    };
    let original = command.terminal_status.is_none()
        && now < command.expires_at
        && command.issuer == authority.seat().as_str()
        && command.approval_id.as_ref() == Some(&approval.approval_id)
        && command.capability_id == invocation.capability_id
        && command.capability_version == i64::from(invocation.capability_version)
        && command.target_kind == invocation.target.kind
        && command.target_id == invocation.target.id
        && command.arguments_hash == invocation.arguments_digest
        && command.arguments == invocation.arguments;
    if !original {
        return Ok(false);
    }
    match ledger.host_command_binding(&invocation.command_id)? {
        Some(recorded) => Ok(HostCommandBinding::decode(recorded)? == *binding),
        None => Ok(false),
    }
}

fn approval_scope(invocation: &ToolInvocation) -> ApprovalScope {
    ApprovalScope {
        target_kind: invocation.target.kind.clone(),
        target_id: invocation.target.id.clone(),
        capability_id: invocation.capability_id.clone(),
        arguments_digest: invocation.arguments_digest,
    }
}

fn consume(
    approval_gate: &mut ApprovalGate<'_>,
    contract: &CapabilityContract,
    invocation: &ToolInvocation,
    now: OffsetDateTime,
) -> KernelResult<ConsumeOutcome> {
    approval_gate.authorize_capability_command(
        contract.effect_class,
        contract.approval,
        ApprovalCommand {
            command_id: &invocation.command_id,
            approval_id: invocation.approval_id.as_ref(),
            scope: &approval_scope(invocation),
            expected_revision: invocation.expected_revision,
            now,
        },
    )
}

/// Construct an authorized invocation only after all checks and approval succeed.
fn conclude(
    authority: &SeatAuthority,
    contract: &CapabilityContract,
    invocation: &ToolInvocation,
    approval: ConsumeOutcome,
) -> AuthorizationOutcome {
    match approval {
        ConsumeOutcome::Redirect(ApprovalRedirect::StaleRevision {
            expected_revision,
            actual_revision,
            ..
        }) => AuthorizationOutcome::rejected(AuthorizationRejection::StaleRevision {
            expected: expected_revision,
            actual: actual_revision,
        }),
        ConsumeOutcome::Redirect(_) => {
            AuthorizationOutcome::rejected(AuthorizationRejection::NeedsApproval {
                capability_id: invocation.capability_id.clone(),
                effect_class: contract.effect_class,
            })
        }
        ConsumeOutcome::NotRequired | ConsumeOutcome::Consumed(_) => {
            AuthorizationOutcome::Authorized(Box::new(AuthorizedInvocation::new(
                authority.clone(),
                invocation.clone(),
                contract.clone(),
            )))
        }
    }
}

type Admission<'a> = Result<(&'a CapabilityContract, OffsetDateTime), AuthorizationRejection>;

/// Plan management skips the plan prerequisite; other authorization paths enforce it.
fn admit<'a>(
    env: &AuthorizationEnvironment<'a>,
    invocation: &ToolInvocation,
    now_ms: u64,
) -> KernelResult<Admission<'a>> {
    let AuthorizationEnvironment {
        authority,
        policy,
        contracts,
        schemas,
        listing,
    } = *env;
    let Some(contract) = contracts.get(&invocation.capability_id) else {
        return Ok(Err(AuthorizationRejection::UnknownCapability {
            capability_id: invocation.capability_id.clone(),
        }));
    };

    if !policy.is_bound_to(authority) {
        return Ok(Err(AuthorizationRejection::ForgedIdentity));
    }

    if !policy.is_capability_effective(&invocation.capability_id, contracts) {
        if let Some(hint) = policy.wrong_seat_hint(&invocation.capability_id) {
            return Ok(Err(AuthorizationRejection::WrongSeat {
                capability_id: invocation.capability_id.clone(),
                hint: hint.clone(),
            }));
        }
        return Ok(Err(AuthorizationRejection::Unavailable {
            capability_id: invocation.capability_id.clone(),
            reason: "capability is outside the current effective policy".to_owned(),
        }));
    }

    let now = timestamp(now_ms)?;
    let expected_expiry = timestamp(authority.expires_at_ms())?;
    let session = match live_session(authority.session()) {
        Ok(session) => session,
        Err(_) => {
            return Ok(Err(AuthorizationRejection::ForgedIdentity));
        }
    };
    let listing_bound = listing.validate().is_ok()
        && listing.seat_id == *authority.seat()
        && listing.slice_id == *authority.slice()
        && listing.session_id == session
        && listing.seat_token_id == *authority.token_id()
        && listing.policy_digest == authority.capability_policy_digest()
        && listing.expires_at == expected_expiry
        && now < listing.expires_at
        && invocation.listing_digest == listing.digest;
    if !listing_bound {
        return Ok(Err(AuthorizationRejection::StaleListing));
    }

    if invocation.capability_version != contract.version {
        return Ok(Err(AuthorizationRejection::VersionMismatch {
            requested: invocation.capability_version,
            available: contract.version,
        }));
    }

    let expected_tool = resolve_tool(policy, contract, schemas)?;
    if !listing.tools.iter().any(|listed| listed == &expected_tool) {
        return Ok(Err(AuthorizationRejection::StaleListing));
    }

    if invocation.arguments_digest != arguments_digest(&invocation.arguments) {
        return Ok(Err(AuthorizationRejection::ArgumentDigestMismatch));
    }
    if !contract.arguments_bind_declared_target(&invocation.arguments) {
        return Ok(Err(AuthorizationRejection::ResourceDenied {
            reason: "canonical delegation target differs from the declared capability".to_owned(),
        }));
    }

    if !resource_is_exact(
        invocation.resource.as_ref(),
        &expected_tool.resource_constraints,
    ) {
        return Ok(Err(AuthorizationRejection::ResourceDenied {
            reason: "invocation resource is not an exact listed constraint".to_owned(),
        }));
    }

    Ok(Ok((contract, now)))
}

fn reject_unplanned_side_effect(
    contract: &CapabilityContract,
    invocation: &ToolInvocation,
    plan: PlanGate,
) -> Option<AuthorizationRejection> {
    if contract.effect_class != EffectClass::R0
        && (invocation.plan_id.is_none() || !plan.permits_side_effect())
    {
        return Some(AuthorizationRejection::NeedsPlan {
            capability_id: invocation.capability_id.clone(),
        });
    }
    None
}

#[must_use]
pub fn arguments_digest(arguments: &serde_json::Value) -> Digest {
    let bytes =
        serde_json::to_vec(arguments).expect("serde_json::Value serialization is infallible");
    Digest::hash(&bytes)
}

/// Share resource matching with host admission so pre-I/O checks cannot disagree.
pub fn resource_is_exact(
    requested: Option<&ResourceConstraint>,
    listed: &[ResourceConstraint],
) -> bool {
    match requested {
        Some(resource) => listed.binary_search(resource).is_ok(),
        None => listed.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use odin_domain::knowledge::{CapabilityListingDigest, ToolSchema};
    use odin_domain::{ApprovalId, CommandId, PlanId, SeatToken, SessionId};
    use odin_ledger::approval::NewApproval;
    use odin_ledger::Ledger;
    use serde_json::json;

    use super::*;
    use crate::capability::{
        list_capabilities, ApprovalRequirement, HandlerBinding, IdempotencyPolicy,
        InvocationTarget, RetryPolicy,
    };
    use crate::token::{
        ExpectedBindings, MemoryRevocations, MintRequest, TokenIssuer, TokenVerifier,
    };

    struct Schemas(ToolSchema);

    impl SchemaCatalog for Schemas {
        fn schema(&self, _reference: &str) -> KernelResult<ToolSchema> {
            Ok(self.0.clone())
        }
    }

    struct Fixture {
        authority: SeatAuthority,
        context: PolicyContext,
        contracts: BTreeMap<CapabilityId, CapabilityContract>,
        schemas: Schemas,
    }

    impl Fixture {
        fn new(effect_class: EffectClass) -> Self {
            let authority = authority();
            let capability_id = CapabilityId::new("tool.write").unwrap();
            let contract = CapabilityContract {
                id: capability_id.clone(),
                delegate_to: None,
                version: 3,
                tool_name: ToolName::new("tool_write").unwrap(),
                description: "Write one declared target".to_owned(),
                handler: HandlerBinding::Builtin {
                    name: "write".to_owned(),
                },
                input_schema_ref: "schemas/capability/tool.write.input.json".to_owned(),
                output_schema_ref: "schemas/capability/tool.write.output.json".to_owned(),
                effect_class,
                seat_tags: BTreeSet::from(["builder".to_owned()]),
                timeout_seconds: NonZeroU32::new(5).unwrap(),
                idempotency: IdempotencyPolicy::Required,
                retry: RetryPolicy { max_attempts: 1 },
                approval: if effect_class == EffectClass::R3 {
                    ApprovalRequirement::Operator
                } else {
                    ApprovalRequirement::None
                },
                evidence_extractor: HandlerBinding::Builtin {
                    name: "write_evidence".to_owned(),
                },
                adapter: None,
                preview: None,
                batchable: false,
                batch: None,
            };
            let allowed = BTreeSet::from([capability_id.clone()]);
            let context = PolicyContext {
                seat_id: authority.seat().clone(),
                slice_id: authority.slice().clone(),
                lane_id: authority.lane().clone(),
                seat_revision: authority.seat_revision(),
                slice_revision: authority.slice_revision(),
                capability_policy_digest: authority.capability_policy_digest(),
                seat_tool_refs: allowed.clone(),
                slice_capabilities: allowed.clone(),
                project_capabilities: allowed.clone(),
                lane_capabilities: allowed,
                denied_capabilities: BTreeSet::new(),
                denied_tools: BTreeSet::new(),
                seat_categories: BTreeSet::from(["builder".to_owned()]),
                adapter_health: AdapterHealth::default(),
                resource_constraints: BTreeMap::new(),
                seat_hints: BTreeMap::new(),
            };
            Self {
                authority,
                context,
                contracts: BTreeMap::from([(capability_id, contract)]),
                schemas: Schemas(ToolSchema::from_value(json!({"type": "object"})).unwrap()),
            }
        }

        fn listing(&self) -> CapabilityListing {
            list_capabilities(
                &self.authority,
                &self.context,
                &self.contracts,
                &self.schemas,
                20,
            )
            .unwrap()
        }

        fn invocation(
            &self,
            capability_id: CapabilityId,
            listing_digest: CapabilityListingDigest,
        ) -> ToolInvocation {
            let arguments = json!({});
            ToolInvocation {
                command_id: CommandId::new("command.one").unwrap(),
                capability_id,
                capability_version: 3,
                listing_digest,
                arguments_digest: arguments_digest(&arguments),
                arguments,
                target: InvocationTarget {
                    kind: "lane".to_owned(),
                    id: "lane.one".to_owned(),
                },
                executor_binding: None,
                expected_revision: None,
                plan_id: Some(PlanId::new("plan.one").unwrap()),
                approval_id: None,
                resource: None,
            }
        }

        fn run(
            &self,
            listing: &CapabilityListing,
            invocation: &ToolInvocation,
            plan: PlanGate,
        ) -> AuthorizationOutcome {
            self.run_with(listing, invocation, plan, |_| {})
        }

        /// Prepare the approval ledger before running the same authorization checks as `run`.
        fn run_with(
            &self,
            listing: &CapabilityListing,
            invocation: &ToolInvocation,
            plan: PlanGate,
            prepare: impl FnOnce(&mut ApprovalGate<'_>),
        ) -> AuthorizationOutcome {
            let mut ledger = Ledger::open_in_memory().unwrap();
            prepare(&mut ApprovalGate::new(&mut ledger));
            self.journal(&mut ledger, invocation, 3_600_000);
            let mut approvals = ApprovalGate::new(&mut ledger);
            authorize(
                AuthorizationEnvironment {
                    authority: &self.authority,
                    policy: &self.context,
                    contracts: &self.contracts,
                    schemas: &self.schemas,
                    listing,
                },
                invocation,
                plan,
                &mut approvals,
                20,
            )
            .unwrap()
        }

        /// `expires_ms` is measured from the Unix epoch.
        fn journal(
            &self,
            ledger: &mut Ledger,
            invocation: &ToolInvocation,
            expires_ms: i64,
        ) -> odin_ledger::command::RecordedCommand {
            ledger
                .record_command(&odin_ledger::command::CommandSpec {
                    id: invocation.command_id.clone(),
                    idempotency_key: invocation.command_id.to_string(),
                    correlation_id: format!("correlation.{}", invocation.command_id),
                    causation_id: None,
                    issuer: self.authority.seat().to_string(),
                    approval_id: invocation.approval_id.clone(),
                    target_kind: invocation.target.kind.clone(),
                    target_id: invocation.target.id.clone(),
                    capability_id: invocation.capability_id.clone(),
                    capability_version: i64::from(invocation.capability_version),
                    arguments_hash: invocation.arguments_digest,
                    arguments: invocation.arguments.clone(),
                    expected_desired_revision: None,
                    issued_at: time::OffsetDateTime::UNIX_EPOCH,
                    expires_at: time::OffsetDateTime::UNIX_EPOCH
                        + time::Duration::milliseconds(expires_ms),
                })
                .unwrap()
                .into_recorded()
        }
    }

    #[test]
    fn deny_wins_and_unavailable_capability_is_omitted() {
        let mut fixture = Fixture::new(EffectClass::R0);
        let displayed = fixture.listing();
        let capability_id = fixture.contracts.keys().next().unwrap().clone();
        let invocation = fixture.invocation(capability_id.clone(), displayed.digest);
        fixture
            .context
            .denied_capabilities
            .insert(capability_id.clone());
        assert!(effective(&fixture.context, &fixture.contracts).is_empty());
        assert!(fixture.listing().tools.is_empty());
        assert_eq!(
            fixture.run(&displayed, &invocation, PlanGate::Accepted),
            AuthorizationOutcome::Rejected(AuthorizationRejection::Unavailable {
                capability_id,
                reason: "capability is outside the current effective policy".to_owned(),
            })
        );
    }

    #[test]
    fn unhealthy_adapter_is_omitted() {
        let mut fixture = Fixture::new(EffectClass::R0);
        fixture.contracts.values_mut().next().unwrap().adapter = Some("offline".to_owned());
        fixture.context.adapter_health =
            AdapterHealth::new(BTreeMap::from([("offline".to_owned(), false)]));
        assert!(fixture.listing().tools.is_empty());
    }

    #[test]
    fn out_of_category_capability_returns_wrong_seat_hint() {
        let mut fixture = Fixture::new(EffectClass::R0);
        let listing = fixture.listing();
        let capability_id = fixture.contracts.keys().next().unwrap().clone();
        fixture.context.seat_categories.clear();
        fixture
            .context
            .seat_hints
            .insert(capability_id.clone(), SeatId::new("seat.builder").unwrap());
        let invocation = fixture.invocation(capability_id.clone(), listing.digest);
        assert_eq!(
            fixture.run(&listing, &invocation, PlanGate::Accepted),
            AuthorizationOutcome::Rejected(AuthorizationRejection::WrongSeat {
                capability_id,
                hint: SeatId::new("seat.builder").unwrap(),
            })
        );
    }

    #[test]
    fn plan_gate_runs_before_a_side_effect_can_be_authorized() {
        let fixture = Fixture::new(EffectClass::R1);
        let listing = fixture.listing();
        let capability_id = fixture.contracts.keys().next().unwrap().clone();
        let mut invocation = fixture.invocation(capability_id.clone(), listing.digest);
        invocation.plan_id = None;
        assert_eq!(
            fixture.run(&listing, &invocation, PlanGate::Missing),
            AuthorizationOutcome::Rejected(AuthorizationRejection::NeedsPlan { capability_id })
        );
    }

    #[test]
    fn stale_listing_digest_is_rejected() {
        let fixture = Fixture::new(EffectClass::R0);
        let listing = fixture.listing();
        let capability_id = fixture.contracts.keys().next().unwrap().clone();
        let invocation = fixture.invocation(
            capability_id,
            CapabilityListingDigest::new(Digest::hash(b"stale listing")),
        );
        assert_eq!(
            fixture.run(&listing, &invocation, PlanGate::Accepted),
            AuthorizationOutcome::Rejected(AuthorizationRejection::StaleListing)
        );
    }

    #[test]
    fn unknown_capability_is_rejected_before_handler_resolution() {
        let fixture = Fixture::new(EffectClass::R0);
        let listing = fixture.listing();
        let unknown = CapabilityId::new("tool.unknown").unwrap();
        let invocation = fixture.invocation(unknown.clone(), listing.digest);
        assert_eq!(
            fixture.run(&listing, &invocation, PlanGate::Accepted),
            AuthorizationOutcome::Rejected(AuthorizationRejection::UnknownCapability {
                capability_id: unknown,
            })
        );
    }

    #[test]
    fn delegation_target_is_checked_before_requesting_approval() {
        let mut fixture = Fixture::new(EffectClass::R3);
        let capability = CapabilityId::new("tool.write").unwrap();
        fixture.contracts.get_mut(&capability).unwrap().delegate_to =
            Some(SeatId::new("worker.alpha").unwrap());
        let listing = fixture.listing();
        let mut invocation = fixture.invocation(capability.clone(), listing.digest);
        invocation.arguments = json!({"_delegate_to": "worker.beta"});
        invocation.arguments_digest = arguments_digest(&invocation.arguments);
        assert!(matches!(
            fixture.run(&listing, &invocation, PlanGate::Accepted),
            AuthorizationOutcome::Rejected(AuthorizationRejection::ResourceDenied { .. })
        ));
        invocation.arguments["_delegate_to"] = json!("worker.alpha");
        invocation.arguments_digest = arguments_digest(&invocation.arguments);
        assert!(matches!(
            fixture.run(&listing, &invocation, PlanGate::Accepted),
            AuthorizationOutcome::Rejected(AuthorizationRejection::NeedsApproval { .. })
        ));
        fixture.contracts.get_mut(&capability).unwrap().delegate_to =
            Some(SeatId::new("worker.beta").unwrap());
        let changed_listing = fixture.listing();
        invocation.listing_digest = changed_listing.digest;
        assert!(matches!(
            fixture.run(&changed_listing, &invocation, PlanGate::Accepted),
            AuthorizationOutcome::Rejected(AuthorizationRejection::ResourceDenied { .. })
        ));
    }

    #[test]
    fn r2_operator_contract_demands_exact_approval_before_authorizing() {
        let mut fixture = Fixture::new(EffectClass::R2);
        let capability_id = fixture.contracts.keys().next().unwrap().clone();
        fixture.contracts.get_mut(&capability_id).unwrap().approval = ApprovalRequirement::Operator;
        let listing = fixture.listing();
        let mut invocation = fixture.invocation(capability_id.clone(), listing.digest);

        // First pass: no approval, typed demand.
        assert_eq!(
            fixture.run(&listing, &invocation, PlanGate::Accepted),
            AuthorizationOutcome::Rejected(AuthorizationRejection::NeedsApproval {
                capability_id: capability_id.clone(),
                effect_class: EffectClass::R2,
            })
        );

        let exact_scope = ApprovalScope {
            target_kind: invocation.target.kind.clone(),
            target_id: invocation.target.id.clone(),
            capability_id: invocation.capability_id.clone(),
            arguments_digest: invocation.arguments_digest,
        };
        let mut wrong_scope = exact_scope.clone();
        wrong_scope.arguments_digest = arguments_digest(&json!({"other": "arguments"}));
        invocation.approval_id = Some(ApprovalId::new("approval:r2-wrong").unwrap());
        invocation.expected_revision = Some(2);
        assert_eq!(
            fixture.run_with(&listing, &invocation, PlanGate::Accepted, |gate| {
                decide_fixture_approval(gate, "approval:r2-wrong", wrong_scope);
            }),
            AuthorizationOutcome::Rejected(AuthorizationRejection::NeedsApproval {
                capability_id: capability_id.clone(),
                effect_class: EffectClass::R2,
            }),
            "an approved scope never covers different arguments"
        );

        invocation.approval_id = Some(ApprovalId::new("approval:r2-exact").unwrap());
        assert!(matches!(
            fixture.run_with(&listing, &invocation, PlanGate::Accepted, |gate| {
                decide_fixture_approval(gate, "approval:r2-exact", exact_scope);
            }),
            AuthorizationOutcome::Authorized(_)
        ));
    }

    #[test]
    fn r2_contract_without_operator_declaration_stays_approval_free() {
        let fixture = Fixture::new(EffectClass::R2);
        let listing = fixture.listing();
        let capability_id = fixture.contracts.keys().next().unwrap().clone();
        assert_eq!(
            fixture.contracts[&capability_id].approval,
            ApprovalRequirement::None
        );
        let invocation = fixture.invocation(capability_id, listing.digest);
        assert!(matches!(
            fixture.run(&listing, &invocation, PlanGate::Accepted),
            AuthorizationOutcome::Authorized(_)
        ));
    }

    /// Retries require the original binding and an unexpired, nonterminal command;
    /// refusals must not backfill bindings.
    #[test]
    fn host_command_recovery_admits_only_the_exact_consumed_original() {
        let mut fixture = Fixture::new(EffectClass::R3);
        let capability_id = fixture.contracts.keys().next().unwrap().clone();
        let named = |value: &str| ResourceConstraint::Named {
            kind: "workspace".to_owned(),
            value: value.to_owned(),
        };
        let resources = vec![named("a"), named("b")];
        fixture
            .context
            .resource_constraints
            .insert(capability_id.clone(), resources.clone());
        let listing = fixture.listing();
        let scope = odin_domain::Scope::default();
        let mut ledger = Ledger::open_in_memory().unwrap();
        let presented = |command: &str, approval: &str, revision: i64| {
            let mut invocation = fixture.invocation(capability_id.clone(), listing.digest);
            invocation.command_id = CommandId::new(command).unwrap();
            invocation.approval_id = Some(ApprovalId::new(approval).unwrap());
            invocation.expected_revision = Some(revision);
            invocation.resource = Some(resources[0].clone());
            invocation
        };
        let run = |ledger: &mut Ledger, invocation: &ToolInvocation, scope: &Scope, now_ms: u64| {
            let env = AuthorizationEnvironment {
                authority: &fixture.authority,
                policy: &fixture.context,
                contracts: &fixture.contracts,
                schemas: &fixture.schemas,
                listing: &listing,
            };
            authorize_host_command(env, invocation, scope, PlanGate::Accepted, ledger, now_ms)
                .unwrap()
        };

        // The original records its binding, then consumes; its exact
        // stranded retry presents the consumed revision and recovers.
        let original = presented("command.original", "approval:original", 2);
        decide_fixture_approval(
            &mut ApprovalGate::new(&mut ledger),
            "approval:original",
            approval_scope(&original),
        );
        let journaled = fixture.journal(&mut ledger, &original, 500);
        assert!(matches!(
            run(&mut ledger, &original, &scope, 20),
            AuthorizationOutcome::Authorized(_)
        ));
        let recorded = ledger
            .host_command_binding(&original.command_id)
            .unwrap()
            .expect("the binding is recorded before consumption");
        let mut retry = original.clone();
        retry.expected_revision = Some(3);
        assert!(matches!(
            run(&mut ledger, &retry, &scope, 20),
            AuthorizationOutcome::Authorized(_)
        ));

        // A command consumed through the ordinary gate has no host binding.
        let legacy = presented("command.legacy", "approval:legacy", 2);
        decide_fixture_approval(
            &mut ApprovalGate::new(&mut ledger),
            "approval:legacy",
            approval_scope(&legacy),
        );
        fixture.journal(&mut ledger, &legacy, 500);
        let env = AuthorizationEnvironment {
            authority: &fixture.authority,
            policy: &fixture.context,
            contracts: &fixture.contracts,
            schemas: &fixture.schemas,
            listing: &listing,
        };
        let mut gate = ApprovalGate::new(&mut ledger);
        let consumed = authorize(env, &legacy, PlanGate::Accepted, &mut gate, 20).unwrap();
        assert!(matches!(consumed, AuthorizationOutcome::Authorized(_)));
        let mut legacy_retry = legacy.clone();
        legacy_retry.expected_revision = Some(3);
        let mut foreign = retry.clone();
        foreign.command_id = CommandId::new("command.foreign").unwrap();
        fixture.journal(&mut ledger, &foreign, 500);
        let mut resource = retry.clone();
        resource.resource = Some(resources[1].clone());
        let mut plan = retry.clone();
        plan.plan_id = Some(PlanId::new("plan.two").unwrap());
        let mut executor = retry.clone();
        executor.executor_binding = Some(json!({"execution": "another"}));
        let moved = odin_domain::Scope {
            project: Some(odin_domain::ProjectId::new("project.other").unwrap()),
            ..odin_domain::Scope::default()
        };
        for (label, invocation, scope, now_ms) in [
            ("legacy", &legacy_retry, &scope, 20),
            ("foreign", &foreign, &scope, 20),
            ("resource", &resource, &scope, 20),
            ("plan", &plan, &scope, 20),
            ("executor", &executor, &scope, 20),
            ("scope", &retry, &moved, 20),
            ("expired", &retry, &scope, 600),
        ] {
            assert!(
                matches!(
                    run(&mut ledger, invocation, scope, now_ms),
                    AuthorizationOutcome::Rejected(AuthorizationRejection::NeedsApproval { .. })
                ),
                "{label}"
            );
        }
        let issued_at = journaled.command().issued_at;
        ledger
            .reject_command(&journaled, 1, json!({"rejected": true}), issued_at)
            .unwrap();
        assert!(matches!(
            run(&mut ledger, &retry, &scope, 20),
            AuthorizationOutcome::Rejected(AuthorizationRejection::NeedsApproval { .. })
        ));

        assert_eq!(
            ledger.host_command_binding(&original.command_id).unwrap(),
            Some(recorded.clone())
        );
        for command in [&legacy.command_id, &foreign.command_id] {
            assert_eq!(
                ledger.host_command_binding(command).unwrap(),
                None,
                "{command}"
            );
        }
        assert!(matches!(
            ledger.record_host_command_binding(&legacy.command_id, &recorded),
            Err(odin_ledger::LedgerError::Conflict(_))
        ));
    }

    /// Leave the approved row at revision two for the invocation.
    fn decide_fixture_approval(gate: &mut ApprovalGate<'_>, id: &str, scope: ApprovalScope) {
        let approval_id = ApprovalId::new(id).unwrap();
        let requested = gate
            .request(NewApproval {
                approval_id: approval_id.clone(),
                issuer: "seat.one".to_owned(),
                scope,
                requested_at: time::OffsetDateTime::UNIX_EPOCH,
                expires_at: time::OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1),
            })
            .unwrap();
        assert!(matches!(
            gate.decide(
                &approval_id,
                requested.revision,
                crate::approval::ApprovalDecision::Approve {
                    evidence_ref: Some("operator:fixture".to_owned()),
                },
                "human:operator",
                time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1),
            )
            .unwrap(),
            crate::approval::DecisionOutcome::Approved(_)
        ));
    }

    fn authority() -> SeatAuthority {
        let seat = SeatId::new("seat.one").unwrap();
        let slice = SliceId::new("slice.one").unwrap();
        let lane = LaneId::new("lane.one").unwrap();
        let session = SessionId::new("00000000-0000-4000-8000-000000000001").unwrap();
        let seat_revision = Digest::hash(b"seat revision");
        let slice_revision = Digest::hash(b"slice revision");
        let capability_policy_digest = Digest::hash(b"capability policy");
        let context_policy_digest = Digest::hash(b"context policy");
        let issuer = TokenIssuer::new(b"test signing key".to_vec()).unwrap();
        let token: SeatToken = issuer
            .mint(MintRequest {
                seat: seat.clone(),
                slice: slice.clone(),
                lane: lane.clone(),
                session: session.clone(),
                seat_revision,
                slice_revision,
                capability_policy_digest,
                context_policy_digest,
                issued_at_ms: 10,
                expires_at_ms: 1_000,
                entropy: b"fixture entropy",
            })
            .unwrap();
        TokenVerifier::new(b"test signing key".to_vec(), MemoryRevocations::new())
            .unwrap()
            .verify(
                &token,
                ExpectedBindings {
                    seat: &seat,
                    slice: &slice,
                    lane: &lane,
                    session: &session,
                    seat_revision,
                    slice_revision,
                    capability_policy_digest,
                    context_policy_digest,
                },
                20,
            )
            .unwrap()
    }
}
