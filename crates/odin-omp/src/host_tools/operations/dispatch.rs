//! Capability dispatch, authorization, approval handling, and durable invocation.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use crate::host_tools::workload_drafts;
use odin_domain::knowledge::{CapabilityListing, ResourceConstraint};
use odin_domain::operation::{EffectState, RequestCost};
use odin_domain::{
    ApprovalId, ApprovalStatus, CapabilityId, CommandId, Digest, EffectClass, PlanId, Scope,
    SessionId,
};
use odin_kernel::{
    arguments_digest, authorize, authorize_host_command, authorize_plan_management,
    list_capabilities, ApprovalGate, ApprovalScope, AuthorizationOutcome, AuthorizationRejection,
    AuthorizedInvocation, CapabilityContract, FreshAuthority, InvocationTarget, InvokeRequest,
    NewApproval, OperationAuthority, OperationDecision, OperationExecutor, OperationRejection,
    PlanGate, PolicyContext, SchemaCatalog, StopIntentOutcome, ToolInvocation,
};
use odin_ledger::command::{CommandSpec, RecordCommand};
use odin_ledger::{Ledger, LedgerError};
use odin_types::{sha256_hex, CorrelationId, OperationId};
use serde_json::Value;
use time::OffsetDateTime;

use super::admission::CheckedDispatchPrefix;
use super::catalog::declared_narrowing_schema;
use super::policy::{correlation_for, host_tool_command_id, restore_consumed_approval};
use super::{
    HostToolOperationError, HostToolOperations, SessionOperationBinding, SessionOperationContext,
};
use crate::host_tools::executor::HostToolExecutor;
use crate::host_tools::plan_set::PlanSetTool;

/// The in-host transport never narrows the authority-derived reservation.
/// Both the ceiling and the charged reservation are bound into the durable
/// request digest; the kernel charges (1 request, 0 stops, 0 spend).
pub(super) const NO_NARROWING: RequestCost = RequestCost {
    requests: u64::MAX,
    stops: u64::MAX,
    spend: u64::MAX,
};

impl HostToolOperations {
    /// Validates catalog bindings and recovers orphaned journal entries to `in_doubt` before serving.
    pub fn new(
        inputs: super::OperationStackInputs,
        contracts: BTreeMap<CapabilityId, CapabilityContract>,
        authority_provider: Arc<super::ProvisionedFreshAuthorityProvider>,
    ) -> Result<Self, HostToolOperationError> {
        let super::OperationStackInputs {
            catalog,
            schemas,
            executor,
            adapter_executor,
            adapter_status,
            limits,
            clock,
            ledger,
            revisions,
            workload_drafts,
        } = inputs;
        let mut tool_index = BTreeMap::new();
        for (id, contract) in &contracts {
            let Some(admitted) = catalog.admitted(id) else {
                if catalog.is_operator_owned(id) {
                    // Operator CLI capabilities have no model-dispatch route.
                    continue;
                }
                return Err(HostToolOperationError::Composition {
                    detail: format!("contract {id} is not admitted by the operation catalog"),
                });
            };
            if admitted.contract != *contract {
                return Err(HostToolOperationError::Composition {
                    detail: format!(
                        "catalog admission for {id} does not match the declared contract"
                    ),
                });
            }
            if !catalog.resolves(&contract.handler)
                || !catalog.resolves(&contract.evidence_extractor)
            {
                return Err(HostToolOperationError::Composition {
                    detail: format!("contract {id} handler or evidence extractor does not resolve"),
                });
            }
            if let Some(existing) =
                tool_index.insert(contract.tool_name.as_ref().to_owned(), id.clone())
            {
                return Err(HostToolOperationError::Composition {
                    detail: format!(
                        "tool {} is bound by both {} and {}",
                        contract.tool_name, existing, id
                    ),
                });
            }
        }
        let contract_adapters: BTreeSet<String> = contracts
            .values()
            .filter_map(|contract| contract.adapter.clone())
            .collect();
        // The declared argument narrowing is compiled exactly once from
        // the immutable registered model surfaces: `HostToolRegistry`
        // takes `&mut` only before it is `Arc`-wrapped for this executor,
        // so the definition set compiled here is the definition set the
        // model was listed with and the executor serves, for the
        // registry's whole lifetime. A definition that does not compile
        // into a schema fails composition instead of silently dropping a
        // declared constraint.
        let mut narrowing_schemas = BTreeMap::new();
        for definition in executor.definitions() {
            let narrowing = declared_narrowing_schema(&definition)?;
            narrowing_schemas.insert(definition.name.into_owned(), narrowing);
        }
        let authority = Arc::new(OperationAuthority::new(
            Arc::clone(&catalog),
            Arc::clone(&schemas),
            Arc::clone(&adapter_executor) as Arc<dyn OperationExecutor>,
            limits,
            Arc::clone(&clock),
            Arc::clone(&ledger),
        ));
        authority.recover()?;
        Ok(Self {
            authority,
            contracts: Arc::new(contracts),
            tool_index: Arc::new(tool_index),
            contract_adapters: Arc::new(contract_adapters),
            narrowing_schemas: Arc::new(narrowing_schemas),
            schemas,
            executor,
            adapter_status,
            authority_provider,
            revisions,
            workload_drafts,
            task_grants: None,
            material_memo: Arc::new(Mutex::new(BTreeMap::new())),
            clock,
            ledger,
        })
    }

    pub fn with_task_grants(
        mut self,
        grants: Arc<crate::host_tools::task_grants::TaskGrantStore>,
    ) -> Self {
        self.task_grants = Some(grants);
        self
    }

    #[cfg(test)]
    pub(super) fn executor(&self) -> &Arc<HostToolExecutor> {
        &self.executor
    }

    #[cfg(test)]
    pub(super) fn authority(&self) -> &Arc<OperationAuthority> {
        &self.authority
    }

    /// Reloads and freshly verifies this session's provisioned token, then
    /// returns the exact current listing. Runtime factories call this before
    /// launching a capability-enabled child; a missing, stale, or revoked
    /// token therefore fails before process creation.
    pub fn session_listing(
        &self,
        binding: &SessionOperationBinding,
        session: &SessionId,
    ) -> Result<CapabilityListing, HostToolOperationError> {
        let now_ms = (self.clock)();
        let (_, listing, _) = self.fresh_listing(binding, session, now_ms)?;
        Ok(listing)
    }

    /// Projects the model-visible definitions of exactly the admitted host
    /// tools. Every admitted name must be capability-bound and concretely
    /// compiled; anything else is a composition defect, never an omission.
    /// Callers without execution-proof support retain the same admitted names
    /// and schemas, but their proof-dependent tools state the limitation.
    pub fn admitted_definitions(
        &self,
        admitted: &BTreeSet<String>,
        execution_proof_supported: bool,
    ) -> Result<Vec<crate::host_tools::RpcHostToolDefinition>, HostToolOperationError> {
        admitted
            .iter()
            .map(|name| {
                if !self.is_capability_bound(name) {
                    return Err(HostToolOperationError::Composition {
                        detail: format!(
                            "listed host tool {name:?} has no admitted capability contract"
                        ),
                    });
                }
                self.executor
                    .definition(name, execution_proof_supported)
                    .ok_or_else(|| HostToolOperationError::Composition {
                        detail: format!(
                            "listed host tool {name:?} has no concrete compiled definition"
                        ),
                    })
            })
            .collect()
    }

    /// Names absent from this index cannot dispatch; this predicate does not imply a fallback route.
    pub fn is_capability_bound(&self, tool_name: &str) -> bool {
        self.tool_index.contains_key(tool_name)
    }

    pub fn capability_of(&self, tool_name: &str) -> Option<&CapabilityId> {
        self.tool_index.get(tool_name)
    }

    /// Dispatches one capability-bound host-tool call end to end: fresh
    /// verification of the externally provisioned token against current
    /// durable revocations, fresh effective listing, fresh policy
    /// authorization over the journaled exact command intent, then the
    /// durable idempotent invoke. `resource` is
    /// host-resolved authority input, never decoded from model arguments, and
    /// must equal one current listed constraint. The returned value is the
    /// executed handler's real result relayed by the executor; a replayed or
    /// unsettled operation is a typed error, never a fabricated result.
    pub fn dispatch_tool(
        &self,
        context: SessionOperationContext<'_>,
        tool_name: &str,
        resource: Option<ResourceConstraint>,
        arguments: Value,
        request_id: &str,
    ) -> Result<Value, HostToolOperationError> {
        let session = context.session.to_string();
        let result = self.dispatch_tool_once(context, tool_name, resource, arguments, request_id);
        // Log refusals because the returned error otherwise reaches only the model.
        if let Err(error) = &result {
            tracing::error!(
                "odin-omp: host tool refused tool={tool_name} session={session} request={request_id}: {error}"
            );
        }
        result
    }

    fn dispatch_tool_once(
        &self,
        context: SessionOperationContext<'_>,
        tool_name: &str,
        resource: Option<ResourceConstraint>,
        arguments: Value,
        request_id: &str,
    ) -> Result<Value, HostToolOperationError> {
        let CheckedDispatchPrefix {
            material,
            arguments,
        } = self.check_dispatch_prefix(&context, tool_name, resource.as_ref(), arguments)?;
        // The shared prefix resolved both entries in this immutable generation.
        let capability_id = &material.tool_index[tool_name];
        let contract = &material.contracts[capability_id];
        // The durable plan gate refuses an unplanned caller BEFORE any
        // sensitive readiness observation. The gate is re-read after the
        // preflight below and the consume binds the fresh observation.
        self.plan_gate(context.scope)?;
        // The workload authoring seam is content-bound: a `workload.publish`
        // dispatch must reference a draft this node actually retained at
        // (digest, bound revision). Unknown or mismatched drafts refuse
        // typed here — before the approval gate mints or consumes a human
        // decision — because re-deriving the declaration from model answers
        // would let a silent redraft convert one approval into a different
        // publication.
        if contract.id.as_str() == workload_drafts::WORKLOAD_PUBLISH_CAPABILITY {
            let Some(workload_drafts) = &self.workload_drafts else {
                return Err(HostToolOperationError::Composition {
                    detail: "workload.publish is admitted but the composed operation stack                              carries no retained-draft store"
                        .to_owned(),
                });
            };
            let profile_id = arguments
                .get("profileId")
                .and_then(|value| value.as_str())
                .ok_or_else(|| HostToolOperationError::Arguments {
                    detail: "workload publish requires the retained draft's profileId".to_owned(),
                })?;
            let declaration_digest = arguments
                .get("declarationDigest")
                .and_then(|value| value.as_str())
                .ok_or_else(|| HostToolOperationError::Arguments {
                    detail: "workload publish requires the retained draft's declarationDigest"
                        .to_owned(),
                })?;
            let expected_registry_revision = arguments
                .get("expectedRegistryRevision")
                .and_then(|value| value.as_u64())
                .ok_or_else(|| HostToolOperationError::Arguments {
                    detail: "workload publish requires the draft's exact \
                             expectedRegistryRevision"
                        .to_owned(),
                })?;
            workload_drafts
                .require_retained(profile_id, declaration_digest, expected_registry_revision)
                .map_err(|error| HostToolOperationError::Arguments {
                    detail: error.to_string(),
                })?;
        }
        // Check declared readiness before journaling or creating or consuming approvals.
        self.executor
            .preflight_contract(contract, context.scope, &arguments)
            .map_err(|error| HostToolOperationError::Arguments {
                detail: error.to_string(),
            })?;
        // The readiness preflight may block (cluster reach, sealed-store
        // probes), and nothing below re-reads: the journal, the gate, and
        // the approval consume all run on the one observation. Re-clock,
        // re-verify the authority, and re-read the durable plan gate, so
        // a token or approval that expired — or a plan that changed —
        // while the preflight ran refuses here, never consuming or
        // executing under the stale pre-preflight observation.
        let now_ms = (self.clock)();
        let (fresh, listing, policy) =
            self.fresh_listing(context.binding, context.session, now_ms)?;
        let (plan, plan_id) = self.plan_gate(context.scope)?;
        let correlation_id = correlation_for(context.session, request_id)?;
        let approval_id = approval_id_of(&arguments)?;
        // Pin the observed approval revision; the gate rejects a changed decision.
        // Ignore another capability's approval so declaration and task-grant decisions still run.
        let (approval_id, expected_revision) = match approval_id {
            Some(approval_id) => {
                let ledger = self.lock_ledger()?;
                match ledger
                    .approval(&approval_id)
                    .map_err(HostToolOperationError::Ledger)?
                {
                    Some(approval) if approval.scope.capability_id != contract.id => (None, None),
                    Some(approval) => (Some(approval_id), Some(approval.revision)),
                    None => (Some(approval_id), None),
                }
            }
            None => (None, None),
        };
        let mut invocation = ToolInvocation {
            command_id: host_tool_command_id(&correlation_id)?,
            capability_id: contract.id.clone(),
            capability_version: contract.version,
            listing_digest: listing.digest,
            arguments_digest: arguments_digest(&arguments),
            arguments,
            target: invocation_target(context.scope)?,
            executor_binding: host_executor_binding(contract, context.scope, context.execution)?,
            expected_revision,
            plan_id,
            approval_id,
            resource,
        };
        // Kernel-decided approvals, minted exact-scope before the intent is
        // journaled and then journaled and consumed below exactly like an
        // owner decision: a declaration-decided capability is decided by
        // `declaration:<seat>` (the seat's declarations already grant the
        // call); an owner-decided one covered by a live task grant — the
        // owner's one plan approval, for this session or its delegating
        // parent — is decided by `grant:<approval>`.
        let gated = contract.effect_class == EffectClass::R3
            || contract.approval == odin_kernel::ApprovalRequirement::Operator;
        if gated {
            // An unknown approval selector must not bypass declaration or task-grant decisions.
            if let Some(id) = invocation.approval_id.clone() {
                let durable = self
                    .lock_ledger()?
                    .approval(&id)
                    .map_err(HostToolOperationError::Ledger)?
                    .is_some();
                if !durable {
                    tracing::error!(
                        "odin-omp: capability={} seat={:?} ignored approvalId {id} that names no \
                         approval",
                        contract.id,
                        context.scope.seat.as_ref().map(ToString::to_string)
                    );
                    invocation.approval_id = None;
                }
            }
            let ledger = self.lock_ledger()?;
            restore_consumed_approval(
                &ledger,
                &mut invocation,
                &correlation_id,
                fresh.get().seat().as_str(),
            )?;
            adopt_decided_approval(
                &ledger,
                &mut invocation,
                contract.effect_class,
                contract.preview.is_some(),
            )?;
        }
        if let Some(id) = &invocation.approval_id {
            let ledger = self.lock_ledger()?;
            if let Some(approval) = ledger.approval(id)? {
                let grant_decider = approval
                    .decided_by
                    .as_deref()
                    .and_then(|actor| actor.strip_prefix("grant:"));
                let owner_preview = contract.preview.is_some();
                let valid = if contract.id.as_str()
                    == crate::host_tools::task_grants::TASK_GRANT_CAPABILITY
                {
                    approval.status == ApprovalStatus::Requested
                        || ledger.approval_has_owner_decision(&approval, owner_preview)?
                } else if let Some(expected) = grant_decider {
                    match &self.task_grants {
                        Some(grants) => {
                            let (limits, batchable) =
                                crate::host_tools::task_grants::admitted_batch_policy(
                                    &material.contracts,
                                )
                                .map_err(|detail| HostToolOperationError::Composition { detail })?;
                            grants
                                .cover(
                                    &invocation,
                                    context.session,
                                    context.binding.parent.as_deref(),
                                    &ledger,
                                    now_ms,
                                    limits,
                                    &batchable,
                                )
                                .map_err(|detail| HostToolOperationError::Composition { detail })?
                                .as_deref()
                                == Some(expected)
                        }
                        None => false,
                    }
                } else if odin_ledger::approval::requires_owner_preview(
                    &approval.scope,
                    contract.preview.is_some(),
                ) {
                    // Direct consent to a consequential effect stands only on
                    // the owner's decision of its complete delivered preview.
                    approval.status == ApprovalStatus::Requested
                        || ledger
                            .approval_has_owner_decision(&approval, contract.preview.is_some())?
                } else {
                    true
                };
                if !valid {
                    invocation.approval_id = None;
                    invocation.expected_revision = None;
                    if let Some(arguments) = invocation.arguments.as_object_mut() {
                        arguments.remove("approvalId");
                    }
                    invocation.arguments_digest = arguments_digest(&invocation.arguments);
                }
            }
        }
        if invocation.approval_id.is_none() && gated {
            if let Some(seat) = context.scope.seat.as_ref() {
                let decider = if material.declaration_decided.contains(&contract.id)
                    && contract.preview.is_none()
                {
                    Some(format!("declaration:{seat}"))
                } else if let Some(grants) = &self.task_grants {
                    let (limits, batchable) =
                        crate::host_tools::task_grants::admitted_batch_policy(&material.contracts)
                            .map_err(|detail| HostToolOperationError::Composition { detail })?;
                    let ledger = self.lock_ledger()?;
                    grants
                        .cover(
                            &invocation,
                            context.session,
                            context.binding.parent.as_deref(),
                            &ledger,
                            now_ms,
                            limits,
                            &batchable,
                        )
                        .map_err(|detail| HostToolOperationError::Composition { detail })?
                        .map(|grant| format!("grant:{grant}"))
                } else {
                    None
                };
                if let Some(decider) = decider {
                    self.kernel_decide(&mut invocation, contract, seat.as_str(), &decider, now_ms)?;
                }
            }
        }
        let outcome = {
            let mut ledger = self.lock_ledger()?;
            // The approval consumption foreign key names the consuming
            // command row: the exact invocation intent is journaled before
            // the gate can consume anything, so a conflicting replay fails
            // durably before any approval is spent and an approved call can
            // only ever consume a command that durably matches it. The
            // kernel records the command's original scope, resource,
            // executor binding, and plan before consuming, so a retry of
            // exactly this command after a crash between consumption and
            // preparation is recognized without reminting anything.
            journal_invocation_command(&mut ledger, &invocation, &correlation_id, &fresh, now_ms)?;
            let environment = odin_kernel::policy::AuthorizationEnvironment {
                authority: fresh.get(),
                policy: &policy,
                contracts: &material.contracts,
                schemas: &*self.schemas,
                listing: &listing,
            };
            let outcome = if tool_name == PlanSetTool::NAME {
                authorize_plan_management(
                    environment,
                    &invocation,
                    context.scope,
                    &mut ledger,
                    now_ms,
                )?
            } else {
                authorize_host_command(
                    environment,
                    &invocation,
                    context.scope,
                    plan,
                    &mut ledger,
                    now_ms,
                )?
            };
            // A first gated dispatch (mandatory R3, or a contract that
            // declares operator approval) the gate refused for lacking an
            // approval must not dead-end: the exact-scope request is minted
            // durably under the same ledger lock that journaled the refused
            // intent, so the operator's existing governed decision surfaces
            // have a row to decide and the model has an id to retry with.
            // Minting authorizes nothing; only an owner decision does.
            match outcome {
                AuthorizationOutcome::Authorized(proof) => {
                    Ok(AuthorizationOutcome::Authorized(proof))
                }
                AuthorizationOutcome::Rejected(AuthorizationRejection::NeedsApproval {
                    capability_id,
                    effect_class,
                }) => {
                    // Mint only when the invocation does not reference a
                    // durable approval row: an absent or placeholder id is
                    // the first gated demand, while a real row carries its own
                    // durable disposition — pending decision, denial,
                    // expiry, consumption — that must never be silently
                    // reminted.
                    let references_durable_row = match invocation.approval_id.as_ref() {
                        Some(id) => ledger
                            .approval(id)
                            .map_err(HostToolOperationError::Ledger)?
                            .is_some(),
                        None => false,
                    };
                    match context.scope.seat.as_ref() {
                        Some(seat) if !references_durable_row => {
                            let (approval_id, revision, _) = mint_approval_request(
                                &mut ledger,
                                &invocation,
                                effect_class,
                                seat.as_str(),
                                None,
                                now_ms,
                                contract.preview.is_some(),
                            )?;
                            Err(HostToolOperationError::ApprovalRequired {
                                capability_id,
                                effect_class,
                                approval_id,
                                revision,
                            })
                        }
                        _ => Ok(AuthorizationOutcome::Rejected(
                            AuthorizationRejection::NeedsApproval {
                                capability_id,
                                effect_class,
                            },
                        )),
                    }
                }
                AuthorizationOutcome::Rejected(rejection) => {
                    Ok(AuthorizationOutcome::Rejected(rejection))
                }
            }
        }?;
        let authorized = match outcome {
            AuthorizationOutcome::Authorized(proof) => *proof,
            AuthorizationOutcome::Rejected(rejection) => {
                if let (Some(grants), Some(_)) = (&self.task_grants, &invocation.approval_id) {
                    let mut ledger = self.lock_ledger()?;
                    grants
                        .release(&invocation, &mut ledger, now_ms)
                        .map_err(|detail| HostToolOperationError::Composition { detail })?;
                }
                return Err(HostToolOperationError::Rejected(rejection));
            }
        };
        let decision: OperationDecision = self
            .authority
            .invoke_authorized(
                authorized,
                &InvokeRequest {
                    capsule_id: context.binding.capsule_id.clone(),
                    correlation_id: correlation_id.clone(),
                    requested_ceiling: NO_NARROWING,
                },
            )
            .map_err(|rejection| self.adapter_failure(contract, &correlation_id, rejection))?;
        match (decision.state, decision.replay) {
            (EffectState::Committed, false) => self
                .executor
                .take_result(&correlation_id)
                .ok_or(HostToolOperationError::MissingResult),
            (EffectState::Committed, true) => Err(HostToolOperationError::Replayed),
            (EffectState::Aborted, _) => {
                self.note_adapter_dispatch_failure(contract);
                Err(HostToolOperationError::Aborted)
            }
            (EffectState::InDoubt, _) => {
                self.note_adapter_dispatch_failure(contract);
                Err(HostToolOperationError::InDoubt)
            }
            (EffectState::Prepared | EffectState::EffectStarted, _) => {
                Err(HostToolOperationError::Composition {
                    detail: "invoke returned a nonterminal state without settling".to_owned(),
                })
            }
        }
    }

    /// An adapter's typed failure (a page that did not load, an upstream
    /// refusal) is relayed beside the in-doubt rejection; the caller gets
    /// that reason, not the settlement internals.
    fn adapter_failure(
        &self,
        contract: &CapabilityContract,
        correlation_id: &CorrelationId,
        rejection: OperationRejection,
    ) -> HostToolOperationError {
        let Some(adapter) = &contract.adapter else {
            return rejection.into();
        };
        let relayed = self.executor.take_result(correlation_id);
        let typed = relayed.as_ref().and_then(|reason| {
            Some((
                reason.get("code")?.as_i64()?,
                reason.get("message")?.as_str()?.to_owned(),
            ))
        });
        let Some((code, message)) = typed else {
            return rejection.into();
        };
        let detail = relayed
            .as_ref()
            .and_then(|reason| reason.pointer("/data/detail")?.as_str())
            .map(|detail| format!(" detail=\"{detail}\""))
            .unwrap_or_default();
        tracing::error!(
            "odind: adapter failed id={adapter} capability={} code={code} reason={message}{detail}",
            contract.id
        );
        HostToolOperationError::AdapterFailed {
            capability_id: contract.id.clone(),
            code,
            message,
        }
    }

    /// Publishes a post-authorization adapter failure to the status source:
    /// the next listing or authorization refreshes for real instead of
    /// trusting the previous snapshot. Purely fail-closed.
    fn note_adapter_dispatch_failure(&self, contract: &CapabilityContract) {
        if let Some(adapter) = &contract.adapter {
            self.adapter_status.record_dispatch_failure(adapter);
        }
    }

    /// Records one durable stop intent against the session capsule, bound to a
    /// freshly verified seat authority. The authority owns the verdict; this
    /// surface only records the intent and reports the recorded outcome.
    pub fn stop_tool(
        &self,
        binding: &SessionOperationBinding,
        session: &SessionId,
        request_id: &str,
        operation_id: Option<OperationId>,
    ) -> Result<StopIntentOutcome, HostToolOperationError> {
        let now_ms = (self.clock)();
        let correlation_id = correlation_for(session, request_id)?;
        let fresh = self.verify_fresh(binding, session, now_ms)?;
        Ok(self
            .authority
            .stop_intent(fresh, &binding.capsule_id, &correlation_id, operation_id)?)
    }

    /// The per-call policy view: the binding's exact context with adapter
    /// health refreshed from the live status source. Listing and
    /// authorization read the same projection, so the listing digest and the
    /// authorized effective set can never disagree about adapter health.
    fn policy_with_health(&self, binding: &SessionOperationBinding, now_ms: u64) -> PolicyContext {
        let mut policy = binding.policy.clone();
        policy.adapter_health = self
            .adapter_status
            .current_health(&self.contract_adapters, now_ms);
        policy
    }

    pub(super) fn fresh_listing(
        &self,
        binding: &SessionOperationBinding,
        session: &SessionId,
        now_ms: u64,
    ) -> Result<(FreshAuthority, CapabilityListing, PolicyContext), HostToolOperationError> {
        let fresh = self.verify_fresh(binding, session, now_ms)?;
        let policy = self.policy_with_health(binding, now_ms);
        // The effective listing recomposes from the session's own
        // generation: its token digests bind that generation's admission,
        // so a co-temporary listing is impossible by construction.
        let material = self.generation_material(binding)?;
        let listing = list_capabilities(
            fresh.get(),
            &policy,
            &material.contracts,
            &*self.schemas,
            now_ms,
        )?;
        Ok((fresh, listing, policy))
    }

    /// Reloads the externally provisioned signed token and verifies it now
    /// against exact session bindings and current durable revocations. For a
    /// delegated child, the exact bound parent token is reloaded and verified
    /// FIRST — signature, expiry, session bindings, current durable
    /// revocations, plus the parent run's recorded plan acceptance — and only
    /// then is the child verified, under one ledger lock, with no automatic
    /// renewal anywhere around revocation. The returned proof is move-only
    /// and is never cached.
    fn verify_fresh(
        &self,
        binding: &SessionOperationBinding,
        session: &SessionId,
        now_ms: u64,
    ) -> Result<FreshAuthority, HostToolOperationError> {
        let ledger = self.lock_ledger()?;
        if let Some(parent) = &binding.parent {
            if parent.depth + 1 > crate::host_tools::delegation::MAX_DELEGATION_DEPTH {
                return Err(HostToolOperationError::Delegation {
                    detail: format!(
                        "delegation depth {} exceeds the configured worker bound",
                        parent.depth + 1
                    ),
                });
            }
            self.authority_provider
                .verify(&parent.binding, &parent.session, &ledger, now_ms)
                .map_err(|error| HostToolOperationError::Delegation {
                    detail: format!(
                        "the bound parent authority {} no longer verifies: {error}",
                        parent.session
                    ),
                })?;
            let accepted = ledger.plan_is_accepted(&parent.run).map_err(|error| {
                HostToolOperationError::Delegation {
                    detail: format!("parent plan {} could not be verified: {error}", parent.run),
                }
            })?;
            if !accepted {
                return Err(HostToolOperationError::Delegation {
                    detail: format!(
                        "the parent run {} has no recorded matching plan acceptance",
                        parent.run
                    ),
                });
            }
        }
        self.authority_provider
            .verify(binding, session, &ledger, now_ms)
    }

    /// The durable plan gate of the invocation's run. Only a recorded
    /// acceptance that still matches the plan's structural fingerprint makes
    /// the gate `Accepted`; a plan that merely exists stays `Draft`, and no
    /// plan at all stays `Missing` — side-effecting capabilities fail closed
    /// until real acceptance machinery records them.
    pub(super) fn plan_gate(
        &self,
        scope: &Scope,
    ) -> Result<(PlanGate, Option<PlanId>), HostToolOperationError> {
        let Some(run_id) = &scope.run else {
            return Ok((PlanGate::Missing, None));
        };
        let ledger = self.lock_ledger()?;
        let Some(plan) = ledger.plan(run_id)? else {
            return Ok((PlanGate::Missing, None));
        };
        let plan_id = Some(PlanId::new(format!(
            "plan:{}:{}",
            run_id.as_str(),
            plan.revision
        ))?);
        let accepted = ledger.plan_is_accepted(run_id)?;
        Ok((
            if accepted {
                PlanGate::Accepted
            } else {
                PlanGate::Draft
            },
            plan_id,
        ))
    }

    /// Mints and decides the exact-scope approval of one invocation on the
    /// kernel's behalf (`decider` names the declaration or task grant), and
    /// rewrites the invocation into the shape an owner-decided retry
    /// presents.
    fn kernel_decide(
        &self,
        invocation: &mut ToolInvocation,
        contract: &CapabilityContract,
        seat: &str,
        decider: &str,
        now_ms: u64,
    ) -> Result<(), HostToolOperationError> {
        let mut ledger = self.lock_ledger()?;
        let (approval_id, revision, status) = mint_approval_request(
            &mut ledger,
            invocation,
            contract.effect_class,
            seat,
            Some(decider),
            now_ms,
            contract.preview.is_some(),
        )?;
        let decided_at = OffsetDateTime::from_unix_timestamp_nanos(i128::from(now_ms) * 1_000_000)
            .map_err(|error| HostToolOperationError::Arguments {
                detail: format!("dispatch clock is not a valid timestamp: {error}"),
            })?;
        let decided = match status {
            ApprovalStatus::Approved => ledger
                .approval(&approval_id)
                .map_err(HostToolOperationError::Ledger)?
                .map(odin_kernel::DecisionOutcome::Approved)
                .ok_or_else(|| HostToolOperationError::Composition {
                    detail: format!("the decided approval {approval_id} is unreadable"),
                }),
            _ => ApprovalGate::new(&mut ledger)
                .decide(
                    &approval_id,
                    revision,
                    odin_ledger::approval::ApprovalDecision::Approve {
                        evidence_ref: Some(decider.to_owned()),
                    },
                    decider,
                    decided_at,
                )
                .map_err(|error| HostToolOperationError::Composition {
                    detail: format!("the {decider} decision failed: {error}"),
                }),
        };
        match decided {
            Ok(odin_kernel::DecisionOutcome::Approved(approval)) => {
                if let Some(arguments) = invocation.arguments.as_object_mut() {
                    arguments.insert(
                        "approvalId".to_owned(),
                        Value::String(approval_id.to_string()),
                    );
                }
                invocation.arguments_digest = arguments_digest(&invocation.arguments);
                invocation.expected_revision = Some(approval.revision);
                invocation.approval_id = Some(approval_id);
                Ok(())
            }
            Ok(_) => Err(HostToolOperationError::Composition {
                detail: format!("the {decider} decision for {approval_id} did not approve"),
            }),
            Err(error) => Err(error),
        }
    }

    /// Mints the move-only recovery proof through the identical pipeline as
    /// [`Self::dispatch_tool`]: freshly verified seat authority, fresh
    /// effective listing, plan gate, and `policy::authorize` over exactly
    /// one admitted capability. `command_id` is the recovery driver's
    /// deterministic command id; the correlation used at invoke time remains
    /// that command id, so a replayed dispatch journals against the same
    /// durable row. The recovery driver journals this exact command before
    /// dispatch, so this surface never re-records it. Refusals are typed
    /// rejections, never weakened proofs.
    pub fn authorize_recovery_invocation(
        &self,
        context: SessionOperationContext<'_>,
        command_id: CommandId,
        capability_id: &CapabilityId,
        arguments: Value,
        resource: Option<ResourceConstraint>,
    ) -> Result<AuthorizedInvocation, HostToolOperationError> {
        let material = self.generation_material(context.binding)?;
        let Some(contract) = material.contracts.get(capability_id) else {
            return Err(HostToolOperationError::Composition {
                detail: format!("capability {capability_id} is not admitted for recovery dispatch"),
            });
        };
        let now_ms = (self.clock)();
        let (fresh, listing, policy) =
            self.fresh_listing(context.binding, context.session, now_ms)?;
        let (plan, plan_id) = self.plan_gate(context.scope)?;
        let invocation = ToolInvocation {
            command_id,
            capability_id: contract.id.clone(),
            capability_version: contract.version,
            listing_digest: listing.digest,
            arguments_digest: arguments_digest(&arguments),
            arguments,
            target: invocation_target(context.scope)?,
            executor_binding: host_executor_binding(contract, context.scope, context.execution)?,
            expected_revision: None,
            plan_id,
            approval_id: None,
            resource,
        };
        let outcome = {
            let mut ledger = self.lock_ledger()?;
            let mut gate = ApprovalGate::new(&mut ledger);
            authorize(
                odin_kernel::policy::AuthorizationEnvironment {
                    authority: fresh.get(),
                    policy: &policy,
                    contracts: &material.contracts,
                    schemas: &*self.schemas,
                    listing: &listing,
                },
                &invocation,
                plan,
                &mut gate,
                now_ms,
            )?
        };
        match outcome {
            AuthorizationOutcome::Authorized(proof) => Ok(*proof),
            AuthorizationOutcome::Rejected(rejection) => {
                Err(HostToolOperationError::Rejected(rejection))
            }
        }
    }

    fn lock_ledger(&self) -> Result<MutexGuard<'_, Ledger>, HostToolOperationError> {
        self.ledger
            .lock()
            .map_err(|_| HostToolOperationError::Composition {
                detail: "operation ledger lock is poisoned".to_owned(),
            })
    }

    pub fn recovery_authority(&self) -> Arc<OperationAuthority> {
        Arc::clone(&self.authority)
    }

    pub fn recovery_contracts(&self) -> Arc<BTreeMap<CapabilityId, CapabilityContract>> {
        Arc::clone(&self.contracts)
    }

    pub fn recovery_schemas(&self) -> Arc<dyn SchemaCatalog + Send + Sync> {
        Arc::clone(&self.schemas)
    }

    pub fn recovery_executor(&self) -> Arc<HostToolExecutor> {
        Arc::clone(&self.executor)
    }

    pub fn recovery_ledger_store(&self) -> Arc<Mutex<Ledger>> {
        Arc::clone(&self.ledger)
    }
}

/// Extracts the caller-presented approval identity from invocation arguments.
/// Only schemas that declare `approvalId` admit the key; an undeclared key is
/// rejected by schema validation before it reaches authorization.
fn approval_id_of(arguments: &Value) -> Result<Option<ApprovalId>, HostToolOperationError> {
    match arguments.get("approvalId") {
        None => Ok(None),
        Some(value) => {
            let raw = value
                .as_str()
                .ok_or_else(|| HostToolOperationError::Arguments {
                    detail: "approvalId must be a string".to_owned(),
                })?;
            ApprovalId::new(raw)
                .map(Some)
                .map_err(|error| HostToolOperationError::Arguments {
                    detail: format!("approvalId is invalid: {error}"),
                })
        }
    }
}

/// Bridge-minted approval requests stay decidable for one hour; the
/// ledger's existing expiry sweep retires whatever the operator leaves
/// undecided.
const MINTED_REQUEST_TTL: Duration = Duration::from_secs(3_600);

fn approval_class_segment(effect_class: EffectClass) -> &'static str {
    match effect_class {
        EffectClass::R0 => "r0",
        EffectClass::R1 => "r1",
        EffectClass::R2 => "r2",
        EffectClass::R3 => "r3",
    }
}

fn approval_seed(invocation: &ToolInvocation, arguments_digest: &Digest) -> Digest {
    let seed_source = serde_json::json!({
        "target_kind": invocation.target.kind,
        "target_id": invocation.target.id,
        "capability_id": invocation.capability_id.to_string(),
        "arguments_digest": arguments_digest.to_string(),
    });
    Digest::hash(&serde_json::to_vec(&seed_source).expect("serde_json serialization is infallible"))
}

fn derived_approval_id(
    class: &str,
    invocation: &ToolInvocation,
    seed: &Digest,
    attempt: u32,
) -> Result<ApprovalId, HostToolOperationError> {
    ApprovalId::new(if attempt == 0 {
        format!("approval:{class}:{}:{seed}", invocation.capability_id)
    } else {
        format!(
            "approval:{class}:{}:{seed}-{attempt}",
            invocation.capability_id
        )
    })
    .map_err(HostToolOperationError::Identity)
}

/// A retry without a valid selector may adopt an Approved row for the same target, capability, and arguments.
/// Consumed approvals are handled only by exact-command recovery.
fn adopt_decided_approval(
    ledger: &Ledger,
    invocation: &mut ToolInvocation,
    effect_class: EffectClass,
    owner_preview: bool,
) -> Result<(), HostToolOperationError> {
    if let Some(presented) = invocation.approval_id.as_ref() {
        if ledger.approval(presented)?.is_some() {
            return Ok(());
        }
    }
    let mut base = invocation.arguments.clone();
    let Some(object) = base.as_object_mut() else {
        return Ok(());
    };
    object.remove("approvalId");
    let seed = approval_seed(invocation, &arguments_digest(&base));
    let class = approval_class_segment(effect_class);
    for attempt in 0u32..64 {
        let approval_id = derived_approval_id(class, invocation, &seed, attempt)?;
        let Some(row) = ledger.approval(&approval_id)? else {
            return Ok(());
        };
        let mut retry = base.clone();
        if let Some(object) = retry.as_object_mut() {
            object.insert(
                "approvalId".to_owned(),
                Value::String(approval_id.to_string()),
            );
        }
        let exact = row.scope.target_kind == invocation.target.kind
            && row.scope.target_id == invocation.target.id
            && row.scope.capability_id == invocation.capability_id
            && row.scope.arguments_digest == arguments_digest(&retry);
        let unproven = odin_ledger::approval::requires_owner_preview(&row.scope, owner_preview)
            && !row
                .decided_by
                .as_deref()
                .is_some_and(|actor| actor.starts_with("grant:"))
            && !ledger.approval_has_owner_decision(&row, owner_preview)?;
        if exact && row.status == ApprovalStatus::Approved && !unproven {
            invocation.arguments_digest = arguments_digest(&retry);
            invocation.arguments = retry;
            invocation.expected_revision = Some(row.revision);
            invocation.approval_id = Some(approval_id);
            return Ok(());
        }
    }
    Ok(())
}

/// Mints — or adopts — the durable exact-scope approval request for one
/// gated dispatch (mandatory R3, or a contract that declares operator
/// approval) the gate just refused for lacking an approval.
///
/// The scope includes the retry's derived `approvalId`, not just the first call's arguments.
/// Identical requests reuse a row; terminal rows get a new suffix and require a new decision.
fn mint_approval_request(
    ledger: &mut Ledger,
    invocation: &ToolInvocation,
    effect_class: EffectClass,
    issuer: &str,
    decider: Option<&str>,
    now_ms: u64,
    owner_preview: bool,
) -> Result<(ApprovalId, i64, ApprovalStatus), HostToolOperationError> {
    let class = approval_class_segment(effect_class);
    let now = OffsetDateTime::from_unix_timestamp_nanos(i128::from(now_ms) * 1_000_000).map_err(
        |error| HostToolOperationError::Arguments {
            detail: format!("dispatch clock is not a valid timestamp: {error}"),
        },
    )?;
    let seed = approval_seed(invocation, &invocation.arguments_digest);
    for attempt in 0u32..64 {
        let approval_id = derived_approval_id(class, invocation, &seed, attempt)?;
        let mut retry_arguments = invocation.arguments.clone();
        let Some(retry_object) = retry_arguments.as_object_mut() else {
            return Err(HostToolOperationError::Arguments {
                detail: "gated approval retry arguments must be a JSON object".to_owned(),
            });
        };
        retry_object.insert(
            "approvalId".to_owned(),
            Value::String(approval_id.to_string()),
        );
        let scope = ApprovalScope {
            target_kind: invocation.target.kind.clone(),
            target_id: invocation.target.id.clone(),
            capability_id: invocation.capability_id.clone(),
            arguments_digest: arguments_digest(&retry_arguments),
        };
        if let Some(existing) = ledger.approval(&approval_id)? {
            if existing.scope != scope || existing.issuer != issuer {
                return Err(HostToolOperationError::Ledger(LedgerError::invalid_data(
                    format!(
                        "derived approval identity {approval_id} collides with a different \
                         durable scope; refusing to reinterpret the stored record"
                    ),
                )));
            }
            // An old artificial grant decision, or consent that never saw
            // the complete preview, cannot be adopted as a fresh owner
            // request after its provenance or exact batch has failed.
            if decider.is_none() && existing.status == ApprovalStatus::Approved {
                let grant = existing
                    .decided_by
                    .as_deref()
                    .is_some_and(|actor| actor.starts_with("grant:"));
                let unproven = !grant
                    && odin_ledger::approval::requires_owner_preview(
                        &existing.scope,
                        owner_preview,
                    )
                    && !ledger.approval_has_owner_decision(&existing, owner_preview)?;
                if unproven {
                    tracing::error!(
                        "odin-omp: approval {} for {} was decided without its complete delivered \
                         preview and cannot authorize; asking the owner anew",
                        existing.approval_id,
                        invocation.capability_id
                    );
                }
                if grant || unproven {
                    continue;
                }
            }
            if matches!(
                existing.status,
                ApprovalStatus::Requested | ApprovalStatus::Approved
            ) {
                return Ok((existing.approval_id, existing.revision, existing.status));
            }
            // Terminal rows never resurrect: roll to a fresh suffix.
            continue;
        }
        let request = NewApproval {
            approval_id: approval_id.clone(),
            issuer: issuer.to_owned(),
            scope: scope.clone(),
            requested_at: now,
            expires_at: now + MINTED_REQUEST_TTL,
        };
        let requested = match decider {
            None => ledger.request_approval(request),
            Some(decider) => ledger
                .request_decided_approval(
                    request,
                    odin_ledger::approval::ApprovalDecision::Approve {
                        evidence_ref: Some(decider.to_owned()),
                    },
                    decider,
                    now,
                )
                .and_then(|outcome| match outcome {
                    odin_ledger::approval::DecideApproval::Decided(approval) => Ok(approval),
                    odin_ledger::approval::DecideApproval::NotFound
                    | odin_ledger::approval::DecideApproval::NotRequested(_)
                    | odin_ledger::approval::DecideApproval::PreviewRequired(_) => {
                        Err(LedgerError::invalid_data(format!(
                            "the {decider} decision for {approval_id} found no fresh request"
                        )))
                    }
                }),
        };
        return match requested {
            Ok(approval) => Ok((approval.approval_id, approval.revision, approval.status)),
            Err(insert_error) => {
                // Adopt a concurrent identical insert; otherwise preserve the insert error.
                let Some(existing) = ledger.approval(&approval_id)? else {
                    tracing::error!(
                        "odin-omp: approval request insert failed approval={approval_id} \
                         capability={} reason={insert_error}",
                        invocation.capability_id
                    );
                    return Err(HostToolOperationError::Ledger(insert_error));
                };
                if existing.scope == scope && existing.issuer == issuer {
                    Ok((existing.approval_id, existing.revision, existing.status))
                } else {
                    Err(HostToolOperationError::Ledger(LedgerError::invalid_data(
                        "concurrent approval insert conflicts with the derived scope".to_owned(),
                    )))
                }
            }
        };
    }
    Err(HostToolOperationError::Composition {
        detail: "the minted approval identity space for this scope is exhausted".to_owned(),
    })
}

/// Shapes one capability-bound dispatch's model arguments at the single
/// host seam before digesting, journaling, or executing them.
///
/// Two normalizations run here, both in the same order for every
/// capability-bound dispatch:
///
/// * A contract that declares an exact delegation target carries the
///   canonical [`CapabilityContract::DELEGATION_TARGET_ARGUMENT`] string —
///   the declared target seat — in its authorized arguments. The public
///   model surface omits the key, so the trusted host derives it from the
///   resolved contract before the arguments are digested, journaled, or
///   approval-gated: an approval scope minted under one target can never
///   authorize a dispatch whose declaration later names a different
///   target. A supplied value is a claim about the same declaration and is
///   never corrected — one that disagrees with the contract is a typed
///   argument rejection, and a matching supplied value is preserved
///   verbatim so canonical replay input stays byte-identical.
/// * The resolved `capsule.eval.run` capability's public model surface
///   omits `source_sha256`, so the trusted host derives it here from the
///   exact UTF-8 bytes of the model-supplied `source`. A supplied digest
///   is a claim about the same bytes and is never corrected — one that
///   disagrees with the observed source is a typed argument rejection.
///
/// Every other argument passes through untouched, and a payload this seam
/// cannot digest (a non-object, or a missing or non-string `source`) is
/// left for the canonical input schema to reject.
pub(super) fn normalize_capability_arguments(
    contract: &CapabilityContract,
    mut arguments: Value,
) -> Result<Value, HostToolOperationError> {
    if let Some(target) = &contract.delegate_to {
        if let Some(object) = arguments.as_object_mut() {
            let key = CapabilityContract::DELEGATION_TARGET_ARGUMENT;
            match object.get(key) {
                Some(Value::String(declared)) if declared != target.as_str() => {
                    return Err(HostToolOperationError::Arguments {
                        detail: format!(
                            "{key} mismatch: declared {declared}, contract target {}",
                            target.as_str()
                        ),
                    });
                }
                Some(_) => {}
                None => {
                    object.insert(key.to_owned(), Value::String(target.as_str().to_owned()));
                }
            }
        }
    }
    if contract.id.as_str()
        != crate::host_tools::CanonicalV2CapabilityBinding::EvalRun.capability_id()
    {
        return Ok(arguments);
    }
    let Some(object) = arguments.as_object_mut() else {
        return Ok(arguments);
    };
    let observed = match object.get("source") {
        Some(Value::String(source)) => sha256_hex(source.as_bytes()).to_string(),
        _ => return Ok(arguments),
    };
    match object.get("source_sha256") {
        Some(Value::String(declared)) if *declared != observed => {
            return Err(HostToolOperationError::Arguments {
                detail: format!(
                    "source_sha256 mismatch: declared {declared}, source digest {observed}"
                ),
            });
        }
        Some(_) => {}
        None => {
            object.insert("source_sha256".to_owned(), Value::String(observed));
        }
    }
    Ok(arguments)
}

/// Selects the ledger-safe logical target for one host-bound dispatch.
///
/// Capability-bound bridge calls are run work: a targetless scope cannot be
/// approved or journaled as an exact invocation.
pub(super) fn invocation_target(scope: &Scope) -> Result<InvocationTarget, HostToolOperationError> {
    let run = scope
        .run
        .as_ref()
        .ok_or_else(|| HostToolOperationError::Arguments {
            detail: "capability-bound dispatch scope must bind a run target".to_owned(),
        })?;
    Ok(InvocationTarget {
        kind: "run".to_owned(),
        id: run.as_str().to_owned(),
    })
}

/// Adapter permits carry no host scope: their backend receives only declared argv and validated input.
fn host_executor_binding(
    contract: &odin_kernel::CapabilityContract,
    scope: &Scope,
    execution: Option<&crate::uri::ExecutionBinding>,
) -> Result<Option<Value>, HostToolOperationError> {
    if contract.adapter.is_some() {
        return Ok(None);
    }
    executor_binding(scope, execution).map(Some)
}

/// Canonicalizes the complete host-owned dispatch scope and the caller-
/// carried bridge execution proof for the executor's digest-bound durable
/// binding. Both are data, never ledger identifiers; the proof travels
/// exactly as the host captured it, so a replayed operation re-decodes the
/// same proof instead of re-deriving one from current ledger state.
pub(super) fn executor_binding(
    scope: &Scope,
    execution: Option<&crate::uri::ExecutionBinding>,
) -> Result<Value, HostToolOperationError> {
    let envelope = crate::host_tools::executor::DurableExecutorBinding {
        scope: scope.clone(),
        execution: execution.cloned(),
    };
    let value =
        serde_json::to_value(&envelope).map_err(|error| HostToolOperationError::Arguments {
            detail: format!("dispatch scope is not serializable: {error}"),
        })?;
    let canonical = odin_strict_json::canonicalize(&value).map_err(|error| {
        HostToolOperationError::Arguments {
            detail: format!("dispatch scope is not canonicalizable: {error}"),
        }
    })?;
    serde_json::from_slice(&canonical).map_err(|error| HostToolOperationError::Arguments {
        detail: format!("canonical dispatch scope is not decodable: {error}"),
    })
}

/// Journals the exact dispatch intent as the durable command row that an
/// approval consumption names: `approvals.consumed_by_command_id` is a
/// foreign key into `commands`, so an approval can only ever be consumed by
/// a command that was journaled first. The spec carries the real
/// correlation-derived idempotency claim, arguments digest, capability
/// identity, and logical target — never a placeholder — and expires with
/// the fresh seat authority that produced it. An identical retry claims the
/// same row and journals nothing new; a different payload, capability, or
/// target under one correlation is a hard durable conflict that fails
/// before any approval is consumed, so an approval can never be spent by a
/// command whose journaled intent differs from the authorized invocation.
pub(super) fn journal_invocation_command(
    ledger: &mut Ledger,
    invocation: &ToolInvocation,
    correlation_id: &CorrelationId,
    fresh: &FreshAuthority,
    now_ms: u64,
) -> Result<(), HostToolOperationError> {
    let authority = fresh.get();
    let spec = CommandSpec {
        id: invocation.command_id.clone(),
        idempotency_key: invocation.command_id.to_string(),
        correlation_id: correlation_id.as_str().to_owned(),
        causation_id: None,
        issuer: authority.seat().as_str().to_owned(),
        approval_id: invocation.approval_id.clone(),
        target_kind: invocation.target.kind.clone(),
        target_id: invocation.target.id.clone(),
        capability_id: invocation.capability_id.clone(),
        capability_version: i64::from(invocation.capability_version),
        arguments_hash: invocation.arguments_digest,
        arguments: invocation.arguments.clone(),
        expected_desired_revision: invocation.expected_revision,
        issued_at: unix_ms(now_ms)?,
        expires_at: unix_ms(authority.expires_at_ms())?,
    };
    match ledger.record_command(&spec)? {
        RecordCommand::Inserted(_) => Ok(()),
        RecordCommand::Existing(recorded) => {
            let stored = recorded.command();
            // The kernel replays or conflicts a correlation on exactly the
            // request identity it binds durably; the journal must never
            // conflict an identical retry and must never conceal a
            // conflicting one.
            if stored.arguments_hash != invocation.arguments_digest
                || stored.capability_id != invocation.capability_id
                || stored.capability_version != i64::from(invocation.capability_version)
                || stored.target_kind != invocation.target.kind
                || stored.target_id != invocation.target.id
            {
                return Err(HostToolOperationError::Authority(
                    OperationRejection::DuplicateConflict {
                        correlation_id: correlation_id.clone(),
                    },
                ));
            }
            Ok(())
        }
    }
}

/// Host clock milliseconds as a durable ledger timestamp.
fn unix_ms(now_ms: u64) -> Result<OffsetDateTime, HostToolOperationError> {
    let detail = "dispatch clock is not representable as a ledger timestamp";
    let milliseconds = i64::try_from(now_ms).map_err(|_| HostToolOperationError::Composition {
        detail: detail.to_owned(),
    })?;
    OffsetDateTime::UNIX_EPOCH
        .checked_add(time::Duration::milliseconds(milliseconds))
        .ok_or_else(|| HostToolOperationError::Composition {
            detail: detail.to_owned(),
        })
}

/// Asking a conversation seat is an escalation, not a nested worker delegation.
pub(super) fn delegates_beyond_depth(
    contract: &CapabilityContract,
    escalation_targets: &std::collections::BTreeSet<odin_domain::SeatId>,
) -> bool {
    contract.id.as_str() == crate::host_tools::delegation::TASK_CREATE_CAPABILITY
        || contract
            .delegate_to
            .as_ref()
            .is_some_and(|target| !escalation_targets.contains(target))
}

#[cfg(test)]
mod adapter_binding_tests {
    use super::*;

    #[test]
    fn an_adapter_permit_carries_no_host_executor_binding() {
        let mut contract = super::super::production_operation_dispatch::fixture::contract(
            "time.get_current_time",
            "time_get_current_time",
            odin_adapter_core::ADAPTER_OPERATION_HANDLER,
            odin_adapter_core::ADAPTER_RECEIPT_EVIDENCE,
            odin_domain::EffectClass::R0,
        );
        let scope = Scope::default();
        assert!(
            host_executor_binding(&contract, &scope, None)
                .expect("host binding")
                .is_some(),
            "a host-tool permit keeps its dispatch scope"
        );
        contract.adapter = Some("mcp-time".to_owned());
        assert_eq!(
            host_executor_binding(&contract, &scope, None).expect("adapter binding"),
            None,
            "an adapter permit carries no executor binding"
        );
    }
}
