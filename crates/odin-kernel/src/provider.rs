//! Provider changes occur only between requests, so active requests retain their lease.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use odin_domain::{Digest, LaneId, LeaseId, ProviderId};
use odin_ledger::provider_lease::{
    NewProviderLease, ProviderLease, ProviderLeaseBoundary, ProviderLeaseEnd,
};
use odin_ledger::Ledger;
use odin_registry::{
    RegistryKind, RegistryObject, ResolvedBudgetPolicy, ResolvedProviderPolicy,
    ResolvedRecoveryPolicy,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::{Duration, OffsetDateTime};

pub const PROVIDER_STATUS_SCHEMA: &str = "odin.providers.status.v1";

static LEASE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Lease expiry does not end a lease; rotation requires an explicit boundary.
const LEASE_TTL: Duration = Duration::hours(24);

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("provider candidate {provider} does not name a registry provider object")]
    UnknownProvider { provider: ProviderId },
    #[error("provider spend budget is exhausted until logical second {eligible_at}")]
    BudgetExhausted { eligible_at: u64 },
    #[error("provider candidate {provider} names a disabled registry provider object")]
    DisabledProvider { provider: ProviderId },
    #[error("provider candidate {provider} field {field} must not be empty")]
    EmptyCandidateField {
        provider: ProviderId,
        field: &'static str,
    },
    #[error(
        "provider candidate {provider} account {account} model {model} is already a candidate"
    )]
    DuplicateCandidate {
        provider: ProviderId,
        account: String,
        model: String,
    },
    #[error("request id must not be empty")]
    EmptyRequestId,
    #[error("request {request} has no active binding")]
    UnknownRequest { request: String },
    #[error("request binding provider {provider} account {account} model {model} is not a configured candidate")]
    UnknownBindingCandidate {
        provider: ProviderId,
        account: String,
        model: String,
    },
    #[error("provider fault window must end after the fault time")]
    InvalidFaultWindow,
    #[error("provider rotation end reason must not be empty")]
    EmptyEndReason,
    #[error("lane {lane} has no eligible provider candidate ({detail})")]
    NoEligibleCandidate { lane: LaneId, detail: String },
    #[error("lane {lane} still has {count} active request(s) on the predecessor; rotation is boundary-only")]
    RequestsActive { lane: LaneId, count: usize },
    #[error("lane {lane} has no active provider lease")]
    NoActiveLease { lane: LaneId },
    #[error("provider lease {lease} disappeared after atomic rotation")]
    LeaseDisappeared { lease: LeaseId },
    #[error("provider lease identity is invalid: {0}")]
    InvalidLeaseId(String),
    #[error("quota snapshot JSON is invalid: {0}")]
    QuotaSnapshot(#[from] serde_json::Error),
    #[error(transparent)]
    Domain(#[from] odin_domain::DomainError),
    #[error(transparent)]
    Ledger(#[from] odin_ledger::LedgerError),
    #[error(transparent)]
    Budget(#[from] odin_ledger::budget::BudgetError),
}

pub type ProviderResult<T> = Result<T, ProviderError>;

/// Eligibility timestamps keep exhausted candidates out of selection without retrying.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "fault", rename_all = "snake_case")]
pub enum ProviderFault {
    QuotaExhausted {
        resets_at: OffsetDateTime,
    },
    /// The gateway answered HTTP 429; the account is rate limited until then.
    RateLimited {
        until: OffsetDateTime,
    },
    Cooldown {
        until: OffsetDateTime,
    },
    Unavailable {
        until: OffsetDateTime,
        reason: String,
    },
}

impl ProviderFault {
    pub fn ready_at(&self) -> OffsetDateTime {
        match self {
            Self::QuotaExhausted { resets_at } => *resets_at,
            Self::RateLimited { until } | Self::Cooldown { until } => *until,
            Self::Unavailable { until, .. } => *until,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::QuotaExhausted { .. } => "exhausted",
            Self::RateLimited { .. } | Self::Cooldown { .. } => "cooling",
            Self::Unavailable { .. } => "unavailable",
        }
    }

    fn from_health(health: &ProviderHealth, reason: &str) -> Option<Self> {
        match *health {
            ProviderHealth::Cooling { until } => Some(Self::Cooldown { until }),
            ProviderHealth::Exhausted { resets_at } => Some(Self::QuotaExhausted { resets_at }),
            ProviderHealth::Unavailable { until } => Some(Self::Unavailable {
                until,
                reason: reason.to_owned(),
            }),
            ProviderHealth::Available | ProviderHealth::Unknown => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProviderHealth {
    Available,
    Cooling {
        until: OffsetDateTime,
    },
    Exhausted {
        resets_at: OffsetDateTime,
    },
    Unavailable {
        until: OffsetDateTime,
    },
    /// The stored snapshot carries no parsable health (foreign or legacy row).
    Unknown,
}

impl ProviderHealth {
    pub fn eligible_at(&self, now: OffsetDateTime) -> bool {
        match self {
            Self::Available => true,
            Self::Cooling { until } | Self::Exhausted { resets_at: until } => now >= *until,
            Self::Unavailable { until } => now >= *until,
            // Unknown health fails closed: unvalidated snapshots never select.
            Self::Unknown => false,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Cooling { .. } => "cooling",
            Self::Exhausted { .. } => "exhausted",
            Self::Unavailable { .. } => "unavailable",
            Self::Unknown => "unknown",
        }
    }

    fn from_fault(fault: Option<&ProviderFault>) -> Self {
        match fault {
            None => Self::Available,
            Some(ProviderFault::QuotaExhausted { resets_at }) => Self::Exhausted {
                resets_at: *resets_at,
            },
            Some(ProviderFault::RateLimited { until } | ProviderFault::Cooldown { until }) => {
                Self::Cooling { until: *until }
            }
            Some(ProviderFault::Unavailable { until, .. }) => Self::Unavailable { until: *until },
        }
    }
}

/// Canonical serialization gives identical quota state identical persisted bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderQuotaSnapshot {
    pub health: ProviderHealth,
    /// Remaining request units when the account exposes a count.
    pub remaining: Option<u64>,
    pub updated_at: OffsetDateTime,
}

impl ProviderQuotaSnapshot {
    pub fn to_value(&self) -> ProviderResult<serde_json::Value> {
        Ok(serde_json::to_value(self)?)
    }

    pub fn from_value(value: &serde_json::Value) -> ProviderResult<Self> {
        Ok(serde_json::from_value(value.clone())?)
    }
}

/// Account handles are references, not credentials; registry authentication stays out of leases.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProviderCandidate {
    pub provider: ProviderId,
    pub account_handle: String,
    pub model: String,
    pub role: String,
    pub affinity_key: String,
    /// Lower binds first; ties break on affinity, provider, account, model.
    pub priority: u32,
}

impl ProviderCandidate {
    pub fn new(
        provider: ProviderId,
        account_handle: impl Into<String>,
        model: impl Into<String>,
        role: impl Into<String>,
        affinity_key: impl Into<String>,
        priority: u32,
    ) -> ProviderResult<Self> {
        let candidate = Self {
            provider,
            account_handle: account_handle.into(),
            model: model.into(),
            role: role.into(),
            affinity_key: affinity_key.into(),
            priority,
        };
        for (field, value) in [
            ("account", &candidate.account_handle),
            ("model", &candidate.model),
            ("role", &candidate.role),
            ("affinity", &candidate.affinity_key),
        ] {
            if value.trim().is_empty() {
                return Err(ProviderError::EmptyCandidateField {
                    provider: candidate.provider.clone(),
                    field,
                });
            }
        }
        Ok(candidate)
    }

    pub fn matches(&self, provider: &ProviderId, account_handle: &str, model: &str) -> bool {
        &self.provider == provider && self.account_handle == account_handle && self.model == model
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProviderCandidateState {
    pub candidate: ProviderCandidate,
    /// Latest terminal fault, if any. Replaced, never accumulated.
    pub fault: Option<ProviderFault>,
    pub remaining: Option<u64>,
}

impl ProviderCandidateState {
    pub fn health_at(&self, now: OffsetDateTime) -> ProviderHealth {
        let health = ProviderHealth::from_fault(self.fault.as_ref());
        if health.eligible_at(now) {
            ProviderHealth::Available
        } else {
            health
        }
    }

    pub fn eligible_at(&self, now: OffsetDateTime) -> bool {
        self.fault
            .as_ref()
            .is_none_or(|fault| now >= fault.ready_at())
    }

    pub fn snapshot_at(&self, now: OffsetDateTime) -> ProviderQuotaSnapshot {
        ProviderQuotaSnapshot {
            health: self.health_at(now),
            remaining: self.remaining,
            updated_at: now,
        }
    }
}

/// Faults attach to a request without changing the lease it started with.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestBinding {
    pub request_id: String,
    pub lane: LaneId,
    pub lease_id: LeaseId,
    pub lease_revision: i64,
    pub provider: ProviderId,
    pub account_handle: String,
    pub model: String,
    pub role: String,
    pub affinity_key: String,
    pub started_at: OffsetDateTime,
    pub expires_at: Option<OffsetDateTime>,
    pub registry_revision: u64,
    pub policy_digest: Digest,
    pub projection_digest: Digest,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProviderFaultRecord {
    pub binding: RequestBinding,
    pub fault: ProviderFault,
    pub snapshot: ProviderQuotaSnapshot,
    pub eligible_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ProviderRotation {
    /// The predecessor ended and its successor began in one transaction.
    Rotated {
        predecessor: Box<ProviderLease>,
        successor: Box<ProviderLease>,
    },
    /// The best eligible candidate is the active binding; nothing ended.
    Unchanged { active: Box<ProviderLease> },
}

/// Restarts reuse the active lease and seed candidate state from its creation snapshot.
pub struct ProviderLeaseCoordinator {
    lane: LaneId,
    affinity_key: Option<String>,
    candidates: Vec<ProviderCandidateState>,
    requests: BTreeMap<String, RequestBinding>,
    registry_revision: u64,
    policy_digest: Digest,
    projection_digest: Digest,
    budget: Option<ResolvedBudgetPolicy>,
    recovery: Option<ResolvedRecoveryPolicy>,
}

impl ProviderLeaseCoordinator {
    pub(crate) fn new(
        lane: LaneId,
        objects: &[RegistryObject],
        affinity_key: Option<String>,
        candidates: impl IntoIterator<Item = ProviderCandidate>,
    ) -> ProviderResult<Self> {
        let states = build_candidate_states(objects, candidates)?;
        if states.is_empty() {
            return Err(ProviderError::NoEligibleCandidate {
                lane: lane.clone(),
                detail: "no candidates configured".to_owned(),
            });
        }
        let mut coordinator = Self {
            lane,
            affinity_key,
            candidates: states,
            requests: BTreeMap::new(),
            registry_revision: 0,
            policy_digest: Digest::hash(b"kernel-test-provider-policy"),
            projection_digest: Digest::hash(b"kernel-test-gateway-projection"),
            budget: None,
            recovery: None,
        };
        coordinator.sort_candidates();
        Ok(coordinator)
    }

    pub fn from_resolved_policy(
        lane: LaneId,
        objects: &[RegistryObject],
        affinity_key: Option<String>,
        policy: &ResolvedProviderPolicy,
    ) -> ProviderResult<Self> {
        ProviderCoordinatorTemplate::from_resolved_policy(objects, affinity_key, policy)?
            .for_lane(lane)
    }

    pub fn recovery_policy(&self) -> Option<&ResolvedRecoveryPolicy> {
        self.recovery.as_ref()
    }

    /// Reads externally written budget status; per-attempt budget enforcement belongs to the gateway.
    fn enforce_budget(&self, ledger: &Ledger, now: OffsetDateTime) -> ProviderResult<()> {
        let Some(policy) = &self.budget else {
            return Ok(());
        };
        let duration = policy.policy.window.duration_seconds.get();
        let window_start = (now.unix_timestamp().max(0) as u64) / duration * duration;
        match odin_ledger::budget::budget_status(
            ledger,
            &policy.scope,
            window_start,
            policy.policy_digest,
        )? {
            None => Ok(()),
            Some(status) => match status.disposition {
                odin_ledger::budget::BudgetDisposition::Eligible => Ok(()),
                odin_ledger::budget::BudgetDisposition::Exhausted { eligible_at } => {
                    Err(ProviderError::BudgetExhausted { eligible_at })
                }
            },
        }
    }

    /// Restore from the immutable lease snapshot; request-local faults do not alter it.
    pub fn restore(
        ledger: &Ledger,
        lane: LaneId,
        objects: &[RegistryObject],
        affinity_key: Option<String>,
        candidates: impl IntoIterator<Item = ProviderCandidate>,
    ) -> ProviderResult<Self> {
        let mut coordinator = Self::new(lane, objects, affinity_key, candidates)?;
        if let Some(lease) = ledger.active_provider_lease_for_lane(&coordinator.lane)? {
            if let Ok(snapshot) = ProviderQuotaSnapshot::from_value(&lease.quota_snapshot) {
                for state in &mut coordinator.candidates {
                    if state.candidate.matches(
                        &lease.provider_id,
                        &lease.account_handle,
                        &lease.model,
                    ) {
                        state.remaining = snapshot.remaining;
                        state.fault =
                            ProviderFault::from_health(&snapshot.health, "restored from ledger");
                    }
                }
            }
        }
        Ok(coordinator)
    }

    pub fn lane(&self) -> &LaneId {
        &self.lane
    }

    pub fn candidates(&self) -> &[ProviderCandidateState] {
        &self.candidates
    }

    pub fn binding(&self, request_id: &str) -> Option<&RequestBinding> {
        self.requests.get(request_id)
    }

    /// Duplicate request IDs reuse their binding without touching the ledger.
    pub fn begin_request(
        &mut self,
        ledger: &mut Ledger,
        request_id: impl Into<String>,
        now: OffsetDateTime,
    ) -> ProviderResult<RequestBinding> {
        let request_id = request_id.into();
        if request_id.trim().is_empty() {
            return Err(ProviderError::EmptyRequestId);
        }
        if let Some(binding) = self.requests.get(&request_id) {
            return Ok(binding.clone());
        }
        self.enforce_budget(ledger, now)?;

        let binding = match ledger.active_provider_lease_for_lane(&self.lane)? {
            Some(lease) => request_binding(
                &request_id,
                &lease,
                self.registry_revision,
                self.policy_digest,
                self.projection_digest,
            ),
            None => {
                let state = self.select(now)?;
                let lease = ledger.start_provider_lease(NewProviderLease {
                    lease_id: mint_lease_id(now)?,
                    lane_id: self.lane.clone(),
                    provider_id: state.candidate.provider.clone(),
                    account_handle: state.candidate.account_handle.clone(),
                    model: state.candidate.model.clone(),
                    role: state.candidate.role.clone(),
                    affinity_key: state.candidate.affinity_key.clone(),
                    quota_snapshot: state.snapshot_at(now).to_value()?,
                    selection_reason: selection_reason(state, "lane-start"),
                    started_at: now,
                    expires_at: Some(now + LEASE_TTL),
                })?;
                request_binding(
                    &request_id,
                    &lease,
                    self.registry_revision,
                    self.policy_digest,
                    self.projection_digest,
                )
            }
        };
        self.requests.insert(request_id, binding.clone());
        Ok(binding)
    }

    /// Updating a candidate fault must not change an active request's binding.
    pub fn record_fault(
        &mut self,
        request_id: &str,
        fault: ProviderFault,
        now: OffsetDateTime,
    ) -> ProviderResult<ProviderFaultRecord> {
        if fault.ready_at() <= now {
            return Err(ProviderError::InvalidFaultWindow);
        }
        let binding = self.requests.get(request_id).cloned().ok_or_else(|| {
            ProviderError::UnknownRequest {
                request: request_id.to_owned(),
            }
        })?;
        let state = self.state_for(&binding)?;
        if matches!(fault, ProviderFault::QuotaExhausted { .. }) {
            state.remaining = Some(0);
        }
        state.fault = Some(fault.clone());
        Ok(ProviderFaultRecord {
            eligible_at: fault.ready_at(),
            snapshot: state.snapshot_at(now),
            binding,
            fault,
        })
    }

    pub fn finish_request(&mut self, request_id: &str) -> ProviderResult<RequestBinding> {
        self.requests
            .remove(request_id)
            .ok_or_else(|| ProviderError::UnknownRequest {
                request: request_id.to_owned(),
            })
    }

    /// Rotation refuses active requests and leaves the lease unchanged if its candidate still wins.
    pub fn rotate_at_boundary(
        &mut self,
        ledger: &mut Ledger,
        end: ProviderLeaseEnd,
        now: OffsetDateTime,
    ) -> ProviderResult<ProviderRotation> {
        if end.reason.trim().is_empty() {
            return Err(ProviderError::EmptyEndReason);
        }
        if !self.requests.is_empty() {
            return Err(ProviderError::RequestsActive {
                lane: self.lane.clone(),
                count: self.requests.len(),
            });
        }
        let predecessor = ledger
            .active_provider_lease_for_lane(&self.lane)?
            .ok_or_else(|| ProviderError::NoActiveLease {
                lane: self.lane.clone(),
            })?;
        let state = self.select(now)?;
        if state.candidate.matches(
            &predecessor.provider_id,
            &predecessor.account_handle,
            &predecessor.model,
        ) {
            return Ok(ProviderRotation::Unchanged {
                active: Box::new(predecessor),
            });
        }

        let boundary = boundary_label(end.boundary);
        let predecessor_id = predecessor.lease_id.clone();
        let successor = ledger.rotate_provider_lease_at_boundary(
            &predecessor_id,
            predecessor.revision,
            now,
            end,
            NewProviderLease {
                lease_id: mint_lease_id(now)?,
                lane_id: self.lane.clone(),
                provider_id: state.candidate.provider.clone(),
                account_handle: state.candidate.account_handle.clone(),
                model: state.candidate.model.clone(),
                role: state.candidate.role.clone(),
                affinity_key: state.candidate.affinity_key.clone(),
                quota_snapshot: state.snapshot_at(now).to_value()?,
                selection_reason: selection_reason(state, boundary),
                started_at: now,
                expires_at: Some(now + LEASE_TTL),
            },
        )?;
        let predecessor = ledger.provider_lease_by_id(&predecessor_id)?.ok_or(
            ProviderError::LeaseDisappeared {
                lease: predecessor_id,
            },
        )?;
        Ok(ProviderRotation::Rotated {
            predecessor: Box::new(predecessor),
            successor: Box::new(successor),
        })
    }

    fn select(&self, now: OffsetDateTime) -> ProviderResult<&ProviderCandidateState> {
        self.candidates
            .iter()
            .find(|state| state.eligible_at(now))
            .ok_or_else(|| ProviderError::NoEligibleCandidate {
                lane: self.lane.clone(),
                detail: if self.candidates.is_empty() {
                    "no candidates configured".to_owned()
                } else {
                    exclusion_detail(&self.candidates, now)
                },
            })
    }

    fn state_for(
        &mut self,
        binding: &RequestBinding,
    ) -> ProviderResult<&mut ProviderCandidateState> {
        self.candidates
            .iter_mut()
            .find(|state| {
                state
                    .candidate
                    .matches(&binding.provider, &binding.account_handle, &binding.model)
            })
            .ok_or_else(|| ProviderError::UnknownBindingCandidate {
                provider: binding.provider.clone(),
                account: binding.account_handle.clone(),
                model: binding.model.clone(),
            })
    }

    fn sort_candidates(&mut self) {
        sort_candidate_states(&mut self.candidates, self.affinity_key.as_deref());
    }
}

/// Share ordering with the template so both construction paths select the same candidate.
fn sort_candidate_states(states: &mut [ProviderCandidateState], affinity_key: Option<&str>) {
    states.sort_by_cached_key(|state| {
        let candidate = &state.candidate;
        (
            candidate.priority,
            u8::from(affinity_key != Some(candidate.affinity_key.as_str())),
            candidate.affinity_key.clone(),
            candidate.provider.to_string(),
            candidate.account_handle.clone(),
            candidate.model.clone(),
        )
    });
}

pub fn enabled_providers(objects: &[RegistryObject]) -> Vec<ProviderId> {
    let mut providers: Vec<ProviderId> = objects
        .iter()
        .filter(|object| object.kind() == RegistryKind::Provider && object.enabled())
        .filter_map(|object| ProviderId::new(object.id.clone()).ok())
        .collect();
    providers.sort();
    providers
}

#[derive(Clone, Debug, Serialize)]
pub struct ProviderLeaseStatus {
    pub lease_id: LeaseId,
    pub provider: ProviderId,
    pub account_handle: String,
    pub model: String,
    pub role: String,
    pub affinity_key: String,
    pub revision: i64,
    pub predecessor: Option<LeaseId>,
    pub started_at: OffsetDateTime,
    pub expires_at: Option<OffsetDateTime>,
    pub ended_at: Option<OffsetDateTime>,
    pub end: Option<ProviderLeaseEnd>,
    pub selection_reason: String,
    /// The stored quota snapshot, verbatim.
    pub quota_snapshot: serde_json::Value,
    /// Health derived from the snapshot at generation time.
    pub health: ProviderHealth,
    /// Whether the binding could receive a new request now.
    pub eligible: bool,
    /// Whether the registry still enables this lease's provider.
    pub provider_enabled: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProviderLaneStatus {
    pub lane: LaneId,
    pub active: Option<ProviderLeaseStatus>,
    /// Complete lease lineage, oldest first.
    pub lineage: Vec<ProviderLeaseStatus>,
}

/// Excludes credentials, authentication references, base URLs, and adapter details.
#[derive(Clone, Debug, Serialize)]
pub struct ProviderStatusSnapshot {
    pub schema: &'static str,
    pub generated_at: OffsetDateTime,
    pub providers: Vec<ProviderId>,
    pub lanes: Vec<ProviderLaneStatus>,
}

/// Without a lane filter, includes every lane with at least one provider lease.
pub fn provider_status_snapshot(
    ledger: &Ledger,
    objects: &[RegistryObject],
    now: OffsetDateTime,
    lane: Option<&LaneId>,
) -> ProviderResult<ProviderStatusSnapshot> {
    let providers = enabled_providers(objects);
    let lanes = match lane {
        Some(lane) => vec![lane.clone()],
        None => ledger.provider_lease_lanes()?,
    };
    let mut statuses = Vec::new();
    for lane_id in lanes {
        let lineage = ledger.provider_leases_for_lane(&lane_id)?;
        let active = ledger.active_provider_lease_for_lane(&lane_id)?;
        statuses.push(ProviderLaneStatus {
            active: active.map(|lease| lease_status(&lease, &providers, now)),
            lineage: lineage
                .iter()
                .map(|lease| lease_status(lease, &providers, now))
                .collect(),
            lane: lane_id,
        });
    }
    statuses.sort_by(|left, right| left.lane.cmp(&right.lane));
    Ok(ProviderStatusSnapshot {
        schema: PROVIDER_STATUS_SCHEMA,
        generated_at: now,
        providers,
        lanes: statuses,
    })
}

fn lease_status(
    lease: &ProviderLease,
    providers: &[ProviderId],
    now: OffsetDateTime,
) -> ProviderLeaseStatus {
    let health = ProviderQuotaSnapshot::from_value(&lease.quota_snapshot)
        .map(|snapshot| snapshot.health)
        .unwrap_or(ProviderHealth::Unknown);
    let provider_enabled = providers
        .iter()
        .any(|provider| provider == &lease.provider_id);
    ProviderLeaseStatus {
        eligible: provider_enabled && health.eligible_at(now),
        provider_enabled,
        health,
        lease_id: lease.lease_id.clone(),
        provider: lease.provider_id.clone(),
        account_handle: lease.account_handle.clone(),
        model: lease.model.clone(),
        role: lease.role.clone(),
        affinity_key: lease.affinity_key.clone(),
        revision: lease.revision,
        predecessor: lease.predecessor_id.clone(),
        started_at: lease.started_at,
        expires_at: lease.expires_at,
        ended_at: lease.ended_at,
        end: lease.end.clone(),
        selection_reason: lease.selection_reason.clone(),
        quota_snapshot: lease.quota_snapshot.clone(),
    }
}

fn validate_candidate(
    objects: &[RegistryObject],
    candidate: &ProviderCandidate,
) -> ProviderResult<()> {
    let object = objects
        .iter()
        .find(|object| {
            object.kind() == RegistryKind::Provider && object.id == candidate.provider.as_str()
        })
        .ok_or_else(|| ProviderError::UnknownProvider {
            provider: candidate.provider.clone(),
        })?;
    if !object.enabled() {
        return Err(ProviderError::DisabledProvider {
            provider: candidate.provider.clone(),
        });
    }
    Ok(())
}

/// Validate lane-independent candidates once, before creating coordinators.
fn build_candidate_states(
    objects: &[RegistryObject],
    candidates: impl IntoIterator<Item = ProviderCandidate>,
) -> ProviderResult<Vec<ProviderCandidateState>> {
    let mut states = Vec::<ProviderCandidateState>::new();
    for candidate in candidates {
        validate_candidate(objects, &candidate)?;
        if states.iter().any(|state| {
            state.candidate.matches(
                &candidate.provider,
                &candidate.account_handle,
                &candidate.model,
            )
        }) {
            return Err(ProviderError::DuplicateCandidate {
                provider: candidate.provider.clone(),
                account: candidate.account_handle.clone(),
                model: candidate.model.clone(),
            });
        }
        states.push(ProviderCandidateState {
            candidate,
            fault: None,
            remaining: None,
        });
    }
    Ok(states)
}

/// Share validated candidates and policy so every lane uses the same selection rules.
pub struct ProviderCoordinatorTemplate {
    affinity_key: Option<String>,
    candidates: Vec<ProviderCandidateState>,
    registry_revision: u64,
    policy_digest: Digest,
    projection_digest: Digest,
    budget: Option<ResolvedBudgetPolicy>,
    recovery: Option<ResolvedRecoveryPolicy>,
}

impl ProviderCoordinatorTemplate {
    pub fn from_resolved_policy(
        objects: &[RegistryObject],
        affinity_key: Option<String>,
        policy: &ResolvedProviderPolicy,
    ) -> ProviderResult<Self> {
        let candidates = policy
            .routes
            .iter()
            .map(|route| {
                ProviderCandidate::new(
                    policy.provider_id.clone(),
                    route.account_handle.clone(),
                    route.gateway_model_id.clone(),
                    route.role.clone(),
                    route.affinity_key.clone(),
                    route.priority,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let states = build_candidate_states(objects, candidates)?;
        let mut candidates = states;
        sort_candidate_states(&mut candidates, affinity_key.as_deref());
        Ok(Self {
            affinity_key,
            candidates,
            registry_revision: policy.registry_revision,
            policy_digest: policy.policy_digest,
            projection_digest: policy.projection_digest,
            budget: policy.budget.clone(),
            recovery: Some(policy.recovery.clone()),
        })
    }

    /// Each coordinator adopts the persisted active lease rather than selecting a replacement.
    pub fn for_lane(&self, lane: LaneId) -> ProviderResult<ProviderLeaseCoordinator> {
        if self.candidates.is_empty() {
            return Err(ProviderError::NoEligibleCandidate {
                lane,
                detail: "no candidates configured".to_owned(),
            });
        }
        Ok(ProviderLeaseCoordinator {
            lane,
            affinity_key: self.affinity_key.clone(),
            candidates: self.candidates.clone(),
            requests: BTreeMap::new(),
            registry_revision: self.registry_revision,
            policy_digest: self.policy_digest,
            projection_digest: self.projection_digest,
            budget: self.budget.clone(),
            recovery: self.recovery.clone(),
        })
    }
}

fn request_binding(
    request_id: &str,
    lease: &ProviderLease,
    registry_revision: u64,
    policy_digest: Digest,
    projection_digest: Digest,
) -> RequestBinding {
    RequestBinding {
        request_id: request_id.to_owned(),
        lane: lease.lane_id.clone(),
        lease_id: lease.lease_id.clone(),
        lease_revision: lease.revision,
        provider: lease.provider_id.clone(),
        account_handle: lease.account_handle.clone(),
        model: lease.model.clone(),
        role: lease.role.clone(),
        affinity_key: lease.affinity_key.clone(),
        started_at: lease.started_at,
        expires_at: lease.expires_at,
        registry_revision,
        policy_digest,
        projection_digest,
    }
}

fn selection_reason(state: &ProviderCandidateState, boundary: &str) -> String {
    format!(
        "boundary {boundary} selected provider {} account {} model {} by priority {}",
        state.candidate.provider,
        state.candidate.account_handle,
        state.candidate.model,
        state.candidate.priority
    )
}

fn boundary_label(boundary: ProviderLeaseBoundary) -> &'static str {
    match boundary {
        ProviderLeaseBoundary::LaneStart => "lane-start",
        ProviderLeaseBoundary::Turn => "turn",
        ProviderLeaseBoundary::Attempt => "attempt",
        ProviderLeaseBoundary::Run => "run",
        ProviderLeaseBoundary::Quota => "quota",
        ProviderLeaseBoundary::Operator => "operator",
    }
}

fn exclusion_detail(states: &[ProviderCandidateState], now: OffsetDateTime) -> String {
    let mut counts = BTreeMap::new();
    for state in states {
        let kind = state
            .fault
            .as_ref()
            .filter(|fault| now < fault.ready_at())
            .map_or("unknown", ProviderFault::kind);
        *counts.entry(kind).or_insert(0usize) += 1;
    }
    counts
        .into_iter()
        .map(|(kind, count)| format!("{count} {kind}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn mint_lease_id(now: OffsetDateTime) -> ProviderResult<LeaseId> {
    let millis = u64::try_from(now.unix_timestamp().max(0)).unwrap_or(0) * 1000;
    let sequence = LEASE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let entropy = format!(
        "{}-{}-{sequence}",
        std::process::id(),
        now.unix_timestamp_nanos()
    );
    LeaseId::from_parts("provider-lease", millis, entropy)
        .map_err(|error| ProviderError::InvalidLeaseId(error.to_string()))
}

#[cfg(test)]
mod tests;
