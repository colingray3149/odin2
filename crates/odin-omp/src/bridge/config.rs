//! Bridge configuration validated before effects.

use super::*;

/// Every field is host configuration: no scope dimension ever comes from OMP
/// or model JSON. `epoch` and the lease fields are blank until [`OmpBridge::start`]
/// acquires them from the ledger; `binding()` on a started bridge returns the
/// completed record.
#[derive(Clone, Debug)]
pub struct BridgeBinding {
    /// The immutable bound scope stamped onto every host-tool invocation and
    /// URI resolution.
    pub scope: Scope,
    pub session_id: SessionId,
    pub run_id: RunId,
    pub lane_id: LaneId,
    /// The lease owner identity used for exclusion.
    pub owner_id: String,
    /// Live-session ownership epoch; `0` before start, incremented by every
    /// reclaim (start over an existing session, recover).
    pub epoch: i64,
    /// Session lease id; `None` before start.
    pub lease_id: Option<LeaseId>,
    /// Session lease expiry; `None` before start.
    pub lease_expires_at: Option<OffsetDateTime>,
}

impl BridgeBinding {
    /// Declares the binding a host intends to start. `scope` must bind the
    /// seat, project, lane, run, and session dimensions exactly (verified at
    /// start); `epoch` and the lease fields start blank.
    pub fn new(
        scope: Scope,
        session_id: SessionId,
        run_id: RunId,
        lane_id: LaneId,
        owner_id: impl Into<String>,
    ) -> Self {
        Self {
            scope,
            session_id,
            run_id,
            lane_id,
            owner_id: owner_id.into(),
            epoch: 0,
            lease_id: None,
            lease_expires_at: None,
        }
    }

    /// The dispatch scope handed to host tools and URI resolutions. Never
    /// derived from any wire input.
    pub fn dispatch_scope(&self) -> Scope {
        self.scope.clone()
    }
}

/// Durable session fields supplied by the host before model interaction.
#[derive(Clone, Debug)]
pub struct LiveSessionDescriptor {
    /// Registry slice the session is accounted to; non-empty.
    pub slice_id: String,
    /// Node the session runs against; non-empty.
    pub target_node_id: String,
    /// Provider binding recorded on the session; non-empty.
    pub provider: String,
    /// Model binding recorded on the session; non-empty.
    pub model: String,
    /// Optional human title.
    pub title: Option<String>,
    /// Whether the CLI opens a zellij tab for the session.
    pub open_tab: bool,
    /// Host-supplied manifest stored verbatim.
    pub manifest: Value,
}

#[derive(Clone)]
pub struct OmpBridgeConfig {
    /// Trusted pinned-OMP launch description. The executable path, pinned
    /// `expected_source_revision`, and the complete sanitized environment
    /// come from host configuration only.
    pub process: OmpProcessSpec,
    /// Sole StopAuthority launch/stop contract for the pinned OMP worker.
    pub worker: OmpWorkerLaunch,
    /// Shared durable authority. The same `Arc` must back the host-tool
    /// registry and URI router so journal and dispatch agree on one truth.
    pub ledger: Arc<Mutex<Ledger>>,
    /// Authorizes each dispatch afresh and supplies definitions for admitted tools.
    pub operations: HostToolOperations,
    /// Session policy context, token digest material, and capsule identity.
    pub operation_binding: SessionOperationBinding,
    /// Exact model-visible host-tool names present in the freshly verified
    /// capability listing and backed by this registry. Static registration
    /// alone never admits a tool.
    pub admitted_host_tools: BTreeSet<String>,
    /// Scope-enforced router over the seven canonical URI schemes.
    pub uri_router: ScopedUriRouter,
    /// Root where checkpoint artifacts are written before ledger registration.
    pub artifact_root: PathBuf,
    /// Completed by start.
    pub binding: BridgeBinding,
    pub session: LiveSessionDescriptor,
    /// Session lease time-to-live; must be positive.
    pub lease_ttl: Duration,
    /// Rollover policy resolved against the lane's context ceiling; `None` disables it.
    pub rollover: Option<crate::live::rollover::RolloverRuntimeConfig>,
    /// Required when rollover is configured, so continuity includes delegated-child state.
    pub rollover_children:
        Option<std::sync::Arc<dyn crate::live::rollover::RolloverChildrenSource>>,
    /// The supervisor's requested durable admission epoch for this launch.
    /// `None` keeps the legacy behavior: `start` reclaims the durable row
    /// at its own current epoch (+1) or creates it at 1. `Some(epoch)`
    /// makes the real launched binding carry EXACTLY the supervisor's
    /// durable journal epoch: a lagging row is corrected forward, a
    /// matching row is re-asserted, and a row ahead of the request is a
    /// stale incarnation refused typed — a published epoch is never
    /// rewound and the admission journal never silently diverges from the
    /// binding it launched.
    pub requested_epoch: Option<odin_domain::huginn::SessionEpoch>,
    /// Remote carriers attach through the factory and stop through their registered job worker.
    pub transport: Option<std::sync::Arc<dyn crate::process::RemoteHarnessFactory>>,
}

impl OmpBridgeConfig {
    /// Verifies the binding's scope dimensions and the deterministic
    /// registration sets before any process, lease, or ledger effect.
    pub fn validate(&self) -> Result<(), BridgeError> {
        let scope = &self.binding.scope;
        let require = |bound: bool, dimension: &str| -> Result<(), BridgeError> {
            if bound {
                Ok(())
            } else {
                Err(BridgeError::ScopeBinding {
                    detail: format!("binding scope does not bind {dimension}"),
                })
            }
        };
        require(scope.seat.is_some(), "seat")?;
        require(scope.project.is_some(), "project")?;
        require(
            scope.lane.as_ref() == Some(&self.binding.lane_id),
            "the exact lane",
        )?;
        require(
            scope.run.as_ref() == Some(&self.binding.run_id),
            "the exact run",
        )?;
        require(
            scope.session.as_ref() == Some(&self.binding.session_id),
            "the exact session",
        )?;
        let operation_policy = &self.operation_binding.policy;
        let expected_context = context_policy_digest(
            operation_policy.seat_id.as_str(),
            operation_policy.slice_id.as_str(),
            operation_policy.lane_id.as_str(),
            operation_policy.seat_revision,
            operation_policy.slice_revision,
        );
        let expected_capsule = session_capsule_id(&self.binding.session_id)?;
        if scope.seat.as_ref() != Some(&operation_policy.seat_id)
            || self.binding.lane_id != operation_policy.lane_id
            || self.session.slice_id.as_str() != operation_policy.slice_id.as_str()
            || self.operation_binding.context_policy_digest != expected_context
            || self.operation_binding.capsule_id != expected_capsule
        {
            return Err(BridgeError::ScopeBinding {
                detail: "operation authority binding does not match the bridge seat, slice, lane, session, and capsule"
                    .to_owned(),
            });
        }
        if self.binding.owner_id.trim().is_empty() {
            return Err(BridgeError::ScopeBinding {
                detail: "owner id is empty".to_owned(),
            });
        }
        if self.binding.epoch != 0 || self.binding.lease_id.is_some() {
            return Err(BridgeError::ScopeBinding {
                detail: "binding must be declared blank; start completes the epoch and lease"
                    .to_owned(),
            });
        }
        if self.binding.lease_expires_at.is_some() {
            return Err(BridgeError::ScopeBinding {
                detail: "binding must not carry a pre-start lease expiry".to_owned(),
            });
        }
        // The requested epoch must fit the DURABLE epoch column exactly
        // (SQLite i64): checked, not cast, and never silently capped.
        if let Some(epoch) = self.requested_epoch {
            if i64::try_from(epoch.get()).is_err() {
                return Err(BridgeError::ScopeBinding {
                    detail: "requested epoch does not fit the durable epoch range".to_owned(),
                });
            }
        }
        for (value, name) in [
            (self.session.slice_id.as_str(), "slice id"),
            (self.session.target_node_id.as_str(), "target node id"),
            (self.session.provider.as_str(), "provider"),
            (self.session.model.as_str(), "model"),
        ] {
            if value.trim().is_empty() {
                return Err(BridgeError::Config {
                    detail: format!("{name} must not be empty"),
                });
            }
        }
        if self.lease_ttl.is_zero() {
            return Err(BridgeError::Config {
                detail: "lease TTL must be positive".to_owned(),
            });
        }
        if self.artifact_root.as_os_str().is_empty() {
            return Err(BridgeError::Config {
                detail: "artifact root is empty".to_owned(),
            });
        }
        for name in &self.admitted_host_tools {
            if !self.operations.is_capability_bound(name) {
                return Err(BridgeError::Config {
                    detail: format!(
                        "listed host tool {name:?} has no admitted capability contract"
                    ),
                });
            }
        }
        if let Some(rollover) = &self.rollover {
            rollover.validate().map_err(|detail| BridgeError::Config {
                detail: format!("rollover policy is invalid: {detail}"),
            })?;
            if self.rollover_children.is_none() {
                return Err(BridgeError::Config {
                    detail: "rollover requires a delegated-children state source".to_owned(),
                });
            }
        }
        Ok(())
    }
}

pub(super) fn binding_with(base: &BridgeBinding, epoch: i64, lease: &LeaseRecord) -> BridgeBinding {
    BridgeBinding {
        scope: base.scope.clone(),
        session_id: base.session_id.clone(),
        run_id: base.run_id.clone(),
        lane_id: base.lane_id.clone(),
        owner_id: base.owner_id.clone(),
        epoch,
        lease_id: Some(lease.lease_id.clone()),
        lease_expires_at: Some(lease.expires_at),
    }
}

pub(super) fn binding_nonce(binding: &BridgeBinding) -> String {
    let material = format!(
        "{}|{}|{}|{}",
        binding.session_id, binding.run_id, binding.lane_id, binding.owner_id
    );
    digest_hex(&Digest::hash(material.as_bytes()))[..16].to_owned()
}
