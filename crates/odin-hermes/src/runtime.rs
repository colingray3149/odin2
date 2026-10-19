//! Composes conversation adapters over the daemon's ledgers and admitted capabilities.
//! Model dispatch consumes approvals in the kernel; external Discord intake uses
//! [`crate::ingress::DiscordIngress::gate_effect`]. Handlers never consume again.
//! The caller starts the composed gateway listener; credentials stay out of model configuration.

mod adapters;
mod approval;
pub(crate) mod authority;
mod bus;
mod catalog;
mod channel_log;
pub mod claude;
pub mod coding;
mod effects;
mod files;
mod governance;
mod grants;
pub mod incidents;
mod intake;
mod memory;
mod model_set;
mod notify;
mod probes;
pub mod projects;
mod purchase;
mod recovery;
pub mod registry_author;
mod registry_read;
mod reminders;
pub mod review;
pub mod routines;
mod seat_ask;
mod spend;
pub use spend::{read_gateway_spend, read_tag_model_groups};
mod tools;
mod workload;

#[cfg(test)]
mod dispatch_handler_tests;

pub use authority::{
    ApprovalDelivery, ApprovedIntentExecution, ApprovedIntentRoute, AuthenticatedOwnerMessage,
    AuthorityMovePlan, ConversationOwnership, DecisionRefusal, DeliveredApproval, DeliveryError,
    FleetDrainOutcome, FleetDrainPlanStep, FleetDrainResolution, FleetDrainResult, FleetDrainRoute,
    FleetRestoreOutcome, HuginnReadRoute, IntakeAuthorityFacts, IntentFailure, OwnerDecisionRoute,
    StandbyCandidate, TerminalReadRoute, TerminalScreenRead, WorkloadAuthoringFailure,
    WorkloadAuthoringRoute, WorkloadClarification, WorkloadDeclaration, WorkloadDraft,
    WorkloadDraftAnswers, WorkloadDraftRequest, WorkloadLaneAvailability, WorkloadPublication,
    WorkloadPublishRequest, WorkloadSeatLimits, WorkspaceCgroupOwner, WorkspaceConnectRoute,
    WorkspaceConnection, WorkspaceConnectionKind, WorkspaceOwnership, APPROVAL_DELIVERY_AUDIT_KIND,
};
pub use bus::{LedgerEventBus, LedgerSubscription};
pub use catalog::{hermes_capability_bindings, hermes_host_tools};
pub use intake::GatewayIntake;
pub use model_set::{
    select_target_session, ModelCommandRoute, ModelLaunchDeclaration, ModelRouteError,
    ModelSetCommand, SeatSessionSurvey,
};
use odin_domain::{
    ApprovalId, ApprovalStatus, CapabilityId, DomainError, Producer, ProjectId, SeatId,
};
use odin_kernel::CapabilityContract;
use odin_ledger::Ledger;
use odin_omp::host_tools::delegation::TaskOwner;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use time::OffsetDateTime;

use crate::config::HermesSettings;
use crate::correlation::{ConversationTaskStore, OwnerPairing};
use crate::delegation::SeatDelegator;
use crate::discord::{DiscordCredential, DiscordRestTransport, SecretToken};
use crate::egress::{DiscordEgressSink, EgressConfig, OutgoingSink};
use crate::finance::{ActualBudget, FinanceDeployment};
use crate::ingress::{
    DiscordIngress, IngressConfig, IngressError, PendingApproval, TaskReceipt,
    INTENT_APPROVAL_PREFIX,
};
use crate::vault::VaultBridge;
use governance::PublishedIntakeGovernance;
use notify::NotifyBridge;

/// Issuer identity stamped on runtime-projected envelopes and approvals.
pub const RUNTIME_ISSUER: &str = "odin-hermes.runtime";

/// The unit environment variable carrying the Discord bot token secret. The
/// sops-rendered unit environment supplies it; the value is read once at
/// composition and never leaves the process boundary.
pub const DISCORD_TOKEN_ENV: &str = "DISCORD_BOT_TOKEN";

/// Approval request lifetime for purchase intents prepared by the runtime.
pub const PURCHASE_APPROVAL_TTL_HOURS: i64 = 24;

/// Bounds one reconcile tick. Kept next to the pump contract so the daemon
/// and the runtime agree on the cadence.
pub const RECONCILE_TICK: Duration = Duration::from_secs(5);

/// Every failure the Hermes runtime composition or its durable projection
/// can produce.
#[derive(Debug, thiserror::Error)]
pub enum HermesRuntimeError {
    #[error("hermes composition rejected: {0}")]
    Composition(String),
    #[error("hermes domain contract violated: {0}")]
    Domain(#[from] DomainError),
    #[error("hermes durable state failed: {0}")]
    Ledger(#[from] odin_ledger::LedgerError),
    #[error("hermes ingress failed: {0}")]
    Ingress(#[from] IngressError),
    #[error("hermes durable cursor state failed: {0}")]
    Cursor(String),
}

pub(crate) fn unix_ms(now: OffsetDateTime) -> u64 {
    u64::try_from(now.unix_timestamp_nanos() / 1_000_000).unwrap_or(0)
}

pub(crate) fn now_utc() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

pub(crate) fn producer() -> Result<Producer, DomainError> {
    Producer::new("odin-hermes", env!("CARGO_PKG_VERSION"), None)
}

/// The daemon's durable ledgers the runtime composes over, bound once at
/// [`HermesRuntime::open`]: the shared conversation task ledger, the
/// life-effects adapter ledger, and the durable purchase ledger.
pub struct HermesLedgers {
    /// The shared conversation task/approval ledger backing the
    /// correlation store.
    pub conversation: Ledger,
    /// The life-effects ledger the email and calendar adapters gate against.
    pub adapter: Arc<parking_lot::Mutex<Ledger>>,
    /// The same authority ledger and mutex as kernel host-command dispatch;
    /// purchase settlement reuses its consumed command and approval.
    pub purchase: Arc<Mutex<Ledger>>,
}

/// The account-bound provider view of one JMAP deployment: the router's
/// [`crate::provider::LifeProvider`] port over that account's mail and
/// calendar transports. It serves exactly its declared account; another
/// selector is an honest `None`, never a fallback.
struct JmapAccountProvider {
    account: String,
    email: Option<Arc<dyn crate::email::EmailTransport>>,
    calendar: Option<Arc<dyn crate::calendar::CalendarTransport>>,
}

impl crate::provider::LifeProvider for JmapAccountProvider {
    fn email_transport(&self, account: &str) -> Option<Arc<dyn crate::email::EmailTransport>> {
        if account != self.account {
            return None;
        }
        self.email.clone()
    }

    fn calendar_transport(
        &self,
        account: &str,
    ) -> Option<Arc<dyn crate::calendar::CalendarTransport>> {
        if account != self.account {
            return None;
        }
        self.calendar.clone()
    }
}

/// Directories one seat may change. `profile` is the directory name, not `memory.<name>`.
#[derive(Clone, Debug)]
pub struct MemoryGrant {
    pub own: bool,
    pub profile: Option<String>,
}

pub struct HermesRuntime {
    settings: HermesSettings,
    store: Arc<ConversationTaskStore>,
    bus: LedgerEventBus,
    vault: Option<VaultBridge>,
    finance: Option<FinanceDeployment>,
    email: Option<crate::email::EmailAdapter>,
    calendar: Option<crate::calendar::CalendarAdapter>,
    ingress: Option<Arc<DiscordIngress>>,
    delegator: Option<Arc<SeatDelegator>>,
    notify: Option<NotifyBridge>,
    egress: Option<(Arc<dyn OutgoingSink>, String, BTreeSet<String>)>,
    /// The shared life-effects ledger the email and calendar adapters gate
    /// against; the task-grant handler reads the exact same durable
    /// approval rows the adapters verify.
    adapter_ledger: Arc<parking_lot::Mutex<Ledger>>,
    /// Durable purchase commands; approval consumption belongs to the kernel.
    purchase_ledger: Arc<Mutex<Ledger>>,
    /// Descriptor-admitted purchase backend. Absence refuses before any
    /// owner approval or provider contact.
    purchase_backend: Mutex<
        Option<(
            crate::purchase::PurchaseAdapterContract,
            Arc<dyn crate::purchase::PurchaseFrameExchange>,
        )>,
    >,
    /// Constructed here; the caller starts the gateway listener.
    gateway: Option<Arc<crate::discord::DiscordGateway>>,
    /// The REST transport for the owner DM reconnect catch-up: Discord's
    /// gateway never replays `MESSAGE_CREATE` events a down or starting
    /// authority missed, so the bounded history backfill since the durable
    /// intake cursor runs over this transport before/behind the listener.
    /// Absent when the Discord surface is not composed.
    discord_transport: Mutex<Option<Arc<crate::discord::DiscordRestTransport>>>,
    /// Admitted (non-gated) intents queued for the conversation route.
    /// The durable row is the enqueue; this stash is the in-memory work
    /// queue, rebuilt from the rows by the reconcile recovery scan.
    admitted: Mutex<Vec<TaskReceipt>>,
    gated: Mutex<Vec<(TaskReceipt, PendingApproval)>>,
    /// Admission/recovery wake for the single daemon reconciler. A stored
    /// permit closes the admit-before-wait race; the periodic sweep remains
    /// the durable crash-recovery backstop.
    reconcile_wake: tokio::sync::Notify,
    /// Executes the existing accepted command through the daemon's supervisor.
    approved_route: Mutex<Option<Arc<dyn ApprovedIntentRoute>>>,
    /// The owner channel's recent lines, as the panes read them.
    channel_log: Arc<channel_log::ChannelLog>,
    /// The live intake-authority facts cell, shared with the governance
    /// port; the daemon binds its real operation authority after
    /// composition and external intake refuses closed until then.
    intake_authority: Arc<Mutex<Option<Arc<dyn IntakeAuthorityFacts>>>>,
    /// Daemon-bound `terminal.read` source; unbound dispatches fail closed.
    terminal_reader: Mutex<Option<Arc<dyn TerminalReadRoute>>>,
    /// Daemon-bound `huginn.read` source; unbound dispatches fail closed.
    huginn_reader: Mutex<Option<Arc<dyn HuginnReadRoute>>>,
    /// Daemon-bound `workspace.connect` resolver; unbound dispatches fail
    /// closed.
    workspace_connector: Mutex<Option<Arc<dyn authority::WorkspaceConnectRoute>>>,
    /// Daemon-bound Claude driver; absent routes refuse before effects.
    claude_session_route: Mutex<Option<Arc<dyn claude::ClaudeSessionRoute>>>,
    /// Daemon-bound `fleet.drain`/`fleet.restore` surface; unbound
    /// dispatches fail closed.
    fleet_drain: Mutex<Option<Arc<dyn authority::FleetDrainRoute>>>,
    /// The pinned snapshot's live seat launch declaration the daemon
    /// derives at startup: the exact model-facing target set of the
    /// model-switch capability. Unbound composes the honest empty
    /// surface whose dispatch refuses typed.
    model_launches: Mutex<Option<Arc<model_set::ModelLaunchDeclaration>>>,
    /// Daemon-bound live model command route (the real `OmpLiveService`
    /// command seam plus the surface's declared vehicle); unbound
    /// dispatches fail closed with a typed unavailability.
    model_route: Mutex<Option<Arc<dyn model_set::ModelCommandRoute>>>,
    /// The daemon's project creation route (`project.create`).
    project_route: Mutex<Option<Arc<dyn projects::ProjectRoute>>>,
    /// The daemon's coding route (`build.run`, `check.run`, `git.patch.propose`).
    coding_route: Mutex<Option<Arc<dyn coding::CodingRoute>>>,
    /// The daemon's pinned published registry (`registry.read`).
    registry_pin: Mutex<Option<Arc<odin_registry::SnapshotHandle>>>,
    /// The daemon's incident desk (`incident.raise`).
    incident_route: Mutex<Option<Arc<dyn incidents::IncidentRoute>>>,
    routine_route: Mutex<Option<Arc<dyn routines::RoutineRoute>>>,
    /// The daemon's skeleton authoring route.
    registry_author_route: Mutex<Option<Arc<dyn registry_author::RegistryAuthorRoute>>>,
    /// The memory each (seat, project) remembers into: the project's own
    /// declared memory namespace when it declares one, set by the daemon
    /// from the published brain policies. Absent pairs use seat memory.
    project_memory: Mutex<BTreeMap<(odin_domain::SeatId, odin_domain::ProjectId), String>>,
    /// Per-seat write grant: own namespace, and the profile directory when declared.
    memory_grants: Mutex<BTreeMap<odin_domain::SeatId, MemoryGrant>>,
    /// Directory name of the owner profile, for refresh of pages every core reads live.
    profile_namespace: Mutex<Option<String>>,
    /// Chat-completions URL for brain review. Absent refuses the review.
    review_gateway: Mutex<Option<String>>,
    review_lanes: Mutex<BTreeMap<odin_domain::SeatId, String>>,
    /// Daemon-bound plain-language owner decision intake for pending
    /// conversation permissions; unbound means every DM is a normal intent.
    owner_decision: Mutex<Option<Arc<dyn OwnerDecisionRoute>>>,
    /// Daemon-bound conversational workload authoring route; unbound
    /// dispatches fail closed with a typed unavailability.
    workload_authoring: Mutex<Option<Arc<dyn WorkloadAuthoringRoute>>>,
    /// Daemon-bound pre-IO vault scoping gate; the generated write refuses
    /// typed BEFORE any IO when unscoped or uncomposed — never a silent
    /// write into the operator vault.
    vault_write_gate: Mutex<Option<Arc<dyn crate::vault::VaultWriteGate>>>,
    /// The pinned snapshot's admitted capability contracts. The declarative
    /// wording source: plain-language approval questions render from the
    /// ADMITTED contract's declared description — never a phrase table.
    contracts: Arc<BTreeMap<CapabilityId, CapabilityContract>>,
    /// The deployment-declared projects the daemon's configured lane
    /// bindings bind to each seat (bindings ∩ declared project roots,
    /// grouped by the daemon at composition). The seat-delegation ask
    /// surfaces render their model-facing project enums from this — never
    /// a compiled constant — and a seat with no binding serves an empty
    /// enum and typed refusals.
    seat_bound_projects: BTreeMap<SeatId, BTreeSet<ProjectId>>,
    /// The exact declared conversation ownership. `None` only for a
    /// nonconversation, adapter-only composition; never a default owner.
    ownership: Option<ConversationOwnership>,
    /// The durable reminder/wake schedule under the state directory.
    schedule: crate::schedule::ScheduleStore,
    /// The owner's current time zone.
    clock: crate::schedule::OwnerClock,
    /// Daemon-bound task grant ledger shared with the operation stack;
    /// unbound `task.grant` dispatches fail closed.
    task_grants: Mutex<Option<Arc<odin_omp::host_tools::task_grants::TaskGrantStore>>>,
    routine_state: routines::RoutineState,
}

impl HermesRuntime {
    /// Composes the runtime from validated settings, the daemon's durable
    /// ledgers, the pinned snapshot's admitted capability contracts, the
    /// governed task owner (when delegation governance is configured), the
    /// delegation prompt ceiling, and the exact declared conversation
    /// ownership. Every Discord fact is re-proven here: the configured
    /// capability must be an admitted contract of the pinned snapshot,
    /// whose version and effect class are taken from it — the published
    /// capability authority, bound before any executable task can exist.
    /// A configured Discord surface REQUIRES an explicit ownership
    /// declaration whose seat and project match it exactly and whose ask
    /// capability is an admitted contract delegating to the owner's own
    /// seat; nothing is inferred and nothing defaults.
    pub fn open(
        settings: HermesSettings,
        ledgers: HermesLedgers,
        contracts: &BTreeMap<CapabilityId, CapabilityContract>,
        task_owner: Option<Arc<dyn TaskOwner>>,
        max_prompt_bytes: usize,
        seat_bound_projects: BTreeMap<SeatId, BTreeSet<ProjectId>>,
        ownership: Option<ConversationOwnership>,
    ) -> Result<Arc<Self>, HermesRuntimeError> {
        std::fs::create_dir_all(&settings.state_dir).map_err(|error| {
            HermesRuntimeError::Composition(format!(
                "could not create hermes state dir {}: {error}",
                settings.state_dir.display()
            ))
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&settings.state_dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|error| {
                HermesRuntimeError::Composition(format!(
                    "could not restrict hermes state dir {}: {error}",
                    settings.state_dir.display()
                ))
            })?;
        }

        let (email, calendar) = Self::compose_life_adapters(&settings, &ledgers)?;
        let store = Arc::new(ConversationTaskStore::new(ledgers.conversation));
        let ownership = Self::admit_ownership(&settings, contracts, ownership)?;
        let bus = LedgerEventBus::open(
            Arc::clone(&store),
            Self::egress_cursor_path(&settings, ownership.as_ref())?,
            settings
                .discord
                .as_ref()
                .map(|discord| discord.egress_capacity)
                .unwrap_or(1),
        )?;

        // The live intake-authority facts cell: the daemon binds its real
        // operation authority (token revocation + stop state) via
        // [`HermesRuntime::set_intake_authority`] after composition;
        // external intake refuses closed until it is bound.
        let intake_authority: Arc<Mutex<Option<Arc<dyn IntakeAuthorityFacts>>>> =
            Arc::new(Mutex::new(None));
        let (ingress, notify, egress, gateway, discord_transport) = match &settings.discord {
            Some(discord) => {
                let contract = contracts.get(&discord.capability).ok_or_else(|| {
                    HermesRuntimeError::Composition(format!(
                        "the configured discord capability {} is not an admitted contract of \
                         the pinned snapshot",
                        discord.capability
                    ))
                })?;
                let config = IngressConfig::new(
                    discord.seat.clone(),
                    discord.capability.clone(),
                    u64::from(contract.version),
                    // The admitted effect class determines whether intake requires approval.
                    contract.effect_class,
                    discord.ttl_seconds,
                    // External ingress is admitted only from the owner's
                    // paired DM channel; the notify channel IS the pairing.
                    Some(discord.notify_channel_id.clone()),
                )
                .map_err(|error| {
                    HermesRuntimeError::Composition(format!(
                        "discord ingress config rejected: {error}"
                    ))
                })?;
                // The published capability authority for non-model intake:
                // the LIVE admitted-contract map the kernel dispatch layer
                // serves, re-proven on every invocation; the live seat
                // authority (token revocation + stop state, bound by the
                // daemon via set_intake_authority — unbound refuses
                // closed); and the durable stop/revocation state of the
                // correlation store.
                let governance = Arc::new(PublishedIntakeGovernance {
                    contracts: Arc::new(contracts.clone()),
                    seat: discord.seat.as_str().to_owned(),
                    authorization_ref: format!(
                        "snapshot:{}:v{}",
                        discord.capability, contract.version
                    ),
                    authority: Arc::clone(&intake_authority),
                    revoked: {
                        let store = Arc::clone(&store);
                        Box::new(move |identity: &str| {
                            // Durable approval stop: cancelled or denied.
                            if let Ok(approval_id) =
                                ApprovalId::new(format!("{INTENT_APPROVAL_PREFIX}{identity}"))
                            {
                                let revoked =
                                    store.approval(&approval_id).ok().flatten().is_some_and(
                                        |approval| {
                                            matches!(
                                                approval.status,
                                                ApprovalStatus::Cancelled | ApprovalStatus::Denied
                                            )
                                        },
                                    );
                                if revoked {
                                    return true;
                                }
                            }
                            // Durable task stop: a terminally stopped
                            // intent row can never become executable again.
                            if let Ok(task_id) = odin_domain::CommandId::new(format!(
                                "command:discord-intent:{identity}"
                            )) {
                                if let Ok(Some(task)) = store.task(&task_id) {
                                    if matches!(
                                        task.terminal_status,
                                        Some(
                                            odin_ledger::command::CommandTerminalStatus::Cancelled
                                                | odin_ledger::command::CommandTerminalStatus::Rejected
                                        )
                                    ) {
                                        return true;
                                    }
                                }
                            }
                            false
                        })
                    },
                });
                let pairing = OwnerPairing::new(discord.owner_user_id.clone())?;
                let ingress = DiscordIngress::new(pairing, Arc::clone(&store), governance, config);
                let secret = std::env::var(DISCORD_TOKEN_ENV)
                    .ok()
                    .filter(|token| !token.trim().is_empty());
                let credential =
                    |secret: Option<&String>| -> Result<DiscordCredential, HermesRuntimeError> {
                        let Some(token) = secret else {
                            return Ok(DiscordCredential::absent());
                        };
                        let handle = odin_domain::huginn::OpaqueCredentialHandle::new(
                            discord.bot_token_handle.clone(),
                        )
                        .map_err(HermesRuntimeError::from)?;
                        let secret = SecretToken::new(token.clone())
                            .map_err(|error| HermesRuntimeError::Composition(error.to_string()))?;
                        Ok(DiscordCredential::token(handle, secret))
                    };
                let gateway = Arc::new(crate::discord::DiscordGateway::new(
                    crate::discord::GatewayOwnership::Odin,
                    credential(secret.as_ref())?,
                    discord.gateway_intents,
                ));
                let transport = Arc::new(DiscordRestTransport::new(credential(secret.as_ref())?));
                let egress_transport: Arc<dyn crate::discord::DiscordTransport> = transport.clone();
                let sink: Arc<dyn OutgoingSink> =
                    Arc::new(DiscordEgressSink::new(egress_transport));
                let bridge =
                    NotifyBridge::spawn(Arc::clone(&sink), discord.notify_channel_id.clone())?;
                (
                    Some(Arc::new(ingress)),
                    Some(bridge),
                    Some((
                        sink,
                        discord.notify_channel_id.clone(),
                        discord.scrub_tokens.clone(),
                    )),
                    Some(gateway),
                    Some(transport),
                )
            }
            None => (None, None, None, None, None),
        };

        let vault = match &settings.vault {
            Some(config) => Some(
                VaultBridge::new(config.clone())
                    .map_err(|error| HermesRuntimeError::Composition(error.to_string()))?,
            ),
            None => None,
        };
        let delegator =
            task_owner.map(|owner| Arc::new(SeatDelegator::new(owner, max_prompt_bytes)));

        let settings_state_dir = settings.state_dir.clone();
        let schedule = crate::schedule::ScheduleStore::open(&settings_state_dir)
            .map_err(HermesRuntimeError::Composition)?;
        Ok(Arc::new(Self {
            finance: settings.finance.clone(),
            settings,
            store,
            bus,
            vault,
            email,
            calendar,
            ingress,
            delegator,
            intake_authority,
            contracts: Arc::new(contracts.clone()),
            seat_bound_projects,
            ownership,
            schedule,
            clock: crate::schedule::OwnerClock::new(&settings_state_dir),
            task_grants: Mutex::new(None),
            routine_state: routines::RoutineState::default(),
            adapter_ledger: Arc::clone(&ledgers.adapter),
            purchase_ledger: ledgers.purchase,
            notify,
            gated: Mutex::new(Vec::new()),
            admitted: Mutex::new(Vec::new()),
            reconcile_wake: tokio::sync::Notify::new(),
            purchase_backend: Mutex::new(None),
            approved_route: Mutex::new(None),
            channel_log: Arc::default(),
            egress,
            workload_authoring: Mutex::new(None),
            discord_transport: Mutex::new(discord_transport),
            vault_write_gate: Mutex::new(None),
            gateway,
            terminal_reader: Mutex::new(None),
            huginn_reader: Mutex::new(None),
            workspace_connector: Mutex::new(None),
            claude_session_route: Mutex::new(None),
            fleet_drain: Mutex::new(None),
            model_launches: Mutex::new(None),
            model_route: Mutex::new(None),
            project_route: Mutex::new(None),
            coding_route: Mutex::new(None),
            registry_pin: Mutex::new(None),
            incident_route: Mutex::new(None),
            routine_route: Mutex::new(None),
            registry_author_route: Mutex::new(None),
            project_memory: Mutex::new(BTreeMap::new()),
            memory_grants: Mutex::new(BTreeMap::new()),
            profile_namespace: Mutex::new(None),
            review_gateway: Mutex::new(None),
            review_lanes: Mutex::new(BTreeMap::new()),
            owner_decision: Mutex::new(None),
        }))
    }

    /// Composes the life adapters over ONE provider router: every
    /// declared account contributes its credential reference to one
    /// `FileCredentialLeases` and its real provider transports to one
    /// `ProviderRouter`, and both adapters sit on that same router
    /// whenever the respective ports exist. No account is served twice
    /// and none is defaulted: an operation naming an undeclared account
    /// is typed unavailable at the router, and no secret value ever
    /// passes through configuration — only each account's opaque handle
    /// and absolute secret path.
    fn compose_life_adapters(
        settings: &HermesSettings,
        ledgers: &HermesLedgers,
    ) -> Result<
        (
            Option<crate::email::EmailAdapter>,
            Option<crate::calendar::CalendarAdapter>,
        ),
        HermesRuntimeError,
    > {
        if settings.accounts.is_empty() {
            return Ok((None, None));
        }
        let mut lease_accounts = BTreeMap::new();
        let mut router = crate::provider::ProviderRouter::new();
        let mut serves_calendar = false;
        for account in &settings.accounts {
            let handle =
                odin_domain::huginn::OpaqueCredentialHandle::new(account.secret_handle.clone())
                    .map_err(HermesRuntimeError::from)?;
            let secret_ref =
                crate::account::AccountSecretRef::new(handle, account.secret_path.clone())
                    .map_err(|error| HermesRuntimeError::Composition(error.to_string()))?;
            lease_accounts.insert(account.account.clone(), secret_ref.clone());
            match &account.provider {
                crate::config::LifeProviderSettings::Jmap {
                    session_url,
                    identity_id,
                    from_address,
                    drafts_mailbox_id,
                    archive_mailbox_id,
                    trash_mailbox_id,
                    calendar_id,
                    request_timeout_ms,
                    max_response_bytes,
                } => {
                    let exchange: Arc<dyn crate::jmap::JmapExchange> =
                        crate::jmap::https_exchange(crate::jmap::JmapEndpointConfig {
                            account_id: account.account.clone(),
                            session_url: session_url.clone(),
                            credential: secret_ref,
                            request_timeout_ms: *request_timeout_ms,
                            max_response_bytes: *max_response_bytes,
                        })
                        .map_err(|error| HermesRuntimeError::Composition(error.to_string()))?;
                    let mail =
                        crate::email::JmapEmailTransport::new(crate::email::JmapMailConfig {
                            account_id: account.account.clone(),
                            identity_id: identity_id.clone(),
                            from_address: from_address.clone(),
                            drafts_mailbox_id: drafts_mailbox_id.clone(),
                            archive_mailbox_id: archive_mailbox_id.clone(),
                            trash_mailbox_id: trash_mailbox_id.clone(),
                            exchange: Arc::clone(&exchange),
                        })
                        .map_err(|error| HermesRuntimeError::Composition(error.to_string()))?;
                    let calendar_transport = calendar_id
                        .as_ref()
                        .map(|calendar_id| {
                            crate::calendar::JmapCalendarTransport::new(
                                crate::calendar::JmapCalendarConfig {
                                    account_id: account.account.clone(),
                                    calendar_id: calendar_id.clone(),
                                    exchange: Arc::clone(&exchange),
                                },
                            )
                        })
                        .transpose()
                        .map_err(|error| HermesRuntimeError::Composition(error.to_string()))?;
                    if calendar_transport.is_some() {
                        serves_calendar = true;
                    }
                    router.bind(
                        account.account.clone(),
                        Arc::new(JmapAccountProvider {
                            account: account.account.clone(),
                            email: Some(Arc::new(mail)),
                            calendar: calendar_transport.map(|transport| {
                                Arc::new(transport) as Arc<dyn crate::calendar::CalendarTransport>
                            }),
                        }),
                    );
                }
                crate::config::LifeProviderSettings::Google {
                    token_url,
                    gmail_api_url,
                    calendar_api_url,
                    calendar_id,
                    request_timeout_ms,
                    max_response_bytes,
                } => {
                    let provider = crate::google::GoogleProvider::new(
                        crate::google::GoogleAccountConfig {
                            account: account.account.clone(),
                            credential: secret_ref,
                            token_url: token_url.clone(),
                            gmail_api_url: gmail_api_url.clone(),
                            calendar_api_url: calendar_api_url.clone(),
                            calendar_id: calendar_id.clone(),
                            request_timeout_ms: *request_timeout_ms,
                            max_response_bytes: *max_response_bytes,
                        },
                        Arc::new(crate::google::HttpsGoogleWire::new(
                            *request_timeout_ms,
                            *max_response_bytes,
                        )),
                    )
                    .map_err(|error| HermesRuntimeError::Composition(error.to_string()))?;
                    serves_calendar = true;
                    router.bind(account.account.clone(), Arc::new(provider));
                }
                crate::config::LifeProviderSettings::Generic {
                    from_address,
                    imap_host,
                    imap_port,
                    imap_tls,
                    smtp_host,
                    smtp_port,
                    smtp_tls,
                    helo_name,
                    inbox_mailbox_id,
                    drafts_mailbox_id,
                    archive_mailbox_id,
                    trash_mailbox_id,
                    caldav_base_url,
                    caldav_calendar_url,
                    request_timeout_ms,
                    max_response_bytes,
                } => {
                    let tls = |mode| match mode {
                        crate::config::MailTls::ImplicitTls => {
                            crate::generic_provider::TlsMode::ImplicitTls
                        }
                        crate::config::MailTls::StartTls => {
                            crate::generic_provider::TlsMode::StartTls
                        }
                    };
                    let provider = crate::generic_provider::GenericLifeProvider::new(
                        crate::generic_provider::GenericProviderConfig {
                            account: account.account.clone(),
                            from_address: from_address.clone(),
                            imap: crate::generic_provider::MailEndpoint {
                                host: imap_host.clone(),
                                port: *imap_port,
                                tls: tls(*imap_tls),
                            },
                            smtp: crate::generic_provider::MailEndpoint {
                                host: smtp_host.clone(),
                                port: *smtp_port,
                                tls: tls(*smtp_tls),
                            },
                            helo_name: helo_name.clone(),
                            inbox_mailbox_id: inbox_mailbox_id.clone(),
                            drafts_mailbox_id: drafts_mailbox_id.clone(),
                            archive_mailbox_id: archive_mailbox_id.clone(),
                            trash_mailbox_id: trash_mailbox_id.clone(),
                            caldav: caldav_base_url.clone().map(|base_url| {
                                crate::generic_provider::CaldavEndpoint {
                                    base_url,
                                    calendar_url: caldav_calendar_url.clone(),
                                }
                            }),
                            credential: secret_ref,
                            request_timeout_ms: *request_timeout_ms,
                            max_response_bytes: *max_response_bytes,
                        },
                        Arc::new(crate::generic_provider::HttpsCaldavExchange::new(
                            Duration::from_millis(*request_timeout_ms),
                            *max_response_bytes,
                        )),
                    )
                    .map_err(|error| HermesRuntimeError::Composition(error.to_string()))?;
                    serves_calendar |= caldav_base_url.is_some();
                    router.bind(account.account.clone(), Arc::new(provider));
                }
            }
        }
        let leases: Arc<dyn crate::account::CredentialLeases> =
            Arc::new(crate::account::FileCredentialLeases::new(lease_accounts));
        let router = Arc::new(router);
        let email = crate::email::EmailAdapter::new(
            Arc::clone(&ledgers.adapter),
            Arc::clone(&router) as Arc<dyn crate::email::EmailTransport>,
            Arc::clone(&leases),
            RUNTIME_ISSUER,
        );
        let calendar = serves_calendar.then(|| {
            crate::calendar::CalendarAdapter::new(
                Arc::clone(&ledgers.adapter),
                Arc::clone(&router) as Arc<dyn crate::calendar::CalendarTransport>,
                Arc::clone(&leases),
                RUNTIME_ISSUER,
            )
        });
        Ok((Some(email), calendar))
    }

    pub const fn settings(&self) -> &HermesSettings {
        &self.settings
    }

    pub const fn store(&self) -> &Arc<ConversationTaskStore> {
        &self.store
    }

    /// The exact declared conversation ownership, when the composition
    /// declares one. There is no default.
    pub const fn ownership(&self) -> Option<&ConversationOwnership> {
        self.ownership.as_ref()
    }

    pub const fn bus(&self) -> &LedgerEventBus {
        &self.bus
    }
    /// The caller must ensure no other process consumes the Discord gateway before running this listener.
    pub const fn gateway(&self) -> &Option<Arc<crate::discord::DiscordGateway>> {
        &self.gateway
    }

    pub const fn ingress(&self) -> &Option<Arc<DiscordIngress>> {
        &self.ingress
    }

    pub const fn delegator(&self) -> &Option<Arc<SeatDelegator>> {
        &self.delegator
    }

    pub const fn vault(&self) -> &Option<VaultBridge> {
        &self.vault
    }

    pub const fn finance(&self) -> &Option<FinanceDeployment> {
        &self.finance
    }

    /// The egress sink and its configuration, when the Discord surface is
    /// configured. REST-only: no gateway consumer is ever spawned here.
    pub fn egress(&self) -> Option<(Arc<dyn OutgoingSink>, EgressConfig)> {
        let (sink, channel, scrub) = self.egress.as_ref()?;
        let capacity = self
            .settings
            .discord
            .as_ref()
            .map(|discord| discord.egress_capacity)
            .unwrap_or(1);
        let config = EgressConfig::new(channel.clone(), scrub.iter().cloned(), capacity)
            .map_err(|error| HermesRuntimeError::Composition(error.to_string()))
            .expect("egress config validated at composition");
        Some((Arc::clone(sink), config))
    }

    /// Renders one status notification to the owner channel through the
    /// dedicated notify worker after the structural scrub pass.
    pub fn notify(&self, content: &str) -> Result<(), String> {
        self.notify_deliverable(content)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    /// Binds an alternate governed outgoing sink for the owner channel;
    /// every later notification (answers, failure notices, delivered
    /// approval questions) is sent through it instead of the composed
    /// Discord REST sink. Unbound, the composition sink stays authoritative.
    pub fn bind_notify_sink(&self, sink: Arc<dyn OutgoingSink>) -> Result<(), String> {
        let bridge = self
            .notify
            .as_ref()
            .ok_or_else(|| "the discord surface is not configured".to_owned())?;
        bridge.bind_sink(sink)
    }

    /// Closes owner-channel notification admission: later notifications are
    /// refused, queued ones are withdrawn unsent, and every waiting caller
    /// wakes. Synchronous and idempotent; call it before the first shutdown
    /// await, then [`Self::drain_notifications_until`].
    pub fn close_notifications(&self) {
        if let Some(bridge) = &self.notify {
            bridge.close();
        }
    }

    /// Closes admission, then waits for the notify worker to stop until
    /// `deadline` (the shutdown's one deadline, not a fresh grace). A worker
    /// still inside its sink at the deadline is reported as an error and stays
    /// owned by the runtime — a timeout is not a stop; its in-flight delivery
    /// is unproved and its durable checkpoint and schedule row stay held.
    pub async fn drain_notifications_until(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), String> {
        match &self.notify {
            Some(bridge) => bridge.drain_until(deadline).await,
            None => Ok(()),
        }
    }

    /// The scrub vocabulary of the Discord surface.
    pub fn scrub_tokens(&self) -> BTreeSet<String> {
        self.egress
            .as_ref()
            .map(|(_, _, tokens)| tokens.clone())
            .unwrap_or_default()
    }

    /// Reads the real finance summary through the Actual Budget adapter.
    /// Unconfigured or unavailable states surface typed — never as zeros
    /// pretending to be a summary.
    pub fn finance_summary(&self, month: &str) -> Result<crate::finance::FinanceSummary, String> {
        let deployment = self
            .finance
            .as_ref()
            .ok_or_else(|| "finance adapter is not configured".to_owned())?;
        let budget = ActualBudget::open(deployment).map_err(|error| error.to_string())?;
        budget
            .month_summary(
                crate::finance::FinanceMonth::parse(month).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())
    }
    /// Waits until intake or route binding makes reconcile work runnable.
    /// `Notify` retains one permit, so an admission immediately before the
    /// daemon starts waiting is not delayed until the recovery sweep.
    pub async fn wait_for_reconcile_wake(&self) {
        self.reconcile_wake.notified().await;
    }

    /// Binds the daemon's real approved-intent execution route. Until this
    /// is called, approved intents stay stashed (fail closed) — they are
    /// never settled as failed for a missing route.
    pub fn set_approved_intent_route(&self, route: Arc<dyn ApprovedIntentRoute>) {
        if let Ok(mut cell) = self.approved_route.lock() {
            *cell = Some(route);
            self.reconcile_wake.notify_one();
        }
    }

    /// Whether the approved-intent route is bound: the daemon-side
    /// "vehicle ready" signal the DM catch-up trigger observes.
    pub fn approved_route_bound(&self) -> bool {
        self.approved_route
            .lock()
            .map(|cell| cell.is_some())
            .unwrap_or(false)
    }

    /// Binds a different REST transport for the DM catch-up (tests bind a
    /// loopback admission target; production composes the real one).
    pub fn set_discord_catch_up_transport(
        &self,
        transport: Arc<crate::discord::DiscordRestTransport>,
    ) {
        if let Ok(mut cell) = self.discord_transport.lock() {
            *cell = Some(transport);
        }
    }

    /// Reads the owner channel oldest first, not the seat's internal history.
    pub async fn owner_thread(
        &self,
        after: Option<&str>,
    ) -> Result<Vec<odin_domain::huginn::ConversationLine>, String> {
        let transport = self
            .discord_transport
            .lock()
            .ok()
            .and_then(|cell| cell.clone())
            .ok_or_else(|| "the discord surface is not composed".to_owned())?;
        let discord = self
            .settings
            .discord
            .as_ref()
            .ok_or_else(|| "the discord surface is not configured".to_owned())?;
        let limit = crate::discord::DM_CATCH_UP_LIMIT;
        if let Some(lines) = self.channel_log.after(after, limit as usize) {
            if self.channel_log.claim_resync() {
                let (log, transport, store, channel, owner) = (
                    Arc::clone(&self.channel_log),
                    Arc::clone(&transport),
                    Arc::clone(&self.store),
                    discord.notify_channel_id.clone(),
                    discord.owner_user_id.clone(),
                );
                tokio::spawn(async move {
                    match transport.fetch_messages_after(&channel, None, limit).await {
                        Ok(messages) => {
                            log.seed(owner_lines(&store, &owner, messages));
                        }
                        Err(error) => {
                            log.sync_failed();
                            tracing::error!(error = %error, "odind: conversation-surface resync_failed error={error}");
                        }
                    }
                });
            }
            return Ok(lines);
        }
        let messages = transport
            .fetch_messages_after(&discord.notify_channel_id, after, limit)
            .await
            .map_err(|error| error.to_string())?;
        let lines = owner_lines(&self.store, &discord.owner_user_id, messages);
        if after.is_none() {
            self.channel_log.seed(lines.clone());
        } else {
            for line in &lines {
                self.channel_log.record(line.clone());
            }
        }
        Ok(lines)
    }

    /// Backfills missed gateway messages oldest-first through normal admission.
    /// Starts after the durable cursor, advances locally past refused messages, and
    /// stops on admission errors before later messages can move the durable frontier.
    /// Full pages must advance; without a cursor only the newest window is fetched.
    pub async fn catch_up_owner_dms(&self) -> Result<usize, String> {
        let transport = self
            .discord_transport
            .lock()
            .ok()
            .and_then(|cell| cell.clone());
        let Some(transport) = transport else {
            return Ok(0);
        };
        let channel = self
            .settings
            .discord
            .as_ref()
            .map(|discord| discord.notify_channel_id.clone())
            .ok_or_else(|| "the discord surface is not configured".to_owned())?;
        let mut after = self
            .store
            .latest_discord_message_id(&channel)
            .map_err(|error| error.to_string())?;
        let mut fetched = 0usize;
        loop {
            let messages = transport
                .fetch_messages_after(
                    &channel,
                    after.as_deref(),
                    crate::discord::DM_CATCH_UP_LIMIT,
                )
                .await
                .map_err(|error| error.to_string())?;
            fetched += messages.len();
            for message in &messages {
                // Skip empty messages so later owner messages can be admitted.
                if message.content.trim().is_empty() && message.attachments.is_empty() {
                    tracing::error!(
                        "odin-hermes intake refused a message: discord intent content must not be empty"
                    );
                    continue;
                }
                if let Err(error) = self.admit_message(message) {
                    if message_specific(&error) {
                        tracing::warn!(
                            message = %message.id,
                            "odin-hermes catch-up skipped message {}: {error}",
                            message.id
                        );
                        continue;
                    }
                    return Err(format!(
                        "odin-hermes catch-up intake failed for message {}: {error}",
                        message.id
                    ));
                }
            }
            if messages.len() < crate::discord::DM_CATCH_UP_LIMIT as usize {
                return Ok(fetched);
            }
            // The page arrived oldest first, so its last id is the
            // newest. Every entry was admitted or typed-refused to reach
            // here, so the invocation-local fetch cursor advances past
            // the whole page — including refused foreign work, which a
            // restart honestly re-refuses when it refetches from the
            // durable frontier. A full page that does not move the
            // cursor is refused rather than fetched forever.
            let Some(newest) = messages.last() else {
                return Ok(fetched);
            };
            let newest_id = newest.id.parse::<u64>().map_err(|_| {
                format!(
                    "odin-hermes catch-up fetched a non-snowflake id {}",
                    newest.id
                )
            })?;
            if after
                .as_deref()
                .and_then(|cursor| cursor.parse::<u64>().ok())
                .is_some_and(|cursor| newest_id <= cursor)
            {
                return Err(format!(
                    "odin-hermes catch-up page did not advance past cursor {after:?}"
                ));
            }
            after = Some(newest.id.clone());
        }
    }
    /// Binds the task grant ledger the operation stack decides against.
    pub fn set_task_grants(&self, grants: Arc<odin_omp::host_tools::task_grants::TaskGrantStore>) {
        if let Ok(mut cell) = self.task_grants.lock() {
            *cell = Some(grants);
        }
    }

    pub(crate) fn task_grants(
        &self,
    ) -> Option<Arc<odin_omp::host_tools::task_grants::TaskGrantStore>> {
        self.task_grants.lock().ok().and_then(|cell| cell.clone())
    }

    pub fn set_vault_write_gate(&self, gate: Arc<dyn crate::vault::VaultWriteGate>) {
        if let Ok(mut cell) = self.vault_write_gate.lock() {
            *cell = Some(gate);
        }
    }

    /// The model-facing tool name of one admitted capability.
    pub(crate) fn tool_name_of(&self, capability: &CapabilityId) -> Option<String> {
        self.contracts
            .get(capability)
            .map(|contract| contract.tool_name.to_string())
    }

    pub(crate) fn vault_write_gate(&self) -> Option<Arc<dyn crate::vault::VaultWriteGate>> {
        self.vault_write_gate
            .lock()
            .ok()
            .and_then(|cell| cell.clone())
    }

    /// Binds the daemon's real operation authority facts (current seat
    /// token revocation and current stop state) into the intake governance.
    /// External intake refuses closed until this is called.
    pub fn set_intake_authority(&self, facts: Arc<dyn IntakeAuthorityFacts>) {
        if let Ok(mut cell) = self.intake_authority.lock() {
            *cell = Some(facts);
        }
    }

    /// Binds the daemon's real `terminal.read` screen source. Unbound
    /// dispatches fail closed with a typed unavailability.
    pub fn set_terminal_read_route(&self, route: Arc<dyn TerminalReadRoute>) {
        if let Ok(mut cell) = self.terminal_reader.lock() {
            *cell = Some(route);
        }
    }

    /// Binds the daemon's real `huginn.read` projection source. Unbound
    /// dispatches fail closed with a typed unavailability.
    pub fn set_huginn_read_route(&self, route: Arc<dyn HuginnReadRoute>) {
        if let Ok(mut cell) = self.huginn_reader.lock() {
            *cell = Some(route);
        }
    }

    /// Binds the daemon's real `workspace.connect` resolution source over
    /// its pinned registry snapshot and shared read model. Unbound
    /// dispatches fail closed with a typed unavailability.
    pub fn set_workspace_connect_route(&self, route: Arc<dyn authority::WorkspaceConnectRoute>) {
        if let Ok(mut cell) = self.workspace_connector.lock() {
            *cell = Some(route);
        }
    }

    /// Binds the durable, governed Claude session driver.
    pub fn set_claude_session_route(&self, route: Arc<dyn claude::ClaudeSessionRoute>) {
        if let Ok(mut cell) = self.claude_session_route.lock() {
            *cell = Some(route);
        }
    }

    /// Binds the daemon's real `fleet.drain`/`fleet.restore` surface over
    /// its pinned registry snapshot, shared read model, and kube cell.
    /// Unbound dispatches fail closed with a typed unavailability.
    pub fn set_fleet_drain_route(&self, route: Arc<dyn authority::FleetDrainRoute>) {
        if let Ok(mut cell) = self.fleet_drain.lock() {
            *cell = Some(route);
        }
    }

    /// Pins the daemon's live seat launch declaration — the ONE active
    /// snapshot's seat bindings derivation — before the compiled catalog
    /// is built, so the model-facing target set is a startup fact and
    /// never a per-dispatch guess.
    pub fn set_model_launch_declaration(&self, declaration: model_set::ModelLaunchDeclaration) {
        if let Ok(mut cell) = self.model_launches.lock() {
            *cell = Some(Arc::new(declaration));
        }
    }

    /// The pinned live seat launch declaration, when the daemon composed
    /// one.
    pub fn model_launches(&self) -> Option<Arc<model_set::ModelLaunchDeclaration>> {
        self.model_launches
            .lock()
            .ok()
            .and_then(|cell| cell.clone())
    }

    /// Binds where each (seat, project) remembers: the memory name
    /// (`memory.<name>`) of the project's declared memory namespace.
    pub fn set_project_memory(
        &self,
        routes: BTreeMap<(odin_domain::SeatId, odin_domain::ProjectId), String>,
    ) {
        if let Ok(mut cell) = self.project_memory.lock() {
            *cell = routes;
        }
    }

    /// Binds each seat's declared brain review lane.
    pub fn set_review_lanes(&self, lanes: BTreeMap<odin_domain::SeatId, String>) {
        if let Ok(mut cell) = self.review_lanes.lock() {
            *cell = lanes;
        }
    }

    pub(crate) fn review_lane(&self, seat: &odin_domain::SeatId) -> Option<String> {
        self.review_lanes.lock().ok()?.get(seat).cloned()
    }

    /// Binds each seat's writable memory directories.
    pub fn set_memory_grants(&self, grants: BTreeMap<odin_domain::SeatId, MemoryGrant>) {
        if let Ok(mut cell) = self.memory_grants.lock() {
            *cell = grants;
        }
    }

    pub fn set_profile_namespace(&self, namespace: Option<String>) {
        if let Ok(mut cell) = self.profile_namespace.lock() {
            *cell = namespace;
        }
    }

    pub fn set_review_gateway(&self, url: String) {
        if let Ok(mut cell) = self.review_gateway.lock() {
            *cell = Some(url);
        }
    }

    pub(crate) fn memory_grant(&self, seat: &odin_domain::SeatId) -> MemoryGrant {
        let Ok(grants) = self.memory_grants.lock() else {
            return MemoryGrant {
                own: false,
                profile: None,
            };
        };
        if grants.is_empty() {
            return MemoryGrant {
                own: true,
                profile: None,
            };
        }
        grants.get(seat).cloned().unwrap_or(MemoryGrant {
            own: false,
            profile: None,
        })
    }

    pub(crate) fn profile_namespace(&self) -> Option<String> {
        self.profile_namespace
            .lock()
            .ok()
            .and_then(|cell| cell.clone())
    }

    pub(crate) fn review_gateway(&self) -> Option<String> {
        self.review_gateway
            .lock()
            .ok()
            .and_then(|cell| cell.clone())
    }

    /// The memory name one seat remembers into for one project: the
    /// project's declared memory, else the seat's own.
    pub fn memory_name(
        &self,
        seat: &odin_domain::SeatId,
        project: Option<&odin_domain::ProjectId>,
    ) -> String {
        project
            .and_then(|project| {
                self.project_memory
                    .lock()
                    .ok()?
                    .get(&(seat.clone(), project.clone()))
                    .cloned()
            })
            .unwrap_or_else(|| seat.as_str().to_owned())
    }

    pub fn set_model_command_route(&self, route: Arc<dyn model_set::ModelCommandRoute>) {
        if let Ok(mut cell) = self.model_route.lock() {
            *cell = Some(route);
        }
    }

    /// The bound live model command route, when the daemon composed one.
    pub fn model_route(&self) -> Option<Arc<dyn model_set::ModelCommandRoute>> {
        self.model_route.lock().ok().and_then(|cell| cell.clone())
    }

    pub fn set_project_route(&self, route: Arc<dyn projects::ProjectRoute>) {
        if let Ok(mut cell) = self.project_route.lock() {
            *cell = Some(route);
        }
    }

    pub fn set_coding_route(&self, route: Arc<dyn coding::CodingRoute>) {
        if let Ok(mut cell) = self.coding_route.lock() {
            *cell = Some(route);
        }
    }

    pub fn set_routine_route(&self, route: Arc<dyn routines::RoutineRoute>) {
        if let Ok(mut cell) = self.routine_route.lock() {
            *cell = Some(route);
        }
    }

    pub fn routine_route(&self) -> Option<Arc<dyn routines::RoutineRoute>> {
        self.routine_route.lock().ok().and_then(|cell| cell.clone())
    }

    pub fn set_registry_author_route(&self, route: Arc<dyn registry_author::RegistryAuthorRoute>) {
        if let Ok(mut cell) = self.registry_author_route.lock() {
            *cell = Some(route);
        }
    }

    pub fn registry_author_route(&self) -> Option<Arc<dyn registry_author::RegistryAuthorRoute>> {
        self.registry_author_route
            .lock()
            .ok()
            .and_then(|cell| cell.clone())
    }

    pub fn set_incident_route(&self, route: Arc<dyn incidents::IncidentRoute>) {
        if let Ok(mut cell) = self.incident_route.lock() {
            *cell = Some(route);
        }
    }

    /// The daemon's incident desk, when composed.
    pub fn incident_route(&self) -> Option<Arc<dyn incidents::IncidentRoute>> {
        self.incident_route
            .lock()
            .ok()
            .and_then(|cell| cell.clone())
    }

    pub fn set_registry_pin(&self, pin: Arc<odin_registry::SnapshotHandle>) {
        if let Ok(mut cell) = self.registry_pin.lock() {
            *cell = Some(pin);
        }
    }

    /// The daemon's pinned published registry, when bound.
    pub fn registry_pin(&self) -> Option<Arc<odin_registry::SnapshotHandle>> {
        self.registry_pin.lock().ok().and_then(|cell| cell.clone())
    }

    /// The bound coding route, when the daemon composed one.
    pub fn coding_route(&self) -> Option<Arc<dyn coding::CodingRoute>> {
        self.coding_route.lock().ok().and_then(|cell| cell.clone())
    }

    /// The bound project creation route, when the daemon composed one.
    pub fn project_route(&self) -> Option<Arc<dyn projects::ProjectRoute>> {
        self.project_route.lock().ok().and_then(|cell| cell.clone())
    }
    /// Binds the daemon's plain-language owner decision intake. Unbound
    /// means every paired DM stays a normal intent.
    pub fn set_owner_decision_route(&self, route: Arc<dyn OwnerDecisionRoute>) {
        if let Ok(mut cell) = self.owner_decision.lock() {
            *cell = Some(route);
        }
    }

    /// Binds the daemon's real conversational workload authoring route over
    /// the pinned snapshot and the deployment's authoring worktree. Unbound
    /// dispatches fail closed with a typed unavailability — the tools stay
    /// listed but never pretend to draft or publish.
    pub fn set_workload_authoring_route(&self, route: Arc<dyn WorkloadAuthoringRoute>) {
        if let Ok(mut cell) = self.workload_authoring.lock() {
            *cell = Some(route);
        }
    }

    /// The bound workload authoring route, when the daemon composed one.
    pub fn workload_authoring(&self) -> Option<Arc<dyn WorkloadAuthoringRoute>> {
        self.workload_authoring
            .lock()
            .ok()
            .and_then(|cell| cell.clone())
    }
    /// `false` is a missing BACKEND DEPLOYMENT — never a missing credential
    /// — and approved purchases stay typed-missing until a real one binds.
    pub fn purchase_transport_deployed(&self) -> bool {
        self.purchase_backend
            .lock()
            .map(|backend| backend.is_some())
            .unwrap_or(false)
    }

    /// The deployment-declared projects each seat's configured lane
    /// bindings bind — the seat-delegation ask surfaces' project enum
    /// source.
    pub const fn seat_bound_projects(&self) -> &BTreeMap<SeatId, BTreeSet<ProjectId>> {
        &self.seat_bound_projects
    }

    /// Admits the declared conversation ownership before any task can
    /// exist. A declared ownership must name an ask capability the pinned
    /// snapshot admits, and that contract must delegate to exactly the
    /// declared owner seat — never another seat, never an undeclared
    /// target. A configured Discord surface requires ownership whose seat
    /// and project match the configured transport exactly; a
    /// nonconversation, adapter-only composition may declare none. Nothing
    /// is inferred and nothing defaults.
    fn admit_ownership(
        settings: &HermesSettings,
        contracts: &BTreeMap<CapabilityId, CapabilityContract>,
        ownership: Option<ConversationOwnership>,
    ) -> Result<Option<ConversationOwnership>, HermesRuntimeError> {
        let Some(ownership) = ownership else {
            if settings.discord.is_some() {
                return Err(HermesRuntimeError::Composition(
                    "the configured Discord surface requires an exact declared \
                     conversation ownership; none was supplied"
                        .to_owned(),
                ));
            }
            return Ok(None);
        };
        let ask_contract = contracts.get(&ownership.ask_capability).ok_or_else(|| {
            HermesRuntimeError::Composition(format!(
                "the declared conversation ask capability {} is not an admitted \
                 contract of the pinned snapshot",
                ownership.ask_capability
            ))
        })?;
        if ask_contract.delegate_to.as_ref() != Some(&ownership.seat) {
            return Err(HermesRuntimeError::Composition(format!(
                "the declared conversation ask capability {} delegates to {}, \
                 not exactly the declared owner seat {}",
                ownership.ask_capability,
                ask_contract
                    .delegate_to
                    .as_ref()
                    .map(|seat| seat.as_str())
                    .unwrap_or("(no declared target)"),
                ownership.seat
            )));
        }
        if let Some(discord) = &settings.discord {
            if ownership.seat != discord.seat || ownership.project != discord.project {
                return Err(HermesRuntimeError::Composition(format!(
                    "the declared conversation ownership ({}, {}) does not match the \
                     configured Discord surface's exact seat and project ({}, {})",
                    ownership.seat, ownership.project, discord.seat, discord.project
                )));
            }
        }
        Ok(Some(ownership))
    }

    /// The durable egress cursor lives under the DECLARED conversation's
    /// own namespace — `conversations/<declared-seat>/egress-cursor.json` —
    /// so a shared ledger's delivered-event state never crosses a bound
    /// owner: a re-bound declaration starts a fresh cursor and can neither
    /// replay nor skip another owner's delivered rows. There is no named
    /// seat and no default owner here: the seat comes exactly from the
    /// admitted declaration, and an adapter-only composition without
    /// ownership keeps the generic cursor.
    fn egress_cursor_path(
        settings: &HermesSettings,
        ownership: Option<&ConversationOwnership>,
    ) -> Result<PathBuf, HermesRuntimeError> {
        let Some(ownership) = ownership else {
            return Ok(settings.state_dir.join("egress-cursor.json"));
        };
        let path = settings
            .state_dir
            .join("conversations")
            .join(ownership.seat.as_str())
            .join("egress-cursor.json");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                HermesRuntimeError::Composition(format!(
                    "could not create the declared conversation cursor dir {}: {error}",
                    parent.display()
                ))
            })?;
        }
        Ok(path)
    }
}

/// A refusal of this one message. A ledger, approval, or governance failure
/// is the intake itself and must stop the drain before a later owner DM is
/// admitted past it.
fn message_specific(error: &crate::ingress::IngressError) -> bool {
    matches!(error, crate::ingress::IngressError::Domain(_))
}

/// The owner channel's messages as conversation lines.
fn owner_lines(
    store: &ConversationTaskStore,
    owner: &str,
    messages: Vec<crate::discord::DiscordMessage>,
) -> Vec<odin_domain::huginn::ConversationLine> {
    messages
        .into_iter()
        .map(|message| intake::owner_channel_line(store, owner, message))
        .collect()
}
