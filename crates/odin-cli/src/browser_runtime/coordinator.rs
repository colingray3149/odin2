use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use odin_browser::session::{ConsumedApproval, PreparedActionView};
use odin_domain::huginn as live;
use odin_domain::ApprovalId;
use odin_huginn::browser::BrowserProjectionHandle;
use odin_huginn::dispatch::AuthenticatedCommandPort;
use odin_huginn::read_model::MaterializedReadModel;
use odin_ledger::approval::{Approval, ApprovalScope};
use odin_ledger::command::AcceptedCommand;
use odin_ledger::Ledger;
use tokio::sync::Notify;

pub use checkout::BrowserCheckoutBackend;
use protocol::unsupported;

mod actions;
mod approvals;
mod checkout;
mod host;
mod journal;
mod protocol;

const COMMAND_TTL: time::Duration = time::Duration::minutes(5);

#[derive(Clone)]
pub struct BrowserCommandCoordinator {
    ledger: Arc<Mutex<Ledger>>,
    read_model: Arc<MaterializedReadModel>,
    projection: BrowserProjectionHandle,
    admission: Arc<CommandAdmission>,
    pending: Arc<Mutex<PendingActions>>,
    owner_preview: BTreeSet<String>,
    runtime: tokio::runtime::Handle,
}

struct CommandAdmission {
    limit: NonZeroUsize,
    state: Mutex<CommandAdmissionState>,
    drained: Notify,
}

struct CommandAdmissionState {
    open: bool,
    in_flight: usize,
}

struct AuthenticatedCallGuard {
    admission: Arc<CommandAdmission>,
}

impl Drop for AuthenticatedCallGuard {
    fn drop(&mut self) {
        let mut state = self
            .admission
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.in_flight -= 1;
        let drained = state.in_flight == 0;
        drop(state);
        if drained {
            self.admission.drained.notify_waiters();
        }
    }
}

struct PendingActions {
    limit: NonZeroUsize,
    by_approval: BTreeMap<ApprovalId, PendingAction>,
}

struct PendingAction {
    accepted: AcceptedCommand,
    approval_id: ApprovalId,
    prepared: PreparedActionView,
    scope: ApprovalScope,
}

enum JournalDisposition {
    Accepted(AcceptedCommand),
    Duplicate(live::HuginnResponse),
}

enum ActionAuthorization {
    NotRequired,
    Pending(Approval),
    Consumed {
        approval: Approval,
        evidence: ConsumedApproval,
    },
    Denied,
    Redirect,
}

enum AppliedApprovalDecision {
    Approved(Approval),
    Denied(Approval),
    Redirect,
}

impl BrowserCommandCoordinator {
    /// The browser session this coordinator serves.
    pub fn session_id(&self) -> live::BrowserSessionId {
        self.projection.browser().session_id()
    }

    /// Whether this session holds the pending action an approval decides:
    /// the routes send a decision to the session that asked for it.
    pub fn holds_pending_approval(&self, approval: &ApprovalId) -> bool {
        self.pending
            .lock()
            .map(|pending| pending.by_approval.contains_key(approval))
            .unwrap_or(false)
    }

    pub fn new(
        ledger: Arc<Mutex<Ledger>>,
        read_model: Arc<MaterializedReadModel>,
        projection: BrowserProjectionHandle,
        max_pending_actions: NonZeroUsize,
    ) -> Self {
        Self {
            ledger,
            read_model,
            projection,
            runtime: tokio::runtime::Handle::current(),
            admission: Arc::new(CommandAdmission {
                limit: max_pending_actions,
                state: Mutex::new(CommandAdmissionState {
                    open: true,
                    in_flight: 0,
                }),
                drained: Notify::new(),
            }),
            pending: Arc::new(Mutex::new(PendingActions {
                limit: max_pending_actions,
                by_approval: BTreeMap::new(),
            })),
            owner_preview: BTreeSet::new(),
        }
    }

    pub fn set_owner_preview(&mut self, ids: BTreeSet<String>) {
        self.owner_preview = ids;
    }
}

#[async_trait]
impl live::HuginnCommandPort for BrowserCommandCoordinator {
    async fn execute(
        &self,
        request: live::HuginnRequest,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        match request {
            live::HuginnRequest::BrowserObserve(_)
            | live::HuginnRequest::BrowserCommand(_)
            | live::HuginnRequest::ApprovalDecision(_) => {
                Err(live::HuginnProtocolError::Unauthenticated)
            }
            _ => Err(unsupported("non-browser command")),
        }
    }
}

#[async_trait]
impl AuthenticatedCommandPort for BrowserCommandCoordinator {
    async fn execute_authenticated(
        &self,
        device: live::DeviceId,
        request: live::HuginnRequest,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        self.consume_takeover_expiry().await?;
        match request {
            live::HuginnRequest::BrowserObserve(request) => {
                let _in_flight = self.admit_authenticated_call()?;
                self.observe_authenticated(device, request).await
            }
            live::HuginnRequest::BrowserCommand(command) => {
                let _in_flight = self.admit_authenticated_call()?;
                self.execute_browser_command(device, command).await
            }
            live::HuginnRequest::ApprovalDecision(command) => {
                let _in_flight = self.admit_authenticated_call()?;
                self.decide_approval(device, command).await
            }
            other => <Self as live::HuginnCommandPort>::execute(self, other).await,
        }
    }
}
