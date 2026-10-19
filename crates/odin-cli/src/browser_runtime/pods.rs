//! Pod browsers: the authority's routes to every live
//! browser session — its own local browser plus one relayed in-pod browser
//! per workload agent pod whose profile grants a browser tool.
//!
//! A pod browser is the same session mechanism as the local one (policy
//! snapshot, safety gate, durable control generation, frame stream,
//! takeover) over a relayed worker transport; odind supplies the relay.
//! Huginn devices address any session by id; an agent tool call addresses
//! only what its own session may: a pod agent its own pod's browser, any
//! other caller the local browser.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use odin_browser::capability::ArtifactPublisher;
use odin_browser::config::{FrameLimits, ResourceLimits, Viewport};
use odin_browser::policy::{ActionRule, BrowserPolicySnapshot};
use odin_browser::relay::{RelayedWorkerLaunch, RelayedWorkerPaths, WorkerRelay};
use odin_browser::safety::BrowserSafetyGate;
use odin_browser::session::{BrowserSession, FrameWiring, SessionLimits};
use odin_browser::{BrowserStopHost, StructuralAction};
use odin_domain::huginn as live;
use odin_domain::{ApprovalId, Scope, SessionId};
use odin_huginn::browser::{BrowserProjection, BrowserProjectionConfig};
use odin_huginn::dispatch::AuthenticatedCommandPort;
use odin_huginn::read_model::MaterializedReadModel;
use odin_huginn::service::{FsExternalContentIndex, FsPublishedArtifactStore};
use odin_huginn::streams::BoundedMultiplexer;
use odin_ledger::Ledger;
use odin_omp::host_tools::{
    BrowserCapabilityBinding, BrowserCapabilityOwner, HostInvocation, HostToolError,
};
use serde_json::Value;

use super::coordinator::BrowserCommandCoordinator;

/// The shared, already-validated inputs every pod browser session opens
/// with: the same policy rules, safety gate, stop host, limits and Huginn
/// wiring the local browser launched under.
#[derive(Clone)]
pub struct PodBrowserOpener {
    pub(super) rules: BTreeMap<StructuralAction, ActionRule>,
    pub(super) safety: Arc<BrowserSafetyGate>,
    pub(super) stop_host: BrowserStopHost,
    pub(super) resource_limits: ResourceLimits,
    pub(super) frame_limits: FrameLimits,
    pub(super) session_limits: SessionLimits,
    pub(super) startup: std::time::Duration,
    pub(super) command: std::time::Duration,
    pub(super) shutdown: std::time::Duration,
    pub(super) takeover_lease: std::time::Duration,
    pub(super) staging_parent: PathBuf,
    pub(super) ledger: Arc<Mutex<Ledger>>,
    pub(super) read_model: Arc<MaterializedReadModel>,
    pub(super) multiplexer: Arc<BoundedMultiplexer>,
    pub(super) artifacts: Arc<FsPublishedArtifactStore>,
    pub(super) external_content: Arc<FsExternalContentIndex>,
    pub(super) projection: BrowserProjectionConfig,
    pub(super) max_pending_actions: NonZeroUsize,
}

/// What odind composes for one pod browser: the established relay into
/// the pod's browser container and the pod plan's declarations.
pub struct PodBrowserLaunch {
    pub relay: Box<dyn WorkerRelay>,
    pub paths: RelayedWorkerPaths,
    pub viewport: Viewport,
    /// Opaque bounded identity projected to session views (`pod:<run>`).
    pub identity: String,
    /// The pod's declared egress hosts: the only hosts it may navigate.
    pub navigate_hosts: Vec<String>,
    /// The profile's declared owner-stream gate.
    pub stream: bool,
}

impl PodBrowserOpener {
    async fn open(
        &self,
        session: live::BrowserSessionId,
        launch: PodBrowserLaunch,
    ) -> Result<(BrowserProjection, BrowserCommandCoordinator, PathBuf), String> {
        let policy = BrowserPolicySnapshot::initial(session, self.rules.clone())
            .map_err(|error| format!("pod browser policy: {error}"))?;
        let staging = self.staging_parent.join(session.to_string());
        create_private_dir(&staging)?;
        let relayed = RelayedWorkerLaunch {
            relay: launch.relay,
            paths: launch.paths,
            viewport: launch.viewport,
            limits: self.resource_limits,
            startup: self.startup,
            command: self.command,
            shutdown: self.shutdown,
            takeover_lease: self.takeover_lease,
            download_staging_root: staging.clone(),
            identity: launch.identity,
            navigate_hosts: Some(launch.navigate_hosts),
        };
        let publisher: Arc<dyn ArtifactPublisher> = self.artifacts.clone();
        let opened = BrowserSession::open_relayed(
            relayed,
            self.stop_host.clone(),
            policy,
            Arc::clone(&self.safety),
            FrameWiring {
                stream_id: live::pod_browser_stream_id(&session),
                limits: self.frame_limits,
                publisher,
                stream: launch.stream,
            },
            self.session_limits,
            Arc::clone(&self.ledger),
        )
        .await;
        let opened = match opened {
            Ok(opened) => opened,
            Err(error) => {
                let _ = std::fs::remove_dir_all(&staging);
                return Err(format!("pod browser session did not open: {error}"));
            }
        };
        let projection = BrowserProjection::spawn(
            opened,
            Arc::clone(&self.read_model),
            Arc::clone(&self.multiplexer),
            Arc::clone(&self.artifacts),
            Arc::clone(&self.external_content),
            self.projection,
        );
        let coordinator = BrowserCommandCoordinator::new(
            Arc::clone(&self.ledger),
            Arc::clone(&self.read_model),
            projection.handle(),
            self.max_pending_actions,
        );
        Ok((projection, coordinator, staging))
    }
}

fn create_private_dir(path: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|error| format!("pod browser staging {}: {error}", path.display()))
}

/// One pod browser's place in the routes: reserved from the moment its
/// agent session is attached, open once the relayed session launched.
struct PodRoute {
    owner: SessionId,
    coordinator: Option<BrowserCommandCoordinator>,
}

/// Where one request goes.
#[derive(Debug, PartialEq, Eq)]
enum Route {
    Local,
    Pod,
    /// The pod browser is reserved but its session has not opened yet.
    Opening,
    Refused(&'static str),
}

/// Agents may address only their own pod browser; devices (`caller: None`)
/// may address any known session. Unknown sessions must not fall back to local.
fn route(
    session: &live::BrowserSessionId,
    caller: Option<&SessionId>,
    pods: &BTreeMap<live::BrowserSessionId, (SessionId, bool)>,
    local: Option<&live::BrowserSessionId>,
) -> Route {
    match (pods.get(session), caller) {
        (Some((owner, _)), Some(caller)) if owner != caller => {
            Route::Refused("this browser belongs to another pod's agent")
        }
        (Some((_, true)), _) => Route::Pod,
        (Some((_, false)), _) => Route::Opening,
        (None, Some(caller)) if pods.values().any(|(owner, _)| owner == caller) => {
            Route::Refused("a pod agent addresses only its own pod's browser")
        }
        (None, _) if local == Some(session) => Route::Local,
        (None, _) => Route::Refused("that browser session is closed or unknown"),
    }
}

/// Every browser session the authority serves, routed by session id.
pub struct BrowserRoutes {
    local: Option<BrowserCommandCoordinator>,
    opener: Option<PodBrowserOpener>,
    pods: Mutex<BTreeMap<live::BrowserSessionId, PodRoute>>,
}

impl BrowserRoutes {
    pub fn new(local: Option<BrowserCommandCoordinator>, opener: Option<PodBrowserOpener>) -> Self {
        Self {
            local,
            opener,
            pods: Mutex::new(BTreeMap::new()),
        }
    }

    fn pods(&self) -> std::sync::MutexGuard<'_, BTreeMap<live::BrowserSessionId, PodRoute>> {
        self.pods
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn resolve(
        &self,
        session: &live::BrowserSessionId,
        caller: Option<&SessionId>,
    ) -> Result<BrowserCommandCoordinator, &'static str> {
        let pods = self.pods();
        let view = pods
            .iter()
            .map(|(id, pod)| (*id, (pod.owner.clone(), pod.coordinator.is_some())))
            .collect();
        let local = self
            .local
            .as_ref()
            .map(BrowserCommandCoordinator::session_id);
        match route(session, caller, &view, local.as_ref()) {
            Route::Local => self
                .local
                .clone()
                .ok_or("the authority runs no local browser"),
            Route::Pod => pods
                .get(session)
                .and_then(|pod| pod.coordinator.clone())
                .ok_or("the pod browser closed"),
            Route::Opening => Err("the pod's browser is still opening; try again shortly"),
            Route::Refused(reason) => Err(reason),
        }
    }

    /// Reserves the pod browser of one agent session. `false` when it is
    /// already reserved or open (a reattach of the same agent session), or
    /// when this authority cannot open pod browsers at all.
    pub fn reserve(&self, session: live::BrowserSessionId, owner: SessionId) -> bool {
        if self.opener.is_none() {
            return false;
        }
        let mut pods = self.pods();
        if pods.contains_key(&session) {
            return false;
        }
        pods.insert(
            session,
            PodRoute {
                owner,
                coordinator: None,
            },
        );
        true
    }

    /// Drops a reservation whose relay could not be established.
    pub fn release(&self, session: &live::BrowserSessionId) {
        let mut pods = self.pods();
        if pods
            .get(session)
            .is_some_and(|route| route.coordinator.is_none())
        {
            pods.remove(session);
        }
    }

    /// Opens a reserved pod browser over the relay odind established and
    /// supervises it: when the session ends (the pod went away, the relay
    /// closed), its pending actions are settled, the projection retires and
    /// the route is removed. A failed open removes the reservation.
    pub async fn open_pod(
        self: &Arc<Self>,
        session: live::BrowserSessionId,
        launch: PodBrowserLaunch,
    ) -> Result<(), String> {
        let Some(opener) = self.opener.clone() else {
            self.pods().remove(&session);
            return Err("this authority opens no pod browsers".to_owned());
        };
        let (projection, coordinator, staging) = match opener.open(session, launch).await {
            Ok(opened) => opened,
            Err(error) => {
                self.pods().remove(&session);
                return Err(error);
            }
        };
        let registered = match self.pods().get_mut(&session) {
            Some(route) => {
                route.coordinator = Some(coordinator.clone());
                true
            }
            None => false,
        };
        if !registered {
            // Released while opening: retire at once.
            let _ = coordinator.shutdown_pending().await;
            let _ = projection.shutdown().await;
            let _ = std::fs::remove_dir_all(&staging);
            return Err("the pod browser was released while it opened".to_owned());
        }
        let routes = Arc::clone(self);
        tokio::spawn(async move {
            let terminal = projection.handle().wait_terminal().await;
            routes.pods().remove(&session);
            let _ = coordinator.shutdown_pending().await;
            let teardown = projection.shutdown().await;
            let _ = std::fs::remove_dir_all(&staging);
            tracing::info!(
                "pod browser {session} closed (terminal={terminal:?}, teardown_ok={})",
                teardown.is_ok()
            );
        });
        Ok(())
    }

    fn approval_route(&self, approval: &ApprovalId) -> Option<BrowserCommandCoordinator> {
        self.pods()
            .values()
            .filter_map(|pod| pod.coordinator.clone())
            .find(|coordinator| coordinator.holds_pending_approval(approval))
            .or_else(|| self.local.clone())
    }

    fn tool_coordinator(
        &self,
        binding: BrowserCapabilityBinding,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<BrowserCommandCoordinator, HostToolError> {
        let session = arguments
            .get("sessionId")
            .and_then(Value::as_str)
            .and_then(|value| live::BrowserSessionId::parse(value).ok());
        let Some(session) = session else {
            // Evidence extractors and malformed inputs carry no session;
            // the local owner keeps its exact typed refusals for them.
            return self.local.clone().ok_or(HostToolError::Arguments {
                tool: binding.id(),
                detail: "the authority runs no local browser".to_owned(),
            });
        };
        self.resolve(&session, scope.session.as_ref())
            .map_err(|detail| HostToolError::Arguments {
                tool: binding.id(),
                detail: detail.to_owned(),
            })
    }
}

fn request_session(request: &live::HuginnRequest) -> Option<live::BrowserSessionId> {
    match request {
        live::HuginnRequest::BrowserObserve(request) => Some(request.session_id),
        live::HuginnRequest::BrowserCommand(command) => Some(command.context().session_id),
        _ => None,
    }
}

#[async_trait]
impl live::HuginnCommandPort for BrowserRoutes {
    async fn execute(
        &self,
        request: live::HuginnRequest,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        match &self.local {
            Some(local) => local.execute(request).await,
            None => Err(live::HuginnProtocolError::Unauthenticated),
        }
    }
}

#[async_trait]
impl AuthenticatedCommandPort for BrowserRoutes {
    async fn execute_authenticated(
        &self,
        device: live::DeviceId,
        request: live::HuginnRequest,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        let coordinator = match (&request, request_session(&request)) {
            (live::HuginnRequest::ApprovalDecision(command), _) => {
                self.approval_route(&command.approval_id)
            }
            (_, Some(session)) => match self.resolve(&session, None) {
                Ok(coordinator) => Some(coordinator),
                Err(reason) => {
                    return Err(live::HuginnProtocolError::InvalidRequest {
                        code: "browserSession".to_owned(),
                        message: reason.to_owned(),
                    })
                }
            },
            (_, None) => self.local.clone(),
        };
        match coordinator {
            Some(coordinator) => coordinator.execute_authenticated(device, request).await,
            None => Err(live::HuginnProtocolError::InvalidRequest {
                code: "browserSession".to_owned(),
                message: "no browser session serves this request".to_owned(),
            }),
        }
    }
}

impl BrowserCapabilityOwner for BrowserRoutes {
    fn invoke_browser_capability(
        &self,
        binding: BrowserCapabilityBinding,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        self.tool_coordinator(binding, &invocation.scope, &invocation.arguments)?
            .invoke_browser_capability(binding, invocation)
    }

    fn invoke_consumed(
        &self,
        binding: BrowserCapabilityBinding,
        invocation: HostInvocation,
        consumed: &odin_omp::host_tools::ConsumedHostCommand,
    ) -> Result<Value, HostToolError> {
        self.tool_coordinator(binding, &invocation.scope, &invocation.arguments)?
            .invoke_consumed(binding, invocation, consumed)
    }

    fn preflight_browser_capability(
        &self,
        contract: &odin_kernel::CapabilityContract,
        binding: BrowserCapabilityBinding,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        self.tool_coordinator(binding, scope, arguments)?
            .preflight_browser_capability(contract, binding, scope, arguments)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> live::BrowserSessionId {
        live::BrowserSessionId::parse(&format!("00000000-0000-4000-8000-0000000000{n:02}")).unwrap()
    }

    fn caller(name: &str) -> SessionId {
        SessionId::new(name.to_owned()).unwrap()
    }

    #[test]
    fn each_browser_session_is_routed_to_its_owner_only() {
        let mut pods = BTreeMap::new();
        pods.insert(id(1), (caller("pod-agent-a"), true));
        pods.insert(id(2), (caller("pod-agent-b"), false));
        let local = id(9);
        // A Huginn device reaches every session; an opening one is typed.
        assert_eq!(route(&id(1), None, &pods, Some(&local)), Route::Pod);
        assert_eq!(route(&id(2), None, &pods, Some(&local)), Route::Opening);
        assert_eq!(route(&local, None, &pods, Some(&local)), Route::Local);
        // A pod agent reaches its own pod's browser and nothing else.
        assert_eq!(
            route(&id(1), Some(&caller("pod-agent-a")), &pods, Some(&local)),
            Route::Pod
        );
        assert!(matches!(
            route(&id(2), Some(&caller("pod-agent-a")), &pods, Some(&local)),
            Route::Refused(_)
        ));
        assert!(matches!(
            route(&local, Some(&caller("pod-agent-a")), &pods, Some(&local)),
            Route::Refused(_)
        ));
        // Any other session keeps the local browser and never a pod's.
        assert_eq!(
            route(&local, Some(&caller("sinmara")), &pods, Some(&local)),
            Route::Local
        );
        assert!(matches!(
            route(&id(1), Some(&caller("sinmara")), &pods, Some(&local)),
            Route::Refused(_)
        ));
        // A closed or unknown session is refused as such, never sent to
        // the local browser (which named it "a different session").
        assert_eq!(
            route(&id(7), None, &pods, Some(&local)),
            Route::Refused("that browser session is closed or unknown")
        );
        assert_eq!(
            route(&id(7), Some(&caller("kubert")), &pods, None),
            Route::Refused("that browser session is closed or unknown")
        );
    }
}
