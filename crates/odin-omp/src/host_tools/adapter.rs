//! Declared out-of-process adapters: framed-exec transport, shared backend
//! configuration, and marker bindings.
//!
//! A new external tool is a declaration: Nix configures one backend per
//! adapter id (`[adapter_backends.<id>]` static argv; the executable is the
//! runtime-manifest identity `adapter.<id>`), and registry capabilities with
//! `implementation = "<id>"` bind the markers. [`DeclaredAdapterBackends`]
//! learns each backend's descriptor through its `describe` handshake
//! (cached; re-described when the backend's status identity changes, e.g.
//! after a restart with a new binding) and probes `status` for health.
//!
//! [`FramedExecAdapterTransport`] implements the core
//! [`AdapterTransport`] seam over the existing supervised framed-exec
//! path: one canonical single-line JSON-RPC request frame on stdin, one
//! canonical single-line response frame on stdout, launched exclusively
//! through the registered-service `StopAuthority` path that already
//! backs `FramedExecTool`. No direct spawn, no shell, no
//! model-built argv — the executable and the fully static argv come only
//! from the configured backend binding.
//!
//! Failures before request delivery are [`AdapterTransportFault::NotDispatched`];
//! failures after launch are [`AdapterTransportFault::DispatchedUnknown`].
//! Unknown outcomes must not be reported as unavailable.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use odin_adapter_core::descriptor::AdapterDescriptor;
use odin_adapter_core::dispatch::{AdapterBackends, AdapterUnavailable};
use odin_adapter_core::ids::WireAdapterIdentity;
use odin_adapter_core::status::AdapterStatusSnapshot;
use odin_adapter_core::transport::{
    encode_frame, AdapterTransport, AdapterTransportFault, JsonRpcOutcome, JsonRpcRequest,
};
use odin_adapter_core::{ADAPTER_OPERATION_HANDLER, ADAPTER_RECEIPT_EVIDENCE};
use odin_domain::Scope;
use odin_kernel::HandlerBinding;
use serde_json::{json, Value};

use super::binding::{framed_exchange, FramedDeadline};
use super::operations::{HostAdapterStatusTransport, HostToolOperationError};
use super::{
    HostInvocation, HostTool, HostToolError, InternalBindingKey, RpcHostToolDefinition,
    ToolLoadMode,
};
use crate::frames::{RpcFrameDecoder, RpcProtocolVersion};
use crate::process::OmpWorkerLaunch;

/// The manifest executable key of one declared adapter backend.
pub fn adapter_executable_key(adapter: &str) -> String {
    format!("adapter.{adapter}")
}

/// Bound on the `describe` and `status` handshakes of a backend.
pub const ADAPTER_PROBE_TIMEOUT: Duration = Duration::from_secs(20);

fn not_dispatched(detail: impl std::fmt::Display) -> AdapterTransportFault {
    AdapterTransportFault::NotDispatched {
        detail: detail.to_string(),
    }
}

fn dispatched_unknown(detail: impl std::fmt::Display) -> AdapterTransportFault {
    AdapterTransportFault::DispatchedUnknown {
        detail: detail.to_string(),
    }
}

/// Uses supervised framed exec with bounded frames and a deadline.
/// A confirmed `Stopped` result is required before trusting captured output.
#[derive(Clone)]
pub struct FramedExecAdapterTransport {
    worker: OmpWorkerLaunch,
}

impl FramedExecAdapterTransport {
    /// Uses the worker's supervised launch path rather than spawning directly.
    pub fn new(worker: OmpWorkerLaunch) -> Self {
        Self { worker }
    }
}

impl AdapterTransport for FramedExecAdapterTransport {
    fn call(
        &self,
        binding: &HandlerBinding,
        timeout: std::time::Duration,
        request: &JsonRpcRequest,
    ) -> Result<JsonRpcOutcome, AdapterTransportFault> {
        let (executable, argv) = match binding {
            HandlerBinding::Exec { executable, argv } => (executable, argv),
            HandlerBinding::Builtin { name } => {
                return Err(not_dispatched(format!(
                    "adapter transport governs only exec subprocess bindings; \
                     builtin handler {name:?} dispatches no frame"
                )));
            }
        };

        // Failures before launch cannot have delivered the request.
        let frame = encode_frame(&request.to_wire())
            .map_err(|error| not_dispatched(format!("adapter request frame rejected: {error}")))?;
        let mut args = Vec::with_capacity(argv.len().saturating_add(1));
        args.push(executable.clone());
        args.extend(argv.iter().cloned());
        let worker = self.worker.clone();
        let naming = worker
            .next_naming()
            .map_err(|error| not_dispatched(format!("adapter worker naming rejected: {error}")))?;
        let frozen_argv = odin_process::FrozenArgv::new(args, 128, 1024 * 1024)
            .map_err(|error| not_dispatched(format!("adapter argv rejected: {error}")))?;
        let environment = odin_process::EnvironmentBuilder::new([odin_process::CORRELATION_ENV])
            .map_err(|error| not_dispatched(format!("adapter environment rejected: {error}")))?
            .set(
                odin_process::CORRELATION_ENV,
                worker.correlation_id.as_str(),
            )
            .map_err(|error| not_dispatched(format!("adapter environment rejected: {error}")))?
            .build();
        let spec = odin_process::CommandSpec {
            argv: frozen_argv,
            environment,
            current_dir: PathBuf::from("/"),
        };
        let deadline = Instant::now() + timeout;
        let launched = worker
            .authority
            .launch_registered_service(
                naming,
                &worker.correlation_id,
                &spec,
                worker.limits,
                &worker.binding,
            )
            .map_err(|error| {
                not_dispatched(format!(
                    "adapter backend {executable} launch failed: {error}"
                ))
            })?;

        // One bounded canonical request frame, then EOF, exchanged by this
        // call under its one deadline. From the first attempted write onward
        // the host can no longer prove the frame never reached the child:
        // every failure is `DispatchedUnknown`, and every path requests the
        // authority's stop before anything captured is trusted.
        let output = framed_exchange(
            &worker.authority,
            launched,
            &frame,
            FramedDeadline {
                at: deadline,
                timeout,
            },
            &format!("adapter backend {executable}"),
        )
        .map_err(dispatched_unknown)?;

        // Canonical framed stdout: exactly one terminated physical line,
        // the frame bytes fully consumed, zero trailing bytes, and the
        // parsed value byte-identical to its canonical re-encoding.
        if !output.ends_with(b"\n") {
            return Err(dispatched_unknown(
                "adapter reply is not newline-terminated after a successful run",
            ));
        }
        let output_len = output.len();
        let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V1);
        let reply = decoder
            .push_owned_line(output)
            .map_err(|error| dispatched_unknown(format!("adapter reply frame rejected: {error}")))?
            .ok_or_else(|| dispatched_unknown("adapter stdout produced no complete reply frame"))?;
        let consumed: usize = reply.lines().iter().map(|line| line.len()).sum();
        if reply.lines().len() != 1 || consumed != output_len {
            return Err(dispatched_unknown(
                "adapter stdout carried trailing bytes beyond one reply frame",
            ));
        }
        let canonical = odin_strict_json::canonicalize(reply.value()).map_err(|error| {
            dispatched_unknown(format!("adapter reply canonical re-encode failed: {error}"))
        })?;
        if canonical != reply.raw() {
            return Err(dispatched_unknown(
                "adapter reply frame is not canonical JSON",
            ));
        }

        // The outcome parser pins the reply to the request id and the
        // typed error-code vocabulary; a malformed reply proves nothing
        // about the upstream call and stays unknown.
        JsonRpcOutcome::from_wire(reply.value(), &request.id)
            .map_err(|error| dispatched_unknown(format!("adapter reply rejected: {error}")))
    }
}

/// One configured adapter backend: its governed worker launch and its
/// exact exec binding (manifest executable plus static argv).
#[derive(Clone)]
pub struct DeclaredAdapterBackend {
    worker: OmpWorkerLaunch,
    binding: HandlerBinding,
}

impl DeclaredAdapterBackend {
    /// Binds one backend. The executable must be the absolute store path
    /// the runtime manifest registers under [`adapter_executable_key`];
    /// the argv is fully static declaration data.
    pub fn new(
        worker: OmpWorkerLaunch,
        executable: String,
        argv: Vec<String>,
    ) -> Result<Self, String> {
        if !super::is_store_executable_form(&executable) {
            return Err(format!(
                "adapter executable {executable:?} is not a normalized /nix/store path"
            ));
        }
        Ok(Self {
            worker,
            binding: HandlerBinding::Exec { executable, argv },
        })
    }
}

/// The configured adapter backends of this host. Shared by the dispatcher
/// ([`AdapterBackends`]) and the health tracker
/// ([`HostAdapterStatusTransport`]), so both always speak to the same
/// backend under the same descriptor identity.
pub struct DeclaredAdapterBackends {
    backends: BTreeMap<String, DeclaredAdapterBackend>,
    descriptors: Mutex<BTreeMap<String, AdapterDescriptor>>,
}

impl DeclaredAdapterBackends {
    pub fn new(backends: BTreeMap<String, DeclaredAdapterBackend>) -> Self {
        Self {
            backends,
            descriptors: Mutex::new(BTreeMap::new()),
        }
    }

    /// No adapter is configured: every adapter capability is a typed
    /// unavailable.
    pub fn none() -> Self {
        Self::new(BTreeMap::new())
    }

    /// The configured adapter ids.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.backends.keys().map(String::as_str)
    }

    fn backend(&self, adapter: &str) -> Result<&DeclaredAdapterBackend, AdapterUnavailable> {
        self.backends
            .get(adapter)
            .ok_or_else(|| AdapterUnavailable {
                adapter: adapter.to_owned(),
                detail: "no backend is declared for it on this host".to_owned(),
            })
    }

    fn transport_call(
        backend: &DeclaredAdapterBackend,
        timeout: Duration,
        request: &JsonRpcRequest,
    ) -> Result<JsonRpcOutcome, AdapterTransportFault> {
        FramedExecAdapterTransport::new(backend.worker.clone()).call(
            &backend.binding,
            timeout,
            request,
        )
    }

    /// The `describe` handshake: one bounded call, the reply validated as a
    /// canonical descriptor whose adapter id is the configured key.
    fn describe(&self, adapter: &str) -> Result<AdapterDescriptor, AdapterUnavailable> {
        let unavailable = |detail: String| AdapterUnavailable {
            adapter: adapter.to_owned(),
            detail,
        };
        let backend = self.backend(adapter)?;
        let id = odin_process::mint_worker_id()
            .map_err(|error| unavailable(format!("describe probe id rejected: {error}")))?;
        let request = JsonRpcRequest::describe(id.as_str());
        let outcome = Self::transport_call(backend, ADAPTER_PROBE_TIMEOUT, &request)
            .map_err(|fault| unavailable(format!("describe did not settle: {}", fault.detail())))?;
        let result = match outcome {
            JsonRpcOutcome::Success { result, .. } => result,
            JsonRpcOutcome::Error { code, message, .. } => {
                return Err(unavailable(format!(
                    "describe answered the typed error {code:?}: {message}"
                )))
            }
        };
        let descriptor = AdapterDescriptor::from_wire(&result)
            .map_err(|error| unavailable(format!("descriptor rejected: {error}")))?;
        if descriptor.adapter().adapter_id.as_str() != adapter {
            return Err(unavailable(format!(
                "backend describes itself as {:?}",
                descriptor.adapter().adapter_id.as_str()
            )));
        }
        tracing::info!(
            "odind: adapter described id={adapter} version={} operations={}",
            descriptor.adapter().version.as_str(),
            descriptor
                .operations()
                .iter()
                .map(|operation| operation.kind.as_str())
                .collect::<Vec<_>>()
                .join(",")
        );
        Ok(descriptor)
    }

    fn descriptors(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, AdapterDescriptor>> {
        self.descriptors
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The cached descriptor identity of one adapter, if it has described
    /// itself.
    pub fn identity(&self, adapter: &str) -> Option<WireAdapterIdentity> {
        self.descriptors()
            .get(adapter)
            .map(|descriptor| descriptor.adapter().clone())
    }
}

impl AdapterBackends for DeclaredAdapterBackends {
    fn descriptor(&self, adapter: &str) -> Result<AdapterDescriptor, AdapterUnavailable> {
        if let Some(descriptor) = self.descriptors().get(adapter) {
            return Ok(descriptor.clone());
        }
        let descriptor = self.describe(adapter)?;
        self.descriptors()
            .insert(adapter.to_owned(), descriptor.clone());
        Ok(descriptor)
    }

    fn call(
        &self,
        adapter: &str,
        timeout: Duration,
        request: &JsonRpcRequest,
    ) -> Result<JsonRpcOutcome, AdapterTransportFault> {
        let backend = self
            .backend(adapter)
            .map_err(|unavailable| not_dispatched(unavailable.to_string()))?;
        Self::transport_call(backend, timeout, request)
    }
}

impl HostAdapterStatusTransport for DeclaredAdapterBackends {
    /// One `status` probe. The snapshot must carry the identity the
    /// adapter described itself with; a changed identity (a restarted
    /// backend with a new binding) is re-described once, so the
    /// dispatcher never serves a stale descriptor.
    fn refresh_status(
        &self,
        adapter: &str,
    ) -> Result<AdapterStatusSnapshot, HostToolOperationError> {
        let failure = |detail: String| HostToolOperationError::AdapterStatus {
            adapter: adapter.to_owned(),
            detail,
        };
        let backend = self
            .backend(adapter)
            .map_err(|unavailable| failure(unavailable.detail))?;
        let id = odin_process::mint_worker_id()
            .map_err(|error| failure(format!("status probe id rejected: {error}")))?;
        let request = JsonRpcRequest::status(id.as_str());
        let outcome = Self::transport_call(backend, ADAPTER_PROBE_TIMEOUT, &request)
            .map_err(|fault| failure(format!("status probe did not settle: {}", fault.detail())))?;
        let result = match outcome {
            JsonRpcOutcome::Success { result, .. } => result,
            JsonRpcOutcome::Error { code, message, .. } => {
                return Err(failure(format!(
                    "status probe answered the typed error {code:?}: {message}"
                )))
            }
        };
        let snapshot = AdapterStatusSnapshot::from_wire(&result)
            .map_err(|error| failure(format!("status snapshot rejected: {error}")))?;
        let known = self.identity(adapter);
        if known.as_ref() != Some(snapshot.adapter()) {
            self.descriptors().remove(adapter);
            let descriptor = self
                .describe(adapter)
                .map_err(|unavailable| failure(unavailable.detail))?;
            if descriptor.adapter() != snapshot.adapter() {
                return Err(failure(
                    "status identity does not match the backend's own descriptor".to_owned(),
                ));
            }
            self.descriptors().insert(adapter.to_owned(), descriptor);
        }
        Ok(snapshot)
    }
}

/// The internal owner of the two declared-adapter markers. Adapter
/// capabilities never dispatch to a HostTool — the adapter executor routes
/// them to their backend — so invoking a marker directly is refused; the
/// registration exists so the operation catalog proves both bindings
/// resolve.
struct AdapterMarkerTool {
    definition: RpcHostToolDefinition,
}

impl HostTool for AdapterMarkerTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn preflight(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        _scope: &Scope,
        _arguments: &Value,
    ) -> Result<(), HostToolError> {
        Ok(())
    }

    fn invoke(&self, _invocation: HostInvocation) -> Result<Value, HostToolError> {
        Err(HostToolError::Catalog {
            detail: format!(
                "{} is a declared-adapter marker; adapter operations dispatch only through \
                 the adapter executor",
                self.definition.name
            ),
        })
    }
}

/// Registers the two declared-adapter markers as internal bindings.
pub fn register_adapter_markers(
    registry: &mut super::HostToolRegistry,
) -> Result<(), HostToolError> {
    for name in [ADAPTER_OPERATION_HANDLER, ADAPTER_RECEIPT_EVIDENCE] {
        registry.register_internal(
            InternalBindingKey::Builtin(name.to_owned()),
            Arc::new(AdapterMarkerTool {
                definition: RpcHostToolDefinition {
                    name: Cow::Borrowed(name),
                    label: Cow::Borrowed("Declared adapter"),
                    description: Cow::Borrowed(
                        "Declared-adapter marker binding; never invoked directly.",
                    ),
                    parameters: json!({"type": "object"}),
                    hidden: true,
                    load_mode: ToolLoadMode::Essential,
                },
            }),
        )?;
    }
    Ok(())
}

/// The model-visible face of one declared-adapter capability: its
/// definition (tool name, the registry description, the declared input
/// schema) is what the session lists. Calls never reach it — the operation
/// authority routes every adapter contract to the adapter executor — so a
/// direct invocation is refused.
struct DeclaredAdapterTool {
    definition: RpcHostToolDefinition,
}

impl HostTool for DeclaredAdapterTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn preflight(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        _scope: &Scope,
        _arguments: &Value,
    ) -> Result<(), HostToolError> {
        Ok(())
    }

    fn invoke(&self, _invocation: HostInvocation) -> Result<Value, HostToolError> {
        Err(HostToolError::Catalog {
            detail: format!(
                "{} is a declared-adapter tool; it dispatches only through the adapter executor",
                self.definition.name
            ),
        })
    }
}

/// Registers each admitted adapter tool using its declared name, description, and schema.
pub fn register_adapter_tools(
    registry: &mut super::HostToolRegistry,
    contracts: &BTreeMap<odin_domain::CapabilityId, odin_kernel::CapabilityContract>,
    schemas: &dyn odin_kernel::capability::SchemaCatalog,
) -> Result<usize, HostToolError> {
    let mut registered = 0;
    for contract in contracts
        .values()
        .filter(|contract| contract.adapter.is_some())
    {
        let schema = schemas
            .schema(&contract.input_schema_ref)
            .map_err(|error| HostToolError::Catalog {
                detail: format!(
                    "adapter capability {} input schema {}: {error}",
                    contract.id, contract.input_schema_ref
                ),
            })?;
        let parameters = schema.canonical_json().clone();
        registry.register(Arc::new(DeclaredAdapterTool {
            definition: RpcHostToolDefinition {
                name: Cow::Owned(contract.tool_name.as_str().to_owned()),
                label: Cow::Owned(contract.id.as_str().to_owned()),
                description: Cow::Owned(contract.description.clone()),
                parameters,
                hidden: false,
                load_mode: ToolLoadMode::Essential,
            },
        }))?;
        registered += 1;
    }
    Ok(registered)
}
