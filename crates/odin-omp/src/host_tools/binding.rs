use std::borrow::Cow;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use odin_domain::Scope;
use odin_kernel::PreparedEffect;
use odin_types::{CapsuleId, CorrelationId};
use serde_json::Value;

use crate::frames::{RpcFrameDecoder, RpcProtocolVersion, MAX_FRAME_BYTES};

use super::{
    ConsumedHostCommand, HostInvocation, HostTool, HostToolError, RpcHostToolDefinition,
    ToolLoadMode,
};

/// The six compiled browser handler/extractor bindings owned by the real
/// BrowserArm runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrowserCapabilityBinding {
    Observe,
    ObserveEvidence,
    Interact,
    InteractEvidence,
    Consequential,
    ConsequentialEvidence,
}

impl BrowserCapabilityBinding {
    pub(super) const ALL: [Self; 6] = [
        Self::Observe,
        Self::ObserveEvidence,
        Self::Interact,
        Self::InteractEvidence,
        Self::Consequential,
        Self::ConsequentialEvidence,
    ];

    pub const fn id(self) -> &'static str {
        match self {
            Self::Observe => "odin_browser.observe",
            Self::ObserveEvidence => "odin_browser.observe_evidence",
            Self::Interact => "odin_browser.interact",
            Self::InteractEvidence => "odin_browser.interact_evidence",
            Self::Consequential => "odin_browser.consequential",
            Self::ConsequentialEvidence => "odin_browser.consequential_evidence",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Observe => "Browser Observe",
            Self::ObserveEvidence => "Browser Observe Evidence",
            Self::Interact => "Browser Interact",
            Self::InteractEvidence => "Browser Interact Evidence",
            Self::Consequential => "Browser Consequential",
            Self::ConsequentialEvidence => "Browser Consequential Evidence",
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::Observe => "Execute one bounded typed BrowserArm observation.",
            Self::ObserveEvidence => "Extract validated evidence from a BrowserArm observation.",
            Self::Interact => "Execute one ordinary authority-bound BrowserArm action.",
            Self::InteractEvidence => "Extract validated evidence from an ordinary browser action.",
            Self::Consequential => "Execute one operator-approved consequential BrowserArm action.",
            Self::ConsequentialEvidence => {
                "Extract validated evidence from a consequential browser action."
            }
        }
    }

    /// The registry capability id this binding serves — the contract the
    /// kernel matches a prepared operation against.
    pub const fn capability_id(self) -> &'static str {
        match self {
            Self::Observe | Self::ObserveEvidence => "browser.observe",
            Self::Interact | Self::InteractEvidence => "browser.interact",
            Self::Consequential | Self::ConsequentialEvidence => "browser.consequential",
        }
    }

    /// The model-visible tool name the registry contract derives for the
    /// capability (`.` → `_`), exactly the name the kernel listing carries.
    pub const fn listed_name(self) -> &'static str {
        match self {
            Self::Observe | Self::ObserveEvidence => "browser_observe",
            Self::Interact | Self::InteractEvidence => "browser_interact",
            Self::Consequential | Self::ConsequentialEvidence => "browser_consequential",
        }
    }

    /// Whether this binding is an evidence extractor whose input is the
    /// handler's post-effect output.
    pub const fn is_evidence_extractor(self) -> bool {
        matches!(
            self,
            Self::ObserveEvidence | Self::InteractEvidence | Self::ConsequentialEvidence
        )
    }
    /// Whether the canonical input schema expresses its action/argument
    /// pairing as a top-level `oneOf` refinement over the plain object.
    /// Strict function-calling providers refuse such combinators at the top
    /// level of function parameters, so exactly these listed routes carry a
    /// model-surface projection; every other binding lists canonically.
    pub(super) const fn pairs_action_with_arguments(self) -> bool {
        matches!(self, Self::Interact | Self::Consequential)
    }
    pub(super) const fn schema(self) -> &'static str {
        match self {
            Self::Observe => {
                include_str!("../../../../schemas/capability/browser.observe.input.json")
            }
            Self::ObserveEvidence => {
                include_str!("../../../../schemas/capability/browser.observe.output.json")
            }
            Self::Interact => {
                include_str!("../../../../schemas/capability/browser.interact.input.json")
            }
            Self::InteractEvidence => {
                include_str!("../../../../schemas/capability/browser.interact.output.json")
            }
            Self::Consequential => {
                include_str!("../../../../schemas/capability/browser.consequential.input.json")
            }
            Self::ConsequentialEvidence => {
                include_str!("../../../../schemas/capability/browser.consequential.output.json")
            }
        }
    }
}

/// Real BrowserArm capability owner installed by production composition.
///
/// The concrete implementation is `BrowserCommandCoordinator`; this trait is
/// the dependency-inversion seam that keeps odin-omp independent of odin-cli.
pub trait BrowserCapabilityOwner: Send + Sync {
    fn invoke_browser_capability(
        &self,
        binding: BrowserCapabilityBinding,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError>;

    /// Recheck executor-recorded command details against durable records without consuming approval twice.
    fn invoke_consumed(
        &self,
        binding: BrowserCapabilityBinding,
        _invocation: HostInvocation,
        _consumed: &ConsumedHostCommand,
    ) -> Result<Value, HostToolError> {
        Err(HostToolError::Unavailable {
            tool: binding.id(),
            reason: "this browser owner cannot verify a consumed permit".to_owned(),
        })
    }

    /// Applies [`HostTool::preflight`] without interacting with the browser; execution rechecks.
    /// Evidence extractors have no preflight output to inspect and must document their no-op.
    fn preflight_browser_capability(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        binding: BrowserCapabilityBinding,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError>;
}

/// Single-assignment construction-order bridge for the real BrowserArm owner.
///
/// OMP runtime factories exist before the browser process is launched. The
/// concrete coordinator is installed exactly once before listener startup;
/// invocation and production-composition checks fail closed while unbound.
#[derive(Default)]
pub struct BrowserCapabilityOwnerSlot {
    owner: RwLock<Option<Arc<dyn BrowserCapabilityOwner>>>,
}

impl BrowserCapabilityOwnerSlot {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn bind(&self, owner: Arc<dyn BrowserCapabilityOwner>) -> Result<(), HostToolError> {
        let mut binding = self.owner.write().map_err(|_| HostToolError::Catalog {
            detail: "browser capability owner slot is poisoned".to_owned(),
        })?;
        if binding.is_some() {
            return Err(HostToolError::Catalog {
                detail: "browser capability owner is already bound".to_owned(),
            });
        }
        *binding = Some(owner);
        Ok(())
    }
}

impl BrowserCapabilityOwner for BrowserCapabilityOwnerSlot {
    fn invoke_browser_capability(
        &self,
        binding: BrowserCapabilityBinding,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        let owner = self
            .owner
            .read()
            .map_err(|_| HostToolError::Catalog {
                detail: "browser capability owner slot is poisoned".to_owned(),
            })?
            .clone()
            .ok_or_else(|| HostToolError::Catalog {
                detail: "browser capability owner is not bound".to_owned(),
            })?;
        owner.invoke_browser_capability(binding, invocation)
    }

    fn invoke_consumed(
        &self,
        binding: BrowserCapabilityBinding,
        invocation: HostInvocation,
        consumed: &ConsumedHostCommand,
    ) -> Result<Value, HostToolError> {
        let owner = self
            .owner
            .read()
            .map_err(|_| HostToolError::Catalog {
                detail: "browser capability owner slot is poisoned".to_owned(),
            })?
            .clone()
            .ok_or_else(|| HostToolError::Catalog {
                detail: "browser capability owner is not bound".to_owned(),
            })?;
        owner.invoke_consumed(binding, invocation, consumed)
    }

    fn preflight_browser_capability(
        &self,
        contract: &odin_kernel::CapabilityContract,
        binding: BrowserCapabilityBinding,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        // An unconfigured owner is unavailable before dispatch.
        let owner = self.owner.read().map_err(|_| HostToolError::Unavailable {
            tool: binding.id(),
            reason: "browser capability owner slot is poisoned".to_owned(),
        })?;
        owner
            .as_ref()
            .ok_or_else(|| HostToolError::Unavailable {
                tool: binding.id(),
                reason: "browser capability owner is not bound".to_owned(),
            })?
            .preflight_browser_capability(contract, binding, scope, arguments)
    }
}

pub(super) struct BrowserCapabilityTool {
    binding: BrowserCapabilityBinding,
    owner: Arc<dyn BrowserCapabilityOwner>,
    definition: RpcHostToolDefinition,
}

impl BrowserCapabilityTool {
    pub(super) fn new(
        binding: BrowserCapabilityBinding,
        owner: Arc<dyn BrowserCapabilityOwner>,
    ) -> Result<Self, HostToolError> {
        Ok(Self {
            binding,
            owner,
            definition: super::hidden_essential_definition(
                binding.id(),
                binding.label(),
                binding.description(),
                binding.schema(),
                binding.is_evidence_extractor(),
            )?,
        })
    }
}

impl HostTool for BrowserCapabilityTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn invoke(&self, invocation: HostInvocation) -> Result<Value, HostToolError> {
        self.owner
            .invoke_browser_capability(self.binding, invocation)
    }

    /// The consequential action carries the executor's consumed-command
    /// proof to its owner, once it provably binds this exact permit and
    /// payload; every other binding keeps its ordinary invocation.
    fn invoke_consumed(
        &self,
        effect: &PreparedEffect,
        consumed: &ConsumedHostCommand,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        if self.binding != BrowserCapabilityBinding::Consequential {
            return self.invoke(invocation);
        }
        if effect.contract().id.as_str() != self.binding.capability_id()
            || consumed.capability_id() != &effect.contract().id
            || consumed.operation_id() != effect.operation_id()
            || consumed.capsule_id() != effect.capsule_id()
            || consumed.target() != effect.target()
            || consumed.arguments() != &invocation.arguments
            || consumed.arguments_digest() != effect.payload().digest
        {
            return Err(HostToolError::Catalog {
                detail: "consumed command does not bind this exact browser permit".to_owned(),
            });
        }
        self.owner
            .invoke_consumed(self.binding, invocation, consumed)
    }

    fn preflight(
        &self,
        contract: &odin_kernel::CapabilityContract,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        self.owner
            .preflight_browser_capability(contract, self.binding, scope, arguments)
    }
}

/// Browser routes derive their names from capability ids and remain subject to seat/slice listing.
/// Invocation requires a prepared operation for the exact capability.
pub(crate) struct BrowserListedTool {
    inner: Arc<BrowserCapabilityTool>,
    definition: RpcHostToolDefinition,
}

/// Strict function-calling providers require a top-level object without `oneOf`.
/// Only the model schema drops action/argument pairing; canonical validation
/// still enforces it before approval. A missing pairing fails composition.
fn strip_model_action_pairing(parameters: &mut Value) -> Result<(), HostToolError> {
    let object = parameters
        .as_object_mut()
        .ok_or_else(|| HostToolError::Catalog {
            detail: "browser input schema is not an object".to_owned(),
        })?;
    if object.get("type").and_then(Value::as_str) != Some("object") {
        return Err(HostToolError::Catalog {
            detail: "browser input schema is not a top-level object".to_owned(),
        });
    }
    if object.remove("oneOf").is_none() {
        return Err(HostToolError::Catalog {
            detail: "browser input schema carries no top-level action pairing".to_owned(),
        });
    }
    Ok(())
}

impl BrowserListedTool {
    pub(super) fn new(
        binding: BrowserCapabilityBinding,
        owner: Arc<dyn BrowserCapabilityOwner>,
    ) -> Result<Self, HostToolError> {
        let inner = Arc::new(BrowserCapabilityTool::new(binding, Arc::clone(&owner))?);
        let mut definition = inner.definition().clone();
        definition.name = Cow::Borrowed(binding.listed_name());
        definition.hidden = false;
        if binding.pairs_action_with_arguments() {
            strip_model_action_pairing(&mut definition.parameters)?;
        }
        Ok(Self { inner, definition })
    }
}

impl HostTool for BrowserListedTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn invoke(&self, _invocation: HostInvocation) -> Result<Value, HostToolError> {
        Err(HostToolError::Catalog {
            detail: format!(
                "{} must be dispatched through the operation authority",
                self.definition.name
            ),
        })
    }

    fn invoke_prepared(
        &self,
        effect: &PreparedEffect,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        if effect.contract().id.as_str() != self.inner.binding.capability_id() {
            return Err(HostToolError::Catalog {
                detail: format!(
                    "prepared operation {} binds {}, not {}",
                    effect.operation_id(),
                    effect.contract().id,
                    self.inner.binding.capability_id()
                ),
            });
        }
        self.inner.invoke(invocation)
    }

    fn preflight(
        &self,
        contract: &odin_kernel::CapabilityContract,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        self.inner.preflight(contract, scope, arguments)
    }
}

/// The canonical-v2 capability bindings served by the sidecar-backed
/// operation adapter. Handler and evidence identities remain distinct so
/// every registry field has one concrete production owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalV2CapabilityBinding {
    EvalRun,
    EvalRunEvidence,
    FileEdit,
    FileEditEvidence,
}

impl CanonicalV2CapabilityBinding {
    pub(super) const ALL: [Self; 4] = [
        Self::EvalRun,
        Self::EvalRunEvidence,
        Self::FileEdit,
        Self::FileEditEvidence,
    ];

    pub const fn id(self) -> &'static str {
        match self {
            Self::EvalRun => "odin_eval.run",
            Self::EvalRunEvidence => "odin_eval.run_evidence",
            Self::FileEdit => "odin_file.edit",
            Self::FileEditEvidence => "odin_file.edit_evidence",
        }
    }

    pub const fn capability_id(self) -> &'static str {
        match self {
            Self::EvalRun | Self::EvalRunEvidence => "capsule.eval.run",
            Self::FileEdit | Self::FileEditEvidence => "capsule.file.edit",
        }
    }

    pub const fn is_evidence_extractor(self) -> bool {
        matches!(self, Self::EvalRunEvidence | Self::FileEditEvidence)
    }

    const fn label(self) -> &'static str {
        match self {
            Self::EvalRun => "Capsule Eval",
            Self::EvalRunEvidence => "Capsule Eval Evidence",
            Self::FileEdit => "Capsule File Edit",
            Self::FileEditEvidence => "Capsule File Edit Evidence",
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::EvalRun => {
                "Relay one authority-bound capsule evaluation over canonical authority wire v2. \
                 The program must leave tracked files unchanged (untracked build and test \
                 outputs are fine); edit files with capsule_file_edit."
            }
            Self::EvalRunEvidence => {
                "Read the durable compiled-effector evidence for one capsule evaluation."
            }
            Self::FileEdit => {
                "Edit one capsule file. To change part of a file pass old_text (exact, occurring \
                 once) and new_text. To create a file or rewrite all of it pass content and \
                 preimage_sha256 (SHA-256 of the current bytes, null for a new file)."
            }
            Self::FileEditEvidence => {
                "Read the durable compiled-effector evidence for one confined capsule edit."
            }
        }
    }

    pub(super) const fn schema(self) -> &'static str {
        match self {
            Self::EvalRun => {
                include_str!("../../../../schemas/capability/capsule.eval.run.input.json")
            }
            Self::EvalRunEvidence => {
                include_str!("../../../../schemas/capability/capsule.eval.run.output.json")
            }
            Self::FileEdit => {
                include_str!("../../../../schemas/capability/capsule.file.edit.input.json")
            }
            Self::FileEditEvidence => {
                include_str!("../../../../schemas/capability/capsule.file.edit.output.json")
            }
        }
    }
}

/// Composition-owned canonical-v2 authority connection. The concrete Odin
/// runtime owns the authenticated sidecar client and matching compiled-effector
/// receipt observer; odin-omp owns only this dependency-inversion seam and
/// cannot manufacture an authority response.
pub trait CanonicalV2CapabilityOwner: Send + Sync {
    fn invoke_authority_binding(
        &self,
        binding: CanonicalV2CapabilityBinding,
        capsule_id: CapsuleId,
        correlation_id: CorrelationId,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError>;

    /// Applies [`HostTool::preflight`] to session/capsule identity and arguments.
    /// Do not materialize session backends or launch sidecars before execution.
    /// Evidence bindings have no receipt to inspect yet and must document their no-op.
    fn preflight_authority_binding(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        binding: CanonicalV2CapabilityBinding,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError>;
}

pub(super) struct CanonicalV2CapabilityTool {
    binding: CanonicalV2CapabilityBinding,
    owner: Arc<dyn CanonicalV2CapabilityOwner>,
    definition: RpcHostToolDefinition,
}

impl CanonicalV2CapabilityTool {
    pub(super) fn new(
        binding: CanonicalV2CapabilityBinding,
        owner: Arc<dyn CanonicalV2CapabilityOwner>,
    ) -> Result<Self, HostToolError> {
        Ok(Self {
            binding,
            owner,
            definition: super::hidden_essential_definition(
                binding.id(),
                binding.label(),
                binding.description(),
                binding.schema(),
                binding.is_evidence_extractor(),
            )?,
        })
    }
}

/// Listed model-facing wrapper over one canonical-v2 internal adapter.
/// A bare `invoke` fails closed: reaching the sidecar always requires the
/// kernel-minted prepared operation produced by HostToolOperations.
pub(super) struct CapsuleListedTool {
    pub(super) inner: Arc<CanonicalV2CapabilityTool>,
    pub(super) definition: RpcHostToolDefinition,
}

impl HostTool for CapsuleListedTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn invoke(&self, _invocation: HostInvocation) -> Result<Value, HostToolError> {
        Err(HostToolError::Catalog {
            detail: format!(
                "{} must be dispatched through the operation authority",
                self.definition.name
            ),
        })
    }

    fn invoke_prepared(
        &self,
        effect: &PreparedEffect,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        self.inner.invoke_prepared(effect, invocation)
    }

    fn preflight(
        &self,
        contract: &odin_kernel::CapabilityContract,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        self.inner.preflight(contract, scope, arguments)
    }
}

impl HostTool for CanonicalV2CapabilityTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn invoke(&self, _invocation: HostInvocation) -> Result<Value, HostToolError> {
        Err(HostToolError::Catalog {
            detail: format!(
                "{} requires a kernel-minted prepared operation",
                self.binding.id()
            ),
        })
    }

    fn invoke_prepared(
        &self,
        effect: &PreparedEffect,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        if effect.contract().id.as_str() != self.binding.capability_id() {
            return Err(HostToolError::Catalog {
                detail: format!(
                    "prepared operation {} binds {}, not {}",
                    effect.operation_id(),
                    effect.contract().id,
                    self.binding.capability_id()
                ),
            });
        }
        self.owner.invoke_authority_binding(
            self.binding,
            effect.capsule_id().clone(),
            effect.correlation_id().clone(),
            invocation,
        )
    }

    fn preflight(
        &self,
        contract: &odin_kernel::CapabilityContract,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        self.owner
            .preflight_authority_binding(contract, self.binding, scope, arguments)
    }
}

pub(super) struct FramedExecTool {
    executable: String,
    argv: Vec<String>,
    timeout: std::time::Duration,
    definition: RpcHostToolDefinition,
    /// Sole StopAuthority launch/stop contract for this registered executable.
    worker: crate::process::OmpWorkerLaunch,
    /// Test-only observation hook: the launched logical worker id.
    #[cfg(test)]
    pub(super) last_worker: std::sync::Mutex<Option<String>>,
}

impl FramedExecTool {
    pub(super) fn new(
        executable: String,
        argv: Vec<String>,
        worker: crate::process::OmpWorkerLaunch,
    ) -> Self {
        Self::with_timeout(executable, argv, std::time::Duration::from_secs(30), worker)
    }

    pub(super) fn with_timeout(
        executable: String,
        argv: Vec<String>,
        timeout: std::time::Duration,
        worker: crate::process::OmpWorkerLaunch,
    ) -> Self {
        Self {
            executable,
            argv,
            timeout,
            definition: RpcHostToolDefinition {
                name: Cow::Borrowed("odin_internal_exec"),
                label: Cow::Borrowed("Internal Exec"),
                description: Cow::Borrowed("Compiled store executable over framed stdin/stdout."),
                parameters: serde_json::json!({
                    "type": "object",
                    "additionalProperties": false
                }),
                hidden: true,
                load_mode: ToolLoadMode::Essential,
            },
            worker,
            #[cfg(test)]
            last_worker: std::sync::Mutex::new(None),
        }
    }
}

impl HostTool for FramedExecTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn preflight(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        _scope: &Scope,
        _arguments: &Value,
    ) -> Result<(), HostToolError> {
        // Declared-admissibility gate for the exec class: the pinned
        // executable must exist, be a regular file, and carry an execute
        // bit — exactly the launch precondition `launch_registered_service`
        // needs — observed by plain metadata, never by spawning or probing
        // the child. A dispatch naming a store path the deployment never
        // rendered therefore refuses typed BEFORE anything is journaled,
        // minted, or consumed. The executed path re-proves launch at the
        // permit, so a binary removed between the two still fails closed
        // there.
        let metadata =
            std::fs::metadata(&self.executable).map_err(|error| HostToolError::Unavailable {
                tool: "odin_internal_exec",
                reason: format!(
                    "the declared executable {} is not present: {error}",
                    self.executable
                ),
            })?;
        if !metadata.is_file() {
            return Err(HostToolError::Unavailable {
                tool: "odin_internal_exec",
                reason: format!(
                    "the declared executable {} is not a regular file",
                    self.executable
                ),
            });
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o111 == 0 {
                return Err(HostToolError::Unavailable {
                    tool: "odin_internal_exec",
                    reason: format!(
                        "the declared executable {} carries no execute permission",
                        self.executable
                    ),
                });
            }
        }
        Ok(())
    }

    fn invoke(&self, invocation: HostInvocation) -> Result<Value, HostToolError> {
        // One canonical bounded stdin frame. The canonical encoder (sorted
        // keys, compact separators, strict numbers) defines the exact bytes
        // the child receives; the frame bound is enforced on those bytes and
        // the terminating newline is only written after the size succeeds.
        let payload = odin_strict_json::canonicalize(&invocation.arguments).map_err(|error| {
            HostToolError::Catalog {
                detail: format!("exec stdin canonical encode failed: {error}"),
            }
        })?;
        if payload.len() + 1 > MAX_FRAME_BYTES {
            return Err(HostToolError::Catalog {
                detail: format!(
                    "exec stdin frame {} exceeds the {}-byte bound",
                    payload.len() + 1,
                    MAX_FRAME_BYTES
                ),
            });
        }

        // Registered-service launch through StopAuthority: pinned executable
        // binding, empty allowlisted environment plus the correlation, cwd at
        // the filesystem root. No Command spawn, no PGID authority.
        let mut args = Vec::with_capacity(self.argv.len().saturating_add(1));
        args.push(self.executable.clone());
        args.extend(self.argv.iter().cloned());
        let worker = self.worker.clone();
        let naming = worker
            .next_naming()
            .map_err(|error| HostToolError::Catalog {
                detail: format!("exec worker naming rejected: {error}"),
            })?;
        let argv = odin_process::FrozenArgv::new(args, 128, 1024 * 1024).map_err(|error| {
            HostToolError::Catalog {
                detail: format!("exec argv rejected: {error}"),
            }
        })?;
        let environment = odin_process::EnvironmentBuilder::new([odin_process::CORRELATION_ENV])
            .map_err(|error| HostToolError::Catalog {
                detail: format!("exec environment rejected: {error}"),
            })?
            .set(
                odin_process::CORRELATION_ENV,
                worker.correlation_id.as_str(),
            )
            .map_err(|error| HostToolError::Catalog {
                detail: format!("exec environment rejected: {error}"),
            })?
            .build();
        let spec = odin_process::CommandSpec {
            argv,
            environment,
            current_dir: PathBuf::from("/"),
        };
        // One absolute deadline from the launch on: the stdin frame, both
        // output drains and the exit wait all spend it.
        let deadline = std::time::Instant::now() + self.timeout;
        let launched = worker
            .authority
            .launch_registered_service(
                naming,
                &worker.correlation_id,
                &spec,
                worker.limits,
                &worker.binding,
            )
            .map_err(|error| HostToolError::Catalog {
                detail: format!("exec {} launch failed: {error}", self.executable),
            })?;
        #[cfg(test)]
        {
            *self
                .last_worker
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                Some(launched.identity.worker_id.to_string());
        }

        // One bounded canonical stdin frame, then EOF, exchanged by this
        // operation; the stop is proved before any captured effect is trusted.
        let mut framed = payload;
        framed.push(b'\n');
        let output = framed_exchange(
            &worker.authority,
            launched,
            &framed,
            FramedDeadline {
                at: deadline,
                timeout: self.timeout,
            },
            &format!("exec {:?}", self.executable),
        )
        .map_err(|detail| HostToolError::Uncertain {
            tool: "odin_internal_exec",
            detail,
        })?;

        // Canonical framed stdout: exactly one terminated physical line, the
        // frame bytes fully consumed, and zero trailing bytes after it. The
        // parsed value is re-encoded canonically and byte-compared with the
        // received logical frame, so whitespace or key-order drift is
        // rejected outright.
        if !output.ends_with(b"\n") {
            return Err(HostToolError::Uncertain {
                tool: "odin_internal_exec",
                detail: "exec stdout response is not newline-terminated after a successful run"
                    .to_owned(),
            });
        }
        let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V1);
        let frame = decoder
            .push_physical_line(&output)
            .map_err(|error| HostToolError::Uncertain {
                tool: "odin_internal_exec",
                detail: format!("exec stdout frame rejected after a successful run: {error}"),
            })?
            .ok_or_else(|| HostToolError::Uncertain {
                tool: "odin_internal_exec",
                detail: "exec stdout produced no complete frame after a successful run".to_owned(),
            })?;
        let consumed: usize = frame.lines().iter().map(|line| line.len()).sum();
        if frame.lines().len() != 1 || consumed != output.len() {
            return Err(HostToolError::Uncertain {
                tool: "odin_internal_exec",
                detail: "exec stdout carried trailing bytes beyond one frame".to_owned(),
            });
        }
        let canonical = odin_strict_json::canonicalize(frame.value()).map_err(|error| {
            HostToolError::Uncertain {
                tool: "odin_internal_exec",
                detail: format!("exec stdout canonical re-encode failed: {error}"),
            }
        })?;
        if canonical != frame.raw() {
            return Err(HostToolError::Uncertain {
                tool: "odin_internal_exec",
                detail: "exec stdout frame is not canonical JSON".to_owned(),
            });
        }
        Ok(frame.value().clone())
    }
}

/// One stdin slice. A pipe write of at most `PIPE_BUF` bytes is atomic, so a
/// slice that timed out delivered nothing and is offered again whole.
const STDIN_SLICE: usize = 4096;

/// How long one pass offers its stdin slice before it drains output again.
const STDIN_SLICE_WAIT: std::time::Duration = std::time::Duration::from_millis(10);

/// The caller's one absolute deadline, and the timeout it was set from (for
/// the report).
pub(super) struct FramedDeadline {
    pub(super) at: std::time::Instant,
    pub(super) timeout: std::time::Duration,
}

/// One output pipe owned and drained by the exchange itself: nonblocking, so
/// a writer that never closes it can hold nothing past the deadline, and
/// closed when the exchange returns.
struct OwnedPipe<R> {
    reader: R,
    eof: bool,
}

impl<R: Read + std::os::fd::AsFd> OwnedPipe<R> {
    fn new(reader: R) -> Result<Self, String> {
        let flags = rustix::fs::fcntl_getfl(&reader).map_err(|error| error.to_string())?;
        rustix::fs::fcntl_setfl(&reader, flags | rustix::fs::OFlags::NONBLOCK)
            .map_err(|error| error.to_string())?;
        Ok(Self { reader, eof: false })
    }

    /// Moves at most 64 KiB into `sink`, so neither pipe starves the other,
    /// the stdin frame or the deadline. Whether anything moved.
    fn drain(&mut self, mut sink: impl FnMut(&[u8]) -> Result<(), String>) -> Result<bool, String> {
        if self.eof {
            return Ok(false);
        }
        let mut progressed = false;
        let mut buffer = [0; 8192];
        for _ in 0..8 {
            match self.reader.read(&mut buffer) {
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(count) => {
                    sink(&buffer[..count])?;
                    progressed = true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.to_string()),
            }
        }
        Ok(progressed)
    }
}

/// Exchanges bounded frames with fair stdout/stderr draining under one deadline.
/// Every path requests stop under that same deadline, even after expiry. Output
/// requires a successful exit and confirmed `Stopped`; no readers survive return.
/// Errors occur after launch, so the effect may have happened. StopAuthority
/// remains responsible for the worker when stop cannot be confirmed.
pub(super) fn framed_exchange(
    authority: &odin_kernel::StopAuthority,
    launched: odin_kernel::WorkerLaunch,
    frame: &[u8],
    deadline: FramedDeadline,
    label: &str,
) -> Result<Vec<u8>, String> {
    let worker = launched.identity.worker_id.clone();
    let exchanged = exchange(
        authority,
        &worker,
        launched.stdout,
        launched.stderr,
        frame,
        &deadline,
        label,
    );
    let stop = match authority.stop_worker_bounded(&worker, deadline.at) {
        Ok(outcome) if outcome.verdict == odin_domain::StopVerdict::Stopped => Ok(()),
        Ok(outcome) => Err(format!(
            "{label} stop was not proved: {:?}",
            outcome.verdict
        )),
        Err(error) => Err(format!("{label} stop failed: {error}")),
    };
    // The exchange's own failure leads; an unproved stop is added to it,
    // and alone it keeps even a complete reply unknown.
    let (output, status) = match (exchanged, stop) {
        (Ok(exchanged), Ok(())) => exchanged,
        (Ok(_), Err(stop)) => return Err(stop),
        (Err(failure), Ok(())) => return Err(failure),
        (Err(failure), Err(stop)) => return Err(format!("{failure}; {stop}")),
    };
    match (status.code(), status.success()) {
        (_, true) => Ok(output),
        (Some(code), false) => Err(format!(
            "{label} exited nonzero after the frame was written: {code}"
        )),
        (None, false) => Err(format!(
            "{label} was terminated by a signal before replying"
        )),
    }
}

fn exchange(
    authority: &odin_kernel::StopAuthority,
    worker: &odin_types::WorkerId,
    stdout: std::process::ChildStdout,
    stderr: std::process::ChildStderr,
    frame: &[u8],
    deadline: &FramedDeadline,
    label: &str,
) -> Result<(Vec<u8>, std::process::ExitStatus), String> {
    let mut stdout = OwnedPipe::new(stdout).map_err(|error| format!("{label} stdout: {error}"))?;
    let mut stderr = OwnedPipe::new(stderr).map_err(|error| format!("{label} stderr: {error}"))?;
    let mut output = Vec::new();
    let mut stderr_bytes: u64 = 0;
    let mut written = 0;
    let mut stdin_open = true;
    loop {
        let mut progressed = stdout
            .drain(|bytes| {
                if output.len().saturating_add(bytes.len()) > MAX_FRAME_BYTES {
                    return Err(format!(
                        "{label} stdout exceeds the {MAX_FRAME_BYTES}-byte single-frame bound"
                    ));
                }
                output.extend_from_slice(bytes);
                Ok(())
            })
            .map_err(|error| format!("{label} stdout: {error}"))?;
        progressed |= stderr
            .drain(|bytes| {
                // Drained so the child never blocks on it; only counted.
                stderr_bytes = stderr_bytes.saturating_add(bytes.len() as u64);
                Ok(())
            })
            .map_err(|error| format!("{label} stderr: {error}"))?;
        if stdin_open {
            if written < frame.len() {
                let end = written.saturating_add(STDIN_SLICE).min(frame.len());
                let wait = STDIN_SLICE_WAIT.min(
                    deadline
                        .at
                        .saturating_duration_since(std::time::Instant::now()),
                );
                match authority.write_worker_stdin_timeout(worker, &frame[written..end], wait) {
                    Ok(_) => {
                        written = end;
                        progressed = true;
                    }
                    Err(odin_kernel::StopAuthorityError::Worker(error))
                        if error.code() == odin_process::WorkerErrorCode::WriteTimeout => {}
                    Err(error) => {
                        return Err(format!("{label} stdin write failed after spawn: {error}"))
                    }
                }
            }
            if written == frame.len() {
                let _ = authority.close_worker_stdin(worker);
                stdin_open = false;
            }
        }
        // The deadline is checked before any completion is accepted: a
        // productive pass that ran past it never turns into a success.
        if std::time::Instant::now() >= deadline.at {
            return Err(format!(
                "{label} did not finish within {:?} (stderr {stderr_bytes} bytes); \
                 StopAuthority stops the worker",
                deadline.timeout
            ));
        }
        if stdout.eof {
            let status = authority
                .try_wait_worker(worker)
                .map_err(|error| format!("{label} exit status is unreadable: {error}"))?;
            if let Some(status) = status {
                return Ok((output, status));
            }
        }
        if !progressed {
            std::thread::sleep(
                std::time::Duration::from_millis(5).min(
                    deadline
                        .at
                        .saturating_duration_since(std::time::Instant::now()),
                ),
            );
        }
    }
}
