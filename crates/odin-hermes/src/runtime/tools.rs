//! Governed host-tool wrappers. Operator-approved surfaces are reachable
//! only through the kernel-consumed host command.

use odin_domain::Scope;
use odin_omp::host_tools::{HostInvocation, HostTool, HostToolError, RpcHostToolDefinition};
use serde_json::Value;

pub(super) type PlainHandler =
    Box<dyn Fn(Scope, Value) -> Result<Value, HostToolError> + Send + Sync>;
pub(super) type PreparedHandler = Box<
    dyn Fn(&odin_kernel::operation::PreparedEffect, Scope, Value) -> Result<Value, HostToolError>
        + Send
        + Sync,
>;
pub(super) type ConsumedHandler = Box<
    dyn Fn(
            &odin_kernel::operation::PreparedEffect,
            &odin_omp::host_tools::ConsumedHostCommand,
            Scope,
            Value,
        ) -> Result<Value, HostToolError>
        + Send
        + Sync,
>;
/// Reuses the handler's read-only readiness checks before journaling or requesting approval.
pub(super) type PreflightHandler =
    Box<dyn Fn(&Scope, &Value) -> Result<(), HostToolError> + Send + Sync>;
pub(super) type ScopedParameters = Box<dyn Fn(&Scope) -> Value + Send + Sync>;

/// Approved handlers require [`HostTool::invoke_consumed`]; bare and prepared
/// invocations cannot bypass the kernel's command and approval checks.
pub(super) struct CapabilityTool {
    definition: RpcHostToolDefinition,
    /// `None` accepts any admitted capability whose id and version match the prepared effect.
    capability: Option<&'static str>,
    handler: PlainHandler,
    prepared: Option<PreparedHandler>,
    consumed: Option<ConsumedHandler>,
    /// Explicit at construction so missing external prerequisites cannot pass by omission.
    preflight: PreflightHandler,
    scoped_parameters: Option<ScopedParameters>,
}

impl CapabilityTool {
    /// A non-R3 wrapper: host-scope dispatch and internal dispatch agree.
    /// `preflight` is the handler's declared-admissibility gate, stated
    /// at construction.
    pub(super) fn plain(
        definition: RpcHostToolDefinition,
        handler: PlainHandler,
        preflight: PreflightHandler,
    ) -> Self {
        Self {
            definition,
            capability: None,
            handler,
            prepared: None,
            consumed: None,
            preflight,
            scoped_parameters: None,
        }
    }

    /// For always-present in-process surfaces with no external readiness checks.
    pub(super) fn plain_without_prerequisites(
        definition: RpcHostToolDefinition,
        handler: PlainHandler,
    ) -> Self {
        Self::plain(definition, handler, Box::new(|_scope, _arguments| Ok(())))
    }

    /// Requires a consumed command for this capability; preflight runs before approval is requested.
    pub(super) fn approved(
        definition: RpcHostToolDefinition,
        capability: &'static str,
        consumed: ConsumedHandler,
        preflight: PreflightHandler,
    ) -> Self {
        Self {
            definition,
            capability: Some(capability),
            handler: Box::new(|_scope, _arguments| {
                unreachable!("approved wrappers never run bare")
            }),
            prepared: None,
            consumed: Some(consumed),
            preflight,
            scoped_parameters: None,
        }
    }

    /// Accepts any contract whose capability id and version match the prepared effect.
    pub(super) fn approved_generic(
        definition: RpcHostToolDefinition,
        consumed: ConsumedHandler,
        preflight: PreflightHandler,
    ) -> Self {
        Self {
            definition,
            capability: None,
            handler: Box::new(|_scope, _arguments| {
                unreachable!("approved wrappers never run bare")
            }),
            prepared: None,
            consumed: Some(consumed),
            preflight,
            scoped_parameters: None,
        }
    }

    /// A governed effect that needs its exact prepared journal identity,
    /// without introducing an operator-approval requirement.
    pub(super) fn prepared(
        definition: RpcHostToolDefinition,
        handler: PreparedHandler,
        preflight: PreflightHandler,
    ) -> Self {
        Self {
            definition,
            capability: None,
            handler: Box::new(|_, _| unreachable!("prepared tools require an effect")),
            prepared: Some(handler),
            consumed: None,
            preflight,
            scoped_parameters: None,
        }
    }

    pub(super) fn with_scoped_parameters(
        mut self,
        parameters: impl Fn(&Scope) -> Value + Send + Sync + 'static,
    ) -> Self {
        self.scoped_parameters = Some(Box::new(parameters));
        self
    }
}

impl HostTool for CapabilityTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn parameters_for_scope(&self, scope: &Scope) -> Option<Value> {
        self.scoped_parameters
            .as_ref()
            .map(|parameters| parameters(scope))
    }

    fn preflight(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        // The gate stated explicitly at construction — either the
        // handler's own read-only resolution or the named
        // no-external-prerequisites disposition.
        (self.preflight)(scope, arguments)
    }

    fn invoke(&self, invocation: HostInvocation) -> Result<Value, HostToolError> {
        if self.prepared.is_some() {
            return Err(HostToolError::Catalog {
                detail: format!("{} requires a kernel-prepared effect", self.definition.name),
            });
        }
        match &self.consumed {
            Some(_) => Err(HostToolError::Catalog {
                detail: format!(
                    "{} requires operator approval and must be dispatched through the operation \
                     authority, never invoked as a bare tool",
                    self.definition.name
                ),
            }),
            None => (self.handler)(invocation.scope, invocation.arguments),
        }
    }

    fn invoke_prepared(
        &self,
        _effect: &odin_kernel::operation::PreparedEffect,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        if let Some(handler) = &self.prepared {
            return handler(_effect, invocation.scope, invocation.arguments);
        }
        match &self.consumed {
            Some(_) => Err(HostToolError::Catalog {
                detail: format!(
                    "{} requires the kernel-consumed host command, not a bare prepared \
                     operation",
                    self.definition.name
                ),
            }),
            None => (self.handler)(invocation.scope, invocation.arguments),
        }
    }

    fn invoke_consumed(
        &self,
        effect: &odin_kernel::operation::PreparedEffect,
        consumed: &odin_omp::host_tools::ConsumedHostCommand,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        if let Some(handler) = &self.prepared {
            if consumed.operation_id() != effect.operation_id()
                || consumed.capsule_id() != effect.capsule_id()
                || consumed.target() != effect.target()
                || consumed.arguments() != &invocation.arguments
                || consumed.arguments_digest() != effect.payload().digest
            {
                return Err(HostToolError::Catalog {
                    detail: "consumed command does not bind this prepared effect".to_owned(),
                });
            }
            return handler(effect, invocation.scope, invocation.arguments);
        }
        let Some(consumed_handler) = self.consumed.as_ref() else {
            return (self.handler)(invocation.scope, invocation.arguments);
        };
        if consumed.operation_id() != effect.operation_id()
            || consumed.capsule_id() != effect.capsule_id()
            || consumed.target() != effect.target()
            || consumed.arguments() != &invocation.arguments
            || consumed.arguments_digest() != effect.payload().digest
        {
            return Err(HostToolError::Catalog {
                detail: "consumed command does not bind this exact effect and payload".to_owned(),
            });
        }
        match self.capability {
            Some(capability) => {
                if effect.contract().id.as_str() != capability {
                    return Err(HostToolError::Catalog {
                        detail: format!(
                            "consumed operation {} binds {}, not {}",
                            effect.operation_id(),
                            effect.contract().id,
                            capability
                        ),
                    });
                }
            }
            None => {
                if consumed.capability_id() != &effect.contract().id
                    || consumed.capability_version() != effect.contract().version
                {
                    return Err(HostToolError::Catalog {
                        detail: format!(
                            "the consumed host command binds {} v{}, not the prepared \
                             effect's admitted contract {} v{}",
                            consumed.capability_id(),
                            consumed.capability_version(),
                            effect.contract().id,
                            effect.contract().version
                        ),
                    });
                }
            }
        }
        consumed_handler(effect, consumed, invocation.scope, invocation.arguments)
    }
}

/// The call the kernel prepared is the call being run: this capability, with exactly these
/// arguments.
pub(super) fn require_prepared(
    effect: &odin_kernel::operation::PreparedEffect,
    capability: &str,
    tool: &str,
    arguments: &Value,
) -> Result<(), HostToolError> {
    if effect.contract().id.as_str() != capability || &effect.payload().arguments != arguments {
        return Err(HostToolError::Catalog {
            detail: format!("{tool} requires its exact prepared contract and payload"),
        });
    }
    Ok(())
}

/// A backend this host does not declare, in one wording per backend.
pub(super) const NO_ARTIFACTS: &str = "the artifact store is not configured on this host";
pub(super) const NO_DISCORD: &str = "the discord surface is not configured on this host";
pub(super) const NO_GATEWAY: &str = "hermes.model_gateway is not configured on this host";

pub(super) fn parse_string(
    arguments: &Value,
    field: &str,
    max_bytes: usize,
) -> Result<String, HostToolError> {
    let value = arguments
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| HostToolError::Arguments {
            tool: "odin_hermes",
            detail: format!("{field} must be a string"),
        })?;
    if value.trim().is_empty() || value.len() > max_bytes {
        return Err(HostToolError::Arguments {
            tool: "odin_hermes",
            detail: format!("{field} must be 1..={max_bytes} bytes"),
        });
    }
    Ok(value.to_owned())
}
