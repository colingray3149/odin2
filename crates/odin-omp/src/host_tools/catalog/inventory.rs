use std::collections::BTreeSet;
use std::sync::Arc;

use super::{CompiledCapabilityBinding, CompiledHandlerBinding};
use crate::host_tools::dispatch::{HostToolRegistry, InternalBindingKey};
use crate::host_tools::{HostTool, HostToolError};

/// The compiled pre-admitted catalog: the sole authority that binds
/// capability handlers to production host tools.
///
/// A host tool being registered in a [`HostToolRegistry`] is never
/// sufficient: only a cataloged builtin handler id resolves, and only to the
/// tool registered under that exact id. No HostTool binding may live outside
/// this catalog.
#[derive(Clone, Debug, Default)]
pub struct CompiledHostToolCatalog {
    bindings: Vec<&'static CompiledCapabilityBinding>,
    builtin_handlers: BTreeSet<&'static str>,
}

impl CompiledHostToolCatalog {
    /// Compiles pre-admitted tuples, rejecting duplicate handlers and incompatible
    /// extractor reuse. Extractors may serve distinct handlers with the same
    /// version and output schema; exec bindings remain fully static store references.
    pub fn compile(
        bindings: &'static [&'static CompiledCapabilityBinding],
    ) -> Result<Self, HostToolError> {
        let mut catalog = Self::default();
        for &binding in bindings {
            let rejected = |detail: String| HostToolError::Catalog {
                detail: format!("binding for {}: {detail}", binding.input_schema),
            };
            if binding.version == 0 {
                return Err(rejected("version must be positive".to_owned()));
            }
            if binding.input_schema.is_empty() || binding.output_schema.is_empty() {
                return Err(rejected(
                    "dedicated input and output schemas must be declared".to_owned(),
                ));
            }
            if binding.input_schema == binding.output_schema {
                return Err(rejected(
                    "input and output schemas must be distinct".to_owned(),
                ));
            }
            validate_compiled_handler("handler", &binding.handler)?;
            validate_compiled_handler("evidence_extractor", &binding.evidence_extractor)?;
            if catalog.bindings.contains(&binding) {
                return Err(HostToolError::Catalog {
                    detail: "duplicate admitted binding tuple".to_owned(),
                });
            }
            for (is_extractor, builtin) in
                [(false, binding.handler), (true, binding.evidence_extractor)]
            {
                if let CompiledHandlerBinding::Builtin { id } = builtin {
                    if catalog.builtin_handlers.insert(id) {
                        continue;
                    }
                    // A reused builtin can only be an extractor for an identical
                    // output contract, never a handler or a handler/extractor alias.
                    let shared_extractor = is_extractor
                        && binding.handler != builtin
                        && catalog.bindings.iter().all(|previous| {
                            previous.handler != builtin
                                && (previous.evidence_extractor != builtin
                                    || (previous.version == binding.version
                                        && previous.output_schema == binding.output_schema))
                        });
                    if !shared_extractor {
                        return Err(HostToolError::Catalog {
                            detail: format!(
                                "builtin binding {id:?} is bound by more than one capability field"
                            ),
                        });
                    }
                }
            }
            catalog.bindings.push(binding);
        }
        Ok(catalog)
    }

    /// Every compiled admitted tuple.
    pub fn bindings(&self) -> impl Iterator<Item = &CompiledCapabilityBinding> {
        self.bindings.iter().copied()
    }

    /// Resolves one builtin capability handler or evidence extractor to the
    /// registered production host tool serving it.
    ///
    /// Denied unless the exact builtin id is cataloged — a registered tool is
    /// never sufficient on its own — and a host tool is registered under it.
    pub fn resolve(
        &self,
        builtin_id: &str,
        registry: &HostToolRegistry,
    ) -> Result<Arc<dyn HostTool>, HostToolError> {
        if !self.builtin_handlers.contains(builtin_id) {
            return Err(HostToolError::Catalog {
                detail: format!(
                    "builtin binding {builtin_id:?} is not bound in the compiled catalog"
                ),
            });
        }
        registry.binding(&InternalBindingKey::Builtin(builtin_id.to_owned()))
    }

    /// Validates every cataloged handler/extractor has a concrete HostTool.
    ///
    /// Builtin ids resolve through internal bindings or listed tools. Exec
    /// identities resolve only through an internal HostTool registered under
    /// the exact executable+argv; compile does not admit Exec without that.
    pub fn validate_production_composition(
        &self,
        registry: &HostToolRegistry,
    ) -> Result<(), HostToolError> {
        for &admitted in &self.bindings {
            for compiled in [admitted.handler, admitted.evidence_extractor] {
                let key = InternalBindingKey::from_compiled(compiled)?;
                if !registry.resolves_key(&key) {
                    return Err(HostToolError::Catalog {
                        detail: match &key {
                            InternalBindingKey::Builtin(id) => format!(
                                "pre-admitted builtin {id:?} has no concrete production HostTool owner"
                            ),
                            InternalBindingKey::Exec { executable, argv } => format!(
                                "pre-admitted exec {executable:?} {argv:?} has no concrete production HostTool owner"
                            ),
                        },
                    });
                }
            }
        }
        Ok(())
    }
}

fn validate_compiled_handler(
    field: &'static str,
    binding: &CompiledHandlerBinding,
) -> Result<(), HostToolError> {
    let detail = match binding {
        CompiledHandlerBinding::Builtin { id: "" } => {
            Some(format!("{field} builtin id must not be empty"))
        }
        CompiledHandlerBinding::Builtin { id } if !is_compiled_builtin_id(id) => Some(format!(
            "{field} builtin id {id:?} must match the registry id grammar"
        )),
        CompiledHandlerBinding::Exec { executable, .. }
            if !is_store_executable_form(executable) =>
        {
            Some(format!(
                "{field} executable {executable:?} must be one normalized /nix/store path"
            ))
        }
        CompiledHandlerBinding::Exec { argv, .. }
            if argv.iter().any(|element| {
                element.is_empty()
                    || element.chars().any(char::is_whitespace)
                    || element.chars().any(is_compiled_shell_syntax)
            }) =>
        {
            Some(format!(
                "{field} argv must be fully static tokens without whitespace or shell syntax"
            ))
        }
        _ => None,
    };
    match detail {
        Some(detail) => Err(HostToolError::Catalog { detail }),
        None => Ok(()),
    }
}

fn is_compiled_builtin_id(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && chars.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
}

/// The 32-character Nix base32 alphabet; `e`, `o`, `u`, and `t` are absent.
const NIX_STORE_HASH_ALPHABET: &str = "0123456789abcdfghijklmnpqrsvwxyz";

/// Whether the path is the exact lexical `/nix/store/<hash>-<name>/...` form.
/// Purely lexical: no filesystem reachability, `PATH`, or caller environment
/// is ever consulted.
pub(in crate::host_tools) fn is_store_executable_form(executable: &str) -> bool {
    if executable.is_empty()
        || executable.chars().any(char::is_whitespace)
        || executable.chars().any(is_compiled_shell_syntax)
    {
        return false;
    }
    let Some(rest) = executable.strip_prefix("/nix/store/") else {
        return false;
    };
    let Some((store_component, tail)) = rest.split_once('/') else {
        return false;
    };
    if tail.is_empty()
        || tail
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return false;
    }
    let Some((hash, name)) = store_component.split_once('-') else {
        return false;
    };
    hash.len() == 32
        && hash
            .bytes()
            .all(|byte| NIX_STORE_HASH_ALPHABET.as_bytes().contains(&byte))
        && !name.is_empty()
}

fn is_compiled_shell_syntax(character: char) -> bool {
    matches!(
        character,
        '$' | '`' | ';' | '&' | '|' | '\n' | '\r' | '>' | '<'
    )
}
