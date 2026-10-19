use std::collections::BTreeSet;
use std::sync::Arc;

use super::context_read::{CONTEXT_READ_EVIDENCE_ID, CONTEXT_READ_HANDLER_ID};
use super::delegation;
use super::dispatch::{HostToolRegistry, InternalBindingKey};
use super::{HostTool, HostToolError};

/// One compiled binding of an enabled registry capability to the production
/// handlers that serve it.
///
/// The tuple is compiled in from [`PRE_ADMITTED_BINDINGS`]; nothing at
/// runtime can widen it. `handler` and `evidence_extractor` are structured
/// bindings: builtin ids resolve to registered host tools through the
/// catalog, and exec bindings pin one absolute store executable with a fully
/// static argv executed over canonical framed stdin/stdout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompiledCapabilityBinding {
    pub version: u16,
    pub input_schema: &'static str,
    pub output_schema: &'static str,
    pub handler: CompiledHandlerBinding,
    pub evidence_extractor: CompiledHandlerBinding,
}

impl CompiledCapabilityBinding {
    pub fn to_admitted_binding(&self) -> odin_registry::relational::AdmittedBinding {
        odin_registry::relational::AdmittedBinding {
            version: self.version,
            input_schema: self.input_schema.to_owned(),
            output_schema: self.output_schema.to_owned(),
            handler: self.handler.to_registry(),
            evidence_extractor: self.evidence_extractor.to_registry(),
        }
    }
}

/// One structured production handler or evidence-extractor binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompiledHandlerBinding {
    /// In-process handler dispatched to the host tool registered under `id`.
    Builtin {
        /// The exact registered host tool name.
        id: &'static str,
    },
    /// Bounded subprocess run from the absolute store `executable` with the
    /// static `argv` over canonical framed stdin/stdout; never dispatched to
    /// a host tool.
    Exec {
        /// The exact absolute store executable.
        executable: &'static str,
        /// The fully static argv; no element is split or interpolated.
        argv: &'static [&'static str],
    },
}

impl CompiledHandlerBinding {
    fn to_registry(self) -> odin_registry::schema::HandlerBindingToml {
        match self {
            Self::Builtin { id } => odin_registry::schema::HandlerBindingToml::Builtin(
                odin_registry::schema::BuiltinHandlerToml { id: id.to_owned() },
            ),
            Self::Exec { executable, argv } => odin_registry::schema::HandlerBindingToml::Exec(
                odin_registry::schema::ExecHandlerToml {
                    executable: executable.to_owned(),
                    argv: argv.iter().map(|value| (*value).to_owned()).collect(),
                },
            ),
        }
    }
}

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
    /// Compiles the pre-admitted tuples, rejecting duplicate tuples or
    /// builtin binding ids, zero versions, undeclared or shared schemas, and
    /// exec bindings that are not fully static store references.
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
            catalog.bindings.push(binding);
            for builtin in [binding.handler, binding.evidence_extractor] {
                if let CompiledHandlerBinding::Builtin { id } = builtin {
                    if !catalog.builtin_handlers.insert(id) {
                        return Err(HostToolError::Catalog {
                            detail: format!(
                                "builtin binding {id:?} is bound by more than one capability field"
                            ),
                        });
                    }
                }
            }
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
        let key = InternalBindingKey::Builtin(builtin_id.to_owned());
        if let Ok(tool) = registry.binding(&key) {
            return Ok(tool);
        }
        registry
            .tools
            .get(builtin_id)
            .cloned()
            .ok_or_else(|| HostToolError::UnknownTool {
                name: builtin_id.to_owned(),
            })
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
                let present = registry.bindings.contains_key(&key)
                    || matches!(
                        &key,
                        InternalBindingKey::Builtin(id) if registry.tools.contains_key(id.as_str())
                    );
                if !present {
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
pub(super) fn is_store_executable_form(executable: &str) -> bool {
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

pub static PRE_ADMITTED_BINDINGS: &[&CompiledCapabilityBinding] = &[
    &BROWSER_CONSEQUENTIAL_BINDING,
    &BROWSER_INTERACT_BINDING,
    &BROWSER_OBSERVE_BINDING,
    &CAPSULE_EVAL_RUN_BINDING,
    &CAPSULE_FILE_EDIT_BINDING,
    &CONTEXT_READ_BINDING,
    &BRAIN_SEARCH_BINDING,
    &BRAIN_READ_BINDING,
    &BRAIN_RECORDS_BINDING,
    &KUBE_HEALTH_READ_BINDING,
    &KUBE_SNAPSHOT_READ_BINDING,
    &KUBE_WORKLOAD_CANCEL_BINDING,
    &KUBE_WORKLOAD_CREATE_BINDING,
    &KUBE_WORKLOAD_PAUSE_BINDING,
    &KUBE_WORKLOAD_RESTART_BINDING,
    &KUBE_WORKLOAD_RESUME_BINDING,
    &KUBE_WORKLOAD_SUMMARIZE_BINDING,
    &TASK_CREATE_BINDING,
    &TASK_READ_BINDING,
    &TASK_PAUSE_BINDING,
    &TASK_STEER_BINDING,
];

static BROWSER_CONSEQUENTIAL_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/browser.consequential.input.json",
    output_schema: "schemas/capability/browser.consequential.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_browser.consequential",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_browser.consequential_evidence",
    },
};

static BROWSER_INTERACT_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/browser.interact.input.json",
    output_schema: "schemas/capability/browser.interact.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_browser.interact",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_browser.interact_evidence",
    },
};

static BROWSER_OBSERVE_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/browser.observe.input.json",
    output_schema: "schemas/capability/browser.observe.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_browser.observe",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_browser.observe_evidence",
    },
};

static CAPSULE_EVAL_RUN_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/capsule.eval.run.input.json",
    output_schema: "schemas/capability/capsule.eval.run.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_eval.run",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_eval.run_evidence",
    },
};

static CAPSULE_FILE_EDIT_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/capsule.file.edit.input.json",
    output_schema: "schemas/capability/capsule.file.edit.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_file.edit",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_file.edit_evidence",
    },
};

static CONTEXT_READ_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/context.read.input.json",
    output_schema: "schemas/capability/context.read.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: CONTEXT_READ_HANDLER_ID,
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: CONTEXT_READ_EVIDENCE_ID,
    },
};

static BRAIN_SEARCH_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/brain.search.input.json",
    output_schema: "schemas/capability/brain.search.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: super::brain::SEARCH_HANDLER,
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: super::brain::SEARCH_EVIDENCE,
    },
};

static BRAIN_READ_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/brain.read.input.json",
    output_schema: "schemas/capability/brain.read.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: super::brain::READ_HANDLER,
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: super::brain::READ_EVIDENCE,
    },
};

static BRAIN_RECORDS_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/brain.input.json",
    output_schema: "schemas/capability/brain.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: super::brain::RECORDS_HANDLER,
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: super::brain::RECORDS_EVIDENCE,
    },
};

static KUBE_SNAPSHOT_READ_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/kube.snapshot.read.input.json",
    output_schema: "schemas/capability/kube.snapshot.read.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_kube.snapshot.read",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_kube.snapshot.read_evidence",
    },
};

static KUBE_HEALTH_READ_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/kube.health.read.input.json",
    output_schema: "schemas/capability/kube.health.read.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_kube.health.read",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_kube.health.read_evidence",
    },
};

static KUBE_WORKLOAD_CANCEL_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/kube.workload.cancel.input.json",
    output_schema: "schemas/capability/kube.workload.cancel.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_kube.workload.cancel",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_kube.workload.cancel_evidence",
    },
};

static KUBE_WORKLOAD_CREATE_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/kube.workload.create.input.json",
    output_schema: "schemas/capability/kube.workload.create.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_kube.workload.create",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_kube.workload.create_evidence",
    },
};

static KUBE_WORKLOAD_PAUSE_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/kube.workload.pause.input.json",
    output_schema: "schemas/capability/kube.workload.pause.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_kube.workload.pause",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_kube.workload.pause_evidence",
    },
};

static KUBE_WORKLOAD_RESTART_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/kube.workload.restart.input.json",
    output_schema: "schemas/capability/kube.workload.restart.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_kube.workload.restart",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_kube.workload.restart_evidence",
    },
};

static KUBE_WORKLOAD_RESUME_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/kube.workload.resume.input.json",
    output_schema: "schemas/capability/kube.workload.resume.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_kube.workload.resume",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_kube.workload.resume_evidence",
    },
};

static KUBE_WORKLOAD_SUMMARIZE_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/kube.workload.summarize.input.json",
    output_schema: "schemas/capability/kube.workload.summarize.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_kube.workload.summarize",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_kube.workload.summarize_evidence",
    },
};

static TASK_CREATE_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/task.create.input.json",
    output_schema: "schemas/capability/task.create.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: delegation::TASK_CREATE_HANDLER_ID,
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: delegation::TASK_CREATE_EVIDENCE_ID,
    },
};

static TASK_READ_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/task.read.input.json",
    output_schema: "schemas/capability/task.read.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: delegation::TASK_READ_HANDLER_ID,
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: delegation::TASK_READ_EVIDENCE_ID,
    },
};

static TASK_PAUSE_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/task.pause.input.json",
    output_schema: "schemas/capability/task.pause.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: delegation::TASK_PAUSE_HANDLER_ID,
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: delegation::TASK_PAUSE_EVIDENCE_ID,
    },
};

static TASK_STEER_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/task.steer.input.json",
    output_schema: "schemas/capability/task.steer.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: delegation::TASK_STEER_HANDLER_ID,
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: delegation::TASK_STEER_EVIDENCE_ID,
    },
};

// The production `odin_hermes.*` life-capability bindings: capability id,
// schemas, and handler/extractor ids are the registry's declared tuples
// verbatim. Their concrete HostTool owners are registered by the daemon at
// startup; `validate_production_composition` refuses the catalog until
// every builtin below resolves.
static CALENDAR_READ_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/calendar.read.input.json",
    output_schema: "schemas/capability/calendar.read.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "calendar_read",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_calendar_read_evidence",
    },
};

static CALENDAR_PROPOSE_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/calendar.propose.input.json",
    output_schema: "schemas/capability/calendar.propose.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "calendar_propose",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_calendar_propose_evidence",
    },
};

static DISCORD_INTAKE_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/discord.intake.input.json",
    output_schema: "schemas/capability/discord.intake.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "discord_intake",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_discord_intake_evidence",
    },
};

static DISCORD_NOTIFY_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/discord.notify.input.json",
    output_schema: "schemas/capability/discord.notify.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "discord_notify",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_discord_notify_evidence",
    },
};

static EMAIL_DRAFT_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/email.draft.input.json",
    output_schema: "schemas/capability/email.draft.output.json",
    handler: CompiledHandlerBinding::Builtin { id: "email_draft" },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_email_draft_evidence",
    },
};

static EMAIL_MANAGE_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/email.manage.input.json",
    output_schema: "schemas/capability/email.manage.output.json",
    handler: CompiledHandlerBinding::Builtin { id: "email_manage" },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_email_manage_evidence",
    },
};

static EMAIL_READ_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/email.read.input.json",
    output_schema: "schemas/capability/email.read.output.json",
    handler: CompiledHandlerBinding::Builtin { id: "email_read" },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_email_read_evidence",
    },
};

static EMAIL_SEARCH_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/email.search.input.json",
    output_schema: "schemas/capability/email.search.output.json",
    handler: CompiledHandlerBinding::Builtin { id: "email_search" },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_email_search_evidence",
    },
};

static EMAIL_SEND_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/email.send.input.json",
    output_schema: "schemas/capability/email.send.output.json",
    handler: CompiledHandlerBinding::Builtin { id: "email_send" },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_email_send_evidence",
    },
};

static WORKLOAD_DRAFT_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/workload.draft.input.json",
    output_schema: "schemas/capability/workload.draft.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "workload_draft",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_workload_draft_evidence",
    },
};

static WORKLOAD_PUBLISH_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/workload.publish.input.json",
    output_schema: "schemas/capability/workload.publish.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "workload_publish",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_workload_publish_evidence",
    },
};

static FINANCE_READ_SUMMARY_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/finance.read_summary.input.json",
    output_schema: "schemas/capability/finance.read_summary.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "finance_read_summary",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_finance_read_summary_evidence",
    },
};

static PURCHASE_SUBMIT_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/purchase.submit.input.json",
    output_schema: "schemas/capability/purchase.submit.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "purchase_submit",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_purchase_submit_evidence",
    },
};

/// Per-seat declarations share this primitive through `delegate_to` and supply their tool names.
static SEAT_ASK_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/seat.ask.input.json",
    output_schema: "schemas/capability/seat.ask.output.json",
    handler: CompiledHandlerBinding::Builtin { id: "seat_ask" },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_seat_ask_evidence",
    },
};

/// The handler's target set comes from the pinned snapshot's live seat bindings.
static SEAT_MODEL_SET_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/seat.model.set.input.json",
    output_schema: "schemas/capability/seat.model.set.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "seat_model_set",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_seat_model_set_evidence",
    },
};

static DESKTOP_INPUT_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/desktop.input.input.json",
    output_schema: "schemas/capability/desktop.input.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "desktop_input",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_desktop_input_evidence",
    },
};

static TERMINAL_READ_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/terminal.read.input.json",
    output_schema: "schemas/capability/terminal.read.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "terminal_read",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_terminal_read_evidence",
    },
};

static HUGINN_READ_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/huginn.read.input.json",
    output_schema: "schemas/capability/huginn.read.output.json",
    handler: CompiledHandlerBinding::Builtin { id: "huginn_read" },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_huginn_read_evidence",
    },
};

static WORKSPACE_CONNECT_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/workspace.connect.input.json",
    output_schema: "schemas/capability/workspace.connect.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_hermes.workspace_connect",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes.workspace_connect_evidence",
    },
};

static CLAUDE_OPEN_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/claude.open.input.json",
    output_schema: "schemas/capability/claude.open.output.json",
    handler: CompiledHandlerBinding::Builtin { id: "claude_open" },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_claude_open_evidence",
    },
};

static CLAUDE_PROMPT_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/claude.prompt.input.json",
    output_schema: "schemas/capability/claude.prompt.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "claude_prompt",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_claude_prompt_evidence",
    },
};

static CLAUDE_READ_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/claude.read.input.json",
    output_schema: "schemas/capability/claude.read.output.json",
    handler: CompiledHandlerBinding::Builtin { id: "claude_read" },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_claude_read_evidence",
    },
};

static CLAUDE_STOP_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/claude.stop.input.json",
    output_schema: "schemas/capability/claude.stop.output.json",
    handler: CompiledHandlerBinding::Builtin { id: "claude_stop" },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_claude_stop_evidence",
    },
};

static FLEET_DRAIN_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/fleet.drain.input.json",
    output_schema: "schemas/capability/fleet.drain.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_hermes.fleet_drain",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes.fleet_drain_evidence",
    },
};

static FLEET_RESTORE_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/fleet.restore.input.json",
    output_schema: "schemas/capability/fleet.restore.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_hermes.fleet_restore",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes.fleet_restore_evidence",
    },
};

static VAULT_SEARCH_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/vault.search.input.json",
    output_schema: "schemas/capability/vault.search.output.json",
    handler: CompiledHandlerBinding::Builtin { id: "vault_search" },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_vault_search_evidence",
    },
};

static VAULT_WRITE_GENERATED_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/vault.write_generated.input.json",
    output_schema: "schemas/capability/vault.write_generated.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "vault_write_generated",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_vault_write_generated_evidence",
    },
};

static MEMORY_REMEMBER_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/memory.remember.input.json",
    output_schema: "schemas/capability/memory.remember.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "memory_remember",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_memory_remember_evidence",
    },
};

static REMINDER_SET_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/reminder.set.input.json",
    output_schema: "schemas/capability/reminder.set.output.json",
    handler: CompiledHandlerBinding::Builtin { id: "reminder_set" },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_reminder_set_evidence",
    },
};

static REMINDER_LIST_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/reminder.list.input.json",
    output_schema: "schemas/capability/reminder.list.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "reminder_list",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_reminder_list_evidence",
    },
};

static REMINDER_CANCEL_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/reminder.cancel.input.json",
    output_schema: "schemas/capability/reminder.cancel.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "reminder_cancel",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_reminder_cancel_evidence",
    },
};

static INCIDENT_RAISE_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/incident.raise.input.json",
    output_schema: "schemas/capability/incident.raise.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "incident_raise",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_incident_raise_evidence",
    },
};

static MEMORY_FORGET_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/memory.forget.input.json",
    output_schema: "schemas/capability/memory.forget.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "memory_forget",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_memory_forget_evidence",
    },
};

static ARTIFACT_WRITE_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/artifact.write.input.json",
    output_schema: "schemas/capability/artifact.write.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "artifact_write",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_artifact_write_evidence",
    },
};

static ARTIFACT_READ_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/artifact.read.input.json",
    output_schema: "schemas/capability/artifact.read.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "artifact_read",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_artifact_read_evidence",
    },
};

static ROUTINE_SET_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/routine.set.input.json",
    output_schema: "schemas/capability/routine.set.output.json",
    handler: CompiledHandlerBinding::Builtin { id: "routine_set" },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_routine_set_evidence",
    },
};

static ROUTINE_REMOVE_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/routine.remove.input.json",
    output_schema: "schemas/capability/routine.remove.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "routine_remove",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_routine_remove_evidence",
    },
};

static REGISTRY_READ_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/registry.read.input.json",
    output_schema: "schemas/capability/registry.read.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "registry_read",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_registry_read_evidence",
    },
};

static SPEND_READ_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/spend.read.input.json",
    output_schema: "schemas/capability/spend.read.output.json",
    handler: CompiledHandlerBinding::Builtin { id: "spend_read" },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_spend_read_evidence",
    },
};

static REGISTRY_SKELETON_READ_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/registry.skeleton.read.input.json",
    output_schema: "schemas/capability/registry.skeleton.read.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "registry_skeleton_read",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_registry_skeleton_read_evidence",
    },
};

static REGISTRY_AUTHOR_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/registry.author.input.json",
    output_schema: "schemas/capability/registry.author.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "registry_author",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_registry_author_evidence",
    },
};

static REGISTRY_AUTHOR_GRANT_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/registry.author.grant.input.json",
    output_schema: "schemas/capability/registry.author.grant.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "registry_author_grant",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_registry_author_grant_evidence",
    },
};

static BUILD_RUN_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/build.run.input.json",
    output_schema: "schemas/capability/build.run.output.json",
    handler: CompiledHandlerBinding::Builtin { id: "build_run" },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_build_run_evidence",
    },
};

static CHECK_RUN_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/check.run.input.json",
    output_schema: "schemas/capability/check.run.output.json",
    handler: CompiledHandlerBinding::Builtin { id: "check_run" },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_check_run_evidence",
    },
};

static CODE_NAVIGATE_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/code.navigate.input.json",
    output_schema: "schemas/capability/code.navigate.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "code_navigate",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_code_navigate_evidence",
    },
};

static CODE_DIAGNOSTICS_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/code.diagnostics.input.json",
    output_schema: "schemas/capability/code.diagnostics.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "code_diagnostics",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_code_diagnostics_evidence",
    },
};

static TEST_RUN_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/test.run.input.json",
    output_schema: "schemas/capability/test.run.output.json",
    handler: CompiledHandlerBinding::Builtin { id: "test_run" },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_test_run_evidence",
    },
};

static CODE_REVIEW_REQUEST_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/code.review.request.input.json",
    output_schema: "schemas/capability/code.review.request.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "code_review_request",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_code_review_request_evidence",
    },
};

static CODE_REVIEW_VERDICT_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/code.review.verdict.input.json",
    output_schema: "schemas/capability/code.review.verdict.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "code_review_verdict",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_code_review_verdict_evidence",
    },
};

static GIT_BRANCH_MERGE_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/git.branch.merge.input.json",
    output_schema: "schemas/capability/git.branch.merge.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "git_branch_merge",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_git_branch_merge_evidence",
    },
};

static GIT_PATCH_PROPOSE_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/git.patch.propose.input.json",
    output_schema: "schemas/capability/git.patch.propose.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "git_patch_propose",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_git_patch_propose_evidence",
    },
};

static PROJECT_CREATE_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/project.create.input.json",
    output_schema: "schemas/capability/project.create.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "project_create",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_project_create_evidence",
    },
};

static SEAT_CREATE_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/seat.create.input.json",
    output_schema: "schemas/capability/seat.create.output.json",
    handler: CompiledHandlerBinding::Builtin { id: "seat_create" },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_seat_create_evidence",
    },
};

static SEAT_PROPOSE_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/seat.propose.input.json",
    output_schema: "schemas/capability/seat.propose.output.json",
    handler: CompiledHandlerBinding::Builtin { id: "seat_propose" },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_seat_propose_evidence",
    },
};

static TIME_ZONE_SET_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/time.zone.set.input.json",
    output_schema: "schemas/capability/time.zone.set.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "time_zone_set",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_time_zone_set_evidence",
    },
};

static INTAKE_READ_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/intake.read.input.json",
    output_schema: "schemas/capability/intake.read.output.json",
    handler: CompiledHandlerBinding::Builtin { id: "intake_read" },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_intake_read_evidence",
    },
};

static INTAKE_FILE_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/intake.file.input.json",
    output_schema: "schemas/capability/intake.file.output.json",
    handler: CompiledHandlerBinding::Builtin { id: "intake_file" },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_intake_file_evidence",
    },
};

static DISCORD_FILE_SEND_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/discord.file.send.input.json",
    output_schema: "schemas/capability/discord.file.send.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "discord_file_send",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_discord_file_send_evidence",
    },
};

static TASK_GRANT_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/task.grant.input.json",
    output_schema: "schemas/capability/task.grant.output.json",
    handler: CompiledHandlerBinding::Builtin { id: "task_grant" },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_task_grant_evidence",
    },
};

static ODIN_PLAN_SET_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/odin.plan_set.input.json",
    output_schema: "schemas/capability/odin.plan_set.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_plan_set",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_plan_set_evidence",
    },
};
static ODIN_TODO_UPDATE_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/odin.todo_update.input.json",
    output_schema: "schemas/capability/odin.todo_update.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_todo_update",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_todo_update_evidence",
    },
};
static ODIN_LANE_STATUS_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/odin.lane_status.input.json",
    output_schema: "schemas/capability/odin.lane_status.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_lane_status",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_lane_status_evidence",
    },
};
static ODIN_ATLAS_QUERY_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/odin.atlas_query.input.json",
    output_schema: "schemas/capability/odin.atlas_query.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_atlas_query",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_atlas_query_evidence",
    },
};
static ODIN_ARTIFACT_READ_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/odin.artifact_read.input.json",
    output_schema: "schemas/capability/odin.artifact_read.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_artifact_read",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_artifact_read_evidence",
    },
};
static ODIN_APPROVAL_REQUEST_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/odin.approval_request.input.json",
    output_schema: "schemas/capability/odin.approval_request.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_approval_request",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_approval_request_evidence",
    },
};

/// The static admission set: every pre-admitted tuple whose binding does
/// not depend on a Nix store fill — the baseline capability routes plus
/// the `odin_hermes.*` life-capability bindings. This is the production
/// admission set.
pub(crate) static STATIC_BINDING_SLICE: &[&CompiledCapabilityBinding] = &[
    &BROWSER_CONSEQUENTIAL_BINDING,
    &BROWSER_INTERACT_BINDING,
    &BROWSER_OBSERVE_BINDING,
    &CALENDAR_READ_BINDING,
    &CALENDAR_PROPOSE_BINDING,
    &CAPSULE_EVAL_RUN_BINDING,
    &CAPSULE_FILE_EDIT_BINDING,
    &CONTEXT_READ_BINDING,
    &BRAIN_SEARCH_BINDING,
    &BRAIN_READ_BINDING,
    &BRAIN_RECORDS_BINDING,
    &DISCORD_INTAKE_BINDING,
    &DISCORD_NOTIFY_BINDING,
    &EMAIL_DRAFT_BINDING,
    &EMAIL_MANAGE_BINDING,
    &EMAIL_READ_BINDING,
    &EMAIL_SEARCH_BINDING,
    &EMAIL_SEND_BINDING,
    &FINANCE_READ_SUMMARY_BINDING,
    &FLEET_DRAIN_BINDING,
    &FLEET_RESTORE_BINDING,
    &HUGINN_READ_BINDING,
    &KUBE_HEALTH_READ_BINDING,
    &KUBE_SNAPSHOT_READ_BINDING,
    &KUBE_WORKLOAD_CANCEL_BINDING,
    &KUBE_WORKLOAD_CREATE_BINDING,
    &KUBE_WORKLOAD_PAUSE_BINDING,
    &KUBE_WORKLOAD_RESTART_BINDING,
    &KUBE_WORKLOAD_RESUME_BINDING,
    &KUBE_WORKLOAD_SUMMARIZE_BINDING,
    &PURCHASE_SUBMIT_BINDING,
    &SEAT_ASK_BINDING,
    &SEAT_MODEL_SET_BINDING,
    &TASK_CREATE_BINDING,
    &TASK_READ_BINDING,
    &TASK_PAUSE_BINDING,
    &TASK_STEER_BINDING,
    &TERMINAL_READ_BINDING,
    &DESKTOP_INPUT_BINDING,
    &VAULT_SEARCH_BINDING,
    &VAULT_WRITE_GENERATED_BINDING,
    &MEMORY_REMEMBER_BINDING,
    &REMINDER_SET_BINDING,
    &REMINDER_LIST_BINDING,
    &REMINDER_CANCEL_BINDING,
    &TIME_ZONE_SET_BINDING,
    &PROJECT_CREATE_BINDING,
    &SEAT_CREATE_BINDING,
    &SEAT_PROPOSE_BINDING,
    &ODIN_PLAN_SET_BINDING,
    &ODIN_TODO_UPDATE_BINDING,
    &ODIN_LANE_STATUS_BINDING,
    &ODIN_ATLAS_QUERY_BINDING,
    &ODIN_ARTIFACT_READ_BINDING,
    &ODIN_APPROVAL_REQUEST_BINDING,
    &REGISTRY_READ_BINDING,
    &SPEND_READ_BINDING,
    &REGISTRY_SKELETON_READ_BINDING,
    &REGISTRY_AUTHOR_BINDING,
    &REGISTRY_AUTHOR_GRANT_BINDING,
    &INCIDENT_RAISE_BINDING,
    &ROUTINE_SET_BINDING,
    &ROUTINE_REMOVE_BINDING,
    &ARTIFACT_WRITE_BINDING,
    &ARTIFACT_READ_BINDING,
    &MEMORY_FORGET_BINDING,
    &BUILD_RUN_BINDING,
    &CHECK_RUN_BINDING,
    &CODE_NAVIGATE_BINDING,
    &CODE_DIAGNOSTICS_BINDING,
    &TEST_RUN_BINDING,
    &CODE_REVIEW_REQUEST_BINDING,
    &CODE_REVIEW_VERDICT_BINDING,
    &GIT_PATCH_PROPOSE_BINDING,
    &GIT_BRANCH_MERGE_BINDING,
    &INTAKE_READ_BINDING,
    &INTAKE_FILE_BINDING,
    &TASK_GRANT_BINDING,
    &DISCORD_FILE_SEND_BINDING,
    &WORKLOAD_DRAFT_BINDING,
    &WORKLOAD_PUBLISH_BINDING,
    &WORKSPACE_CONNECT_BINDING,
    &CLAUDE_OPEN_BINDING,
    &CLAUDE_PROMPT_BINDING,
    &CLAUDE_READ_BINDING,
    &CLAUDE_STOP_BINDING,
];

/// Static production bindings; declared adapters are admitted separately by their two markers.
pub fn production_bindings() -> &'static [&'static CompiledCapabilityBinding] {
    STATIC_BINDING_SLICE
}
