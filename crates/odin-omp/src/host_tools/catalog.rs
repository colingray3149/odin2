use super::context_read::{CONTEXT_READ_EVIDENCE_ID, CONTEXT_READ_HANDLER_ID};
use super::delegation;

mod capsule;
use capsule::{
    CAPSULE_EVAL_RUN_BINDING, CAPSULE_FILE_EDIT_BINDING, CODE_LOOK_BINDING, CODE_REWRITE_BINDING,
};

mod desktop;

mod deploy;
use deploy::{ODIN_DEPLOY_BINDING, ODIN_DEPLOY_STATUS_BINDING};

mod inventory;
pub(super) use inventory::is_store_executable_form;
pub use inventory::CompiledHostToolCatalog;

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

pub static PRE_ADMITTED_BINDINGS: &[&CompiledCapabilityBinding] = &[
    &BROWSER_CONSEQUENTIAL_BINDING,
    &BROWSER_INTERACT_BINDING,
    &BROWSER_OBSERVE_BINDING,
    &CAPSULE_EVAL_RUN_BINDING,
    &CAPSULE_FILE_EDIT_BINDING,
    &CODE_REWRITE_BINDING,
    &CODE_LOOK_BINDING,
    &CONTEXT_READ_BINDING,
    &TASK_NOTE_BINDING,
    &KUBE_HEALTH_READ_BINDING,
    &KUBE_SNAPSHOT_READ_BINDING,
    &KUBE_WORKLOAD_CANCEL_BINDING,
    &KUBE_WORKLOAD_CREATE_BINDING,
    &KUBE_WORKLOAD_CREATE_MANY_BINDING,
    &KUBE_WORKLOAD_PAUSE_BINDING,
    &KUBE_WORKLOAD_RESTART_BINDING,
    &KUBE_WORKLOAD_RESUME_BINDING,
    &KUBE_WORKLOAD_STEER_BINDING,
    &KUBE_WORKLOAD_SUMMARIZE_BINDING,
    &KUBE_WORKLOAD_QUEUE_BINDING,
    &KUBE_WORKLOAD_QUEUE_DROP_BINDING,
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

static TASK_NOTE_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/task.note.input.json",
    output_schema: "schemas/capability/task.note.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: super::brain::NOTE_HANDLER,
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: super::brain::NOTE_EVIDENCE,
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

static KUBE_WORKLOAD_CREATE_MANY_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/kube.workload.create_many.input.json",
    output_schema: "schemas/capability/kube.workload.create_many.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_kube.workload.create_many",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_kube.workload.create_many_evidence",
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

static KUBE_WORKLOAD_STEER_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/kube.workload.steer.input.json",
    output_schema: "schemas/capability/kube.workload.steer.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_kube.workload.steer",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_kube.workload.steer_evidence",
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

static KUBE_WORKLOAD_QUEUE_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/kube.workload.queue.input.json",
    output_schema: "schemas/capability/kube.workload.queue.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_kube.workload.queue",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_kube.workload.queue_evidence",
    },
};

static KUBE_WORKLOAD_QUEUE_DROP_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/kube.workload.queue_drop.input.json",
    output_schema: "schemas/capability/kube.workload.queue_drop.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_kube.workload.queue_drop",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_kube.workload.queue_drop_evidence",
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

static CLAUDE_REVIEW_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/claude.review.input.json",
    output_schema: "schemas/capability/claude.review.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "claude_review",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_claude_review_evidence",
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

static REGISTRY_EDIT_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/registry.edit.input.json",
    output_schema: "schemas/capability/registry.edit.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "registry_edit",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_registry_edit_evidence",
    },
};

static REGISTRY_EDIT_GRANT_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/registry.edit.grant.input.json",
    output_schema: "schemas/capability/registry.edit.grant.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "registry_edit_grant",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_registry_edit_grant_evidence",
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


static INTAKE_READ_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/intake.read.input.json",
    output_schema: "schemas/capability/intake.read.output.json",
    handler: CompiledHandlerBinding::Builtin { id: "intake_read" },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_intake_read_evidence",
    },
};

static MODEL_CONSULT_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/model.consult.input.json",
    output_schema: "schemas/capability/model.consult.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "model_consult",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_model_consult_evidence",
    },
};

static MODEL_COMPLETE_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/model.complete.input.json",
    output_schema: "schemas/capability/model.complete.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "model_complete",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_model_complete_evidence",
    },
};

static JOBS_LIST_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/jobs.list.input.json",
    output_schema: "schemas/capability/jobs.list.output.json",
    handler: CompiledHandlerBinding::Builtin { id: "jobs_list" },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_jobs_list_evidence",
    },
};

static JOURNAL_READ_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/journal.read.input.json",
    output_schema: "schemas/capability/journal.read.output.json",
    handler: CompiledHandlerBinding::Builtin { id: "journal_read" },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_journal_read_evidence",
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
static ODIN_PLAN_ACCEPT_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/odin.plan_accept.input.json",
    output_schema: "schemas/capability/odin.plan_accept.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_plan_accept",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_plan_accept_evidence",
    },
};
static ODIN_PLAN_GET_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/odin.plan_get.input.json",
    output_schema: "schemas/capability/odin.plan_get.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_plan_get",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_plan_get_evidence",
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

/// The binding of one `odin_hermes` builtin capability `$id` served by the
/// host tool `$tool`: its schemas, handler and evidence extractor by name.
macro_rules! hermes_binding {
    ($id:literal, $tool:literal) => {
        CompiledCapabilityBinding {
            version: 1,
            input_schema: concat!("schemas/capability/", $id, ".input.json"),
            output_schema: concat!("schemas/capability/", $id, ".output.json"),
            handler: CompiledHandlerBinding::Builtin { id: $tool },
            evidence_extractor: CompiledHandlerBinding::Builtin {
                id: concat!("odin_hermes_", $tool, "_evidence"),
            },
        }
    };
}

/// The static admission set: every pre-admitted tuple whose binding does
/// not depend on a Nix store fill — the baseline capability routes plus
/// the `odin_hermes.*` life-capability bindings. This is the production
/// admission set.
pub(crate) static STATIC_BINDING_SLICE: &[&CompiledCapabilityBinding] = &[
    &BROWSER_CONSEQUENTIAL_BINDING,
    &BROWSER_INTERACT_BINDING,
    &BROWSER_OBSERVE_BINDING,
    &CAPSULE_EVAL_RUN_BINDING,
    &CAPSULE_FILE_EDIT_BINDING,
    &CODE_REWRITE_BINDING,
    &CODE_LOOK_BINDING,
    &CONTEXT_READ_BINDING,
    &TASK_NOTE_BINDING,
    &DISCORD_INTAKE_BINDING,
    &FLEET_DRAIN_BINDING,
    &FLEET_RESTORE_BINDING,
    &HUGINN_READ_BINDING,
    &KUBE_HEALTH_READ_BINDING,
    &KUBE_SNAPSHOT_READ_BINDING,
    &KUBE_WORKLOAD_CANCEL_BINDING,
    &KUBE_WORKLOAD_CREATE_BINDING,
    &KUBE_WORKLOAD_CREATE_MANY_BINDING,
    &KUBE_WORKLOAD_PAUSE_BINDING,
    &KUBE_WORKLOAD_RESTART_BINDING,
    &KUBE_WORKLOAD_RESUME_BINDING,
    &KUBE_WORKLOAD_STEER_BINDING,
    &KUBE_WORKLOAD_SUMMARIZE_BINDING,
    &KUBE_WORKLOAD_QUEUE_BINDING,
    &KUBE_WORKLOAD_QUEUE_DROP_BINDING,
    &SEAT_ASK_BINDING,
    &SEAT_MODEL_SET_BINDING,
    &TASK_CREATE_BINDING,
    &TASK_READ_BINDING,
    &TASK_PAUSE_BINDING,
    &TASK_STEER_BINDING,
    &TERMINAL_READ_BINDING,
    &desktop::DESKTOP_LOOK_BINDING,
    &desktop::DESKTOP_ACT_BINDING,
    &desktop::DESKTOP_DEVICE_BINDING,
    &desktop::DESKTOP_SCENE_BINDING,
    &desktop::DESKTOP_HEADLESS_BINDING,
    &desktop::DESKTOP_DISPLAY_BINDING,
    &VAULT_SEARCH_BINDING,
    &VAULT_WRITE_GENERATED_BINDING,
    &PROJECT_CREATE_BINDING,
    &SEAT_CREATE_BINDING,
    &SEAT_PROPOSE_BINDING,
    &ODIN_PLAN_GET_BINDING,
    &ODIN_PLAN_SET_BINDING,
    &ODIN_PLAN_ACCEPT_BINDING,
    &ODIN_TODO_UPDATE_BINDING,
    &ODIN_LANE_STATUS_BINDING,
    &ODIN_ATLAS_QUERY_BINDING,
    &ODIN_APPROVAL_REQUEST_BINDING,
    &REGISTRY_READ_BINDING,
    &SPEND_READ_BINDING,
    &hermes_binding!("compute.lease.create", "compute_lease_create"),
    &hermes_binding!("compute.lease.destroy", "compute_lease_destroy"),
    &hermes_binding!("compute.lease.enroll", "compute_lease_enroll"),
    &hermes_binding!("compute.lease.list", "compute_lease_list"),
    &hermes_binding!("run.stats", "run_stats"),
    &hermes_binding!("simulation.read", "simulation_read"),
    &hermes_binding!("simulation.frame", "simulation_frame"),
    &hermes_binding!("models.read", "models_read"),
    &hermes_binding!("local.models", "local_models"),
    &hermes_binding!("time.get_current_time", "time_get_current_time"),
    &hermes_binding!("time.convert_time", "time_convert_time"),
    &hermes_binding!("files.list", "files_list"),
    &hermes_binding!("files.share", "files_share"),
    &hermes_binding!("files.save", "files_save"),
    &hermes_binding!("intake.copy", "intake_copy"),
    &REGISTRY_SKELETON_READ_BINDING,
    &REGISTRY_AUTHOR_BINDING,
    &REGISTRY_AUTHOR_GRANT_BINDING,
    &REGISTRY_EDIT_BINDING,
    &REGISTRY_EDIT_GRANT_BINDING,
    &INCIDENT_RAISE_BINDING,
    &ROUTINE_SET_BINDING,
    &ROUTINE_REMOVE_BINDING,
    &hermes_binding!("artifact.write", "artifact_write"),
    &hermes_binding!("artifact.read", "artifact_read"),
    &hermes_binding!("artifact.analyze", "artifact_analyze"),
    &BUILD_RUN_BINDING,
    &CHECK_RUN_BINDING,
    &CODE_NAVIGATE_BINDING,
    &CODE_DIAGNOSTICS_BINDING,
    &TEST_RUN_BINDING,
    &CODE_REVIEW_REQUEST_BINDING,
    &CODE_REVIEW_VERDICT_BINDING,
    &hermes_binding!("science.review.verdict", "science_review_verdict"),
    &GIT_PATCH_PROPOSE_BINDING,
    &GIT_BRANCH_MERGE_BINDING,
    &INTAKE_READ_BINDING,
    &TASK_GRANT_BINDING,
    &hermes_binding!("discord.file.send", "discord_file_send"),
    &JOBS_LIST_BINDING,
    &WORKLOAD_DRAFT_BINDING,
    &WORKLOAD_PUBLISH_BINDING,
    &WORKSPACE_CONNECT_BINDING,
    &CLAUDE_OPEN_BINDING,
    &CLAUDE_PROMPT_BINDING,
    &CLAUDE_READ_BINDING,
    &CLAUDE_STOP_BINDING,
    &CLAUDE_REVIEW_BINDING,
    &JOURNAL_READ_BINDING,
    &MODEL_CONSULT_BINDING,
    &MODEL_COMPLETE_BINDING,
    &hermes_binding!("device.run", "device_run"),
    &hermes_binding!("knowledge.search", "knowledge_search"),
    &hermes_binding!("knowledge.read", "knowledge_read"),
    &hermes_binding!("knowledge.dig", "knowledge_dig"),
    &hermes_binding!("knowledge.add", "knowledge_add"),
    &hermes_binding!("knowledge.pull", "knowledge_pull"),
    &hermes_binding!("knowledge.edit", "knowledge_edit"),
    &hermes_binding!("knowledge.remember", "knowledge_remember"),
    &hermes_binding!("knowledge.forget", "knowledge_forget"),
    &hermes_binding!("knowledge.promote", "knowledge_promote"),
    &hermes_binding!("knowledge.exile", "knowledge_exile"),
    &hermes_binding!("knowledge.delete", "knowledge_delete"),
    &hermes_binding!("knowledge.new", "knowledge_new"),
    &hermes_binding!("knowledge.status", "knowledge_status"),
    &hermes_binding!("knowledge.pause", "knowledge_pause"),
    &hermes_binding!("knowledge.resume", "knowledge_resume"),
    &hermes_binding!("knowledge.where", "knowledge_where"),
    &ODIN_DEPLOY_BINDING,
    &ODIN_DEPLOY_STATUS_BINDING,
];

/// Static production bindings; declared adapters are admitted separately by their two markers.
pub fn production_bindings() -> &'static [&'static CompiledCapabilityBinding] {
    STATIC_BINDING_SLICE
}
