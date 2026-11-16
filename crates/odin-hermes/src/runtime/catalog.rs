//! The compiled capability catalog: the one ordered model surface list and
//! the exact internal binding owners the kernel executor resolves.

use std::collections::BTreeMap;
use std::sync::Arc;

use odin_domain::Scope;
use odin_omp::host_tools::{HostTool, RpcHostToolDefinition};
use serde_json::{json, Value};

use super::effects::{discord_tools, vault_tools};
use super::grants::grant_tools;
use super::probes::read_tools;
use super::reminders::schedule_tools;
use super::seat_ask::{seat_ask_binding, seat_ask_model_tool};
use super::tools::CapabilityTool;
use super::workload::workload_tools;
use super::HermesRuntime;

/// Builds the governed `odin_hermes.*` capability tools over the composed
/// runtime. Each wrapper dispatches only through the runtime's governed
/// seams; the kernel operation authority wrapping every invocation is the
/// one approval gate for the model-dispatch route.
pub fn hermes_host_tools(runtime: &Arc<HermesRuntime>) -> Vec<Arc<dyn HostTool>> {
    let mut tools: Vec<Arc<dyn HostTool>> = Vec::new();

    // -- seat delegation surfaces (generated from admitted contracts) -----
    // Generate model-facing tools from admitted delegation contracts; dispatch injects
    // the target seat, and the schema exposes only that seat's declared projects.
    for contract in runtime
        .contracts
        .values()
        .filter(|contract| contract.delegate_to.is_some())
    {
        tools.push(seat_ask_model_tool(runtime, contract));
    }
    vault_tools(runtime, &mut tools);
    super::knowledge::knowledge_tools(runtime, &mut tools);
    discord_tools(runtime, &mut tools);
    read_tools(runtime, &mut tools);
    workload_tools(runtime, &mut tools);
    schedule_tools(runtime, &mut tools);
    grant_tools(runtime, &mut tools);
    super::jobs::jobs_tools(runtime, &mut tools);
    super::journal::journal_tools(runtime, &mut tools);
    super::consult::consult_tools(runtime, &mut tools);
    super::model_complete::model_complete_tools(runtime, &mut tools);
    super::coding::deploy::deploy_tools(runtime, &mut tools);
    super::files::file_send_tools(runtime, &mut tools);
    super::projects::project_tools(runtime, &mut tools);
    super::coding::coding_tools(runtime, &mut tools);
    super::registry_read::registry_tools(runtime, &mut tools);
    super::incidents::incident_tools(runtime, &mut tools);
    super::routines::routine_tools(runtime, &mut tools);
    super::spend::spend_tools(runtime, &mut tools);
    super::run_stats::run_stats_tools(runtime, &mut tools);
    super::simulation::simulation_tools(runtime, &mut tools);
    super::models::models_tools(runtime, &mut tools);
    super::local_models::local_models_tools(runtime, &mut tools);
    super::shared_files::shared_file_tools(runtime, &mut tools);
    super::registry_author::registry_author_tools(runtime, &mut tools);
    super::claude::claude_tools(runtime, &mut tools);
    super::rental::rental_tools(runtime, &mut tools);
    super::desktop::desktop_tools(runtime, &mut tools);
    super::time_ops::time_tools(runtime, &mut tools);

    // -- live model switch (generated from the pinned seat declaration) --
    // ONE compiled surface per admitted `seat.model.set` contract: the
    // exact declared `(seat, provider, model)` tuples come from the
    // daemon's pinned live seat bindings, and the dispatch routes only
    // through the daemon-bound `OmpLiveService::command` seam.
    if let Some(tool) = super::model_set::seat_model_set_tool(runtime) {
        tools.push(tool);
    }

    tools
}

/// Maps catalog handlers and evidence extractors to the same tools the model uses.
/// Extractors relay handler output without I/O; all delegation contracts share `seat_ask`.
pub fn hermes_capability_bindings(
    runtime: &Arc<HermesRuntime>,
) -> Vec<(&'static str, Arc<dyn HostTool>)> {
    const HANDLERS: &[&str] = &[
        "seat_ask",
        "claude_open",
        "claude_prompt",
        "claude_read",
        "claude_stop",
        "claude_review",
        "compute_lease_create",
        "compute_lease_destroy",
        "compute_lease_enroll",
        "compute_lease_list",
        "huginn_read",
        "vault_search",
        "vault_write_generated",
        "discord_intake",
        "terminal_read",
        "desktop_look",
        "desktop_act",
        "desktop_device",
        "desktop_display",
        "desktop_scene",
        "desktop_headless",
        // The dotted contract id resolves the same instance as `workspace_connect`.
        "odin_hermes.workspace_connect",
        // The `fleet.drain` / `fleet.restore` contracts' declared builtin
        // handler ids: two model-surface tools over the ONE daemon fleet
        // route, each resolved through its own dotted identity.
        "odin_hermes.fleet_drain",
        "odin_hermes.fleet_restore",
        "workload_draft",
        "workload_publish",
        "seat_model_set",
        "reminder_set",
        "reminder_list",
        "reminder_cancel",
        "time_zone_set",
        "time_get_current_time",
        "time_convert_time",
        "intake_read",
        "jobs_list",
        "task_grant",
        "discord_file_send",
        "files_list",
        "files_share",
        "files_save",
        "intake_copy",
        "project_create",
        "seat_create",
        "seat_propose",
        "registry_read",
        "incident_raise",
        "routine_set",
        "routine_remove",
        "artifact_write",
        "artifact_read",
        "artifact_analyze",
        "build_run",
        "check_run",
        "code_navigate",
        "code_diagnostics",
        "test_run",
        "code_review_request",
        "code_review_verdict",
        "science_review_verdict",
        "git_patch_propose",
        "git_branch_merge",
        "spend_read",
        "run_stats",
        "simulation_read",
        "simulation_frame",
        "models_read",
        "local_models",
        "registry_skeleton_read",
        "registry_author",
        "registry_author_grant",
        "registry_edit",
        "registry_edit_grant",
        "journal_read",
        "model_consult",
        "model_complete",
        "odin_deploy",
        "odin_deploy_status",
        "knowledge_search",
        "knowledge_read",
        "knowledge_dig",
        "knowledge_add",
        "knowledge_pull",
        "knowledge_edit",
        "knowledge_remember",
        "knowledge_forget",
        "knowledge_promote",
        "knowledge_exile",
        "knowledge_delete",
        "knowledge_new",
        "knowledge_status",
        "knowledge_pause",
        "knowledge_resume",
        "knowledge_where",
    ];
    const EXTRACTORS: &[(&str, &str)] = &[
        ("odin_hermes_seat_ask_evidence", "seat_ask"),
        ("odin_hermes_claude_open_evidence", "claude_open"),
        ("odin_hermes_claude_prompt_evidence", "claude_prompt"),
        ("odin_hermes_claude_read_evidence", "claude_read"),
        ("odin_hermes_claude_stop_evidence", "claude_stop"),
        ("odin_hermes_claude_review_evidence", "claude_review"),
        (
            "odin_hermes_compute_lease_create_evidence",
            "compute_lease_create",
        ),
        (
            "odin_hermes_compute_lease_destroy_evidence",
            "compute_lease_destroy",
        ),
        (
            "odin_hermes_compute_lease_enroll_evidence",
            "compute_lease_enroll",
        ),
        (
            "odin_hermes_compute_lease_list_evidence",
            "compute_lease_list",
        ),
        ("odin_hermes_huginn_read_evidence", "huginn_read"),
        ("odin_hermes_vault_search_evidence", "vault_search"),
        (
            "odin_hermes_vault_write_generated_evidence",
            "vault_write_generated",
        ),
        ("odin_hermes_discord_intake_evidence", "discord_intake"),
        ("odin_hermes_seat_model_set_evidence", "seat_model_set"),
        ("odin_hermes_terminal_read_evidence", "terminal_read"),
        ("odin_hermes_desktop_look_evidence", "desktop_look"),
        ("odin_hermes_desktop_act_evidence", "desktop_act"),
        ("odin_hermes_desktop_display_evidence", "desktop_display"),
        (
            "odin_hermes.workspace_connect_evidence",
            "odin_hermes.workspace_connect",
        ),
        (
            "odin_hermes.fleet_drain_evidence",
            "odin_hermes.fleet_drain",
        ),
        (
            "odin_hermes.fleet_restore_evidence",
            "odin_hermes.fleet_restore",
        ),
        ("odin_hermes_workload_draft_evidence", "workload_draft"),
        ("odin_hermes_workload_publish_evidence", "workload_publish"),
        ("odin_hermes_reminder_set_evidence", "reminder_set"),
        ("odin_hermes_reminder_list_evidence", "reminder_list"),
        ("odin_hermes_reminder_cancel_evidence", "reminder_cancel"),
        ("odin_hermes_time_zone_set_evidence", "time_zone_set"),
        (
            "odin_hermes_time_get_current_time_evidence",
            "time_get_current_time",
        ),
        (
            "odin_hermes_time_convert_time_evidence",
            "time_convert_time",
        ),
        ("odin_hermes_intake_read_evidence", "intake_read"),
        ("odin_hermes_jobs_list_evidence", "jobs_list"),
        ("odin_hermes_task_grant_evidence", "task_grant"),
        (
            "odin_hermes_discord_file_send_evidence",
            "discord_file_send",
        ),
        ("odin_hermes_files_list_evidence", "files_list"),
        ("odin_hermes_files_share_evidence", "files_share"),
        ("odin_hermes_files_save_evidence", "files_save"),
        ("odin_hermes_intake_copy_evidence", "intake_copy"),
        ("odin_hermes_project_create_evidence", "project_create"),
        ("odin_hermes_seat_create_evidence", "seat_create"),
        ("odin_hermes_seat_propose_evidence", "seat_propose"),
        ("odin_hermes_registry_read_evidence", "registry_read"),
        ("odin_hermes_incident_raise_evidence", "incident_raise"),
        ("odin_hermes_routine_set_evidence", "routine_set"),
        ("odin_hermes_routine_remove_evidence", "routine_remove"),
        ("odin_hermes_artifact_write_evidence", "artifact_write"),
        ("odin_hermes_artifact_read_evidence", "artifact_read"),
        ("odin_hermes_artifact_analyze_evidence", "artifact_analyze"),
        ("odin_hermes_build_run_evidence", "build_run"),
        ("odin_hermes_check_run_evidence", "check_run"),
        ("odin_hermes_code_navigate_evidence", "code_navigate"),
        ("odin_hermes_code_diagnostics_evidence", "code_diagnostics"),
        ("odin_hermes_test_run_evidence", "test_run"),
        (
            "odin_hermes_code_review_request_evidence",
            "code_review_request",
        ),
        (
            "odin_hermes_code_review_verdict_evidence",
            "code_review_verdict",
        ),
        (
            "odin_hermes_science_review_verdict_evidence",
            "science_review_verdict",
        ),
        (
            "odin_hermes_git_patch_propose_evidence",
            "git_patch_propose",
        ),
        ("odin_hermes_git_branch_merge_evidence", "git_branch_merge"),
        ("odin_hermes_spend_read_evidence", "spend_read"),
        ("odin_hermes_run_stats_evidence", "run_stats"),
        ("odin_hermes_simulation_read_evidence", "simulation_read"),
        ("odin_hermes_simulation_frame_evidence", "simulation_frame"),
        ("odin_hermes_models_read_evidence", "models_read"),
        ("odin_hermes_local_models_evidence", "local_models"),
        (
            "odin_hermes_registry_skeleton_read_evidence",
            "registry_skeleton_read",
        ),
        ("odin_hermes_registry_author_evidence", "registry_author"),
        (
            "odin_hermes_registry_author_grant_evidence",
            "registry_author_grant",
        ),
        ("odin_hermes_registry_edit_evidence", "registry_edit"),
        (
            "odin_hermes_registry_edit_grant_evidence",
            "registry_edit_grant",
        ),
        ("odin_hermes_journal_read_evidence", "journal_read"),
        ("odin_hermes_model_consult_evidence", "model_consult"),
        ("odin_hermes_model_complete_evidence", "model_complete"),
        ("odin_hermes_odin_deploy_evidence", "odin_deploy"),
        (
            "odin_hermes_odin_deploy_status_evidence",
            "odin_deploy_status",
        ),
        ("odin_hermes_knowledge_search_evidence", "knowledge_search"),
        ("odin_hermes_knowledge_read_evidence", "knowledge_read"),
        ("odin_hermes_knowledge_dig_evidence", "knowledge_dig"),
        ("odin_hermes_knowledge_add_evidence", "knowledge_add"),
        ("odin_hermes_knowledge_pull_evidence", "knowledge_pull"),
        ("odin_hermes_knowledge_edit_evidence", "knowledge_edit"),
        (
            "odin_hermes_knowledge_remember_evidence",
            "knowledge_remember",
        ),
        ("odin_hermes_knowledge_forget_evidence", "knowledge_forget"),
        (
            "odin_hermes_knowledge_promote_evidence",
            "knowledge_promote",
        ),
        ("odin_hermes_knowledge_exile_evidence", "knowledge_exile"),
        ("odin_hermes_knowledge_delete_evidence", "knowledge_delete"),
        ("odin_hermes_knowledge_new_evidence", "knowledge_new"),
        ("odin_hermes_knowledge_status_evidence", "knowledge_status"),
        ("odin_hermes_knowledge_pause_evidence", "knowledge_pause"),
        ("odin_hermes_knowledge_resume_evidence", "knowledge_resume"),
        ("odin_hermes_knowledge_where_evidence", "knowledge_where"),
    ];
    let mut by_name: BTreeMap<String, Arc<dyn HostTool>> = BTreeMap::new();
    for tool in hermes_host_tools(runtime) {
        by_name.insert(tool.definition().name.to_string(), tool);
    }
    // The generic primitive is an internal binding owner, never a model
    // listing entry — but its evidence extractor resolves through the same
    // owner table.
    let seat_ask = seat_ask_binding(runtime);
    by_name.insert(seat_ask.definition().name.to_string(), seat_ask);
    // The dotted internal handler identity of `workspace.connect` aliases
    // the model-surface tool: the compiled catalog and every admitted
    // contract resolve the handler and the extractor through it, while the
    // listing keeps the plain capability-derived name.
    if let Some(tool) = by_name.get("workspace_connect").cloned() {
        by_name.insert("odin_hermes.workspace_connect".to_owned(), tool);
    }
    // The dotted internal handler identities of `fleet.drain` and
    // `fleet.restore` alias their model-surface tools the same way: the
    // compiled catalog and the admitted contracts resolve the handler and
    // the extractor through them, while the listing keeps the plain
    // capability-derived names.
    if let Some(tool) = by_name.get("fleet_drain").cloned() {
        by_name.insert("odin_hermes.fleet_drain".to_owned(), tool);
    }
    if let Some(tool) = by_name.get("fleet_restore").cloned() {
        by_name.insert("odin_hermes.fleet_restore".to_owned(), tool);
    }
    let mut bindings: Vec<(&'static str, Arc<dyn HostTool>)> = Vec::new();
    for id in HANDLERS {
        let Some(tool) = by_name.get(*id) else {
            continue;
        };
        bindings.push((*id, Arc::clone(tool)));
    }
    for (extractor_id, tool) in EXTRACTORS {
        let Some(owner) = by_name.get(*tool) else {
            continue;
        };
        let capability = owner.definition().name.to_string();
        let extractor = Arc::new(CapabilityTool::plain_without_prerequisites(
            RpcHostToolDefinition {
                name: (*extractor_id).into(),
                label: "Evidence extractor".into(),
                description:
                    "Internal kernel evidence extractor: projects the handler's real result \
                     verbatim as the operation evidence. Never listed, never a model surface."
                        .into(),
                parameters: json!({
                    "type": "object",
                    "properties": { "output": { "type": ["object", "array", "null"] } },
                    "required": ["output"],
                    "additionalProperties": false,
                }),
                hidden: true,
                load_mode: odin_omp::host_tools::ToolLoadMode::Discoverable,
            },
            // The explicit no-external-prerequisites disposition: an
            // evidence extractor's input is the handler's post-effect
            // output, which cannot exist at dispatch time; its verbatim
            // relay is the execution and governs at the permit.
            Box::new(move |_scope: Scope, arguments: Value| {
                let output = arguments.get("output").cloned().unwrap_or(Value::Null);
                Ok(json!({
                    "capability": capability,
                    "result": output,
                }))
            }),
        ));
        bindings.push((*extractor_id, extractor));
    }
    bindings
}
