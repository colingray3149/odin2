use super::*;

pub(super) fn validate_seat(
    object: &RegistryObject,
    value: &SeatToml,
    findings: &mut Vec<RegistryFinding>,
) {
    validate_common(
        object,
        &value.schema,
        value.kind,
        &value.description,
        findings,
    );
    if let Some(ephemeral) = &value.ephemeral {
        if ephemeral.expires_at_unix().is_none() {
            findings.push(fail(
                object,
                "seat-ephemeral",
                format!(
                    "ephemeral expires_at {:?} is not a UTC time like 2026-10-03T12:00:00Z",
                    ephemeral.expires_at
                ),
            ));
        }
        if value.conversation.is_some() {
            findings.push(fail(
                object,
                "seat-ephemeral",
                "a conversation seat cannot be ephemeral".to_owned(),
            ));
        }
    }
    for category in &value.categories {
        require_nonempty(object, "categories", category, findings);
    }
    for subtree in &value.brain_scope {
        if !valid_brain_scope(subtree.as_str()) {
            findings.push(fail(
                object,
                "seat-brain-scope",
                format!(
                    "brain_scope entry {subtree:?} must name an atlas.* subtree, an archive \
                     export, memory.<seat>, or a supported state source"
                ),
            ));
        }
    }
    if let Some(profile) = &value.profile_namespace {
        if !valid_memory_namespace(profile.as_str()) || !profile.as_str().starts_with("memory.") {
            findings.push(fail(
                object,
                "seat-profile-namespace",
                format!(
                    "profile_namespace {:?} must be a memory.<name> namespace",
                    profile.as_str()
                ),
            ));
        } else if !value.brain_scope.contains(profile) {
            findings.push(fail(
                object,
                "seat-profile-namespace",
                format!(
                    "profile_namespace {:?} is outside brain_scope",
                    profile.as_str()
                ),
            ));
        }
    }
    if !(1..=1_024).contains(&value.limits.max_parallel_runs) {
        findings.push(fail(
            object,
            "seat-limits-range",
            "limits.max_parallel_runs must be in 1..=1024",
        ));
    }
    if !(1..=1_024).contains(&value.limits.max_sessions) {
        findings.push(fail(
            object,
            "seat-limits-range",
            "limits.max_sessions must be in 1..=1024",
        ));
    }
    if !(1..=1_024).contains(&value.limits.max_background_jobs) {
        findings.push(fail(
            object,
            "seat-limits-range",
            "limits.max_background_jobs must be in 1..=1024",
        ));
    }
    if value.limits.max_batch_launches == 0 {
        findings.push(fail(
            object,
            "seat-limits-range",
            "limits.max_batch_launches must be positive",
        ));
    }
    if value.limits.max_batch_inputs == 0 {
        findings.push(fail(
            object,
            "seat-limits-range",
            "limits.max_batch_inputs must be positive",
        ));
    }
    if !(1..=600).contains(&value.limits.inline_seconds) {
        findings.push(fail(
            object,
            "seat-limits-range",
            "limits.inline_seconds must be in 1..=600",
        ));
    }
    if let Some(Err(message)) = value
        .limits
        .budget
        .as_ref()
        .map(validate_budget_policy_fields)
    {
        findings.push(fail(object, "seat-budget-policy", message));
    }
    if let Some(live) = &value.live {
        if live.max_sessions.get() > 64 {
            findings.push(fail(
                object,
                "seat-live-range",
                "live.max_sessions must be in 1..=64",
            ));
        }
        for watch in &live.watches {
            let (name, project) = watch
                .split_once(':')
                .map_or((watch.as_str(), None), |(name, project)| {
                    (name, Some(project))
                });
            let project_event = watch
                .strip_prefix("project_event:")
                .is_some_and(|project| odin_domain::ProjectId::new(project).is_ok());
            if !project_event
                && !matches!(
                    name,
                    "child_report" | "stall" | "repo_watch" | "workload_watch" | "simulation"
                )
            {
                findings.push(fail(
                    object,
                    "seat-live-watch",
                    format!("live.watches names unknown event {watch:?}"),
                ));
            }
            if let Some(project) = project {
                if !value
                    .project_scope
                    .iter()
                    .any(|scoped| scoped.as_str() == project)
                {
                    findings.push(fail(
                        object,
                        "seat-live-watch",
                        format!("live.watches {watch:?} names a project outside project_scope"),
                    ));
                }
            }
        }
        if let Some(seconds) = &live.max_turn_seconds {
            if seconds.get() > super::super::seat::MAX_TURN_SECONDS {
                findings.push(fail(
                    object,
                    "seat-live-range",
                    "live.max_turn_seconds must be in 1..=86400",
                ));
            }
        }
        if let Some(rollover) = &live.rollover {
            if rollover.threshold_tokens == 0 || rollover.threshold_tokens > 2_000_000 {
                findings.push(fail(
                    object,
                    "seat-live-rollover-range",
                    "live.rollover.threshold_tokens must be in 1..=2000000",
                ));
            }
            if !(1024..=32_768).contains(&rollover.max_brief_bytes) {
                findings.push(fail(
                    object,
                    "seat-live-rollover-range",
                    "live.rollover.max_brief_bytes must be in 1024..=32768",
                ));
            }
            if !(8..=1024).contains(&rollover.history_tail_events) {
                findings.push(fail(
                    object,
                    "seat-live-rollover-range",
                    "live.rollover.history_tail_events must be in 8..=1024",
                ));
            }
            if rollover
                .window_fraction
                .is_some_and(|fraction| !(1..=99).contains(&fraction))
            {
                findings.push(fail(
                    object,
                    "seat-live-rollover-range",
                    "live.rollover.window_fraction must be in 1..=99",
                ));
            }
            if rollover
                .fresh_after_rollovers
                .is_some_and(|count| !(1..=16).contains(&count))
            {
                findings.push(fail(
                    object,
                    "seat-live-rollover-range",
                    "live.rollover.fresh_after_rollovers must be in 1..=16",
                ));
            }
            if rollover
                .heartbeat_minutes
                .is_some_and(|minutes| !(5..=1440).contains(&minutes))
            {
                findings.push(fail(
                    object,
                    "seat-live-rollover-range",
                    "live.rollover.heartbeat_minutes must be in 5..=1440",
                ));
            }
        }
        if let Some(loom) = &live.loom {
            let sane = (1_000..=2_000_000).contains(&loom.turn_budget_tokens)
                && loom.compact_to_tokens < loom.compact_at_tokens
                && loom.compact_at_tokens < loom.turn_budget_tokens
                && (256..=65_536).contains(&loom.summary_max_bytes)
                && loom.summary_model.starts_with("gateway/")
                && (256..=loom.inline_result_bytes).contains(&loom.digest_bytes)
                && loom.inline_result_bytes <= 1 << 20
                && loom.inline_tool_calls >= 1
                && loom.max_tool_calls_per_turn >= loom.inline_tool_calls
                && loom.loop_repeat_limit >= 2
                && loom.cache_hit_floor_percent <= 100
                && (1..=24 * 365).contains(&loom.cache_floor_window_hours)
                && (1..=3_600).contains(&loom.connect_timeout_seconds)
                && (1..=86_400).contains(&loom.stream_idle_seconds)
                && loom.max_queued_turns >= 1;
            if !sane {
                findings.push(fail(
                    object,
                    "seat-live-loom-range",
                    "live.loom: compact_to < compact_at < turn_budget_tokens (1000..=2000000), \
                     summary_max_bytes 256..=65536, summary_model gateway/<lane>, \
                     256 <= digest_bytes <= inline_result_bytes <= 1 MiB, \
                     1 <= inline_tool_calls <= max_tool_calls_per_turn, loop_repeat_limit >= 2, \
                     cache_hit_floor_percent <= 100, cache_floor_window_hours 1..=8760, \
                     connect_timeout_seconds 1..=3600, stream_idle_seconds 1..=86400, \
                     max_queued_turns >= 1",
                ));
            }
        }
    }
    if let Some(knowledge) = &value.knowledge {
        if !knowledge.required_tags.is_disjoint(&knowledge.denied_tags) {
            findings.push(fail(
                object,
                "seat-knowledge-tags",
                "knowledge.required_tags and knowledge.denied_tags must be disjoint",
            ));
        }
    }
    if let Some(context) = &value.context {
        if let Some(lane) = &context.review_lane {
            if lane.is_empty()
                || !lane
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'))
            {
                findings.push(fail(
                    object,
                    "seat-review-lane",
                    "context.review_lane must name one gateway lane",
                ));
            }
        }
        if let Some(consult) = &context.consult {
            if !value
                .models
                .iter()
                .any(|model| model.model.as_str() == consult.lane)
            {
                findings.push(fail(
                    object,
                    "seat-consult-lane",
                    format!(
                        "context.consult.lane {} is not one of this seat's models",
                        consult.lane
                    ),
                ));
            }
            if consult.effort.is_empty() || !consult.effort.chars().all(|c| c.is_ascii_lowercase())
            {
                findings.push(fail(
                    object,
                    "seat-consult-effort",
                    "context.consult.effort must be one reasoning effort word, such as high",
                ));
            }
        }
    }
    if let Some(guidance) = &value.guidance {
        require_nonempty(object, "guidance", guidance, findings);
    }
    if let Some(conversation) = &value.conversation {
        require_nonempty(
            object,
            "conversation.guidance",
            &conversation.guidance,
            findings,
        );
        if !value.project_scope.contains(&conversation.project) {
            findings.push(fail(
                object,
                "seat-conversation-scope",
                format!(
                    "conversation.project {:?} must be listed in the seat's project_scope",
                    conversation.project.as_str()
                ),
            ));
        }
        if conversation
            .stall_seconds
            .is_some_and(|stall| stall >= conversation.answer_timeout_seconds)
        {
            findings.push(fail(
                object,
                "seat-conversation-stall",
                "conversation.stall_seconds must be shorter than answer_timeout_seconds, or the \
                 turn is handed off as late before its quiet lane is replaced",
            ));
        }
        if value.live.is_none() {
            findings.push(fail(
                object,
                "seat-conversation-live",
                "conversation requires the seat to declare its live plane",
            ));
        }
    }
    validate_sandbox(object, value, findings);
}

fn validate_sandbox(object: &RegistryObject, seat: &SeatToml, findings: &mut Vec<RegistryFinding>) {
    let sandbox = &seat.sandbox;
    for (field, entry) in sandbox
        .writable_entries()
        .into_iter()
        .map(|entry| ("writable", entry))
        .chain(
            sandbox
                .readonly
                .iter()
                .map(|entry| ("readonly", entry.clone())),
        )
    {
        if let Some(reason) = sandbox_path_rejection(&entry) {
            findings.push(fail(
                object,
                "seat-sandbox",
                format!("sandbox.{field} {entry:?} {reason}"),
            ));
        }
    }
    if sandbox.shell
        && seat
            .tools
            .as_ref()
            .is_some_and(|tools| tools.deny.iter().any(|name| name.as_str() == "Bash"))
    {
        findings.push(fail(
            object,
            "seat-sandbox",
            "shell = true passes the bash tool; remove Bash from tools.deny",
        ));
    }
    if sandbox.network == SeatSandboxNetwork::Host && !sandbox.shell {
        findings.push(fail(
            object,
            "seat-sandbox",
            "network = host requires shell = true",
        ));
    }
}

fn sandbox_path_rejection(entry: &str) -> Option<&'static str> {
    if super::super::seat::SANDBOX_PATH_ROLES.contains(&entry) {
        return None;
    }
    let path = std::path::Path::new(entry);
    if !path.is_absolute() || entry.contains('\0') {
        return Some("must be capsule, scratch, checkout, or an absolute path");
    }
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Some("must not contain ..");
    }
    let normalized = path.components().collect::<std::path::PathBuf>();
    if normalized == std::path::Path::new("/") {
        return Some("must not be /");
    }
    let mut parts = normalized.components();
    if matches!(parts.next(), Some(std::path::Component::RootDir))
        && matches!(parts.next(), Some(std::path::Component::Normal(name)) if name == "home")
    {
        return Some("must not be a path under /home");
    }
    None
}
