use super::container_rules::validate_container_alert;
use super::*;
use crate::schema::valid_allow_host;

pub(super) fn validate_workload(
    object: &RegistryObject,
    value: &WorkloadProfileToml,
    findings: &mut Vec<RegistryFinding>,
) {
    validate_common(
        object,
        &value.schema,
        value.kind,
        &value.description,
        findings,
    );
    if let Some(report) = &value.report {
        let root = report.downloads_root.as_deref();
        if (report.pdf && root.is_none()) || root.is_some_and(|root| !valid_id(root)) {
            findings.push(fail(
                object,
                "workload-report-downloads-root",
                "report.downloads_root must name a files.save root when report.pdf is true",
            ));
        }
    }
    if value
        .export
        .deliver_root
        .as_deref()
        .is_some_and(|root| !valid_id(root))
    {
        findings.push(fail(
            object,
            "workload-export-deliver-root",
            "export.deliver_root must name a files.save root",
        ));
    }
    if let Some(simulation) = &value.simulation {
        if simulation
            .max_frame_bytes
            .is_some_and(|bytes| bytes == 0 || bytes > crate::schema::MAX_FRAME_BYTES)
        {
            findings.push(fail(
                object,
                "workload-simulation-frame-bytes",
                "simulation.max_frame_bytes must be in 1..=8388608",
            ));
        }
        if !simulation.render_command.is_empty()
            && (simulation.renderers.is_empty()
                || !simulation.render_command[0].starts_with('/')
                || simulation.render_command.iter().any(String::is_empty))
        {
            findings.push(fail(
                object,
                "workload-simulation-render-command",
                "simulation.render_command is an absolute in-image argv and needs declared renderers",
            ));
        }
        if [
            simulation.keep_frames,
            simulation.stale_seconds,
            simulation.render_timeout_seconds,
            simulation.retire_after_hours,
        ]
        .contains(&Some(0))
        {
            findings.push(fail(
                object,
                "workload-simulation-zero",
                "simulation.keep_frames, stale_seconds, render_timeout_seconds and \
                 retire_after_hours must be positive when declared",
            ));
        }
        if simulation.plot.iter().any(|key| key.trim().is_empty()) {
            findings.push(fail(
                object,
                "workload-simulation-plot",
                "simulation.plot names telemetry keys, none empty",
            ));
        }
    }
    // Require a digest pin; platform images resolve to their deployed digest at launch.
    if !value.image.is_platform() && !valid_digest_pinned_oci_reference(&value.image.reference) {
        findings.push(fail(
            object,
            "workload-image-reference",
            "image.reference must be \"platform\" or a fully qualified OCI reference pinned \
             by an @sha256 manifest digest",
        ));
    }
    let agent = value.runs_agent();
    if let Some(reviewer) = value.monitoring.as_ref().and_then(|m| m.reviewer.as_ref()) {
        if !agent
            || odin_domain::huginn::ProviderName::new(&reviewer.provider).is_err()
            || odin_domain::huginn::ModelName::new(&reviewer.model).is_err()
        {
            findings.push(fail(
                object,
                "workload-reviewer",
                "monitoring.reviewer requires an agent workload and valid provider/model names",
            ));
        }
    }
    // Relational validation checks that agent harnesses are enabled and permit pods.
    match (&value.script, agent) {
        (Some(script), false) => {
            if script.command.is_empty() || script.command.iter().any(|arg| arg.is_empty()) {
                findings.push(fail(
                    object,
                    "workload-script-command",
                    "script.command must be a nonempty argv of nonempty strings",
                ));
            }
        }
        (None, false) => findings.push(fail(
            object,
            "workload-script-command",
            "a script pod declares script.command",
        )),
        (Some(_), true) => findings.push(fail(
            object,
            "workload-script-command",
            "an agent pod runs its harness; script.command belongs to harness = \"script\"",
        )),
        (None, true) => {}
    }
    // Agent pods require a model lane; a script pod may name one for its gateway env.
    // Relational validation checks provider availability for either.
    match (&value.seat.gateway_lane, agent) {
        (Some(lane), _) if !valid_id(lane) => findings.push(fail(
            object,
            "workload-gateway-lane",
            "seat.gateway_lane must be a stable id naming an existing provider route lane",
        )),
        (None, true) => findings.push(fail(
            object,
            "workload-gateway-lane",
            "an agent pod declares seat.gateway_lane, its model route",
        )),
        _ => {}
    }
    if agent {
        match (&value.runtime, &value.display) {
            (Some(runtime), Some(display)) => {
                for (field, path) in [
                    ("runtime.launcher", &runtime.launcher),
                    ("runtime.browser", &runtime.browser),
                    ("runtime.supervisor", &runtime.supervisor),
                    ("display.xvfb", &display.xvfb),
                    ("runtime.playwright", &runtime.playwright),
                ] {
                    if !valid_pod_path(path) {
                        findings.push(fail(
                            object,
                            "workload-runtime-path",
                            format!("{field} must be an absolute in-image path without escapes"),
                        ));
                    }
                }
                if !valid_screen(&display.screen) {
                    findings.push(fail(
                        object,
                        "workload-display-screen",
                        "display.screen must be <width>x<height>x<depth>",
                    ));
                }
            }
            _ => findings.push(fail(
                object,
                "workload-runtime-path",
                "an agent pod declares its in-image runtime and display",
            )),
        }
    }
    if let Some(resources) = &value.resources {
        if resources.cpu == 0 {
            findings.push(fail(
                object,
                "workload-resources-cpu",
                "resources.cpu must be at least 1",
            ));
        }
        if let Err(reason) = resources.memory_bytes() {
            findings.push(fail(
                object,
                "workload-resources-memory",
                format!("resources.memory is not a valid quantity: {reason}"),
            ));
        }
        match (resources.shm_bytes(), resources.memory_bytes()) {
            (Err(reason), _) => findings.push(fail(
                object,
                "workload-resources-shm",
                format!("resources.shm is not a valid quantity: {reason}"),
            )),
            (Ok(Some(shm)), Ok(memory)) if shm >= memory => findings.push(fail(
                object,
                "workload-resources-shm",
                "resources.shm counts inside resources.memory and must be below it",
            )),
            _ => {}
        }
    }
    validate_stop_and_data(object, value, findings);
    if let Some(control) = &value.control {
        if control.max_bytes == 0 || control.max_bytes > CONTROL_MAP_LIMIT_BYTES / 2 {
            findings.push(fail(
                object,
                "workload-control",
                format!(
                    "control.max_bytes must be 1..={}, half the ConfigMap limit",
                    CONTROL_MAP_LIMIT_BYTES / 2
                ),
            ));
        }
        if let Err(reason) = control.validator() {
            findings.push(fail(object, "workload-control", reason));
        }
    }
    if let Some(limits) = &value.limits {
        if limits
            .checkpoint_percent
            .is_some_and(|percent| !CHECKPOINT_PERCENT_RANGE.contains(&percent))
        {
            findings.push(fail(
                object,
                "workload-limits-checkpoint-percent",
                format!(
                    "limits.checkpoint_percent must be in {}..={}",
                    CHECKPOINT_PERCENT_RANGE.start(),
                    CHECKPOINT_PERCENT_RANGE.end()
                ),
            ));
        }
        if limits
            .max_rollovers
            .is_some_and(|rollovers| rollovers > MAX_ROLLOVERS_LIMIT)
        {
            findings.push(fail(
                object,
                "workload-limits-max-rollovers",
                format!("limits.max_rollovers must be at most {MAX_ROLLOVERS_LIMIT}"),
            ));
        }
        if limits.output_reserve_tokens == Some(0) || limits.tool_result_bytes == Some(0) {
            findings.push(fail(
                object,
                "workload-limits-positive",
                "limits.output_reserve_tokens and limits.tool_result_bytes must be at least 1",
            ));
        }
    }
    if value.gpu_count > odin_kube_bounds::MAX_CONTAINER_GPU_COUNT {
        findings.push(fail(
            object,
            "workload-gpu-count",
            format!(
                "gpu_count {} exceeds the declared bound {}",
                value.gpu_count,
                odin_kube_bounds::MAX_CONTAINER_GPU_COUNT
            ),
        ));
    }
    if value.gpu_count > 0
        && !value
            .placement
            .iter()
            .any(|capability| capability == "cuda")
    {
        findings.push(fail(
            object,
            "workload-gpu-placement",
            "a profile with gpu_count must place on cuda nodes: add \"cuda\" to placement",
        ));
    }
    if let Some(gpu) = &value.gpu {
        if value.gpu_count == 0 {
            findings.push(fail(
                object,
                "workload-gpu-memory",
                "[gpu] memory needs gpu_count of at least 1",
            ));
        }
        if gpu.min_vram_gib == Some(0) || gpu.vram_gib == Some(0) {
            findings.push(fail(
                object,
                "workload-gpu-memory",
                "gpu.min_vram_gib and gpu.vram_gib must be at least 1 when declared",
            ));
        }
    }
    if let Some(offload) = &value.offload {
        // The target sees everything a run carries, and reaches none of the owner's services.
        if value.runs_agent()
            || value.seat.gateway_lane.is_some()
            || !value.network.transport.is_direct()
            || !value.tools.is_empty()
            || value.mode != crate::schema::WorkloadMode::Job
        {
            findings.push(fail(
                object,
                "workload-offload-scope",
                "an offload profile is a finite script run with no seat.gateway_lane, no \
                 vpn-required transport and no tools",
            ));
        }
        if offload.targets.is_empty() || offload.targets.iter().any(|target| !valid_id(target)) {
            findings.push(fail(
                object,
                "workload-offload-targets",
                "offload.targets must name at least one compute target id",
            ));
        }
        require_unique_list(object, "offload.targets", &offload.targets, findings);
    }
    require_unique_list(object, "tolerate", &value.tolerate, findings);
    if value
        .tolerate
        .iter()
        .any(|taint| taint != crate::schema::EXTERNAL_TOLERATION)
    {
        findings.push(fail(
            object,
            "workload-tolerate",
            "tolerate may name only \"external\"",
        ));
    }
    if value.tolerates_external() {
        // The provider sees everything inside a pod on its box: nothing that unlocks the owner's
        // services may be scheduled there.
        if value.runs_agent()
            || value.seat.gateway_lane.is_some()
            || !value.network.transport.is_direct()
            || !value.tools.is_empty()
        {
            findings.push(fail(
                object,
                "workload-external-scope",
                "a profile tolerating external nodes must be a script pod with no \
                 seat.gateway_lane, no vpn-required transport and no tools",
            ));
        }
        let image = value.image.reference.as_str();
        if image == crate::schema::PLATFORM_IMAGE || image.starts_with("localhost/") {
            findings.push(fail(
                object,
                "workload-external-image",
                "a profile tolerating external nodes needs an image an external box can pull: \
                 a registry reference, not platform or localhost/",
            ));
        }
    }
    require_unique_list(object, "placement", &value.placement, findings);
    for capability in &value.placement {
        if !valid_registry_hostname_label(capability) {
            findings.push(fail(
                object,
                "workload-placement",
                format!(
                    "placement entry {capability:?} must be a node capability name \
                     (lowercase letters, digits, inner hyphens; at most 63 bytes)"
                ),
            ));
        }
    }
    if let Some(monitoring) = &value.monitoring {
        if !(5..=3_600).contains(&monitoring.cadence_seconds.get()) {
            findings.push(fail(
                object,
                "workload-monitoring-cadence",
                "monitoring.cadence_seconds must be 5..=3600",
            ));
        }
        if monitoring.watchdogs.is_empty()
            && monitoring.progress.is_none()
            && monitoring.reviewer.is_none()
        {
            findings.push(fail(
                object,
                "workload-monitoring-watchdogs",
                "monitoring declares a watchdog, progress counter, or independent reviewer",
            ));
        }
        if let Err(reason) = check_pod_recovery(monitoring) {
            findings.push(fail(object, "workload-monitoring-recovery", reason));
        }
        let mut ids = std::collections::BTreeSet::new();
        for watchdog in &monitoring.watchdogs {
            validate_container_alert(object, watchdog, findings);
            if let Some(patch) = &watchdog.patch {
                let verdict = value
                    .control
                    .as_ref()
                    .ok_or_else(|| "the profile declares no [control] to steer".to_owned())
                    .and_then(|control| control.admit(&patch.0));
                if let Err(reason) = verdict {
                    findings.push(fail(
                        object,
                        "workload-monitoring-steer",
                        format!("watchdog {:?} patch: {reason}", watchdog.id),
                    ));
                }
            }
            if !ids.insert(watchdog.id.as_str()) {
                findings.push(fail(
                    object,
                    "workload-monitoring-watchdogs",
                    format!("duplicate watchdog id {:?}", watchdog.id),
                ));
            }
        }
    }
    require_unique_list(
        object,
        "network.allow_hosts",
        &value.network.allow_hosts,
        findings,
    );
    for host in &value.network.allow_hosts {
        if !valid_allow_host(host) {
            findings.push(fail(
                object,
                "workload-network-host",
                format!("network.allow_hosts entry {host:?} is not a bare hostname"),
            ));
        }
    }
    if value.network.open && !value.network.allow_hosts.is_empty() {
        findings.push(fail(
            object,
            "workload-network-open",
            "network.open admits public destinations and cannot also pin allow_hosts",
        ));
    }
    if !valid_pod_path(&value.state.path) {
        findings.push(fail(
            object,
            "workload-state-path",
            "state.path must be an absolute in-pod path without escapes",
        ));
    }
    if let Err(quantity_error) = storage_quantity_bytes(&value.state.storage) {
        findings.push(fail(object, "workload-state-storage", quantity_error));
    }
    if !valid_pod_path(&value.export.pod_path) {
        findings.push(fail(
            object,
            "workload-export-pod-path",
            "export.pod_path must be an absolute in-pod path without escapes",
        ));
    }
    if !valid_pod_path(&value.export.host_folder) {
        findings.push(fail(
            object,
            "workload-export-host-folder",
            "export.host_folder must be an absolute host folder without escapes",
        ));
    }
    if paths_nest_or_collide(&value.state.path, &value.export.pod_path) {
        findings.push(fail(
            object,
            "workload-volume-collision",
            "state.path and export.pod_path must name distinct in-pod mount points; \
             neither may equal or nest inside the other",
        ));
    }
    // Limit briefs because they are injected on every turn.
    if value.brief.text.trim().is_empty() {
        findings.push(fail(
            object,
            "workload-brief-empty",
            "brief.text must be nonempty",
        ));
    }
    if value.brief.text.len() > WORKLOAD_BRIEF_MAX_BYTES {
        findings.push(fail(
            object,
            "workload-brief-bound",
            format!("brief.text exceeds the declared bound {WORKLOAD_BRIEF_MAX_BYTES} bytes"),
        ));
    }
    // Relations check project and seat memory scope after validating namespace syntax.
    match (&value.memory, agent) {
        (Some(memory), _) if !valid_memory_namespace(&memory.namespace) => findings.push(fail(
            object,
            "workload-memory-namespace",
            "memory.namespace must be a nonempty atlas.<subtree> or memory.<name> namespace",
        )),
        (None, true) => findings.push(fail(
            object,
            "workload-memory-namespace",
            "an agent pod declares memory.namespace",
        )),
        _ => {}
    }
    // Match runtime job deadlines; services declare no lifetime and run until stopped.
    match (&value.lifetime, value.mode) {
        (Some(lifetime), crate::schema::workload::WorkloadMode::Job) => {
            let deadline = lifetime.deadline_seconds;
            if !(MIN_WORKLOAD_DEADLINE_SECONDS..=MAX_WORKLOAD_DEADLINE_SECONDS).contains(&deadline)
            {
                findings.push(fail(
                    object,
                    "workload-lifetime-deadline",
                    format!(
                        "lifetime.deadline_seconds {deadline}s is outside the declared bound \
                         {MIN_WORKLOAD_DEADLINE_SECONDS}..={MAX_WORKLOAD_DEADLINE_SECONDS}s"
                    ),
                ));
            }
        }
        (None, crate::schema::workload::WorkloadMode::Job) => findings.push(fail(
            object,
            "workload-lifetime-deadline",
            "a job declares lifetime.deadline_seconds",
        )),
        (Some(_), crate::schema::workload::WorkloadMode::Service) => findings.push(fail(
            object,
            "workload-lifetime-deadline",
            "a service runs until stopped and declares no lifetime",
        )),
        (None, crate::schema::workload::WorkloadMode::Service) => {}
    }
}

fn validate_stop_and_data(
    object: &RegistryObject,
    value: &WorkloadProfileToml,
    findings: &mut Vec<RegistryFinding>,
) {
    if let Some(grace) = value.stop_grace_seconds {
        let deadline = value
            .lifetime
            .as_ref()
            .map(|lifetime| lifetime.deadline_seconds);
        if grace == 0 || deadline.is_some_and(|deadline| grace >= deadline) {
            findings.push(fail(
                object,
                "workload-stop-grace",
                "stop_grace_seconds must be at least 1 and below lifetime.deadline_seconds",
            ));
        }
    }
    let mut taken: Vec<&str> = vec![value.state.path.as_str(), value.export.pod_path.as_str()];
    taken.extend(RESERVED_POD_PATHS);
    let mut names = std::collections::BTreeSet::new();
    for data in &value.data {
        if !valid_id(&data.name) || !names.insert(data.name.as_str()) {
            findings.push(fail(
                object,
                "workload-data",
                format!("data name {:?} must be a unique stable id", data.name),
            ));
        }
        if !valid_pod_path(&data.host_path)
            || FORBIDDEN_DATA_HOST_ROOTS
                .iter()
                .any(|root| std::path::Path::new(&data.host_path).starts_with(root))
        {
            findings.push(fail(
                object,
                "workload-data-host-path",
                format!(
                    "data {:?} host_path {:?} must be a normalized absolute path outside {}",
                    data.name,
                    data.host_path,
                    FORBIDDEN_DATA_HOST_ROOTS.join(", ")
                ),
            ));
        }
        if !valid_pod_path(&data.pod_path) {
            findings.push(fail(
                object,
                "workload-data-pod-path",
                format!(
                    "data {:?} pod_path {:?} must be a normalized absolute path",
                    data.name, data.pod_path
                ),
            ));
        } else if let Some(other) = taken
            .iter()
            .find(|other| paths_nest_or_collide(&data.pod_path, other))
        {
            findings.push(fail(
                object,
                "workload-data-pod-path",
                format!(
                    "data {:?} pod_path {:?} collides or nests with {other:?}",
                    data.name, data.pod_path
                ),
            ));
        }
        taken.push(&data.pod_path);
    }
}
