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
    // Only agent pods have model lanes; relational validation checks provider availability.
    match (&value.seat.gateway_lane, agent) {
        (Some(lane), true) if !valid_id(lane) => findings.push(fail(
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
        if monitoring.watchdogs.is_empty() && monitoring.progress.is_none() {
            findings.push(fail(
                object,
                "workload-monitoring-watchdogs",
                "monitoring declares at least one watchdog or a progress counter",
            ));
        }
        if let Err(reason) = check_pod_recovery(monitoring) {
            findings.push(fail(object, "workload-monitoring-recovery", reason));
        }
        let mut ids = std::collections::BTreeSet::new();
        for watchdog in &monitoring.watchdogs {
            validate_container_alert(object, watchdog, findings);
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
