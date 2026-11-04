use super::*;

pub(super) fn validate_container(
    object: &RegistryObject,
    value: &ContainerToml,
    findings: &mut Vec<RegistryFinding>,
) {
    validate_common(
        object,
        &value.schema,
        value.kind,
        &value.description,
        findings,
    );
    require_nonempty(object, "purpose", &value.purpose, findings);
    require_nonempty(object, "base", &value.base, findings);
    if value.gpu_count > odin_kube_bounds::MAX_CONTAINER_GPU_COUNT {
        findings.push(fail(
            object,
            "container-gpu-count",
            format!(
                "gpu_count {} exceeds the declared bound {}",
                value.gpu_count,
                odin_kube_bounds::MAX_CONTAINER_GPU_COUNT
            ),
        ));
    }
    if let Some(deadline) = value.deadline_seconds {
        if !(odin_kube_bounds::MIN_CONTAINER_DEADLINE_SECONDS
            ..=odin_kube_bounds::MAX_CONTAINER_DEADLINE_SECONDS)
            .contains(&deadline)
        {
            findings.push(fail(
                object,
                "container-deadline-seconds",
                format!(
                    "deadline_seconds {deadline}s is outside the declared bound \
                     {}..={}s",
                    odin_kube_bounds::MIN_CONTAINER_DEADLINE_SECONDS,
                    odin_kube_bounds::MAX_CONTAINER_DEADLINE_SECONDS
                ),
            ));
        }
    }
    if value.identity_fields.is_empty() {
        findings.push(fail(
            object,
            "container-identity-fields",
            "identity_fields must contain at least one canonical field path",
        ));
    }
    for script in &value.scripts {
        require_nonempty(object, "scripts", script, findings);
    }
    for watchdog in &value.watchdogs {
        match watchdog {
            ContainerWatchdogToml::Script(script) => {
                require_nonempty(object, "watchdogs", script, findings);
            }
            ContainerWatchdogToml::Alert(alert) => {
                validate_container_alert(object, alert, findings);
            }
        }
    }
    for surface in &value.surface {
        match surface {
            ContainerSurfaceToml::Id(id) => {
                if !valid_id(id) {
                    findings.push(fail(
                        object,
                        "container-surface-id",
                        format!("surface {id:?} is not a stable ID"),
                    ));
                }
            }
            ContainerSurfaceToml::Definition(definition) => {
                validate_surface_definition(object, definition, findings);
            }
        }
    }
    let serialized = toml::Value::try_from(value).ok();
    for field in &value.identity_fields {
        match validate_declared_path(field) {
            Err(ContainerIdentityError::TunablePath { .. }) => {
                findings.push(fail(
                    object,
                    "container-identity-tunable",
                    format!("identity field {field:?} points into tunables"),
                ));
                continue;
            }
            Err(_) => {
                findings.push(fail(
                    object,
                    "container-identity-path",
                    format!("identity field {field:?} does not resolve in the container config"),
                ));
                continue;
            }
            Ok(()) => {}
        }
        if serialized
            .as_ref()
            .and_then(|root| lookup_toml_path(root, field))
            .is_none()
        {
            findings.push(fail(
                object,
                "container-identity-path",
                format!("identity field {field:?} does not resolve in the container config"),
            ));
        }
    }
    for name in value.tunables.keys() {
        if !valid_id(name) {
            findings.push(fail(
                object,
                "container-tunable-name",
                format!("tunable {name:?} is not a stable ID"),
            ));
        }
    }
    match &value.monitoring {
        ContainerMonitoringToml::Policy(policy) => {
            if policy.cadence_seconds.get() > 86_400 {
                findings.push(fail(
                    object,
                    "container-monitoring-range",
                    "monitoring.cadence_seconds must be in 1..=86400",
                ));
            }
        }
        ContainerMonitoringToml::None(marker) if marker == "none" => {}
        ContainerMonitoringToml::None(marker) => findings.push(fail(
            object,
            "container-monitoring-none",
            format!("monitoring string must be \"none\", found {marker:?}"),
        )),
    }
}

pub(super) fn validate_container_alert(
    object: &RegistryObject,
    alert: &ContainerAlertToml,
    findings: &mut Vec<RegistryFinding>,
) {
    if !valid_id(&alert.id) {
        findings.push(fail(
            object,
            "container-watchdog-id",
            format!("watchdog alert id {:?} is not a stable ID", alert.id),
        ));
    }
    if let Err(detail) = crate::schema::container::AlertCondition::parse(&alert.condition) {
        findings.push(fail(object, "container-watchdog-condition", detail));
    }
    if alert.consecutive_hits.get() > 1_000 {
        findings.push(fail(
            object,
            "container-watchdog-range",
            "watchdog consecutive_hits must be in 1..=1000",
        ));
    }
    if alert.cooldown_seconds > 86_400 {
        findings.push(fail(
            object,
            "container-watchdog-range",
            "watchdog cooldown_seconds must be in 0..=86400",
        ));
    }
}

fn validate_surface_definition(
    object: &RegistryObject,
    definition: &ContainerSurfaceDefinitionToml,
    findings: &mut Vec<RegistryFinding>,
) {
    if !valid_id(&definition.id) {
        findings.push(fail(
            object,
            "container-surface-id",
            format!("surface {:?} is not a stable ID", definition.id),
        ));
    }
    require_nonempty(object, "surface.source", &definition.source, findings);
    if !valid_media_type(&definition.media_type) {
        findings.push(fail(
            object,
            "container-surface-media-type",
            format!(
                "surface media_type {:?} is not a nonempty type/subtype",
                definition.media_type
            ),
        ));
    }
    if definition.refresh_seconds > 86_400 {
        findings.push(fail(
            object,
            "container-surface-range",
            "surface refresh_seconds must be in 0..=86400",
        ));
    }
    if let Some(renderer) = &definition.renderer {
        if renderer.is_empty() || !valid_id(renderer) {
            findings.push(fail(
                object,
                "container-surface-renderer",
                format!("surface renderer {renderer:?} is not a stable ID"),
            ));
        }
    }
}
