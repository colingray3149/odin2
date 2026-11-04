//! Published pod profiles and project-declared profile admission.
/// The caller's project sphere, when that project declares one.
///
/// `Ok(None)` is an absent sphere: launch stays on the seat-offer checks.
/// A disabled or non-project object is not a sphere. An enabled project
/// whose sphere is present returns that sphere, including an empty
/// `pod_profiles` set (which launches nothing).
pub(crate) fn project_sphere<'a>(
    snapshot: &'a odin_registry::Snapshot,
    project: &odin_domain::ProjectId,
) -> Result<Option<&'a odin_registry::schema::ProjectSphereToml>, String> {
    let Some(object) = snapshot.object(odin_registry::RegistryKind::Project, project.as_str())
    else {
        return Ok(None);
    };
    if !object.enabled() {
        return Err(format!(
            "project {project} is declared but disabled; its sphere cannot admit a pod profile"
        ));
    }
    match &object.config {
        odin_registry::schema::ObjectConfig::Project(project_toml) => {
            Ok(project_toml.sphere.as_ref())
        }
        _ => Ok(None),
    }
}

/// Whether `profile` may launch under this caller's project sphere.
///
/// An absent sphere does not narrow. A declared sphere admits only its
/// `pod_profiles`; an empty set admits none.
pub(crate) fn sphere_admits_profile(
    sphere: Option<&odin_registry::schema::ProjectSphereToml>,
    profile: &str,
) -> bool {
    match sphere {
        None => true,
        Some(sphere) => sphere.pod_profiles.iter().any(|allowed| allowed == profile),
    }
}

/// Lists the same published profiles whether or not the cluster runtime is configured.
pub(crate) fn launchable_profiles(
    snapshot: &odin_registry::Snapshot,
) -> Vec<odin_omp::host_tools::LaunchableProfile> {
    snapshot
        .objects
        .iter()
        .filter_map(|object| match &object.config {
            odin_registry::schema::ObjectConfig::Container(container)
                if container.enabled && container.image_executable_paths() =>
            {
                Some(odin_omp::host_tools::LaunchableProfile {
                    id: object.id.clone(),
                    description: container.description.clone(),
                    gpu_count: container.gpu_count,
                    seats: container
                        .seats_offered
                        .iter()
                        .map(ToString::to_string)
                        .collect(),
                })
            }
            _ => None,
        })
        .chain(
            // Script and agent profiles use the same create route.
            odin_registry::compose_workload_profiles(&snapshot.objects)
                .into_iter()
                .map(|profile| odin_omp::host_tools::LaunchableProfile {
                    description: format!(
                        "{} ({} pod{}{})",
                        profile.profile.description,
                        if profile.profile.runs_agent() {
                            "agent"
                        } else {
                            "script"
                        },
                        if profile.profile.mode == odin_registry::WorkloadMode::Service {
                            ", long-lived service"
                        } else {
                            ""
                        },
                        if profile.profile.placement.is_empty() {
                            String::new()
                        } else {
                            format!(", on {}", profile.profile.placement.join("+"))
                        },
                    ),
                    gpu_count: profile.profile.gpu_count,
                    seats: profile
                        .profile
                        .seats_offered
                        .iter()
                        .chain(std::iter::once(&profile.profile.seat.seat))
                        .map(ToString::to_string)
                        .collect::<std::collections::BTreeSet<_>>()
                        .into_iter()
                        .collect(),
                    id: profile.id,
                }),
        )
        .collect()
}
