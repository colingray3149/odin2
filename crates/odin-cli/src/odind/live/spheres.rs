//! Declared project spheres and device actions owned by session workers.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use odin_cli::live_authority::{Capture, OwnedProgram, OwnedStep, Retention, SessionAuthorityPool};
use odin_huginn::RuntimeManifest;
use odin_omp::host_tools::device::DeviceRunBinding;
use odin_registry::SnapshotHandle;

pub(super) fn device_binding(
    registry: &Arc<SnapshotHandle>,
    state_root: &Path,
    manifest: &RuntimeManifest,
    pool: Arc<SessionAuthorityPool>,
) -> DeviceRunBinding {
    DeviceRunBinding {
        registry: Arc::clone(registry),
        state_root: state_root.to_path_buf(),
        run: Arc::new(move |effect, scope, capsule, args| {
            let timeout = Duration::from_secs(u64::from(effect.contract().timeout_seconds.get()));
            pool.run_owned_step(
                effect,
                scope,
                OwnedStep {
                    program: OwnedProgram::Bwrap,
                    args,
                    environment: Vec::new(),
                    current_dir: capsule,
                    capture: Capture {
                        stdout: Retention::Tail,
                        stderr: Retention::Tail,
                    },
                },
                Instant::now() + timeout,
            )
            .map(|captured| captured.output)
        }),
        executables: manifest
            .executables
            .iter()
            .map(|(key, binding)| (key.clone(), binding.path.clone()))
            .collect(),
        tool_path: Vec::new(),
    }
}
/// Project spheres from enabled projects. A project that declares none is
/// absent, and its lanes keep the seat sandbox.
pub(super) fn declared_project_spheres(
    registry: &[odin_registry::RegistryObject],
) -> Result<
    std::collections::BTreeMap<odin_domain::ProjectId, odin_omp::process::SphereProjection>,
    String,
> {
    registry
        .iter()
        .filter_map(|object| {
            let odin_registry::ObjectConfig::Project(project) = &object.config else {
                return None;
            };
            let sphere = project
                .enabled
                .then_some(project.sphere.as_ref())
                .flatten()?;
            Some(
                odin_domain::ProjectId::new(&object.id)
                    .map_err(|error| format!("project {}: {error}", object.id))
                    .and_then(|id| {
                        odin_omp::process::SphereProjection::from_sphere(sphere)
                            .map(|projection| (id, projection))
                            .map_err(|error| format!("project {}: {error}", object.id))
                    }),
            )
        })
        .collect()
}
