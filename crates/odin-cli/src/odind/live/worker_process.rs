//! Supervised worker-process composition: the manifest-bound OMP process
//! spec with its pinned extension overlay, the pinned-identity retention
//! check, and the zellij CLI factory.

use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::time::Duration as StdDuration;

use super::super::composition::child_environment;
use odin_domain::extension_policy::{
    ExtensionPolicyBinding, EXTENSION_POLICY_DIGEST_ENV, EXTENSION_POLICY_PATH_ENV,
};
use odin_huginn::OdindConfig;
use odin_omp::live::zellij::ZellijCliFactory;
use odin_omp::process::OmpWorkerLaunch;

pub(super) async fn compose(
    config: &OdindConfig,
    extension: PathBuf,
    extension_policy: &ExtensionPolicyBinding,
    omp_worker: &OmpWorkerLaunch,
    zellij_worker: OmpWorkerLaunch,
    huginn_root: &Path,
) -> Result<
    (
        odin_omp::process::OmpProcessSpec,
        odin_omp::live::zellij::ZellijCliFactory,
    ),
    String,
> {
    let mut explicit_env = child_environment();
    explicit_env.push((
        EXTENSION_POLICY_PATH_ENV.to_owned(),
        extension_policy
            .path
            .to_str()
            .ok_or_else(|| "extension policy path is not valid UTF-8".to_owned())?
            .to_owned(),
    ));
    explicit_env.push((
        EXTENSION_POLICY_DIGEST_ENV.to_owned(),
        extension_policy.digest.clone(),
    ));
    let process = odin_omp::process::OmpProcessSpec {
        executable: config.executables.omp_bin.clone(),
        cwd: config.paths.state_root.clone(),
        // The omp executable is the manifest-bound wrapper; Config's
        // immutable Nix settings overlay (governed defaults: MCP project
        // config off, native eval backends off, shell pin, full
        // disabledProviders list) is always appended LAST inside that
        // wrapper — the single security authority for startup defaults.
        // This spec carries only the pinned extension, the governed tool
        // exposure, and the no-* flags; the wrapper supplies --config itself,
        // so no parallel host-written overlay exists here.
        explicit_args: odin_omp::process::governed_harness_args(&extension),
        explicit_env,
        expected_source_revision: config.executables.omp_revision.clone(),
        startup_timeout: StdDuration::from_secs(120),
        drain_timeout: StdDuration::from_secs(10),
        kill_timeout: StdDuration::from_secs(5),
    };
    let identity = process
        .establish_identity(omp_worker)
        .await
        .map_err(|error| format!("could not validate pinned OMP executable: {error}"))?;
    if identity.source_revision() != odin_omp::probe::PINNED_OMP_SOURCE_REVISION {
        return Err("validated OMP executable did not retain the configured pin".to_owned());
    }
    let zellij = ZellijCliFactory::open(
        config.executables.zellij_bin.clone(),
        config.executables.zellij_session.clone(),
        huginn_root.join("terminal"),
        StdDuration::from_secs(15),
        NonZeroU16::new(80).expect("80 is non-zero"),
        NonZeroU16::new(24).expect("24 is non-zero"),
        zellij_worker,
    )
    .map_err(|error| error.to_string())?;
    let zellij = if config.executables.attach_command.is_empty() {
        zellij
    } else {
        zellij
            .with_attach_command(config.executables.attach_command.iter().cloned())
            .map_err(|error| error.to_string())?
    };
    Ok((process, zellij))
}
