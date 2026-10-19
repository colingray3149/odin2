//! Composes and registers the declared image's pinned extension policy for its run.
//!
//! Trust chain, end to end:
//!
//! 1. The operator declares `kube.image_identity` — the image build's
//!    `identity.json`. The kube composition reads it once, validates it
//!    strictly, and pins the exact bytes as a content-addressed ledger
//!    artifact ([`crate::kube::WorkloadExtensionIdentity`]). The build
//!    output path is never consulted again.
//! 2. Every admission re-reads the identity through that digest-verified
//!    artifact and re-parses it strictly, then refuses unless its
//!    `manifest_digest` pins EXACTLY the profile's `@sha256:` reference
//!    digest — the identity of one image validates only that image.
//! 3. The policy document composes from the identity's `tools.extension`:
//!    `extension.path` is the declared in-image entrypoint,
//!    `extension.digest` is the identity's recorded BLAKE3 of the exact
//!    shipped bytes, and the document is revision-bound to the admitting
//!    snapshot revision and the controller config revision. Its canonical
//!    bytes register as another Pinned artifact, bind to the launching
//!    run through [`super::scoped_registration`], and ride the launch's
//!    staging projection, so the existing staging ConfigMap transport
//!    digest-verifies them again before upload.
//!
//! Preflight shares pure composition; execution adds registration and run binding.
//!
//! Unknown, missing, pruned, or mismatched material is a typed refusal —
//! never a path-based or name-based trust shortcut.

use std::sync::Mutex;

use odin_domain::extension_policy::{
    ExtensionArtifactPolicy, ExtensionPolicyV1, SidecarOperationalPolicy, EXTENSION_POLICY_SCHEMA,
    EXTENSION_POLICY_VERSION,
};
use odin_domain::huginn::KubeContentIdentity;
use odin_domain::{ArtifactId, Digest, RunId, WorkloadImageIdentity};
use odin_kube::artifacts::ArtifactStore;
use odin_kube::job::JobExtensionLaunch;
use odin_ledger::Ledger;

use odin_omp::host_tools::HostToolError;

use super::admission::{arguments_error, storage_error};

/// The admitted extension launch material: the durable launch binding plus
/// the staging input identity that carries the policy bytes into the pod.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ExtensionLaunchMaterial {
    pub launch: JobExtensionLaunch,
    /// The validated identity's in-image node executable, carried for the
    /// plan's dedicated browser container.
    pub browser_node: String,
    pub staging_input: KubeContentIdentity,
}

/// The purely composed extension policy material: the exact policy bytes,
/// canonical digest, content-addressed storage path, and the launch
/// fields derived from the pinned identity — no ledger writes, no
/// registrations, no identities invented. Shared verbatim by the pre-mint
/// preflight and the executing producer.
pub(super) struct ExtensionPolicyMaterial {
    pub verifier: String,
    pub trusted_extension: String,
    /// The validated identity's in-image node executable: the dedicated
    /// browser container's `--node` binding, resolved from the SAME parsed
    /// identity this composition verified — never re-read or re-parsed.
    pub browser_node: String,
    pub bytes: Vec<u8>,
    pub digest: String,
    pub storage_path: String,
}

/// The declared image profile binding one admission composes against: the
/// pinned image reference plus the declared in-image executables and module
/// root the image identity must provably carry.
pub(super) struct ProfileBinding<'a> {
    pub image_reference: &'a str,
    pub launcher: &'a str,
    pub supervisor: &'a str,
    /// The declared in-image Chromium executable.
    pub browser: &'a str,
    /// The declared in-image playwright module root.
    pub playwright: &'a str,
    /// The declared in-image Xvfb executable.
    pub xvfb: &'a str,
}

/// Composes the workload extension launch material for one admitted
/// profile, purely. The identity re-read is digest- and size-proven on
/// every composition; a pruned artifact row or drifted bytes refuse
/// before anything composes. Deterministic per (image identity, snapshot
/// revision, config revision).
pub(super) fn compose_extension_policy(
    tool: &'static str,
    store: &ArtifactStore,
    identity_artifact: &ArtifactId,
    config_revision: u64,
    profile: &ProfileBinding<'_>,
    snapshot_revision: u64,
) -> Result<ExtensionPolicyMaterial, HostToolError> {
    let identity_bytes = store
        .read_registered(identity_artifact)
        .map_err(|error| storage_error(tool, error.to_string()))?;
    let identity = WorkloadImageIdentity::parse(&identity_bytes).map_err(|error| {
        storage_error(
            tool,
            format!("the pinned image identity is no longer valid: {error}"),
        )
    })?;
    let image_reference = profile.image_reference;
    let launcher = profile.launcher;
    let supervisor = profile.supervisor;
    // The manifest digest is the only anchor: a name or tag match proves
    // nothing, so the profile's exact `@sha256:` pin must equal the
    // identity's manifest digest.
    if !identity.pins_reference(profile.image_reference) {
        return Err(arguments_error(
            tool,
            format!(
                "the declared image identity pins {}, which is not the profile image \
                 {image_reference:?}; a workload launch may use only the exact identity-pinned image",
                identity.manifest_digest
            ),
        ));
    }
    // Exact declared-executable equality: the profile's pinned in-image
    // launcher and browser supervisor must be EXACTLY the identity's
    // declared omp and odind entrypoints — the identity of this image
    // declares those bytes, so any other declaration is a mismatched
    // contract, refused before the policy composes.
    if profile.launcher != identity.tools.omp.in_image {
        return Err(arguments_error(
            tool,
            format!(
                "the workload launcher {launcher:?} is not the declared image launcher \
                 {:?}; the image identity pins its exact bytes",
                identity.tools.omp.in_image
            ),
        ));
    }
    if profile.supervisor != identity.tools.odind.in_image {
        return Err(arguments_error(
            tool,
            format!(
                "the workload browser supervisor {supervisor:?} is not the declared image \
                 supervisor {:?}; the image identity pins its exact bytes",
                identity.tools.odind.in_image
            ),
        ));
    }
    let browser = profile.browser;
    let playwright = profile.playwright;
    let xvfb = profile.xvfb;
    // Browser executable paths must match the pinned image identity.
    if profile.browser != identity.tools.chromium.in_image {
        return Err(arguments_error(
            tool,
            format!(
                "the workload browser {browser:?} is not the declared image browser {:?}; \
                 the image identity pins its exact bytes",
                identity.tools.chromium.in_image
            ),
        ));
    }
    if profile.playwright != identity.module_roots.playwright.in_image {
        return Err(arguments_error(
            tool,
            format!(
                "the workload playwright root {playwright:?} is not the declared image \
                 module root {:?}; the image identity pins its exact bytes",
                identity.module_roots.playwright.in_image
            ),
        ));
    }
    if profile.xvfb != identity.tools.xvfb.in_image {
        return Err(arguments_error(
            tool,
            format!(
                "the workload display Xvfb {xvfb:?} is not the declared image Xvfb {:?}; \
                 the image identity pins its exact bytes",
                identity.tools.xvfb.in_image
            ),
        ));
    }
    let extension = identity.extension();
    let policy = ExtensionPolicyV1 {
        schema: EXTENSION_POLICY_SCHEMA.to_owned(),
        version: EXTENSION_POLICY_VERSION,
        snapshot_revision,
        config_revision,
        extension: ExtensionArtifactPolicy {
            path: std::path::PathBuf::from(&extension.in_image),
            digest: extension.blake3.clone(),
        },
        sidecar: SidecarOperationalPolicy::compiled_default(),
    };
    policy.validate().map_err(|error| {
        arguments_error(
            tool,
            format!("resolved extension policy is invalid: {error}"),
        )
    })?;
    let bytes = serde_json::to_vec(&policy).map_err(|error| {
        storage_error(tool, format!("could not encode extension policy: {error}"))
    })?;
    let digest = ExtensionPolicyV1::digest_bytes(&bytes);
    let hex = digest
        .strip_prefix("blake3:")
        .ok_or_else(|| arguments_error(tool, "extension policy digest is not blake3-prefixed"))?
        .to_owned();
    let storage_path = format!("{}/{}", &hex[..2], hex);
    Ok(ExtensionPolicyMaterial {
        verifier: identity.tools.odind.in_image.clone(),
        browser_node: identity.tools.node.in_image.clone(),
        trusted_extension: extension.in_image.clone(),
        bytes,
        digest,
        storage_path,
    })
}

/// Composes and durably registers the workload extension launch material
/// for one admitted profile, bound to the exact declared run.
/// Deterministic per (image identity, snapshot revision, config
/// revision): identical re-admissions re-register the same
/// content-addressed bytes and re-attach the same run reference as
/// idempotent no-ops, so retries and recovery replay the identical
/// binding.
#[allow(clippy::too_many_arguments)]
pub(super) fn compose_extension_launch(
    tool: &'static str,
    store: &ArtifactStore,
    ledger: &Mutex<Ledger>,
    identity_artifact: &ArtifactId,
    config_revision: u64,
    profile: &ProfileBinding<'_>,
    snapshot_revision: u64,
    run_id: &RunId,
) -> Result<ExtensionLaunchMaterial, HostToolError> {
    let material = compose_extension_policy(
        tool,
        store,
        identity_artifact,
        config_revision,
        profile,
        snapshot_revision,
    )?;
    let registration = super::scoped_registration::register_scoped_bytes(
        tool,
        store,
        ledger,
        &material.bytes,
        &material.storage_path,
        run_id,
    )?;
    Ok(ExtensionLaunchMaterial {
        browser_node: material.browser_node,
        launch: JobExtensionLaunch {
            verifier: material.verifier,
            trusted_extension: material.trusted_extension,
            policy_artifact: registration.artifact_id.clone(),
            policy_digest: material.digest.clone(),
        },
        staging_input: KubeContentIdentity {
            artifact_id: registration.artifact_id,
            content_digest: Digest::parse(&material.digest)
                .map_err(|error| storage_error(tool, error.to_string()))?,
            byte_len: material.bytes.len() as u64,
        },
    })
}
