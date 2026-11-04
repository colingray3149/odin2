//! Pinned kube launch bindings and workload image deployment facts.

use odin_domain::ArtifactId;

/// Real composition context for kube Job label bindings, resolved once from
/// the daemon's configured delegation route and the pinned published
/// snapshot. `launch_binding` is `None` whenever no delegation route is
/// configured — the coordinator must then refuse kube create with a typed
/// unavailable, never fabricate a binding.
#[derive(Clone, Debug)]
pub struct KubeLaunchBinding {
    pub model: String,
    pub budget_policy_digest: odin_domain::Digest,
}

/// The pinned workload image identity: the typed
/// `odin.workload-image-identity.v1` document bound to the content-addressed
/// ledger artifact holding its exact bytes. Composed once from the
/// operator-declared `kube.image_identity` path; every admission re-reads
/// the identity through the artifact, so the build output path itself is
/// consumed exactly once at startup.
#[derive(Clone, Debug)]
pub struct WorkloadExtensionIdentity {
    pub artifact: ArtifactId,
    /// The pinned image's deployment facts, for completing workload drafts.
    pub deployment: WorkloadDeploymentFacts,
}

/// The pinned workload image's deployment facts a workload draft is
/// completed from: its reference and in-image paths. The model states what
/// a pod is for; these it cannot know, so it never has to guess them.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WorkloadDeploymentFacts {
    pub image_reference: String,
    pub launcher: String,
    pub browser: String,
    pub supervisor: String,
    pub playwright: String,
    pub xvfb: String,
    pub state_path: Option<String>,
    pub export_pod_path: Option<String>,
    /// The node's declared host export root (`[kube] export_root`).
    pub export_host_folder: Option<String>,
    /// The declared default agent-pod gateway lane (`[kube] agent_lane`).
    pub agent_lane: Option<String>,
}

impl WorkloadDeploymentFacts {
    pub fn of(
        identity: &odin_domain::WorkloadImageIdentity,
        export_root: Option<&std::path::Path>,
        agent_lane: Option<&str>,
    ) -> Self {
        let mount = |path: &str| {
            identity
                .mount_points
                .iter()
                .find(|mount| mount.as_str() == path)
                .cloned()
        };
        Self {
            image_reference: identity.reference.clone(),
            launcher: identity.tools.omp.in_image.clone(),
            browser: identity.tools.chromium.in_image.clone(),
            supervisor: identity.tools.odind.in_image.clone(),
            playwright: identity.module_roots.playwright.in_image.clone(),
            xvfb: identity.tools.xvfb.in_image.clone(),
            state_path: mount("/state"),
            export_pod_path: mount("/export"),
            export_host_folder: export_root.map(|root| root.display().to_string()),
            agent_lane: agent_lane.map(str::to_owned),
        }
    }
}
