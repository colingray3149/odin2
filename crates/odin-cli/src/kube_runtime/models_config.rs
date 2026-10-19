//! Workload model-config admission: composes the per-session stock-OMP
//! models document from the explicitly selected target node's declared
//! gateway endpoint, registers it as bounded admission material bound to the
//! exact declared run, and stages it with the launch.
//!
//! The document carries NO secret bytes: the provider `apiKey` is the
//! fixed carrier env NAME the pod injects via SecretKeyRef from the
//! operator-declared Secret (stock OMP resolves config references from
//! `process.env` before literals); `baseUrl` is the declared node gateway
//! endpoint URI verbatim — the address the pods on that node actually
//! reach, loopback refused where the node declaration is parsed; the single
//! model entry is the admitted (lane, model) pair, because the bridge
//! selects the exact model via its journaled `set_model` RPC and never
//! falls back to catalog roles. The provider sends the session's spend tags
//! (`ODIN_SPEND_TAG`, staged by the in-pod session assembly) as
//! `x-litellm-tags`, exactly as the hosts' models.yml does, so a pod
//! session's requests are accounted per seat, workload, and session. The
//! canonical bytes register as a Pinned
//! ledger artifact, bind to the launching run through
//! [`super::scoped_registration`], and ride the launch's staging
//! projection, so the existing staging ConfigMap transport digest-verifies
//! them again before upload.
//!
//! Preflight shares pure composition; execution adds registration and run binding.

use std::sync::Mutex;

use serde_json::json;

use odin_domain::huginn::KubeContentIdentity;
use odin_domain::{Digest, RunId};
use odin_kube::artifacts::ArtifactStore;
use odin_kube::workload::WORKLOAD_CREDENTIAL_ENV;
use odin_ledger::Ledger;

use odin_omp::host_tools::HostToolError;

use super::admission::{arguments_error, storage_error};

/// The admitted model-config material: the staging input identity that
/// carries the document bytes into the pod, plus the digest the in-pod
/// verifier re-proves before any copy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ModelsConfigMaterial {
    pub staging_input: KubeContentIdentity,
    pub digest: String,
}

/// The purely composed models document: canonical bytes, blake3 digest,
/// and the content-addressed storage path — no ledger effects, no
/// identities, no registrations. Shared verbatim by the pre-mint
/// preflight and the executing producer.
pub(super) struct ModelsDocument {
    pub bytes: Vec<u8>,
    pub digest: String,
    pub storage_path: String,
}

/// Includes only the admitted provider/model, with the credential environment
/// name and declared gateway URL. Identical inputs produce identical bytes.
pub(super) fn compose_models_document(
    tool: &'static str,
    provider: &str,
    model: &str,
    endpoint: &odin_registry::schema::NodeGatewayEndpoint,
) -> Result<ModelsDocument, HostToolError> {
    if provider.trim().is_empty() || model.trim().is_empty() || endpoint.as_str().trim().is_empty()
    {
        return Err(arguments_error(
            tool,
            "the model config requires a nonempty provider, model, and endpoint",
        ));
    }
    let document = json!({
        "providers": {
            provider: {
                "api": "openai-completions",
                "apiKey": WORKLOAD_CREDENTIAL_ENV,
                "baseUrl": endpoint.as_str(),
                "headers": {odin_omp::SPEND_TAG_HEADER: odin_omp::SPEND_TAG_ENV},
                "models": [
                    {"id": model, "name": model}
                ]
            }
        }
    });
    let bytes = serde_json::to_vec(&document).map_err(|error| {
        storage_error(tool, format!("could not encode the model config: {error}"))
    })?;
    let digest = Digest::hash(&bytes).to_string();
    let hex = digest
        .strip_prefix("blake3:")
        .ok_or_else(|| arguments_error(tool, "model config digest is not blake3-prefixed"))?
        .to_owned();
    let storage_path = format!("{}/{}", &hex[..2], hex);
    Ok(ModelsDocument {
        bytes,
        digest,
        storage_path,
    })
}

/// Composes and durably registers the workload models document for one
/// admitted route, bound to the exact declared run. Deterministic per
/// (provider, model, endpoint): identical re-admissions re-register the
/// same content-addressed bytes and re-attach the same run reference as
/// idempotent no-ops, so retries and recovery replay the identical
/// document.
pub(super) fn compose_models_config_launch(
    tool: &'static str,
    store: &ArtifactStore,
    ledger: &Mutex<Ledger>,
    provider: &str,
    model: &str,
    endpoint: &odin_registry::schema::NodeGatewayEndpoint,
    run_id: &RunId,
) -> Result<ModelsConfigMaterial, HostToolError> {
    let document = compose_models_document(tool, provider, model, endpoint)?;
    let registration = super::scoped_registration::register_scoped_bytes(
        tool,
        store,
        ledger,
        &document.bytes,
        &document.storage_path,
        run_id,
    )?;
    Ok(ModelsConfigMaterial {
        staging_input: KubeContentIdentity {
            artifact_id: registration.artifact_id,
            content_digest: Digest::parse(&document.digest)
                .map_err(|error| storage_error(tool, error.to_string()))?,
            byte_len: document.bytes.len() as u64,
        },
        digest: document.digest,
    })
}

#[cfg(test)]
#[path = "tests/scoped_registration.rs"]
mod tests;
