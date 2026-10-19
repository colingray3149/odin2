//! Explicit kubeconfig loading without ambient credentials or credential-helper processes.

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::{ConfigMap, PersistentVolume, PersistentVolumeClaim, Pod, Secret};
use k8s_openapi::api::networking::v1::NetworkPolicy;

use crate::config::KubeConfig;

#[derive(Debug, thiserror::Error)]
pub enum KubeError {
    #[error("kubernetes unavailable: {reason}")]
    Unavailable { reason: String },
    #[error("kubernetes conflict: {reason}")]
    Conflict { reason: String },
    #[error("kubernetes request rejected: {reason}")]
    Rejected { reason: String },
    #[error("kubernetes storage failure: {reason}")]
    Storage { reason: String },
    #[error(transparent)]
    Api(#[from] kube::Error),
}

impl KubeError {
    pub fn is_unavailable(&self) -> bool {
        matches!(self, Self::Unavailable { .. })
    }

    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::Unavailable {
            reason: reason.into(),
        }
    }

    pub fn rejected(reason: impl Into<String>) -> Self {
        Self::Rejected {
            reason: reason.into(),
        }
    }
}

#[derive(Clone)]
pub struct KubeClient {
    pub client: kube::Client,
    pub config: KubeConfig,
}

impl KubeClient {
    pub async fn connect(config: KubeConfig) -> Result<Self, KubeError> {
        validate_config(&config)?;
        let kubeconfig = read_config(&config)?;
        if kubeconfig.auth_infos.iter().any(|named| {
            named
                .auth_info
                .as_ref()
                .is_some_and(|auth| auth.exec.is_some() || auth.auth_provider.is_some())
        }) {
            return Err(KubeError::rejected(
                "credential-helper plugins are not permitted; k3s must use static credentials",
            ));
        }
        // The declared file selects its own current-context. `cluster` is Odin's
        // logical identity (e.g. laptop), not k3s' kubeconfig entry (usually default).
        let mut api_config = kube::Config::from_custom_kubeconfig(
            kubeconfig,
            &kube::config::KubeConfigOptions::default(),
        )
        .await
        .map_err(|error| {
            KubeError::rejected(format!(
                "declared kubeconfig does not contain a usable current-context or credentials: {error}"
            ))
        })?;
        api_config.connect_timeout = Some(config.request_timeout);
        let client = kube::Client::try_from(api_config).map_err(|error| {
            KubeError::rejected(format!(
                "declared Kubernetes TLS or authentication configuration is invalid: {error}"
            ))
        })?;
        match tokio::time::timeout(config.request_timeout, client.apiserver_version()).await {
            Ok(Ok(_)) => Ok(Self { client, config }),
            Ok(Err(error)) => Err(KubeError::unavailable(format!(
                "declared Kubernetes API server did not answer the authenticated version probe: {error}"
            ))),
            Err(_) => Err(KubeError::unavailable(
                "declared Kubernetes API server version probe timed out",
            )),
        }
    }

    pub fn jobs(&self) -> kube::Api<Job> {
        kube::Api::namespaced(self.client.clone(), &self.config.namespace)
    }

    pub fn pods(&self) -> kube::Api<Pod> {
        kube::Api::namespaced(self.client.clone(), &self.config.namespace)
    }

    pub fn secrets(&self) -> kube::Api<Secret> {
        kube::Api::namespaced(self.client.clone(), &self.config.namespace)
    }

    pub fn persistent_volume_claims(&self) -> kube::Api<PersistentVolumeClaim> {
        kube::Api::namespaced(self.client.clone(), &self.config.namespace)
    }

    /// Cluster-scoped volumes used to inspect state placement.
    pub fn persistent_volumes(&self) -> kube::Api<PersistentVolume> {
        kube::Api::all(self.client.clone())
    }

    pub fn network_policies(&self) -> kube::Api<NetworkPolicy> {
        kube::Api::namespaced(self.client.clone(), &self.config.namespace)
    }

    /// Namespaced staging and checkpoint maps, listed by the run-id label.
    pub fn config_maps(&self) -> kube::Api<ConfigMap> {
        kube::Api::namespaced(self.client.clone(), &self.config.namespace)
    }

    pub fn request_timeout(&self) -> Duration {
        self.config.request_timeout
    }

    pub fn teardown_timeout(&self) -> Duration {
        self.config.teardown_timeout
    }
}

fn validate_config(config: &KubeConfig) -> Result<(), KubeError> {
    if !config.kubeconfig.is_absolute() || config.cluster.trim().is_empty() {
        return Err(KubeError::rejected("Kubernetes configuration requires an absolute kubeconfig path and a logical cluster identity"));
    }
    let namespace = config.namespace.as_bytes();
    if namespace.is_empty()
        || namespace.len() > 63
        || !namespace[0].is_ascii_alphanumeric()
        || !namespace[namespace.len() - 1].is_ascii_alphanumeric()
        || namespace
            .iter()
            .any(|byte| !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && *byte != b'-')
    {
        return Err(KubeError::rejected(
            "Kubernetes namespace must be a DNS label",
        ));
    }
    for bound in [config.request_timeout, config.teardown_timeout] {
        if bound.is_zero() || bound > Duration::from_secs(3600) {
            return Err(KubeError::rejected(
                "Kubernetes timeouts must be nonzero and at most one hour",
            ));
        }
    }
    Ok(())
}

fn read_config(config: &KubeConfig) -> Result<kube::config::Kubeconfig, KubeError> {
    const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
    let unavailable = |error: std::io::Error| {
        let reason = match error.kind() {
            std::io::ErrorKind::NotFound => "does not exist",
            std::io::ErrorKind::PermissionDenied => {
                "is not readable; activate k3s group membership"
            }
            _ => "cannot be read",
        };
        KubeError::unavailable(format!(
            "declared kubeconfig {} {reason}",
            config.kubeconfig.display()
        ))
    };
    let mut file = File::open(&config.kubeconfig).map_err(unavailable)?;
    let metadata = file.metadata().map_err(unavailable)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o027 != 0 {
        return Err(KubeError::rejected("kubeconfig must be a regular file, without group write or access by others; 0600 and 0640 are supported"));
    }
    if metadata.len() > MAX_CONFIG_BYTES {
        return Err(KubeError::rejected(
            "kubeconfig exceeds its bounded read size",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    (&mut file)
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(unavailable)?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(KubeError::rejected(
            "kubeconfig grew beyond its bounded read size",
        ));
    }
    // YAML diagnostics may embed the offending credential-bearing source line.
    // Never expose those diagnostics, serialized auth entries, or file contents.
    let text = std::str::from_utf8(&bytes).map_err(|error| {
        KubeError::rejected(format!("declared kubeconfig is not UTF-8: {error}"))
    })?;
    let mut parsed = kube::config::Kubeconfig::from_yaml(text)
        .map_err(|_| KubeError::rejected("declared kubeconfig is malformed"))?;
    let directory = config
        .kubeconfig
        .parent()
        .ok_or_else(|| KubeError::rejected("kubeconfig parent is missing"))?;
    for named in &mut parsed.clusters {
        if let Some(cluster) = &mut named.cluster {
            absolutize(&mut cluster.certificate_authority, directory)?;
        }
    }
    for named in &mut parsed.auth_infos {
        if let Some(auth) = &mut named.auth_info {
            absolutize(&mut auth.client_certificate, directory)?;
            absolutize(&mut auth.client_key, directory)?;
            absolutize(&mut auth.token_file, directory)?;
        }
    }
    Ok(parsed)
}

fn absolutize(value: &mut Option<String>, directory: &std::path::Path) -> Result<(), KubeError> {
    if let Some(path) = value {
        if std::path::Path::new(path).is_relative() {
            *path = directory
                .join(&*path)
                .into_os_string()
                .into_string()
                .map_err(|error| {
                    KubeError::rejected(format!(
                        "kubeconfig credential path cannot be represented as UTF-8: {}",
                        error.to_string_lossy()
                    ))
                })?;
        }
    }
    Ok(())
}
