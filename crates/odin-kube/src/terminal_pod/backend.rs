use std::future::Future;
use std::time::Duration;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{DeleteParams, Preconditions};
use odin_kernel::stop::{PodWorkerBackend, PodWorkerBackendFault, PodWorkerIdentity, WorkerId};

use super::{CORRELATION_ANNOTATION, WORKER_ANNOTATION};
use crate::client::{KubeClient, KubeError};

pub struct KubernetesPodBackend {
    client: KubeClient,
    cluster: String,
    namespace: String,
    runtime: tokio::runtime::Handle,
}

impl KubernetesPodBackend {
    pub fn new(client: KubeClient, cluster: String, namespace: String) -> Result<Self, KubeError> {
        let runtime = tokio::runtime::Handle::try_current().map_err(|error| {
            KubeError::rejected(format!("initialize pod backend runtime: {error}"))
        })?;
        if matches!(
            runtime.runtime_flavor(),
            tokio::runtime::RuntimeFlavor::CurrentThread
        ) {
            return Err(KubeError::rejected(
                "pod backend requires a multithread runtime",
            ));
        }
        Ok(Self {
            client,
            cluster,
            namespace,
            runtime,
        })
    }

    fn run<T>(
        &self,
        step: impl Future<Output = Result<T, PodWorkerBackendFault>>,
    ) -> Result<T, PodWorkerBackendFault> {
        if tokio::runtime::Handle::try_current().is_ok_and(|runtime| {
            matches!(
                runtime.runtime_flavor(),
                tokio::runtime::RuntimeFlavor::CurrentThread
            )
        }) {
            return Err(unavailable(
                "pod backend cannot block a current-thread runtime",
            ));
        }
        tokio::task::block_in_place(|| self.runtime.block_on(step))
    }

    fn validate(&self, identity: &PodWorkerIdentity) -> Result<(), PodWorkerBackendFault> {
        if identity.cluster != self.cluster || identity.namespace != self.namespace {
            return Err(PodWorkerBackendFault::Invalid {
                reason: "pod identity is outside the declared cluster/namespace".to_owned(),
            });
        }
        Ok(())
    }

    async fn stop_pod(
        &self,
        worker: &WorkerId,
        identity: &PodWorkerIdentity,
    ) -> Result<(), PodWorkerBackendFault> {
        self.validate(identity)?;
        let pods = self.client.pods();
        let policies = self.client.network_policies();
        let secrets = self.client.secrets();
        let bound = self.client.request_timeout();
        let deadline = tokio::time::Instant::now() + self.client.teardown_timeout();
        loop {
            let pod = request(bound, pods.get_opt(&identity.pod_name)).await?;
            let policy = request(bound, policies.get_opt(&identity.policy_name)).await?;
            let secret = if let Some(name) = &identity.secret_name {
                secret_request(bound, secrets.get_opt(name)).await?
            } else {
                None
            };
            // Check every resource before deleting any of them.
            if let Some(pod) = &pod {
                check_metadata(&pod.metadata, worker, identity, identity.pod_uid.as_deref())?;
            }
            if let Some(policy) = &policy {
                check_metadata(
                    &policy.metadata,
                    worker,
                    identity,
                    identity.policy_uid.as_deref(),
                )?;
            }
            if let Some(secret) = &secret {
                check_metadata(
                    &secret.metadata,
                    worker,
                    identity,
                    identity.secret_uid.as_deref(),
                )?;
            }
            if pod.is_none() && policy.is_none() && secret.is_none() {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(unavailable(format!(
                    "stop pod {}: resource deletion timed out",
                    identity.pod_name
                )));
            }
            if let Some(pod) = &pod {
                if pod.metadata.deletion_timestamp.is_none()
                    && request(
                        bound,
                        raced(pods.delete(&identity.pod_name, &delete_params(&pod.metadata)?)),
                    )
                    .await?
                {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            }
            // Keep default-deny until the pod is gone.
            if pod.is_none() {
                if let Some(policy) = &policy {
                    if policy.metadata.deletion_timestamp.is_none()
                        && request(
                            bound,
                            raced(
                                policies.delete(
                                    &identity.policy_name,
                                    &delete_params(&policy.metadata)?,
                                ),
                            ),
                        )
                        .await?
                    {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                }
                if let (Some(name), Some(secret)) = (&identity.secret_name, &secret) {
                    if secret.metadata.deletion_timestamp.is_none()
                        && secret_request(
                            bound,
                            raced(secrets.delete(name, &delete_params(&secret.metadata)?)),
                        )
                        .await?
                    {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}

impl PodWorkerBackend for KubernetesPodBackend {
    fn stop(
        &self,
        worker: &WorkerId,
        identity: &PodWorkerIdentity,
    ) -> Result<(), PodWorkerBackendFault> {
        self.run(self.stop_pod(worker, identity))
    }
}

fn unavailable(reason: impl Into<String>) -> PodWorkerBackendFault {
    PodWorkerBackendFault::Unavailable {
        reason: reason.into(),
    }
}

async fn request<T>(
    bound: Duration,
    future: impl Future<Output = Result<T, kube::Error>>,
) -> Result<T, PodWorkerBackendFault> {
    tokio::time::timeout(bound, future)
        .await
        .map_err(|error| unavailable(format!("pod cleanup API request timed out: {error}")))?
        .map_err(|error| unavailable(format!("pod cleanup API request failed: {error}")))
}

// Secret API responses can include credential material.
async fn secret_request<T>(
    bound: Duration,
    future: impl Future<Output = Result<T, kube::Error>>,
) -> Result<T, PodWorkerBackendFault> {
    tokio::time::timeout(bound, future)
        .await
        .map_err(|error| unavailable(format!("secret cleanup API request timed out: {error}")))?
        .map_err(|error| match error {
            kube::Error::Api(status) => unavailable(format!(
                "secret cleanup API request failed: status {} {}",
                status.code, status.reason
            )),
            error => unavailable(format!("secret cleanup API request failed: {error}")),
        })
}

// Re-read after a concurrent update so the next delete uses current preconditions.
async fn raced<T>(
    future: impl Future<Output = Result<T, kube::Error>>,
) -> Result<bool, kube::Error> {
    match future.await {
        Ok(_) => Ok(false),
        Err(kube::Error::Api(status)) if status.code == 404 || status.code == 409 => Ok(true),
        Err(error) => Err(error),
    }
}

fn check_metadata(
    metadata: &ObjectMeta,
    worker: &WorkerId,
    identity: &PodWorkerIdentity,
    expected: Option<&str>,
) -> Result<(), PodWorkerBackendFault> {
    let uid = metadata
        .uid
        .as_deref()
        .filter(|uid| !uid.is_empty())
        .ok_or_else(|| unavailable("Kubernetes object has no UID"))?;
    let bound = metadata.annotations.as_ref().is_some_and(|annotations| {
        annotations.get(WORKER_ANNOTATION).map(String::as_str) == Some(worker.as_str())
            && annotations.get(CORRELATION_ANNOTATION).map(String::as_str)
                == Some(identity.correlation_id.as_str())
    });
    if !bound || expected.is_some_and(|expected| uid != expected) {
        return Err(PodWorkerBackendFault::Conflict {
            reason: "pod cleanup resource UID or worker annotation changed".to_owned(),
        });
    }
    Ok(())
}

fn delete_params(metadata: &ObjectMeta) -> Result<DeleteParams, PodWorkerBackendFault> {
    let uid = metadata
        .uid
        .clone()
        .ok_or_else(|| unavailable("delete requires UID"))?;
    let resource_version = metadata
        .resource_version
        .clone()
        .ok_or_else(|| unavailable("delete requires resourceVersion"))?;
    Ok(DeleteParams {
        preconditions: Some(Preconditions {
            uid: Some(uid),
            resource_version: Some(resource_version),
        }),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests;
