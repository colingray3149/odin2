//! Job and node watches start with a complete list, then resume at its
//! resourceVersion. Bookmarks and object events advance the resume point;
//! `410 Gone` triggers a fresh list, and short sessions back off before resuming.
//!
//! [`KubeJobWatchEvent::Listed`] lets consumers retire Jobs missing between
//! sessions. Invalid Job bindings yield rejection items without ending the stream.
//! ResourceVersions remain opaque; catalogs assign durable revision ordinals.

use std::collections::VecDeque;
use std::time::Duration;

use crate::client::{KubeClient, KubeError};
use crate::job::{
    JobObservation, JOB_LABEL_RUN_ID, JOB_PROJECTION_ANNOTATION, KUBE_OWNED_SELECTOR,
};
use crate::placement::node_view;
use crate::status::{observe_foreign_job, observe_job};
use futures_util::Stream;
use futures_util::StreamExt;
use k8s_openapi::api::batch::v1;
use k8s_openapi::api::core::v1::Node;
use kube::api::WatchEvent;
use kube::api::{ListParams, WatchParams};
use odin_domain::huginn::{KubeNodeView, KubeResourceRef, KubeWorkloadView};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Pause before the first watch resume after a clean session end.
const RESUME_BACKOFF_START: Duration = Duration::from_millis(250);
/// Upper bound for exponential resume backoff.
const RESUME_BACKOFF_CAP: Duration = Duration::from_millis(5_000);
/// A session that lived this long ended normally; it resumes without pause.
const HEALTHY_SESSION: Duration = Duration::from_secs(5);

/// Deletions carry identity only; live objects carry validated projections.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum KubeJobWatchEvent {
    /// Added or modified owned Job, fully re-projected through
    /// [`observe_job`].
    Applied(Box<JobObservation>),
    /// Observed deletion of a label-selected owned Job: raw identity fields
    /// only, no synthesized state.
    Deleted(KubeJobDeleted),
    /// One complete authoritative list ended: every owned Job it held.
    Listed(Vec<KubeResourceRef>),
}

/// The raw run label may be digest-encoded and must not be parsed as a run ID.
/// Job deletion does not establish pod absence; stop settlement checks that separately.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KubeJobDeleted {
    pub resource: KubeResourceRef,
    pub run_label: Option<String>,
}

/// One authoritative list plus a live watch of every Odin-owned Job in the
/// declared namespace, as a stream of typed [`KubeJobWatchEvent`] items.
/// The first list's failure is returned here; later failures are items.
pub async fn job_observations(
    client: KubeClient,
) -> Result<impl Stream<Item = Result<KubeJobWatchEvent, KubeError>> + Send + Unpin, KubeError> {
    let mut state = JobWatchState {
        watch: ListedWatch::new(
            client.jobs(),
            Some(KUBE_OWNED_SELECTOR),
            client.config.request_timeout,
            "kube job",
        ),
        cluster: client.config.cluster.clone(),
        client,
        revision: 0,
        pending: VecDeque::new(),
    };
    let listed = state.watch.next().await?;
    state.project(listed).await?;
    Ok(Box::pin(futures_util::stream::unfold(
        state,
        |mut state| async move {
            loop {
                if let Some(item) = state.pending.pop_front() {
                    return Some((item, state));
                }
                let projected = match state.watch.next().await {
                    Ok(step) => state.project(step).await,
                    Err(error) => Err(error),
                };
                if let Err(error) = projected {
                    return Some((Err(error), state));
                }
            }
        },
    )))
}

/// Lists yield batches and changes yield individual views; deleted nodes
/// are omitted so the catalog retains their last view.
pub async fn node_inventory(
    client: KubeClient,
) -> Result<impl Stream<Item = Result<Vec<KubeNodeView>, KubeError>> + Send + Unpin, KubeError> {
    let cluster = client.config.cluster.clone();
    let watch = ListedWatch::new(
        kube::Api::<Node>::all(client.client.clone()),
        None,
        client.config.request_timeout,
        "node inventory",
    );
    inventory(watch, move |step| match step {
        Step::Listed(nodes) => Some(
            nodes
                .iter()
                .map(|node| node_view(&cluster, node, 0))
                .collect(),
        ),
        Step::Applied(node) => Some(node_view(&cluster, &node, 0).map(|view| vec![view])),
        Step::Deleted(_) => None,
    })
    .await
}

#[derive(Clone, Debug)]
pub enum ForeignEvent {
    /// A complete list: every foreign Job the namespace holds.
    Listed(Vec<KubeWorkloadView>),
    /// One foreign Job as it now is.
    Applied(Box<KubeWorkloadView>),
    /// A Job that is no longer foreign: deleted, or bound by Odin.
    Gone(KubeResourceRef),
}

/// Read-only mirror of every Job in the declared namespace that Odin does
/// not own: every object without the [`JOB_PROJECTION_ANNOTATION`] binding
/// projects through [`observe_foreign_job`] as a foreign view. Owned Jobs —
/// including any whose binding validation rejects — flow, with their full
/// projections and typed rejections, through [`job_observations`]. The
/// views carry the presentation placeholder revision `0`; the consuming
/// catalog assigns the durable per-object ordinal when it publishes each.
pub async fn foreign_inventory(
    client: KubeClient,
) -> Result<impl Stream<Item = Result<ForeignEvent, KubeError>> + Send + Unpin, KubeError> {
    let cluster = client.config.cluster.clone();
    let watch = ListedWatch::new(
        client.jobs(),
        None,
        client.config.request_timeout,
        "foreign Job mirror",
    );
    inventory(watch, move |step| {
        Some(Ok(match step {
            Step::Listed(jobs) => ForeignEvent::Listed(
                jobs.iter()
                    .filter(|job| !bound(job))
                    .map(|job| observe_foreign_job(&cluster, job, 0))
                    .collect(),
            ),
            Step::Applied(job) if !bound(&job) => {
                ForeignEvent::Applied(Box::new(observe_foreign_job(&cluster, &job, 0)))
            }
            Step::Applied(job) | Step::Deleted(job) => {
                ForeignEvent::Gone(deleted_identity(&cluster, &job).resource)
            }
        }))
    })
    .await
}

/// Whether the Job carries Odin's binding annotation.
fn bound(job: &v1::Job) -> bool {
    job.metadata
        .annotations
        .as_ref()
        .is_some_and(|annotations| annotations.contains_key(JOB_PROJECTION_ANNOTATION))
}

/// A [`ListedWatch`] mapped through `map` (`None` skips the step); the
/// first list's failure is returned here.
async fn inventory<K, T>(
    mut watch: ListedWatch<K>,
    mut map: impl FnMut(Step<K>) -> Option<Result<T, KubeError>> + Send + 'static,
) -> Result<impl Stream<Item = Result<T, KubeError>> + Send + Unpin, KubeError>
where
    K: kube::Resource + Clone + DeserializeOwned + std::fmt::Debug + Send + 'static,
    T: Send + 'static,
{
    let first = watch.next().await?;
    let first = map(first);
    Ok(Box::pin(futures_util::stream::unfold(
        (watch, map, first),
        |(mut watch, mut map, mut held)| async move {
            loop {
                if let Some(item) = held.take() {
                    return Some((item, (watch, map, None)));
                }
                held = match watch.next().await {
                    Ok(step) => map(step),
                    Err(error) => Some(Err(error)),
                };
            }
        },
    )))
}

enum Step<K> {
    /// A complete authoritative list.
    Listed(Vec<K>),
    Applied(K),
    Deleted(K),
}

/// A bounded authoritative list, then a watch resumed from it.
struct ListedWatch<K> {
    api: kube::Api<K>,
    selector: Option<&'static str>,
    timeout: Duration,
    what: &'static str,
    /// Last observed `resourceVersion`: bookmark, list marker, or `None`
    /// meaning "server's current state". Opaque; never parsed.
    from: Option<String>,
    /// Whether the next step must be a fresh authoritative list.
    relist: bool,
    backoff: Duration,
    opened: tokio::time::Instant,
    /// Keep the session across yielded events to avoid replaying from stale resume points.
    session: Option<futures_util::stream::BoxStream<'static, Result<WatchEvent<K>, kube::Error>>>,
}

impl<K> ListedWatch<K>
where
    K: kube::Resource + Clone + DeserializeOwned + std::fmt::Debug + Send + 'static,
{
    fn new(
        api: kube::Api<K>,
        selector: Option<&'static str>,
        timeout: Duration,
        what: &'static str,
    ) -> Self {
        Self {
            api,
            selector,
            timeout,
            what,
            from: None,
            relist: true,
            backoff: RESUME_BACKOFF_START,
            opened: tokio::time::Instant::now(),
            session: None,
        }
    }

    async fn next(&mut self) -> Result<Step<K>, KubeError> {
        loop {
            if self.relist {
                let items = self.list().await?;
                self.relist = false;
                return Ok(Step::Listed(items));
            }
            let session = match self.session.as_mut() {
                Some(session) => session,
                None => {
                    let version = self.from.clone().unwrap_or_else(|| "0".to_owned());
                    let mut params = WatchParams::default();
                    if let Some(selector) = self.selector {
                        params = params.labels(selector);
                    }
                    let session =
                        tokio::time::timeout(self.timeout, self.api.watch(&params, &version))
                            .await
                            .map_err(|_| {
                                KubeError::unavailable(format!(
                                    "{} watch open timed out",
                                    self.what
                                ))
                            })??;
                    self.opened = tokio::time::Instant::now();
                    self.session.insert(session.boxed())
                }
            };
            let Some(event) = session.next().await else {
                // Back off only short sessions; healthy sessions resume immediately.
                self.session = None;
                if self.opened.elapsed() < HEALTHY_SESSION {
                    tokio::time::sleep(self.backoff).await;
                    self.backoff = (self.backoff * 2).min(RESUME_BACKOFF_CAP);
                }
                continue;
            };
            self.backoff = RESUME_BACKOFF_START;
            match event {
                Ok(WatchEvent::Bookmark(bookmark)) => {
                    self.from = Some(bookmark.metadata.resource_version);
                }
                Ok(WatchEvent::Added(object) | WatchEvent::Modified(object)) => {
                    self.advance(&object);
                    return Ok(Step::Applied(object));
                }
                Ok(WatchEvent::Deleted(object)) => {
                    self.advance(&object);
                    return Ok(Step::Deleted(object));
                }
                Ok(WatchEvent::Error(status)) if status.code == 410 => {
                    self.session = None;
                    self.relist = true;
                }
                Ok(WatchEvent::Error(status)) => {
                    self.session = None;
                    return Err(KubeError::Api(kube::Error::Api(status)));
                }
                Err(error) => {
                    self.session = None;
                    return Err(KubeError::from(error));
                }
            }
        }
    }

    /// One bounded list; records its `resourceVersion` as the resume point.
    async fn list(&mut self) -> Result<Vec<K>, KubeError> {
        let mut params = ListParams::default().limit(1024);
        if let Some(selector) = self.selector {
            params = params.labels(selector);
        }
        let listing = tokio::time::timeout(self.timeout, self.api.list(&params))
            .await
            .map_err(|_| KubeError::unavailable(format!("{} list timed out", self.what)))??;
        // Absence from a list retires an object: only a complete list may.
        if listing
            .metadata
            .continue_
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        {
            return Err(KubeError::unavailable(format!(
                "{} list came back chunked; absence from a partial list proves nothing",
                self.what
            )));
        }
        self.from = listing.metadata.resource_version.clone();
        Ok(listing.items)
    }

    fn advance(&mut self, object: &K) {
        if let Some(version) = object.meta().resource_version.as_ref() {
            self.from = Some(version.clone());
        }
    }
}

/// Whether an observed Job's view should name its pod's node: a Job object
/// carries no placement, and finished Jobs keep whatever the consumer last
/// saw.
fn needs_node(observation: &JobObservation) -> bool {
    use odin_domain::huginn::KubeWorkloadState;
    matches!(
        observation.workload.state,
        KubeWorkloadState::Scheduling | KubeWorkloadState::Running | KubeWorkloadState::Pending
    )
}

/// Names the node a live workload's pod runs on with one bounded pod read.
/// An unreadable pod list is an error, never "unscheduled": a cleared node
/// would overwrite the one the catalog knows.
async fn locate(client: &KubeClient, observation: &mut JobObservation) -> Result<(), KubeError> {
    if needs_node(observation) {
        observation.workload.node_id =
            crate::status::job_node(client, &observation.workload.resource.name).await?;
    }
    Ok(())
}

/// Raw identity of one observed Job object: the API server's own fields
/// and the raw run binding label, nothing derived.
fn deleted_identity(cluster: &str, job: &v1::Job) -> KubeJobDeleted {
    let metadata = &job.metadata;
    KubeJobDeleted {
        resource: KubeResourceRef {
            cluster: cluster.to_owned(),
            api_version: "batch/v1".to_owned(),
            kind: "Job".to_owned(),
            namespace: metadata.namespace.clone(),
            name: metadata.name.clone().unwrap_or_default(),
            uid: metadata.uid.clone().unwrap_or_default(),
        },
        run_label: metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get(JOB_LABEL_RUN_ID).cloned()),
    }
}

struct JobWatchState {
    client: KubeClient,
    watch: ListedWatch<v1::Job>,
    cluster: String,
    /// Stream-local observation ordinal handed to `observe_job`.
    revision: u64,
    pending: VecDeque<Result<KubeJobWatchEvent, KubeError>>,
}

impl JobWatchState {
    /// Projects one step into the pending queue: a list as every owned Job
    /// (nodes from one pod list) then [`KubeJobWatchEvent::Listed`]; a
    /// change as its observation; a deletion as its raw identity only —
    /// `observe_job` never runs on a removed object, so no lifecycle or
    /// timestamp is synthesized from it.
    async fn project(&mut self, step: Step<v1::Job>) -> Result<(), KubeError> {
        match step {
            Step::Listed(jobs) => {
                let nodes = crate::status::job_nodes(&self.client).await?;
                let mut listed = Vec::with_capacity(jobs.len());
                for job in &jobs {
                    listed.push(deleted_identity(&self.cluster, job).resource);
                    self.revision = self.revision.saturating_add(1);
                    let observed =
                        observe_job(&self.cluster, job, self.revision).map(|mut observation| {
                            if needs_node(&observation) {
                                observation.workload.node_id =
                                    nodes.get(&observation.workload.resource.name).cloned();
                            }
                            KubeJobWatchEvent::Applied(Box::new(observation))
                        });
                    self.pending.push_back(observed);
                }
                self.pending
                    .push_back(Ok(KubeJobWatchEvent::Listed(listed)));
            }
            Step::Applied(job) => {
                self.revision = self.revision.saturating_add(1);
                match observe_job(&self.cluster, &job, self.revision) {
                    Ok(mut observation) => {
                        locate(&self.client, &mut observation).await?;
                        self.pending
                            .push_back(Ok(KubeJobWatchEvent::Applied(Box::new(observation))));
                    }
                    Err(error) => self.pending.push_back(Err(error)),
                }
            }
            Step::Deleted(job) => {
                self.pending
                    .push_back(Ok(KubeJobWatchEvent::Deleted(deleted_identity(
                        &self.cluster,
                        &job,
                    ))));
            }
        }
        Ok(())
    }
}
