use std::collections::{BTreeMap, VecDeque};
use std::io::{BufRead, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use super::*;

fn binding() -> (WorkerId, PodWorkerIdentity, ObjectMeta) {
    let worker = WorkerId::new("pod-backend-test").expect("worker");
    let identity = PodWorkerIdentity {
        cluster: "cluster".to_owned(),
        namespace: "namespace".to_owned(),
        pod_name: "terminal".to_owned(),
        pod_uid: Some("pod-uid".to_owned()),
        policy_name: "egress".to_owned(),
        policy_uid: Some("policy-uid".to_owned()),
        secret_name: None,
        secret_uid: None,
        correlation_id: "run:live:session".to_owned(),
    };
    let metadata = ObjectMeta {
        uid: identity.pod_uid.clone(),
        resource_version: Some("17".to_owned()),
        annotations: Some(BTreeMap::from([
            (WORKER_ANNOTATION.to_owned(), worker.as_str().to_owned()),
            (
                CORRELATION_ANNOTATION.to_owned(),
                identity.correlation_id.clone(),
            ),
        ])),
        ..Default::default()
    };
    (worker, identity, metadata)
}

#[test]
fn replacement_uid_is_refused() {
    let (worker, identity, mut metadata) = binding();
    metadata.uid = Some("replacement".to_owned());
    assert!(matches!(
        check_metadata(&metadata, &worker, &identity, identity.pod_uid.as_deref()),
        Err(PodWorkerBackendFault::Conflict { .. })
    ));
}

#[test]
fn metadata_requires_worker_and_correlation_even_without_expected_uid() {
    let (worker, identity, mut metadata) = binding();
    check_metadata(&metadata, &worker, &identity, None).expect("matching annotations");
    metadata.annotations.as_mut().expect("annotations").insert(
        CORRELATION_ANNOTATION.to_owned(),
        "run:live:other".to_owned(),
    );
    assert!(check_metadata(&metadata, &worker, &identity, None).is_err());
    metadata.annotations = None;
    assert!(check_metadata(&metadata, &worker, &identity, None).is_err());
}

#[test]
fn delete_requires_uid_and_resource_version() {
    let (_, _, mut metadata) = binding();
    let parameters = delete_params(&metadata)
        .expect("delete parameters")
        .preconditions
        .expect("preconditions");
    assert_eq!(parameters.uid.as_deref(), Some("pod-uid"));
    assert_eq!(parameters.resource_version.as_deref(), Some("17"));
    metadata.uid = None;
    assert!(delete_params(&metadata).is_err());
    metadata.uid = Some("pod-uid".to_owned());
    metadata.resource_version = None;
    assert!(delete_params(&metadata).is_err());
}

// Force read/delete races while enforcing UID and resourceVersion preconditions.

const POD: &str = "terminal-pod";
const POLICY: &str = "terminal-egress";
const SECRET: &str = "terminal-secret";
const CORRELATION: &str = "0f1e2d3c000040008000000000000001";
const SENTINEL: &str = "sensitive-account-data-7f3a";
const CLUSTER: &str = "fixture-cluster";
const TEARDOWN: Duration = Duration::from_secs(5);
const REQUEST_BOUND: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Kind {
    Pod,
    Policy,
    Secret,
}

impl Kind {
    fn collection(self) -> &'static str {
        match self {
            Kind::Pod => "pods",
            Kind::Policy => "networkpolicies",
            Kind::Secret => "secrets",
        }
    }

    fn from_collection(segment: &str) -> Option<Self> {
        [Kind::Pod, Kind::Policy, Kind::Secret]
            .into_iter()
            .find(|kind| kind.collection() == segment)
    }

    fn api_version(self) -> &'static str {
        match self {
            Kind::Pod | Kind::Secret => "v1",
            Kind::Policy => "networking.k8s.io/v1",
        }
    }

    fn api_kind(self) -> &'static str {
        match self {
            Kind::Pod => "Pod",
            Kind::Policy => "NetworkPolicy",
            Kind::Secret => "Secret",
        }
    }
}

// What happens to the cluster between the controller's read and its DELETE.
#[derive(Clone, Copy)]
enum Mutation {
    // An unrelated writer (scheduler, kubelet status) advances resourceVersion.
    Churn(Kind),
    // Another actor deletes the object outright.
    Remove(Kind),
    // The name is reused by a different object without worker annotations.
    Replace(Kind),
    // The same object loses its worker annotation.
    Disown(Kind),
}

#[derive(Default)]
struct Interleaving {
    script: VecDeque<Vec<Mutation>>,
    repeat: Vec<Mutation>,
}

struct Stored {
    body: Value,
    ours: bool,
    reads_until_gone: Option<u32>,
}

#[derive(Clone, Debug)]
struct Accepted {
    kind: Kind,
    uid: String,
    resource_version: String,
}

#[derive(Default)]
struct State {
    revision: u64,
    objects: BTreeMap<Kind, Stored>,
    interleavings: BTreeMap<Kind, Interleaving>,
    read_failures: BTreeMap<Kind, u16>,
    grace_reads: u32,
    secret_detail: String,
    accepted: Vec<Accepted>,
    violations: Vec<String>,
}

impl State {
    fn bump(&mut self) -> String {
        self.revision += 1;
        self.revision.to_string()
    }

    fn insert(&mut self, kind: Kind, name: &str, annotations: Value, ours: bool) {
        let version = self.bump();
        let body = json!({
            "apiVersion": kind.api_version(),
            "kind": kind.api_kind(),
            "metadata": {
                "name": name,
                "namespace": "default",
                "uid": format!("{}-uid-{version}", kind.collection()),
                "resourceVersion": version,
                "annotations": annotations,
            },
        });
        self.objects.insert(
            kind,
            Stored {
                body,
                ours,
                reads_until_gone: None,
            },
        );
    }

    fn race(&mut self, kind: Kind, mutations: Vec<Mutation>) {
        self.interleavings
            .entry(kind)
            .or_default()
            .script
            .push_back(mutations);
    }

    fn always(&mut self, kind: Kind, mutations: Vec<Mutation>) {
        self.interleavings.entry(kind).or_default().repeat = mutations;
    }

    fn metadata_field(&self, kind: Kind, field: &str) -> Option<String> {
        self.objects.get(&kind)?.body["metadata"][field]
            .as_str()
            .map(str::to_owned)
    }

    fn present(&self, kind: Kind, name: &str) -> bool {
        self.objects
            .get(&kind)
            .is_some_and(|stored| stored.body["metadata"]["name"] == name)
    }

    fn apply(&mut self, mutation: Mutation) {
        match mutation {
            Mutation::Churn(kind) => {
                let version = self.bump();
                if let Some(stored) = self.objects.get_mut(&kind) {
                    stored.body["metadata"]["resourceVersion"] = json!(version);
                }
            }
            Mutation::Remove(kind) => {
                self.objects.remove(&kind);
            }
            Mutation::Replace(kind) => {
                let Some(name) = self.metadata_field(kind, "name") else {
                    return;
                };
                self.insert(kind, &name, json!({}), false);
            }
            Mutation::Disown(kind) => {
                let version = self.bump();
                if let Some(stored) = self.objects.get_mut(&kind) {
                    stored.body["metadata"]["resourceVersion"] = json!(version);
                    stored.body["metadata"]["annotations"][WORKER_ANNOTATION] =
                        json!("another-worker");
                    stored.ours = false;
                }
            }
        }
    }

    fn failure(&self, kind: Kind, code: u16, reason: &str) -> (u16, Value) {
        let detail = if kind == Kind::Secret {
            self.secret_detail.as_str()
        } else {
            ""
        };
        (
            code,
            json!({
                "apiVersion": "v1", "kind": "Status", "metadata": {},
                "status": "Failure", "reason": reason, "code": code,
                "message": format!("{} {reason} {detail}", kind.collection()),
            }),
        )
    }

    fn unexpected(&mut self, method: &str, path: &str) -> (u16, Value) {
        self.violations
            .push(format!("unexpected API effect {method} {path}"));
        (
            405,
            json!({
                "apiVersion": "v1", "kind": "Status", "metadata": {},
                "status": "Failure", "reason": "MethodNotAllowed", "code": 405,
                "message": "the fixture serves only GET and DELETE of custody resources",
            }),
        )
    }

    fn read(&mut self, kind: Kind, name: &str) -> (u16, Value) {
        if let Some(code) = self.read_failures.get(&kind).copied() {
            return self.failure(kind, code, "Forbidden");
        }
        if !self.present(kind, name) {
            return self.failure(kind, 404, "NotFound");
        }
        let Some(stored) = self.objects.get_mut(&kind) else {
            return self.failure(kind, 404, "NotFound");
        };
        if stored.reads_until_gone == Some(0) {
            self.objects.remove(&kind);
            return self.failure(kind, 404, "NotFound");
        }
        if let Some(left) = stored.reads_until_gone.as_mut() {
            *left -= 1;
        }
        (200, stored.body.clone())
    }

    fn remove(&mut self, kind: Kind, name: &str, options: &Value) -> (u16, Value) {
        let mutations = match self.interleavings.get_mut(&kind) {
            Some(plan) => plan
                .script
                .pop_front()
                .unwrap_or_else(|| plan.repeat.clone()),
            None => Vec::new(),
        };
        for mutation in mutations {
            self.apply(mutation);
        }
        let precondition =
            |field: &str| options["preconditions"][field].as_str().map(str::to_owned);
        let (Some(uid), Some(version)) = (precondition("uid"), precondition("resourceVersion"))
        else {
            self.violations.push(format!(
                "{kind:?} DELETE lacked UID and resourceVersion preconditions"
            ));
            return self.failure(kind, 400, "BadRequest");
        };
        if !self.present(kind, name) {
            return self.failure(kind, 404, "NotFound");
        }
        if self.metadata_field(kind, "uid").as_deref() != Some(uid.as_str())
            || self.metadata_field(kind, "resourceVersion").as_deref() != Some(version.as_str())
        {
            return self.failure(kind, 409, "Conflict");
        }
        if !self.objects.get(&kind).is_some_and(|stored| stored.ours) {
            self.violations.push(format!(
                "{kind:?} {uid} carries no custody binding yet its delete was accepted"
            ));
        }
        if kind == Kind::Policy && self.objects.contains_key(&Kind::Pod) {
            self.violations
                .push("default-deny NetworkPolicy deleted while the Pod still exists".to_owned());
        }
        self.accepted.push(Accepted {
            kind,
            uid,
            resource_version: version,
        });
        let grace = self.grace_reads;
        if kind == Kind::Pod && grace > 0 {
            if let Some(stored) = self.objects.get_mut(&kind) {
                if stored.reads_until_gone.is_none() {
                    stored.reads_until_gone = Some(grace);
                }
                stored.body["metadata"]["deletionTimestamp"] = json!("2026-01-01T00:00:00Z");
                return (200, stored.body.clone());
            }
        }
        let removed = self
            .objects
            .remove(&kind)
            .map_or(Value::Null, |stored| stored.body);
        (200, removed)
    }

    fn handle(&mut self, method: &str, path: &str, body: &Value) -> (u16, Value) {
        let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
        let [.., collection, name] = segments.as_slice() else {
            return self.unexpected(method, path);
        };
        let Some(kind) = Kind::from_collection(collection) else {
            return self.unexpected(method, path);
        };
        match method {
            "GET" => self.read(kind, name),
            "DELETE" => self.remove(kind, name, body),
            _ => self.unexpected(method, path),
        }
    }
}

fn serve(mut stream: std::net::TcpStream, state: &Mutex<State>) {
    let bound = Some(Duration::from_secs(2));
    if stream.set_read_timeout(bound).is_err() || stream.set_write_timeout(bound).is_err() {
        return;
    }
    let Ok(reader_stream) = stream.try_clone() else {
        return;
    };
    let mut reader = std::io::BufReader::new(reader_stream);
    let mut request = String::new();
    if reader.read_line(&mut request).unwrap_or(0) == 0 {
        return;
    }
    let mut length = 0;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line.trim().is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            if key.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse::<usize>().unwrap_or(0);
            }
        }
    }
    let mut bytes = vec![0; length];
    if reader.read_exact(&mut bytes).is_err() {
        return;
    }
    let body = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
    let mut parts = request.split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return;
    };
    let path = target.split('?').next().unwrap_or(target);
    let (code, response) = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .handle(method, path, &body);
    let payload = serde_json::to_vec(&response).unwrap_or_default();
    let header = format!(
        "HTTP/1.1 {code} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(&payload);
}

struct Cluster {
    port: u16,
    state: Arc<Mutex<State>>,
    stopped: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Cluster {
    fn start() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("loopback API");
        let port = listener.local_addr().expect("API address").port();
        let state = Arc::new(Mutex::new(State::default()));
        let stopped = Arc::new(AtomicBool::new(false));
        let serving_state = Arc::clone(&state);
        let serving_stopped = Arc::clone(&stopped);
        let thread = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if serving_stopped.load(Ordering::Acquire) {
                    break;
                }
                if let Ok(stream) = stream {
                    serve(stream, &serving_state);
                }
            }
        });
        Self {
            port,
            state,
            stopped,
            thread: Some(thread),
        }
    }

    fn with<R>(&self, inspect: impl FnOnce(&mut State) -> R) -> R {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inspect(&mut guard)
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct Rig {
    backend: KubernetesPodBackend,
    cluster: Cluster,
    worker: WorkerId,
    identity: PodWorkerIdentity,
    pod_uid: String,
    pod_version: String,
    teardown: Duration,
}

impl Rig {
    fn new(with_secret: bool, teardown: Duration) -> Self {
        let cluster = Cluster::start();
        let worker = WorkerId::new("pod-backend-test").expect("worker id");
        let annotations = json!(BTreeMap::from([
            (WORKER_ANNOTATION.to_owned(), worker.as_str().to_owned()),
            (CORRELATION_ANNOTATION.to_owned(), CORRELATION.to_owned()),
        ]));
        let (pod_uid, pod_version) = cluster.with(|state| {
            state.insert(Kind::Pod, POD, annotations.clone(), true);
            state.insert(Kind::Policy, POLICY, annotations.clone(), true);
            if with_secret {
                state.insert(Kind::Secret, SECRET, annotations.clone(), true);
            }
            (
                state.metadata_field(Kind::Pod, "uid").expect("pod uid"),
                state
                    .metadata_field(Kind::Pod, "resourceVersion")
                    .expect("pod resourceVersion"),
            )
        });
        let identity = PodWorkerIdentity {
            cluster: CLUSTER.to_owned(),
            namespace: "default".to_owned(),
            pod_name: POD.to_owned(),
            pod_uid: Some(pod_uid.clone()),
            policy_name: POLICY.to_owned(),
            policy_uid: cluster.with(|state| state.metadata_field(Kind::Policy, "uid")),
            secret_name: with_secret.then(|| SECRET.to_owned()),
            secret_uid: cluster.with(|state| state.metadata_field(Kind::Secret, "uid")),
            correlation_id: CORRELATION.to_owned(),
        };
        let client = KubeClient {
            client: kube::Client::try_from(kube::Config::new(
                format!("http://127.0.0.1:{}", cluster.port)
                    .parse()
                    .expect("API URI"),
            ))
            .expect("client"),
            config: crate::KubeConfig {
                kubeconfig: "unused-kubeconfig".into(),
                cluster: CLUSTER.to_owned(),
                namespace: "default".to_owned(),
                allowed_nodes: std::collections::BTreeSet::new(),
                request_timeout: REQUEST_BOUND,
                teardown_timeout: teardown,
            },
        };
        let backend = KubernetesPodBackend::new(client, CLUSTER.to_owned(), "default".to_owned())
            .expect("pod backend");
        Self {
            backend,
            cluster,
            worker,
            identity,
            pod_uid,
            pod_version,
            teardown,
        }
    }

    fn stop(&self) -> Result<(), PodWorkerBackendFault> {
        self.backend.stop(&self.worker, &self.identity)
    }

    fn exists(&self, kind: Kind) -> bool {
        self.cluster.with(|state| state.objects.contains_key(&kind))
    }

    fn uid(&self, kind: Kind) -> Option<String> {
        self.cluster.with(|state| state.metadata_field(kind, "uid"))
    }

    fn accepted(&self, kind: Option<Kind>) -> Vec<Accepted> {
        self.cluster.with(|state| {
            state
                .accepted
                .iter()
                .filter(|accepted| kind.is_none_or(|kind| accepted.kind == kind))
                .cloned()
                .collect()
        })
    }

    fn report(&self, outcome: &Result<(), PodWorkerBackendFault>) -> String {
        let violations = self.cluster.with(|state| state.violations.clone());
        format!(
            "stop result: {outcome:#?}\nAPI accepted deletes: {:#?}\nAPI violations: {violations:#?}",
            self.accepted(None)
        )
    }

    // Check preconditions, ownership and default-deny ordering against live state.
    fn assert_safe(&self, outcome: &Result<(), PodWorkerBackendFault>) {
        let violations = self.cluster.with(|state| state.violations.clone());
        assert!(
            violations.is_empty(),
            "backend safety was violated at the API\n{}",
            self.report(outcome)
        );
    }

    fn assert_secret_body_absent(&self, outcome: &Result<(), PodWorkerBackendFault>) {
        let error = outcome.as_ref().expect_err("secret cleanup must fail");
        assert!(
            !format!("{error:?}").contains(SENTINEL) && !error.to_string().contains(SENTINEL),
            "a Secret API error body reached the returned error\n{}",
            self.report(outcome)
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_churn_retries_with_current_delete_preconditions() {
    let rig = Rig::new(false, TEARDOWN);
    rig.cluster
        .with(|state| state.race(Kind::Pod, vec![Mutation::Churn(Kind::Pod)]));
    let outcome = rig.stop();
    let report = rig.report(&outcome);
    assert!(outcome.is_ok(), "{report}");
    assert!(
        !rig.exists(Kind::Pod) && !rig.exists(Kind::Policy),
        "{report}"
    );
    let pod_deletes = rig.accepted(Some(Kind::Pod));
    assert_eq!(pod_deletes.len(), 1, "{report}");
    assert_eq!(pod_deletes[0].uid, rig.pod_uid, "{report}");
    assert_ne!(
        pod_deletes[0].resource_version, rig.pod_version,
        "the accepted delete must carry the re-observed resourceVersion\n{report}"
    );
    rig.assert_safe(&outcome);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_deletion_is_reread_before_policy_deletion() {
    let rig = Rig::new(false, TEARDOWN);
    rig.cluster
        .with(|state| state.race(Kind::Pod, vec![Mutation::Remove(Kind::Pod)]));
    let outcome = rig.stop();
    let report = rig.report(&outcome);
    assert!(outcome.is_ok(), "{report}");
    assert!(
        !rig.exists(Kind::Pod) && !rig.exists(Kind::Policy),
        "{report}"
    );
    rig.assert_safe(&outcome);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replacement_after_conflict_refuses_every_destructive_effect() {
    let rig = Rig::new(false, TEARDOWN);
    rig.cluster
        .with(|state| state.race(Kind::Pod, vec![Mutation::Replace(Kind::Pod)]));
    let outcome = rig.stop();
    let report = rig.report(&outcome);
    assert!(
        matches!(outcome, Err(PodWorkerBackendFault::Conflict { .. })),
        "{report}"
    );
    assert!(rig.accepted(None).is_empty(), "{report}");
    let replacement = rig.uid(Kind::Pod);
    assert!(
        replacement.is_some() && replacement.as_deref() != Some(rig.pod_uid.as_str()),
        "the replacement Pod must survive untouched\n{report}"
    );
    assert!(rig.exists(Kind::Policy), "{report}");
    rig.assert_safe(&outcome);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ownership_change_after_conflict_refuses_pod_and_policy_deletion() {
    let rig = Rig::new(false, TEARDOWN);
    rig.cluster.with(|state| {
        state.race(
            Kind::Pod,
            vec![Mutation::Churn(Kind::Pod), Mutation::Disown(Kind::Policy)],
        )
    });
    let outcome = rig.stop();
    let report = rig.report(&outcome);
    assert!(
        matches!(outcome, Err(PodWorkerBackendFault::Conflict { .. })),
        "{report}"
    );
    assert!(rig.accepted(None).is_empty(), "{report}");
    assert_eq!(
        rig.uid(Kind::Pod).as_deref(),
        Some(rig.pod_uid.as_str()),
        "{report}"
    );
    assert!(rig.exists(Kind::Policy), "{report}");
    rig.assert_safe(&outcome);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_replacement_after_conflict_preserves_secret() {
    let rig = Rig::new(true, TEARDOWN);
    let policy_uid = rig.uid(Kind::Policy).expect("original policy");
    let secret_uid = rig.uid(Kind::Secret).expect("original secret");
    rig.cluster.with(|state| {
        state.race(Kind::Policy, vec![Mutation::Replace(Kind::Policy)]);
    });
    let outcome = rig.stop();
    let report = rig.report(&outcome);
    assert!(
        matches!(outcome, Err(PodWorkerBackendFault::Conflict { .. })),
        "{report}"
    );
    assert!(!rig.exists(Kind::Pod), "{report}");
    let replacement = rig.uid(Kind::Policy);
    assert!(
        replacement.is_some() && replacement.as_deref() != Some(policy_uid.as_str()),
        "the replacement policy must survive untouched\n{report}"
    );
    assert_eq!(
        rig.uid(Kind::Secret).as_deref(),
        Some(secret_uid.as_str()),
        "{report}"
    );
    assert!(rig.accepted(Some(Kind::Policy)).is_empty(), "{report}");
    assert!(rig.accepted(Some(Kind::Secret)).is_empty(), "{report}");
    rig.assert_safe(&outcome);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_deny_policy_outlives_a_terminating_pod() {
    let rig = Rig::new(false, TEARDOWN);
    rig.cluster.with(|state| state.grace_reads = 3);
    let outcome = rig.stop();
    let report = rig.report(&outcome);
    assert!(outcome.is_ok(), "{report}");
    assert!(
        !rig.exists(Kind::Pod) && !rig.exists(Kind::Policy),
        "{report}"
    );
    assert_eq!(rig.accepted(Some(Kind::Pod)).len(), 1, "{report}");
    assert_eq!(rig.accepted(Some(Kind::Policy)).len(), 1, "{report}");
    rig.assert_safe(&outcome);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn teardown_timeout_returns_error_and_preserves_default_deny() {
    let rig = Rig::new(false, Duration::from_secs(1));
    rig.cluster.with(|state| state.grace_reads = u32::MAX);
    let started = std::time::Instant::now();
    let outcome = rig.stop();
    let elapsed = started.elapsed();
    let report = rig.report(&outcome);
    assert!(
        matches!(outcome, Err(PodWorkerBackendFault::Unavailable { .. })),
        "{report}"
    );
    assert!(
        elapsed < rig.teardown + REQUEST_BOUND,
        "stop outlived its teardown bound: {elapsed:?}\n{report}"
    );
    assert_eq!(rig.accepted(Some(Kind::Pod)).len(), 1, "{report}");
    assert!(rig.accepted(Some(Kind::Policy)).is_empty(), "{report}");
    assert_eq!(
        rig.uid(Kind::Pod).as_deref(),
        Some(rig.pod_uid.as_str()),
        "{report}"
    );
    assert!(rig.exists(Kind::Policy), "{report}");
    rig.assert_safe(&outcome);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn secret_read_error_body_never_enters_returned_error() {
    let rig = Rig::new(true, TEARDOWN);
    rig.cluster.with(|state| {
        state.read_failures.insert(Kind::Secret, 403);
        state.secret_detail = SENTINEL.to_owned();
    });
    let outcome = rig.stop();
    let report = rig.report(&outcome);
    assert!(
        matches!(outcome, Err(PodWorkerBackendFault::Unavailable { .. })),
        "{report}"
    );
    assert!(rig.accepted(None).is_empty(), "{report}");
    rig.assert_secret_body_absent(&outcome);
    rig.assert_safe(&outcome);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn secret_delete_conflict_body_never_enters_returned_error() {
    let rig = Rig::new(true, Duration::from_millis(1500));
    rig.cluster.with(|state| {
        state.always(Kind::Secret, vec![Mutation::Churn(Kind::Secret)]);
        state.secret_detail = SENTINEL.to_owned();
    });
    let outcome = rig.stop();
    let report = rig.report(&outcome);
    assert!(
        matches!(outcome, Err(PodWorkerBackendFault::Unavailable { .. })),
        "{report}"
    );
    assert!(rig.exists(Kind::Secret), "{report}");
    assert!(rig.accepted(Some(Kind::Secret)).is_empty(), "{report}");
    rig.assert_secret_body_absent(&outcome);
    rig.assert_safe(&outcome);
}
