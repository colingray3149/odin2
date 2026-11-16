//! A stateful loopback Kubernetes API for the runtime tests: objects POSTed, merge-patched and deleted
//! stay in a path-keyed map, so a test reads back the Job the reconciler left behind. Only the cluster is
//! simulated; the journal, stop authority and reconciler above it are real.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Default)]
struct State {
    objects: BTreeMap<String, Value>,
    revision: u64,
}

pub(crate) struct FakeKubeApi {
    port: u16,
    state: Arc<Mutex<State>>,
}

fn status(code: u16, reason: &str) -> (u16, Value) {
    (
        code,
        json!({"apiVersion": "v1", "kind": "Status", "status": "Failure", "reason": reason,
               "message": reason, "code": code}),
    )
}

fn merge(value: &mut Value, patch: Value) {
    match (value, patch) {
        (Value::Object(value), Value::Object(patch)) => {
            for (key, field) in patch {
                if field.is_null() {
                    value.remove(&key);
                } else {
                    merge(value.entry(key).or_insert(Value::Null), field);
                }
            }
        }
        (value, patch) => *value = patch,
    }
}

impl State {
    fn respond(&mut self, method: &str, path: &str, body: Value) -> (u16, Value) {
        if path == "/version" {
            return (
                200,
                json!({"major": "1", "minor": "31", "gitVersion": "v1.31.0"}),
            );
        }
        match method {
            "POST" => {
                let mut object = body;
                let name = object["metadata"]["name"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned();
                let key = format!("{path}/{name}");
                if self.objects.contains_key(&key) {
                    return status(409, "AlreadyExists");
                }
                self.revision += 1;
                object["metadata"]["uid"] = json!(format!("uid-{}", self.revision));
                object["metadata"]["resourceVersion"] = json!(self.revision.to_string());
                object["metadata"]["namespace"] = json!("default");
                self.objects.insert(key, object.clone());
                (201, object)
            }
            "PATCH" => {
                let Some(object) = self.objects.get_mut(path) else {
                    return status(404, "NotFound");
                };
                if let Some(version) = body["metadata"]["resourceVersion"].as_str() {
                    if object["metadata"]["resourceVersion"] != version {
                        return status(409, "Conflict");
                    }
                }
                merge(object, body);
                self.revision += 1;
                object["metadata"]["resourceVersion"] = json!(self.revision.to_string());
                (200, object.clone())
            }
            "DELETE" => match self.objects.remove(path) {
                Some(object) => (200, object),
                None => status(404, "NotFound"),
            },
            _ => {
                if let Some(object) = self.objects.get(path) {
                    return (200, object.clone());
                }
                let prefix = format!("{path}/");
                let collection = path.ends_with('s');
                if !collection {
                    return status(404, "NotFound");
                }
                let items: Vec<Value> = self
                    .objects
                    .iter()
                    .filter(|(key, _)| key.starts_with(&prefix))
                    .map(|(_, object)| object.clone())
                    .collect();
                (
                    200,
                    json!({"apiVersion": "v1", "kind": "List", "items": items}),
                )
            }
        }
    }
}

impl FakeKubeApi {
    pub(crate) async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback API");
        let port = listener.local_addr().expect("API address").port();
        // One ready node, so the reconciler's placement has somewhere to put a Job.
        let node = json!({
            "apiVersion": "v1", "kind": "Node",
            "metadata": {"name": "pc", "uid": "node-pc", "labels": {"node-restriction.kubernetes.io/odin-trust": "fleet"}},
            "status": {
                "conditions": [{"type": "Ready", "status": "True"}],
                "allocatable": {"cpu": "16", "memory": "32Gi", "ephemeral-storage": "64Gi", "pods": "100"}
            }
        });
        let state = Arc::new(Mutex::new(State {
            objects: BTreeMap::from([("/api/v1/nodes/pc".to_owned(), node)]),
            revision: 0,
        }));
        let serving = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let serving = Arc::clone(&serving);
                tokio::spawn(async move {
                    let mut buffer = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let (head_end, length) = loop {
                        let read = stream.read(&mut chunk).await.unwrap_or(0);
                        if read == 0 {
                            return;
                        }
                        buffer.extend_from_slice(&chunk[..read]);
                        if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&buffer[..at]).to_lowercase();
                            let length = head
                                .lines()
                                .find_map(|line| line.strip_prefix("content-length:"))
                                .and_then(|value| value.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            break (at + 4, length);
                        }
                    };
                    while buffer.len() < head_end + length {
                        let read = stream.read(&mut chunk).await.unwrap_or(0);
                        if read == 0 {
                            return;
                        }
                        buffer.extend_from_slice(&chunk[..read]);
                    }
                    let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
                    let mut parts = head.split_whitespace();
                    let method = parts.next().unwrap_or_default().to_owned();
                    let target = parts.next().unwrap_or_default();
                    let path = target.split('?').next().unwrap_or_default().to_owned();
                    let body = serde_json::from_slice(&buffer[head_end..head_end + length])
                        .unwrap_or(Value::Null);
                    let (code, reply) = serving
                        .lock()
                        .expect("API state")
                        .respond(&method, &path, body);
                    let reply = serde_json::to_vec(&reply).expect("reply JSON");
                    let _ = stream
                        .write_all(
                            format!(
                                "HTTP/1.1 {code} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                reply.len()
                            )
                            .as_bytes(),
                        )
                        .await;
                    let _ = stream.write_all(&reply).await;
                });
            }
        });
        Self { port, state }
    }

    pub(crate) fn client(&self, root: &Path) -> odin_kube::KubeClient {
        odin_kube::KubeClient {
            client: kube::Client::try_from(kube::Config::new(
                format!("http://127.0.0.1:{}", self.port)
                    .parse()
                    .expect("API URI"),
            ))
            .expect("kube client"),
            config: self.config(root),
        }
    }

    /// The cell's cluster binding; `connect` reads the kubeconfig written beside it.
    pub(super) fn config(&self, root: &Path) -> odin_kube::KubeConfig {
        std::fs::write(
            root.join("kubeconfig"),
            format!(
                "apiVersion: v1\nkind: Config\ncurrent-context: fake\nclusters:\n- name: fake\n  cluster:\n    server: http://127.0.0.1:{}\ncontexts:\n- name: fake\n  context:\n    cluster: fake\n    user: fake\nusers:\n- name: fake\n  user: {{}}\n",
                self.port
            ),
        )
        .expect("kubeconfig");
        std::fs::set_permissions(
            root.join("kubeconfig"),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .expect("kubeconfig mode");
        odin_kube::KubeConfig {
            node_data_roots: Default::default(),
            kubeconfig: root.join("kubeconfig"),
            cluster: "fake".to_owned(),
            namespace: "default".to_owned(),
            allowed_nodes: ["pc".to_owned()].into(),
            request_timeout: std::time::Duration::from_secs(5),
            teardown_timeout: std::time::Duration::from_secs(5),
            vpn_transport: None,
        }
    }

    /// Adds an object the cluster already holds, such as a Pending pod that fills the node.
    pub(super) fn seed(&self, key: &str, object: Value) {
        self.state
            .lock()
            .expect("API state")
            .objects
            .insert(key.to_owned(), object);
    }

    /// The Jobs the API holds right now, by name.
    pub(super) fn jobs(&self) -> BTreeMap<String, Value> {
        self.state
            .lock()
            .expect("API state")
            .objects
            .iter()
            .filter(|(key, _)| key.contains("/jobs/"))
            .map(|(key, object)| {
                (
                    key.rsplit('/').next().unwrap_or_default().to_owned(),
                    object.clone(),
                )
            })
            .collect()
    }
}
