//! One finite compute sample per declared host.
//!
//! The authority samples itself in-process. Every other enabled, enrolled host
//! is one `odin compute-sample` child over the registered SSH binding. The child
//! takes two readings so CPU percent is a real delta, prints one JSON sample,
//! and exits. Dropping this future — the view closes, or the request bound
//! fires — aborts the join and `kill_on_drop` ends every remote child. No
//! sampler is left running.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use odin_cli::compute_sample::take_stopped;
use odin_compute::{ComputePod, ComputeSample};
use odin_domain::huginn::{HuginnProtocolError, HuginnResponse};
use odin_kube::inventory::ObservedPod;

use odin_registry::{ObjectConfig, RegistryKind, SnapshotHandle};
use serde_json::Value;
use tokio::process::Command;
use tokio::task::JoinSet;

/// Inside the view's 15 s request bound, so a hung host reaches the view as a
/// named miss before the view's own timeout fires.
const SAMPLE_BOUND: Duration = Duration::from_secs(12);
const INVENTORY_CONNECT_BOUND: Duration = Duration::from_secs(3);
const OUTPUT_LIMIT: usize = 256 * 1024;
const HOST_LIMIT: usize = 64;

/// Why one host did not contribute a sample. The others still answer.
#[derive(Clone, Debug, Eq, PartialEq)]
struct HostMiss {
    host: String,
    node: String,
    detail: String,
}

/// One declared host the authority can reach through registered SSH.
#[derive(Clone, Debug, Eq, PartialEq)]
struct DeclaredHost {
    id: String,
    tailscale: String,
    node: String,
    local: bool,
}

/// Enabled, enrolled hosts that name an enabled node. The authority's own
/// node is local; every other host is reached by its declared tailscale name.
fn declared_hosts(registry: &odin_registry::Snapshot, local_node: &str) -> Vec<DeclaredHost> {
    let mut hosts = Vec::new();
    for object in registry.listed_objects(RegistryKind::Host) {
        let ObjectConfig::Host(host) = &object.config else {
            continue;
        };
        if !(host.enabled && host.enrolled) {
            continue;
        }
        let Some(node) = registry
            .listed_objects(RegistryKind::Node)
            .find_map(|node| {
                let ObjectConfig::Node(declared) = &node.config else {
                    return None;
                };
                (declared.enabled && declared.host == object.id).then(|| node.id.clone())
            })
        else {
            continue;
        };
        hosts.push(DeclaredHost {
            local: node == local_node,
            id: object.id.clone(),
            tailscale: host.tailscale.clone(),
            node,
        });
    }
    hosts.sort_by(|left, right| left.id.cmp(&right.id));
    hosts.truncate(HOST_LIMIT);
    hosts
}

/// Pods scheduled onto `node`. A Job is not a row: each pod keeps its own name.
fn pods_for(pods: &[ObservedPod], node: &str) -> Vec<ComputePod> {
    let mut rows = pods
        .iter()
        .filter(|pod| pod.node == node)
        .map(|pod| ComputePod {
            name: pod.name.clone(),
            node: node.to_owned(),
            state: pod.phase.clone(),
        })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| left.name.cmp(&right.name));
    rows
}

async fn pod_inventory(
    kube: Option<Arc<super::kube::KubeRuntimeCell>>,
) -> (Vec<ObservedPod>, Option<String>) {
    let Some(cell) = kube else {
        return (
            Vec::new(),
            Some("kube is not bound on this plane".to_owned()),
        );
    };
    let client = match tokio::time::timeout(INVENTORY_CONNECT_BOUND, cell.client()).await {
        Ok(Ok(client)) => client,
        Ok(Err(error)) => return (Vec::new(), Some(error.to_string())),
        Err(_) => return (Vec::new(), Some("pod inventory timed out".to_owned())),
    };
    match odin_kube::inventory::list_pods(&client).await {
        Ok(inventory) => {
            let note = inventory.truncated.then(|| {
                format!(
                    "pod inventory truncated at {}",
                    odin_kube::inventory::POD_INVENTORY_LIMIT
                )
            });
            (inventory.pods, note)
        }
        Err(error) => (Vec::new(), Some(error.to_string())),
    }
}

fn sample_argv(executable: &Path, tailscale: &str, node: &str, host: &str) -> Vec<String> {
    let mut argv = vec![executable.display().to_string()];
    argv.extend(odin_omp::live::harness::ssh_argv(
        &["-T"],
        tailscale,
        &["odin", "compute-sample", "--node", node, "--host", host],
    ));
    argv
}

const STDERR_TAIL: usize = 180;

/// Last `limit` bytes. A split multibyte sequence becomes U+FFFD, never a panic.
fn utf8_tail(bytes: &[u8], limit: usize) -> String {
    let start = bytes.len().saturating_sub(limit);
    let text = String::from_utf8_lossy(&bytes[start..]);
    let mut end = 0;
    for (index, character) in text.char_indices() {
        if index + character.len_utf8() > limit {
            break;
        }
        end = index + character.len_utf8();
    }
    text[..end].trim().to_owned()
}

async fn remote_sample(ssh: &Path, host: &DeclaredHost) -> Result<ComputeSample, HostMiss> {
    let mut argv = sample_argv(ssh, &host.tailscale, &host.node, &host.id);
    let executable = argv.remove(0);
    let miss = |detail: String| HostMiss {
        host: host.id.clone(),
        node: host.node.clone(),
        detail,
    };
    // Registered SSH path from the runtime manifest, same options as the
    // fleet probe. `kill_on_drop` is the cancel: dropping this future (peer
    // close or the sample bound) kills ssh, and ssh without a tty still
    // delivers SIGHUP to the remote sample on channel close.
    let mut child = Command::new(executable)
        .args(&argv)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| miss(format!("ssh did not start: {error}")))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| miss("ssh stdout missing".to_owned()))?;
    let stderr = child.stderr.take();
    let stdout_task = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut kept = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let read = stdout
                .read(&mut chunk)
                .await
                .map_err(|error| error.to_string())?;
            if read == 0 {
                break;
            }
            let room = OUTPUT_LIMIT.saturating_sub(kept.len());
            if room == 0 {
                return Err(format!("sample exceeded {OUTPUT_LIMIT} bytes"));
            }
            kept.extend_from_slice(&chunk[..read.min(room)]);
            if read > room {
                return Err(format!("sample exceeded {OUTPUT_LIMIT} bytes"));
            }
        }
        Ok(kept)
    });
    let stderr_task = tokio::spawn(async move {
        let Some(mut stderr) = stderr else {
            return Vec::new();
        };
        use tokio::io::AsyncReadExt;
        let mut kept = Vec::new();
        let mut chunk = [0u8; 1024];
        while let Ok(read) = stderr.read(&mut chunk).await {
            if read == 0 {
                break;
            }
            if read >= STDERR_TAIL {
                kept.clear();
                kept.extend_from_slice(&chunk[read - STDERR_TAIL..read]);
            } else {
                kept.extend_from_slice(&chunk[..read]);
                if kept.len() > STDERR_TAIL {
                    let start = kept.len() - STDERR_TAIL;
                    kept.drain(..start);
                }
            }
        }
        kept
    });
    let status = child
        .wait()
        .await
        .map_err(|error| miss(format!("ssh did not finish: {error}")))?;
    let stdout = stdout_task
        .await
        .map_err(|error| miss(error.to_string()))?
        .map_err(miss)?;
    let stderr = stderr_task.await.unwrap_or_default();
    if !status.success() {
        return Err(miss(format!(
            "odin compute-sample on {} exited {:?}: {}",
            host.tailscale,
            status.code(),
            utf8_tail(&stderr, STDERR_TAIL)
        )));
    }
    serde_json::from_slice(&stdout).map_err(|error| miss(format!("sample was not JSON: {error}")))
}

/// One fleet snapshot. Every declared host is a sample or a named failure.
/// A miss does not keep the previous gauges, and an all-host failure is still
/// a snapshot the view can draw.
async fn collect_snapshot(
    registry: &SnapshotHandle,
    local_node: &str,
    ssh: &Path,
    kube: Option<Arc<super::kube::KubeRuntimeCell>>,
) -> Result<Value, String> {
    let hosts = declared_hosts(&registry.current(), local_node);
    if hosts.is_empty() {
        return Err("no enabled enrolled host declares this node's placement".to_owned());
    }
    let inventory = tokio::spawn(pod_inventory(kube));
    let mut set = JoinSet::new();
    for host in hosts {
        let ssh = ssh.to_path_buf();
        set.spawn(async move {
            let node = host.node.clone();
            let id = host.id.clone();
            let sample = if host.local {
                let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let stop = Arc::clone(&cancel);
                struct StopOnDrop(Arc<std::sync::atomic::AtomicBool>);
                impl Drop for StopOnDrop {
                    fn drop(&mut self) {
                        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                let _stop = StopOnDrop(Arc::clone(&cancel));
                let sampled_node = node.clone();
                let sampled_id = id.clone();
                let joined = tokio::task::spawn_blocking(move || {
                    take_stopped(&sampled_node, &sampled_id, &stop)
                });
                joined
                    .await
                    .map_err(|error| HostMiss {
                        host: id.clone(),
                        node: node.clone(),
                        detail: error.to_string(),
                    })?
                    .map_err(|error| HostMiss {
                        host: id.clone(),
                        node: node.clone(),
                        detail: error,
                    })?
            } else {
                tokio::time::timeout(SAMPLE_BOUND, remote_sample(&ssh, &host))
                    .await
                    .map_err(|_| HostMiss {
                        host: id.clone(),
                        node: node.clone(),
                        detail: "sample exceeded its bound".to_owned(),
                    })??
            };
            Ok::<_, HostMiss>((node, id, sample))
        });
    }
    let mut rows = Vec::new();
    while let Some(joined) = set.join_next().await {
        rows.push(joined.unwrap_or_else(|error| {
            Err(HostMiss {
                node: "unknown".to_owned(),
                host: "unknown".to_owned(),
                detail: error.to_string(),
            })
        }));
    }
    let (pods, pods_note) = inventory
        .await
        .unwrap_or_else(|error| (Vec::new(), Some(error.to_string())));
    let mut hosts = Vec::with_capacity(rows.len());
    for row in rows {
        hosts.push(match row {
            Ok((node, host, mut sample)) => {
                sample.pods = pods_for(&pods, &node);
                if sample.pods_note.is_none() {
                    sample.pods_note = pods_note.clone();
                }
                serde_json::json!({ "node": node, "host": host, "sample": sample })
            }
            Err(HostMiss { node, host, detail }) => {
                tracing::warn!(host = %host, "compute sample missed: {detail}");
                serde_json::json!({ "node": node, "host": host, "error": detail })
            }
        });
    }
    hosts.sort_by(|left, right| {
        left.get("node")
            .and_then(Value::as_str)
            .cmp(&right.get("node").and_then(Value::as_str))
    });
    Ok(serde_json::json!({ "hosts": hosts }))
}

/// Join the one cadence. Closing this request unsubscribes; the last close
/// stops the in-flight collect.
pub(crate) async fn answer(
    registry: Option<&Arc<SnapshotHandle>>,
    local_node: Option<&str>,
    ssh: Option<&Path>,
    kube: Option<&Arc<super::kube::KubeRuntimeCell>>,
) -> Result<HuginnResponse, HuginnProtocolError> {
    let (Some(registry), Some(node), Some(ssh)) = (registry, local_node, ssh) else {
        return Err(HuginnProtocolError::unavailable(
            "computeUnavailable",
            "compute sampling is not bound on this plane",
        ));
    };
    let registry = Arc::clone(registry);
    let node = node.to_owned();
    let ssh = ssh.to_path_buf();
    let kube = kube.cloned();
    let snapshot = super::compute_hub::ComputeHub::shared()
        .sample(move || {
            let registry = Arc::clone(&registry);
            let node = node.clone();
            let ssh = ssh.clone();
            let kube = kube.clone();
            async move { collect_snapshot(&registry, &node, &ssh, kube).await }
        })
        .await
        .map_err(|error| HuginnProtocolError::unavailable("computeUnavailable", error))?;
    Ok(HuginnResponse::Compute(snapshot))
}

#[cfg(test)]
mod tests {
    use super::{declared_hosts, sample_argv};

    use odin_registry::{ObjectConfig, RegistryKind, RegistryObject, Snapshot};
    use std::path::Path;

    fn host(id: &str, enrolled: bool) -> RegistryObject {
        RegistryObject {
            id: id.to_owned(),
            relative_config: format!("registry/hosts/{id}/host.toml").into(),
            config: ObjectConfig::Host(Box::new(odin_registry::schema::HostToml {
                schema: odin_registry::schema::REGISTRY_SCHEMA.to_owned(),
                kind: RegistryKind::Host,
                enabled: true,
                description: "fixture".to_owned(),
                hardware: "fixture".to_owned(),
                role: "control".to_owned(),
                tailscale: format!("{id}-ts"),
                enrolled,
            })),
        }
    }

    fn node(id: &str, host_id: &str, enabled: bool) -> RegistryObject {
        RegistryObject {
            id: id.to_owned(),
            relative_config: format!("registry/nodes/{id}/node.toml").into(),
            config: ObjectConfig::Node(Box::new(odin_registry::schema::NodeToml {
                schema: odin_registry::schema::REGISTRY_SCHEMA.to_owned(),
                kind: RegistryKind::Node,
                enabled,
                description: "fixture".to_owned(),
                host: host_id.to_owned(),
                role: "control".to_owned(),
                capabilities: Default::default(),
                allow_workloads: false,
                authoritative_state: true,
                gateway_endpoint: None,
            })),
        }
    }

    #[test]
    fn declared_hosts_keep_enabled_enrolled_placements_only() {
        let snapshot = Snapshot::build(
            1,
            vec![
                host("pc", true),
                host("laptop", false),
                node("pc-node", "pc", true),
                node("laptop-node", "laptop", true),
                node("disabled", "pc", false),
            ],
        )
        .expect("fixture snapshot");
        let hosts = declared_hosts(&snapshot, "pc-node");
        assert_eq!(hosts.len(), 1);
        assert!(hosts[0].local);
        assert_eq!(hosts[0].id, "pc");
        assert_eq!(hosts[0].tailscale, "pc-ts");
        assert_eq!(hosts[0].node, "pc-node");
    }

    #[test]
    fn remote_argv_runs_one_finite_child_on_the_declared_host() {
        let argv = sample_argv(Path::new("/nix/store/ssh"), "mini-ts", "mini-node", "mini");
        assert_eq!(argv[0], "/nix/store/ssh");
        // The child contract: one finite sample for one node, on that host,
        // with the tailscale name after `--` so it cannot read as a flag.
        assert!(argv.contains(&"--".to_owned()));
        assert_eq!(
            argv.iter().position(|word| word == "mini-ts"),
            Some(argv.iter().position(|word| word == "--").unwrap() + 1)
        );
        assert!(argv
            .windows(2)
            .any(|pair| pair == ["odin", "compute-sample"]));
        assert!(argv.windows(2).any(|pair| pair == ["--node", "mini-node"]));
        assert!(argv.windows(2).any(|pair| pair == ["--host", "mini"]));
    }
}
