//! Fetch and pin campaign stage bytes on the declared execution host.
use std::collections::{BTreeMap, HashSet};
use std::io::Read;
use std::path::{Component, Path};
use std::sync::Arc;

use odin_registry::{ObjectConfig, RegistryKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::claude_host_transport::ClaudeHostTransport;
use crate::kube_runtime::stage::VerifiedStage;

const DEFAULT_MAX_STAGE: u64 = 256 * 1024 * 1024;
const DEFAULT_MAX_RUN: u64 = 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    run_id: String,
    case_id: String,
    tar: String,
    sha256: String,
    bytes: u64,
    campaign: Option<String>,
    rung: Option<String>,
    params: BTreeMap<String, f64>,
}

#[derive(Deserialize)]
struct Run {
    schema: String,
    run_id: String,
    case_id: String,
    campaign: Option<String>,
    rung: Option<String>,
    node: Option<String>,
    params: BTreeMap<String, f64>,
}

pub(crate) struct StageTransport {
    registry: Arc<odin_registry::SnapshotHandle>,
    transport: ClaudeHostTransport,
}

impl StageTransport {
    pub(crate) fn new(
        registry: Arc<odin_registry::SnapshotHandle>,
        transport: ClaudeHostTransport,
    ) -> Self {
        Self {
            registry,
            transport,
        }
    }

    pub(crate) fn verify(
        &self,
        profile: &str,
        node: &str,
        bytes: &[u8],
    ) -> Result<VerifiedStage, String> {
        let mut manifest: Manifest =
            serde_json::from_slice(bytes).map_err(|e| format!("invalid stage manifest: {e}"))?;
        if manifest.schema != "project.stage/1"
            || manifest.bytes == 0
            || manifest.sha256.len() != 64
            || !manifest
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || manifest.params.values().any(|v| !v.is_finite())
        {
            return Err("invalid stage identity, size or digest".into());
        }
        if !valid_id(&manifest.run_id, "Run") || !valid_id(&manifest.case_id, "Case") {
            return Err("invalid stage run or case id".into());
        }
        let campaign = manifest
            .campaign
            .clone()
            .filter(|s| !s.is_empty())
            .ok_or("stage has no campaign")?;
        let rung = manifest
            .rung
            .clone()
            .filter(|s| !s.is_empty())
            .ok_or("stage has no rung")?;
        let snapshot = self.registry.current();
        let profile = snapshot
            .workload_profile_ref(profile)
            .map_err(|e| e.to_string())?;
        let limit = profile
            .profile
            .stage_max_bytes
            .map_or(DEFAULT_MAX_STAGE, std::num::NonZeroU64::get);
        let run_limit = profile
            .profile
            .stage_run_max_bytes
            .map_or(DEFAULT_MAX_RUN, std::num::NonZeroU64::get);
        if manifest.bytes > limit {
            return Err(format!("stage exceeds profile limit of {limit} bytes"));
        }
        let output_limit =
            usize::try_from(manifest.bytes).map_err(|_| "stage exceeds addressable memory")?;
        let object = snapshot
            .object(RegistryKind::Node, node)
            .ok_or("unknown stage node")?;
        let ObjectConfig::Node(declared) = &object.config else {
            return Err("invalid stage node".into());
        };
        if !declared.enabled || !declared.allow_workloads {
            return Err("stage node is disabled for workloads".into());
        }
        let host = snapshot
            .object(RegistryKind::Host, &declared.host)
            .ok_or("stage host is not declared")?;
        let ObjectConfig::Host(host) = &host.config else {
            return Err("invalid stage host".into());
        };
        if !host.enabled || !host.enrolled {
            return Err("stage host is not enrolled".into());
        }
        let path = Path::new(&manifest.tar);
        if !path.is_absolute()
            || path
                .components()
                .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        {
            return Err("invalid stage path".into());
        }
        let mut mounts = profile.profile.data.iter().filter(|mount| {
            path.strip_prefix(&mount.pod_path)
                .is_ok_and(|relative| !relative.as_os_str().is_empty())
                && declared.covers_data([mount.host_path.as_str()])
        });
        let mount = mounts
            .next()
            .ok_or("stage path is outside declared profile data mounts and node roots")?;
        if mounts.next().is_some() {
            return Err("ambiguous stage data mount".into());
        }
        let relative = path
            .strip_prefix(&mount.pod_path)
            .map_err(|e| e.to_string())?;
        let relative = relative.to_str().ok_or("stage path is not UTF-8")?;
        let request = serde_json::json!({"root": mount.host_path, "source": relative, "sha256": manifest.sha256, "bytes": manifest.bytes});
        let archive = self.transport.run_remote(
            &host.tailscale,
            crate::claude_host_transport::remote_command(PIN_SCRIPT),
            Some(request.to_string().as_bytes()),
            output_limit,
        )?;
        if archive.len() as u64 != manifest.bytes
            || format!("{:x}", Sha256::digest(&archive)) != manifest.sha256
        {
            return Err("stage bytes do not match manifest".into());
        }
        let run_bytes = staged_run_bytes(&archive, &manifest.run_id, run_limit)?;
        validate_staged_run(&run_bytes, &manifest, node)?;
        manifest.tar = format!(
            "{}/.odin-stage/{}.tar",
            mount.pod_path.trim_end_matches('/'),
            manifest.sha256
        );
        let pinned = serde_json::to_vec(&manifest).map_err(|e| e.to_string())?;
        Ok(VerifiedStage {
            campaign,
            rung,
            point: manifest.params,
            manifest: pinned,
            sha256: manifest.sha256,
        })
    }
}

fn validate_staged_run(bytes: &[u8], manifest: &Manifest, node: &str) -> Result<(), String> {
    let run: Run =
        serde_yaml::from_slice(bytes).map_err(|e| format!("invalid staged run record: {e}"))?;
    if run.params.values().any(|value| !value.is_finite()) {
        return Err("invalid staged run parameters".into());
    }
    if run.schema != "project.run/1"
        || run.run_id != manifest.run_id
        || run.case_id != manifest.case_id
        || run.campaign != manifest.campaign
        || run.rung != manifest.rung
        || run.node.as_deref() != Some(node)
        || run.params != manifest.params
    {
        return Err("stage run record does not match manifest".into());
    }
    Ok(())
}

fn staged_run_bytes(archive: &[u8], run_id: &str, run_limit: u64) -> Result<Vec<u8>, String> {
    let mut tar = tar::Archive::new(archive);
    let expected = format!("{run_id}/run.yaml");
    let mut run_bytes = None;
    let mut paths = HashSet::new();
    for entry in tar
        .entries()
        .map_err(|e| format!("invalid stage tar: {e}"))?
    {
        let mut entry = entry.map_err(|e| format!("invalid stage tar entry: {e}"))?;
        let entry_path = entry.path().map_err(|e| e.to_string())?.into_owned();
        let mut components = entry_path.components();
        if components.next() != Some(Component::Normal(run_id.as_ref()))
            || components.any(|part| !matches!(part, Component::Normal(_)))
            || !paths.insert(entry_path.to_path_buf())
            || !(entry.header().entry_type().is_file() || entry.header().entry_type().is_dir())
        {
            return Err("unsafe or duplicate stage tar entry".into());
        }
        if entry_path == Path::new(&expected) {
            if run_bytes.is_some()
                || !entry.header().entry_type().is_file()
                || entry.size() > run_limit
            {
                return Err("invalid or duplicate staged run record".into());
            }
            let mut content = Vec::new();
            entry.read_to_end(&mut content).map_err(|e| e.to_string())?;
            run_bytes = Some(content);
        }
    }
    run_bytes.ok_or_else(|| "stage has no run record".into())
}

fn valid_id(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|digits| digits.len() == 5 && digits.bytes().all(|b| b.is_ascii_digit()))
}

// Walk from an open root without following symlinks; pin the exact bytes under a
// digest name. Existing pins are rechecked and never overwritten.
const PIN_SCRIPT: &str = r#"
import hashlib, json, os, stat, sys
r = json.load(sys.stdin)
root = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
for part in r['root'].split('/'):
    if not part: continue
    if part in ('.', '..'): raise ValueError('invalid root')
    n = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root); os.close(root); root=n
parts = r['source'].split('/')
if not parts or any(p in ('', '.', '..') for p in parts): raise ValueError('invalid source')
d = os.dup(root)
for part in parts[:-1]:
    n = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=d); os.close(d); d=n
src = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=d)
if not stat.S_ISREG(os.fstat(src).st_mode): raise ValueError('source is not regular')
try: os.mkdir('.odin-stage', 0o755, dir_fd=root)
except FileExistsError: pass
pin = os.open('.odin-stage', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
if os.fstat(pin).st_uid != os.geteuid() or os.fstat(pin).st_mode & 0o022: raise ValueError('untrusted pin directory')
os.fchmod(pin, 0o755)
name = r['sha256'] + '.tar'
# Build a private temporary file before publishing with a non-replacing link.
tmpname = '.tmp-' + os.urandom(16).hex()
out = os.open(tmpname, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=pin)
h = hashlib.sha256(); size = 0
try:
    while True:
        chunk = os.read(src, 1048576)
        if not chunk: break
        size += len(chunk)
        if size > r['bytes']: raise ValueError('stage too large')
        h.update(chunk)
        view = memoryview(chunk)
        while view: view = view[os.write(out, view):]
    if size != r['bytes'] or h.hexdigest() != r['sha256']: raise ValueError('stage digest mismatch')
    os.fchmod(out, 0o444); os.fsync(out); os.close(out); out = -1
    try: os.link(tmpname, name, src_dir_fd=pin, dst_dir_fd=pin, follow_symlinks=False)
    except FileExistsError: pass
finally:
    if out != -1: os.close(out)
    os.unlink(tmpname, dir_fd=pin)
f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=pin)
if not stat.S_ISREG(os.fstat(f).st_mode) or os.fstat(f).st_uid != os.geteuid() or os.fstat(f).st_mode & 0o222: raise ValueError('untrusted pin file')
h = hashlib.sha256(); size = 0
while True:
    chunk = os.read(f, 1048576)
    if not chunk: break
    size += len(chunk)
    if size > r['bytes']: raise ValueError('pin too large')
    h.update(chunk)
if size != r['bytes'] or h.hexdigest() != r['sha256']: raise ValueError('pin digest mismatch')
os.lseek(f, 0, os.SEEK_SET)
remaining = r['bytes']
while remaining:
    chunk = os.read(f, min(1048576, remaining))
    if not chunk: raise ValueError('pin changed while streaming')
    remaining -= len(chunk)
    sys.stdout.buffer.write(chunk)
"#;

#[cfg(test)]
mod tests {
    use super::{staged_run_bytes, validate_staged_run, Manifest, DEFAULT_MAX_RUN};

    fn manifest() -> Manifest {
        serde_json::from_str(r#"{"schema":"project.stage/1","run_id":"Run00001","case_id":"Case00001","tar":"/data/stage.tar","sha256":"abc","bytes":1,"campaign":"campaign","rung":"rung","params":{"axis":1.0}}"#).unwrap()
    }

    fn run(params: &str) -> String {
        format!("schema: project.run/1\nrun_id: Run00001\ncase_id: Case00001\ncampaign: campaign\nrung: rung\nnode: node\n{params}\n")
    }

    #[test]
    fn staged_parameters_require_complete_numeric_finite_map() {
        let manifest = manifest();
        assert!(
            validate_staged_run(run("params: {axis: 1}").as_bytes(), &manifest, "node").is_ok()
        );
        for params in [
            "params: {axis: 1, extra: bad}",
            "params: {axis: 1, extra: null}",
            "params: {axis: 1, extra: true}",
            "params: {axis: 1, extra: [2]}",
            "params: {axis: 1, extra: .nan}",
            "params: {axis: 1, extra: .inf}",
            "params: {axis: 1, extra: -.inf}",
            "params: {axis: 1, extra: 2}",
            "params: {}",
            "",
        ] {
            assert!(
                validate_staged_run(run(params).as_bytes(), &manifest, "node").is_err(),
                "accepted {params}"
            );
        }
    }

    #[test]
    fn stage_manifest_requires_params() {
        let mut value = serde_json::to_value(manifest()).unwrap();
        value.as_object_mut().unwrap().remove("params");
        assert!(serde_json::from_value::<Manifest>(value).is_err());
    }

    #[test]
    fn staged_run_limit_respects_boundaries_and_explicit_larger_limits() {
        let bytes = vec![b'x'; DEFAULT_MAX_RUN as usize + 1];
        let mut archive = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, "Run00001/run.yaml", bytes.as_slice())
            .unwrap();
        let archive = archive.into_inner().unwrap();

        assert!(staged_run_bytes(&archive, "Run00001", DEFAULT_MAX_RUN).is_err());
        assert!(staged_run_bytes(&archive, "Run00001", bytes.len() as u64 - 1).is_err());
        assert_eq!(
            staged_run_bytes(&archive, "Run00001", bytes.len() as u64).unwrap(),
            bytes
        );
    }
}
