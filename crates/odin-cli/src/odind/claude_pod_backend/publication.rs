//! Exact-branch publication across the untrusted pod boundary.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use odin_kube::{
    claude_pod::{self, ClaudePodReceipt},
    exec::WorkloadLauncherSpec,
    KubeClient,
};
use serde_json::{json, Value};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const LIMIT: usize = 32 * 1024 * 1024;
const WIRE_LIMIT: usize = LIMIT * 4 / 3 + 65536;
const DEADLINE: Duration = Duration::from_secs(90);
// Fixed program: no pod-provided command, pathname, URL or interpreter argument.
const QUEUE: &str = r#"
import base64,ctypes,json,os,re,stat,sys
# Isolated interpreter imports only image-owned modules; never inspect agent Git
# configuration or queue bytes with the root supervisor's credentials.
os.chdir('/')
libc=ctypes.CDLL(None,use_errno=True)
if libc.prctl(38,1,0,0,0)!=0: raise OSError(ctypes.get_errno(),'no_new_privs')
if os.geteuid()==0:
 os.setgroups([]); os.setgid(1000); os.setuid(1000)
if os.geteuid()!=1000 or os.getegid()!=1000: raise ValueError('publication uid')
class Header(ctypes.Structure):
 _fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
class Cap(ctypes.Structure):
 _fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
if libc.capset(ctypes.byref(Header(0x20080522,0)),ctypes.byref((Cap*2)()))!=0: raise OSError(ctypes.get_errno(),'capset')
a=json.load(sys.stdin)
def queue():
 fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
 try:
  for part in ('workspace','.odin-claude','publish'):
   child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
   os.close(fd); fd=child
  return fd
 except BaseException:
  os.close(fd); raise
def bounded(fd,name,limit):
 child=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
 with os.fdopen(child,'rb') as f:
  info=os.fstat(f.fileno())
  if not stat.S_ISREG(info.st_mode) or info.st_size>limit: raise ValueError('publication file bound')
  data=f.read(limit+1)
  if len(data)>limit: raise ValueError('publication file bound')
  return data
if a['op']=='scan':
 out=[]
 try: fd=queue()
 except FileNotFoundError: fd=None
 if fd is not None:
  try:
   with os.scandir(fd) as entries:
    for index,p in enumerate(entries):
     if index>=4096: raise ValueError('publication queue exceeds entry bound')
     if len(out)>=1: break
     if not re.fullmatch(r'[0-9a-f]{32}\.request',p.name): continue
     n=p.name[:-8]
     try: os.stat(n+'.ack',dir_fd=fd,follow_symlinks=False); continue
     except FileNotFoundError: pass
     r=json.loads(bounded(fd,p.name,4096)); r['file_nonce']=n
     if r.get('kind')=='push': r['bundle']=base64.b64encode(bounded(fd,n+'.bundle',33554432)).decode()
     out.append(r)
  finally: os.close(fd)
 print(json.dumps({'requests':out}))
elif a['op']=='ack':
 n=a['ack']['nonce']
 if not re.fullmatch('[0-9a-f]{32}',n): raise ValueError('nonce')
 fd=queue()
 try:
  t=n+'.ack.tmp'
  try: os.unlink(t,dir_fd=fd)
  except FileNotFoundError: pass
  child=os.open(t,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
  with os.fdopen(child,'w') as f: json.dump(a['ack'],f); f.flush(); os.fsync(f.fileno())
  os.rename(t,n+'.ack',src_dir_fd=fd,dst_dir_fd=fd); os.fsync(fd)
 finally: os.close(fd)
 print('{}')
elif a['op']=='clean':
 import subprocess
 def git(*v): return subprocess.check_output(['/bin/git','-C','/workspace/repo','-c','core.hooksPath=/dev/null',*v],timeout=30,env={'PATH':'/bin','HOME':'/home/claude','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_TERMINAL_PROMPT':'0'}).decode().strip()
 print(json.dumps({'tip':git('rev-parse','HEAD'),'branch':git('symbolic-ref','HEAD'),'dirty':bool(git('status','--porcelain','--untracked-files=all'))}))
"#;

async fn rpc(
    client: &KubeClient,
    receipt: &ClaudePodReceipt,
    value: Value,
) -> Result<Value, String> {
    tokio::time::timeout(DEADLINE, async {
        let launcher = WorkloadLauncherSpec {
            launcher_path: "/bin/python3".into(),
            arguments: vec!["-I".into(), "-c".into(), QUEUE.into()],
        };
        let stream = claude_pod::exec(client, receipt, &launcher)
            .await
            .map_err(|e| e.to_string())?;
        let odin_kube::exec::WorkloadExecStream {
            mut stdin,
            mut stdout,
            stderr,
            exit,
            ..
        } = stream;
        let input = serde_json::to_vec(&value).map_err(|e| e.to_string())?;
        let send = async {
            stdin.write_all(&input).await.map_err(|e| e.to_string())?;
            stdin.shutdown().await.map_err(|e| e.to_string())
        };
        let receive = async {
            let mut bytes = Vec::new();
            (&mut stdout)
                .take((WIRE_LIMIT + 1) as u64)
                .read_to_end(&mut bytes)
                .await
                .map_err(|e| e.to_string())?;
            if bytes.len() > WIRE_LIMIT {
                return Err("publication response exceeds bound".into());
            }
            Ok::<_, String>(bytes)
        };
        let drain = async {
            if let Some(mut stderr) = stderr {
                tokio::io::copy(&mut stderr, &mut tokio::io::sink())
                    .await
                    .map_err(|e| e.to_string())?;
            }
            Ok::<_, String>(())
        };
        let (sent, received, drained, status) = tokio::join!(send, receive, drain, exit);
        sent?;
        drained?;
        let bytes = received?;
        if status.is_some() {
            return Err("publication transport failed".into());
        }
        serde_json::from_slice(&bytes).map_err(|e| e.to_string())
    })
    .await
    .map_err(|_| "publication transport timed out".to_owned())?
}

fn branch_ref(branch: &str) -> Result<String, String> {
    let name = branch
        .strip_prefix("claude/")
        .ok_or("publication branch is not allowed")?;
    if name.is_empty()
        || name.len() > 80
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("publication branch is not allowed".into());
    }
    Ok(format!("refs/heads/{branch}"))
}
fn oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|b| b.is_ascii_hexdigit())
}
fn nonce(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(super) fn read_only_git(root: &Path, args: &[&str]) -> Result<String, String> {
    match args {
        ["remote", "get-url", "origin"]
        | ["rev-parse", "HEAD"]
        | ["rev-parse", "--verify", "HEAD^{commit}"] => git(root, args),
        ["for-each-ref", "--format=%(objectname)", reference]
            if reference
                .strip_prefix("refs/heads/")
                .is_some_and(|branch| branch_ref(branch).is_ok()) =>
        {
            git(root, args)
        }
        _ => Err("Git observation is not allowlisted".into()),
    }
}

// Files rather than reader threads ensure a timed-out Git cannot retain a pipe
// through an ssh child. Every invocation is killed/reaped and output is bounded.
fn git(root: &Path, args: &[&str]) -> Result<String, String> {
    odin_omp::live::capsules::bounded_git_in(root, args, DEADLINE)
        .map(|output| output.trim().to_owned())
}
fn origin(project: &Path) -> Result<String, String> {
    let url = git(project, &["config", "--get", "remote.origin.url"])?;
    if url.is_empty() || url.starts_with('-') || url.contains('\n') || url.contains('\0') {
        return Err("invalid host origin".into());
    }
    Ok(url)
}
pub(super) fn remote_tip(project_root: &Path, branch: &str) -> Result<Option<String>, String> {
    advertised(project_root, &origin(project_root)?, &branch_ref(branch)?)
}
fn advertised(root: &Path, url: &str, reference: &str) -> Result<Option<String>, String> {
    let text = git(root, &["ls-remote", "--refs", url, reference])?;
    if text.is_empty() {
        return Ok(None);
    }
    let fields: Vec<_> = text.split_whitespace().collect();
    if fields.len() != 2 || fields[1] != reference || !oid(fields[0]) {
        return Err("origin advertised an invalid exact ref".into());
    }
    Ok(Some(fields[0].to_owned()))
}
fn durable(path: &Path, value: &Value) -> Result<(), String> {
    let temporary = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temporary)
        .map_err(|e| e.to_string())?;
    file.write_all(&serde_json::to_vec(value).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    fs::rename(temporary, path).map_err(|e| e.to_string())?;
    fs::File::open(path.parent().ok_or("missing parent")?)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())
}
fn state_dir(state_root: &Path, receipt: &ClaudePodReceipt) -> PathBuf {
    let key: String = receipt
        .worker
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    state_root.join("publication").join(key)
}
fn load(path: &Path) -> Result<Value, String> {
    serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

fn quarantine(
    directory: &Path,
    branch: &str,
    request: &Value,
) -> Result<(PathBuf, String, usize), String> {
    let reference = branch_ref(branch)?;
    let tip = request["tip"]
        .as_str()
        .filter(|s| oid(s))
        .ok_or("invalid publication tip")?;
    let encoded = request["bundle"].as_str().ok_or("missing bundle")?;
    if encoded.len() > LIMIT.div_ceil(3) * 4 {
        return Err("publication bundle exceeds bound".into());
    }
    let bundle = STANDARD
        .decode(encoded)
        .map_err(|_| "invalid bundle encoding")?;
    if bundle.len() > LIMIT {
        return Err("publication bundle exceeds bound".into());
    }
    let size = bundle.len();
    let quarantine = directory.join("quarantine");
    if quarantine.exists() {
        fs::remove_dir_all(&quarantine).map_err(|e| e.to_string())?;
    }
    fs::create_dir(&quarantine).map_err(|e| e.to_string())?;
    git(&quarantine, &["init", "--bare", "--template="])?;
    let bundle_path = quarantine.join("incoming.bundle");
    fs::write(&bundle_path, bundle).map_err(|e| e.to_string())?;
    let bundle_path = bundle_path.to_str().ok_or("non-UTF8 broker path")?;
    let heads = git(&quarantine, &["bundle", "list-heads", bundle_path])?;
    if heads != format!("{tip} {reference}") {
        return Err("bundle must advertise only the assigned branch and tip".into());
    }
    git(&quarantine, &["bundle", "verify", bundle_path])?;
    git(
        &quarantine,
        &[
            "fetch",
            "--no-tags",
            "--no-write-fetch-head",
            bundle_path,
            &format!("{reference}:{reference}"),
        ],
    )?;
    if git(
        &quarantine,
        &["rev-parse", &format!("{reference}^{{commit}}")],
    )? != tip
    {
        return Err("bundle tip is not the requested commit".into());
    }
    git(&quarantine, &["fsck", "--strict", "--full"])?;
    Ok((quarantine, tip.to_owned(), size))
}

pub(super) fn validate_candidate(
    receipt: &ClaudePodReceipt,
    project: &Path,
    project_id: &str,
    session: &str,
    state_root: &Path,
    request: &Value,
) -> Result<Value, String> {
    if project_id.is_empty() {
        return Err("missing publication project identity".into());
    }
    let id = request["file_nonce"]
        .as_str()
        .filter(|s| nonce(s))
        .ok_or("invalid request filename")?;
    if request["nonce"] != id
        || request["session"] != session
        || request["branch"] != receipt.branch
    {
        return Err("publication request differs from immutable binding".into());
    }
    let reference = branch_ref(&receipt.branch)?;
    let directory = state_dir(state_root, receipt);
    fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
    let (commit, size) = match request["kind"].as_str() {
        Some("push") => {
            let (_, tip, size) = quarantine(&directory, &receipt.branch, request)?;
            (Some(tip), size)
        }
        Some("list") => (None, 0),
        _ => return Err("unsupported publication operation".into()),
    };
    let digest = blake3::hash(&serde_json::to_vec(request).map_err(|e| e.to_string())?)
        .to_hex()
        .to_string();
    Ok(
        json!({"request_id":id,"session":session,"project":project_id,"project_root":fs::canonicalize(project).map_err(|e| e.to_string())?,"branch":reference,"commit":commit,"size":size,"request_digest":digest,"kind":request["kind"]}),
    )
}

fn publish(
    project: &Path,
    directory: &Path,
    branch: &str,
    request: &Value,
) -> Result<String, String> {
    let reference = branch_ref(branch)?;
    let (quarantine, tip, _) = quarantine(directory, branch, request)?;
    let url = origin(project)?;
    if advertised(&quarantine, &url, &reference)?.as_deref() != Some(tip.as_str()) {
        git(
            &quarantine,
            &[
                "push",
                "--porcelain",
                "--no-verify",
                &url,
                &format!("{reference}:{reference}"),
            ],
        )?;
    }
    if advertised(&quarantine, &url, &reference)?.as_deref() != Some(tip.as_str()) {
        return Err("origin did not confirm published tip".into());
    }
    Ok(tip)
}

pub(super) async fn discover(
    client: &KubeClient,
    receipt: &ClaudePodReceipt,
) -> Result<Vec<Value>, String> {
    let mut response = rpc(client, receipt, json!({"op":"scan"})).await?;
    let requests = response["requests"]
        .as_array_mut()
        .ok_or("invalid publication scan")?;
    if requests.len() > 1 {
        return Err("publication scan exceeds bound".into());
    }
    Ok(std::mem::take(requests))
}

pub(super) fn perform(
    receipt: &ClaudePodReceipt,
    project_root: &Path,
    project_id: &str,
    session: &str,
    state_root: &Path,
    request: &Value,
    admitted: &Value,
) -> Result<Value, String> {
    if &validate_candidate(
        receipt,
        project_root,
        project_id,
        session,
        state_root,
        request,
    )? != admitted
    {
        return Err("publication candidate changed after admission".into());
    }
    branch_ref(&receipt.branch)?;
    let directory = state_dir(state_root, receipt);
    fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
    let binding = json!({"project":fs::canonicalize(project_root).map_err(|e| e.to_string())?,"project_id":project_id,"branch":receipt.branch,"session":session,"origin":origin(project_root)?});
    let binding_path = directory.join("binding.json");
    if binding_path.exists() {
        if load(&binding_path)? != binding {
            return Err("publication binding changed".into());
        }
    } else {
        durable(&binding_path, &binding)?;
    }
    let mut events = Vec::new();
    let id = request["file_nonce"]
        .as_str()
        .filter(|s| nonce(s))
        .ok_or("invalid request filename")?;
    let ack_path = directory.join(format!("{id}.json"));
    let identity = admitted.clone();
    let ack = if ack_path.exists() {
        let previous = load(&ack_path)?;
        if previous["request"] != identity {
            return Err("publication nonce reused with different request".into());
        }
        if request["kind"] == "push"
            && remote_tip(project_root, &receipt.branch)?.as_deref() != request["tip"].as_str()
        {
            return Err("replayed publication is no longer the exact remote tip".into());
        }
        previous["ack"].clone()
    } else {
        let result = if request["nonce"] != id
            || request["session"] != session
            || request["branch"] != receipt.branch
        {
            Err("publication request differs from immutable binding".to_owned())
        } else {
            match request["kind"].as_str() {
                Some("list") => remote_tip(project_root, &receipt.branch),
                Some("push") => {
                    publish(project_root, &directory, &receipt.branch, request).map(Some)
                }
                _ => Err("unsupported publication operation".into()),
            }
        };
        let tip = result?;
        if request["kind"] == "push" {
            durable(
                &directory.join("published.json"),
                &json!({"tip":tip,"branch":receipt.branch,"project":binding["project"]}),
            )?;
            events.push(json!({"type":"branch_published","branch":receipt.branch,"commit":tip}));
        }
        let ack = json!({"nonce":id,"ok":true,"tip":tip});
        durable(&ack_path, &json!({"request":identity,"ack":ack}))?;
        ack
    };
    let mut result = admitted.clone();
    result["ack"] = ack.clone();
    result["events"] = json!(events);
    result["remote_result"] = ack;
    Ok(result)
}

pub(super) async fn acknowledge(
    client: &KubeClient,
    receipt: &ClaudePodReceipt,
    result: &Value,
) -> Result<(), String> {
    rpc(client, receipt, json!({"op":"ack","ack":result["ack"]})).await?;
    Ok(())
}

/// Called only after the worker has durably recorded denial or uncertainty.
/// A fixed negative acknowledgment retires the queue head without granting replay.
pub(super) async fn reject(
    client: &KubeClient,
    receipt: &ClaudePodReceipt,
    request: &Value,
) -> Result<(), String> {
    let id = request["file_nonce"]
        .as_str()
        .filter(|value| nonce(value))
        .ok_or("invalid request filename")?;
    rpc(client, receipt, json!({"op":"ack","ack":{"nonce":id,"ok":false,"error":"publication denied or uncertain; automatic replay is forbidden"}})).await?;
    Ok(())
}

pub(super) async fn clean(
    client: &KubeClient,
    receipt: &ClaudePodReceipt,
    project_root: &Path,
    state_root: &Path,
    baseline: &str,
    discard_unpushed: bool,
) -> Result<bool, String> {
    let pod = rpc(client, receipt, json!({"op":"clean"})).await?;
    if !clean_workspace(&pod, &receipt.branch)? {
        return Ok(false);
    }
    if discard_unpushed {
        return Ok(true);
    }
    let directory = state_dir(state_root, receipt);
    let path = directory.join("published.json");
    if !path.exists() {
        return Ok(oid(baseline)
            && pod["dirty"] == false
            && pod["tip"] == baseline
            && pod["branch"] == branch_ref(&receipt.branch)?);
    }
    let published = load(&path)?;
    let binding = load(&directory.join("binding.json"))?;
    let project = serde_json::to_value(fs::canonicalize(project_root).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    if published["project"] != project
        || published["branch"] != receipt.branch
        || binding["origin"] != origin(project_root)?
    {
        return Err("publication custody binding changed".into());
    }
    let tip = published["tip"]
        .as_str()
        .ok_or("invalid durable publication tip")?;
    if remote_tip(project_root, &receipt.branch)?.as_deref() != Some(tip) {
        return Ok(false);
    }
    Ok(pod["dirty"] == false && pod["tip"] == tip && pod["branch"] == branch_ref(&receipt.branch)?)
}

fn clean_workspace(pod: &Value, branch: &str) -> Result<bool, String> {
    Ok(pod["dirty"] == false
        && pod["tip"].as_str().is_some_and(oid)
        && pod["branch"] == branch_ref(branch)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dirty_workspace_never_passes_discard_gate() {
        let tip = "1111111111111111111111111111111111111111";
        assert!(!clean_workspace(
            &json!({"dirty":true,"tip":tip,"branch":"refs/heads/claude/test"}),
            "claude/test"
        )
        .unwrap());
        assert!(!clean_workspace(
            &json!({"tip":tip,"branch":"refs/heads/claude/test"}),
            "claude/test"
        )
        .unwrap());
        assert!(clean_workspace(
            &json!({"dirty":false,"tip":tip,"branch":"refs/heads/claude/test"}),
            "claude/test"
        )
        .unwrap());
    }
    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("project");
        let remote = temp.path().join("remote");
        let state = temp.path().join("state");
        for p in [&project, &remote, &state] {
            fs::create_dir(p).unwrap();
        }
        git(&remote, &["init", "--bare", "--template="]).unwrap();
        git(&project, &["init", "--template="]).unwrap();
        git(&project, &["config", "user.name", "Broker test"]).unwrap();
        git(
            &project,
            &["config", "user.email", "broker@example.invalid"],
        )
        .unwrap();
        git(
            &project,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        )
        .unwrap();
        git(&project, &["checkout", "-b", "claude/test"]).unwrap();
        fs::write(project.join("file"), "one").unwrap();
        git(&project, &["add", "file"]).unwrap();
        git(&project, &["commit", "-m", "one"]).unwrap();
        (temp, project, remote, state)
    }
    fn request(project: &Path, branch: &str) -> Value {
        let reference = format!("refs/heads/{branch}");
        let bundle = project.join("test.bundle");
        git(
            project,
            &["bundle", "create", bundle.to_str().unwrap(), &reference],
        )
        .unwrap();
        json!({"tip":git(project,&["rev-parse",&reference]).unwrap(),"bundle":STANDARD.encode(fs::read(bundle).unwrap())})
    }
    #[test]
    fn exact_branch_publication_and_replay() {
        let (_temp, project, _remote, state) = fixture();
        let input = request(&project, "claude/test");
        assert_eq!(remote_tip(&project, "claude/test").unwrap(), None);
        let tip = publish(&project, &state, "claude/test", &input).unwrap();
        assert_eq!(
            remote_tip(&project, "claude/test").unwrap().as_deref(),
            Some(tip.as_str())
        );
        assert_eq!(
            publish(&project, &state, "claude/test", &input).unwrap(),
            tip
        );
    }
    #[test]
    fn rejects_other_refs_and_forged_tip() {
        let (_temp, project, _remote, state) = fixture();
        let mut input = request(&project, "claude/test");
        for branch in [
            "main",
            "refs/tags/x",
            "claude/../main",
            "claude/",
            "claude/a/b",
        ] {
            assert!(publish(&project, &state, branch, &input).is_err());
        }
        assert!(publish(&project, &state, "claude/other", &input).is_err());
        input["tip"] = json!("0000000000000000000000000000000000000000");
        assert!(publish(&project, &state, "claude/test", &input).is_err());
    }
    #[test]
    fn refuses_non_fast_forward() {
        let (_temp, project, _remote, state) = fixture();
        let old = request(&project, "claude/test");
        fs::write(project.join("file"), "two").unwrap();
        git(&project, &["commit", "-am", "two"]).unwrap();
        let new = request(&project, "claude/test");
        publish(&project, &state, "claude/test", &new).unwrap();
        assert!(publish(&project, &state, "claude/test", &old).is_err());
        assert_eq!(
            remote_tip(&project, "claude/test").unwrap().as_deref(),
            new["tip"].as_str()
        );
    }
    #[test]
    fn rejects_bundle_with_extra_advertised_ref() {
        let (_temp, project, _remote, state) = fixture();
        git(&project, &["branch", "claude/other"]).unwrap();
        let bundle = project.join("extra.bundle");
        git(
            &project,
            &[
                "bundle",
                "create",
                bundle.to_str().unwrap(),
                "refs/heads/claude/test",
                "refs/heads/claude/other",
            ],
        )
        .unwrap();
        let input = json!({"tip":git(&project, &["rev-parse", "HEAD"]).unwrap(),"bundle":STANDARD.encode(fs::read(bundle).unwrap())});
        assert!(publish(&project, &state, "claude/test", &input).is_err());
        assert_eq!(remote_tip(&project, "claude/test").unwrap(), None);
    }
}
