//! The test harness every family uses: a runner that runs the inner command
//! without bwrap, fake executables, a context over a temp dir, a loopback
//! HTTP fake, a fake desktop, and an argv check. No test needs network, bwrap or Nix.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde_json::Value;
use url::Url;

use crate::config::{Root, ToolsConfig};
use crate::desk::{Desk, Transfer};
use crate::http::Method;
use crate::sandbox::{read_streams, RunFault, RunOutput, RunSpec, Runner};
use crate::{Ctx, SCRATCH_ROOT};

/// The bwrap path test contexts carry; `LocalRunner` never runs it.
pub const TEST_BWRAP: &str = "/nix/store/0-bubblewrap/bin/bwrap";

/// Runs the argv after bwrap's `--` directly, with the spec's environment;
/// kills it at the timeout.
pub struct LocalRunner;

impl Runner for LocalRunner {
    fn run(&self, spec: &RunSpec, on_line: &mut dyn FnMut(&str)) -> Result<RunOutput, RunFault> {
        let inner = spec.inner_argv();
        let (program, args) = inner
            .split_first()
            .ok_or_else(|| RunFault::NotStarted("the spec has no command".to_owned()))?;
        let stdin = match &spec.stdin {
            Some(path) => std::fs::File::open(path)
                .map(Stdio::from)
                .map_err(|error| {
                    RunFault::NotStarted(format!("stdin {}: {error}", path.display()))
                })?,
            None => Stdio::null(),
        };
        let mut child = Command::new(program)
            .args(args)
            .env_clear()
            .envs(spec.env.iter().map(|(key, value)| (key, value)))
            .stdin(stdin)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| RunFault::NotStarted(error.to_string()))?;
        let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
            return Err(RunFault::Lost("the child has no output pipes".to_owned()));
        };
        let streams = read_streams(stdout, stderr, spec, on_line);
        if streams.timed_out {
            let _ = child.kill();
        }
        let status = child
            .wait()
            .map_err(|error| RunFault::Lost(error.to_string()))?;
        Ok(RunOutput {
            code: if streams.timed_out {
                None
            } else {
                status.code()
            },
            timed_out: streams.timed_out,
            stdout: streams.stdout,
            stderr_tail: streams.stderr_tail,
        })
    }
}

/// A `#!/bin/sh` stand-in for a declared executable, using shell builtins only.
pub struct FakeExe {
    path: PathBuf,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit: i32,
    files: Vec<(PathBuf, Vec<u8>)>,
}

impl FakeExe {
    pub fn new(dir: &Path, name: &str) -> Self {
        Self {
            path: dir.join(name),
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit: 0,
            files: Vec::new(),
        }
    }

    pub fn stdout(mut self, bytes: impl AsRef<[u8]>) -> Self {
        self.stdout = bytes.as_ref().to_vec();
        self
    }

    pub fn stderr(mut self, bytes: impl AsRef<[u8]>) -> Self {
        self.stderr = bytes.as_ref().to_vec();
        self
    }

    pub fn exit(mut self, code: i32) -> Self {
        self.exit = code;
        self
    }

    /// A file the fake writes when it runs, as the real tool would.
    pub fn file(mut self, path: impl AsRef<Path>, bytes: impl AsRef<[u8]>) -> Self {
        self.files
            .push((path.as_ref().to_path_buf(), bytes.as_ref().to_vec()));
        self
    }

    /// Writes the script and returns its path. Each run records its
    /// arguments, one per line, in `<path>.args` (see `recorded_args`).
    pub fn install(self) -> PathBuf {
        let mut script = String::from("#!/bin/sh\n");
        script.push_str(&format!(
            "for a in \"$@\"; do printf '%s\\n' \"$a\"; done > {}\n",
            quote(&self.path.with_extension("args"))
        ));
        for (path, bytes) in &self.files {
            script.push_str(&format!(
                "printf '%b' '{}' > {}\n",
                octal(bytes),
                quote(path)
            ));
        }
        script.push_str(&format!("printf '%b' '{}'\n", octal(&self.stdout)));
        script.push_str(&format!("printf '%b' '{}' >&2\n", octal(&self.stderr)));
        script.push_str(&format!("exit {}\n", self.exit));
        std::fs::write(&self.path, script).expect("write fake executable");
        let mut permissions = std::fs::metadata(&self.path)
            .expect("fake executable metadata")
            .permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
        std::fs::set_permissions(&self.path, permissions).expect("make fake executable runnable");
        self.path
    }
}

/// The arguments of the fake's last run.
pub fn recorded_args(fake: &Path) -> Vec<String> {
    std::fs::read_to_string(fake.with_extension("args"))
        .map(|text| text.lines().map(str::to_owned).collect())
        .unwrap_or_default()
}

fn octal(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("\\0{byte:03o}")).collect()
}

fn quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}

/// A context over `dir`: the given declarations, a writable `scratch` root at
/// `dir/scratch` unless one is given, the `LocalRunner`, and `TEST_BWRAP`.
pub fn ctx_for(
    dir: &Path,
    exes: &[(&str, &Path)],
    roots: &[(&str, &Path, bool)],
    secrets: &[(&str, &Path)],
    endpoints: &[(&str, &str)],
) -> Ctx {
    let mut config = ToolsConfig {
        executables: exes
            .iter()
            .map(|(key, path)| ((*key).to_owned(), path.to_path_buf()))
            .collect(),
        roots: roots
            .iter()
            .map(|(key, path, writable)| {
                let root = Root {
                    path: path.to_path_buf(),
                    writable: *writable,
                };
                ((*key).to_owned(), root)
            })
            .collect(),
        secrets: secrets
            .iter()
            .map(|(key, path)| ((*key).to_owned(), path.to_path_buf()))
            .collect(),
        endpoints: endpoints
            .iter()
            .map(|(key, url)| ((*key).to_owned(), Url::parse(url).expect("endpoint url")))
            .collect(),
    };
    config
        .roots
        .entry(SCRATCH_ROOT.to_owned())
        .or_insert_with(|| Root {
            path: dir.join(SCRATCH_ROOT),
            writable: true,
        });
    Ctx::new(
        config,
        Some(PathBuf::from(TEST_BWRAP)),
        Arc::new(LocalRunner),
    )
}

/// Panics unless `expected` appears as one contiguous run in the spec's argv.
pub fn assert_bwrap(spec: &RunSpec, expected: &[&str]) {
    let argv: Vec<String> = spec
        .argv
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    assert!(
        argv.windows(expected.len())
            .any(|window| window == expected),
        "bwrap argv lacks {expected:?}: {argv:?}"
    );
}

/// One request the fake server saw.
#[derive(Clone, Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    /// Lowercased names.
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// The requests a `FakeHttp` recorded, in arrival order.
#[derive(Clone, Default)]
pub struct Recorded(Arc<Mutex<Vec<Request>>>);

impl Recorded {
    pub fn requests(&self) -> Vec<Request> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// A route's replies, `(status, body)`: the nth request gets the nth, and the last repeats.
type Replies<'a> = &'a [(u16, &'a str)];

/// A loopback HTTP server on port 0 answering fixed routes (exact method and
/// path, query included); anything else is 404.
pub struct FakeHttp;

impl FakeHttp {
    pub fn start(routes: &[(Method, &str, u16, &str)]) -> (Url, Recorded) {
        Self::serve(
            routes
                .iter()
                .map(|(method, path, status, body)| Route::new(*method, path, &[(*status, *body)]))
                .collect(),
        )
    }

    /// Like `start`, with each route answering through its replies in order, so a
    /// read after a write can differ from the read before it.
    pub fn start_sequenced(routes: &[(Method, &str, Replies<'_>)]) -> (Url, Recorded) {
        Self::serve(
            routes
                .iter()
                .map(|(method, path, replies)| Route::new(*method, path, replies))
                .collect(),
        )
    }

    fn serve(mut routes: Vec<Route>) -> (Url, Recorded) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind loopback");
        let address = listener.local_addr().expect("local address");
        let recorded = Recorded::default();
        let sink = recorded.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                if let Some(request) = answer(stream, &mut routes) {
                    sink.0
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(request);
                }
            }
        });
        let url = Url::parse(&format!("http://{address}")).expect("fake url");
        (url, recorded)
    }
}

struct Route {
    method: Method,
    path: String,
    replies: Vec<(u16, String)>,
    hits: usize,
}

impl Route {
    fn new(method: Method, path: &str, replies: Replies<'_>) -> Self {
        Self {
            method,
            path: path.to_owned(),
            replies: replies
                .iter()
                .map(|(status, body)| (*status, (*body).to_owned()))
                .collect(),
            hits: 0,
        }
    }
}

fn answer(stream: TcpStream, routes: &mut [Route]) -> Option<Request> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let (method, path) = (parts.next()?.to_owned(), parts.next()?.to_owned());
    let mut headers = Vec::new();
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
    }
    let length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0; length];
    reader.read_exact(&mut body).ok()?;
    let (status, reply) = routes
        .iter_mut()
        .find(|route| route.method.as_str() == method && route.path == path)
        .and_then(|route| {
            let at = route.hits.min(route.replies.len().saturating_sub(1));
            route.hits += 1;
            route.replies.get(at).cloned()
        })
        .unwrap_or((404, String::new()));
    let mut stream = stream;
    let _ = write!(
        stream,
        "HTTP/1.1 {status} FIXTURE\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
         connection: close\r\n\r\n{reply}",
        reply.len()
    );
    Some(Request {
        method,
        path,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

/// A desktop over a temp dir: steps answer from `replies` in order and are
/// recorded in `sent`; the desk host's absolute paths live under `host`, so
/// `pull` and `push` copy real files and are recorded in `transfers`.
pub struct FakeDesk {
    pub replies: Mutex<VecDeque<Result<Vec<String>, String>>>,
    pub sent: Mutex<Vec<(Option<String>, Vec<Value>)>>,
    pub transfers: Mutex<Vec<String>>,
    host: PathBuf,
}

impl FakeDesk {
    pub fn new(host: &Path) -> Self {
        Self {
            replies: Mutex::default(),
            sent: Mutex::default(),
            transfers: Mutex::default(),
            host: host.to_path_buf(),
        }
    }

    /// Queues the next step reply.
    pub fn reply(self, reply: Result<Vec<String>, String>) -> Self {
        lock(&self.replies).push_back(reply);
        self
    }

    /// Where the desk host's absolute `path` lives in the test.
    pub fn on_host(&self, path: &Path) -> PathBuf {
        self.host.join(path.strip_prefix("/").unwrap_or(path))
    }

    pub fn sent(&self) -> Vec<(Option<String>, Vec<Value>)> {
        lock(&self.sent).clone()
    }

    pub fn transfers(&self) -> Vec<String> {
        lock(&self.transfers).clone()
    }

    fn copy(
        &self,
        from: &Path,
        to: &Path,
        files: &[PathBuf],
        what: String,
    ) -> Result<Transfer, String> {
        let mut moved = Transfer::default();
        for file in files {
            if !plain_relative(file) {
                return Err(format!(
                    "{:?} is not a plain relative file name",
                    file.display()
                ));
            }
            let target = to.join(file);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
            }
            moved.bytes += std::fs::copy(from.join(file), &target)
                .map_err(|error| format!("{}: {error}", file.display()))?;
            moved.files += 1;
        }
        lock(&self.transfers).push(what);
        Ok(moved)
    }
}

fn plain_relative(file: &Path) -> bool {
    !file.as_os_str().is_empty()
        && file
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn lock<T>(cell: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    cell.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Desk for FakeDesk {
    fn steps(
        &self,
        device: Option<&str>,
        steps: Vec<Value>,
        _bound: Duration,
    ) -> Result<Vec<String>, String> {
        lock(&self.sent).push((device.map(str::to_owned), steps));
        lock(&self.replies)
            .pop_front()
            .unwrap_or_else(|| Err("the fake desk has no reply queued".to_owned()))
    }

    fn pull(
        &self,
        device: Option<&str>,
        remote_dir: &Path,
        files: &[PathBuf],
        local_dir: &Path,
        _bound: Duration,
    ) -> Result<Transfer, String> {
        let what = format!(
            "pull {} {} {}",
            device.unwrap_or("-"),
            remote_dir.display(),
            files.len()
        );
        self.copy(&self.on_host(remote_dir), local_dir, files, what)
    }

    fn push(
        &self,
        device: Option<&str>,
        local_dir: &Path,
        files: &[PathBuf],
        _bound: Duration,
    ) -> Result<Transfer, String> {
        let what = format!(
            "push {} {} {}",
            device.unwrap_or("-"),
            local_dir.display(),
            files.len()
        );
        self.copy(local_dir, &self.on_host(local_dir), files, what)
    }
}
