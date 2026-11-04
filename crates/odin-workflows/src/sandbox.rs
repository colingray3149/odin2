//! One bwrap invocation per tool run: the Nix store read-only, inputs
//! read-only, one output dir writable, no home, network only when asked.
//! The runner spawns bwrap with a cleared environment and sets `RunSpec.env`
//! on the process itself, so no value ever appears in an argv.

use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::{Ctx, Failure};

/// The stderr bytes kept for cause mapping.
pub const OUTPUT_TAIL: usize = 16 * 1024;
/// The stdout bytes kept; JSON outputs (yt-dlp -J, ffprobe) fit.
pub const MAX_STDOUT: usize = 8 * 1024 * 1024;
/// A run's limit unless the family sets one.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// A partial line longer than this is handed on as it stands.
const MAX_LINE_BYTES: usize = 4 * 1024;
/// One read from a stream.
const READ_CHUNK: usize = 64 * 1024;

/// Whether the tool reaches the network. Per-host filtering is not possible in bwrap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Net {
    None,
    Host,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Bind {
    Ro,
    Rw,
}

/// A tool run being composed; `build` turns it into the exact argv.
pub struct Sandbox {
    tool: String,
    bwrap: PathBuf,
    exe: PathBuf,
    args: Vec<OsString>,
    binds: Vec<(Bind, PathBuf, PathBuf)>,
    gpu: bool,
    net: Net,
    cwd: Option<PathBuf>,
    env: Vec<(String, String)>,
    timeout: Duration,
    stdin: Option<PathBuf>,
}

impl Sandbox {
    /// Resolves the declared executable and the authority's bwrap.
    pub fn new(ctx: &Ctx, exe_key: &str) -> Result<Self, Failure> {
        Ok(Self {
            tool: exe_key.to_owned(),
            bwrap: ctx.bwrap()?.to_path_buf(),
            exe: ctx.exe(exe_key)?.to_path_buf(),
            args: Vec::new(),
            binds: Vec::new(),
            gpu: false,
            net: Net::None,
            cwd: None,
            env: Vec::new(),
            timeout: DEFAULT_TIMEOUT,
            stdin: None,
        })
    }

    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> Self {
        self.args.push(arg.as_ref().to_owned());
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args
            .extend(args.into_iter().map(|arg| arg.as_ref().to_owned()));
        self
    }

    /// Binds `path` read-only at the same path inside.
    pub fn ro(mut self, path: &Path) -> Self {
        self.binds
            .push((Bind::Ro, path.to_path_buf(), path.to_path_buf()));
        self
    }

    /// Binds `path` writable at the same path inside.
    pub fn rw(mut self, path: &Path) -> Self {
        self.binds
            .push((Bind::Rw, path.to_path_buf(), path.to_path_buf()));
        self
    }

    /// `--dev-bind /dev/dri` and `--ro-bind /run/opengl-driver` (Vulkan and VA-API find their drivers there on NixOS).
    pub fn gpu(mut self) -> Self {
        self.gpu = true;
        self
    }

    /// Read-only binds a declared secret file at `at` inside; the value never passes through Rust.
    pub fn secret_file(mut self, ctx: &Ctx, key: &str, at: &str) -> Result<Self, Failure> {
        let path = ctx.secret_path(key)?.to_path_buf();
        self.binds.push((Bind::Ro, path, PathBuf::from(at)));
        Ok(self)
    }

    /// Sets the secret value as `var` in the process environment (never the argv).
    /// Prefer `secret_file` when the tool can read a file.
    pub fn secret_env(mut self, ctx: &Ctx, key: &str, var: &str) -> Result<Self, Failure> {
        let secret = ctx.secret(key)?;
        self.env.push((var.to_owned(), secret.expose().to_owned()));
        Ok(self)
    }

    pub fn net(mut self, net: Net) -> Self {
        self.net = net;
        self
    }

    pub fn cwd(mut self, path: &Path) -> Self {
        self.cwd = Some(path.to_path_buf());
        self
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    pub fn timeout(mut self, limit: Duration) -> Self {
        self.timeout = limit;
        self
    }

    /// The file the tool reads on stdin.
    pub fn stdin_file(mut self, path: &Path) -> Self {
        self.stdin = Some(path.to_path_buf());
        self
    }

    /// The bwrap argv: `--unshare-all [--share-net] --die-with-parent --new-session
    /// --ro-bind /nix/store /nix/store [/etc and the resolver, net only] --proc /proc
    /// --dev /dev [gpu] --tmpfs /tmp --setenv HOME /tmp <binds in call order>
    /// [--chdir cwd] -- <exe> <args…>`.
    pub fn build(self) -> RunSpec {
        let mut argv: Vec<OsString> = vec![self.bwrap.into(), "--unshare-all".into()];
        if self.net == Net::Host {
            argv.push("--share-net".into());
        }
        argv.extend(["--die-with-parent", "--new-session"].map(OsString::from));
        push_bind(
            &mut argv,
            "--ro-bind",
            Path::new("/nix/store"),
            Path::new("/nix/store"),
        );
        if self.net == Net::Host {
            push_bind(&mut argv, "--ro-bind", Path::new("/etc"), Path::new("/etc"));
            for resolver in ["/run/systemd/resolve", "/run/nscd"] {
                push_bind(
                    &mut argv,
                    "--ro-bind-try",
                    Path::new(resolver),
                    Path::new(resolver),
                );
            }
        }
        argv.extend(["--proc", "/proc", "--dev", "/dev"].map(OsString::from));
        if self.gpu {
            push_bind(
                &mut argv,
                "--dev-bind",
                Path::new("/dev/dri"),
                Path::new("/dev/dri"),
            );
            let driver = Path::new("/run/opengl-driver");
            push_bind(&mut argv, "--ro-bind", driver, driver);
        }
        argv.extend(["--tmpfs", "/tmp", "--setenv", "HOME", "/tmp"].map(OsString::from));
        for (bind, source, inside) in &self.binds {
            let flag = match bind {
                Bind::Ro => "--ro-bind",
                Bind::Rw => "--bind",
            };
            push_bind(&mut argv, flag, source, inside);
        }
        if let Some(cwd) = &self.cwd {
            argv.push("--chdir".into());
            argv.push(cwd.into());
        }
        argv.push("--".into());
        argv.push(self.exe.into());
        argv.extend(self.args);
        RunSpec {
            tool: self.tool,
            argv,
            env: self.env,
            timeout: self.timeout,
            stdin: self.stdin,
        }
    }
}

fn push_bind(argv: &mut Vec<OsString>, flag: &str, source: &Path, inside: &Path) {
    argv.push(flag.into());
    argv.push(source.into());
    argv.push(inside.into());
}

/// One composed run. Holds environment values, so it is never printed.
pub struct RunSpec {
    /// The executable key, for messages.
    pub tool: String,
    pub argv: Vec<OsString>,
    pub env: Vec<(String, String)>,
    pub timeout: Duration,
    pub stdin: Option<PathBuf>,
}

impl RunSpec {
    /// The tool's own argv: everything after bwrap's `--`.
    pub fn inner_argv(&self) -> &[OsString] {
        match self.argv.iter().position(|arg| arg == "--") {
            Some(separator) => &self.argv[separator + 1..],
            None => &[],
        }
    }
}

/// How one run ended. A nonzero exit is still an output.
#[derive(Clone, Debug, Default)]
pub struct RunOutput {
    /// `None` when stopped by a signal or by the timeout.
    pub code: Option<i32>,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stderr_tail: String,
}

impl RunOutput {
    pub fn success(&self) -> bool {
        self.code == Some(0) && !self.timed_out
    }

    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
}

/// Why a run gave no output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunFault {
    /// Nothing ran.
    NotStarted(String),
    /// It may have run; its end was not observed.
    Lost(String),
}

/// Runs one composed spec. The authority's runner launches it as a registered
/// service, so the stop authority reaches it.
pub trait Runner: Send + Sync {
    /// `on_line` sees each stdout and stderr line as it arrives; the full
    /// stdout up to `MAX_STDOUT` and the stderr tail are still returned.
    fn run(&self, spec: &RunSpec, on_line: &mut dyn FnMut(&str)) -> Result<RunOutput, RunFault>;
}

/// What came out of a started process's two streams.
pub struct Streams {
    pub stdout: Vec<u8>,
    pub stderr_tail: String,
    /// The limit passed before both streams closed; the caller stops the process.
    pub timed_out: bool,
}

/// Reads both streams until they close or `spec.timeout` passes, handing
/// each line (split at `\n` or `\r`) to `on_line`. Shared by every runner.
pub fn read_streams(
    stdout: impl Read + Send + 'static,
    stderr: impl Read + Send + 'static,
    spec: &RunSpec,
    on_line: &mut dyn FnMut(&str),
) -> Streams {
    let (sender, chunks) = mpsc::channel::<(bool, Vec<u8>)>();
    spawn_reader(stdout, false, sender.clone());
    spawn_reader(stderr, true, sender);
    let deadline = Instant::now() + spec.timeout;
    let mut out = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let mut partial = [Vec::new(), Vec::new()];
    let mut timed_out = false;
    loop {
        let wait = deadline.saturating_duration_since(Instant::now());
        match chunks.recv_timeout(wait) {
            Ok((is_err, chunk)) => {
                if is_err {
                    err.extend_from_slice(&chunk);
                    let excess = err.len().saturating_sub(OUTPUT_TAIL);
                    err.drain(..excess);
                } else {
                    let kept = MAX_STDOUT.saturating_sub(out.len()).min(chunk.len());
                    out.extend_from_slice(&chunk[..kept]);
                }
                lines(&mut partial[usize::from(is_err)], &chunk, on_line);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                timed_out = true;
                break;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    for rest in partial {
        emit(&rest, on_line);
    }
    Streams {
        stdout: out,
        stderr_tail: String::from_utf8_lossy(&err).into_owned(),
        timed_out,
    }
}

fn spawn_reader(
    mut stream: impl Read + Send + 'static,
    is_err: bool,
    sender: mpsc::Sender<(bool, Vec<u8>)>,
) {
    std::thread::spawn(move || {
        let mut buffer = vec![0; READ_CHUNK];
        while let Ok(read) = stream.read(&mut buffer) {
            if read == 0 || sender.send((is_err, buffer[..read].to_vec())).is_err() {
                break;
            }
        }
    });
}

fn lines(partial: &mut Vec<u8>, chunk: &[u8], on_line: &mut dyn FnMut(&str)) {
    for &byte in chunk {
        if byte == b'\n' || byte == b'\r' {
            emit(partial, on_line);
            partial.clear();
        } else {
            partial.push(byte);
            if partial.len() >= MAX_LINE_BYTES {
                emit(partial, on_line);
                partial.clear();
            }
        }
    }
}

fn emit(line: &[u8], on_line: &mut dyn FnMut(&str)) {
    if !line.is_empty() {
        on_line(&String::from_utf8_lossy(line));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{assert_bwrap, ctx_for};

    fn sandbox(dir: &Path) -> Sandbox {
        let ctx = ctx_for(
            dir,
            &[("yt-dlp", Path::new("/nix/store/0-yt-dlp/bin/yt-dlp"))],
            &[],
            &[],
            &[],
        );
        Sandbox::new(&ctx, "yt-dlp").expect("declared")
    }

    #[test]
    fn inputs_bind_read_only_outputs_read_write_and_only_the_gpu_adds_dri() {
        let dir = tempfile::tempdir().expect("dir");
        let spec = sandbox(dir.path())
            .ro(Path::new("/in/a.mkv"))
            .rw(Path::new("/out"))
            .build();
        assert_bwrap(
            &spec,
            &[
                "--ro-bind",
                "/in/a.mkv",
                "/in/a.mkv",
                "--bind",
                "/out",
                "/out",
            ],
        );
        assert!(!spec.argv.iter().any(|arg| arg == "/dev/dri"));
        let gpu = sandbox(dir.path()).gpu().build();
        assert_bwrap(
            &gpu,
            &["--dev", "/dev", "--dev-bind", "/dev/dri", "/dev/dri"],
        );
    }

    #[test]
    fn a_run_past_its_limit_is_stopped_and_says_so() {
        let dir = tempfile::tempdir().expect("dir");
        let sleeper = dir.path().join("sleeper");
        std::fs::write(&sleeper, "#!/bin/sh\necho started\nwhile :; do :; done\n").unwrap();
        std::fs::set_permissions(
            &sleeper,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();
        let ctx = ctx_for(dir.path(), &[("sleeper", sleeper.as_path())], &[], &[], &[]);
        let spec = Sandbox::new(&ctx, "sleeper")
            .unwrap()
            .timeout(Duration::from_millis(300))
            .build();
        let out = ctx.run(&spec).expect("ran");
        assert!(out.timed_out);
        assert_eq!(out.stdout_text().trim(), "started");
        let failure = crate::cause::failure("sleeper", &[], &[], &out, Duration::from_millis(300))
            .expect("a failure");
        assert!(
            failure.cause.contains("ran past its") && failure.cause.contains("stopped"),
            "{}",
            failure.cause
        );
    }
}
