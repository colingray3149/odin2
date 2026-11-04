//! One read-only Claude invocation; daily caps come from completed review receipts.
use odin_domain::Scope;
use odin_hermes::runtime::{
    claude::{ClaudeReviewOrigin, ClaudeReviewRequest, ClaudeReviewRoute},
    coding::CodingRoute,
};
use odin_registry::{
    ClaudePlacement, ClaudeReviewToml, ObjectConfig, RegistryKind, SnapshotHandle,
};
use serde_json::{json, Value};
use std::{
    fs,
    io::{ErrorKind, Read, Write},
    path::{Component, Path, PathBuf},
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};

type ReviewError = Box<dyn std::error::Error>;

/// How often the review child is checked for exit while it runs.
const REVIEW_POLL: Duration = Duration::from_millis(100);
const MISSING_WORKLOAD: &str = "claude-review workload is disabled or missing";
const MISSING_CAPABILITY: &str = "claude.review capability is disabled or missing";
const OPAQUE: &str = "cannot verify artifact source; use a non-sensitive brain-relative path";
const MCP_JSON: &[u8] = b"{\"mcpServers\":{}}";
const ONBOARD: &[u8] = b"{\"hasCompletedOnboarding\":true}";
/// The reviewer's HOME inside the sandbox.
const HOME: &str = "/tmp/home";
const INPUT: &str = "/review/input";
const SANDBOX: [&str; 15] = [
    "--unshare-all",
    "--share-net",
    "--die-with-parent",
    "--new-session",
    "--cap-drop",
    "ALL",
    "--ro-bind",
    "/nix/store",
    "/nix/store",
    "--tmpfs",
    "/tmp",
    "--proc",
    "/proc",
    "--dev",
    "/dev",
];
const HOST_FILES: [&str; 4] = [
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/ssl/certs",
];

pub(crate) struct DaemonClaudeReviewRoute {
    pub pin: Arc<SnapshotHandle>,
    pub state_root: PathBuf,
    pub brain_root: Option<PathBuf>,
    pub bwrap: PathBuf,
    pub coding: Arc<dyn CodingRoute>,
}

impl DaemonClaudeReviewRoute {
    fn ready(
        &self,
        origin: ClaudeReviewOrigin,
    ) -> Result<(ClaudeReviewToml, Duration), ReviewError> {
        let snapshot = self.pin.current();
        let workload = snapshot.object(RegistryKind::Workload, "claude-review");
        let Some(workload) = workload.filter(|object| object.enabled()) else {
            return Err(MISSING_WORKLOAD.into());
        };
        let ObjectConfig::ClaudeCode(profile) = &workload.config else {
            return Err(MISSING_WORKLOAD.into());
        };
        if profile.placement != ClaudePlacement::Review {
            return Err(MISSING_WORKLOAD.into());
        }
        let review = profile.review.clone().ok_or(MISSING_WORKLOAD)?;
        let capability = snapshot.object(RegistryKind::Capability, "claude.review");
        let Some(capability) = capability.filter(|object| object.enabled()) else {
            return Err(MISSING_CAPABILITY.into());
        };
        let ObjectConfig::Capability(capability) = &capability.config else {
            return Err(MISSING_CAPABILITY.into());
        };
        let timeout = Duration::from_secs(u64::from(capability.timeout_seconds.get()));
        let root = self.state_root.join("claude-review");
        check_cap(daily_counts(&root)?, origin, &review)?;
        Ok((review, timeout))
    }

    fn bundle(
        &self,
        request: &ClaudeReviewRequest,
        review: &ClaudeReviewToml,
    ) -> Result<Vec<Vec<u8>>, ReviewError> {
        if request.bundle.is_empty() {
            return Ok(Vec::new());
        }
        let brain = self.brain_root.as_deref();
        let brain = brain.ok_or("hermes.brain_raw_root is not configured")?;
        let root = odin_confined_fs::Capability::seal(brain)?;
        let mut files = Vec::new();
        let mut remaining = review.max_bundle_bytes;
        for entry in &request.bundle {
            if entry.starts_with("blake3:") || entry.starts_with("artifact:") {
                return Err(OPAQUE.into());
            }
            let excluded = Path::new(entry)
                .components()
                .any(|component| match component {
                    Component::Normal(name) => {
                        review.excluded.iter().any(|part| name == part.as_str())
                    }
                    Component::CurDir => false,
                    _ => true,
                });
            if excluded {
                let message = format!("review excludes personal-data or escaping path: {entry}");
                return Err(message.into());
            }
            let mut bytes = Vec::new();
            root.open_read(Path::new(entry))?
                .take(remaining.saturating_add(1))
                .read_to_end(&mut bytes)?;
            remaining = remaining
                .checked_sub(bytes.len() as u64)
                .ok_or("review exceeds max_bundle_bytes")?;
            files.push(bytes);
        }
        Ok(files)
    }
}

/// Today's completed reviews under `root/<id>/receipt.json`: `(total, self)`.
fn daily_counts(root: &Path) -> Result<(usize, usize), ReviewError> {
    let today = time::OffsetDateTime::now_utc().date().to_string();
    let mut counts = (0, 0);
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(counts),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let path = entry?.path().join("receipt.json");
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let receipt: Value = serde_json::from_slice(&bytes)?;
        if receipt["date"] == today {
            counts.0 += 1;
            counts.1 += usize::from(receipt["initiatedBy"] == "self");
        }
    }
    Ok(counts)
}

fn check_cap(
    counts: (usize, usize),
    origin: ClaudeReviewOrigin,
    review: &ClaudeReviewToml,
) -> Result<(), String> {
    let budget = &review.budget;
    if counts.0 >= budget.max_per_day as usize {
        let max = budget.max_per_day;
        return Err(format!("review max_per_day cap {max} reached"));
    }
    if origin == ClaudeReviewOrigin::Sinmara && counts.1 >= budget.self_per_day as usize {
        let max = budget.self_per_day;
        return Err(format!("review self_per_day cap {max} reached"));
    }
    Ok(())
}

impl ClaudeReviewRoute for DaemonClaudeReviewRoute {
    fn preflight_review(
        &self,
        _scope: &Scope,
        request: &ClaudeReviewRequest,
    ) -> Result<(), String> {
        self.ready(request.initiated_by)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn review(
        &self,
        _effect: &odin_kernel::operation::PreparedEffect,
        scope: Scope,
        request: ClaudeReviewRequest,
    ) -> Result<Value, String> {
        let (review, timeout) = self
            .ready(request.initiated_by)
            .map_err(|error| error.to_string())?;
        let files = self
            .bundle(&request, &review)
            .map_err(|error| error.to_string())?;
        let id = odin_process::mint_worker_id().map_err(|error| error.to_string())?;
        let run = self.state_root.join("claude-review").join(id.as_str());
        let result = (|| -> Result<Value, ReviewError> {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&run)?;
            fs::create_dir(run.join("bundle"))?;
            for (index, bytes) in files.iter().enumerate() {
                fs::write(run.join("bundle").join(format!("{index}.txt")), bytes)?;
            }
            let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
            let creds = PathBuf::from(home).join(".claude/.credentials.json");
            let value = invoke(
                &self.bwrap,
                &review,
                &creds,
                &run,
                &request.question,
                timeout,
            )?;
            if value["is_error"] == true {
                return Err(format!("claude review failed: {}", value["result"]).into());
            }
            let text = value["result"]
                .as_str()
                .ok_or("review has no result text")?;
            // Count the completed review before publication can fail.
            let date = time::OffsetDateTime::now_utc().date().to_string();
            let receipt = json!({"date": date, "initiatedBy": request.initiated_by});
            private_file(&run.join("receipt.json"), &serde_json::to_vec(&receipt)?)?;
            let artifact = self
                .coding
                .share_bytes(&scope, text.as_bytes(), "text/markdown")?;
            Ok(json!({"review": text, "artifactId": artifact, "initiatedBy": request.initiated_by}))
        })()
        .map_err(|error| format!("claude review: {error}"));
        for name in ["bundle", "launch"] {
            let _ = fs::remove_dir_all(run.join(name));
        }
        result
    }
}

fn private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    options.open(path)?.write_all(bytes)
}

fn invoke(
    bwrap: &Path,
    review: &ClaudeReviewToml,
    credentials: &Path,
    run: &Path,
    question: &str,
    timeout: Duration,
) -> std::io::Result<Value> {
    let launch = run.join("launch");
    fs::create_dir(&launch)?;
    let prompt = format!(
        "Review the read-only files in the current directory. Report material findings briefly.\nQuestion: {question}"
    );
    private_file(&launch.join("prompt"), prompt.as_bytes())?;
    let settings = json!({
        "permissions": {"deny": [format!("Read({HOME}/**)")]},
        "env": {
            "DISABLE_AUTOUPDATER": "1",
            "DISABLE_TELEMETRY": "1",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        },
    });
    private_file(
        &launch.join("settings.json"),
        settings.to_string().as_bytes(),
    )?;
    private_file(&launch.join("mcp.json"), MCP_JSON)?;
    private_file(&launch.join(".claude.json"), ONBOARD)?;
    let binary = fs::canonicalize(&review.binary).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("claude binary {}: {error}", review.binary),
        )
    })?;
    let mut command = Command::new(bwrap);
    command
        .args(SANDBOX)
        .arg("--dir")
        .arg(format!("{HOME}/.claude"));
    for path in HOST_FILES {
        if Path::new(path).exists() {
            command.args(["--ro-bind", path, path]);
        }
    }
    let settings_path = format!("{HOME}/.claude/settings.json");
    let mcp_path = format!("{HOME}/.claude/mcp.json");
    let binds = [
        (run.join("bundle"), INPUT.to_owned()),
        (
            credentials.to_owned(),
            format!("{HOME}/.claude/.credentials.json"),
        ),
        (launch.join("settings.json"), settings_path.clone()),
        (launch.join("mcp.json"), mcp_path.clone()),
        (launch.join(".claude.json"), format!("{HOME}/.claude.json")),
    ];
    for (source, dest) in binds {
        command.arg("--ro-bind").arg(source).arg(dest);
    }
    command.arg("--ro-bind").arg(&binary).arg(&binary);
    command.args([
        "--clearenv",
        "--setenv",
        "HOME",
        HOME,
        "--setenv",
        "PATH",
        "/tmp",
    ]);
    command.args(["--chdir", INPUT, "--"]);
    command.arg(&binary);
    let tools = review.tools.join(",");
    command.args(["-p", "--model", &review.model]);
    command.args(["--tools", &tools, "--allowedTools", &tools]);
    command.args([
        "--restricted",
        "--permission-prompts",
        "none",
        "--strict-mcp-config",
    ]);
    command.args(["--mcp-config", &mcp_path, "--settings", &settings_path]);
    command.args(["--no-session-persistence", "--output-format", "json"]);
    command.env_clear();
    command.stdin(fs::File::open(launch.join("prompt"))?);
    command.stdout(fs::File::create(launch.join("stdout"))?);
    command.stderr(fs::File::create(launch.join("stderr"))?);
    let mut child = command.spawn()?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::other("review exceeded declared timeout"));
        }
        std::thread::sleep(REVIEW_POLL);
    };
    if !status.success() {
        return Err(std::io::Error::other(format!("claude exited {status}")));
    }
    let mut bytes = Vec::new();
    fs::File::open(launch.join("stdout"))?
        .take(4 << 20)
        .read_to_end(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(std::io::Error::other)
}

#[cfg(test)]
#[path = "claude_review_tests.rs"]
mod tests;
