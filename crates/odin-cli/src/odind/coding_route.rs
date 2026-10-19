//! Coding tools over registered session capsules and reviewed Git publication.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use odin_cli::eval_daemon::{apply_mergiraf_attributes, mergiraf_driver};
use odin_domain::Scope;
use odin_hermes::runtime::coding::{
    ArtifactSource, CheckoutQuery, CodeQuery, CodingRoute, NixLog, NixVerb, ProposalFailure,
    TestSelection,
};
use odin_kernel::operation::PreparedEffect;
use serde_json::{json, Value};

#[path = "coding_route/claims.rs"]
pub(crate) mod claims;
#[path = "coding_route/engineering.rs"]
mod engineering;
#[path = "coding_route/execution.rs"]
mod execution;
#[path = "coding_route/navigation.rs"]
mod navigation;
#[path = "coding_route/publication.rs"]
pub(crate) mod publication;
#[path = "coding_route/review.rs"]
mod review;

#[cfg(test)]
pub(crate) use execution::Unowned;
pub(crate) use execution::{GitRunner, Lifecycle, Owned};

/// A build or check longer than this is killed (the capability timeout is a
/// minute longer, so the typed result always arrives).
const NIX_SECONDS: u64 = 1_200;
/// Hand-back, review, and search deadline; the capability permit may expire first.
const OPERATION_SECONDS: u64 = 1_200;
const LOG_TAIL_BYTES: usize = 6_000;
/// Rollover claim carry only reads repository identities.
const CARRY_SECONDS: u64 = 120;
/// Leave a minute before the merge capability expires so a refusal can be delivered.
const MERGE_CHECK_SECONDS: u64 = 1_140;

/// The most capsule-relative test files one scoped `test_run` names
/// (mirrors the Hermes-side schema bound).
const MAX_TEST_PATHS: usize = 8;

/// Waiting must leave room for this merge's own fetch, merge, check and
/// push inside the same capability window.
const MERGE_LOCK_BOUND: Duration = Duration::from_secs(30);

pub(crate) struct DaemonCodingRoute {
    pub(crate) state_root: PathBuf,
    pub(crate) session_pool: Option<std::sync::Arc<odin_cli::live_authority::SessionAuthorityPool>>,
    pub(crate) supervisor: std::sync::Weak<odin_omp::live::supervisor::LiveSupervisor>,
    /// Declared project roots (the rendered `projects` plus runtime-created).
    pub(crate) projects: BTreeMap<String, PathBuf>,
    /// Live published registry. Review admission reads the project/lane
    /// verdict capability and the named seat's grants from it.
    pub(crate) registry: Option<std::sync::Arc<odin_registry::SnapshotHandle>>,
}

/// One session's capsule and where its work goes.
struct Capsule {
    path: PathBuf,
    project_root: PathBuf,
    branch: String,
    seat: String,
}

impl DaemonCodingRoute {
    fn capsule(&self, scope: &Scope) -> Result<Capsule, String> {
        let session = scope
            .session
            .as_ref()
            .ok_or("this dispatch is not bound to a session")?;
        let seat = scope.seat.as_ref().ok_or("this dispatch has no seat")?;
        let project = scope
            .project
            .as_ref()
            .ok_or("this dispatch is not bound to a project")?;
        let capsule_id = odin_omp::host_tools::operations::session_capsule_id(session)
            .map_err(|error| error.to_string())?;
        let path = self
            .state_root
            .join("session-authorities")
            .join(format!("capsule-{}", capsule_id.as_str().replace(':', "-")))
            .join("capsule")
            .join("project");
        if !path.join(".git").is_dir() {
            return Err(format!(
                "this session has no code capsule (project {project} is not a git repository)"
            ));
        }
        let project_root = self
            .projects
            .get(project.as_str())
            .ok_or_else(|| format!("project {project} has no declared root"))?
            .clone();
        Ok(Capsule {
            path,
            project_root,
            // The full session id: an eight-character prefix can collide
            // between two sessions of one seat, and a hand-back or salvage
            // pin on a shared ref would drop the first session's work.
            branch: session_branch(seat.as_str(), session.as_str()),
            seat: seat.to_string(),
        })
    }

    /// The session's capsule as the pool registered it: tests, reviews and
    /// reviewed offers bind this identity, and a derived path that is not
    /// the registered Git capsule of this seat and project is refused. Its
    /// Git steps run on `runner`.
    fn registered<'g>(
        &self,
        scope: &Scope,
        runner: &'g dyn GitRunner,
    ) -> Result<Registered<'g>, String> {
        let capsule = self.capsule(scope)?;
        let session = scope
            .session
            .as_ref()
            .ok_or("this dispatch has no session")?;
        let registration = self
            .session_pool
            .as_ref()
            .ok_or("this session has no registered code capsule to test or review")?
            .registered_code_capsule(session)?
            .ok_or("this session is registered over a knowledge root, not a Git capsule")?;
        let canonical = |path: &Path| {
            path.canonicalize()
                .map_err(|error| format!("{}: {error}", path.display()))
        };
        if registration.seat.as_str() != capsule.seat
            || canonical(&capsule.path)? != canonical(&registration.capsule_project)?
            || canonical(&capsule.project_root)? != registration.declared_project
        {
            return Err("this session's code capsule differs from its registration".to_owned());
        }
        Ok(Registered {
            capsule,
            project: scope
                .project
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default(),
            session: session.to_string(),
            declared_root: registration.declared_project,
            capsule_project: registration.capsule_project,
            base: registration.source_commit,
            runner,
        })
    }
    /// Publication uses the actual registered Git capsule. Harness MCP
    /// registrations name their workspace rather than the declared repo;
    /// the prepared kernel Scope still owns seat/project selection.
    fn publication_capsule(&self, scope: &Scope) -> Result<Capsule, String> {
        let session = scope
            .session
            .as_ref()
            .ok_or("this publication has no session")?;
        let seat = scope.seat.as_ref().ok_or("this publication has no seat")?;
        let project = scope
            .project
            .as_ref()
            .ok_or("this publication has no project")?;
        let registration = self
            .session_pool
            .as_ref()
            .ok_or("this publication has no session registration")?
            .registered_code_capsule(session)?
            .ok_or("this session is registered over a knowledge root")?;
        if registration.seat != *seat {
            return Err("publication seat differs from its registration".to_owned());
        }
        let root = self
            .projects
            .get(project.as_str())
            .ok_or_else(|| format!("project {project} has no declared root"))?
            .canonicalize()
            .map_err(|error| error.to_string())?;
        Ok(Capsule {
            path: registration.capsule_project,
            project_root: root,
            branch: session_branch(seat.as_str(), session.as_str()),
            seat: seat.to_string(),
        })
    }

    fn claim_branch(
        &self,
        runner: &dyn GitRunner,
        capsule: &Capsule,
        project: &str,
        session: &str,
        branch: &str,
    ) -> Result<claims::Claim, String> {
        claims::Claim::acquire(
            runner,
            &self.state_root,
            &capsule.project_root,
            branch,
            claims::Owner {
                session: session.to_owned(),
                seat: capsule.seat.clone(),
                project: project.to_owned(),
            },
            |owner| claims::owner_ended(self.supervisor.upgrade(), owner),
        )
    }
}

/// One session's registered Git capsule: the identity test runs, reviews
/// and reviewed offers are bound to, and the runner of the operation that
/// resolved it.
struct Registered<'g> {
    capsule: Capsule,
    project: String,
    session: String,
    declared_root: PathBuf,
    /// The pool's own registered capsule path (the canonical twin of
    /// `capsule.path`).
    capsule_project: PathBuf,
    /// The source commit the capsule was registered at.
    base: String,
    /// Every Git step on this capsule runs here: the admitted operation's
    /// [`Owned`] permit.
    runner: &'g dyn GitRunner,
}

/// The host executable by name, preferring the system profile (the daemon's
/// unit PATH is minimal).
#[cfg(test)]
fn program(name: &str) -> PathBuf {
    let system = Path::new("/run/current-system/sw/bin").join(name);
    if system.exists() {
        system
    } else {
        PathBuf::from(name)
    }
}

/// The fixed Nix argv for one verb over one flake reference: the staged
/// capsule, or a test run's frozen snapshot revision.
fn nix_flake_argv(flake: &str, verb: NixVerb, attr: Option<&str>) -> Vec<String> {
    let mut argv: Vec<String> = ["--extra-experimental-features", "nix-command flakes"]
        .iter()
        .map(|part| (*part).to_owned())
        .collect();
    match verb {
        NixVerb::Build => argv.extend(
            [
                "build",
                "--no-link",
                "--print-out-paths",
                "--no-write-lock-file",
                "--option",
                "accept-flake-config",
                "false",
                &format!("{flake}#{}", attr.unwrap_or("default")),
            ]
            .map(str::to_owned),
        ),
        NixVerb::Check => argv.extend(
            [
                "flake",
                "check",
                "--no-write-lock-file",
                "--option",
                "accept-flake-config",
                "false",
                flake,
            ]
            .map(str::to_owned),
        ),
    }
    argv
}

/// The staged capsule as a dirty `git+file` flake.
fn capsule_flake(capsule: &Path) -> String {
    format!("git+file://{}", capsule.display())
}

fn valid_attr(attr: &str) -> bool {
    (1..=128).contains(&attr.len())
        && attr.starts_with(|c: char| c.is_ascii_alphanumeric())
        && attr
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn valid_test_path(path: &str) -> bool {
    (1..=200).contains(&path.len())
        && path.ends_with(".py")
        && !path.starts_with('/')
        && !path.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != ".." && !part.starts_with('-'))
}

fn tail(text: &str) -> String {
    let start = text.len().saturating_sub(LOG_TAIL_BYTES);
    let start = (start..=text.len())
        .find(|index| text.is_char_boundary(*index))
        .unwrap_or(text.len());
    text[start..].to_owned()
}

/// The names of the checks a merged tree declares for this system.
fn nix_checks_presence_argv(worktree: &Path) -> Vec<String> {
    let flake = format!("git+file://{}#checks", worktree.display());
    [
        "--extra-experimental-features",
        "nix-command flakes",
        "eval",
        "--json",
        "--impure",
        "--no-write-lock-file",
        "--option",
        "accept-flake-config",
        "false",
        &flake,
        "--apply",
        "checks: builtins.attrNames (checks.${builtins.currentSystem} or {})",
    ]
    .iter()
    .map(|part| (*part).to_owned())
    .collect()
}

/// Runs blocking work off the async worker the tool handler runs on.
fn blocking<T>(work: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(work)
        }
        _ => work(),
    }
}

const MAX_ARTIFACT_BYTES: u64 = 32 * 1024 * 1024;
/// The largest artifact a seat reads back inline.
const MAX_INLINE_READ_BYTES: u64 = 256 * 1024;

impl DaemonCodingRoute {
    /// The bytes of one file inside the calling session's workspace.
    fn workspace_file(&self, scope: &Scope, path: &str) -> Result<Vec<u8>, String> {
        let workspace = self.workspace(scope)?;
        let relative = Path::new(path);
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(format!("{path:?} is not a path inside your workspace"));
        }
        let canonical = workspace
            .join(relative)
            .canonicalize()
            .map_err(|error| format!("{path}: {error}"))?;
        let root = workspace
            .canonicalize()
            .map_err(|error| format!("the workspace is unreadable: {error}"))?;
        if !canonical.starts_with(&root) || !canonical.is_file() {
            return Err(format!("{path:?} is not a file inside your workspace"));
        }
        let size = canonical
            .metadata()
            .map_err(|error| format!("{path}: {error}"))?
            .len();
        if size > MAX_ARTIFACT_BYTES {
            return Err(format!(
                "{path} is {size} bytes; an artifact holds at most {MAX_ARTIFACT_BYTES}"
            ));
        }
        std::fs::read(&canonical).map_err(|error| format!("{path}: {error}"))
    }

    /// The calling session's capsule workspace, git repository or not.
    fn workspace(&self, scope: &Scope) -> Result<PathBuf, String> {
        let session = scope
            .session
            .as_ref()
            .ok_or("this dispatch is not bound to a session")?;
        let capsule_id = odin_omp::host_tools::operations::session_capsule_id(session)
            .map_err(|error| error.to_string())?;
        let path = self
            .state_root
            .join("session-authorities")
            .join(format!("capsule-{}", capsule_id.as_str().replace(':', "-")))
            .join("capsule")
            .join("project");
        if !path.is_dir() {
            return Err("this session has no workspace capsule".to_owned());
        }
        Ok(path)
    }

    fn artifact_root(&self) -> PathBuf {
        self.state_root.join("huginn").join("artifacts")
    }

    fn ledger(&self) -> Result<odin_ledger::Ledger, String> {
        odin_ledger::Ledger::open(self.state_root.join("ledger.sqlite3"))
            .map_err(|error| format!("the controller ledger could not be opened: {error}"))
    }
}

/// A media type from the file name, when the caller named none.
fn media_type_of(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("txt" | "log") => "text/plain",
        Some("md") => "text/markdown",
        Some("json") => "application/json",
        Some("csv") => "text/csv",
        Some("toml") => "application/toml",
        Some("py" | "rs" | "sh" | "nix") => "text/plain",
        Some("html") => "text/html",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("svg") => "image/svg+xml",
        Some("pdf") => "application/pdf",
        _ => "application/octet-stream",
    }
}

/// Stores content-addressed bytes and grants access to each `(kind, id)` reference.
pub(crate) fn store_artifact(
    state_root: &Path,
    bytes: &[u8],
    media_type: &str,
    shares: &[(&'static str, String)],
) -> Result<odin_ledger::artifact::ArtifactMetadata, String> {
    let digest = odin_domain::Digest::hash(bytes).to_string();
    let hex = digest.trim_start_matches("blake3:");
    let storage_path = format!("cas/{}/{hex}", &hex[..2]);
    let mut ledger = odin_ledger::Ledger::open(state_root.join("ledger.sqlite3"))
        .map_err(|error| format!("the controller ledger could not be opened: {error}"))?;
    let mut metadata = ledger
        .register_artifact(odin_ledger::artifact::ArtifactRegistration {
            bytes,
            media_type,
            storage_path: &storage_path,
            retention: odin_ledger::artifact::RetentionClass::Canonical,
            created_at: time::OffsetDateTime::now_utc(),
        })
        .map_err(|error| format!("the artifact could not be registered: {error}"))?;
    // The bytes live at the registered path (an earlier registration of
    // the same content keeps its own); written atomically, once.
    let stored = state_root
        .join("huginn")
        .join("artifacts")
        .join(&metadata.storage_path);
    if !stored.is_file() {
        let parent = stored.parent().ok_or("the artifact path has no parent")?;
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("the artifact store is not writable: {error}"))?;
        let staging = stored.with_extension("odin-tmp");
        std::fs::write(&staging, bytes)
            .and_then(|()| std::fs::rename(&staging, &stored))
            .map_err(|error| format!("the artifact bytes could not be stored: {error}"))?;
    }
    for (kind, id) in shares {
        let attached = ledger
            .attach_artifact_reference(
                &metadata.artifact_id,
                metadata.revision,
                odin_ledger::artifact::NewArtifactReference {
                    object_kind: kind,
                    object_id: id,
                    relation: "readable",
                    created_at: time::OffsetDateTime::now_utc(),
                },
            )
            .map_err(|error| format!("the artifact could not be shared with {id}: {error}"))?;
        metadata = match attached {
            odin_ledger::artifact::AttachReference::Added(metadata)
            | odin_ledger::artifact::AttachReference::Existing(metadata) => metadata,
        };
    }
    Ok(metadata)
}

/// One `shareWith` entry as a ledger reference: `project:<id>` names a
/// project, anything else a seat.
fn share_reference(entry: &str) -> Result<(&'static str, String), String> {
    let (kind, id) = match entry.strip_prefix("project:") {
        Some(project) => ("project", project),
        None => ("seat", entry.strip_prefix("seat:").unwrap_or(entry)),
    };
    if !odin_registry::schema::valid_id(id) {
        return Err(format!("shareWith {entry:?} is not a seat or project:<id>"));
    }
    Ok((kind, id.to_owned()))
}

impl CodingRoute for DaemonCodingRoute {
    fn nix(
        &self,
        effect: &PreparedEffect,
        scope: &Scope,
        verb: NixVerb,
        attr: Option<String>,
    ) -> Result<Value, String> {
        if let Some(attr) = &attr {
            if !valid_attr(attr) {
                return Err(format!("{attr:?} is not a flake output name"));
            }
        }
        let capsule = self.capsule(scope)?;
        let owned = Owned::new(self, effect, scope, Duration::from_secs(NIX_SECONDS))?;
        blocking(|| {
            // Staged files are part of a dirty `git+file` flake; untracked
            // ones would silently be missing from the build.
            stage_change(&owned, &capsule.path)?;
            let started = Instant::now();
            let flake = capsule_flake(&capsule.path);
            let argv = nix_flake_argv(&flake, verb, attr.as_deref());
            let output = owned.nix(&capsule.path, argv)?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            let outputs: Vec<&str> = stdout
                .lines()
                .filter(|line| line.starts_with("/nix/store/"))
                .collect();
            Ok(json!({
                "ok": output.status.success(),
                "outputs": outputs,
                "log": tail(&String::from_utf8_lossy(&output.stderr)),
                "seconds": started.elapsed().as_secs(),
            }))
        })
    }

    fn merge(
        &self,
        effect: &PreparedEffect,
        scope: &Scope,
        project: &str,
        branch: &str,
        expected_base: &str,
        expected_head: &str,
    ) -> Result<Value, ProposalFailure> {
        // One deadline for lock, Git, check and publication.
        let owned = Owned::new(
            self,
            effect,
            scope,
            Duration::from_secs(MERGE_CHECK_SECONDS),
        )?;
        blocking(|| self.merge_blocking(&owned, project, branch, expected_base, expected_head))
    }

    fn search_code(
        &self,
        effect: &PreparedEffect,
        scope: &Scope,
        query: CodeQuery,
        limit: usize,
    ) -> Result<Value, String> {
        let workspace = self.workspace(scope)?;
        let owned = Owned::new(self, effect, scope, Duration::from_secs(OPERATION_SECONDS))?;
        blocking(|| self.search_code_blocking(&owned, &workspace, &query, limit))
    }

    fn inspect_project(
        &self,
        effect: &PreparedEffect,
        scope: &Scope,
        project: &str,
        query: CheckoutQuery,
        limit: usize,
    ) -> Result<Value, String> {
        let root = self.readable_project(scope, project)?;
        let owned = Owned::new(self, effect, scope, Duration::from_secs(OPERATION_SECONDS))?;
        let limit = limit.clamp(1, 200);
        blocking(|| match &query {
            CheckoutQuery::Code(code) => self.search_code_blocking(&owned, &root, code, limit),
            _ => navigation::inspect_checkout(&owned, &root, &query, limit),
        })
    }

    fn nix_log(
        &self,
        effect: &PreparedEffect,
        scope: &Scope,
        verb: NixVerb,
        attr: Option<String>,
    ) -> Result<NixLog, String> {
        if let Some(attr) = &attr {
            if !valid_attr(attr) {
                return Err(format!("{attr:?} is not a flake output name"));
            }
        }
        let capsule = self.capsule(scope)?;
        let owned = Owned::new(self, effect, scope, Duration::from_secs(NIX_SECONDS))?;
        blocking(|| self.nix_log_blocking(&owned, &capsule.path, verb, attr.as_deref()))
    }

    fn run_tests(
        &self,
        effect: &odin_kernel::operation::PreparedEffect,
        scope: &Scope,
        selection: TestSelection,
    ) -> Result<Value, String> {
        match &selection {
            TestSelection::Paths(paths) => {
                if paths.is_empty() || paths.len() > MAX_TEST_PATHS {
                    return Err(
                        "paths must name 1 to 8 capsule-relative .py files for pytest".to_owned(),
                    );
                }
                if let Some(path) = paths.iter().find(|path| !valid_test_path(path)) {
                    return Err(format!(
                        "paths: {path:?} is not a capsule-relative .py test file for pytest"
                    ));
                }
            }
            TestSelection::Attr(Some(attr)) if !valid_attr(attr) => {
                return Err(format!("{attr:?} is not a flake output name"));
            }
            TestSelection::Attr(_) => {}
        }
        // The snapshot's Git preparation runs under the same permit.
        let owned = Owned::new(self, effect, scope, Duration::from_secs(NIX_SECONDS))?;
        let registered = self.registered(scope, &owned)?;
        blocking(|| {
            // The run executes exactly the snapshot frozen (and recorded
            // pending) here; later edits of the working tree are never
            // what it tested. Its report is answered only once recorded.
            let run = self.begin_test_run(&registered, &selection)?;
            let input = odin_cli::live_authority::ScopedTestInput {
                capsule_project: &registered.capsule_project,
                source_commit: &registered.base,
                reference: &run.reference,
                revision: &run.snapshot,
            };
            // A cancelled, retired or expired run errors here: it stays
            // pending and never records a report.
            let log = match &selection {
                TestSelection::Paths(paths) => self
                    .session_pool
                    .as_ref()
                    .ok_or("scoped test session owner is unavailable")?
                    .run_scoped_tests(effect, scope, &input, paths)?,
                TestSelection::Attr(attr) => {
                    let attr = attr.as_deref();
                    self.attr_log(effect, scope, &input, attr)?
                }
            };
            self.finish_test_run(run, &selection, log)
        })
    }

    fn propose(
        &self,
        effect: &PreparedEffect,
        scope: &Scope,
        summary: String,
        branch: Option<String>,
    ) -> Result<Value, ProposalFailure> {
        let capsule = self.publication_capsule(scope)?;
        let owned = Owned::new(self, effect, scope, Duration::from_secs(OPERATION_SECONDS))?;
        let branch = branch.map(|name| seat_branch(&name)).transpose()?;
        let chosen = branch.as_deref().unwrap_or(&capsule.branch);
        let session = scope
            .session
            .as_ref()
            .ok_or("this publication has no session".to_owned())?;
        let project = scope
            .project
            .as_ref()
            .ok_or("this publication has no project".to_owned())?;
        blocking(|| {
            let mut claim =
                self.claim_branch(&owned, &capsule, project.as_str(), session.as_str(), chosen)?;
            publication::propose_capsule(&owned, &capsule, &summary, Some(chosen), &mut claim)
        })
    }

    fn carry_review_evidence(
        &self,
        predecessor: &odin_domain::SessionId,
        successor: &odin_domain::SessionId,
    ) -> Result<(), String> {
        // The rollover holds no admitted permit: its claim identity lookups
        // run on the pool's lifecycle owner under one carry deadline, and a
        // closed pool (the daemon stopping) launches none.
        let lifecycle = std::sync::atomic::AtomicBool::new(false);
        let runner = Lifecycle::new(
            self.session_pool.as_deref(),
            &lifecycle,
            Duration::from_secs(CARRY_SECONDS),
        );
        blocking(|| {
            self.carry_review_evidence_blocking(&runner, predecessor.as_str(), || {
                // Only a real registered Git capsule of the successor can
                // receive evidence; its seat, project and base are checked
                // against every carried record.
                let pool = self
                    .session_pool
                    .as_ref()
                    .ok_or("the successor has no registered code capsule")?;
                pool.registered_code_capsule(successor)
            })
        })
    }

    fn request_review(
        &self,
        effect: &PreparedEffect,
        scope: &Scope,
        reviewer: String,
    ) -> Result<Value, String> {
        let owned = Owned::new(self, effect, scope, Duration::from_secs(OPERATION_SECONDS))?;
        let registered = self.registered(scope, &owned)?;
        let lane = scope.lane.as_ref().map(|lane| lane.as_str().to_owned());
        blocking(|| self.request_review_on(&registered, &reviewer, lane.as_deref()))
    }

    fn record_verdict(
        &self,
        scope: &Scope,
        diff_digest: String,
        approve: bool,
        notes: String,
    ) -> Result<Value, String> {
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let runner = Lifecycle::new(
            self.session_pool.as_deref(),
            &cancel,
            Duration::from_secs(OPERATION_SECONDS),
        );
        blocking(|| self.record_verdict_blocking(&runner, scope, &diff_digest, approve, &notes))
    }

    fn propose_reviewed(
        &self,
        effect: &PreparedEffect,
        scope: &Scope,
        summary: String,
        branch: Option<String>,
    ) -> Result<Value, ProposalFailure> {
        let branch = branch.map(|name| seat_branch(&name)).transpose()?;
        let owned = Owned::new(self, effect, scope, Duration::from_secs(OPERATION_SECONDS))?;
        let registered = self.registered(scope, &owned)?;
        blocking(|| self.propose_reviewed_blocking(&registered, &summary, branch.as_deref()))
    }

    fn write_artifact(
        &self,
        scope: &Scope,
        source: ArtifactSource,
        media_type: Option<String>,
        share_with: Vec<String>,
    ) -> Result<Value, String> {
        let seat = scope.seat.as_ref().ok_or("this dispatch has no seat")?;
        let project = scope
            .project
            .as_ref()
            .ok_or("this dispatch is not bound to a project")?;
        let (bytes, inferred) = match source {
            ArtifactSource::File(path) => {
                let bytes = self.workspace_file(scope, &path)?;
                (bytes, media_type_of(Path::new(&path)))
            }
            ArtifactSource::Text(text) => (text.into_bytes(), "text/plain"),
        };
        let media_type = media_type.unwrap_or_else(|| inferred.to_owned());
        let mut shares = vec![("seat", seat.to_string()), ("project", project.to_string())];
        for entry in &share_with {
            shares.push(share_reference(entry)?);
        }
        let metadata = store_artifact(&self.state_root, &bytes, &media_type, &shares)?;
        tracing::debug!(
            "artifact written id={} seat={seat} project={project} bytes={} shared={:?}",
            metadata.artifact_id,
            metadata.size_bytes,
            shares
        );
        Ok(json!({
            "artifactId": metadata.artifact_id.to_string(),
            "sizeBytes": metadata.size_bytes,
            "mediaType": metadata.media_type,
            "readableBy": shares
                .iter()
                .map(|(kind, id)| format!("{kind}:{id}"))
                .collect::<Vec<_>>(),
        }))
    }

    fn read_artifact(&self, scope: &Scope, artifact_id: String) -> Result<Value, String> {
        let (bytes, media_type) =
            self.artifact_bytes(scope, &artifact_id, MAX_INLINE_READ_BYTES)?;
        let mut view = json!({
            "artifactId": artifact_id,
            "sizeBytes": bytes.len(),
            "mediaType": media_type,
        });
        match String::from_utf8(bytes) {
            Ok(text) => view["text"] = json!(text),
            Err(error) => {
                use base64::Engine as _;
                view["base64"] =
                    json!(base64::engine::general_purpose::STANDARD.encode(error.into_bytes()))
            }
        }
        Ok(view)
    }

    fn artifact_bytes(
        &self,
        scope: &Scope,
        artifact_id: &str,
        max_bytes: u64,
    ) -> Result<(Vec<u8>, String), String> {
        let id = odin_domain::ArtifactId::new(artifact_id)
            .map_err(|error| format!("{artifact_id:?} is not an artifact id: {error}"))?;
        let ledger = self.ledger()?;
        let unreadable = || format!("no artifact {artifact_id} is shared with you");
        let metadata = ledger
            .artifact(&id)
            .map_err(|error| error.to_string())?
            .ok_or_else(unreadable)?;
        let references = ledger
            .artifact_references(&id)
            .map_err(|error| error.to_string())?;
        let readable = references.iter().any(|reference| {
            (reference.object_kind == "seat"
                && scope.seat.as_ref().map(|seat| seat.as_str()) == Some(&*reference.object_id))
                || (reference.object_kind == "project"
                    && scope.project.as_ref().map(|project| project.as_str())
                        == Some(&*reference.object_id))
        });
        if !readable {
            return Err(unreadable());
        }
        if metadata.size_bytes > max_bytes {
            return Err(format!(
                "{artifact_id} is {} bytes; this use takes at most {max_bytes}",
                metadata.size_bytes
            ));
        }
        let bytes = std::fs::read(self.artifact_root().join(&metadata.storage_path))
            .map_err(|error| format!("{artifact_id}'s bytes are unreadable: {error}"))?;
        if odin_domain::Digest::hash(&bytes) != metadata.digest {
            return Err(format!("{artifact_id}'s stored bytes fail their digest"));
        }
        Ok((bytes, metadata.media_type))
    }
}

/// Where eval stages its runners inside a capsule; never part of a change.
const EVAL_SCRATCH: &str = ".odin-eval";

/// One capsule index writer at a time: parallel tool calls (three
/// `build_run`s at once) otherwise collide on `.git/index.lock`.
static STAGING: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn staging() -> std::sync::MutexGuard<'static, ()> {
    STAGING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Stages every capsule change except eval scratch (an earlier stage or
/// commit of it is undone): what a review digests and a propose commits.
fn stage_change(runner: &dyn GitRunner, capsule: &Path) -> Result<(), String> {
    let _staging = staging();
    stage_change_locked(runner, capsule)
}

fn stage_change_locked(runner: &dyn GitRunner, capsule: &Path) -> Result<(), String> {
    runner.git(capsule, &["add", "-A", "--", "."], None)?;
    runner.git(
        capsule,
        &[
            "rm",
            "-r",
            "-q",
            "--cached",
            "--ignore-unmatch",
            "--",
            EVAL_SCRATCH,
        ],
        None,
    )?;
    Ok(())
}

/// Inside `task.read`'s five-second capability window.
const BRANCH_READ_SECONDS: u64 = 4;

/// A worker capsule's change against its base for `task_read`, on the pool's lifecycle workers.
pub(crate) fn capsule_branch_diff(
    pool: &odin_cli::live_authority::SessionAuthorityPool,
    capsule: &odin_cli::live_authority::RegisteredCodeCapsule,
) -> Result<odin_omp::host_tools::delegation::TaskBranchReport, String> {
    let cancel = std::sync::atomic::AtomicBool::new(false);
    let runner = Lifecycle::new(
        Some(pool),
        &cancel,
        Duration::from_secs(BRANCH_READ_SECONDS),
    );
    let branch = session_branch(capsule.seat.as_str(), capsule.session.as_str());
    blocking(|| {
        navigation::branch_diff(
            &runner,
            &capsule.capsule_project,
            &branch,
            &capsule.source_commit,
        )
    })
}

/// The branch a session's capsule work is handed back on.
pub(crate) fn session_branch(seat: &str, session: &str) -> String {
    format!("seat/{seat}/{}", session.replace(':', "-"))
}

/// A branch a seat may hand back: `seat/<seat>/<id>`.
pub(crate) fn is_seat_branch(branch: &str) -> bool {
    let mut parts = branch.split('/');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some("seat"), Some(seat), Some(id), None)
            if !seat.is_empty()
                && !id.is_empty()
                && branch
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '/')
    )
}

/// A hand-back may name its exact branch: only the seat-branch shape, so a
/// protected ref (`main`) or any other unsafe ref is refused before
/// anything is committed or pushed.
fn seat_branch(branch: &str) -> Result<String, String> {
    if is_seat_branch(branch) {
        Ok(branch.to_owned())
    } else {
        Err(format!(
            "{branch:?} is not a seat branch (seat/<seat>/<id>): leave `branch` out to publish \
             your own session branch"
        ))
    }
}

impl DaemonCodingRoute {
    /// Serialize merges per project, require independent review of the exact head,
    /// and check a temporary worktree before pushing. Cancellation stops the current
    /// step and prevents subsequent steps; a clean root then fast-forwards to the merge.
    fn merge_blocking(
        &self,
        owned: &Owned<'_>,
        project: &str,
        branch: &str,
        expected_base: &str,
        expected_head: &str,
    ) -> Result<Value, ProposalFailure> {
        if !is_seat_branch(branch) {
            return Err(format!("{branch:?} is not a seat branch (seat/<seat>/<id>)").into());
        }
        if !publication::full_commit(expected_base) || !publication::full_commit(expected_head) {
            return Err("merge requires full expected base and head identities"
                .to_owned()
                .into());
        }
        let root = self
            .projects
            .get(project)
            .ok_or_else(|| format!("project {project} has no declared root"))?;
        let url = publication::destination(owned, root)?
            .ok_or_else(|| format!("project {project} has no remote to merge into"))?;
        let _merge_lock = MergeLock::acquire(
            &self.state_root,
            project,
            MERGE_LOCK_BOUND.min(owned.remaining()),
            || owned.cancelled(),
        )?;
        tracing::info!("seat-branch merging project={project} branch={branch}");
        let local = format!("refs/heads/{branch}");
        let advertised = owned.git_remote(
            root,
            &[
                "ls-remote",
                "--heads",
                "--",
                &url,
                "refs/heads/main",
                &local,
            ],
        )?;
        let (mut base, mut head) = (None, None);
        for line in advertised.lines() {
            let (commit, reference) = line
                .split_once('\t')
                .ok_or_else(|| "merge ref advertisement is malformed".to_owned())?;
            if !publication::full_commit(commit) {
                return Err("merge ref advertisement lacks a full commit"
                    .to_owned()
                    .into());
            }
            let slot = if reference == "refs/heads/main" {
                &mut base
            } else if reference == local {
                &mut head
            } else {
                return Err("merge ref advertisement names an unexpected ref"
                    .to_owned()
                    .into());
            };
            if slot.replace(commit).is_some() {
                return Err("merge ref advertisement repeats a ref".to_owned().into());
            }
        }
        let base = base.ok_or_else(|| "the remote has no main branch".to_owned())?;
        let head =
            head.ok_or_else(|| format!("there is no branch {branch} in project {project}"))?;
        if !head.eq_ignore_ascii_case(expected_head) {
            return Err(format!(
                "branch {branch} moved: expected {expected_head}, observed {head}"
            )
            .into());
        }
        let local_observed = owned.git(
            root,
            &[
                "for-each-ref",
                "--format=%(objectname)%09%(refname)",
                &local,
            ],
            None,
        )?;
        if publication::parse_ref_head(&local_observed, &local)?
            .is_some_and(|commit| commit != head)
        {
            return Err(
                "the offered local branch differs from the expected remote head"
                    .to_owned()
                    .into(),
            );
        }
        // Fetch immutable objects, not mutable tracking refs or the user's branch.
        owned.git_remote(
            root,
            &["fetch", "--quiet", "--no-tags", "--", &url, base, head],
        )?;
        // A retried merge of a tip main already holds is done: no second
        // check, no second push.
        if owned.git_holds(root, &["merge-base", "--is-ancestor", head, base])? {
            tracing::warn!(
                "seat-branch already merged project={project} branch={branch} \
                 head={head} main={base}"
            );
            return Ok(json!({
                "project": project,
                "branch": branch,
                "mergeCommit": base,
                "remote": url,
                "alreadyMerged": true,
            }));
        }
        if !base.eq_ignore_ascii_case(expected_base) {
            return Err(format!(
                "main moved: expected {expected_base}, observed {base}; retry git_branch_merge \
                 with expectedBase {base} and the same expectedHead {expected_head}"
            )
            .into());
        }
        let review = self
            .approved_review(project, branch, head)?
            .ok_or_else(|| {
                let short = &head[..head.len().min(12)];
                format!(
                    "{branch} is not approved to merge at commit {short}: no approving \
                     independent review is bound to this exact commit"
                )
            })?;
        let reviewer = review.reviewer;
        let worktree = self
            .state_root
            .join("merge-worktrees")
            .join(uuid::Uuid::new_v4().simple().to_string());
        let worktree_text = worktree
            .to_str()
            .ok_or_else(|| "the merge worktree path is not UTF-8".to_owned())?;
        // Capture the project's administrative directory to confine later cleanup.
        let common = owned.git(
            root,
            &["rev-parse", "--path-format=absolute", "--git-common-dir"],
            None,
        )?;
        let common = Path::new(&common)
            .canonicalize()
            .map_err(|error| format!("{common}: {error}"))?;
        let mut check_seconds = 0u64;
        let merged = (|| -> Result<String, ProposalFailure> {
            owned.git(
                root,
                &[
                    "worktree",
                    "add",
                    "--quiet",
                    "--detach",
                    worktree_text,
                    base,
                ],
                None,
            )?;
            let attributes_path = owned.git(
                &worktree,
                &["rev-parse", "--git-path", "info/attributes"],
                None,
            )?;
            apply_mergiraf_attributes(&worktree.join(attributes_path))?;
            let message = format!("Merge {branch} (reviewed by {reviewer} through Odin)");
            if let Err(error) = owned.git(
                &worktree,
                &[
                    "-c",
                    "merge.conflictstyle=diff3",
                    "-c",
                    "merge.mergiraf.name=mergiraf",
                    "-c",
                    &format!("merge.mergiraf.driver={}", mergiraf_driver()),
                    "merge",
                    "--no-ff",
                    "--no-edit",
                    "-m",
                    &message,
                    // The exact reviewed commit, never the mutable branch ref.
                    head,
                ],
                Some("Odin"),
            ) {
                // The throwaway worktree is removed whole; nothing to abort.
                return Err(format!("{branch} does not merge cleanly into main: {error}").into());
            }
            let commit = owned.git(&worktree, &["rev-parse", "HEAD"], None)?;
            let started = Instant::now();
            let declared = owned.nix(&worktree, nix_checks_presence_argv(&worktree))?;
            let declared_names = if declared.status.success() {
                serde_json::from_str::<Vec<String>>(&String::from_utf8_lossy(&declared.stdout))
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            if declared_names.is_empty() {
                let log = tail(&String::from_utf8_lossy(&declared.stderr));
                tracing::error!(
                    "seat-branch check failed project={project} branch={branch} \
                     reason=declares-no-checks"
                );
                return Err(format!("the merged main declares no checks: {log}").into());
            }
            let flake = format!("git+file://{}", worktree.display());
            let output = owned.nix(&worktree, nix_flake_argv(&flake, NixVerb::Check, None))?;
            check_seconds = started.elapsed().as_secs();
            if !output.status.success() {
                let log = tail(&String::from_utf8_lossy(&output.stderr));
                tracing::error!(
                    "seat-branch check failed project={project} branch={branch} \
                     seconds={check_seconds}"
                );
                return Err(format!("the merged main fails its declared check: {log}").into());
            }
            if owned.git(&worktree, &["rev-parse", "HEAD"], None)? != commit
                || !owned
                    .git(&worktree, &["status", "--porcelain"], None)?
                    .is_empty()
            {
                return Err("the checked merge worktree changed before publication"
                    .to_owned()
                    .into());
            }
            publication::push_merged(owned, &worktree, &url, base, &commit)?;
            Ok(commit)
        })();
        if let Err(error) = remove_merge_worktree(&worktree, &common) {
            tracing::error!(
                "coding-route worktree-leaked root={} worktree={worktree_text} \
                 reason={error}",
                root.display()
            );
            let publication = match &merged {
                Ok(commit) => format!("remote main accepted merge {commit}"),
                Err(error) => format!("merge did not settle: {error}"),
            };
            return Err(ProposalFailure::Uncertain(format!(
                "{publication}; cleanup of {worktree_text} was not proved: {error}"
            )));
        }
        let commit = merged?;
        // Keep the declared root current when it sits clean on main; after a
        // cancellation these steps launch nothing and the root stays as is.
        let on_main = owned
            .git(root, &["symbolic-ref", "--short", "HEAD"], None)
            .is_ok_and(|head| head == "main");
        let clean = owned
            .git(root, &["status", "--porcelain"], None)
            .is_ok_and(|out| out.is_empty());
        let fast_forwarded = on_main
            && clean
            && owned
                .git(
                    root,
                    &[
                        "merge",
                        "--ff-only",
                        "--no-overwrite-ignore",
                        "--quiet",
                        &commit,
                    ],
                    None,
                )
                .is_ok();
        tracing::info!(
            "seat-branch merged project={project} branch={branch} commit={commit} \
             remote={url} root_fast_forwarded={fast_forwarded} reviewer={reviewer} \
             check_seconds={check_seconds}"
        );
        Ok(json!({
            "project": project,
            "branch": branch,
            "mergeCommit": commit,
            "remote": url,
            "rootFastForwarded": fast_forwarded,
        }))
    }
}

/// One merge of a declared project at a time. The lock file is created
/// once and never unlinked, so waiters always lock the same inode; a
/// released-then-unlinked file would let a raced waiter hold a stale
/// inode beside a fresh lock — two concurrent merges of one project.
struct MergeLock {
    file: std::fs::File,
}

impl MergeLock {
    /// Waits at most `bound`, and not past a cancellation of the waiting
    /// operation.
    fn acquire(
        state_root: &Path,
        project: &str,
        bound: Duration,
        cancelled: impl Fn() -> bool,
    ) -> Result<Self, String> {
        use std::fs::TryLockError;

        let directory = state_root.join("merge-locks");
        std::fs::create_dir_all(&directory)
            .map_err(|error| format!("could not create {}: {error}", directory.display()))?;
        let name = if odin_registry::schema::valid_id(project) {
            project.to_owned()
        } else {
            odin_domain::Digest::hash(project.as_bytes())
                .to_string()
                .trim_start_matches("blake3:")
                .to_owned()
        };
        let lock_path = directory.join(format!("{name}.lock"));
        let deadline = Instant::now() + bound;
        loop {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&lock_path)
                .map_err(|error| {
                    format!(
                        "could not open the merge lock {}: {error}",
                        lock_path.display()
                    )
                })?;
            match file.try_lock() {
                Ok(()) => return Ok(Self { file }),
                Err(TryLockError::WouldBlock) => {}
                Err(TryLockError::Error(error)) => {
                    return Err(format!(
                        "merge lock {} failed: {error}",
                        lock_path.display()
                    ));
                }
            }
            if cancelled() {
                return Err(format!("the merge of project {project} was cancelled"));
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(format!(
                    "another merge of project {project} is already in flight"
                ));
            }
            // An in-process holder wakes this waiter on release; a holder in
            // another process is seen at the next second's retry.
            let (released, wake) = &MERGE_RELEASED;
            let guard = released.lock().map_err(|_| "merge lock wake is poisoned")?;
            let _ = wake.wait_timeout(guard, (deadline - now).min(Duration::from_secs(1)));
        }
    }
}

/// Clean up without Git because the permit may have expired or been cancelled.
/// Require `<common>/worktrees/<name>`, reject symlinks, and check reciprocal
/// `.git`/`gitdir` links when present. Partial creation may leave either side;
/// retain paths whose identity cannot be verified and report them in the error.
fn remove_merge_worktree(worktree: &Path, common: &Path) -> Result<(), String> {
    let canonical = |path: &Path| {
        path.canonicalize()
            .map_err(|error| format!("{}: {error}", path.display()))
    };
    // A real directory, absent, or an error: never a followed symlink.
    let present = |path: &Path| match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(true),
        Ok(_) => Err(format!("{} is not a real directory", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("{}: {error}", path.display())),
    };
    let unproved = |path: &Path, why: &str| {
        Err(format!(
            "{} is not provably this merge's ({why}); it is left in place",
            path.display()
        ))
    };
    let name = worktree
        .file_name()
        .ok_or("the merge worktree has no name")?;
    let admin = canonical(common)?.join("worktrees").join(name);
    let (has_worktree, has_admin) = (present(worktree)?, present(&admin)?);
    if has_admin && canonical(&admin)? != admin {
        return unproved(&admin, "it resolves elsewhere");
    }
    if has_worktree {
        match std::fs::read_to_string(worktree.join(".git")) {
            Ok(link) => {
                let Some(named) = link.trim().strip_prefix("gitdir: ") else {
                    return unproved(worktree, "its .git link is malformed");
                };
                if !has_admin || canonical(&worktree.join(named))? != admin {
                    return unproved(worktree, "its .git link names another directory");
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("{}: {error}", worktree.display())),
        }
    }
    if has_admin {
        let Ok(back) = std::fs::read_to_string(admin.join("gitdir")) else {
            return unproved(&admin, "it names no worktree");
        };
        let back = admin.join(back.trim());
        let names_this = back.file_name().is_some_and(|file| file == ".git")
            && back.parent().is_some_and(|parent| {
                parent == worktree
                    || matches!(
                        (canonical(parent), canonical(worktree)),
                        (Ok(named), Ok(this)) if has_worktree && named == this
                    )
            });
        if !names_this {
            return unproved(&admin, "it names another worktree");
        }
    }
    for (directory, owned) in [(worktree, has_worktree), (admin.as_path(), has_admin)] {
        if owned {
            std::fs::remove_dir_all(directory)
                .map_err(|error| format!("{}: {error}", directory.display()))?;
        }
    }
    Ok(())
}

static MERGE_RELEASED: (std::sync::Mutex<()>, std::sync::Condvar) =
    (std::sync::Mutex::new(()), std::sync::Condvar::new());

impl Drop for MergeLock {
    fn drop(&mut self) {
        // Unlock ONLY. The lock file stays on disk forever: unlinking here
        // would let a waiter that raced a release hold the old inode while
        // a new entrant creates and locks a fresh one — two concurrent
        // merges of one project.
        let _ = self.file.unlock();
        let (released, wake) = &MERGE_RELEASED;
        let _guard = released.lock();
        wake.notify_all();
    }
}
#[cfg(test)]
pub(crate) fn review_registry() -> std::sync::Arc<odin_registry::SnapshotHandle> {
    use std::sync::LazyLock;
    static PIN: LazyLock<std::sync::Arc<odin_registry::SnapshotHandle>> = LazyLock::new(|| {
        fn copy_tree(source: &std::path::Path, destination: &std::path::Path) {
            std::fs::create_dir_all(destination).unwrap();
            for entry in std::fs::read_dir(source).unwrap() {
                let entry = entry.unwrap();
                let target = destination.join(entry.file_name());
                if entry.file_type().unwrap().is_dir() {
                    copy_tree(&entry.path(), &target);
                } else {
                    std::fs::copy(entry.path(), target).unwrap();
                }
            }
        }
        let root =
            std::env::temp_dir().join(format!("odin-review-registry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let repository = root.join("repo");
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for tree in ["registry", "schemas"] {
            copy_tree(&source.join(tree), &repository.join(tree));
        }
        crate::test_support::git(
            &repository,
            &["-c", "init.defaultBranch=main", "init", "--quiet"],
        );
        let commit = crate::test_support::commit_all(&repository, "review registry fixture");
        let store = odin_registry::SnapshotStore::new(root.join("snapshot.json"));
        let candidate = odin_registry::ValidatedSnapshotCandidate::from_committed_worktree(
            &repository,
            &commit,
            odin_cli::runtime_bindings::admitted_registry_bindings(),
        )
        .expect("review registry candidate");
        store
            .publish_committed(&candidate, 1)
            .expect("publish review registry");
        std::sync::Arc::new(
            odin_registry::SnapshotHandle::open(store).expect("open review registry"),
        )
    });
    std::sync::Arc::clone(&PIN)
}

#[cfg(test)]
#[path = "tests/coding_route.rs"]
mod tests;

#[cfg(test)]
mod staging_tests {
    use super::{stage_change, valid_test_path, Unowned};
    use crate::test_support::git;

    #[test]
    fn staging_ignored_eval_scratch_keeps_changes_and_unstages_scratch() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        git(root, &["init", "-q"]);
        std::fs::write(root.join(".gitignore"), ".odin-eval/\n").unwrap();
        std::fs::create_dir(root.join(".odin-eval")).unwrap();
        std::fs::write(root.join(".odin-eval/runner.py"), "print(1)\n").unwrap();
        std::fs::write(root.join("config.toml"), "enabled = true\n").unwrap();

        for pre_staged in [false, true] {
            if pre_staged {
                git(root, &["add", "-f", "--", ".odin-eval/runner.py"]);
            }
            stage_change(&Unowned, root).unwrap();
            assert_eq!(git(root, &["ls-files"]), ".gitignore\nconfig.toml");
            assert!(root.join(".odin-eval/runner.py").is_file());
        }
    }

    #[test]
    fn pytest_paths_require_python_files() {
        assert!(valid_test_path("tests/test_config.py"));
        for path in [
            "tests",
            "README.md",
            "flake.nix",
            "test.rs",
            "test.py::test_config",
        ] {
            assert!(!valid_test_path(path), "{path}");
        }
    }
}
