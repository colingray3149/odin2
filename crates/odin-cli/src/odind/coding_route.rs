//! Coding tools over registered session capsules and reviewed Git publication.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use odin_cli::eval_daemon::{apply_mergiraf_attributes, mergiraf_driver};
use odin_cli::live_authority::ScopedRun;
use odin_domain::Scope;
use odin_hermes::runtime::coding::{
    ArtifactSource, CheckoutQuery, CodeQuery, CodingRoute, NixLog, NixVerb, ProposalFailure,
    TestSelection,
};
use odin_kernel::operation::PreparedEffect;
use serde_json::{json, Value};

#[path = "coding_route/artifacts.rs"]
mod artifacts;
#[path = "coding_route/budgets.rs"]
mod budgets;
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
#[path = "coding_route/science_review.rs"]
pub(crate) mod science_review;
#[path = "coding_route/sphere.rs"]
mod sphere;

use artifacts::share_reference;
pub(crate) use artifacts::{
    controller_artifact_id, media_type_of, store_artifact, store_artifact_file,
};

#[cfg(test)]
pub(crate) use execution::Unowned;
pub(crate) use execution::{GitRunner, Lifecycle, Owned};

/// A build or check longer than this is killed (the capability timeout is a
/// minute longer, so the typed result always arrives).
const NIX_SECONDS: u64 = 1_200;
/// Hand-back, review, and search deadline; the capability permit may expire first.
pub(crate) const OPERATION_SECONDS: u64 = 1_200;
/// The most bytes one `artifact.read` page returns.
const MAX_ARTIFACT_PAGE_BYTES: usize = 262_144;
const LOG_TAIL_BYTES: usize = 6_000;
/// Rollover claim carry only reads repository identities.
const CARRY_SECONDS: u64 = 120;
/// Leave a minute before the merge capability expires so a refusal can be delivered.
const MERGE_CHECK_SECONDS: u64 = 1_140;

/// Waiting must leave room for this merge's own fetch, merge, check and
/// push inside the same capability window.
pub(crate) const MERGE_LOCK_BOUND: Duration = Duration::from_secs(30);
/// How long a waiting merge sleeps before it looks at the lock file again, whatever wakes it.
const MERGE_LOCK_RECHECK: Duration = Duration::from_secs(1);

pub(crate) struct DaemonCodingRoute {
    pub(crate) state_root: PathBuf,
    pub(crate) session_pool: Option<std::sync::Arc<odin_cli::live_authority::SessionAuthorityPool>>,
    pub(crate) supervisor: std::sync::Weak<odin_omp::live::supervisor::LiveSupervisor>,
    /// Declared project roots (the rendered `projects` plus runtime-created).
    pub(crate) projects: BTreeMap<String, PathBuf>,
    /// Live published registry. Review admission reads the project/lane
    /// verdict capability and the named seat's grants from it.
    pub(crate) registry: Option<std::sync::Arc<odin_registry::SnapshotHandle>>,
    /// Pinned executables for daemon-owned capsule commands. Absent in
    /// tests that never exec a build.
    pub(crate) manifest: Option<odin_huginn::RuntimeManifest>,
    /// How long a merge waits behind another merge of its project.
    pub(crate) merge_lock_bound: Duration,
}

/// One session's capsule and where its work goes.
struct Capsule {
    path: PathBuf,
    project_root: PathBuf,
    branch: String,
    seat: String,
}

/// Fails unless the file holds exactly the artifact's registered bytes; leaves it at the start.
fn verify_artifact(
    file: &mut std::fs::File,
    metadata: &odin_ledger::artifact::ArtifactMetadata,
    artifact_id: &str,
) -> Result<(), String> {
    use std::io::{Seek, SeekFrom};
    let mut hasher = blake3::Hasher::new();
    hasher
        .update_reader(&mut *file)
        .map_err(|error| error.to_string())?;
    if hasher.finalize().as_bytes() != metadata.digest.as_bytes()
        || file.stream_position().map_err(|error| error.to_string())? != metadata.size_bytes
    {
        return Err(format!("{artifact_id}'s stored bytes fail their digest"));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| error.to_string())
        .map(|_| ())
}

impl DaemonCodingRoute {
    /// The stored bytes of an artifact shared with the caller's seat or project.
    fn open_artifact(
        &self,
        scope: &Scope,
        artifact_id: &str,
    ) -> Result<(std::fs::File, odin_ledger::artifact::ArtifactMetadata), String> {
        let id = controller_artifact_id(artifact_id)?;
        let ledger = self.ledger()?;
        let unreadable = || format!("no artifact {artifact_id} is shared with you");
        let metadata = ledger
            .artifact(&id)
            .map_err(|error| error.to_string())?
            .ok_or_else(unreadable)?;
        if !ledger
            .artifact_references(&id)
            .map_err(|error| error.to_string())?
            .iter()
            .any(|reference| {
                (reference.object_kind == "seat"
                    && scope.seat.as_ref().map(|id| id.as_str())
                        == Some(reference.object_id.as_str()))
                    || (reference.object_kind == "project"
                        && scope.project.as_ref().map(|id| id.as_str())
                            == Some(reference.object_id.as_str()))
            })
        {
            return Err(unreadable());
        }
        let file = odin_confined_fs::Capability::seal(&self.artifact_root())
            .and_then(|root| root.open_read(Path::new(&metadata.storage_path)))
            .map_err(|error| format!("{artifact_id}'s bytes are unreadable: {error}"))?;
        Ok((file, metadata))
    }

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
/// capsule, or a test run's frozen snapshot revision. The host daemon
/// builds; flake config from the project is never accepted.
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
                "--option",
                "substitute",
                "true",
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
                "--option",
                "substitute",
                "true",
                flake,
            ]
            .map(str::to_owned),
        ),
    }
    argv
}

/// The staged capsule as a dirty `git+file` flake.
/// Who may read an artifact the caller stores: its seat and, when it has one, its project.
fn artifact_shares(scope: &Scope) -> Result<Vec<(&'static str, String)>, String> {
    let seat = scope.seat.as_ref().ok_or("this dispatch has no seat")?;
    let mut shares = vec![("seat", seat.to_string())];
    if let Some(project) = &scope.project {
        shares.push(("project", project.to_string()));
    }
    Ok(shares)
}

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
        "--option",
        "substitute",
        "true",
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
        // One lane build slot covers the whole nix step: the build it runs
        // is the work the cap counts, whatever builder executes it.
        let _slot = self.hold_lane_build_slot(scope)?;
        blocking(|| {
            // Staged files are part of a dirty `git+file` flake; untracked
            // ones would silently be missing from the build.
            stage_change(&owned, &capsule.path)?;
            let started = Instant::now();
            let flake = capsule_flake(&capsule.path);
            let argv = nix_flake_argv(&flake, verb, attr.as_deref());
            let output = self.nix_in_capsule(
                &owned,
                &capsule.path,
                argv,
                self.lane_slot_env(scope)?,
                sphere::BUILD_CAPTURE,
            )?;
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
        let slot_env = self.lane_slot_env(scope)?;
        let _slot = self.hold_lane_build_slot(scope)?;
        // One deadline for lock, Git, check and publication.
        let owned = Owned::new(
            self,
            effect,
            scope,
            Duration::from_secs(MERGE_CHECK_SECONDS),
        )?;
        blocking(|| {
            self.merge_blocking(
                &owned,
                project,
                branch,
                expected_base,
                expected_head,
                &slot_env,
            )
        })
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
        let _slot = self.hold_lane_build_slot(scope)?;
        blocking(|| {
            self.nix_log_blocking(
                &owned,
                &capsule.path,
                verb,
                attr.as_deref(),
                self.lane_slot_env(scope)?,
            )
        })
    }

    fn run_tests(
        &self,
        effect: &odin_kernel::operation::PreparedEffect,
        scope: &Scope,
        selection: TestSelection,
    ) -> Result<Value, String> {
        engineering::check_selection(&selection)?;
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
                    .run_scoped_tests(effect, scope, &input, ScopedRun::Pytest(paths))?,
                TestSelection::Cargo(cargo) => {
                    let _slot = self.hold_lane_build_slot(scope)?;
                    self.session_pool
                        .as_ref()
                        .ok_or("scoped test session owner is unavailable")?
                        .run_scoped_tests(effect, scope, &input, ScopedRun::Cargo(cargo))?
                }
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

    fn record_science_verdict(
        &self,
        scope: &Scope,
        proposal: String,
        approve: bool,
        notes: String,
    ) -> Result<Value, String> {
        blocking(|| self.record_science_verdict_on(scope, &proposal, approve, &notes))
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
        let mut shares = artifact_shares(scope)?;
        for entry in &share_with {
            shares.push(share_reference(entry)?);
        }
        let metadata = match source {
            ArtifactSource::Existing(id) => {
                self.share_existing_artifact(scope, &id, media_type.as_deref(), &shares)?
            }
            ArtifactSource::File(path) => {
                let bytes = self.workspace_file(scope, &path)?;
                let inferred = media_type_of(Path::new(&path));
                store_artifact(
                    &self.state_root,
                    &bytes,
                    media_type.as_deref().unwrap_or(inferred),
                    &shares,
                )?
            }
            ArtifactSource::Text(text) => store_artifact(
                &self.state_root,
                text.as_bytes(),
                media_type.as_deref().unwrap_or("text/plain"),
                &shares,
            )?,
        };
        tracing::debug!(
            "artifact written id={} bytes={} shared={:?}",
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

    fn share_bytes(&self, scope: &Scope, bytes: &[u8], media_type: &str) -> Result<String, String> {
        let shares = artifact_shares(scope)?;
        Ok(
            store_artifact(&self.state_root, bytes, media_type, &shares)?
                .artifact_id
                .to_string(),
        )
    }

    fn share_file(
        &self,
        scope: &Scope,
        file: &mut std::fs::File,
        media_type: &str,
    ) -> Result<String, String> {
        let shares = artifact_shares(scope)?;
        Ok(
            store_artifact_file(&self.state_root, file, media_type, &shares)?
                .artifact_id
                .to_string(),
        )
    }

    /// An artifact's stored bytes whose digest and size were just checked.
    fn artifact_file(
        &self,
        scope: &Scope,
        artifact_id: &str,
    ) -> Result<(std::fs::File, String), String> {
        let (mut file, metadata) = self.open_artifact(scope, artifact_id)?;
        verify_artifact(&mut file, &metadata, artifact_id)?;
        Ok((file, metadata.media_type))
    }

    fn read_artifact(
        &self,
        scope: &Scope,
        artifact_id: String,
        offset: u64,
        limit: usize,
    ) -> Result<Value, String> {
        use std::io::{Read, Seek, SeekFrom};
        if !(1..=MAX_ARTIFACT_PAGE_BYTES).contains(&limit) {
            return Err(format!(
                "artifact page limit must be 1..={MAX_ARTIFACT_PAGE_BYTES}"
            ));
        }
        let (mut file, metadata) = self.open_artifact(scope, &artifact_id)?;
        // The first page proves the stored bytes; later pages of one read do not re-hash them.
        if offset == 0 {
            verify_artifact(&mut file, &metadata, &artifact_id)?;
        }
        let media_type = metadata.media_type;
        let total = file.metadata().map_err(|error| error.to_string())?.len();

        let offset = offset.min(total);
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| error.to_string())?;
        let mut bytes = Vec::with_capacity(limit.min((total - offset) as usize));
        file.take(limit as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        // A page that ends inside a multi-byte character stops before it, so
        // text stays text and the next page starts on a character boundary.
        if let Err(cut) = std::str::from_utf8(&bytes) {
            if cut.error_len().is_none()
                && cut.valid_up_to() > 0
                && offset + (bytes.len() as u64) < total
            {
                bytes.truncate(cut.valid_up_to());
            }
        }
        let next = offset + bytes.len() as u64;
        let mut view = json!({
            "artifactId": artifact_id, "sizeBytes": bytes.len(), "mediaType": media_type,
            "offset": offset, "next_offset": next, "eof": next == total, "totalBytes": total,
        });
        match String::from_utf8(bytes) {
            Ok(text) => view["text"] = json!(text),
            Err(error) => {
                use base64::Engine as _;
                view["base64"] =
                    json!(base64::engine::general_purpose::STANDARD.encode(error.into_bytes()));
            }
        }
        Ok(view)
    }
    fn analyze_artifact(
        &self,
        effect: &PreparedEffect,
        scope: &Scope,
        artifact_id: String,
        program: Vec<String>,
    ) -> Result<Value, String> {
        let owned = Owned::new(self, effect, scope, Duration::from_secs(OPERATION_SECONDS))?;
        blocking(|| self.analyze_in_capsule(&owned, &artifact_id, program))
    }

    fn artifact_bytes(
        &self,
        scope: &Scope,
        artifact_id: &str,
        max_bytes: u64,
    ) -> Result<(Vec<u8>, String), String> {
        use std::io::Read;
        let (mut file, media_type) = self.artifact_file(scope, artifact_id)?;
        let size = file.metadata().map_err(|error| error.to_string())?.len();
        if size > max_bytes {
            return Err(format!(
                "{artifact_id} is {size} bytes; this use takes at most {max_bytes}"
            ));
        }
        let mut bytes =
            Vec::with_capacity(usize::try_from(size).map_err(|error| error.to_string())?);
        file.read_to_end(&mut bytes)
            .map_err(|error| format!("{artifact_id}'s bytes are unreadable: {error}"))?;
        Ok((bytes, media_type))
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
        slot_env: &[(String, String)],
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
            self.merge_lock_bound.min(owned.remaining()),
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
            let declared = self.nix_in_capsule(
                owned,
                &worktree,
                nix_checks_presence_argv(&worktree),
                slot_env.to_vec(),
                sphere::BUILD_CAPTURE,
            )?;
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
            let flake = capsule_flake(&worktree);
            let output = self.nix_in_capsule(
                owned,
                &worktree,
                nix_flake_argv(&flake, NixVerb::Check, None),
                slot_env.to_vec(),
                sphere::BUILD_CAPTURE,
            )?;
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
            let guard = released
                .lock()
                .map_err(|error| format!("merge lock wake: {error}"))?;
            let _ = wake.wait_timeout(guard, (deadline - now).min(MERGE_LOCK_RECHECK));
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
pub(crate) fn review_registry() -> (
    std::sync::Arc<odin_registry::SnapshotHandle>,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().unwrap();
    let repository = dir.path().join("repo");
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for tree in ["registry", "schemas"] {
        crate::test_fixture::copy_tree(&source.join(tree), &repository.join(tree));
    }
    crate::test_support::git(
        &repository,
        &["-c", "init.defaultBranch=main", "init", "--quiet"],
    );
    let commit = crate::test_support::commit_all(&repository, "review registry fixture");
    let store = odin_registry::SnapshotStore::new(dir.path().join("snapshot.json"));
    let candidate = odin_registry::ValidatedSnapshotCandidate::from_committed_worktree(
        &repository,
        &commit,
        odin_cli::runtime_bindings::admitted_registry_bindings(),
    )
    .expect("review registry candidate");
    store
        .publish_committed(&candidate, 1)
        .expect("publish review registry");
    (
        std::sync::Arc::new(
            odin_registry::SnapshotHandle::open(store).expect("open review registry"),
        ),
        dir,
    )
}

#[cfg(test)]
#[path = "coding_route/file_result_tests.rs"]
mod file_result_tests;

#[cfg(test)]
#[path = "tests/coding_route.rs"]
mod tests;

#[cfg(test)]
mod staging_tests {

    use super::{stage_change, Unowned};
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
}

#[cfg(test)]
mod confined_nix_tests {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use super::nix_flake_argv;
    use odin_hermes::runtime::coding::NixVerb;
    use odin_omp::process::{capsule_nix_argv, SphereProjection};

    fn store_bin(name: &str) -> Option<PathBuf> {
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path).find_map(|dir| {
            let candidate = dir.join(name);
            candidate
                .canonicalize()
                .ok()
                .filter(|resolved| resolved.starts_with("/nix/store/"))
        })
    }

    fn required(name: &str) -> PathBuf {
        store_bin(name).unwrap_or_else(|| {
            panic!("{name} missing from PATH as a /nix/store binary: run inside nix develop")
        })
    }

    /// A build inside the bubble realizes through the host daemon.
    #[test]
    fn a_capsule_build_realizes_through_the_host_daemon() {
        let (bwrap, nix, bash) = (required("bwrap"), required("nix"), required("bash"));
        assert!(
            Path::new(odin_omp::process::NIX_DAEMON_SOCKET).exists(),
            "nix daemon socket missing at {}: run inside nix develop",
            odin_omp::process::NIX_DAEMON_SOCKET
        );
        let system = Command::new(&nix)
            .args([
                "eval",
                "--raw",
                "--impure",
                "--expr",
                "builtins.currentSystem",
            ])
            .output()
            .expect("current system");
        let system = String::from_utf8(system.stdout).expect("system utf-8");
        let root = tempfile::tempdir().expect("capsule parent");
        let capsule = root.path().join("project");
        std::fs::create_dir(&capsule).expect("capsule");
        let marker = uuid::Uuid::new_v4().simple().to_string();
        let flake = format!(
            "{{\n  outputs = {{ self }}: {{\n    default = derivation {{\n      name = \"odin-capsule-marker\";\n      system = \"{}\";\n      preferLocalBuild = true; allowSubstitutes = false;\n      builder = builtins.appendContext \"{}\" {{ \"{}\" = {{ path = true; }}; }};\n      args = [ \"-c\" \"echo {marker} > \\$out\" ];\n    }};\n  }};\n}}\n",
            system.trim(),
            bash.display(),
            bash.parent().and_then(Path::parent).expect("bash store").display()
        );
        std::fs::write(capsule.join("flake.nix"), flake).expect("flake");
        let sphere = SphereProjection {
            data_roots: Vec::new(),
            scratch: capsule.clone(),
            devices: Vec::new(),
            endpoints: Vec::new(),
        };
        let mut command = vec![nix.display().to_string()];
        command.extend(nix_flake_argv("path:.", NixVerb::Build, Some("default")));
        let argv = capsule_nix_argv(&capsule, &sphere, &[], &command).expect("argv");

        let output = Command::new(&bwrap).args(&argv).output().expect("bwrap");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "capsule build failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let realized = stdout
            .lines()
            .find(|line| line.contains("odin-capsule-marker"))
            .expect("print-out-paths");
        assert_eq!(
            std::fs::read_to_string(realized).expect("realized in the host store"),
            format!("{marker}\n")
        );
    }
}
