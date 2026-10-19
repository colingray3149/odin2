//! Non-OMP workspaces publish the exact branch selected by the task.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use async_trait::async_trait;
use odin_domain::huginn::{LiveError, SessionManifest};
use odin_omp::live::harness::{HarnessRoute, HarnessWorkspace};
use odin_registry::EnvironmentTransport;
use serde_json::Value;

use crate::coding_route::{GitRunner, Lifecycle};

#[path = "workspace/publication.rs"]
mod publication;

pub(crate) struct DaemonHarnessWorkspace {
    /// Declared project roots on the authority.
    pub(crate) projects: BTreeMap<String, PathBuf>,
    /// The authority's host name as other fleet machines reach it.
    pub(crate) authority_host: String,
    pub(crate) state_root: PathBuf,
    pub(crate) supervisor: crate::live_authority::SupervisorHandle,
    /// The session pool whose lifecycle owner runs every hand-back step as
    /// a registered worker; closed at the daemon's stop.
    pub(crate) pool: crate::live_authority::SessionPoolHandle,
}

struct Placement {
    project_root: PathBuf,
    branch: String,
    seat: String,
}

impl DaemonHarnessWorkspace {
    fn placement(&self, manifest: &SessionManifest) -> Result<Placement, LiveError> {
        let project_root = self
            .projects
            .get(manifest.project_id.as_str())
            .cloned()
            .ok_or_else(|| LiveError::NotFound {
                object_kind: "projectRoot".to_owned(),
                object_id: manifest.project_id.to_string(),
            })?;
        Ok(Placement {
            project_root,
            branch: format!("seat/{}/{}", manifest.seat_id, manifest.session_id),
            seat: manifest.seat_id.to_string(),
        })
    }

    /// The local workspace: beside the projects (the agent's confined unit
    /// may write it; Odin's own state stays hidden from it).
    fn local_dir(placement: &Placement, manifest: &SessionManifest) -> PathBuf {
        placement
            .project_root
            .parent()
            .unwrap_or(&placement.project_root)
            .join(".odin-workspaces")
            .join(manifest.session_id.to_string())
    }

    fn remote_dir(manifest: &SessionManifest) -> PathBuf {
        PathBuf::from(format!(".local/state/odin-harness/{}", manifest.session_id))
    }
}

/// What a hand-back publishes when the workspace is no longer on the
/// session's default seat branch.
enum PublishTarget {
    Default,
    /// An exact seat branch the agent checked out — how a non-OMP ask names
    /// the branch to push (`git checkout -b seat/<seat>/<id>`).
    Exact(String),
}

/// The publish target for a hand-back: the session's default seat branch,
/// unless the workspace sits on another exact seat branch. Any other ref is
/// refused — never `main`, never a non-seat branch — the same boundary
/// `git.patch.propose` holds for its explicit `branch`.
fn publish_target(default: &str, head: &str) -> Result<PublishTarget, LiveError> {
    let head = head.trim();
    if head == default || head.is_empty() || head == "HEAD" {
        return Ok(PublishTarget::Default);
    }
    if crate::coding_route::is_seat_branch(head) {
        Ok(PublishTarget::Exact(head.to_owned()))
    } else {
        Err(harness_failure(
            "hand_back",
            format!(
                "the workspace is on {head:?}, not a seat branch: refusing to publish it — \
                 stay on {default:?} or check out the exact seat branch to push \
                 (seat/<seat>/<id>)"
            ),
        ))
    }
}

pub(super) fn harness_failure(step: &str, detail: impl std::fmt::Display) -> LiveError {
    LiveError::Unavailable {
        code: format!("harness_workspace_{step}: {detail}"),
    }
}

/// Preparation and hand-back share the admitted hand-back timeout.
const WORKFLOW_SECONDS: u64 = 1_200;

impl DaemonHarnessWorkspace {
    /// The open session pool whose lifecycle owner runs this workspace's
    /// Git and SSH. A gone or closed pool (the daemon stopping) admits no
    /// workflow: nothing is cloned, committed or pushed after the stop.
    fn admitted_pool(
        &self,
        step: &str,
    ) -> Result<std::sync::Arc<crate::live_authority::SessionAuthorityPool>, LiveError> {
        let pool = self
            .pool
            .get()
            .and_then(std::sync::Weak::upgrade)
            .ok_or_else(|| {
                harness_failure(step, "the session pool that owns its workers is gone")
            })?;
        if pool.is_closed() {
            return Err(harness_failure(
                step,
                "the daemon is stopping; no workspace work is admitted",
            ));
        }
        Ok(pool)
    }
}

/// Stdout of one successful config-free Git step in `directory` on the
/// lifecycle's registered worker; Odin's own commits name the seat.
fn local(
    runner: &Lifecycle<'_>,
    directory: &Path,
    seat: &str,
    args: &[&str],
    step: &str,
) -> Result<String, LiveError> {
    runner
        .git(directory, args, Some(seat))
        .map_err(|error| harness_failure(step, error))
}

/// Stdout of one successful script on `host`, run over the registered SSH
/// client from `directory`.
fn remote(
    runner: &Lifecycle<'_>,
    directory: &Path,
    host: &str,
    script: &str,
    step: &str,
) -> Result<String, LiveError> {
    let mut args: Vec<String> = odin_omp::live::harness::SSH_OPTIONS
        .iter()
        .map(|option| (*option).to_owned())
        .collect();
    args.extend([
        host.to_owned(),
        "--".to_owned(),
        "bash".to_owned(),
        "-lc".to_owned(),
        quote(script),
    ]);
    let output = runner
        .ssh(directory, args)
        .map_err(|error| harness_failure(step, error))?;
    if !output.status.success() {
        return Err(harness_failure(
            step,
            String::from_utf8_lossy(&output.stderr).trim(),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn quote(word: &str) -> String {
    format!("'{}'", word.replace('\'', "'\\''"))
}

/// The remote prepare script ends with `pwd`. Clone noise is not a path.
fn workspace_path(output: &str) -> Result<PathBuf, LiveError> {
    let path = output
        .lines()
        .map(str::trim)
        .rfind(|line| !line.is_empty())
        .filter(|line| line.starts_with('/') && !line.contains(char::is_whitespace))
        .ok_or_else(|| {
            harness_failure(
                "prepare",
                "remote prepare did not return an absolute workspace path",
            )
        })?;
    Ok(PathBuf::from(path))
}

/// `git://<mirror>/<owner>/<repo>.git` for a GitHub origin; any other
/// origin has no mirror.
fn mirror_origin(origin: &str, mirror: &str) -> Option<String> {
    let path = [
        "git@github.com:",
        "ssh://git@github.com/",
        "https://github.com/",
    ]
    .iter()
    .find_map(|prefix| origin.strip_prefix(prefix))?;
    let (owner, repo) = path.trim_end_matches(".git").split_once('/')?;
    (!owner.is_empty() && !repo.is_empty() && !repo.contains('/'))
        .then(|| format!("git://{mirror}/{owner}/{repo}.git"))
}

/// The session clone fetches from the authority's mirror, never GitHub;
/// Odin's hand-back pushes the branch. A project without a readable origin
/// (its Git's real nonzero exit) stays unmirrored; a step that did not run
/// to completion fails the prepare.
fn point_origin_at_mirror(
    runner: &Lifecycle<'_>,
    placement: &Placement,
    dir: &Path,
    mirror: &str,
    session: &str,
    project: &str,
) -> Result<(), LiveError> {
    let output = runner
        .run_git(
            &placement.project_root,
            &["remote", "get-url", "origin"],
            Some(&placement.seat),
            false,
        )
        .map_err(|error| harness_failure("origin", error))?;
    let upstream = if output.status.success() {
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    } else {
        String::new()
    };
    let Some(url) = mirror_origin(&upstream, mirror) else {
        tracing::info!(
            "harness clone unmirrored session={session} project={project} \
             upstream={upstream:?}"
        );
        return Ok(());
    };
    local(
        runner,
        dir,
        &placement.seat,
        &["remote", "set-url", "origin", &url],
        "origin",
    )?;
    tracing::info!("harness clone session={session} project={project} origin={url}");
    Ok(())
}

/// Keep the blocking preparation alive until completion or stop, regardless of caller cancellation.
struct Prepare {
    placement: Placement,
    /// The SSH host of a remote workspace; `None` on this machine.
    host: Option<String>,
    authority_host: String,
    local_dir: PathBuf,
    remote_dir: PathBuf,
    mirror: Option<String>,
    session: String,
    project: String,
}

impl Prepare {
    fn run(
        &self,
        runner: &Lifecycle<'_>,
        pool: &crate::live_authority::SessionAuthorityPool,
    ) -> Result<PathBuf, LiveError> {
        let placement = &self.placement;
        if let Some(destination) = &self.host {
            let dir = &self.remote_dir;
            let origin = format!(
                "{}:{}",
                self.authority_host,
                placement.project_root.display()
            );
            let script = format!(
                "set -e; if [ ! -d {dir}/.git ]; then mkdir -p {parent}; git clone -q {origin} \
                 {dir}; git -C {dir} checkout -q -b {branch}; fi; cd {dir} && pwd",
                dir = quote(&dir.display().to_string()),
                parent = quote(&dir.parent().unwrap_or(dir).display().to_string()),
                origin = quote(&origin),
                branch = quote(&placement.branch),
            );
            let prepared = remote(
                runner,
                &placement.project_root,
                destination,
                &script,
                "prepare",
            )?;
            return workspace_path(&prepared);
        }
        let dir = &self.local_dir;
        if dir.join(".git").is_dir() {
            return Ok(dir.clone());
        }
        // Admission is checked again right before the first new filesystem
        // effect; the clone step itself is refused by a closed pool too.
        if pool.is_closed() {
            return Err(harness_failure(
                "prepare",
                "the daemon is stopping; no workspace work is admitted",
            ));
        }
        let target = dir
            .to_str()
            .ok_or_else(|| harness_failure("clone", "the workspace path is not UTF-8"))?;
        if let Some(parent) = dir.parent() {
            std::fs::create_dir_all(parent).map_err(|error| harness_failure("prepare", error))?;
        }
        local(
            runner,
            &placement.project_root,
            &placement.seat,
            &["clone", "-q", "--no-hardlinks", ".", target],
            "clone",
        )?;
        local(
            runner,
            dir,
            &placement.seat,
            &["checkout", "-q", "-b", &placement.branch],
            "branch",
        )?;
        if let Some(mirror) = &self.mirror {
            point_origin_at_mirror(runner, placement, dir, mirror, &self.session, &self.project)?;
        }
        Ok(dir.clone())
    }
}

#[async_trait]
impl HarnessWorkspace for DaemonHarnessWorkspace {
    async fn prepare(
        &self,
        manifest: &SessionManifest,
        route: &HarnessRoute,
    ) -> Result<PathBuf, LiveError> {
        let placement = self.placement(manifest)?;
        // Admission closes before any workspace mutation: a stopping daemon
        // clones nothing more.
        let pool = self.admitted_pool("prepare")?;
        let prepare = Prepare {
            host: (route.environment.transport == EnvironmentTransport::SshHost)
                .then(|| route.environment.host.clone().unwrap_or_default()),
            authority_host: self.authority_host.clone(),
            local_dir: Self::local_dir(&placement, manifest),
            remote_dir: Self::remote_dir(manifest),
            mirror: route.environment.git_mirror.clone(),
            session: manifest.session_id.to_string(),
            project: manifest.project_id.to_string(),
            placement,
        };
        tokio::task::spawn_blocking(move || {
            // Only the daemon's stop cancels a prepare: the pool closing.
            let cancel = AtomicBool::new(false);
            let runner =
                Lifecycle::new(Some(&*pool), &cancel, Duration::from_secs(WORKFLOW_SECONDS));
            prepare.run(&runner, &pool)
        })
        .await
        .map_err(|error| harness_failure("prepare", error))?
    }

    async fn hand_back(
        &self,
        manifest: &SessionManifest,
        route: &HarnessRoute,
        workspace: &Path,
    ) -> Result<Option<String>, LiveError> {
        self.publish_work(manifest, route, workspace).await
    }
}

fn remote_phrase(published: &Value) -> String {
    if published.get("uncertain").and_then(Value::as_bool) == Some(true) {
        return format!(
            "publication to the project's remote is unproved ({})",
            published
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("reply unavailable")
        );
    }
    match (
        published.get("pushed").and_then(Value::as_bool),
        published.get("url").and_then(Value::as_str),
    ) {
        (Some(true), Some(url)) => format!("published it to {url}"),
        _ => format!(
            "could not publish it to the project's remote ({})",
            published
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("no reason given")
        ),
    }
}

/// Report publication state after hand-back, which may differ from the agent's earlier report.
fn hand_back_note(changed: usize, branch: &str, project: &str, published: &Value) -> String {
    format!(
        "Odin has committed {changed} changed file(s) on branch {branch} of {project} and \
         {}; anything above about committing or pushing predates this. The hand-back \
         publishes whatever seat branch the workspace is on: check out a task's exact \
         branch (git checkout -b seat/<seat>/<name>) before finishing to publish it.",
        remote_phrase(published)
    )
}

/// A retry publishes work an earlier refused hand-back had already
/// committed; the sentence says exactly that instead of counting again.
fn retry_note(branch: &str, project: &str, published: &Value) -> String {
    format!(
        "Odin published the work already committed on branch {branch} of {project} and {}; \
         the hand-back publishes whatever seat branch the workspace is on.",
        remote_phrase(published)
    )
}
#[cfg(test)]
mod path_tests {
    use super::workspace_path;

    #[test]
    fn noisy_remote_output_is_not_a_workspace_path() {
        let path = workspace_path("Cloning into '/tmp/noise'\n/home/colin/work/surtr\n")
            .expect("the pwd line is the path");
        assert_eq!(path, std::path::PathBuf::from("/home/colin/work/surtr"));
        assert!(workspace_path("").is_err());
        assert!(workspace_path("not a path\nrelative/dir\n").is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixture::LifecyclePool;
    use odin_domain::huginn::{LiveSessionId, ModelName, ProviderName};
    use odin_domain::{NodeId, ProjectId, SeatId, SliceId};
    use odin_process::test_support::RegisteredWorkerFixture;

    fn sh(directory: &Path, args: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(directory)
            .args(args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git runs");
        assert!(output.status.success(), "git {args:?}: {output:?}");
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    #[test]
    fn only_a_github_origin_has_a_mirror() {
        for origin in [
            "git@github.com:colingray3149/surtr.git",
            "ssh://git@github.com/colingray3149/surtr.git",
            "https://github.com/colingray3149/surtr",
        ] {
            assert_eq!(
                mirror_origin(origin, "10.77.0.11").as_deref(),
                Some("git://10.77.0.11/colingray3149/surtr.git"),
                "{origin}"
            );
        }
        for origin in ["", "/home/colin/valhalla/surtr", "git@gitlab.com:a/b.git"] {
            assert_eq!(mirror_origin(origin, "10.77.0.11"), None, "{origin}");
        }
    }

    #[tokio::test]
    async fn the_clone_fetches_from_the_mirror_and_the_hand_back_publishes_the_branch() {
        let fixture = tempfile::tempdir().expect("fixture");
        let root = fixture.path().join("surtr");
        let upstream = fixture.path().join("upstream.git");
        std::fs::create_dir(&root).expect("root");
        sh(&root, &["init", "-q", "-b", "main"]);
        sh(
            &root,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "init",
            ],
        );
        sh(
            &root,
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:colingray3149/surtr.git",
            ],
        );
        sh(fixture.path(), &["init", "-q", "--bare", "upstream.git"]);
        let owner = LifecyclePool::new(
            &fixture.path().join("state"),
            RegisteredWorkerFixture::new().expect("private registered workers"),
        );
        let workspace = DaemonHarnessWorkspace {
            projects: BTreeMap::from([("surtr".to_owned(), root.clone())]),
            authority_host: "mini".to_owned(),
            state_root: fixture.path().join("state"),
            supervisor: Default::default(),
            pool: owner.handle.clone(),
        };
        let manifest = SessionManifest {
            session_id: LiveSessionId::parse("00000000-0000-4000-8000-0000000013a4")
                .expect("session"),
            seat_id: SeatId::new("gungnir").expect("seat"),
            slice_id: SliceId::new("slice:mirror").expect("slice"),
            project_id: ProjectId::new("surtr").expect("project"),
            provider: ProviderName::new("fixture").expect("provider"),
            model: ModelName::new("fixture-model").expect("model"),
            title: None,
            target_node: NodeId::new("mini").expect("node"),
            open_tab: false,
            workload: None,
            served_revision: None,
            harness: None,
        };
        let route = HarnessRoute {
            harness_id: "codex".to_owned(),
            harness: toml::from_str(include_str!(
                "../../../../../registry/harnesses/codex/harness.toml"
            ))
            .expect("codex parses"),
            environment_id: "pod-authority".to_owned(),
            environment: toml::from_str(include_str!(
                "../../../../../registry/environments/pod-authority/environment.toml"
            ))
            .expect("pod-authority parses"),
            account: None,
        };
        let dir = workspace
            .prepare(&manifest, &route)
            .await
            .expect("prepared");
        assert_eq!(
            sh(&dir, &["remote", "get-url", "origin"]),
            "git://10.77.0.11/colingray3149/surtr.git"
        );
        sh(
            &root,
            &[
                "remote",
                "set-url",
                "origin",
                upstream.to_str().expect("utf8"),
            ],
        );
        std::fs::write(dir.join("note.txt"), "work").expect("work written");
        workspace
            .hand_back(&manifest, &route, &dir)
            .await
            .expect("handed back")
            .expect("a change was committed");
        let branch = sh(&dir, &["branch", "--show-current"]);
        assert!(branch.starts_with("seat/gungnir/"), "{branch}");
        assert_eq!(
            sh(&upstream, &["rev-parse", &branch]),
            sh(&dir, &["rev-parse", "HEAD"]),
            "the seat branch is on the upstream"
        );
    }

    /// A local-transport harness session fixture: the project root `root`
    /// with one commit and a local bare upstream (offline pushes), plus its
    /// prepared workspace, its hand-back steps owned by a lifecycle pool on
    /// private registered workers.
    async fn session(
        root: &Path,
        seat: &str,
        session: &str,
    ) -> (
        DaemonHarnessWorkspace,
        SessionManifest,
        HarnessRoute,
        PathBuf,
        LifecyclePool,
    ) {
        let worker = RegisteredWorkerFixture::new().expect("private registered workers");
        session_on(root, seat, session, worker).await
    }

    async fn session_on(
        root: &Path,
        seat: &str,
        session: &str,
        worker: RegisteredWorkerFixture,
    ) -> (
        DaemonHarnessWorkspace,
        SessionManifest,
        HarnessRoute,
        PathBuf,
        LifecyclePool,
    ) {
        let upstream = root.parent().expect("parent").join("upstream.git");
        std::fs::create_dir(root).expect("root");
        sh(root, &["init", "-q", "-b", "main"]);
        sh(
            root,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "init",
            ],
        );
        sh(
            root.parent().expect("parent"),
            &["init", "-q", "--bare", "upstream.git"],
        );
        sh(
            root,
            &["remote", "add", "origin", upstream.to_str().expect("utf8")],
        );
        let owner = LifecyclePool::new(&root.parent().expect("parent").join("state"), worker);
        let workspace = DaemonHarnessWorkspace {
            projects: BTreeMap::from([("surtr".to_owned(), root.to_path_buf())]),
            authority_host: "mini".to_owned(),
            state_root: root.parent().expect("parent").join("state"),
            supervisor: Default::default(),
            pool: owner.handle.clone(),
        };
        let manifest = SessionManifest {
            session_id: LiveSessionId::parse(session).expect("session"),
            seat_id: SeatId::new(seat).expect("seat"),
            slice_id: SliceId::new("slice:fixture").expect("slice"),
            project_id: ProjectId::new("surtr").expect("project"),
            provider: ProviderName::new("fixture").expect("provider"),
            model: ModelName::new("fixture-model").expect("model"),
            title: None,
            target_node: NodeId::new("mini").expect("node"),
            open_tab: false,
            workload: None,
            served_revision: None,
            harness: None,
        };
        let route = HarnessRoute {
            harness_id: "codex".to_owned(),
            harness: toml::from_str(include_str!(
                "../../../../../registry/harnesses/codex/harness.toml"
            ))
            .expect("codex parses"),
            environment_id: "pod-authority".to_owned(),
            environment: toml::from_str(include_str!(
                "../../../../../registry/environments/pod-authority/environment.toml"
            ))
            .expect("pod-authority parses"),
            account: None,
        };
        let dir = workspace
            .prepare(&manifest, &route)
            .await
            .expect("prepared");
        (workspace, manifest, route, dir, owner)
    }

    #[tokio::test]
    async fn a_closed_lifecycle_refuses_workspace_prepare_before_creating_another_clone() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("surtr");
        let (workspace, mut manifest, route, original, owner) =
            session(&root, "reginn", "00000000-0000-4000-8000-0000000013bd").await;
        let original_head = sh(&original, &["rev-parse", "HEAD"]);
        owner.pool.close();
        manifest.session_id = "00000000-0000-4000-8000-0000000013be".parse().unwrap();
        let next =
            DaemonHarnessWorkspace::local_dir(&workspace.placement(&manifest).unwrap(), &manifest);
        let outcome = workspace.prepare(&manifest, &route).await;
        assert!(
            outcome.is_err(),
            "closed daemon admission started a new clone: {outcome:?}"
        );
        assert!(
            !next.exists(),
            "no new workspace may appear after admission closes"
        );
        assert_eq!(sh(&original, &["rev-parse", "HEAD"]), original_head);
    }

    #[test]
    fn publish_targets_hold_the_seat_boundary() {
        assert!(matches!(
            publish_target("seat/reginn/abc", "seat/reginn/abc"),
            Ok(PublishTarget::Default)
        ));
        for head in ["", "HEAD"] {
            assert!(
                matches!(
                    publish_target("seat/reginn/abc", head),
                    Ok(PublishTarget::Default)
                ),
                "{head}"
            );
        }
        assert!(matches!(
            publish_target("seat/reginn/abc", "seat/acceptance/a1n4188"),
            Ok(PublishTarget::Exact(branch)) if branch == "seat/acceptance/a1n4188"
        ));
        for head in ["main", "feature/x", "seat/A/B", "seat/a/b/c", "seat//b"] {
            assert!(publish_target("seat/reginn/abc", head).is_err(), "{head}");
        }
    }

    #[tokio::test]
    async fn an_exact_seat_branch_the_agent_checked_out_is_published() {
        let fixture = tempfile::tempdir().expect("fixture");
        let root = fixture.path().join("surtr");
        let (workspace, manifest, route, dir, _pool) =
            session(&root, "reginn", "00000000-0000-4000-8000-0000000013b1").await;
        sh(&dir, &["checkout", "-q", "-b", "seat/acceptance/a1n4188"]);
        std::fs::write(dir.join("tools.txt"), "a1n4188\n").expect("work written");
        let note = workspace
            .hand_back(&manifest, &route, &dir)
            .await
            .expect("handed back")
            .expect("a change was committed");
        assert!(note.contains("seat/acceptance/a1n4188"), "{note}");
        assert_eq!(
            sh(&root, &["rev-parse", "refs/heads/seat/acceptance/a1n4188"]),
            sh(&dir, &["rev-parse", "HEAD"]),
            "the exact branch holds the handed-back work"
        );
        assert!(
            sh(
                &root,
                &[
                    "for-each-ref",
                    "--format=%(refname:short)",
                    "refs/heads/seat/reginn"
                ]
            )
            .is_empty(),
            "the session branch was not created"
        );
    }

    /// Any other ref is refused before anything is committed: a hand-back
    /// never publishes a non-seat branch, and a shape refusal leaves the
    /// work uncommitted for the agent to move to a seat branch.
    #[tokio::test]
    async fn a_non_seat_branch_is_refused_not_published() {
        let fixture = tempfile::tempdir().expect("fixture");
        let root = fixture.path().join("surtr");
        let (workspace, manifest, route, dir, _pool) =
            session(&root, "reginn", "00000000-0000-4000-8000-0000000013b2").await;
        sh(&dir, &["checkout", "-q", "-b", "feature/x"]);
        std::fs::write(dir.join("tools.txt"), "work\n").expect("work written");
        workspace
            .hand_back(&manifest, &route, &dir)
            .await
            .expect_err("a non-seat branch is refused");
        assert_eq!(
            sh(&dir, &["status", "--porcelain"]),
            "?? tools.txt",
            "the refusal committed nothing"
        );
        assert_eq!(
            sh(
                &root,
                &["for-each-ref", "--format=%(refname:short)", "refs/heads"]
            ),
            "main",
            "no branch beyond main was published"
        );
    }

    #[tokio::test]
    async fn an_exact_seat_branch_holding_other_work_is_never_overwritten() {
        let fixture = tempfile::tempdir().expect("fixture");
        let root = fixture.path().join("surtr");
        let (workspace, manifest, route, dir, _pool) =
            session(&root, "reginn", "00000000-0000-4000-8000-0000000013b3").await;
        sh(
            &root,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "other work",
            ],
        );
        sh(&root, &["branch", "seat/acceptance/taken"]);
        let taken = sh(&root, &["rev-parse", "refs/heads/seat/acceptance/taken"]);
        sh(&dir, &["checkout", "-q", "-b", "seat/acceptance/taken"]);
        std::fs::write(dir.join("tools.txt"), "work\n").expect("work written");
        workspace
            .hand_back(&manifest, &route, &dir)
            .await
            .expect_err("other work is never overwritten");
        assert_eq!(
            sh(&root, &["rev-parse", "refs/heads/seat/acceptance/taken"]),
            taken,
            "the taken branch still holds the other work"
        );
    }

    /// A refused hand-back's committed work is not stranded: the agent
    /// moves to a valid exact branch, and a retry with no new edits still
    /// publishes that work (the zero-staged path is a publish, not a skip).
    #[tokio::test]
    async fn a_retry_after_refusal_publishes_committed_work_without_new_edits() {
        let fixture = tempfile::tempdir().expect("fixture");
        let root = fixture.path().join("surtr");
        let (workspace, manifest, route, dir, _pool) =
            session(&root, "reginn", "00000000-0000-4000-8000-0000000013b4").await;
        sh(
            &root,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "other work",
            ],
        );
        sh(&root, &["branch", "seat/acceptance/taken"]);
        sh(&dir, &["checkout", "-q", "-b", "seat/acceptance/taken"]);
        std::fs::write(dir.join("tools.txt"), "rescued\n").expect("work written");
        sh(&dir, &["add", "-A"]);
        sh(
            &dir,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "commit",
                "-qm",
                "agent work",
            ],
        );
        let captured = sh(&dir, &["rev-parse", "HEAD"]);
        workspace
            .hand_back(&manifest, &route, &dir)
            .await
            .expect_err("the taken name is refused");
        assert_eq!(sh(&dir, &["rev-parse", "HEAD"]), captured);
        sh(&dir, &["checkout", "-q", "-b", "seat/acceptance/rescued"]);
        workspace
            .hand_back(&manifest, &route, &dir)
            .await
            .expect("the retry publishes the committed work")
            .expect("a note reports the publish");
        assert_eq!(
            sh(&root, &["rev-parse", "refs/heads/seat/acceptance/rescued"]),
            captured,
            "the refused hand-back's commit published on the valid branch"
        );
        assert!(
            sh(&dir, &["status", "--porcelain"]).is_empty(),
            "the retry had nothing new staged"
        );
    }

    /// Two turns on the same exact branch fast-forward: the second
    /// hand-back's commit descends from the first, not "other work".
    #[tokio::test]
    async fn two_turns_on_the_same_exact_branch_fast_forward() {
        let fixture = tempfile::tempdir().expect("fixture");
        let root = fixture.path().join("surtr");
        let (workspace, manifest, route, dir, _pool) =
            session(&root, "reginn", "00000000-0000-4000-8000-0000000013b5").await;
        sh(&dir, &["checkout", "-q", "-b", "seat/acceptance/twice"]);
        std::fs::write(dir.join("first.txt"), "one\n").expect("first work written");
        workspace
            .hand_back(&manifest, &route, &dir)
            .await
            .expect("first turn handed back")
            .expect("first turn committed");
        let first = sh(&root, &["rev-parse", "refs/heads/seat/acceptance/twice"]);
        std::fs::write(dir.join("second.txt"), "two\n").expect("second work written");
        let note = workspace
            .hand_back(&manifest, &route, &dir)
            .await
            .expect("second turn handed back")
            .expect("second turn committed");
        assert!(note.contains("seat/acceptance/twice"), "{note}");
        let second = sh(&root, &["rev-parse", "refs/heads/seat/acceptance/twice"]);
        assert_eq!(second, sh(&dir, &["rev-parse", "HEAD"]));
        assert_eq!(
            sh(
                &dir,
                &["rev-list", "--count", &format!("{first}..{second}")]
            ),
            "1",
            "the second turn fast-forwarded the same branch"
        );
    }

    #[tokio::test]
    async fn full_session_defaults_keep_shared_prefix_tasks_disjoint() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("surtr");
        let (workspace, first, route, first_dir, _pool) =
            session(&root, "reginn", "00000000-0000-4000-8000-0000000013b6").await;
        let base = sh(&root, &["rev-parse", "main"]);
        let mut second = first.clone();
        second.session_id = "00000000-0000-4000-8000-0000000013b7".parse().unwrap();
        let second_dir = workspace.prepare(&second, &route).await.unwrap();
        std::fs::write(first_dir.join("first.txt"), "first task\n").unwrap();
        std::fs::write(second_dir.join("second.txt"), "second task\n").unwrap();
        workspace
            .hand_back(&first, &route, &first_dir)
            .await
            .unwrap();
        workspace
            .hand_back(&second, &route, &second_dir)
            .await
            .unwrap();
        let first_ref = format!("refs/heads/seat/reginn/{}", first.session_id);
        let second_ref = format!("refs/heads/seat/reginn/{}", second.session_id);
        assert_eq!(
            sh(&root, &["rev-parse", &first_ref]),
            sh(&first_dir, &["rev-parse", "HEAD"])
        );
        assert_eq!(
            sh(&root, &["rev-parse", &second_ref]),
            sh(&second_dir, &["rev-parse", "HEAD"])
        );
        assert_eq!(
            sh(&root, &["show", &format!("{first_ref}:first.txt")]),
            "first task"
        );
        assert_eq!(
            sh(&root, &["show", &format!("{second_ref}:second.txt")]),
            "second task"
        );
        assert_eq!(sh(&root, &["rev-parse", "main"]), base);
    }

    #[tokio::test]
    async fn another_harness_task_cannot_fast_forward_an_owned_ref() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("surtr");
        let (workspace, first, route, first_dir, _pool) =
            session(&root, "reginn", "00000000-0000-4000-8000-0000000013b8").await;
        let base = sh(&root, &["rev-parse", "main"]);
        let branch = "seat/reginn/shared";
        sh(&first_dir, &["checkout", "-q", "-b", branch]);
        std::fs::write(first_dir.join("first.txt"), "first task\n").unwrap();
        workspace
            .hand_back(&first, &route, &first_dir)
            .await
            .unwrap();
        let published = sh(&root, &["rev-parse", branch]);
        let mut second = first.clone();
        second.session_id = "00000000-0000-4000-8000-0000000013b9".parse().unwrap();
        let second_dir = workspace.prepare(&second, &route).await.unwrap();
        sh(&second_dir, &["fetch", "-q", "origin", branch]);
        sh(&second_dir, &["checkout", "-q", "-b", branch, "FETCH_HEAD"]);
        std::fs::write(second_dir.join("second.txt"), "second task\n").unwrap();
        workspace
            .hand_back(&second, &route, &second_dir)
            .await
            .unwrap_err();
        assert_eq!(sh(&root, &["rev-parse", branch]), published);
        assert_eq!(sh(&second_dir, &["rev-parse", "HEAD"]), published);
        assert_eq!(
            std::fs::read_to_string(second_dir.join("second.txt")).unwrap(),
            "second task\n"
        );
        sh(
            &second_dir,
            &["checkout", "-q", "-b", "seat/reginn/independent"],
        );
        workspace
            .hand_back(&second, &route, &second_dir)
            .await
            .unwrap();
        assert_eq!(
            sh(&root, &["show", "seat/reginn/independent:second.txt"]),
            "second task"
        );
        assert_eq!(sh(&root, &["rev-parse", branch]), published);
        assert_eq!(sh(&root, &["rev-parse", "main"]), base);
    }

    /// The first absolute `name` on the runner's PATH.
    fn on_path(name: &str) -> String {
        std::env::var_os("PATH")
            .and_then(|paths| {
                std::env::split_paths(&paths)
                    .map(|directory| directory.join(name))
                    .find(|candidate| candidate.is_absolute() && candidate.is_file())
            })
            .unwrap_or_else(|| panic!("no absolute {name} on PATH"))
            .display()
            .to_string()
    }

    /// Only the recorded pid/start identity still executing this fixture's sleep.
    fn live_holders(helpers: &Path, sleep: &str) -> Vec<rustix::process::Pid> {
        let exact = [sleep.as_bytes(), b"\0", b"61", b"\0"].concat();
        std::fs::read_to_string(helpers.join("holders"))
            .unwrap_or_default()
            .lines()
            .filter_map(|record| {
                let (pid, start) = record.split_once(' ')?;
                let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
                let (_, fields) = stat.rsplit_once(')')?;
                if fields.split_whitespace().nth(19) != Some(start)
                    || !std::fs::read(format!("/proc/{pid}/cmdline"))
                        .is_ok_and(|cmdline| cmdline == exact)
                {
                    return None;
                }
                pid.parse().ok().and_then(rustix::process::Pid::from_raw)
            })
            .collect()
    }

    /// A transport descendant that keeps only Git's stderr open (an ssh
    /// master that persists; here an `ext::` helper) does not hold the
    /// hand-back: each Git step ends with its Git and leaves nothing of its
    /// own running. The unowned runner waited for every inheritor of its
    /// pipes to close them.
    #[tokio::test]
    async fn a_transport_descendant_holding_git_stderr_does_not_hold_the_hand_back() {
        const BOUND: std::time::Duration = std::time::Duration::from_secs(20);
        let fixture = tempfile::tempdir().expect("fixture");
        let root = fixture.path().join("surtr");
        // Only a real cgroup proves a reparented descendant of a Git step
        // gone: the hand-back's workers run on the caller's user session.
        let worker = RegisteredWorkerFixture::new_delegated()
            .expect("the caller's systemd user session owns the hand-back's workers");
        let (workspace, manifest, route, dir, _pool) = session_on(
            &root,
            "reginn",
            "00000000-0000-4000-8000-0000000013bb",
            worker,
        )
        .await;
        let upstream = fixture.path().join("upstream.git");
        let helpers = fixture.path().join("helpers");
        std::fs::create_dir(&helpers).expect("helpers");
        let sleep = on_path("sleep");
        let transport = helpers.join("transport.sh");
        std::fs::write(
            &transport,
            format!(
                "#!/bin/sh\n\
                 if [ ! -e '{helpers}/stop' ]; then\n\
                 '{sleep}' 61 </dev/null >/dev/null &\n\
                 pid=$!; ( read -r stat < /proc/$pid/stat; set -- $stat; printf '%s %s\\n' \"$pid\" \"${{22}}\" ) >> '{helpers}/holders'\n\
                 fi\n\
                 exec '{git}' \"${{1#git-}}\" \"$2\"\n",
                helpers = helpers.display(),
                git = on_path("git"),
            ),
        )
        .expect("transport written");
        std::fs::set_permissions(
            &transport,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .expect("transport executable");
        sh(&root, &["config", "protocol.ext.allow", "always"]);
        sh(
            &root,
            &[
                "remote",
                "set-url",
                "origin",
                &format!("ext::{} %S {}", transport.display(), upstream.display()),
            ],
        );
        std::fs::write(dir.join("work.txt"), "work\n").expect("work written");
        let branch = format!("refs/heads/seat/reginn/{}", manifest.session_id);
        let source = dir.clone();
        let mut task =
            tokio::spawn(async move { workspace.hand_back(&manifest, &route, &source).await });
        let answered = tokio::time::timeout(BOUND, &mut task).await;
        let left_running = live_holders(&helpers, &sleep).len();
        // Release: no helper is born from here, every recorded one is
        // killed, and the hand-back is joined before the fixture goes.
        std::fs::write(helpers.join("stop"), "").expect("stop marker");
        let released = std::time::Instant::now();
        while !task.is_finished() && released.elapsed() < std::time::Duration::from_secs(120) {
            for pid in live_holders(&helpers, &sleep) {
                let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        for pid in live_holders(&helpers, &sleep) {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
        }
        assert!(task.is_finished(), "the released hand-back was joined");
        let held = answered.is_err();
        let result = match answered {
            Ok(joined) => joined,
            Err(_) => task.await,
        };
        assert!(
            !held,
            "the hand-back was held past {BOUND:?} by a descendant of its Git"
        );
        assert_eq!(
            left_running, 0,
            "the answered hand-back left its Git's descendants running"
        );
        result.expect("joined").expect("handed back");
        assert_eq!(
            sh(&root, &["rev-parse", &branch]),
            sh(&dir, &["rev-parse", "HEAD"]),
            "the project holds the captured commit"
        );
    }

    /// A hand-back whose origin never answers is stopped by the daemon's
    /// stop (its pool closing): the running Git ends — its connection
    /// closes — the hand-back answers, no further step reaches the remote,
    /// and the captured commit stays published in the project with its
    /// origin leg retained as unresolved, never cleaned up.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_daemon_stop_ends_a_hand_back_held_by_a_silent_origin() {
        let fixture = tempfile::tempdir().expect("fixture");
        let root = fixture.path().join("surtr");
        let (workspace, manifest, route, dir, owner) =
            session(&root, "reginn", "00000000-0000-4000-8000-0000000013bc").await;
        let remote = crate::test_fixture::SilentRemote::start();
        sh(&root, &["remote", "set-url", "origin", &remote.url()]);
        std::fs::write(dir.join("work.txt"), "work\n").expect("work written");
        let branch = format!("refs/heads/seat/reginn/{}", manifest.session_id);
        let source = dir.clone();
        let mut task =
            tokio::spawn(async move { workspace.hand_back(&manifest, &route, &source).await });
        let reached =
            tokio::task::block_in_place(|| remote.reached(1, std::time::Duration::from_secs(60)));
        owner.pool.close();
        let answered = tokio::time::timeout(std::time::Duration::from_secs(30), &mut task).await;
        let closed = tokio::task::block_in_place(|| {
            remote.all_closed_within(std::time::Duration::from_secs(10))
        });
        let connections = remote.connections();
        assert!(reached, "the hand-back's Git reached the silent origin");
        let result = answered.expect("the stopped hand-back answers");
        assert!(closed, "the stopped Git's connection is closed");
        assert_eq!(connections, 1, "no step reached the remote after the stop");
        result
            .expect("joined")
            .expect("the project leg is published; the origin leg stays unresolved");
        assert_eq!(
            sh(&root, &["rev-parse", &branch]),
            sh(&dir, &["rev-parse", "HEAD"]),
            "the project holds the captured commit"
        );
        // The unresolved origin leg keeps the claim's preparation: the ref
        // cannot be taken over by another task meanwhile.
        let claims = std::fs::read_dir(fixture.path().join("state/branch-claims"))
            .expect("claims")
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
            .map(|entry| {
                serde_json::from_slice::<Value>(&std::fs::read(entry.path()).expect("claim"))
                    .expect("claim record")
            })
            .collect::<Vec<_>>();
        assert!(
            claims
                .iter()
                .any(|claim| claim["pending"]["kind"] == "direct"),
            "{claims:?}"
        );
    }

    #[tokio::test]
    async fn an_already_applied_uncertain_hand_back_reports_its_reconciliation() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("surtr");
        let (workspace, manifest, route, directory, _pool) =
            session(&root, "reginn", "00000000-0000-4000-8000-0000000013ba").await;
        let upstream = fixture.path().join("upstream.git");
        let unavailable = fixture.path().join("unavailable.git");
        std::fs::write(directory.join("work.txt"), "captured work\n").unwrap();
        std::fs::rename(&upstream, &unavailable).unwrap();
        workspace
            .hand_back(&manifest, &route, &directory)
            .await
            .unwrap();
        let captured = sh(&directory, &["rev-parse", "HEAD"]);
        let reference = format!("refs/heads/seat/reginn/{}", manifest.session_id);
        // Reconciliation may find that every leg was already applied.
        sh(
            &root,
            &[
                "push",
                "-q",
                unavailable.to_str().unwrap(),
                &format!("{captured}:{reference}"),
            ],
        );
        std::fs::rename(&unavailable, &upstream).unwrap();
        std::fs::write(directory.join("later.txt"), "keep later work\n").unwrap();
        let report = workspace
            .hand_back(&manifest, &route, &directory)
            .await
            .unwrap();
        assert!(
            report.is_some(),
            "resolving uncertainty must be reported, not hidden as no work"
        );
        assert_eq!(sh(&upstream, &["rev-parse", &reference]), captured);
        assert_eq!(sh(&directory, &["rev-parse", "HEAD"]), captured);
        assert_eq!(sh(&directory, &["status", "--porcelain"]), "?? later.txt");
        assert_eq!(
            std::fs::read_to_string(directory.join("later.txt")).unwrap(),
            "keep later work\n"
        );
    }
}
