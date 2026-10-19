//! Non-OMP hand-back shares task/ref claims and exact-commit publication.
//! Registered Git/SSH workers share one deadline; pool shutdown stops the
//! current step and prevents further steps. Uncertain preparations are retained.
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use serde_json::json;

use super::{
    hand_back_note, harness_failure, publish_target, quote, retry_note, DaemonHarnessWorkspace,
    EnvironmentTransport, HarnessRoute, LiveError, Path, PublishTarget, SessionManifest,
    WORKFLOW_SECONDS,
};
use crate::coding_route::claims::{self, Claim, Owner, Pending};
use crate::coding_route::publication::{self, PublicationOutcome};
use crate::coding_route::Lifecycle;

/// Keep the claim guard alive if the async caller drops the blocking publisher.
struct HandBack {
    state_root: std::path::PathBuf,
    project_root: std::path::PathBuf,
    default_branch: String,
    seat: String,
    owner: Owner,
    /// The SSH host of a remote workspace; `None` on this machine.
    host: Option<String>,
    harness: String,
    project: String,
    session: String,
    workspace: std::path::PathBuf,
}

impl DaemonHarnessWorkspace {
    pub(super) async fn publish_work(
        &self,
        manifest: &SessionManifest,
        route: &HarnessRoute,
        workspace: &Path,
    ) -> Result<Option<String>, LiveError> {
        let placement = self.placement(manifest)?;
        let host =
            match route.environment.transport {
                EnvironmentTransport::SshHost => {
                    Some(route.environment.host.clone().ok_or_else(|| {
                        harness_failure("head_branch", "the SSH route has no host")
                    })?)
                }
                _ => None,
            };
        let pool = self.admitted_pool("hand_back")?;
        let supervisor = self.supervisor.get().and_then(std::sync::Weak::upgrade);
        let hand_back = HandBack {
            state_root: self.state_root.clone(),
            project_root: placement.project_root,
            default_branch: placement.branch,
            seat: placement.seat,
            owner: Owner {
                session: manifest.session_id.to_string(),
                seat: manifest.seat_id.to_string(),
                project: manifest.project_id.to_string(),
            },
            host,
            harness: route.harness_id.clone(),
            project: manifest.project_id.to_string(),
            session: manifest.session_id.to_string(),
            workspace: workspace.to_owned(),
        };
        tokio::task::spawn_blocking(move || {
            // Only the daemon's stop cancels a hand-back: the pool closing.
            let cancel = AtomicBool::new(false);
            let runner =
                Lifecycle::new(Some(&*pool), &cancel, Duration::from_secs(WORKFLOW_SECONDS));
            hand_back.run(&runner, supervisor)
        })
        .await
        .map_err(|error| harness_failure("hand_back", error))?
    }
}

impl HandBack {
    fn run(
        &self,
        runner: &Lifecycle<'_>,
        supervisor: Option<std::sync::Arc<odin_omp::live::supervisor::LiveSupervisor>>,
    ) -> Result<Option<String>, LiveError> {
        // Resolve and claim the name before staging or committing on either transport.
        let head = match &self.host {
            Some(host) => self.remote(
                runner,
                host,
                &format!(
                    "git -C {} rev-parse --abbrev-ref HEAD",
                    quote(&self.workspace.display().to_string())
                ),
                "head_branch",
            )?,
            None => self.local(
                runner,
                &["rev-parse", "--abbrev-ref", "HEAD"],
                "head_branch",
            )?,
        };
        let branch = match publish_target(&self.default_branch, &head)? {
            PublishTarget::Default => self.default_branch.clone(),
            PublishTarget::Exact(branch) => branch,
        };
        let mut claim = Claim::acquire(
            runner,
            &self.state_root,
            &self.project_root,
            &branch,
            self.owner.clone(),
            |owner| claims::owner_ended(supervisor, owner),
        )
        .map_err(|error| harness_failure("claim", error))?;
        let recovering = matches!(
            claim.pending(),
            Some(Pending::Direct { .. } | Pending::Remote { .. })
        );
        let staged = if recovering {
            // An interrupted offer keeps its original source, commit and destinations.
            0
        } else {
            if claim
                .unresolved()
                .map_err(|error| harness_failure("claim", error))?
            {
                return Err(harness_failure(
                    "claim",
                    "this ref retains a reviewed preparation; recover it through the review lane",
                ));
            }
            let (staged, pending) = self.capture_offer(runner, &branch, head.trim())?;
            claim
                .prepare(pending)
                .map_err(|error| harness_failure("prepare", error))?;
            staged
        };
        let root = &self.project_root;
        let outcome = match claim.pending() {
            Some(Pending::Direct {
                commit,
                origin,
                source,
            }) => publication::publish_prepared(
                runner,
                source,
                root,
                &branch,
                commit,
                false,
                origin.as_deref(),
            )
            .map_err(|error| harness_failure("publish", error))?,
            Some(Pending::Remote {
                commit,
                origin,
                host,
                workspace,
                upstream,
            }) => {
                let local =
                    self.publish_remote_project(runner, host, workspace, upstream, &branch, commit);
                let remote = if local.report["pushed"] == true {
                    publication::publish_destination(
                        runner,
                        root,
                        &branch,
                        commit,
                        origin.as_deref(),
                    )
                } else {
                    PublicationOutcome {
                        report: json!({"pushed":false,"uncertain":false,"reason":"project publication was not proved; origin was not attempted"}),
                        uncertain: false,
                        unchanged: true,
                    }
                };
                PublicationOutcome {
                    report: json!({"branch":branch,"commit":commit,"local":local.report,"remote":remote.report}),
                    uncertain: local.uncertain || remote.uncertain,
                    unchanged: local.unchanged && remote.unchanged,
                }
            }
            _ => {
                return Err(harness_failure(
                    "publish",
                    "the claimed publication preparation is missing",
                ))
            }
        };
        if !outcome.uncertain {
            claim
                .complete()
                .map_err(|error| harness_failure("publish", error))?;
        }
        if outcome.report["local"]["pushed"] != true {
            return Err(harness_failure(
                "publish",
                format!(
                    "captured commit is retained; project publication: {}",
                    outcome.report["local"]
                ),
            ));
        }
        if staged == 0 && outcome.unchanged && !recovering {
            return Ok(None);
        }
        tracing::warn!(
            "harness hand_back session={} branch={} files={staged}{}",
            self.session,
            branch,
            if staged == 0 { " (retry)" } else { "" }
        );
        let remote = &outcome.report["remote"];
        Ok(Some(if staged == 0 {
            retry_note(&branch, &self.project, remote)
        } else {
            hand_back_note(staged, &branch, &self.project, remote)
        }))
    }

    /// Stdout of one successful Git step in the local workspace.
    fn local(
        &self,
        runner: &Lifecycle<'_>,
        args: &[&str],
        step: &str,
    ) -> Result<String, LiveError> {
        super::local(runner, &self.workspace, &self.seat, args, step)
    }

    /// Stdout of one successful script on the remote workspace's host, over
    /// the registered SSH client.
    fn remote(
        &self,
        runner: &Lifecycle<'_>,
        host: &str,
        script: &str,
        step: &str,
    ) -> Result<String, LiveError> {
        super::remote(runner, &self.project_root, host, script, step)
    }

    fn capture_offer(
        &self,
        runner: &Lifecycle<'_>,
        branch: &str,
        head_branch: &str,
    ) -> Result<(usize, Pending), LiveError> {
        let origin = publication::destination(runner, &self.project_root)
            .map_err(|error| harness_failure("origin", error))?;
        let message = format!("{} via Odin ({})", self.seat, self.harness);
        let workspace = &self.workspace;
        if let Some(host) = &self.host {
            let upstream = self.remote(
                runner,
                host,
                &format!(
                    "git -C {} remote get-url --push --all origin",
                    quote(&workspace.display().to_string())
                ),
                "origin",
            )?;
            let upstream = match (upstream.lines().next(), upstream.lines().nth(1)) {
                (Some(url), None) if !url.is_empty() => url.to_owned(),
                _ => {
                    return Err(harness_failure(
                        "origin",
                        "publication requires one exact push destination",
                    ))
                }
            };
            let script = format!(
                "set -e; cd {dir}; test \"$(git rev-parse --abbrev-ref HEAD)\" = {head}; \
                 git add -A; if git diff --cached --quiet; then n=0; else \
                 n=$(git diff --cached --name-only | wc -l); git -c user.name={who} \
                 -c user.email=odin@localhost commit -qm {message}; fi; \
                 printf '%s %s\\n' \"$n\" \"$(git rev-parse HEAD)\"",
                dir = quote(&workspace.display().to_string()),
                head = quote(head_branch),
                who = quote(&format!("{} via Odin", self.seat)),
                message = quote(&message),
            );
            let output = self.remote(runner, host, &script, "commit")?;
            let mut fields = output.split_whitespace();
            let staged = fields
                .next()
                .and_then(|count| count.parse::<usize>().ok())
                .ok_or_else(|| harness_failure("commit", "invalid staged-file count"))?;
            let commit = fields
                .next()
                .filter(|commit| publication::full_commit(commit))
                .ok_or_else(|| harness_failure("commit", "missing full commit identity"))?;
            if fields.next().is_some() {
                return Err(harness_failure("commit", "ambiguous commit result"));
            }
            return Ok((
                staged,
                Pending::Remote {
                    commit: commit.to_owned(),
                    origin,
                    host: host.clone(),
                    workspace: workspace.clone(),
                    upstream,
                },
            ));
        }
        let head = self.local(runner, &["rev-parse", "HEAD"], "head_commit")?;
        // The branch must be new, at this commit, or strictly behind it.
        publication::guard_seat_branch(runner, &self.project_root, branch, head.trim(), workspace)
            .map_err(|reason| harness_failure("hand_back", reason))?;
        self.local(runner, &["add", "-A"], "stage")?;
        let names = self.local(runner, &["diff", "--cached", "--name-only"], "diff")?;
        let staged = names.lines().filter(|name| !name.is_empty()).count();
        if staged > 0 {
            self.local(runner, &["commit", "-q", "-m", &message], "commit")?;
        }
        let commit = self.local(runner, &["rev-parse", "HEAD"], "head_commit")?;
        Ok((
            staged,
            Pending::Direct {
                commit: commit.trim().to_owned(),
                origin,
                source: workspace.clone(),
            },
        ))
    }

    fn remote_ref(
        &self,
        runner: &Lifecycle<'_>,
        host: &str,
        workspace: &Path,
        target: &str,
        reference: &str,
    ) -> Result<Option<String>, String> {
        let output = self
            .remote(
                runner,
                host,
                &format!(
                    "git -C {} ls-remote --heads -- {} {}",
                    quote(&workspace.display().to_string()),
                    quote(target),
                    quote(reference)
                ),
                "readback",
            )
            .map_err(|error| error.to_string())?;
        publication::parse_ref_head(&output, reference).map(|commit| commit.map(str::to_owned))
    }

    fn publish_remote_project(
        &self,
        runner: &Lifecycle<'_>,
        host: &str,
        workspace: &Path,
        target: &str,
        branch: &str,
        commit: &str,
    ) -> PublicationOutcome {
        if !publication::full_commit(commit) {
            return PublicationOutcome {
                report: json!({"pushed":false,"uncertain":true,"reason":"the retained remote commit identity is invalid","url":target}),
                uncertain: true,
                unchanged: false,
            };
        }
        let reference = format!("refs/heads/{branch}");
        match self.remote_ref(runner, host, workspace, target, &reference) {
            Ok(Some(observed)) if observed == commit => {
                return PublicationOutcome {
                    report: json!({"pushed":true,"uncertain":false,"reconciled":true,"url":target}),
                    uncertain: false,
                    unchanged: true,
                }
            }
            Err(reason) => {
                return PublicationOutcome {
                    report: json!({"pushed":false,"uncertain":true,"reason":reason,"url":target}),
                    uncertain: true,
                    unchanged: false,
                }
            }
            _ => {}
        }
        let pushed = self.remote(
            runner,
            host,
            &format!(
                "git -C {} push --quiet -- {} {}",
                quote(&workspace.display().to_string()),
                quote(target),
                quote(&format!("{commit}:{reference}"))
            ),
            "push",
        );
        let (pushed_exactly, uncertain, reason) =
            match self.remote_ref(runner, host, workspace, target, &reference) {
                Ok(Some(observed)) if observed == commit => (true, false, None),
                Ok(observed) => (
                    false,
                    false,
                    Some(format!(
                        "publication ref is {observed:?}, not captured commit {commit}; push={pushed:?}"
                    )),
                ),
                Err(error) => (
                    false,
                    true,
                    Some(format!(
                        "publication outcome is unproved after push: {error}; push={pushed:?}"
                    )),
                ),
            };
        PublicationOutcome {
            report: json!({"pushed":pushed_exactly,"uncertain":uncertain,"reconciled":pushed_exactly && pushed.is_err(),"url":target,"reason":reason}),
            uncertain,
            unchanged: false,
        }
    }
}
