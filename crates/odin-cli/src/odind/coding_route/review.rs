//! Test snapshots, independent review, and publication of reviewed changes.

use std::path::{Path, PathBuf};

use odin_cli::live_authority::RegisteredCodeCapsule;
use odin_domain::Digest;
use odin_hermes::runtime::coding::{test_report, NixLog, ProposalFailure, TestSelection};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{
    claims, publication, stage_change_locked, staging, store_artifact, DaemonCodingRoute,
    GitRunner, Registered,
};

const MAX_REVIEW_NOTES_BYTES: usize = 4_000;
const MAX_DIFF_BYTES: usize = 4 * 1024 * 1024;

/// The exact offered state a run tested and a review approved: the declared
/// project, the registered base, the HEAD before the run and the complete
/// tree (HEAD plus every pending change but eval scratch).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Offered {
    pub project: String,
    pub declared_root: String,
    pub base: String,
    pub head: String,
    pub tree: String,
}

/// One test run, written pending before it executes: what was frozen and
/// selected, then the outcome of exactly that execution.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RunRecord {
    pub id: String,
    pub seat: String,
    pub session: String,
    pub capsule: String,
    pub offered: Offered,
    /// The snapshot commit of `offered.tree` and the run's own ref to it.
    pub snapshot: String,
    pub reference: String,
    /// The selected tests, as the structured command that ran them.
    pub command: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<RunOutcome>,
    /// Successor sessions this evidence was explicitly carried to.
    #[serde(default)]
    pub carried_to: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RunOutcome {
    pub ok: bool,
    /// The report derived from this run's own log (no `logTail`).
    pub report: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LatestRun {
    run: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Verdict {
    pub reviewer: String,
    pub approve: bool,
    pub notes: String,
}

/// Captured before moving HEAD or publishing either ref. The private ref
/// keeps the exact commit reachable while publication is incomplete.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PreparedPublication {
    capsule: PathBuf,
    head: String,
    commit: String,
    branch: String,
    reference: String,
    origin: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ReviewRecord {
    /// The review's identity (offered state, session, run and reviewer).
    pub diff_digest: String,
    pub requested_by: String,
    pub reviewer: String,
    pub branch: String,
    pub artifact_id: String,
    /// The project whose merge this review may land, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// The exact source commit the reviewed proposal produced; the merge
    /// gate accepts only a branch head that still is this commit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prepared: Option<PreparedPublication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,
    pub session: String,
    pub run: String,
    pub offered: Offered,
    /// Lane whose review policy admitted this request. Verdicts re-check that policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lane: Option<String>,
    #[serde(default)]
    pub carried_to: Vec<String>,
}
fn belongs(owner: &str, carried_to: &[String], session: &str) -> bool {
    owner == session || carried_to.iter().any(|carried| carried == session)
}

/// The capsule's offered state now; the caller holds the staging lock.
fn offered_locked(registered: &Registered) -> Result<Offered, String> {
    let (runner, capsule) = (registered.runner, &registered.capsule.path);
    stage_change_locked(runner, capsule)?;
    let head = runner.git(capsule, &["rev-parse", "HEAD"], None)?;
    // Everything since the registered base is part of the offer, so the
    // work must descend from it.
    if !runner.git_holds(
        capsule,
        &["merge-base", "--is-ancestor", &registered.base, &head],
    )? {
        return Err("the capsule's HEAD does not descend from its registered base".to_owned());
    }
    Ok(Offered {
        project: registered.project.clone(),
        declared_root: registered.declared_root.display().to_string(),
        base: registered.base.clone(),
        head,
        tree: runner.git(capsule, &["write-tree"], None)?,
    })
}

pub(super) fn offered(registered: &Registered) -> Result<Offered, String> {
    let _staging = staging();
    offered_locked(registered)
}

/// The command a selection runs, argument by argument, as its run records
/// it (the flake is the run's own snapshot).
fn command(selection: &TestSelection) -> Vec<String> {
    let (fixed, scope) = match selection {
        TestSelection::Cargo(cargo) => return odin_cli::live_authority::cargo_command(cargo),
        TestSelection::Paths(paths) => ("pytest --color=no -p no:cacheprovider --", paths.clone()),
        TestSelection::Attr(Some(attr)) => {
            ("nix build --print-build-logs", vec![format!("#{attr}")])
        }
        TestSelection::Attr(None) => ("nix flake check --print-build-logs", Vec::new()),
    };
    fixed.split(' ').map(str::to_owned).chain(scope).collect()
}

fn key(digest: &str) -> String {
    digest.trim_start_matches("blake3:").to_owned()
}

/// The capability the project, or the lane when one is named, requires of a reviewer.
fn review_capability(
    snapshot: &odin_registry::Snapshot,
    project: &str,
    lane: Option<&str>,
) -> Result<String, String> {
    if let Some(lane) = lane {
        let object = snapshot
            .object(odin_registry::RegistryKind::Lane, lane)
            .ok_or_else(|| format!("lane {lane} is not declared"))?;
        let odin_registry::ObjectConfig::Lane(declared) = &object.config else {
            return Err(format!("{lane} is not a lane"));
        };
        if !declared.enabled {
            return Err(format!("lane {lane} is disabled"));
        }
        if let Some(capability) = &declared.review_verdict {
            return Ok(capability.as_str().to_owned());
        }
    }
    let object = snapshot
        .object(odin_registry::RegistryKind::Project, project)
        .ok_or_else(|| format!("project {project} is not declared"))?;
    let odin_registry::ObjectConfig::Project(declared) = &object.config else {
        return Err(format!("{project} is not a project"));
    };
    declared
        .review_verdict
        .as_ref()
        .map(|capability| capability.as_str().to_owned())
        .ok_or_else(|| format!("project {project} names no review-verdict capability"))
}

/// A reviewer is an enabled seat other than the requester that holds the named capability.
fn admit_reviewer(
    snapshot: &odin_registry::Snapshot,
    requester: &str,
    reviewer: &str,
    capability: &str,
) -> Result<(), String> {
    if reviewer == requester {
        return Err("a seat never reviews its own change; name another seat".to_owned());
    }
    odin_domain::SeatId::new(reviewer)
        .map_err(|error| format!("{reviewer:?} is not a seat id: {error}"))?;
    let seat = snapshot
        .object(odin_registry::RegistryKind::Seat, reviewer)
        .ok_or_else(|| format!("seat {reviewer} is not declared"))?;
    let odin_registry::ObjectConfig::Seat(declared) = &seat.config else {
        return Err(format!("{reviewer} is not a seat"));
    };
    if !declared.enabled {
        return Err(format!("seat {reviewer} is disabled"));
    }
    if !declared
        .tool_refs
        .iter()
        .any(|held| held.as_str() == capability)
    {
        return Err(format!(
            "seat {reviewer} does not hold {capability}, the review-verdict capability this change requires"
        ));
    }
    let object = snapshot
        .object(odin_registry::RegistryKind::Capability, capability)
        .ok_or_else(|| format!("capability {capability} is not declared"))?;
    let odin_registry::ObjectConfig::Capability(declared) = &object.config else {
        return Err(format!("{capability} is not a capability"));
    };
    if !declared.enabled {
        return Err(format!("capability {capability} is disabled"));
    }
    Ok(())
}

/// Why a verdict cannot be recorded or a reviewed propose cannot push.
pub(super) fn verdict_refusal(
    record: &ReviewRecord,
    reviewer_seat: &str,
) -> Result<(), &'static str> {
    if reviewer_seat == record.requested_by {
        return Err("a seat never reviews its own change");
    }
    if reviewer_seat != record.reviewer {
        return Err("this change was sent to a different reviewer seat");
    }
    Ok(())
}

pub(super) fn unreviewable_report(report: &Value, command: &[String]) -> Option<&'static str> {
    // Cached flake checks can pass without printing a test framework's log.
    if report.get("ok").and_then(Value::as_bool) == Some(true)
        && command
            .iter()
            .map(String::as_str)
            .eq(["nix", "flake", "check", "--print-build-logs"])
    {
        return None;
    }
    let frameworks = report
        .get("frameworks")
        .and_then(Value::as_array)
        .is_some_and(|frameworks| !frameworks.is_empty());
    if !frameworks {
        return Some(
            "the last test report recognized no test output, so nothing was tested: fix the \
             project's checks so test_run reports tests, then run it again",
        );
    }
    let failed_silently = report.get("ok").and_then(Value::as_bool) == Some(false)
        && report.get("failed").and_then(Value::as_u64).unwrap_or(0) == 0
        && report
            .get("diagnostics")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty);
    failed_silently.then_some(
        "the last test report failed without a failing test or a diagnostic: read its log, \
         fix the run, then run test_run again",
    )
}

/// Require approval of the exact offered state, requested by the offering seat.
pub(super) fn propose_refusal(record: Option<&ReviewRecord>, seat: &str) -> Option<String> {
    match record {
        None => Some(
            "this lane requires an independent review before the branch is offered: run \
             test_run, then code_review_request, ask the reviewer seat with the artifact it \
             returns, and propose after it approves"
                .to_owned(),
        ),
        Some(record) => {
            if record.requested_by != seat {
                return Some(format!(
                    "the review of this change ({}) was requested by seat {}: only that seat \
                     may offer it",
                    record.diff_digest, record.requested_by
                ));
            }
            match &record.verdict {
                None => Some(format!(
                    "the review of this change ({}) is pending with {}",
                    record.diff_digest, record.reviewer
                )),
                Some(verdict) if !verdict.approve => Some(format!(
                    "{} asked for changes to this exact tree: {}",
                    verdict.reviewer, verdict.notes
                )),
                Some(_) => None,
            }
        }
    }
}

pub(super) struct ClaimPreparation {
    pub(super) base: String,
    pub(super) commit: String,
}

/// The review journal is authoritative for reviewed preparation. A claim
/// points here instead of duplicating a second completion state.
pub(super) fn claim_preparation(
    state_root: &Path,
    digest: &str,
    branch: &str,
) -> Result<Option<ClaimPreparation>, String> {
    let path = state_root
        .join("reviews")
        .join(format!("{}.json", key(digest)));
    let record: ReviewRecord =
        DaemonCodingRoute::read_json(&path)?.ok_or("the claimed review is missing")?;
    if record.diff_digest != digest {
        return Err("the claimed review identity changed".to_owned());
    }
    Ok(record
        .prepared
        .filter(|prepared| prepared.branch == branch)
        .map(|prepared| ClaimPreparation {
            base: record.offered.base,
            commit: prepared.commit,
        }))
}

impl DaemonCodingRoute {
    fn reviews_root(&self) -> PathBuf {
        self.state_root.join("reviews")
    }

    fn run_path(&self, run: &str) -> PathBuf {
        self.reviews_root().join("runs").join(format!("{run}.json"))
    }

    fn latest_run_path(&self, session: &str) -> PathBuf {
        let name = Digest::hash(session.as_bytes()).to_string();
        self.reviews_root()
            .join("latest-runs")
            .join(format!("{}.json", key(&name)))
    }

    fn review_path(&self, digest: &str) -> PathBuf {
        self.reviews_root().join(format!("{}.json", key(digest)))
    }

    fn write_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
        }
        let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
        let temporary = path.with_extension("tmp");
        std::fs::write(&temporary, bytes)
            .and_then(|()| std::fs::rename(&temporary, path))
            .map_err(|error| format!("could not write {}: {error}", path.display()))
    }

    fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>, String> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|error| {
                format!(
                    "{} is not exact test or review evidence: {error}",
                    path.display()
                )
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("{} is unreadable: {error}", path.display())),
        }
    }

    fn read_review(&self, digest: &str) -> Result<Option<ReviewRecord>, String> {
        Self::read_json(&self.review_path(digest))
    }

    fn read_run(&self, run: &str) -> Result<RunRecord, String> {
        Self::read_json(&self.run_path(run))?.ok_or_else(|| format!("there is no test run {run}"))
    }

    /// Every readable record of one kind in `directory`; an unreadable
    /// record vouches for nothing and is skipped.
    fn records<T: serde::de::DeserializeOwned>(
        directory: &Path,
    ) -> Result<Vec<(PathBuf, T)>, String> {
        let entries = match std::fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(format!("the review records are unreadable: {error}")),
        };
        let mut records = Vec::new();
        for entry in entries {
            let path = entry
                .map_err(|error| format!("the review records are unreadable: {error}"))?
                .path();
            if path.extension().and_then(|name| name.to_str()) != Some("json") {
                continue;
            }
            if let Ok(Some(record)) = Self::read_json(&path) {
                records.push((path, record));
            }
        }
        Ok(records)
    }
    /// The requesting session's open review of this project, head and tree.
    /// Another session's review of the same bytes is not this request.
    fn live_review(
        &self,
        offered: &Offered,
        session: &str,
    ) -> Result<Option<ReviewRecord>, String> {
        let mut owned = None;
        let mut carried = None;
        let mut extra_carried = false;
        for (_, record) in Self::records::<ReviewRecord>(&self.reviews_root())? {
            if record.project.as_deref() != Some(offered.project.as_str())
                || record.offered.head != offered.head
                || record.offered.tree != offered.tree
                || !belongs(&record.session, &record.carried_to, session)
            {
                continue;
            }
            // Own request wins over a carried one. Decide after the whole
            // scan: directory order must not turn two carried records into
            // an error before this session's own record is seen.
            if record.session == session {
                if owned.is_some() {
                    return Err(format!(
                        "head {} tree {} has more than one live review",
                        offered.head, offered.tree
                    ));
                }
                owned = Some(record);
            } else if carried.is_some() {
                extra_carried = true;
            } else {
                carried = Some(record);
            }
        }
        if owned.is_some() {
            return Ok(owned);
        }
        if extra_carried {
            return Err(format!(
                "head {} tree {} has more than one live review",
                offered.head, offered.tree
            ));
        }
        Ok(carried)
    }

    /// Require independent approval of this exact project, branch, and head.
    pub(super) fn approved_review(
        &self,
        project: &str,
        branch: &str,
        commit: &str,
    ) -> Result<Option<ReviewRecord>, String> {
        self.approving_review(project, Some(branch), commit)
    }

    /// An approving independent review for exactly this project and commit.
    /// `branch` pins the name the review was offered under; `None` accepts
    /// any name.
    fn approving_review(
        &self,
        project: &str,
        branch: Option<&str>,
        commit: &str,
    ) -> Result<Option<ReviewRecord>, String> {
        let entries = match std::fs::read_dir(self.reviews_root()) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("the review records are unreadable: {error}")),
        };
        let mut found = None;
        for entry in entries {
            let path = entry
                .map_err(|error| format!("the review records are unreadable: {error}"))?
                .path();
            if path.extension().and_then(|name| name.to_str()) != Some("json") {
                continue;
            }
            // An unreadable record cannot vouch for anything: skipping it
            // fails closed — the merge finds no approving review.
            let record = match std::fs::read(&path) {
                Ok(bytes) => serde_json::from_slice::<ReviewRecord>(&bytes),
                Err(_) => continue,
            }
            .ok();
            let Some(record) = record.filter(|record| {
                record.project.as_deref() == Some(project)
                    && branch.is_none_or(|name| record.branch == name)
                    && record.commit.as_deref() == Some(commit)
                    && record.reviewer != record.requested_by
                    && record
                        .verdict
                        .as_ref()
                        .is_some_and(|verdict| verdict.approve)
            }) else {
                continue;
            };
            if found.is_some() {
                return Err(format!(
                    "{project} commit {commit} has more than one approving review"
                ));
            }
            found = Some(record);
        }
        Ok(found)
    }

    /// Freezes the registered capsule's complete tree as a snapshot commit
    /// under the run's own create-only ref and records the run pending as
    /// the session's latest — all under the staging lock, so the latest
    /// run is the last one frozen, and an earlier run that completes later
    /// never stands in for it.
    pub(super) fn begin_test_run(
        &self,
        registered: &Registered,
        selection: &TestSelection,
    ) -> Result<RunRecord, String> {
        let id = uuid::Uuid::new_v4().simple().to_string();
        let reference = format!("refs/odin/test-runs/{id}");
        let (runner, capsule) = (registered.runner, &registered.capsule.path);
        let _staging = staging();
        let offered = offered_locked(registered)?;
        let snapshot = runner.git(
            capsule,
            &[
                "commit-tree",
                &offered.tree,
                "-p",
                &offered.head,
                "-m",
                &format!("odin test run {id}"),
            ],
            Some("Odin"),
        )?;
        runner.git(capsule, &["update-ref", &reference, &snapshot, ""], None)?;
        let record = RunRecord {
            id,
            seat: registered.capsule.seat.clone(),
            session: registered.session.clone(),
            capsule: registered.capsule_project.display().to_string(),
            offered,
            snapshot,
            reference,
            command: command(selection),
            outcome: None,
            carried_to: Vec::new(),
        };
        Self::write_json(&self.run_path(&record.id), &record)?;
        Self::write_json(
            &self.latest_run_path(&registered.session),
            &LatestRun {
                run: record.id.clone(),
            },
        )?;
        Ok(record)
    }

    /// Records the executed run's outcome and the report parsed from its
    /// own log, then returns that report: nothing is answered unrecorded.
    /// The durable record is re-read under the metadata lock — a rollover
    /// may have carried the run while it executed — and only its outcome is
    /// set, once.
    pub(super) fn finish_test_run(
        &self,
        run: RunRecord,
        selection: &TestSelection,
        log: NixLog,
    ) -> Result<Value, String> {
        let report = test_report(&log, selection);
        let mut recorded = report.clone();
        if let Some(object) = recorded.as_object_mut() {
            object.remove("logTail");
        }
        let _staging = staging();
        let mut stored = self.read_run(&run.id)?;
        if stored.session != run.session
            || stored.snapshot != run.snapshot
            || stored.offered != run.offered
            || stored.command != run.command
            || stored.outcome.is_some()
        {
            return Err(format!(
                "test run {} changed or completed while it ran: its report is not recorded",
                run.id
            ));
        }
        stored.outcome = Some(RunOutcome {
            ok: log.ok,
            report: recorded,
        });
        Self::write_json(&self.run_path(&stored.id), &stored)?;
        Ok(report)
    }

    #[cfg(test)]
    pub(super) fn request_review_blocking(
        &self,
        registered: &Registered,
        reviewer: &str,
    ) -> Result<Value, String> {
        self.request_review_on(registered, reviewer, None)
    }

    pub(super) fn request_review_on(
        &self,
        registered: &Registered,
        reviewer: &str,
        lane: Option<&str>,
    ) -> Result<Value, String> {
        let capsule = &registered.capsule;
        let snapshot = self
            .registry
            .as_ref()
            .ok_or("the published registry is not bound")?
            .current();
        let capability = review_capability(&snapshot, &registered.project, lane)?;
        admit_reviewer(&snapshot, &capsule.seat, reviewer, &capability)?;
        let current = offered(registered)?;
        let latest: LatestRun = Self::read_json(&self.latest_run_path(&registered.session))?
            .ok_or("run test_run on this change first: the reviewer reads its report")?;
        let run = self.read_run(&latest.run)?;
        if run.seat != capsule.seat
            || !belongs(&run.session, &run.carried_to, &registered.session)
            || run.offered != current
        {
            return Err(
                "the last test run was on another tree, HEAD or base of this capsule: run \
                 test_run on this exact change first"
                    .to_owned(),
            );
        }
        let outcome = run.outcome.as_ref().ok_or(
            "the last test run of this change has not completed: wait for it or run test_run \
             again",
        )?;
        if let Some(refusal) = unreviewable_report(&outcome.report, &run.command) {
            return Err(refusal.to_owned());
        }
        // The complete change from the base: earlier commits are part of
        // what an approval lands.
        let delta = registered.runner.git(
            &capsule.path,
            &["diff", "--binary", &current.base, &current.tree],
            None,
        )?;
        if delta.is_empty() {
            return Err("there is no change to review".to_owned());
        }
        if delta.len() > MAX_DIFF_BYTES {
            return Err(format!(
                "the change is {} bytes; split it below {MAX_DIFF_BYTES} bytes for review",
                delta.len()
            ));
        }
        // The reviewer reads the declared checkout, which never fetched this capsule.
        let declared = registered.declared_root.display().to_string();
        let revision = registered.runner.git(
            &capsule.path,
            &[
                "commit-tree",
                &current.tree,
                "-p",
                &current.base,
                "-m",
                &format!("odin review of test run {}", run.id),
            ],
            Some("Odin"),
        )?;
        registered
            .runner
            .git_remote(
                &capsule.path,
                &[
                    "push",
                    "--quiet",
                    "--",
                    &declared,
                    &format!("+{revision}:refs/odin/reviews/{}", run.id),
                ],
            )
            .map_err(|error| format!("make the reviewed tree readable in {declared}: {error}"))?;
        let identity = json!({
            "offered": current,
            "session": registered.session,
            "run": run.id,
            "reviewer": reviewer,
        });
        let identity = serde_json::to_vec(&identity).map_err(|error| error.to_string())?;
        let digest = Digest::hash(&identity);
        let document = format!(
            "# Review request\n\nseat: {}\nproject: {}\nbranch: {}\nreview: {digest}\nbase: {}\n\
             head: {}\ntree: {}\nrevision: {} (the complete change: code_navigate mode show in project {})\n\
             test run: {} {:?}\n\n## Test report\n\n```json\n{}\n```\n\n\
             ## Complete change from the base\n\n```diff\n{delta}\n```\n",
            capsule.seat,
            current.project,
            capsule.branch,
            current.base,
            current.head,
            current.tree,
            revision,
            current.project,
            run.id,
            run.command,
            serde_json::to_string_pretty(&outcome.report).unwrap_or_default(),
        );
        // Seat-level access lets the requester read the review after session rollover.
        let metadata = store_artifact(
            &self.state_root,
            document.as_bytes(),
            "text/markdown",
            &[
                ("seat", reviewer.to_owned()),
                ("seat", capsule.seat.clone()),
            ],
        )?;
        let record = {
            let _staging = staging();
            if let Some(existing) = self.live_review(&current, &registered.session)? {
                if existing.reviewer != reviewer {
                    return Err(format!(
                        "this tree already has a live review with {}; one review per tree head",
                        existing.reviewer
                    ));
                }
                return Ok(json!({
                    "diffDigest": existing.diff_digest,
                    "artifactId": existing.artifact_id,
                    "reviewer": existing.reviewer,
                    "tests": outcome.report,
                    "verdict": existing.verdict,
                }));
            }
            match self.read_review(&digest.to_string())? {
                Some(existing) => existing,
                None => {
                    let record = ReviewRecord {
                        diff_digest: digest.to_string(),
                        requested_by: capsule.seat.clone(),
                        reviewer: reviewer.to_owned(),
                        branch: capsule.branch.clone(),
                        artifact_id: metadata.artifact_id.to_string(),
                        project: Some(current.project.clone()),
                        commit: None,
                        prepared: None,
                        verdict: None,
                        session: registered.session.clone(),
                        run: run.id.clone(),
                        offered: current.clone(),
                        lane: lane.map(str::to_owned),
                        carried_to: Vec::new(),
                    };
                    Self::write_json(&self.review_path(&record.diff_digest), &record)?;
                    record
                }
            }
        };
        tracing::info!(
            "review requested seat={} reviewer={reviewer} review={digest} run={} \
             tree={} artifact={}",
            capsule.seat,
            run.id,
            record.offered.tree,
            record.artifact_id
        );
        Ok(json!({
            "diffDigest": record.diff_digest,
            "artifactId": record.artifact_id,
            "reviewer": reviewer,
            "tests": outcome.report,
            "verdict": record.verdict,
        }))
    }

    pub(super) fn record_verdict_blocking(
        &self,
        runner: &dyn GitRunner,
        scope: &odin_domain::Scope,
        diff_digest: &str,
        approve: bool,
        notes: &str,
    ) -> Result<Value, String> {
        let reviewer = scope
            .seat
            .as_ref()
            .ok_or("this dispatch has no seat")?
            .to_string();
        if notes.len() > MAX_REVIEW_NOTES_BYTES {
            return Err(format!(
                "notes are limited to {MAX_REVIEW_NOTES_BYTES} bytes"
            ));
        }
        let record = self.update_review(diff_digest, |record| {
            verdict_refusal(record, &reviewer).map_err(str::to_owned)?;
            let snapshot = self
                .registry
                .as_ref()
                .ok_or("the published registry is not bound")?
                .current();
            let project = record
                .project
                .clone()
                .ok_or("this review names no project")?;
            let capability = review_capability(&snapshot, &project, record.lane.as_deref())?;
            admit_reviewer(&snapshot, &record.requested_by, &reviewer, &capability)?;
            record.verdict = Some(Verdict {
                reviewer: reviewer.clone(),
                approve,
                notes: notes.to_owned(),
            });
            Ok(())
        })?;
        tracing::info!(
            "review verdict reviewer={reviewer} review={diff_digest} approve={approve} requested_by={}",
            record.requested_by
        );
        // The reviewed revision was only for the reviewer to read.
        let reference = format!("refs/odin/reviews/{}", record.run);
        let declared = Path::new(&record.offered.declared_root);
        if let Err(error) = runner.git(declared, &["update-ref", "-d", &reference], None) {
            tracing::warn!(
                "review ref remains ref={reference} checkout={} error={error}",
                declared.display()
            );
        }
        Ok(json!({
            "diffDigest": record.diff_digest,
            "approve": approve,
            "requestedBy": record.requested_by,
            "branch": record.branch,
        }))
    }

    /// One review's read-modify-write under the metadata lock: a concurrent
    /// carry, verdict or binding is re-read, never overwritten by a stale
    /// copy.
    fn update_review(
        &self,
        digest: &str,
        change: impl FnOnce(&mut ReviewRecord) -> Result<(), String>,
    ) -> Result<ReviewRecord, String> {
        let _staging = staging();
        let mut record = self
            .read_review(digest)?
            .ok_or_else(|| format!("no review was requested for {digest}"))?;
        change(&mut record)?;
        Self::write_json(&self.review_path(digest), &record)?;
        Ok(record)
    }

    /// The review `matches` selects that belongs to `session`: the offering
    /// seat's approving one first, else any for its refusal.
    fn owned_review(
        &self,
        session: &str,
        seat: &str,
        matches: impl Fn(&ReviewRecord) -> bool,
    ) -> Result<Option<ReviewRecord>, String> {
        let mut found = None;
        for (_, record) in Self::records::<ReviewRecord>(&self.reviews_root())? {
            if !matches(&record) || !belongs(&record.session, &record.carried_to, session) {
                continue;
            }
            if record.requested_by == seat
                && record
                    .verdict
                    .as_ref()
                    .is_some_and(|verdict| verdict.approve)
            {
                return Ok(Some(record));
            }
            found.get_or_insert(record);
        }
        Ok(found)
    }

    /// Prepare under the metadata/index lock. No public ref moves before
    /// the exact commit, target and private retention ref are recorded.
    fn prepare_publication(
        &self,
        registered: &Registered,
        summary: &str,
        branch: Option<&str>,
    ) -> Result<(ReviewRecord, claims::Claim), ProposalFailure> {
        let (runner, capsule) = (registered.runner, &registered.capsule);
        let declared_root = registered.declared_root.display().to_string();
        // Resolve a recovery target without the staging mutex, then acquire
        // its ref lock first. Preparation re-reads metadata under staging and
        // refuses if that target changed instead of reversing lock order.
        let hinted = if branch.is_none() {
            self.owned_review(&registered.session, &capsule.seat, |record| {
                record.offered.project == registered.project
                    && record.offered.declared_root == declared_root
                    && record.offered.base == registered.base
                    && record.prepared.is_some()
            })?
            .and_then(|record| record.prepared.map(|prepared| prepared.branch))
        } else {
            None
        };
        let target = branch.or(hinted.as_deref()).unwrap_or(&capsule.branch);
        let mut claim = self.claim_branch(
            runner,
            capsule,
            &registered.project,
            &registered.session,
            target,
        )?;
        if matches!(
            claim.pending(),
            Some(claims::Pending::Direct { .. } | claims::Pending::Remote { .. })
        ) {
            return Err(ProposalFailure::Refused(
                "this ref retains an unresolved direct publication".to_owned(),
            ));
        }
        let branch = target;
        let _staging = staging();
        let head = runner.git(&capsule.path, &["rev-parse", "HEAD"], None)?;
        let pending = self.owned_review(&registered.session, &capsule.seat, |record| {
            record.offered.project == registered.project
                && record.offered.declared_root == declared_root
                && record.offered.base == registered.base
                && record.prepared.as_ref().is_some_and(|prepared| {
                    prepared.capsule != capsule.path
                        || prepared.head == head
                        || prepared.commit == head
                })
        })?;
        let mut record = if let Some(record) = pending {
            record
        } else {
            let current = offered_locked(registered)?;
            let committed_tree =
                runner.git(&capsule.path, &["rev-parse", "HEAD^{tree}"], None)? == current.tree;
            self.owned_review(&registered.session, &capsule.seat, |record| {
                record.offered == current
                    || (committed_tree
                        && record.commit.as_deref() == Some(current.head.as_str())
                        && record.offered.project == current.project
                        && record.offered.declared_root == current.declared_root
                        && record.offered.base == current.base
                        && record.offered.tree == current.tree)
            })?
            .ok_or_else(|| {
                ProposalFailure::Refused("no independent review covers this offer".to_owned())
            })?
        };
        if let Some(refusal) = propose_refusal(Some(&record), &capsule.seat) {
            return Err(ProposalFailure::Refused(refusal));
        }
        claim.prepare(claims::Pending::Review {
            digest: record.diff_digest.clone(),
        })?;
        if let Some(prepared) = &record.prepared {
            if branch != prepared.branch {
                return Err(ProposalFailure::Refused(
                    "the pending publication already names a different branch".to_owned(),
                ));
            }
        } else {
            publication::guard_seat_branch(
                runner,
                &capsule.project_root,
                branch,
                &head,
                &capsule.path,
            )?;
            let origin = publication::destination(runner, &capsule.project_root)?;
            let commit = if runner.git(&capsule.path, &["rev-parse", "HEAD^{tree}"], None)?
                == record.offered.tree
            {
                head.clone()
            } else {
                runner.git(
                    &capsule.path,
                    &[
                        "commit-tree",
                        &record.offered.tree,
                        "-p",
                        &head,
                        "-m",
                        summary,
                    ],
                    Some(&capsule.seat),
                )?
            };
            let reference = format!("refs/odin/proposals/{}", key(&record.diff_digest));
            runner.git(&capsule.path, &["update-ref", &reference, &commit], None)?;
            record.prepared = Some(PreparedPublication {
                capsule: capsule.path.clone(),
                head: head.clone(),
                commit,
                branch: branch.to_owned(),
                reference,
                origin,
            });
            Self::write_json(&self.review_path(&record.diff_digest), &record)?;
        }
        let prepared = record.prepared.as_ref().ok_or_else(|| {
            ProposalFailure::Refused("the publication record is not prepared".to_owned())
        })?;
        let source_head = if prepared.capsule == capsule.path {
            head
        } else {
            runner.git(&prepared.capsule, &["rev-parse", "HEAD"], None)?
        };
        if source_head != prepared.head && source_head != prepared.commit {
            return Err(ProposalFailure::Refused(
                "the prepared capsule's HEAD moved; publication remains retained".to_owned(),
            ));
        }
        if runner.git(&prepared.capsule, &["rev-parse", &prepared.reference], None)?
            != prepared.commit
            || runner.git(
                &prepared.capsule,
                &["rev-parse", &format!("{}^{{tree}}", prepared.commit)],
                None,
            )? != record.offered.tree
        {
            return Err(ProposalFailure::Refused(
                "the retained publication no longer matches its reviewed commit".to_owned(),
            ));
        }
        if source_head != prepared.commit {
            // HEAD may have moved outside the daemon's lock; Git owns the CAS.
            runner
                .git(
                    &prepared.capsule,
                    &[
                        "update-ref",
                        "-m",
                        "odin: reviewed offer",
                        "HEAD",
                        &prepared.commit,
                        &prepared.head,
                    ],
                    None,
                )
                .map_err(ProposalFailure::Uncertain)?;
        }
        Ok((record, claim))
    }

    pub(super) fn propose_reviewed_blocking(
        &self,
        registered: &Registered,
        summary: &str,
        branch: Option<&str>,
    ) -> Result<Value, ProposalFailure> {
        let (record, _claim) = self.prepare_publication(registered, summary, branch)?;
        let prepared = record.prepared.as_ref().ok_or_else(|| {
            ProposalFailure::Uncertain("the publication record is not prepared".to_owned())
        })?;
        let outcome = publication::publish_prepared(
            registered.runner,
            &prepared.capsule,
            &registered.capsule.project_root,
            &prepared.branch,
            &prepared.commit,
            prepared.commit != prepared.head,
            prepared.origin.as_deref(),
        )
        .map_err(ProposalFailure::Uncertain)?;
        let complete = !outcome.uncertain;
        let record = self
            .update_review(&record.diff_digest, |stored| {
                if stored.prepared.as_ref() != Some(prepared) {
                    if stored.prepared.is_none()
                        && stored.commit.as_deref() == Some(prepared.commit.as_str())
                        && stored.branch == prepared.branch
                    {
                        return Ok(()); // Another exact reconciliation already completed.
                    }
                    return Err("publication record changed during reconciliation".to_owned());
                }
                if outcome.report["local"]["pushed"] == true || stored.commit.is_none() {
                    stored.branch = prepared.branch.clone();
                }
                // A refused retarget must preserve approval of the published branch.
                stored.commit = Some(prepared.commit.clone());
                if complete {
                    stored.prepared = None;
                }
                Ok(())
            })
            .map_err(ProposalFailure::Uncertain)?;
        if outcome.uncertain {
            return Err(ProposalFailure::Uncertain(format!(
                "commit {} is retained; publication is unproved",
                prepared.commit,
            )));
        }
        let mut proposed = outcome.report;
        if let Some(object) = proposed.as_object_mut() {
            object.insert(
                "review".to_owned(),
                json!({
                    "diffDigest": record.diff_digest,
                    "reviewer": record.reviewer,
                    "notes": record.verdict.map(|verdict| verdict.notes),
                }),
            );
        }
        Ok(proposed)
    }

    /// The conversation rollover's explicit transfer: every run (a pending
    /// one completes into the carried record) and review that belongs to
    /// `predecessor` is carried to the trusted successor whose registered
    /// seat, project root and base it matches. The successor's registration
    /// is read only when there is evidence; carrying twice is the same as
    /// once.
    pub(super) fn carry_review_evidence_blocking(
        &self,
        runner: &dyn GitRunner,
        predecessor: &str,
        successor: impl FnOnce() -> Result<Option<RegisteredCodeCapsule>, String>,
    ) -> Result<(), String> {
        let mut runs = Self::records::<RunRecord>(&self.reviews_root().join("runs"))?;
        runs.retain(|(_, run)| belongs(&run.session, &run.carried_to, predecessor));
        let mut reviews = Self::records::<ReviewRecord>(&self.reviews_root())?;
        reviews.retain(|(_, review)| belongs(&review.session, &review.carried_to, predecessor));
        if runs.is_empty()
            && reviews.is_empty()
            && !claims::owned_by(&self.state_root, predecessor)?
        {
            return Ok(());
        }
        let Some(successor) = successor()? else {
            tracing::error!(
                "review evidence of {predecessor} not carried: its successor is \
                 registered over a knowledge root, with no capsule to offer from"
            );
            return Ok(());
        };
        let name = successor.session.to_string();
        claims::carry(
            runner,
            &self.state_root,
            predecessor,
            &name,
            successor.seat.as_str(),
            &successor.declared_project,
            &successor.source_commit,
        )?;
        // Ref locks and the successor's pool lookup have ended. Re-read
        // records under staging so concurrent completions are never lost.
        let _staging = staging();
        runs = Self::records::<RunRecord>(&self.reviews_root().join("runs"))?;
        runs.retain(|(_, run)| belongs(&run.session, &run.carried_to, predecessor));
        reviews = Self::records::<ReviewRecord>(&self.reviews_root())?;
        reviews.retain(|(_, review)| belongs(&review.session, &review.carried_to, predecessor));
        let declared_root = successor.declared_project.display().to_string();
        let fits = |seat: &str, offered: &Offered| {
            seat == successor.seat.as_str()
                && offered.declared_root == declared_root
                && offered.base == successor.source_commit
        };
        let mut carried = (0, 0);
        let latest: Option<LatestRun> = Self::read_json(&self.latest_run_path(predecessor))?;
        for (path, mut run) in runs {
            if !fits(&run.seat, &run.offered) {
                continue;
            }
            if !run.carried_to.contains(&name) {
                run.carried_to.push(name.clone());
                Self::write_json(&path, &run)?;
                carried.0 += 1;
            }
            let successor_latest = self.latest_run_path(&name);
            if latest.as_ref().is_some_and(|latest| latest.run == run.id)
                && !successor_latest.exists()
            {
                Self::write_json(&successor_latest, &LatestRun { run: run.id })?;
            }
        }
        for (path, mut review) in reviews {
            if fits(&review.requested_by, &review.offered) && !review.carried_to.contains(&name) {
                review.carried_to.push(name.clone());
                Self::write_json(&path, &review)?;
                carried.1 += 1;
            }
        }
        tracing::info!(
            "review evidence carried from {predecessor} to {name}: runs={} reviews={}",
            carried.0,
            carried.1
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::super::Capsule;
    use super::*;
    use crate::test_support::git as git_in;
    use odin_domain::Scope;

    fn selection() -> TestSelection {
        TestSelection::Paths(vec!["test_fixture.py".to_owned()])
    }

    /// Completes `run` through the production finish with a passing log
    /// the unit test writes itself (the boundary below the executors).
    fn passed(route: &DaemonCodingRoute, run: RunRecord) {
        let log = NixLog {
            ok: true,
            log: "test result: ok. 2 passed; 0 failed; 0 ignored".to_owned(),
            seconds: 0,
        };
        route.finish_test_run(run, &selection(), log).unwrap();
    }

    /// A completed run of `registered`'s current tree.
    fn tested(route: &DaemonCodingRoute, registered: &Registered) {
        passed(
            route,
            route.begin_test_run(registered, &selection()).unwrap(),
        );
    }

    fn record(verdict: Option<Verdict>) -> ReviewRecord {
        ReviewRecord {
            diff_digest: "blake3:abc".to_owned(),
            requested_by: "gungnir".to_owned(),
            reviewer: "gungnir-review".to_owned(),
            branch: "seat/gungnir/1234".to_owned(),
            artifact_id: "blake3:def".to_owned(),
            project: Some("rig".to_owned()),
            commit: None,
            prepared: None,
            verdict,
            session: "1234".to_owned(),
            run: "0".repeat(32),
            offered: Offered {
                project: "rig".to_owned(),
                declared_root: "/rig".to_owned(),
                base: "a".repeat(40),
                head: "a".repeat(40),
                tree: "b".repeat(40),
            },
            lane: None,
            carried_to: Vec::new(),
        }
    }

    /// A declared project repository with one base commit.
    fn project(dir: &Path, name: &str) -> PathBuf {
        let root = dir.join(name);
        std::fs::create_dir_all(&root).unwrap();
        git_in(&root, &["init", "-q"]);
        std::fs::write(root.join("flake.nix"), "# base\n").unwrap();
        git_in(&root, &["add", "-A"]);
        git_in(&root, &["commit", "-qm", "base"]);
        root
    }

    const GIT: &dyn GitRunner = &super::super::Unowned;

    /// One session's capsule cloned at the project's HEAD and registered
    /// exactly as the pool registers it (the unit boundary below the pool).
    fn registered(dir: &Path, root: &Path, project: &str, session: &str) -> Registered<'static> {
        git_in(dir, &["clone", "-q", root.to_str().unwrap(), session]);
        let path = dir.join(session);
        Registered {
            capsule: Capsule {
                path: path.clone(),
                project_root: root.to_owned(),
                branch: format!("seat/gungnir/{session}"),
                seat: "gungnir".to_owned(),
            },
            project: project.to_owned(),
            session: session.to_owned(),
            declared_root: root.canonicalize().unwrap(),
            capsule_project: path,
            base: git_in(root, &["rev-parse", "HEAD"]),
            runner: GIT,
        }
    }

    /// The pool's view of the same registration.
    fn pool_view(registered: &Registered) -> RegisteredCodeCapsule {
        RegisteredCodeCapsule {
            session: registered.session.parse().unwrap(),
            seat: registered.capsule.seat.parse().unwrap(),
            declared_project: registered.declared_root.clone(),
            capsule_project: registered.capsule_project.clone(),
            source_commit: registered.base.clone(),
        }
    }

    fn route(dir: &Path) -> (tempfile::TempDir, DaemonCodingRoute) {
        let (registry, registry_dir) = super::super::review_registry();
        (
            registry_dir,
            DaemonCodingRoute {
                state_root: dir.join("state"),
                session_pool: None,
                supervisor: Default::default(),
                projects: BTreeMap::new(),
                registry: Some(registry),
                manifest: None,
                merge_lock_bound: crate::coding_route::MERGE_LOCK_BOUND,
            },
        )
    }

    fn scope(seat: &str, project: &str) -> Scope {
        Scope {
            seat: Some(seat.parse().unwrap()),
            project: Some(project.parse().unwrap()),
            ..Scope::default()
        }
    }
    #[test]
    fn a_reviewer_must_hold_the_capability_the_project_names() {
        let (registry, _registry_dir) = super::super::review_registry();
        let snapshot = registry.current();
        let capability = review_capability(&snapshot, "rig", None).unwrap();
        assert_eq!(capability, "code.review.verdict");
        assert!(admit_reviewer(&snapshot, "gungnir", "gungnir", &capability)
            .unwrap_err()
            .contains("never reviews its own"));
        let missing = admit_reviewer(&snapshot, "gungnir", "reginn", &capability).unwrap_err();
        assert!(missing.contains("does not hold"), "{missing}");
        admit_reviewer(&snapshot, "gungnir", "forseti", &capability).unwrap();
        let lane = review_capability(&snapshot, "rig", Some("gungnir-rig")).unwrap();
        assert_eq!(lane, "code.review.verdict");
    }

    #[test]
    fn one_live_review_per_tree_refuses_a_second_reviewer() {
        let dir = tempfile::tempdir().unwrap();
        let root = project(dir.path(), "project");
        let capsule = registered(dir.path(), &root, "rig", "shop");
        std::fs::write(capsule.capsule.path.join("shop.txt"), "one tree\n").unwrap();
        let (_registry, route) = route(dir.path());
        tested(&route, &capsule);
        let current = offered(&capsule).unwrap();
        let planted = ReviewRecord {
            diff_digest: "blake3:planted".to_owned(),
            requested_by: "gungnir".to_owned(),
            reviewer: "other-judge".to_owned(),
            branch: capsule.capsule.branch.clone(),
            artifact_id: "artifact".to_owned(),
            project: Some(current.project.clone()),
            commit: None,
            prepared: None,
            verdict: None,
            session: capsule.session.clone(),
            run: "run".to_owned(),
            offered: current,
            lane: None,
            carried_to: Vec::new(),
        };
        std::fs::create_dir_all(route.reviews_root()).unwrap();
        std::fs::write(
            route.reviews_root().join("planted.json"),
            serde_json::to_vec(&planted).unwrap(),
        )
        .unwrap();
        let refused = route
            .request_review_blocking(&capsule, "forseti")
            .unwrap_err();
        assert!(
            refused.contains("already has a live review with other-judge"),
            "{refused}"
        );
    }

    #[test]
    fn a_branch_is_offered_only_on_an_approving_verdict_for_the_exact_diff() {
        assert!(propose_refusal(None, "gungnir").is_some());
        assert!(propose_refusal(Some(&record(None)), "gungnir").is_some());
        let changes = Verdict {
            reviewer: "gungnir-review".to_owned(),
            approve: false,
            notes: "the error path is untested".to_owned(),
        };
        assert!(propose_refusal(Some(&record(Some(changes))), "gungnir")
            .is_some_and(|refusal| refusal.contains("untested")));
        let approve = Verdict {
            reviewer: "gungnir-review".to_owned(),
            approve: true,
            notes: "ok".to_owned(),
        };
        let approved = record(Some(approve));
        assert!(propose_refusal(Some(&approved), "gungnir").is_none());
        // The review belongs to the seat that requested it: another seat
        // never offers it, whatever its verdict.
        assert!(propose_refusal(Some(&approved), "loki")
            .is_some_and(|refusal| refusal.contains("only that seat may offer it")));
    }

    #[test]
    fn the_merge_gate_accepts_only_an_independent_review_of_the_exact_head() {
        let dir = tempfile::tempdir().unwrap();
        let route = DaemonCodingRoute {
            state_root: dir.path().to_path_buf(),
            session_pool: None,
            supervisor: Default::default(),
            projects: BTreeMap::new(),
            registry: None,
            manifest: None,
            merge_lock_bound: crate::coding_route::MERGE_LOCK_BOUND,
        };
        std::fs::create_dir_all(route.reviews_root()).unwrap();
        let write = |record: &ReviewRecord| {
            std::fs::write(
                route.reviews_root().join(format!(
                    "{}.json",
                    record.diff_digest.trim_start_matches("blake3:")
                )),
                serde_json::to_vec_pretty(record).unwrap(),
            )
            .unwrap();
        };
        let head = "a".repeat(40);
        let mut approved = record(Some(Verdict {
            reviewer: "gungnir-review".to_owned(),
            approve: true,
            notes: String::new(),
        }));
        approved.commit = Some(head.clone());
        assert!(route
            .approved_review("rig", "seat/gungnir/1234", &head)
            .unwrap()
            .is_none());
        write(&approved);
        assert!(route
            .approved_review("rig", "seat/gungnir/1234", &head)
            .unwrap()
            .is_some());
        // The head moved after the reviewed proposal: stale, never passes.
        assert!(route
            .approved_review("rig", "seat/gungnir/1234", &"b".repeat(40))
            .unwrap()
            .is_none());
        // The same review does not land another project's merge, and a
        // record bound to no project binds nothing at all.
        let mut unbound = record(Some(Verdict {
            reviewer: "gungnir-review".to_owned(),
            approve: true,
            notes: String::new(),
        }));
        unbound.diff_digest = "blake3:fed".to_owned();
        unbound.project = None;
        unbound.commit = Some(head.clone());
        write(&unbound);
        assert!(route
            .approved_review("odin", "seat/gungnir/1234", &head)
            .unwrap()
            .is_none());
        assert!(route
            .approved_review("rig", "seat/gungnir/1234", &head)
            .unwrap()
            .is_some());
        // The requesting seat's own approval is no review.
        let mut self_approved = record(Some(Verdict {
            reviewer: "gungnir".to_owned(),
            approve: true,
            notes: String::new(),
        }));
        self_approved.diff_digest = "blake3:def".to_owned();
        self_approved.reviewer = "gungnir".to_owned();
        self_approved.commit = Some(head.clone());
        write(&self_approved);
        assert!(route
            .approved_review("rig", "seat/gungnir/1234", &head)
            .unwrap()
            .is_some());
        std::fs::remove_file(route.reviews_root().join("abc.json")).unwrap();
        assert!(route
            .approved_review("rig", "seat/gungnir/1234", &head)
            .unwrap()
            .is_none());
        // A record that is not exact evidence binds nothing, and stays.
        let legacy = serde_json::json!({
            "diffDigest": "blake3:0ld", "requestedBy": "gungnir", "reviewer": "forseti",
            "branch": "seat/gungnir/1234", "artifactId": "blake3:def", "project": "rig",
            "commit": head, "verdict": { "reviewer": "forseti", "approve": true, "notes": "" },
        });
        let legacy_path = route.reviews_root().join("0ld.json");
        std::fs::write(&legacy_path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        assert!(route
            .approved_review("rig", "seat/gungnir/1234", &head)
            .unwrap()
            .is_none());
        assert!(route.read_review("blake3:0ld").is_err());
        assert!(legacy_path.is_file(), "legacy evidence is never deleted");
    }

    #[test]
    fn a_committed_offer_recovers_after_the_project_push_is_interrupted() {
        let dir = tempfile::tempdir().unwrap();
        let root = project(dir.path(), "project");
        let origin = dir.path().join("origin.git");
        git_in(
            dir.path(),
            &["init", "--bare", "-q", origin.to_str().unwrap()],
        );
        git_in(
            &root,
            &["remote", "add", "origin", origin.to_str().unwrap()],
        );
        let capsule = registered(dir.path(), &root, "rig", "interrupted");
        let (_registry, first_route) = route(dir.path());
        let before = git_in(&capsule.capsule.path, &["rev-parse", "HEAD"]);
        std::fs::write(capsule.capsule.path.join("reviewed.txt"), "retained work\n").unwrap();
        tested(&first_route, &capsule);
        let requested = first_route
            .request_review_blocking(&capsule, "forseti")
            .unwrap();
        first_route
            .record_verdict_blocking(
                GIT,
                &scope("forseti", "rig"),
                requested["diffDigest"].as_str().unwrap(),
                true,
                "reviewed complete tree",
            )
            .unwrap();
        let reference = format!("refs/heads/{}", capsule.capsule.branch);
        let lock = root.join(".git").join(format!("{reference}.lock"));
        std::fs::create_dir_all(lock.parent().unwrap()).unwrap();
        std::fs::write(&lock, "another ref transaction owns this lock\n").unwrap();
        let held = first_route
            .propose_reviewed_blocking(&capsule, "reviewed offer", None)
            .unwrap();
        assert_eq!(held["local"]["pushed"], false);
        assert_eq!(held["local"]["uncertain"], false);
        let produced = git_in(&capsule.capsule.path, &["rev-parse", "HEAD"]);
        assert_ne!(
            produced, before,
            "the interruption follows the local commit"
        );
        assert_eq!(
            git_in(&capsule.capsule.path, &["rev-parse", "HEAD^"]),
            before
        );
        std::fs::remove_file(lock).unwrap();
        drop(first_route);

        let (_reopened_registry, reopened) = route(dir.path());
        let unavailable_origin = dir.path().join("temporarily-unavailable.git");
        std::fs::rename(&origin, &unavailable_origin).unwrap();
        assert!(matches!(
            reopened.propose_reviewed_blocking(&capsule, "reviewed offer", None),
            Err(ProposalFailure::Uncertain(_))
        ));
        std::fs::rename(&unavailable_origin, &origin).unwrap();
        let retried = reopened
            .propose_reviewed_blocking(&capsule, "reviewed offer", None)
            .expect("durable prepared identity must recover the already committed offer");
        assert_eq!(retried["commit"], produced);
        assert_eq!(
            git_in(&capsule.capsule.path, &["rev-parse", "HEAD"]),
            produced
        );
        assert_eq!(git_in(&root, &["rev-parse", &reference]), produced);
        assert_eq!(git_in(&origin, &["rev-parse", &reference]), produced);
        assert_eq!(
            git_in(&origin, &["show", &format!("{produced}:reviewed.txt")]),
            "retained work"
        );
        assert!(reopened
            .approved_review("rig", &capsule.capsule.branch, &produced)
            .unwrap()
            .is_some());
    }


}
