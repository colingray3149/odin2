//! One stable-inode publication lock per declared project/ref, and a durable
//! task claim that outlives that lock and daemon restarts. Only an Ended
//! session with no unresolved publication can be replaced by another task.
use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::GitRunner;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Owner {
    pub(crate) session: String,
    pub(crate) seat: String,
    pub(crate) project: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub(crate) enum Pending {
    Direct {
        commit: String,
        origin: Option<String>,
        source: PathBuf,
    },
    Remote {
        commit: String,
        origin: Option<String>,
        host: String,
        workspace: PathBuf,
        upstream: String,
    },
    // The review record is the sole prepared-publication journal for this
    // lane. Do not create a second completion write that can strand it.
    Review {
        digest: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Record {
    schema: u8,
    project_root: PathBuf,
    reference: String,
    owner: Owner,
    pending: Option<Pending>,
}

pub(crate) struct Claim {
    // Drop releases this invocation's lock, never the session's claim.
    _lock: File,
    state_root: PathBuf,
    path: PathBuf,
    record: Record,
}

fn record_path(
    runner: &dyn GitRunner,
    state_root: &Path,
    project: &Path,
    reference: &str,
) -> Result<PathBuf, String> {
    let common = runner.git(project, &["rev-parse", "--git-common-dir"], None)?;
    let repository = project
        .join(common)
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let project = repository
        .to_str()
        .ok_or("branch repository root is not UTF-8")?;
    let mut digest = blake3::Hasher::new();
    digest.update(project.as_bytes());
    digest.update(b"\0");
    digest.update(reference.as_bytes());
    Ok(state_root
        .join("branch-claims")
        .join(format!("{}.json", digest.finalize().to_hex())))
}

fn lock(path: &Path) -> Result<File, String> {
    let directory = path
        .parent()
        .ok_or("branch claim has no parent directory")?;
    std::fs::create_dir_all(directory)
        .map_err(|error| format!("branch claim directory: {error}"))?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path.with_extension("lock"))
        .map_err(|error| format!("branch claim lock: {error}"))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => {
            Err("another publication of this exact ref is in flight".to_owned())
        }
        Err(TryLockError::Error(error)) => Err(format!("branch claim lock is unreadable: {error}")),
    }
}

fn read_record(path: &Path) -> Result<Option<Record>, String> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let record: Record = serde_json::from_slice(&bytes).map_err(|error| {
                format!("branch claim {} is unreadable: {error}", path.display())
            })?;
            if record.schema != 1 {
                return Err("branch claim schema is not supported".to_owned());
            }
            Ok(Some(record))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "branch claim {} is unreadable: {error}",
            path.display()
        )),
    }
}

impl Claim {
    /// Lock before the staging mutex; keep this guard through every
    /// publication leg and its final metadata write. `ended` must read the
    /// durable exact-session journal, never infer retirement from absence.
    /// The ref's repository identity is read on the caller's `runner`.
    pub(crate) fn acquire(
        runner: &dyn GitRunner,
        state_root: &Path,
        project_root: &Path,
        branch: &str,
        owner: Owner,
        ended: impl FnOnce(&Owner) -> Result<bool, String>,
    ) -> Result<Self, String> {
        let project_root = project_root
            .canonicalize()
            .map_err(|error| error.to_string())?;
        let reference = format!("refs/heads/{branch}");
        let path = record_path(runner, state_root, &project_root, &reference)?;
        let guard = lock(&path)?;
        let (record, changed) = match read_record(&path)? {
            Some(mut record) => {
                if record.project_root != project_root || record.reference != reference {
                    return Err("branch claim does not bind this project and ref".to_owned());
                }
                let changed = record.owner != owner;
                if changed {
                    if unresolved(state_root, record.pending.as_ref(), branch)?
                        || !ended(&record.owner)?
                    {
                        return Err(format!(
                            "branch {branch} remains owned by task {}",
                            record.owner.session
                        ));
                    }
                    record.owner = owner;
                }
                (record, changed)
            }
            None => (
                Record {
                    schema: 1,
                    project_root,
                    reference,
                    owner,
                    pending: None,
                },
                true,
            ),
        };
        let claim = Self {
            _lock: guard,
            state_root: state_root.to_owned(),
            path,
            record,
        };
        if changed {
            claim.save()?;
        }
        Ok(claim)
    }

    pub(crate) fn pending(&self) -> Option<&Pending> {
        self.record.pending.as_ref()
    }

    pub(crate) fn unresolved(&self) -> Result<bool, String> {
        let branch = self
            .record
            .reference
            .strip_prefix("refs/heads/")
            .ok_or("the claimed reference is not a branch")?;
        unresolved(&self.state_root, self.record.pending.as_ref(), branch)
    }

    pub(crate) fn prepare(&mut self, pending: Pending) -> Result<(), String> {
        if self.record.pending.as_ref() == Some(&pending) {
            return Ok(());
        }
        if self.unresolved()? {
            return Err("this ref retains a different unresolved publication".to_owned());
        }
        self.record.pending = Some(pending);
        self.save()
    }

    /// Confirmed publication or refusal clears uncertainty without releasing an active ref.
    pub(crate) fn complete(&mut self) -> Result<(), String> {
        if self.record.pending.is_none() {
            return Ok(());
        }
        self.record.pending = None;
        self.save()
    }

    fn save(&self) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(&self.record).map_err(|error| error.to_string())?;
        let temporary = self.path.with_extension("tmp");
        std::fs::write(&temporary, bytes)
            .and_then(|()| std::fs::rename(&temporary, &self.path))
            .map_err(|error| {
                format!(
                    "cannot persist branch claim {}: {error}",
                    self.path.display()
                )
            })
    }
}

/// Explicit trusted rollover only. The caller resolves the successor's
/// registration BEFORE acquiring any ref lock or staging mutex. Pending
/// identity is kept verbatim; transfer never chooses a new destination.
pub(crate) fn carry(
    runner: &dyn GitRunner,
    state_root: &Path,
    predecessor: &str,
    successor: &str,
    seat: &str,
    project_root: &Path,
    base: &str,
) -> Result<(), String> {
    let directory = state_root.join("branch-claims");
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("cannot read branch claims: {error}")),
    };
    let project_root = project_root
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let mut moved = 0;
    let mut held = 0;
    let result: Result<(), String> = (|| {
        for entry in entries {
            let path = entry.map_err(|error| error.to_string())?.path();
            if path.extension().and_then(|part| part.to_str()) != Some("json") {
                continue;
            }
            let Some(discovered) = read_record(&path)? else {
                continue;
            };
            if discovered.owner.session != predecessor
                || discovered.owner.seat != seat
                || discovered.project_root != project_root
            {
                continue;
            }
            if record_path(runner, state_root, &project_root, &discovered.reference)? != path {
                return Err("branch claim filename contradicts its identity".to_owned());
            }
            let guard = lock(&path)?;
            let mut record = read_record(&path)?.ok_or("branch claim disappeared during carry")?;
            if record.owner.session == successor && record.owner.seat == seat {
                continue;
            }
            if record.owner != discovered.owner
                || record.project_root != discovered.project_root
                || record.reference != discovered.reference
            {
                return Err("branch ownership changed during carry".to_owned());
            }
            if let Some(Pending::Review { digest }) = &record.pending {
                let branch = record
                    .reference
                    .strip_prefix("refs/heads/")
                    .ok_or("the claimed reference is not a branch")?;
                if let Some(prepared) =
                    super::review::claim_preparation(state_root, digest, branch)?
                        .filter(|prepared| prepared.base != base)
                {
                    // The predecessor is already retired during rollover. Keep
                    // this unresolved ref, but do not prevent the successor from
                    // continuing unrelated work on its current base.
                    held += 1;
                    tracing::warn!(
                    "prepared publication retained owner={predecessor} ref={} commit={} \
                     original_base={} successor={successor} successor_base={base}; operator recovery required",
                    record.reference, prepared.commit, prepared.base
                );
                    continue;
                }
            }
            record.owner.session.clear();
            record.owner.session.push_str(successor);
            Claim {
                _lock: guard,
                state_root: state_root.to_owned(),
                path,
                record,
            }
            .save()?;
            moved += 1;
        }
        Ok(())
    })();
    tracing::info!(
        "claim carry predecessor={predecessor} successor={successor} moved={moved} retained={held}"
    );
    result.map_err(|error| format!("claim carry failed after {moved} ref transfers and {held} retained preparations: {error}"))
}

pub(crate) fn owned_by(state_root: &Path, session: &str) -> Result<bool, String> {
    let entries = match std::fs::read_dir(state_root.join("branch-claims")) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("cannot read branch claims: {error}")),
    };
    for entry in entries {
        let path = entry.map_err(|error| error.to_string())?.path();
        if path.extension().and_then(|part| part.to_str()) == Some("json")
            && read_record(&path)?.is_some_and(|record| record.owner.session == session)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn unresolved(state_root: &Path, pending: Option<&Pending>, branch: &str) -> Result<bool, String> {
    match pending {
        None => Ok(false),
        Some(Pending::Direct { .. } | Pending::Remote { .. }) => Ok(true),
        Some(Pending::Review { digest }) => {
            Ok(super::review::claim_preparation(state_root, digest, branch)?.is_some())
        }
    }
}

/// Exact durable lookup, shared by both publication producers. The weak
/// supervisor link is an observation dependency, never an ownership cycle.
pub(crate) fn owner_ended(
    supervisor: Option<std::sync::Arc<odin_omp::live::supervisor::LiveSupervisor>>,
    owner: &Owner,
) -> Result<bool, String> {
    let supervisor = supervisor.ok_or("the durable session owner reader is unavailable")?;
    let session = odin_domain::huginn::LiveSessionId::parse(&owner.session)
        .map_err(|error| error.to_string())?;
    let runtime = tokio::runtime::Handle::try_current()
        .map_err(|_| "the durable session owner reader has no runtime")?;
    if runtime.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread {
        return Err("the durable session owner reader requires the daemon runtime".to_owned());
    }
    let summary = super::blocking(|| runtime.block_on(supervisor.terminal_summary(session)))
        .map_err(|error| error.to_string())?;
    Ok(summary.is_some_and(|summary| summary.seat_id.as_str() == owner.seat))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{commit_all, git};

    const GIT: &dyn GitRunner = &super::super::Unowned;

    fn owner(session: &str) -> Owner {
        Owner {
            session: session.to_owned(),
            seat: "gungnir".to_owned(),
            project: "surtr".to_owned(),
        }
    }

    #[test]
    fn claims_survive_reopen_and_carry_until_publication_and_owner_are_finished() {
        let fixture = tempfile::tempdir().unwrap();
        let project = fixture.path().join("project");
        let state = fixture.path().join("state");
        std::fs::create_dir(&project).unwrap();
        git(&project, &["init", "-q"]);
        std::fs::write(project.join("work.txt"), "retained work\n").unwrap();
        let commit = commit_all(&project, "initial");
        let first = owner("00000000-0000-4000-8000-000000000001");
        let successor = owner("00000000-0000-4000-8000-000000000002");
        let other = owner("00000000-0000-4000-8000-000000000003");
        let branch = "seat/gungnir/shared";
        let mut claim =
            Claim::acquire(GIT, &state, &project, branch, first.clone(), |_| Ok(false)).unwrap();
        assert!(
            Claim::acquire(GIT, &state, &project, branch, first.clone(), |_| Ok(false)).is_err()
        );
        let independent = Claim::acquire(
            GIT,
            &state,
            &project,
            "seat/gungnir/disjoint",
            other.clone(),
            |_| Ok(false),
        )
        .unwrap();
        let alias = fixture.path().join("linked-worktree");
        git(
            &project,
            &[
                "worktree",
                "add",
                "-q",
                "--detach",
                alias.to_str().unwrap(),
                "HEAD",
            ],
        );
        assert!(Claim::acquire(GIT, &state, &alias, branch, other.clone(), |_| Ok(true)).is_err());
        let pending = Pending::Direct {
            commit: commit.clone(),
            origin: None,
            source: project.clone(),
        };
        claim.prepare(pending.clone()).unwrap();
        drop(claim);
        // A completed owner cannot release an unresolved publication.
        assert!(
            Claim::acquire(GIT, &state, &project, branch, other.clone(), |_| Ok(true)).is_err()
        );
        carry(
            GIT,
            &state,
            &first.session,
            &successor.session,
            &first.seat,
            &project,
            &commit,
        )
        .unwrap();
        assert!(Claim::acquire(GIT, &state, &project, branch, first, |_| Ok(false)).is_err());
        let mut carried = Claim::acquire(GIT, &state, &project, branch, successor.clone(), |_| {
            Ok(false)
        })
        .unwrap();
        assert_eq!(carried.pending(), Some(&pending));
        carried.complete().unwrap();
        drop(carried);
        // A resolved publication still belongs to its active task.
        assert!(
            Claim::acquire(GIT, &state, &project, branch, other.clone(), |_| Ok(false)).is_err()
        );
        let replacement =
            Claim::acquire(GIT, &state, &project, branch, other, |_| Ok(true)).unwrap();
        assert!(replacement.pending().is_none());
        assert!(Claim::acquire(GIT, &state, &project, branch, successor, |_| Ok(false)).is_err());
        assert_eq!(git(&project, &["rev-parse", "HEAD"]), commit);
        assert_eq!(
            std::fs::read_to_string(project.join("work.txt")).unwrap(),
            "retained work\n"
        );
        drop((replacement, independent));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn only_an_exact_durable_ended_owner_releases_its_claim() {
        use odin_domain::huginn::{
            LiveEventBody, LiveSessionId, LiveSessionState, SessionEpoch, SessionManifest,
            SessionStateChanged,
        };
        use odin_omp::live::ledger::{fs::FsLiveLedger, LiveLedger, NewLiveEvent};
        use odin_omp::live::supervisor::{LiveSessionLauncher, LiveSupervisor, SessionRuntime};
        use std::sync::Arc;

        struct NoLaunch;
        #[async_trait::async_trait]
        impl LiveSessionLauncher for NoLaunch {
            fn harness_turns(&self) -> Option<Arc<odin_omp::live::harness::HarnessTurns>> {
                None
            }

            async fn open(
                &self,
                _: &SessionManifest,
                _: SessionEpoch,
                _: bool,
            ) -> Result<SessionRuntime, odin_domain::huginn::LiveError> {
                Err(odin_domain::huginn::LiveError::Unsupported {
                    operation: "no launches in this fixture".to_owned(),
                })
            }
        }
        let fixture = tempfile::tempdir().unwrap();
        let ledger: Arc<dyn LiveLedger> = Arc::new(FsLiveLedger::open(fixture.path()).unwrap());
        let supervisor = LiveSupervisor::discover(Arc::clone(&ledger), Arc::new(NoLaunch), 4, None)
            .await
            .unwrap();
        let first = owner("00000000-0000-4000-8000-000000000004");
        let session = LiveSessionId::parse(&first.session).unwrap();
        assert!(owner_ended(None, &first).is_err());
        assert!(!owner_ended(Some(Arc::clone(&supervisor)), &first).unwrap());
        ledger
            .create_session(SessionManifest {
                session_id: session,
                seat_id: "gungnir".parse().unwrap(),
                slice_id: "slice:claims".parse().unwrap(),
                project_id: "surtr".parse().unwrap(),
                provider: odin_domain::huginn::ProviderName::new("fixture").unwrap(),
                model: odin_domain::huginn::ModelName::new("fixture").unwrap(),
                title: None,
                target_node: "fixture".parse().unwrap(),
                open_tab: false,
                workload: None,
                served_revision: None,
                harness: None,
            })
            .await
            .unwrap();
        assert!(!owner_ended(Some(Arc::clone(&supervisor)), &first).unwrap());
        ledger
            .append(
                SessionEpoch::new(1),
                NewLiveEvent {
                    session_id: session,
                    event_id: "claim-owner:ended".parse().unwrap(),
                    occurred_at: time::OffsetDateTime::now_utc(),
                    body: LiveEventBody::SessionStateChanged(SessionStateChanged {
                        previous: LiveSessionState::Starting,
                        current: LiveSessionState::Ended,
                        reason: Some("fixture completion".to_owned()),
                    }),
                },
            )
            .await
            .unwrap();
        assert!(owner_ended(Some(Arc::clone(&supervisor)), &first).unwrap());
        let mut wrong_seat = first.clone();
        wrong_seat.seat = "reginn".to_owned();
        assert!(!owner_ended(Some(supervisor), &wrong_seat).unwrap());
        let reopened = LiveSupervisor::discover(
            Arc::new(FsLiveLedger::open(fixture.path()).unwrap()),
            Arc::new(NoLaunch),
            4,
            None,
        )
        .await
        .unwrap();
        assert!(owner_ended(Some(reopened), &first).unwrap());
    }
}
