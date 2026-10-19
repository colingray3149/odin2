use std::sync::Arc;

use super::{
    declared_gateway_routes, git, git_bytes, git_commit, pod_launch_refusal, DeclarationCompile,
    Failure, RevisionScope, WorktreeLock, LOCK_BOUND,
};

impl super::BridgeRoute {
    /// The active published snapshot: the exact `Arc` the daemon's launch
    /// seams resolve profiles from at this instant.
    fn snapshot(&self) -> Arc<odin_registry::Snapshot> {
        self.pin.current()
    }

    /// A deployed authority's private worktree exists before any read of it
    /// (a one-time `git worktree add`; no registry effect).
    fn ensure_worktree(&self) -> Result<(), Failure> {
        match &self.sync {
            Some(sync) => sync.ensure(&self.worktree),
            None => Ok(()),
        }
    }

    fn anchored_commit(&self, active: Option<&odin_registry::Snapshot>) -> Result<String, Failure> {
        let active = active.ok_or_else(|| Failure::PublicationRefused {
            reason: "no active registry publication to anchor a runtime commit".to_owned(),
        })?;
        odin_registry::SnapshotStore::new(&self.snapshot_store)
            .publication_at(active.revision)
            .map(|(_, receipt)| receipt.commit)
            .map_err(|error| Failure::PublicationRefused {
                reason: format!("active publication receipt is unreadable: {error}"),
            })
    }

    pub(super) fn draft(
        &self,
        request: &odin_hermes::runtime::WorkloadDraftRequest,
    ) -> Result<odin_hermes::runtime::WorkloadDraft, Failure> {
        self.ensure_worktree()?;
        let request = &self.with_agent_lane(request);
        let snapshot = self.snapshot();
        let (base_revision, publish_revision) = Self::draft_scope(&snapshot, request)?;
        let seat_runs = request
            .answers
            .seat
            .as_deref()
            .and_then(|seat| self.seat_lanes.get(seat).map(|lanes| (seat, lanes)));
        // The selected seat must hold the capability needed to launch its pod.
        if let Some(reason) = request
            .answers
            .seat
            .as_deref()
            .and_then(|seat| pod_launch_refusal(&snapshot.objects, seat))
        {
            return Err(Failure::InvalidDeclaration {
                issues: vec![reason],
            });
        }
        // Reject lanes the selected seat cannot launch before retaining a draft.
        if let (Some((seat, runs)), Some(lane)) =
            (seat_runs, request.answers.gateway_lane.as_deref())
        {
            if !runs.iter().any(|candidate| candidate == lane) {
                return Err(Failure::InvalidDeclaration {
                    issues: vec![format!(
                        "seat {seat} runs only on gateway lane(s) {}; a pod bound to it cannot \
                         use {lane:?}",
                        runs.join(", ")
                    )],
                });
            }
        }
        let lane = request
            .answers
            .gateway_lane
            .as_deref()
            .and_then(|lane| self.lane_availability(&snapshot.objects, lane))
            .map(|mut facts| {
                if let Some((_, runs)) = seat_runs {
                    facts
                        .declared_alternatives
                        .retain(|candidate| runs.contains(candidate));
                }
                facts
            });
        let seat_limits = request
            .answers
            .seat
            .as_deref()
            .and_then(|seat| Self::seat_limits(&snapshot.objects, seat));
        let memory_namespaces = request
            .answers
            .seat
            .as_deref()
            .zip(request.answers.project.as_deref())
            .and_then(|(seat, project)| {
                Self::admitted_memory_namespaces(&snapshot.objects, seat, project)
            });
        // Sync under the authoring lock so drafting and publication use current skeletons.
        let _transaction = WorktreeLock::acquire(&self.worktree, LOCK_BOUND)?;
        if let Some(sync) = &self.sync {
            let anchor = self.anchored_commit(Some(&snapshot))?;
            let origin = sync.fetch(&self.worktree)?;
            sync.sync(&self.worktree, &anchor, &origin, |_| false)?;
        }
        let compiled = match self.compile_declaration(&request.profile_id, &request.answers) {
            DeclarationCompile::Complete(compiled) => compiled,
            DeclarationCompile::NeedsAnswers(clarifications) => {
                return Ok(odin_hermes::runtime::WorkloadDraft {
                    profile_id: request.profile_id.clone(),
                    base_revision,
                    publish_revision,
                    declaration: None,
                    missing: clarifications,
                    lane,
                    seat_limits,
                    memory_namespaces,
                });
            }
            DeclarationCompile::Failed(failure) => return Err(failure),
        };
        let (digest, rendered) = Self::declaration_digest(&compiled)?;
        // Published ids are immutable; reject different content while a new id can still be chosen.
        if let Some(published) = snapshot.objects.iter().find(|object| {
            object.kind() == odin_registry::RegistryKind::Workload
                && object.id == request.profile_id
        }) {
            let same = odin_registry::schema::parse_object_toml(
                odin_registry::RegistryKind::Workload,
                &request.profile_id,
                format!("registry/workloads/{}/profile.toml", request.profile_id),
                &rendered,
            )
            .is_ok_and(|drafted| drafted.config == published.config);
            if !same {
                return Err(Failure::InvalidDeclaration {
                    issues: vec![format!(
                        "workload profile {:?} is already published with different content; \
                         published profiles are immutable, so draft this one under a new id",
                        request.profile_id
                    )],
                });
            }
        }
        // Retain the exact compiled declaration: the approval binds THIS
        // digest, and the publish consumes THIS retained bytes — never a
        // re-derivation from model answers.
        self.drafts
            .retain(&odin_omp::host_tools::WorkloadDraftRecord {
                declaration_digest: digest.clone(),
                profile_id: request.profile_id.clone(),
                rendered_toml: rendered.clone(),
                bound_registry_revision: publish_revision,
            })
            .map_err(|failure| Failure::DraftRetention {
                reason: failure.to_string(),
            })?;
        Ok(odin_hermes::runtime::WorkloadDraft {
            profile_id: request.profile_id.clone(),
            base_revision,
            publish_revision,
            declaration: Some(odin_hermes::runtime::WorkloadDeclaration {
                destination: Self::destination(&request.profile_id),
                declaration_digest: digest,
                rendered_toml: rendered,
            }),
            missing: Vec::new(),
            lane,
            seat_limits,
            memory_namespaces,
        })
    }

    /// Fill an absent agent lane from deployment configuration, then validate it like an explicit lane.
    fn with_agent_lane(
        &self,
        request: &odin_hermes::runtime::WorkloadDraftRequest,
    ) -> odin_hermes::runtime::WorkloadDraftRequest {
        let mut request = request.clone();
        let script = request.answers.harness.as_deref() == Some(odin_registry::SCRIPT_HARNESS);
        if script || request.answers.gateway_lane.is_some() {
            return request;
        }
        if let Some(lane) = self
            .deployment
            .as_ref()
            .and_then(|facts| facts.agent_lane.as_ref())
        {
            tracing::warn!(
                "workload draft lane defaulted profile={} lane={lane}",
                request.profile_id
            );
            request.answers.gateway_lane = Some(lane.clone());
        }
        request
    }

    /// Read-only draft preparation: the registry scope the draft needs
    /// before it compiles anything, observed before the dispatch journals
    /// the draft; the draft re-derives the same scope at execution.
    pub(super) fn prepare_draft(
        &self,
        request: &odin_hermes::runtime::WorkloadDraftRequest,
    ) -> Result<(), Failure> {
        Self::draft_scope(&self.snapshot(), request).map(|_| ())
    }

    /// The draft's registry scope: the active base revision, the
    /// publication target the draft binds — the store installs exactly
    /// active + 1, so the model must present that number, not the base;
    /// a saturated revision is a typed failure — and the caller's
    /// bound-revision agreement. Shared by the read-only preparation and
    /// the draft itself, so both refuse the same stale scope.
    fn draft_scope(
        snapshot: &odin_registry::Snapshot,
        request: &odin_hermes::runtime::WorkloadDraftRequest,
    ) -> Result<(u64, u64), Failure> {
        let base_revision = snapshot.revision;
        let publish_revision = Self::next_revision(Some(snapshot))?;
        if let Some(bound) = request.expected_registry_revision {
            if bound != base_revision {
                return Err(Failure::StaleRevision {
                    bound,
                    next: base_revision,
                });
            }
        }
        Ok((base_revision, publish_revision))
    }

    pub(super) fn publish(
        &self,
        request: &odin_hermes::runtime::WorkloadPublishRequest,
    ) -> Result<odin_hermes::runtime::WorkloadPublication, Failure> {
        // Publish only retained bytes matching the approved profile, digest, and revision.
        let retained = self.retained_material(request)?;
        let profile_id = request.profile_id.clone();
        // The store re-hashed the retained bytes against this digest at
        // load: the publication material IS the approved declaration.
        let rendered = retained.rendered_toml;
        let digest = request.declaration_digest.clone();
        self.ensure_worktree()?;
        self.worktree_git_marker()?;
        let admitted = Self::admitted_bindings();
        let store = odin_registry::SnapshotStore::new(&self.snapshot_store);
        // Serialize the WHOLE effect transaction (state re-read, resume or
        // fresh install, commit, store publication, adoption) under the
        // per-worktree authoring lock. Every state decision below is made
        // AFTER acquiring, so a concurrent identical retry — or a timed-out
        // one still finishing — reconciles exactly once instead of racing.
        let _transaction = WorktreeLock::acquire(&self.worktree, LOCK_BOUND)?;
        let active = self.active_publication()?;
        // Replay only the exact approved revision with its durable receipt; later work invalidates the scope.
        match Self::revision_scope(active.as_ref(), request.expected_registry_revision)? {
            RevisionScope::Replay => {
                return self.already_published_receipt(&profile_id, request, &digest)
            }
            RevisionScope::Fresh => {}
        }
        let next_revision = Self::next_revision(active.as_ref())?;
        // Revalidate the candidate under the lock before writing.
        let validated =
            self.validated_candidate(&profile_id, &rendered, active.as_ref(), &admitted)?;
        // Resume-or-fresh install, keyed on the exact destination file and
        // its content digest — the one file a single-fill batch writes. The
        // retained declaration bytes install verbatim through the shared
        // authoring transaction.
        let relative = Self::destination(&profile_id);
        let mut attempt = 0;
        let candidate = loop {
            attempt += 1;
            // On a deployed authority the worktree first moves onto odin `main`
            // (keeping only this publication's own pending commit).
            let synced = match &self.sync {
                Some(sync) => {
                    let anchor = self.anchored_commit(active.as_ref())?;
                    let origin = sync.fetch(&self.worktree)?;
                    sync.sync(&self.worktree, &anchor, &origin, |worktree| {
                        git_bytes(worktree, &["show", &format!("HEAD:{relative}")]).is_ok_and(
                            |bytes| odin_domain::Digest::hash(&bytes).to_string() == digest,
                        )
                    })?;
                    Some((sync, origin))
                }
                None => None,
            };
            let (committed_digest, installed_digest) = self.destination_digests(&relative)?;
            let commit = if committed_digest.as_deref() == Some(digest.as_str()) {
                // The approved declaration is already committed: resume
                // straight to publication. The candidate builder revalidates
                // the full committed registry, so no check is skipped.
                if self.sync.is_some() {
                    self.pending_mutation(&relative, &digest)?
                } else {
                    git(&self.worktree, &["rev-parse", "HEAD"])
                        .map_err(|reason| Failure::WorktreeInvalid { reason })?
                }
            } else if installed_digest.as_deref() == Some(digest.as_str()) {
                // Crash between the private install and the commit: resume by
                // committing exactly the installed destination. Anything else
                // dirty or staged in the worktree is not ours and refuses.
                Self::resume_commit(&self.worktree, &relative, &profile_id, &digest)?
            } else if installed_digest.is_some() || committed_digest.is_some() {
                // The destination is occupied by a DIFFERENT declaration: the
                // old scope is dead, never silently overwritten.
                return Err(Failure::DigestMismatch {
                    approved: digest,
                    compiled: installed_digest.or(committed_digest).unwrap_or_default(),
                });
            } else {
                // Shared staging rejects existing destinations and verifies the generated index
                // before the pathspec commit; unrelated staged work must not enter publication.
                Self::require_clean(&self.worktree)?;
                let staging_leaf = self
                    .ledger_path
                    .parent()
                    .expect("the ledger lives in the state root")
                    .join("authoring-staging")
                    .join(format!(
                        "{}-{}",
                        std::process::id(),
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|elapsed| elapsed.as_nanos())
                            .unwrap_or_default()
                    ));
                let staged = odin_registry::authoring::stage_fill_batch(
                    &validated,
                    &self.worktree,
                    &staging_leaf,
                )
                .map_err(|errors| Failure::PublicationRefused {
                    reason: format!("authoring staging failed: {errors}"),
                })?;
                let installed =
                    odin_registry::authoring::install_staged_batch(&self.worktree, &staged);
                // The staging leaf is this attempt's own private residue: the
                // install has consumed (or refused) its bytes, so it never
                // outlives the transaction.
                let _ = std::fs::remove_dir_all(&staging_leaf);
                let installed = installed.map_err(|errors| Failure::PublicationRefused {
                    reason: format!("authoring install failed: {errors}"),
                })?;
                git_commit(&self.worktree, &profile_id, "publish", &installed, &digest).map_err(
                    |failure| match failure {
                        Failure::DigestMismatch { approved, compiled } => {
                            Failure::DigestMismatch { approved, compiled }
                        }
                        other => Failure::PublicationRefused {
                            reason: other.to_string(),
                        },
                    },
                )?
            };
            // Validate isolated active content before making the commit reachable on main.
            let candidate = if self.sync.is_some() {
                Self::require_clean(&self.worktree)?;
                git(
                    &self.worktree,
                    &["checkout", "--quiet", "--detach", &commit],
                )
                .map_err(|reason| Failure::PublicationRefused { reason })?;
                store.runtime_candidate(&self.worktree, &commit, admitted.iter().cloned())
            } else {
                odin_registry::ValidatedSnapshotCandidate::from_committed_worktree(
                    &self.worktree,
                    &commit,
                    admitted.iter().cloned(),
                )
            }
            .map_err(|error| Failure::PublicationRefused {
                reason: format!("committed registry candidate is invalid: {error}"),
            })?;
            if let Some((sync, origin)) = synced {
                // A resumed mutation remains M even if unrelated main commits
                // followed it during a push/publication crash window.
                if git(
                    &self.worktree,
                    &["merge-base", "--is-ancestor", &commit, &origin],
                )
                .is_err()
                {
                    if let Err(failure) = sync.push(&self.worktree, &commit, &origin) {
                        let current = sync.fetch(&self.worktree);
                        if current.as_ref().is_ok_and(|current| {
                            git(
                                &self.worktree,
                                &["merge-base", "--is-ancestor", &commit, current],
                            )
                            .is_ok()
                        }) {
                            break candidate;
                        }
                        let moved = current.is_ok_and(|current| current != origin);
                        if !moved || attempt >= 3 {
                            return Err(failure);
                        }
                        continue;
                    }
                }
            }
            break candidate;
        };
        let result = store
            .publish_committed(&candidate, next_revision)
            .map_err(|error| Failure::PublicationRefused {
                reason: format!("registry publication failed: {error}"),
            })?;
        // Shared registry adoption: the SAME handle the daemon's launch
        // seams read advances through the handle's verified in-chain reload
        // — no daemon restart, no ad-hoc repin. An identical active
        // publication keeps the pin unchanged.
        let adopted = self
            .pin
            .reload()
            .map_err(|error| Failure::PublicationRefused {
                reason: format!("published snapshot adoption failed: {error}"),
            })?;
        if adopted.revision < result.receipt.revision {
            return Err(Failure::PublicationRefused {
                reason: format!(
                    "adoption pinned revision {} below the published revision {}",
                    adopted.revision, result.receipt.revision
                ),
            });
        }
        // Recompose at the published revision before new profiles or successor sessions are admitted.
        if matches!(result.outcome, odin_registry::PublicationOutcome::Published) {
            crate::project_authoring::request_reload();
        }
        let destination = Self::destination(&profile_id);
        Ok(odin_hermes::runtime::WorkloadPublication {
            profile_id,
            destination,
            declaration_digest: digest,
            published_revision: result.receipt.revision,
            pinned_revision: adopted.revision,
            commit: result.receipt.commit,
            outcome: match result.outcome {
                odin_registry::PublicationOutcome::Published => "published".to_owned(),
                odin_registry::PublicationOutcome::Unchanged => "unchanged".to_owned(),
            },
        })
    }

    /// Recover the immutable single-file mutation, not a later main tip
    /// that merely retains the approved bytes. No new request identity is
    /// needed: the retained approval already fixes this path and digest.
    fn pending_mutation(&self, relative: &str, digest: &str) -> Result<String, Failure> {
        let refused = |reason: String| Failure::PublicationRefused { reason };
        let commit = git(
            &self.worktree,
            &["log", "-1", "--format=%H", "HEAD", "--", relative],
        )
        .map_err(refused)?;
        let changed = git(
            &self.worktree,
            &["diff-tree", "--no-commit-id", "--name-only", "-r", &commit],
        )
        .map_err(refused)?;
        let parents = git(
            &self.worktree,
            &["rev-list", "--parents", "-n", "1", &commit],
        )
        .map_err(refused)?;
        let bytes = git_bytes(&self.worktree, &["show", &format!("{commit}:{relative}")])
            .map_err(refused)?;
        if parents.split_whitespace().count() != 2
            || changed != relative
            || odin_domain::Digest::hash(&bytes).to_string() != digest
        {
            return Err(refused(
                "the approved declaration is not an isolated ordinary mutation".to_owned(),
            ));
        }
        Ok(commit)
    }

    /// Validate before approval using the execution helpers; publication rechecks under its lock.
    pub(super) fn prepare_publish(
        &self,
        request: &odin_hermes::runtime::WorkloadPublishRequest,
    ) -> Result<(), Failure> {
        let retained = self.retained_material(request)?;
        self.ensure_worktree()?;
        self.worktree_git_marker()?;
        let active = self.active_publication()?;
        match Self::revision_scope(active.as_ref(), request.expected_registry_revision)? {
            RevisionScope::Replay => self
                .exact_replay_proof(&request.profile_id, request, &request.declaration_digest)
                .map(|_| ()),
            RevisionScope::Fresh => {
                let admitted = Self::admitted_bindings();
                self.validated_candidate(
                    &request.profile_id,
                    &retained.rendered_toml,
                    active.as_ref(),
                    &admitted,
                )?;
                self.install_precondition(&request.profile_id, &request.declaration_digest)
            }
        }
    }

    /// The current verified active publication, or None when the store has
    /// nothing yet. IO and integrity failures propagate typed: an
    /// unreadable store is never silently observed as an absent registry.
    /// Shared by the read-only preparation and the execution's locked
    /// state re-read.
    fn active_publication(&self) -> Result<Option<odin_registry::Snapshot>, Failure> {
        if self
            .snapshot_store
            .try_exists()
            .map_err(|error| Failure::PublicationRefused {
                reason: format!("active registry store is unreadable: {error}"),
            })?
        {
            odin_registry::SnapshotStore::new(&self.snapshot_store)
                .load_verified()
                .map(Some)
                .map_err(|error| Failure::PublicationRefused {
                    reason: format!("active registry publication is invalid: {error}"),
                })
        } else {
            Ok(None)
        }
    }

    /// The revision one publication after the active one — the store
    /// installs exactly active + 1. A saturated space is one typed refusal
    /// in every scope; no caller computes it with a bare `+ 1`.
    fn next_revision(active: Option<&odin_registry::Snapshot>) -> Result<u64, Failure> {
        active
            .map_or(0, |snapshot| snapshot.revision)
            .checked_add(1)
            .ok_or_else(|| Failure::PublicationRefused {
                reason: "registry revision space is exhausted".to_owned(),
            })
    }

    /// The pure publication-candidate validation shared by the read-only
    /// preparation and the execution: the retained bytes strictly re-parsed
    /// — never re-derived from model answers — and batch-validated against
    /// the current registry objects and relation context. No filesystem
    /// write, no staging: a deterministically invalid retained declaration
    /// or broken current reference refuses BEFORE the approval is consumed.
    fn validated_candidate(
        &self,
        profile_id: &str,
        rendered: &str,
        active: Option<&odin_registry::Snapshot>,
        admitted: &[odin_registry::AdmittedBinding],
    ) -> Result<odin_registry::ValidatedFillBatch, Failure> {
        let relative = Self::destination(profile_id);
        let profile: odin_registry::WorkloadProfileToml =
            toml::from_str(rendered).map_err(|error| Failure::InvalidDeclaration {
                issues: vec![format!(
                    "the retained declaration does not parse as a workload profile: {error}"
                )],
            })?;
        let compiled = odin_registry::authoring::CompiledFill {
            skeleton: odin_registry::SkeletonKind::NewWorkload,
            destination: odin_registry::authoring::AuthoringDestination::RegistryObject {
                kind: odin_registry::RegistryKind::Workload,
                id: profile_id.to_owned(),
                relative_config: std::path::PathBuf::from(&relative),
            },
            document: odin_registry::CompiledDocument::Registry(
                odin_registry::ObjectConfig::Workload(Box::new(profile)),
            ),
            canonical_toml: rendered.as_bytes().to_vec(),
        };
        let context = odin_registry::RelationContext::new(&self.worktree)
            .with_admitted_bindings(admitted.iter().cloned())
            .map_err(|finding| Failure::InvalidDeclaration {
                issues: vec![finding.message],
            })?;
        let objects: Vec<odin_registry::RegistryObject> = active
            .map(|snapshot| {
                snapshot
                    .objects
                    .iter()
                    .filter(|object| {
                        object.relative_config.as_path() != std::path::Path::new(&relative)
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        odin_registry::validate_fill_batch(vec![compiled], &objects, &context).map_err(|errors| {
            Failure::InvalidDeclaration {
                issues: errors
                    .issues()
                    .iter()
                    .map(|issue| {
                        format!(
                            "{}: {} ({})",
                            issue.path.display(),
                            issue.message,
                            issue.code
                        )
                    })
                    .collect(),
            }
        })
    }

    /// The worktree's install precondition for one publication, observed
    /// read-only: the approved bytes already committed need nothing; the
    /// crash-resume scope (installed, uncommitted) tolerates only the
    /// destination dirty; a destination occupied by a different declaration
    /// is a dead scope; a fresh install demands a completely clean worktree
    /// and a resolvable commit identity. The effectful completion of each
    /// branch stays at execution.
    fn install_precondition(&self, profile_id: &str, digest: &str) -> Result<(), Failure> {
        let relative = Self::destination(profile_id);
        let (committed_digest, installed_digest) = self.destination_digests(&relative)?;
        if committed_digest.as_deref() == Some(digest) {
            return Ok(());
        }
        if installed_digest.as_deref() == Some(digest) {
            let foreign = Self::foreign_dirty_lines(&self.worktree, &relative)?;
            if !foreign.is_empty() {
                return Err(Failure::PublicationRefused {
                    reason: format!(
                        "authoring worktree carries unrelated uncommitted changes: {foreign:?}"
                    ),
                });
            }
            return self.commit_identity();
        }
        if installed_digest.is_some() || committed_digest.is_some() {
            return Err(Failure::DigestMismatch {
                approved: digest.to_owned(),
                compiled: installed_digest.or(committed_digest).unwrap_or_default(),
            });
        }
        Self::require_clean(&self.worktree)?;
        self.commit_identity()
    }

    /// A resolvable commit identity, observed read-only via `git var`; the
    /// digest-pinned commit has no inline identity and would otherwise
    /// refuse only after the spend. BOTH idents are required: an explicit
    /// author env resolves without a committer, and the commit dies on the
    /// missing committer after the spend.
    fn commit_identity(&self) -> Result<(), Failure> {
        for var in ["GIT_AUTHOR_IDENT", "GIT_COMMITTER_IDENT"] {
            git(&self.worktree, &["var", var]).map_err(|reason| Failure::WorktreeInvalid {
                reason: format!("authoring worktree cannot commit ({var}): {reason}"),
            })?;
        }
        Ok(())
    }

    /// Missing paths return None; all other read failures propagate rather than imply absence.
    fn destination_digests(
        &self,
        relative: &str,
    ) -> Result<(Option<String>, Option<String>), Failure> {
        let committed = if self.head_contains(relative)? {
            let bytes = git_bytes(&self.worktree, &["show", &format!("HEAD:{relative}")])
                .map_err(|reason| Failure::WorktreeInvalid { reason })?;
            Some(odin_domain::Digest::hash(&bytes).to_string())
        } else {
            None
        };
        let installed = match std::fs::read(self.worktree.join(relative)) {
            Ok(bytes) => Some(odin_domain::Digest::hash(&bytes).to_string()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(Failure::WorktreeInvalid {
                    reason: format!("authoring destination {relative} is unreadable: {error}"),
                });
            }
        };
        Ok((committed, installed))
    }

    /// Only a successful empty ls-tree result means absence; Git failures propagate.
    fn head_contains(&self, relative: &str) -> Result<bool, Failure> {
        let output = git_bytes(&self.worktree, &["ls-tree", "-z", "HEAD", "--", relative])
            .map_err(|reason| Failure::WorktreeInvalid { reason })?;
        Ok(!output.is_empty())
    }

    /// Status entries outside the destination prevent resuming over unrelated dirty work.
    fn foreign_dirty_lines(
        worktree: &std::path::Path,
        relative: &str,
    ) -> Result<Vec<String>, Failure> {
        let status = git(worktree, &["status", "--porcelain", "-uall"])
            .map_err(|reason| Failure::WorktreeInvalid { reason })?;
        Ok(status
            .lines()
            .filter(|line| {
                let trimmed = line.trim_start();
                !trimmed.is_empty()
                    && !trimmed
                        .split_whitespace()
                        .last()
                        .is_some_and(|path| path == relative)
            })
            .map(str::to_owned)
            .collect())
    }

    /// A completely clean worktree — the fresh-install precondition shared
    /// by the read-only preparation and the execution's fresh branch.
    fn require_clean(worktree: &std::path::Path) -> Result<(), Failure> {
        let status = git(worktree, &["status", "--porcelain", "-uall"])
            .map_err(|reason| Failure::WorktreeInvalid { reason })?;
        if !status.trim().is_empty() {
            return Err(Failure::PublicationRefused {
                reason: format!(
                    "authoring worktree carries unrelated uncommitted changes: {:?}",
                    status.lines().collect::<Vec<_>>()
                ),
            });
        }
        Ok(())
    }

    /// Check retained draft identity, digest, and declaration using the same store for preparation and execution.
    fn retained_material(
        &self,
        request: &odin_hermes::runtime::WorkloadPublishRequest,
    ) -> Result<odin_omp::host_tools::WorkloadDraftRecord, Failure> {
        self.drafts
            .require_retained(
                &request.profile_id,
                &request.declaration_digest,
                request.expected_registry_revision,
            )
            .map_err(|failure| match failure {
                odin_omp::host_tools::WorkloadDraftStoreError::UnknownDraft {
                    digest,
                    bound_registry_revision,
                } => Failure::UnknownDraft {
                    digest,
                    bound_registry_revision,
                },
                odin_omp::host_tools::WorkloadDraftStoreError::CorruptRecord {
                    digest,
                    bound_registry_revision,
                    detail,
                } => Failure::DraftRetention {
                    reason: format!(
                        "the retained draft {digest} at bound revision \
                         {bound_registry_revision} is corrupt: {detail}"
                    ),
                },
                other => Failure::DraftRetention {
                    reason: other.to_string(),
                },
            })
    }

    /// The authoring worktree must be a clean linked Git worktree: the
    /// exact precondition the CLI author stage enforces. Read-only: the
    /// marker observation, never the lock.
    fn worktree_git_marker(&self) -> Result<(), Failure> {
        let marker = std::fs::symlink_metadata(self.worktree.join(".git")).map_err(|error| {
            Failure::WorktreeInvalid {
                reason: format!("authoring worktree has no .git marker: {error}"),
            }
        })?;
        if !marker.file_type().is_file() {
            return Err(Failure::WorktreeInvalid {
                reason: "author stage is permitted only in an isolated linked Git worktree"
                    .to_owned(),
            });
        }
        Ok(())
    }

    /// Permit exact-revision replay or installation at the next revision;
    /// reject all other scopes during preparation and the post-lock recheck.
    fn revision_scope(
        active: Option<&odin_registry::Snapshot>,
        bound: u64,
    ) -> Result<RevisionScope, Failure> {
        if let Some(active) = active {
            if active.revision == bound {
                return Ok(RevisionScope::Replay);
            }
            if active.revision > bound {
                return Err(Failure::StaleRevision {
                    bound,
                    next: Self::next_revision(Some(active))?,
                });
            }
        }
        if Self::next_revision(active)? != bound {
            return Err(Failure::StaleRevision {
                bound,
                next: Self::next_revision(active)?,
            });
        }
        Ok(RevisionScope::Fresh)
    }

    /// Compiles the strict new-workload fill and classifies the result:
    /// missing declared variables become the clarification list; any other
    /// compile or relational defect is a typed invalid-declaration refusal.
    fn compile_declaration(
        &self,
        profile_id: &str,
        answers: &odin_hermes::runtime::WorkloadDraftAnswers,
    ) -> DeclarationCompile {
        let catalog = match odin_registry::SkeletonCatalog::load(self.worktree.join("skeletons")) {
            Ok(catalog) => catalog,
            Err(errors) => {
                return DeclarationCompile::Failed(Failure::WorktreeInvalid {
                    reason: format!("skeleton catalog is invalid: {errors}"),
                });
            }
        };
        // The node's declared export root is the only folder a pod can
        // mount and write: any other answer is refused naming it.
        if let (Some(answer), Some(root)) = (
            answers.export_host_folder.as_deref(),
            self.deployment
                .as_ref()
                .and_then(|facts| facts.export_host_folder.as_deref()),
        ) {
            if answer != root {
                return DeclarationCompile::Failed(Failure::InvalidDeclaration {
                    issues: vec![format!(
                        "export host folder {answer:?} is not this node's declared export root \
                         {root:?}; omit exportHostFolder and the declared root is used"
                    )],
                });
            }
        }
        if answers.image_reference.is_some()
            && answers.harness.as_deref() != Some(odin_registry::SCRIPT_HARNESS)
        {
            return DeclarationCompile::Failed(Failure::InvalidDeclaration {
                issues: vec![
                    "an agent pod runs the platform's own image; imageReference is a script \
                     pod's (harness = script) image"
                        .to_owned(),
                ],
            });
        }
        let admitted = Self::admitted_bindings();
        let fill = odin_registry::FillRequest {
            skeleton: odin_registry::SkeletonKind::NewWorkload,
            destination_id: profile_id.to_owned(),
            values: odin_registry::FillValues(Self::fill_values(answers, self.deployment.as_ref())),
        };
        // What a pod must declare depends on what it is:
        // an agent its model lane, memory and display; a script its image
        // and command; a job its deadline. Absent ones join the declared
        // clarification list exactly like the skeleton's required variables.
        let script = answers.harness.as_deref() == Some(odin_registry::SCRIPT_HARNESS);
        let job = answers.mode.as_deref() != Some("service");
        let conditional: Vec<&str> = [
            (!script && answers.gateway_lane.is_none(), "gateway_lane"),
            (
                !script && answers.memory_namespace.is_none(),
                "memory_namespace",
            ),
            (!script && answers.screen.is_none(), "screen"),
            (!script && answers.stream.is_none(), "stream"),
            (
                script && answers.image_reference.is_none(),
                "image_reference",
            ),
            (script && answers.script_command.is_none(), "script_command"),
            (
                job && answers.deadline_seconds.is_none(),
                "deadline_seconds",
            ),
        ]
        .into_iter()
        .filter_map(|(missing, name)| missing.then_some(name))
        .collect();
        let conditional_clarifications = || {
            conditional
                .iter()
                .map(|name| odin_hermes::runtime::WorkloadClarification {
                    variable: (*name).to_owned(),
                    meaning: catalog
                        .contract(odin_registry::SkeletonKind::NewWorkload)
                        .and_then(|contract| contract.variable(name))
                        .map(|variable| variable.meaning().to_owned())
                        .unwrap_or_default(),
                })
                .collect::<Vec<_>>()
        };
        let compiled = match catalog.compile_with_bindings(fill, &admitted) {
            Ok(compiled) if conditional.is_empty() => compiled,
            Ok(_) => return DeclarationCompile::NeedsAnswers(conditional_clarifications()),
            Err(errors) => {
                return match Self::classify_issues(&catalog, &errors) {
                    DeclarationCompile::NeedsAnswers(mut missing) => {
                        for extra in conditional_clarifications() {
                            if !missing.iter().any(|known| known.variable == extra.variable) {
                                missing.push(extra);
                            }
                        }
                        DeclarationCompile::NeedsAnswers(missing)
                    }
                    other => other,
                }
            }
        };
        // Relational truth against the pinned snapshot: unknown or disabled
        // references, duplicate ids, namespaces outside the seat's brain
        // scope — everything the publication would refuse — refuse here.
        let context = match odin_registry::RelationContext::new(&self.worktree)
            .with_admitted_bindings(admitted.iter().cloned())
        {
            Ok(context) => context,
            Err(finding) => {
                return DeclarationCompile::Failed(Failure::InvalidDeclaration {
                    issues: vec![finding.message],
                });
            }
        };
        let snapshot = self.snapshot();
        // Exclude the destination from relation checks so identical content can replay
        // and conflicting content reaches the digest-mismatch check.
        let destination = Self::destination(profile_id);
        let objects: Vec<odin_registry::RegistryObject> = snapshot
            .objects
            .iter()
            .filter(|object| object.relative_config.as_path() != std::path::Path::new(&destination))
            .cloned()
            .collect();
        if let Err(errors) =
            odin_registry::validate_fill_batch(vec![compiled.clone()], &objects, &context)
        {
            return Self::classify_issues(&catalog, &errors);
        }
        DeclarationCompile::Complete(compiled)
    }

    /// Splits one authoring error set: pure missing-required issues become
    /// the declared clarification list; anything else is a typed refusal
    /// naming the exact defects.
    fn classify_issues(
        catalog: &odin_registry::SkeletonCatalog,
        errors: &odin_registry::AuthoringErrors,
    ) -> DeclarationCompile {
        let mut missing = Vec::new();
        let mut other = Vec::new();
        for issue in errors.issues() {
            if issue.code == "authoring-value-missing" {
                if let Some(name) = issue.variable.as_deref() {
                    let meaning = catalog
                        .contract(odin_registry::SkeletonKind::NewWorkload)
                        .and_then(|contract| contract.variable(name))
                        .map(|variable| variable.meaning().to_owned())
                        .unwrap_or_else(|| "required by the new-workload skeleton".to_owned());
                    missing.push(odin_hermes::runtime::WorkloadClarification {
                        variable: name.to_owned(),
                        meaning,
                    });
                    continue;
                }
            }
            other.push(match issue.variable.as_deref() {
                Some(variable) => format!(
                    "{}: {variable}: {} ({})",
                    issue.path.display(),
                    issue.message,
                    issue.code
                ),
                None => format!(
                    "{}: {} ({})",
                    issue.path.display(),
                    issue.message,
                    issue.code
                ),
            });
        }
        if other.is_empty() && !missing.is_empty() {
            DeclarationCompile::NeedsAnswers(missing)
        } else {
            DeclarationCompile::Failed(Failure::InvalidDeclaration { issues: other })
        }
    }

    /// The canonical declaration identity: blake3 over the exact canonical
    /// TOML bytes the compiled typed value serializes to — the same bytes
    /// staging writes, so the approved digest and the published file can
    /// never diverge.
    fn declaration_digest(
        compiled: &odin_registry::CompiledFill,
    ) -> Result<(String, String), Failure> {
        let odin_registry::CompiledDocument::Registry(config) = &compiled.document else {
            return Err(Failure::InvalidDeclaration {
                issues: vec![
                    "the new-workload skeleton did not compile to a registry object".to_owned(),
                ],
            });
        };
        let odin_registry::ObjectConfig::Workload(profile) = config else {
            return Err(Failure::InvalidDeclaration {
                issues: vec!["the compiled object is not a workload profile".to_owned()],
            });
        };
        let bytes = toml::to_string(profile).map_err(|error| Failure::InvalidDeclaration {
            issues: vec![format!(
                "canonical declaration serialization failed: {error}"
            )],
        })?;
        let digest = odin_domain::Digest::hash(bytes.as_bytes()).to_string();
        Ok((digest, bytes))
    }

    /// The registry destination the profile publishes to:
    /// `registry/workloads/<id>/profile.toml`.
    fn destination(profile_id: &str) -> String {
        let kind = odin_registry::RegistryKind::Workload;
        std::path::Path::new("registry")
            .join(kind.directory())
            .join(profile_id)
            .join(kind.config_name())
            .to_string_lossy()
            .to_string()
    }

    fn admitted_bindings() -> Vec<odin_registry::AdmittedBinding> {
        odin_cli::runtime_bindings::admitted_registry_bindings()
    }

    /// Decodes the declared answers into the strict typed fill table. Only
    /// present answers enter the table. An agent pod's image is "platform"
    /// and its in-image paths are the deployment's pinned facts alone (the
    /// model never states them); its mount facts complete the mount answers. The skeleton compiler owns every grammar and every
    /// missing-variable decision.
    fn fill_values(
        answers: &odin_hermes::runtime::WorkloadDraftAnswers,
        deployment: Option<&crate::kube::WorkloadDeploymentFacts>,
    ) -> toml::Table {
        // A script pod states its own image and runs no
        // agent: the deployment's agent facts (launcher, browser, display)
        // are never filled for it. An agent pod runs the platform image.
        let script = answers.harness.as_deref() == Some(odin_registry::SCRIPT_HARNESS);
        // Mount facts apply to every pod; agent facts only to an agent pod.
        let fact = |select: fn(&crate::kube::WorkloadDeploymentFacts) -> Option<&String>| {
            deployment.and_then(select)
        };
        let agent_fact = |select: fn(&crate::kube::WorkloadDeploymentFacts) -> Option<&String>| {
            deployment.filter(|_| !script).and_then(select)
        };
        let platform = odin_registry::PLATFORM_IMAGE.to_owned();
        let mut values = toml::Table::new();
        let strings: &[(&str, Option<&String>)] = &[
            ("description", answers.description.as_ref()),
            (
                "image_reference",
                if script {
                    answers.image_reference.as_ref()
                } else {
                    Some(&platform)
                },
            ),
            ("launcher", agent_fact(|facts| Some(&facts.launcher))),
            ("browser", agent_fact(|facts| Some(&facts.browser))),
            ("supervisor", agent_fact(|facts| Some(&facts.supervisor))),
            ("playwright", agent_fact(|facts| Some(&facts.playwright))),
            ("seat", answers.seat.as_ref()),
            ("project", answers.project.as_ref()),
            ("gateway_lane", answers.gateway_lane.as_ref()),
            ("xvfb", agent_fact(|facts| Some(&facts.xvfb))),
            ("screen", answers.screen.as_ref().filter(|_| !script)),
            (
                "state_path",
                answers
                    .state_path
                    .as_ref()
                    .or(fact(|facts| facts.state_path.as_ref())),
            ),
            ("storage", answers.state_storage.as_ref()),
            (
                "export_pod_path",
                answers
                    .export_pod_path
                    .as_ref()
                    .or(fact(|facts| facts.export_pod_path.as_ref())),
            ),
            (
                "export_host_folder",
                answers
                    .export_host_folder
                    .as_ref()
                    .or(fact(|facts| facts.export_host_folder.as_ref())),
            ),
            ("brief_text", answers.brief_text.as_ref()),
            ("memory_namespace", answers.memory_namespace.as_ref()),
            ("harness", answers.harness.as_ref()),
            ("mode", answers.mode.as_ref()),
            ("monitoring_progress", answers.progress.as_ref()),
        ];
        for (name, value) in strings {
            if let Some(value) = value {
                values.insert((*name).to_owned(), toml::Value::from(value.as_str()));
            }
        }
        if let Some(enabled) = answers.enabled {
            values.insert("enabled".to_owned(), toml::Value::from(enabled));
        }
        if let Some(stream) = answers.stream.filter(|_| !script) {
            values.insert("stream".to_owned(), toml::Value::from(stream));
        }
        let integers = [
            ("gpu_count", answers.gpu_count),
            (
                "monitoring_cadence_seconds",
                answers.monitoring_cadence_seconds,
            ),
            ("monitoring_stall_seconds", answers.stall_seconds),
        ];
        for (name, value) in integers {
            if let Some(value) = value {
                values.insert(
                    name.to_owned(),
                    toml::Value::from(i64::try_from(value).unwrap_or(i64::MAX)),
                );
            }
        }
        let string_arrays = [
            ("script_command", answers.script_command.as_deref()),
            ("placement", answers.placement.as_deref()),
            ("tools", answers.tools.as_deref()),
        ];
        for (name, items) in string_arrays {
            if let Some(items) = items {
                values.insert(
                    name.to_owned(),
                    toml::Value::Array(
                        items
                            .iter()
                            .map(|item| toml::Value::from(item.as_str()))
                            .collect(),
                    ),
                );
            }
        }
        if let Some(recovery) = answers
            .recovery
            .as_ref()
            .and_then(|recovery| toml::Value::try_from(recovery).ok())
        {
            values.insert("monitoring_recovery".to_owned(), recovery);
        }
        if let Some(watchdogs) = answers.watchdogs.as_deref() {
            // JSON objects become TOML tables verbatim; anything the alert
            // grammar refuses is the skeleton compiler's typed issue.
            let tables: Vec<toml::Value> = watchdogs
                .iter()
                .filter_map(|watchdog| toml::Value::try_from(watchdog).ok())
                .collect();
            values.insert("watchdogs".to_owned(), toml::Value::Array(tables));
        }
        if let Some(deadline) = answers.deadline_seconds {
            // Beyond i64 is beyond the skeleton's declared range anyway; the
            // strict compiler refuses the saturated value with its bound.
            values.insert(
                "deadline_seconds".to_owned(),
                toml::Value::from(i64::try_from(deadline).unwrap_or(i64::MAX)),
            );
        }
        if let Some(hosts) = answers.allow_hosts.as_deref() {
            values.insert(
                "allow_hosts".to_owned(),
                toml::Value::Array(
                    hosts
                        .iter()
                        .map(|host| toml::Value::from(host.as_str()))
                        .collect(),
                ),
            );
        }
        values
    }

    /// Report enabled gateway chat routes and alternatives, not session lanes;
    /// alternatives are offers and never silently replace the selected route.
    fn lane_availability(
        &self,
        objects: &[odin_registry::RegistryObject],
        lane_id: &str,
    ) -> Option<odin_hermes::runtime::WorkloadLaneAvailability> {
        odin_domain::LaneId::new(lane_id).ok()?;
        let routes = declared_gateway_routes(objects);
        let own = routes.iter().find(|(lane, _, _)| lane == lane_id);
        Some(odin_hermes::runtime::WorkloadLaneAvailability {
            lane: lane_id.to_owned(),
            available: own.is_some(),
            provider: own.map(|(_, provider, _)| provider.clone()),
            model: own.map(|(_, _, model)| model.clone()),
            declared_alternatives: routes
                .into_iter()
                .map(|(lane, _, _)| lane)
                .filter(|candidate| candidate != lane_id)
                .collect(),
        })
    }

    fn seat_limits(
        objects: &[odin_registry::RegistryObject],
        seat_id: &str,
    ) -> Option<odin_hermes::runtime::WorkloadSeatLimits> {
        let seat = objects.iter().find(|object| {
            object.kind() == odin_registry::RegistryKind::Seat && object.id == seat_id
        })?;
        let odin_registry::ObjectConfig::Seat(seat_config) = &seat.config else {
            return None;
        };
        Some(odin_hermes::runtime::WorkloadSeatLimits {
            seat: seat_id.to_owned(),
            max_sessions: seat_config.limits.max_sessions,
            max_parallel_runs: seat_config.limits.max_parallel_runs,
        })
    }

    /// Return valid project memory namespaces within the seat's brain scope,
    /// or None if either declaration is absent.
    fn admitted_memory_namespaces(
        objects: &[odin_registry::RegistryObject],
        seat_id: &str,
        project_id: &str,
    ) -> Option<Vec<String>> {
        let seat = objects.iter().find_map(|object| match &object.config {
            odin_registry::ObjectConfig::Seat(seat) if object.id == seat_id => Some(seat),
            _ => None,
        })?;
        let project = objects.iter().find_map(|object| match &object.config {
            odin_registry::ObjectConfig::Project(project) if object.id == project_id => {
                Some(project)
            }
            _ => None,
        })?;
        Some(
            project
                .memory_namespaces
                .iter()
                .map(|namespace| namespace.as_str())
                .filter(|namespace| odin_registry::schema::valid_memory_namespace(namespace))
                .filter(|namespace| {
                    seat.brain_scope
                        .iter()
                        .any(|scope| scope.as_str() == *namespace)
                })
                .map(str::to_owned)
                .collect(),
        )
    }

    /// Verify the exact revision's receipt, then adopt its publication before returning.
    fn already_published_receipt(
        &self,
        profile_id: &str,
        request: &odin_hermes::runtime::WorkloadPublishRequest,
        digest: &str,
    ) -> Result<odin_hermes::runtime::WorkloadPublication, Failure> {
        let (_active, receipt) = self.exact_replay_proof(profile_id, request, digest)?;
        // Adoption is idempotent: an identical active publication keeps the
        // pin; a lagging pin catches up. Either way the same handle the
        // launch seams read names the profile before this returns.
        let adopted = self
            .pin
            .reload()
            .map_err(|error| Failure::PublicationRefused {
                reason: format!("published snapshot adoption failed: {error}"),
            })?;
        Ok(odin_hermes::runtime::WorkloadPublication {
            profile_id: profile_id.to_owned(),
            destination: Self::destination(profile_id),
            declaration_digest: digest.to_owned(),
            published_revision: receipt.revision,
            pinned_revision: adopted.revision,
            commit: receipt.commit,
            outcome: "unchanged".to_owned(),
        })
    }

    /// Read the requested revision and verify its profile and digest without adopting it.
    /// Return the snapshot and receipt for completion; unrelated content invalidates the scope.
    fn exact_replay_proof(
        &self,
        profile_id: &str,
        request: &odin_hermes::runtime::WorkloadPublishRequest,
        digest: &str,
    ) -> Result<(odin_registry::Snapshot, odin_registry::PublicationReceipt), Failure> {
        let store = odin_registry::SnapshotStore::new(&self.snapshot_store);
        let fallback_next = Self::next_revision(Some(self.snapshot().as_ref()));
        let (active, receipt) = store
            .publication_at(request.expected_registry_revision)
            .map_err(|_| match fallback_next {
                Ok(next) => Failure::StaleRevision {
                    bound: request.expected_registry_revision,
                    next,
                },
                Err(exhausted) => exhausted,
            })?;
        let existing = active.objects.iter().find(|object| {
            object.kind() == odin_registry::RegistryKind::Workload && object.id == profile_id
        });
        let Some(existing) = existing else {
            return Err(Failure::StaleRevision {
                bound: request.expected_registry_revision,
                next: Self::next_revision(Some(&active))?,
            });
        };
        let odin_registry::ObjectConfig::Workload(profile) = &existing.config else {
            return Err(Failure::StaleRevision {
                bound: request.expected_registry_revision,
                next: Self::next_revision(Some(&active))?,
            });
        };
        let bytes =
            toml::to_string(profile.as_ref()).map_err(|error| Failure::PublicationRefused {
                reason: format!("canonical declaration serialization failed: {error}"),
            })?;
        let existing_digest = odin_domain::Digest::hash(bytes.as_bytes()).to_string();
        if existing_digest != digest {
            return Err(Failure::DigestMismatch {
                approved: digest.to_owned(),
                compiled: existing_digest,
            });
        }
        Ok((active, receipt))
    }

    /// Commits the already-installed destination after a crash between the
    /// private install and the commit. Only the exact destination may be
    /// dirty or staged; anything else refuses instead of being swept.
    fn resume_commit(
        worktree: &std::path::Path,
        relative: &str,
        profile_id: &str,
        expected_digest: &str,
    ) -> Result<String, Failure> {
        let foreign = Self::foreign_dirty_lines(worktree, relative)?;
        if !foreign.is_empty() {
            return Err(Failure::PublicationRefused {
                reason: format!(
                    "authoring worktree carries unrelated uncommitted changes: {foreign:?}"
                ),
            });
        }
        // Stage exactly the installed destination: the pathspec commit
        // below includes only this path, so concurrently staged foreign
        // work still cannot enter — but a crash-window install (a plain
        // file git never indexed) becomes the commit's sole content.
        git(worktree, &["add", "--", relative])
            .map_err(|reason| Failure::WorktreeInvalid { reason })?;
        git_commit(
            worktree,
            profile_id,
            "resume",
            std::slice::from_ref(&relative.to_owned()),
            expected_digest,
        )
    }
}
