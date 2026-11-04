//! Sessions retain their publication's contracts and policies across later publications.
//! Tokens without a revision must match exactly one retained publication; there is no default revision.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use odin_domain::{CapabilityId, Digest, LaneId, ProjectId, SeatId, SeatToken, SessionId};
use odin_kernel::CapabilityContract;

use super::SeatOperationPolicy;

/// Bounded per-revision memo inside [`super::HostToolOperations`]: entries
/// are pure recompositions of already-durable snapshots, so eviction is
/// always safe — a miss recomposes the generation again.
pub(super) const GENERATION_MEMO_CAP: usize = 32;

/// The exact operation material of one retained publication revision:
/// the contracts the generation admits, its admission digest, and every
/// served (seat, lane) policy binding derived from that revision's
/// objects through the host's pure composition functions.
#[derive(Clone)]
pub struct RevisionMaterial {
    pub revision: u64,
    pub contracts: Arc<BTreeMap<CapabilityId, CapabilityContract>>,
    /// `admission_digest(&contracts, revision)` — the digest every token
    /// of this generation binds.
    pub admission_digest: Digest,
    pub seat_operation_bindings: BTreeMap<(SeatId, LaneId), SeatOperationPolicy>,
    pub session_lanes: BTreeMap<(SeatId, ProjectId), LaneId>,
    pub tool_index: BTreeMap<String, CapabilityId>,
    pub contract_adapters: BTreeSet<String>,
    /// Operator-gated capabilities whose approval the kernel decides from the
    /// declarations (`approval_decider = "declaration"`) instead of the owner.
    pub declaration_decided: BTreeSet<CapabilityId>,
    /// Conversation seats accept escalations from workers without creating nested workers.
    pub escalation_targets: BTreeSet<SeatId>,
}

/// Missing composition digests permit only an exact revision match.
pub(crate) fn same_composition(source: &dyn RevisionMaterialSource, left: u64, right: u64) -> bool {
    if left == right {
        return true;
    }
    match (
        source.composition_digest_at(left),
        source.composition_digest_at(right),
    ) {
        (Ok(left), Ok(right)) => left == right,
        (left, right) => {
            for error in [left.err(), right.err()].into_iter().flatten() {
                tracing::warn!("odin-omp: composition digest unavailable: {error}");
            }
            false
        }
    }
}

/// Search older revisions for retained sessions and newer ones for publications since startup.
const EQUIVALENCE_BELOW: u64 = 32;
const EQUIVALENCE_ABOVE: u64 = 512;

/// Admits digests from revisions whose composition matches the catalog's revision.
/// Publications are immutable, so per-revision results can be cached.
pub struct CompositionEquivalence {
    admission_revision: u64,
    contracts: Arc<BTreeMap<CapabilityId, CapabilityContract>>,
    source: Arc<dyn RevisionMaterialSource>,
    /// revision → admission digest when it composes like the admission
    /// revision, else `None`. A raced fill writes the same digest.
    checked: std::sync::Mutex<BTreeMap<u64, Option<Digest>>>,
}

impl CompositionEquivalence {
    pub fn new(
        admission_revision: u64,
        contracts: Arc<BTreeMap<CapabilityId, CapabilityContract>>,
        source: Arc<dyn RevisionMaterialSource>,
    ) -> Self {
        Self {
            admission_revision,
            contracts,
            source,
            checked: std::sync::Mutex::new(BTreeMap::new()),
        }
    }

    fn checked(&self) -> std::sync::MutexGuard<'_, BTreeMap<u64, Option<Digest>>> {
        self.checked
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The admission digest of `revision` when it composes like `base`; `Err` when its
    /// publication is pruned or not published yet.
    fn admission_digest_if_identical(
        &self,
        base: odin_registry::CompositionDigest,
        revision: u64,
    ) -> Result<Option<Digest>, String> {
        if let Some(entry) = self.checked().get(&revision).copied() {
            return Ok(entry);
        }
        let entry = if self.source.composition_digest_at(revision)? == base {
            let revision_i64 = i64::try_from(revision)
                .map_err(|_| format!("revision {revision} exceeds the admission range"))?;
            Some(
                super::admission_digest(&self.contracts, revision_i64)
                    .map_err(|error| error.to_string())?,
            )
        } else {
            None
        };
        self.checked().insert(revision, entry);
        Ok(entry)
    }

    /// Whether `digest` is the admission digest of a revision that composes like the
    /// admission revision: older ones for sessions kept across a restart, newer ones
    /// for publications since startup.
    pub fn equivalent(&self, digest: Digest) -> bool {
        let base = match self.source.composition_digest_at(self.admission_revision) {
            Ok(base) => base,
            Err(error) => {
                tracing::warn!(
                    "odin-omp: admission equivalence unavailable admission_revision={} error={error}",
                    self.admission_revision
                );
                return false;
            }
        };
        let identical = |revision: u64| -> Result<bool, String> {
            Ok(self.admission_digest_if_identical(base, revision)? == Some(digest))
        };
        let admitted = |revision: u64| {
            tracing::info!(
                "odin-omp: admission digest of composition-identical revision={revision} admitted admission_revision={}",
                self.admission_revision
            );
            true
        };
        let low = self
            .admission_revision
            .saturating_sub(EQUIVALENCE_BELOW)
            .max(1);
        // A pruned publication below proves nothing; keep looking.
        for revision in (low..self.admission_revision).rev() {
            if identical(revision) == Ok(true) {
                return admitted(revision);
            }
        }
        for revision in self.admission_revision + 1..=self.admission_revision + EQUIVALENCE_ABOVE {
            match identical(revision) {
                Ok(true) => return admitted(revision),
                Ok(false) => {}
                // Not published yet: nothing newer exists.
                Err(_) => break,
            }
        }
        false
    }
}

/// The host-injected recomposition seam: derives one retained publication's
/// exact operation material through the pure composition functions the
/// provisioning path itself uses. Implementations never cache here — the
/// operation stack owns the bounded memo.
pub trait RevisionMaterialSource: Send + Sync {
    /// Recomposes the exact material of one retained publication.
    /// Unknown or pruned revisions fail typed.
    fn material_at(&self, revision: u64) -> Result<RevisionMaterial, String>;

    /// Resolves one legacy (pre-revision-claim) token to its publication:
    /// the unique retained revision whose material matches the token's
    /// signed digests. Zero or multiple matches refuse typed.
    fn resolve_legacy(&self, token: &SeatToken) -> Result<u64, String>;

    /// Equal digests mean identical seat, brain, and binding composition.
    /// Without a digest, only an exact revision match is accepted.
    fn composition_digest_at(
        &self,
        revision: u64,
    ) -> Result<odin_registry::CompositionDigest, String> {
        Err(format!(
            "this host reports no composition digest for revision {revision}"
        ))
    }
}

/// An existing session requires the token's revision to match its persisted revision.
/// A new session adopts the token's revision; if neither has one, resolve from retained publications.
pub fn resolve_session_generation(
    session: &SessionId,
    token: &SeatToken,
    manifest_revision: Option<u64>,
    source: &dyn RevisionMaterialSource,
) -> Result<u64, String> {
    match (manifest_revision, token.served_revision) {
        (Some(bound), Some(claim)) if claim == bound => Ok(bound),
        (Some(bound), Some(claim)) => Err(format!(
            "session {session} is bound to publication {bound} but its installed token claims \
             generation {claim}; the bound generation is frozen — re-open the session under the \
             current revision"
        )),
        (Some(_), None) => Err(format!(
            "session {session} was opened revision-bound but its installed token predates \
             revision binding; re-open the session under the current revision"
        )),
        (None, Some(claim)) => Ok(claim),
        (None, None) => source.resolve_legacy(token).map_err(|detail| {
            format!(
                "session {session} carries legacy authority that predates revision binding \
                 and no retained publication proves its generation: {detail}; re-open the \
                 session under the current revision"
            )
        }),
    }
}

#[cfg(test)]
mod composition_tests {
    use super::{RevisionMaterial, RevisionMaterialSource};
    use odin_domain::SeatToken;
    use odin_registry::CompositionDigest;

    /// Revisions 1 and 2 compose identically (a routine between them);
    /// revision 3 changed a seat; revision 9 is pruned.
    struct Digests;

    impl RevisionMaterialSource for Digests {
        fn material_at(&self, revision: u64) -> Result<RevisionMaterial, String> {
            Err(format!("no material for {revision}"))
        }

        fn resolve_legacy(&self, _token: &SeatToken) -> Result<u64, String> {
            Err("none".to_owned())
        }

        fn composition_digest_at(&self, revision: u64) -> Result<CompositionDigest, String> {
            match revision {
                1 | 2 => Ok(CompositionDigest::from_bytes([1; 32])),
                3 => Ok(CompositionDigest::from_bytes([3; 32])),
                _ => Err(format!("publication {revision} is pruned")),
            }
        }
    }

    #[test]
    fn the_catalog_admits_composition_identical_admission_digests() {
        use crate::host_tools::operations::{
            admission_digest, CompositionEquivalence, DeclaredOperationCatalog,
        };
        use odin_kernel::{AdmittedCapability, OperationCatalog};
        use std::collections::{BTreeMap, BTreeSet};
        use std::sync::Arc;

        let contracts = Arc::new(BTreeMap::new());
        let at = |revision| admission_digest(&contracts, revision).expect("digest");
        let kept = CompositionEquivalence::new(2, Arc::clone(&contracts), Arc::new(Digests));
        assert!(kept.equivalent(at(1)), "the kept vehicle's revision below");
        assert!(
            !kept.equivalent(at(3)),
            "a seat change composes differently"
        );
        let started = CompositionEquivalence::new(1, Arc::clone(&contracts), Arc::new(Digests));
        assert!(started.equivalent(at(2)), "a routine published since start");
        assert!(!started.equivalent(at(3)));

        // Without composition equivalence, only the exact admission digest is admitted.
        let registry = Arc::new(crate::host_tools::HostToolRegistry::new());
        let catalog = |equivalent: bool| {
            let catalog = DeclaredOperationCatalog::from_contracts(
                &contracts,
                2,
                at(2),
                Arc::clone(&registry),
                &BTreeSet::new(),
            )
            .expect("catalog");
            if equivalent {
                catalog.with_equivalence(Arc::new(CompositionEquivalence::new(
                    2,
                    Arc::clone(&contracts),
                    Arc::new(Digests),
                )))
            } else {
                catalog
            }
        };
        let admitted = AdmittedCapability {
            contract:
                crate::host_tools::operations::production_operation_dispatch::fixture::contract(
                    "fixture.equivalence",
                    "fixture_equivalence",
                    "fixture.handler",
                    "fixture.extract",
                    odin_domain::EffectClass::R1,
                ),
            snapshot_revision: 2,
            snapshot_digest: at(2),
        };
        assert!(!catalog(false).admits_policy_digest(&admitted, at(1)));
        assert!(catalog(true).admits_policy_digest(&admitted, at(1)));
        assert!(catalog(true).admits_policy_digest(&admitted, at(2)));
        assert!(!catalog(true).admits_policy_digest(&admitted, at(3)));
    }
}
