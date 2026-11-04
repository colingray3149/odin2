//! Router construction and dispatch: operator authority injection with a sealed artifact
//! root, canonical parse before any resolver, and the ledger lock.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use odin_atlas::AtlasScope;
use odin_brain::service::BrainService;
use odin_confined_fs::Capability;
use odin_domain::SeatId;
use odin_ledger::Ledger;

use super::ScopedUriRouter;
use super::{UriContext, UriError, UriResult, UriScheme, MAX_ARTIFACT_READ_BOUND};
use crate::host_tools::atlas_query::SharedAtlas;

impl ScopedUriRouter {
    /// Validates the read limit and seals the artifact root at construction.
    /// Each read rechecks the root's identity, refusing replacement rather than reading an orphaned tree.
    pub fn new(
        ledger: Arc<Mutex<Ledger>>,
        atlas: SharedAtlas,
        allowed_atlas_scope: AtlasScope,
        artifact_root: PathBuf,
        max_artifact_bytes: u64,
        brains: BTreeMap<SeatId, Arc<BrainService>>,
    ) -> Result<Self, UriError> {
        if max_artifact_bytes == 0 || max_artifact_bytes > MAX_ARTIFACT_READ_BOUND {
            return Err(UriError::ConfigurationRejected {
                detail: format!(
                    "artifact read bound {max_artifact_bytes} is outside 1..={MAX_ARTIFACT_READ_BOUND}"
                ),
            });
        }
        let sealed =
            Capability::seal(&artifact_root).map_err(|error| UriError::ConfigurationRejected {
                detail: format!(
                    "artifact root {} could not be sealed: {error}",
                    artifact_root.display()
                ),
            })?;
        Ok(Self {
            ledger,
            atlas,
            allowed_atlas_scope: Arc::new(allowed_atlas_scope),
            artifact_root: Arc::new(sealed),
            artifact_root_path: Arc::new(artifact_root),
            max_artifact_bytes,
            brains: Arc::new(brains),
        })
    }

    /// Resolves a canonical read-only URI against the bound scope.
    pub fn resolve(&self, context: &UriContext, url: &str) -> Result<UriResult, UriError> {
        let request = Self::parse(url)?;
        match request.scheme {
            UriScheme::Atlas => self.resolve_atlas(request),
            UriScheme::Brain => self.resolve_brain(context, request),
            UriScheme::Lane => {
                let ledger = self.lock_ledger(&request.url)?;
                self.resolve_lane(&ledger, context, request)
            }
            UriScheme::Run => {
                let ledger = self.lock_ledger(&request.url)?;
                self.resolve_run(&ledger, context, request)
            }
            UriScheme::Artifact => self.resolve_artifact(context, request),
            UriScheme::Incident => {
                let ledger = self.lock_ledger(&request.url)?;
                self.resolve_incident(&ledger, context, request)
            }
            UriScheme::Approval => {
                let ledger = self.lock_ledger(&request.url)?;
                self.resolve_approval(&ledger, context, request)
            }
        }
    }

    pub(super) fn lock_ledger(&self, url: &str) -> Result<MutexGuard<'_, Ledger>, UriError> {
        self.ledger.lock().map_err(|poisoned| UriError::Storage {
            detail: format!("ledger mutex poisoned for {url}: {poisoned}"),
        })
    }
}
