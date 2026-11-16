//! Trusted host verification result for a campaign stage.

use std::collections::BTreeMap;
use std::sync::Arc;

/// The identity proved from the staged tar and the rewritten, pinned manifest.
pub(crate) struct VerifiedStage {
    pub campaign: String,
    pub rung: String,
    pub point: BTreeMap<String, f64>,
    pub manifest: Vec<u8>,
    pub sha256: String,
}

pub(crate) type StageVerifier =
    Arc<dyn Fn(&str, &str, &[u8]) -> Result<VerifiedStage, String> + Send + Sync>;
