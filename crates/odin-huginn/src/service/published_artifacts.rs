use std::time::Duration;

use odin_domain::huginn::{ArtifactRef, BrowserSessionId, HuginnProtocolError};
use serde::{Deserialize, Serialize};

use crate::config::{CONNECTIONS_CEILING, SESSIONS_CEILING};
use crate::streams::BoundedMultiplexer;

mod pointer;
mod publication;
#[cfg(test)]
mod render_reopen_tests;
mod retirement;
mod store;
#[cfg(test)]
mod tests;

pub use store::FsPublishedArtifactStore;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublishedArtifactRecord {
    artifact: ArtifactRef,
    payload_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BrowserArtifactRetirement {
    browser_session: BrowserSessionId,
    kind: BrowserArtifactKind,
    record: PublishedArtifactRecord,
}

/// Browser payload class persisted by [`FsPublishedArtifactStore`].
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BrowserArtifactKind {
    Frame,
    Screenshot,
    Download,
    Timeline,
}

const BROWSER_FRAME_RETENTION_CAPACITY: usize = 1;
const BROWSER_TIMELINE_RETENTION_CAPACITY: usize = 1;
const BROWSER_RETIREMENT_COMMAND_CAPACITY: usize = 1;
/// Worst distinct delivered-frame lease window across the most concurrent connections a
/// configuration may declare.
const BROWSER_DELIVERED_LEASE_RETIREMENT_WINDOW: usize =
    CONNECTIONS_CEILING * BoundedMultiplexer::MAX_DELIVERED_LEASE_WINDOW;
/// Room for one current frame and one timeline artifact in every session a configuration may
/// declare.
const BROWSER_CURRENT_TIMELINE_RETIREMENT_MARGIN: usize =
    SESSIONS_CEILING * (BROWSER_FRAME_RETENTION_CAPACITY + BROWSER_TIMELINE_RETENTION_CAPACITY);
/// Store-global pending-retirement ceiling. This remains fixed and strictly
/// above every delivered-frame lease plus current/timeline turnover, avoiding
/// circular saturation before another producer frame can release a lease.
const BROWSER_RETIREMENT_BACKLOG_CAPACITY: usize = 4096;
const _: () = assert!(
    BROWSER_RETIREMENT_BACKLOG_CAPACITY
        > BROWSER_DELIVERED_LEASE_RETIREMENT_WINDOW + BROWSER_CURRENT_TIMELINE_RETIREMENT_MARGIN
);
const BROWSER_RETIREMENT_FLUSH_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a flush waits before retrying a retirement queue that is full.
const FULL_QUEUE_RETRY: Duration = Duration::from_millis(1);

fn browser_retirement_resource_limit() -> HuginnProtocolError {
    HuginnProtocolError::ResourceLimit {
        limit: "browserArtifactRetirements".to_owned(),
    }
}

fn is_browser_retirement_resource_limit(error: &HuginnProtocolError) -> bool {
    matches!(
        error,
        HuginnProtocolError::ResourceLimit { limit }
            if limit == "browserArtifactRetirements"
    )
}
