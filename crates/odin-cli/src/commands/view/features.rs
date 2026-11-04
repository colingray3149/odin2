//! The Capabilities tab's bridge side: the `features` line from the Status snapshot, and F5's refresh.

use super::{cause, emit, Bridge};
use odin_domain::huginn as live;
use serde_json::{json, Value};
use std::time::Duration;

/// A features refresh waits for the authority's evaluation, which may take up to its own 30 s bound; 35 s
/// keeps a finished-but-slow answer from reading as a lost link.
const FEATURES_BOUND: Duration = Duration::from_secs(35);
/// The Status id odind publishes the Capabilities evaluation under.
const FEATURES_STATUS: &str = "features";

impl Bridge {
    /// F5 on the Capabilities tab: the authority evaluates now, then the snapshot is read again and sent. A
    /// refusal or a missed evaluation goes out as a note; the view keeps its last value under it.
    pub(super) async fn refresh_features(&mut self) {
        let refreshed = tokio::time::timeout(FEATURES_BOUND, self.client.features_refresh()).await;
        let failure = match refreshed {
            Ok(Ok(_)) => None,
            Ok(Err(error)) => Some(cause(&error)),
            Err(_) => Some(format!(
                "no evaluation within {} s",
                FEATURES_BOUND.as_secs()
            )),
        };
        if let Some(note) = failure {
            emit(&json!({ "t": "features", "note": note }));
            return;
        }
        let Some(objects) = self.snapshot_all(live::ObjectKind::Status).await else {
            emit(
                &json!({ "t": "features", "note": "the capabilities could not be read after the refresh" }),
            );
            return;
        };
        match features_line(&objects) {
            Some(line) => {
                self.features = line.to_string();
                emit(&line);
            }
            None => emit(&json!({ "t": "features", "note": "no capabilities are evaluated yet" })),
        }
    }
}

/// The Capabilities object as one `features` line, when the Status snapshot holds it.
pub(super) fn features_line(objects: &[live::ObjectSnapshot]) -> Option<Value> {
    objects
        .iter()
        .find(|object| {
            object.object.kind == live::ObjectKind::Status && object.object.id == FEATURES_STATUS
        })
        .map(|object| json!({ "t": "features", "value": object.value }))
}
