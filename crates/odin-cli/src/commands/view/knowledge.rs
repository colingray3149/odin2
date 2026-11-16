//! The Brain tab's bridge side: the `knowledge` line from the Status snapshot. F5 needs nothing here: the view sends the
//! existing `features` request, which wakes the pump that re-reads status.json.

use odin_domain::huginn as live;
use serde_json::{json, Value};

/// The Status id odind publishes `~/knowledge/_system/status.json` under.
const KNOWLEDGE_STATUS: &str = "knowledge";

/// The Brain object as one `knowledge` line, when the Status snapshot holds it.
pub(super) fn knowledge_line(objects: &[live::ObjectSnapshot]) -> Option<Value> {
    objects
        .iter()
        .find(|object| {
            object.object.kind == live::ObjectKind::Status && object.object.id == KNOWLEDGE_STATUS
        })
        .map(|object| json!({ "t": "knowledge", "value": object.value }))
}
