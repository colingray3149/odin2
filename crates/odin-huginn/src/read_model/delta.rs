use odin_domain::huginn::{ObjectDelta, Revision};
use serde_json::Value;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeltaBatch {
    pub from_revision: Revision,
    pub to_revision: Revision,
    pub deltas: Vec<ObjectDelta>,
}

pub fn apply_merge_patch(target: &mut Value, patch: &Value) {
    let Value::Object(patch) = patch else {
        *target = patch.clone();
        return;
    };
    if !target.is_object() {
        *target = Value::Object(Default::default());
    }
    let target = target.as_object_mut().expect("target was made an object");
    for (key, value) in patch {
        if value.is_null() {
            target.remove(key);
        } else {
            apply_merge_patch(target.entry(key.clone()).or_insert(Value::Null), value);
        }
    }
}
