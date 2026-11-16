//! Declared tool schemas compiled once, and the violations of one instance.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use odin_domain::knowledge::ToolSchema;
use odin_domain::Digest;
use serde_json::Value;

/// Compiled validators keyed by schema digest; a hit never serves a different schema.
static VALIDATORS: LazyLock<Mutex<HashMap<Digest, Arc<jsonschema::Validator>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Reported violations per instance; later ones only repeat the same defect.
const MAX_REPORTED: usize = 5;

/// The compiled validator of a declared schema; the error says why it does not compile.
pub fn validator(schema: &ToolSchema) -> Result<Arc<jsonschema::Validator>, String> {
    let digest = schema.digest();
    if let Some(validator) = VALIDATORS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&digest)
    {
        return Ok(Arc::clone(validator));
    }
    let validator = Arc::new(compile(schema.canonical_json())?);
    VALIDATORS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(digest, Arc::clone(&validator));
    Ok(validator)
}

pub fn compile(schema: &Value) -> Result<jsonschema::Validator, String> {
    jsonschema::options()
        .build(schema)
        .map_err(|error| error.to_string())
}

/// The violations of one instance, each at its location, joined for an error message;
/// `None` when it is valid.
pub fn violations(validator: &jsonschema::Validator, instance: &Value) -> Option<String> {
    let errors: Vec<String> = validator
        .iter_errors(instance)
        .take(MAX_REPORTED)
        .map(|error| match error.instance_path.to_string() {
            at if at.is_empty() => error.to_string(),
            at => format!("{at}: {error}"),
        })
        .collect();
    (!errors.is_empty()).then(|| errors.join("; "))
}
