//! Narrow the kernel's child-effect grant for this driver.
//! Neither a session identifier nor a project scope can mint this authority.
use odin_hermes::runtime::claude::ClaudeSessionRecord;
use odin_kernel::operation::{ChildEffectGrant, ChildEffectRequest, PreparedEffect, Target};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    session: String,
    project: String,
    branch: String,
}

const KIND: &str = "claude.git-publication";

pub(super) fn mint(
    effect: &PreparedEffect,
    session: &ClaudeSessionRecord,
    branch: &str,
) -> Result<ChildEffectGrant, String> {
    if effect.contract().id.as_str() != "claude.open" {
        return Err("publication custody requires the prepared claude.open effect".into());
    }
    let original = &effect.payload().arguments;
    if original.get("project").and_then(Value::as_str) != Some(session.request.project.as_str()) {
        return Err("publication project differs from the admitted open payload".into());
    }
    let original_name = original.get("name").filter(|value| !value.is_null());
    if original_name.and_then(Value::as_str) != session.request.name.as_deref()
        || original_name.is_some_and(|value| !value.is_string())
    {
        return Err("publication name differs from the admitted open payload".into());
    }
    let id = uuid::Uuid::parse_str(&session.session).map_err(|error| error.to_string())?;
    if id.is_nil() || id.to_string() != session.session {
        return Err("publication session is not a canonical non-nil UUID".into());
    }
    let name = session.request.name.as_deref().unwrap_or(&session.session);
    if name.is_empty()
        || name.len() > 80
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || branch != format!("claude/{name}")
    {
        return Err("publication branch differs from the exact admitted Claude name".into());
    }
    let binding = Binding {
        session: session.session.clone(),
        project: session.request.project.clone(),
        branch: format!("refs/heads/{branch}"),
    };
    let target = Target {
        kind: KIND.into(),
        id: serde_json::to_string(&binding).map_err(|error| error.to_string())?,
    };
    ChildEffectGrant::from_prepared(effect, target).map_err(|error| error.to_string())
}

fn validate(target: &Target, candidate: &Value) -> Result<String, String> {
    if target.kind != KIND {
        return Err("child custody is not Claude publication authority".into());
    }
    let binding: Binding = serde_json::from_str(&target.id).map_err(|error| error.to_string())?;
    for (key, expected) in [
        ("session", binding.session.as_str()),
        ("project", binding.project.as_str()),
        ("branch", binding.branch.as_str()),
    ] {
        if candidate.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("publication {key} differs from immutable custody"));
        }
    }
    let nonce = candidate
        .get("request_id")
        .and_then(Value::as_str)
        .ok_or("publication request has no identity")?;
    if nonce.len() != 32
        || !nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("publication request identity is invalid".into());
    }
    match candidate.get("kind").and_then(Value::as_str) {
        Some("push") => {
            let commit = candidate
                .get("commit")
                .and_then(Value::as_str)
                .ok_or("publication commit missing")?;
            if !matches!(commit.len(), 40 | 64) || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("publication commit is not an exact object identity".into());
            }
            if !matches!(
                candidate.get("size").and_then(Value::as_u64),
                Some(1..=33_554_432)
            ) {
                return Err("publication bundle size is outside its declared bound".into());
            }
        }
        Some("list")
            if candidate.get("commit") == Some(&Value::Null)
                && candidate.get("size").and_then(Value::as_u64) == Some(0) => {}
        _ => return Err("publication request kind or observation payload is invalid".into()),
    }
    let digest = candidate
        .get("request_digest")
        .and_then(Value::as_str)
        .ok_or("publication request digest missing")?;
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("publication request digest is invalid".into());
    }
    // Identity depends on the immutable session and nonce, NOT request contents:
    // reusing a nonce with a different commit must conflict, never become new work.
    Ok(format!("claude-publish-{}-{nonce}", binding.session))
}

pub(super) fn request(
    grant: &ChildEffectGrant,
    candidate: &Value,
) -> Result<ChildEffectRequest, String> {
    let correlation = validate(grant.target(), candidate)?;
    Ok(ChildEffectRequest {
        correlation_id: odin_types::CorrelationId::new(&correlation)
            .map_err(|error| error.to_string())?,
        target: grant.target().clone(),
        arguments: candidate.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> (Target, Value) {
        let binding = Binding {
            session: "a6e1e724-60e9-4818-bc76-27077f5fb785".into(),
            project: "surtr".into(),
            branch: "refs/heads/claude/work".into(),
        };
        let target = Target {
            kind: KIND.into(),
            id: serde_json::to_string(&binding).unwrap(),
        };
        let candidate = json!({"kind":"push","session":binding.session,"project":binding.project,"branch":binding.branch,"request_id":"0123456789abcdef0123456789abcdef","commit":"a".repeat(40),"size":123,"request_digest":"b".repeat(64)});
        (target, candidate)
    }

    #[test]
    fn list_is_bound_observation_not_a_disguised_push() {
        let (target, mut candidate) = fixture();
        candidate["kind"] = json!("list");
        candidate["commit"] = Value::Null;
        candidate["size"] = json!(0);
        assert!(validate(&target, &candidate).is_ok());
        candidate["commit"] = json!("a".repeat(40));
        assert!(validate(&target, &candidate).is_err());
        candidate["kind"] = json!("delete");
        assert!(validate(&target, &candidate).is_err());
    }

    #[test]
    fn rejects_foreign_session_project_and_branch() {
        let (target, candidate) = fixture();
        assert!(validate(&target, &candidate).is_ok());
        for key in ["session", "project", "branch"] {
            let mut changed = candidate.clone();
            changed[key] = json!("foreign");
            assert!(validate(&target, &changed).is_err());
        }
    }

    #[test]
    fn rejects_missing_or_unbounded_effect_identity() {
        let (target, candidate) = fixture();
        for key in ["request_id", "commit", "size", "request_digest"] {
            let mut changed = candidate.clone();
            changed.as_object_mut().unwrap().remove(key);
            assert!(validate(&target, &changed).is_err());
        }
        let mut changed = candidate;
        changed["size"] = json!(33_554_433);
        assert!(validate(&target, &changed).is_err());
    }

    #[test]
    fn altered_commit_does_not_acquire_a_new_idempotency_identity() {
        let (target, candidate) = fixture();
        let mut changed = candidate.clone();
        changed["commit"] = json!("c".repeat(40));
        assert_eq!(
            validate(&target, &candidate).unwrap(),
            validate(&target, &changed).unwrap()
        );
    }
}
