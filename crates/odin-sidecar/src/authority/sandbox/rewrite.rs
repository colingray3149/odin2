//! ast-grep run as one Execute effect in the capsule bubble; the argv is fixed here, never caller-chosen.

use odin_kernel::ExecutorFault;
use odin_sidecar_protocol::{EFFECT_MAX_CAPTURE_BYTES, EVAL_SCRATCH_DIR};
use odin_strict_json::Value as Json;
use odin_types::OperationId;
use std::path::{Component, Path};

use super::bindings::{execute_params, optional_text, EffectorSandboxBinding};
use super::{require_string, strict_field};

/// The effector's per-stream capture ceiling.
const MAX_STDOUT_BYTES: u64 = EFFECT_MAX_CAPTURE_BYTES as u64;

/// Preview prints every match as one JSON line; apply writes every replacement.
pub(super) fn arguments(
    sandbox: &EffectorSandboxBinding,
    ast_grep: &Path,
    capsule_root: &Path,
    input: &Json,
    operation_id: Option<&OperationId>,
    deadline_ms: u64,
) -> Result<Json, ExecutorFault> {
    let pattern = require_string(input, "pattern")?;
    let lang = require_string(input, "lang")?;
    let rewrite = optional_text(input, "rewrite")?;
    let apply = matches!(strict_field(input, "apply"), Ok(Json::Bool(true)));
    let paths = paths(input)?;
    let program = if apply {
        ast_grep
    } else {
        Path::new("python3")
    };
    let mut argv = sandbox.bubble(capsule_root, program)?;
    if !apply {
        let operation = operation_id.map_or("preview", OperationId::as_str);
        argv.extend([
            "-c".to_owned(),
            include_str!("rewrite_preview.py").to_owned(),
            format!("{EVAL_SCRATCH_DIR}/rewrite-{operation}.jsonl"),
            ast_grep.display().to_string(),
        ]);
    }
    argv.extend(["run".to_owned(), "--pattern".to_owned(), pattern]);
    match (&rewrite, apply) {
        (None, true) => {
            return Err(ExecutorFault::Rejected {
                detail: "apply needs a rewrite".to_owned(),
            })
        }
        (Some(rewrite), _) => argv.extend(["--rewrite".to_owned(), rewrite.clone()]),
        (None, false) => {}
    }
    argv.extend(["--lang".to_owned(), lang]);
    if apply {
        argv.push("--update-all".to_owned());
    } else {
        argv.push("--json=stream".to_owned());
    }
    argv.extend(["--color".to_owned(), "never".to_owned(), "--".to_owned()]);
    argv.extend(paths);
    execute_params(argv, capsule_root, deadline_ms, MAX_STDOUT_BYTES)
}

/// Capsule-relative paths only; the whole capsule when none are given.
fn paths(input: &Json) -> Result<Vec<String>, ExecutorFault> {
    let items = match strict_field(input, "paths") {
        Err(_) | Ok(Json::Null) => return Ok(vec![".".to_owned()]),
        Ok(Json::Array(items)) if items.is_empty() => return Ok(vec![".".to_owned()]),
        Ok(Json::Array(items)) => items,
        Ok(other) => {
            return Err(ExecutorFault::Rejected {
                detail: format!("paths must be an array, got {}", other.kind()),
            })
        }
    };
    items
        .iter()
        .map(|item| {
            let Json::String(path) = item else {
                return Err(ExecutorFault::Rejected {
                    detail: format!("each path must be a string, got {}", item.kind()),
                });
            };
            capsule_relative(path)
        })
        .collect()
}

/// A path that stays inside the capsule: relative, no `..`, not empty.
pub(super) fn capsule_relative(path: &str) -> Result<String, ExecutorFault> {
    let inside = !path.is_empty()
        && Path::new(path)
            .components()
            .all(|part| matches!(part, Component::Normal(_) | Component::CurDir));
    if inside {
        Ok(path.to_owned())
    } else {
        Err(ExecutorFault::Rejected {
            detail: format!("path {path:?} is not a capsule-relative path"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEADLINE_MS: u64 = 100_000;

    fn sandbox() -> EffectorSandboxBinding {
        EffectorSandboxBinding::new(
            "/bin/bwrap".into(),
            "/cache".into(),
            "/tools/bin".to_owned(),
            None,
            None,
            None,
            None,
        )
        .expect("sandbox")
    }

    fn argv(input: &str) -> Result<Vec<String>, ExecutorFault> {
        let input = odin_strict_json::decode(input.as_bytes(), 4096).expect("input");
        let params = arguments(
            &sandbox(),
            Path::new("/ag"),
            Path::new("/capsule"),
            &input,
            None,
            DEADLINE_MS,
        )?;
        let Ok(Json::Array(items)) = strict_field(&params, "argv") else {
            panic!("argv");
        };
        Ok(items
            .iter()
            .map(|item| match item {
                Json::String(text) => text.clone(),
                other => panic!("{other:?}"),
            })
            .collect())
    }

    #[test]
    fn the_effector_runs_the_program_for_the_deadline_it_was_given() {
        let input = odin_strict_json::decode(br#"{"pattern":"f","lang":"rust"}"#, 4096).unwrap();
        let params = arguments(
            &sandbox(),
            Path::new("/ag"),
            Path::new("/capsule"),
            &input,
            None,
            83_333,
        )
        .unwrap();
        assert_eq!(
            strict_field(&params, "timeout_ms").unwrap(),
            &Json::Int(83_333)
        );
    }

    #[test]
    fn apply_without_rewrite_is_refused() {
        let refused = argv(r#"{"pattern":"f($A)","lang":"rust","apply":true}"#);
        assert!(
            matches!(refused, Err(ExecutorFault::Rejected { detail }) if detail == "apply needs a rewrite")
        );
    }

    #[test]
    fn absolute_or_parent_paths_are_refused() {
        for path in ["/etc", "../up", "src/../../x", ""] {
            let input = format!(r#"{{"pattern":"f","lang":"rust","paths":["{path}"]}}"#);
            let refused = argv(&input);
            assert!(
                matches!(&refused, Err(ExecutorFault::Rejected { detail }) if detail.contains(&format!("{path:?}"))),
                "{path}: {refused:?}"
            );
        }
    }
}
