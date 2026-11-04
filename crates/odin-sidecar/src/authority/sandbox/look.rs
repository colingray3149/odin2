//! The dev-server look as one Execute effect in the capsule bubble: the server and Chromium share
//! the bubble's private loopback. The argv is fixed here; screenshots land in the eval scratch.

use odin_kernel::ExecutorFault;
use odin_sidecar_protocol::EVAL_SCRATCH_DIR;
use odin_strict_json::Value as Json;
use odin_types::OperationId;
use std::path::Path;

use super::bindings::{execute_params, optional_text, EffectorSandboxBinding};
use super::rewrite::capsule_relative;
use super::{require_string, strict_field};

const MAX_STDOUT_BYTES: u64 = 256 * 1024;
const DEFAULT_WIDTHS: &str = "390,1280";
const DEFAULT_WAIT_MS: u64 = 30_000;

pub(super) fn arguments(
    sandbox: &EffectorSandboxBinding,
    look: &Path,
    capsule_root: &Path,
    input: &Json,
    operation_id: Option<&OperationId>,
    deadline_ms: u64,
) -> Result<Json, ExecutorFault> {
    let url = loopback_url(&require_string(input, "url")?)?;
    let source = match (
        optional_text(input, "start")?,
        optional_text(input, "serve")?,
    ) {
        (Some(start), None) => ["--start".to_owned(), start],
        (None, Some(serve)) => ["--serve".to_owned(), capsule_relative(&serve)?],
        _ => {
            return Err(ExecutorFault::Rejected {
                detail: "give exactly one of start (a dev command) or serve (a built directory)"
                    .to_owned(),
            })
        }
    };
    let widths = match strict_field(input, "widths") {
        Ok(Json::Array(items)) if !items.is_empty() => items
            .iter()
            .map(|item| match item {
                Json::UInt(width) => Ok(width.to_string()),
                Json::Int(width) if *width > 0 => Ok(width.to_string()),
                other => Err(ExecutorFault::Rejected {
                    detail: format!(
                        "each width must be a positive integer, got {}",
                        other.kind()
                    ),
                }),
            })
            .collect::<Result<Vec<_>, _>>()?
            .join(","),
        _ => DEFAULT_WIDTHS.to_owned(),
    };
    let wait_ms = match strict_field(input, "wait_ms") {
        Ok(Json::UInt(wait)) => *wait,
        _ => DEFAULT_WAIT_MS,
    };
    let out = match operation_id {
        Some(operation) => format!("{EVAL_SCRATCH_DIR}/look-{}", operation.as_str()),
        None => format!("{EVAL_SCRATCH_DIR}/look"),
    };
    let mut argv = sandbox.bubble(capsule_root, look)?;
    argv.extend(["--url".to_owned(), url]);
    argv.extend(source);
    argv.extend([
        "--widths".to_owned(),
        widths,
        "--wait-ms".to_owned(),
        wait_ms.to_string(),
        "--out".to_owned(),
        out,
    ]);
    execute_params(argv, capsule_root, deadline_ms, MAX_STDOUT_BYTES)
}

/// The page must be the bubble's own loopback; the script owns the same check.
fn loopback_url(url: &str) -> Result<String, ExecutorFault> {
    let rest = url
        .strip_prefix("http://")
        .and_then(|rest| rest.strip_prefix(&std::net::Ipv4Addr::LOCALHOST.to_string()));
    let Some(rest) = rest else {
        return Err(ExecutorFault::Rejected {
            detail: format!("url {url:?} is not the capsule loopback"),
        });
    };
    let Some((port, path)) = rest
        .strip_prefix(':')
        .and_then(|rest| {
            rest.split_once('/')
                .map(|(port, path)| (port, format!("/{path}")))
        })
        .or_else(|| rest.strip_prefix(':').map(|port| (port, "/".to_owned())))
        .filter(|(port, _)| {
            (2..=5).contains(&port.len())
                && port.bytes().all(|byte| byte.is_ascii_digit())
                && port.parse::<u16>().is_ok_and(|port| port != 0)
        })
    else {
        return Err(ExecutorFault::Rejected {
            detail: format!("url {url:?} is not the capsule loopback"),
        });
    };
    Ok(format!(
        "http://{}:{port}{path}",
        std::net::Ipv4Addr::LOCALHOST
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEADLINE_MS: u64 = 100_000;

    fn argv(input: &str, operation: Option<&OperationId>) -> Result<Vec<String>, ExecutorFault> {
        let sandbox = EffectorSandboxBinding::new(
            "/bin/bwrap".into(),
            "/cache".into(),
            "/tools/bin".to_owned(),
            None,
            None,
            None,
            None,
        )
        .expect("sandbox");
        let input = odin_strict_json::decode(input.as_bytes(), 4096).expect("input");
        let params = arguments(
            &sandbox,
            Path::new("/look"),
            Path::new("/capsule"),
            &input,
            operation,
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
    fn a_url_off_the_capsule_loopback_is_refused() {
        let refused = argv(r#"{"url":"http://10.0.0.8:4173/","serve":"result"}"#, None);
        assert!(
            matches!(&refused, Err(ExecutorFault::Rejected { detail }) if detail.contains("10.0.0.8")),
            "{refused:?}"
        );
    }
}
