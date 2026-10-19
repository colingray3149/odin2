use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use url::Url;

use super::ToolName;
use crate::{CapabilityId, Digest, DomainError};

const MAX_HTTP_REDIRECT_HOPS: u8 = 3;
const ALIAS_REDIRECT_DEPTH: u8 = 1;

/// Metadata describing a redirect observed while invoking an already-authorized tool.
///
/// This type carries no authority and does not permit argument transformation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum RedirectTarget {
    Http {
        from: Url,
        to: Url,
        status: u16,
    },
    ToolAlias {
        from: ToolName,
        to: ToolName,
        /// The single schema identity bound to both alias endpoints.
        schema_digest: Digest,
    },
    Filesystem {
        root: PathBuf,
        requested: PathBuf,
        resolved: PathBuf,
    },
}

/// A redirect bound to the original capability and the policy that approved the hop.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedirectDecision {
    pub target: RedirectTarget,
    pub capability_id: CapabilityId,
    pub hop: u8,
    pub policy_digest: Digest,
}

impl RedirectDecision {
    /// Checks recorded metadata only; the kernel resolves policy, aliases, and schemas.
    /// Filesystem containment and authorization must be checked against the opened object.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.hop > MAX_HTTP_REDIRECT_HOPS {
            return Err(invalid_redirect("redirect hop exceeds three"));
        }

        match &self.target {
            RedirectTarget::Http { from, to, .. } => validate_http(from, to),
            RedirectTarget::ToolAlias {
                from,
                to,
                schema_digest,
            } => validate_alias(from, to, *schema_digest, self.hop),
            RedirectTarget::Filesystem {
                root,
                requested,
                resolved,
            } => validate_filesystem(root, requested, resolved),
        }
    }
}

fn validate_http(from: &Url, to: &Url) -> Result<(), DomainError> {
    if !is_http(from) || !is_http(to) {
        return Err(invalid_redirect(
            "HTTP redirect endpoints must use HTTP or HTTPS",
        ));
    }
    if from.scheme() == "https" && to.scheme() == "http" {
        return Err(invalid_redirect("HTTPS-to-HTTP downgrade is forbidden"));
    }
    if from == to {
        return Err(invalid_redirect("HTTP redirect must change the target URL"));
    }
    Ok(())
}

fn is_http(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
}

fn validate_alias(
    from: &ToolName,
    to: &ToolName,
    schema_digest: Digest,
    hop: u8,
) -> Result<(), DomainError> {
    if hop != ALIAS_REDIRECT_DEPTH {
        return Err(invalid_redirect("tool alias depth must be exactly one"));
    }
    if from == to {
        return Err(invalid_redirect(
            "tool alias self-redirects and cycles are forbidden",
        ));
    }
    if schema_digest.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(invalid_redirect(
            "tool alias requires the equal source and target schema digest",
        ));
    }
    Ok(())
}

fn validate_filesystem(root: &Path, requested: &Path, resolved: &Path) -> Result<(), DomainError> {
    if !root.is_absolute() {
        return Err(invalid_redirect(
            "filesystem redirect root must be absolute",
        ));
    }
    if requested.as_os_str().is_empty() {
        return Err(invalid_redirect(
            "filesystem requested path must not be empty",
        ));
    }
    if resolved.as_os_str().is_empty() {
        return Err(invalid_redirect(
            "filesystem resolved path must not be empty",
        ));
    }
    if !resolved.is_absolute() {
        return Err(invalid_redirect(
            "filesystem resolved path must be absolute",
        ));
    }
    Ok(())
}

fn invalid_redirect(reason: impl Into<String>) -> DomainError {
    DomainError::InvalidScope(format!("tool redirect: {}", reason.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capability_id() -> CapabilityId {
        CapabilityId::new("tool.invoke").unwrap()
    }

    fn digest(seed: &[u8]) -> Digest {
        Digest::hash(seed)
    }

    fn decision(target: RedirectTarget, hop: u8) -> RedirectDecision {
        RedirectDecision {
            target,
            capability_id: capability_id(),
            hop,
            policy_digest: digest(b"policy"),
        }
    }

    fn url(value: &str) -> Url {
        Url::parse(value).unwrap()
    }

    fn tool(value: &str) -> ToolName {
        ToolName::new(value).unwrap()
    }

    #[test]
    fn rejects_redirect_hops_over_three() {
        let redirect = decision(
            RedirectTarget::Http {
                from: url("https://example.test/old"),
                to: url("https://example.test/new"),
                status: 307,
            },
            4,
        );
        assert!(redirect.validate().is_err());
    }

    #[test]
    fn rejects_https_downgrade() {
        let redirect = decision(
            RedirectTarget::Http {
                from: url("https://example.test/old"),
                to: url("http://example.test/new"),
                status: 301,
            },
            1,
        );
        assert!(redirect.validate().is_err());
    }

    #[test]
    fn rejects_alias_self_redirect_depth_and_missing_schema_identity() {
        let name = tool("Read");
        let self_redirect = decision(
            RedirectTarget::ToolAlias {
                from: name.clone(),
                to: name,
                schema_digest: digest(b"schema"),
            },
            1,
        );
        assert!(self_redirect.validate().is_err());

        let chained = decision(
            RedirectTarget::ToolAlias {
                from: tool("Read"),
                to: tool("FileRead"),
                schema_digest: digest(b"schema"),
            },
            2,
        );
        assert!(chained.validate().is_err());

        let missing_schema = decision(
            RedirectTarget::ToolAlias {
                from: tool("Read"),
                to: tool("FileRead"),
                schema_digest: Digest::new([0; 32]),
            },
            1,
        );
        assert!(missing_schema.validate().is_err());
    }

    #[test]
    fn rejects_empty_or_rootless_filesystem_metadata() {
        let relative_root = decision(
            RedirectTarget::Filesystem {
                root: PathBuf::from("workspace"),
                requested: PathBuf::from("src/lib.rs"),
                resolved: PathBuf::from("/workspace/src/lib.rs"),
            },
            0,
        );
        assert!(relative_root.validate().is_err());

        let empty_requested = decision(
            RedirectTarget::Filesystem {
                root: PathBuf::from("/workspace"),
                requested: PathBuf::new(),
                resolved: PathBuf::from("/workspace/src/lib.rs"),
            },
            0,
        );
        assert!(empty_requested.validate().is_err());

        let empty_resolved = decision(
            RedirectTarget::Filesystem {
                root: PathBuf::from("/workspace"),
                requested: PathBuf::from("src/lib.rs"),
                resolved: PathBuf::new(),
            },
            0,
        );
        assert!(empty_resolved.validate().is_err());
    }

    #[test]
    fn filesystem_metadata_does_not_claim_opened_object_authorization() {
        let redirect = decision(
            RedirectTarget::Filesystem {
                root: PathBuf::from("/workspace"),
                requested: PathBuf::from("link"),
                resolved: PathBuf::from("/outside/target"),
            },
            0,
        );
        assert!(redirect.validate().is_ok());
    }
}
