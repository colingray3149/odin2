//! `context_read` — bounded read-only access to one host-provisioned context root.
//!
//! The caller supplies only a relative path and a byte ceiling. The root is a
//! sealed descriptor created before the model exists; `openat2` beneath/no-link
//! resolution prevents lexical, symlink, magic-link, and rename escapes.

use std::borrow::Cow;
use std::ffi::OsStr;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use odin_confined_fs::{Capability, ConfinedError};
use odin_domain::{Digest, Scope};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::host_tools::{
    response, HostInvocation, HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode,
};

pub const CONTEXT_READ_HANDLER_ID: &str = "odin_context.read";
pub const CONTEXT_READ_EVIDENCE_ID: &str = "odin_context.read_evidence";
pub const MAX_CONTEXT_PATH_BYTES: usize = 1_024;

/// Bounded model-facing reader over one sealed private context directory.
pub struct ContextReadTool {
    root: Capability,
    root_path: PathBuf,
    max_bytes: u64,
    definition: RpcHostToolDefinition,
}

impl ContextReadTool {
    pub const NAME: &str = "context_read";

    pub fn new(root: &Path, max_bytes: u64) -> Result<Self, HostToolError> {
        if max_bytes == 0 {
            return Err(HostToolError::Arguments {
                tool: Self::NAME,
                detail: "configured context-read ceiling must be nonzero".to_owned(),
            });
        }
        let root_path = root.to_owned();
        let root = Capability::seal(root).map_err(confinement)?;
        Ok(Self {
            root,
            root_path,
            max_bytes,
            definition: RpcHostToolDefinition {
                name: Cow::Borrowed(Self::NAME),
                label: Cow::Borrowed("Context Read"),
                description: Cow::Borrowed(
                    "Read one UTF-8 file beneath the host-provisioned read-only context root. The path must be relative; `.` components are ignored, while `..`, symlinks, non-files, and reads above the configured byte ceiling are rejected. The root path and unrelated filesystem are never exposed.",
                ),
                parameters: serde_json::json!({
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "path": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": MAX_CONTEXT_PATH_BYTES
                        },
                        "maxBytes": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": max_bytes
                        }
                    },
                    "required": ["path", "maxBytes"]
                }),
                hidden: false,
                load_mode: ToolLoadMode::Essential,
            },
        })
    }

    /// Validates scope and arguments, then opens a confined path beneath the sealed root.
    /// Preflight drops the descriptor unread; invocation serves its bytes.
    fn resolve(
        &self,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(ContextReadArguments, std::fs::File), HostToolError> {
        if scope.seat.is_none() || scope.session.is_none() {
            return Err(HostToolError::Scope {
                tool: Self::NAME,
                reason: "the invocation scope must bind both a seat and a session",
            });
        }
        let arguments: ContextReadArguments =
            serde_json::from_value(arguments.clone()).map_err(|error| {
                HostToolError::Arguments {
                    tool: Self::NAME,
                    detail: format!("arguments violate the context.read schema: {error}"),
                }
            })?;
        if arguments.path.as_os_str().as_encoded_bytes().len() > MAX_CONTEXT_PATH_BYTES {
            return Err(HostToolError::Arguments {
                tool: Self::NAME,
                detail: format!("path exceeds {MAX_CONTEXT_PATH_BYTES} bytes"),
            });
        }
        if arguments.max_bytes == 0 || arguments.max_bytes > self.max_bytes {
            return Err(HostToolError::Arguments {
                tool: Self::NAME,
                detail: format!(
                    "maxBytes must be within 1..={} for this runtime",
                    self.max_bytes
                ),
            });
        }
        let path = normalize_context_path(&arguments.path)?;
        self.root
            .verify_declared_root(&self.root_path)
            .map_err(confinement)?;
        let file = self.root.open_read(path.as_ref()).map_err(confinement)?;
        Ok((arguments, file))
    }
}

impl HostTool for ContextReadTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn preflight(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        // Check accessibility without reading content; invocation resolves the path again.
        let (_arguments, file) = self.resolve(scope, arguments)?;
        let metadata = file.metadata().map_err(io_storage)?;
        if !metadata.is_file() {
            return Err(HostToolError::Arguments {
                tool: Self::NAME,
                detail: "context.read serves regular files only".to_owned(),
            });
        }
        Ok(())
    }

    fn invoke(&self, invocation: HostInvocation) -> Result<Value, HostToolError> {
        let (arguments, mut file) = self.resolve(&invocation.scope, &invocation.arguments)?;
        let metadata = file.metadata().map_err(io_storage)?;
        let retain =
            usize::try_from(arguments.max_bytes).map_err(|_| HostToolError::Arguments {
                tool: Self::NAME,
                detail: "maxBytes does not fit this host".to_owned(),
            })?;
        let file_size = metadata.len() as usize;
        let alloc_size = file_size.min(retain).saturating_add(1);
        let mut bytes = Vec::with_capacity(alloc_size);
        (&mut file)
            .take(arguments.max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(io_storage)?;
        let truncated = bytes.len() > retain;
        if truncated {
            bytes.truncate(retain);
        }
        let content = match String::from_utf8(bytes) {
            Ok(content) => content,
            Err(error) if truncated && error.utf8_error().error_len().is_none() => {
                let valid = error.utf8_error().valid_up_to();
                String::from_utf8(error.into_bytes()[..valid].to_vec()).map_err(|_| {
                    HostToolError::Storage {
                        tool: Self::NAME,
                        detail: "context UTF-8 prefix could not be recovered".to_owned(),
                    }
                })?
            }
            Err(_) => {
                return Err(HostToolError::Arguments {
                    tool: Self::NAME,
                    detail: "context.read serves UTF-8 text files only".to_owned(),
                })
            }
        };
        let byte_count = u64::try_from(content.len()).unwrap_or(u64::MAX);
        let content_digest = Digest::hash(content.as_bytes());
        let truncated = truncated || byte_count < arguments.max_bytes.min(metadata.len());
        response(
            Self::NAME,
            &ContextReadView {
                path: arguments.path,
                content,
                byte_count,
                total_bytes: metadata.len(),
                truncated,
                content_digest,
            },
        )
    }
}

/// Evidence extractor for the already-landed read. It validates the closed
/// output shape and returns provenance without duplicating private content in
/// the durable evidence payload.
pub struct ContextReadEvidenceTool {
    definition: RpcHostToolDefinition,
}

impl ContextReadEvidenceTool {
    pub fn new() -> Self {
        Self {
            definition: RpcHostToolDefinition {
                name: Cow::Borrowed("context_read_evidence"),
                label: Cow::Borrowed("Context Read Evidence"),
                description: Cow::Borrowed(
                    "Internal evidence projection for one completed context.read.",
                ),
                parameters: serde_json::json!({
                    "type": "object",
                    "additionalProperties": false,
                    "properties": { "output": { "type": "object" } },
                    "required": ["output"]
                }),
                hidden: true,
                load_mode: ToolLoadMode::Essential,
            },
        }
    }
}

impl Default for ContextReadEvidenceTool {
    fn default() -> Self {
        Self::new()
    }
}

impl HostTool for ContextReadEvidenceTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn preflight(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        _scope: &Scope,
        _arguments: &Value,
    ) -> Result<(), HostToolError> {
        // Explicit no-gate, by construction: an evidence extractor's input
        // is the handler's post-effect output, which cannot exist at
        // dispatch time, so there is no declared readiness to observe
        // pre-consume. Its strict envelope validation is the execution and
        // governs at the permit.
        Ok(())
    }

    fn invoke(&self, invocation: HostInvocation) -> Result<Value, HostToolError> {
        let envelope: EvidenceEnvelope =
            serde_json::from_value(invocation.arguments).map_err(|error| {
                HostToolError::Arguments {
                    tool: "context_read_evidence",
                    detail: format!("context.read output evidence is malformed: {error}"),
                }
            })?;
        let output: ContextReadView =
            serde_json::from_value(envelope.output).map_err(|error| HostToolError::Arguments {
                tool: "context_read_evidence",
                detail: format!("context.read output is malformed: {error}"),
            })?;
        response(
            "context_read_evidence",
            &ContextReadEvidence {
                path: output.path,
                byte_count: output.byte_count,
                total_bytes: output.total_bytes,
                truncated: output.truncated,
                content_digest: output.content_digest,
            },
        )
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContextReadArguments {
    path: PathBuf,
    max_bytes: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContextReadView {
    path: PathBuf,
    content: String,
    byte_count: u64,
    total_bytes: u64,
    truncated: bool,
    content_digest: Digest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceEnvelope {
    output: Value,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContextReadEvidence {
    path: PathBuf,
    byte_count: u64,
    total_bytes: u64,
    truncated: bool,
    content_digest: Digest,
}

fn confinement(error: ConfinedError) -> HostToolError {
    HostToolError::Arguments {
        tool: ContextReadTool::NAME,
        detail: format!("context path is unavailable within the sealed root: {error}"),
    }
}

/// Drop `.` components. `..`, absolute paths, empty components, and NUL
/// bytes stay refused; confinement still opens the result beneath the root.
fn normalize_context_path(path: &Path) -> Result<Cow<'_, Path>, HostToolError> {
    let bytes = path.as_os_str().as_bytes();
    if !bytes
        .split(|byte| *byte == b'/')
        .any(|component| component == b".")
    {
        return Ok(Cow::Borrowed(path));
    }
    if bytes[0] == b'/' {
        return Err(HostToolError::Arguments {
            tool: ContextReadTool::NAME,
            detail: "path must be relative".to_owned(),
        });
    }
    let mut normalized = PathBuf::new();
    for component in bytes.split(|byte| *byte == b'/') {
        if component.is_empty() {
            return Err(HostToolError::Arguments {
                tool: ContextReadTool::NAME,
                detail: "path has an empty component".to_owned(),
            });
        }
        if component == b"." {
            continue;
        }
        if component == b".." {
            return Err(HostToolError::Arguments {
                tool: ContextReadTool::NAME,
                detail: "path must not contain ..".to_owned(),
            });
        }
        if component.contains(&0) {
            return Err(HostToolError::Arguments {
                tool: ContextReadTool::NAME,
                detail: "path contains a NUL byte".to_owned(),
            });
        }
        normalized.push(OsStr::from_bytes(component));
    }
    if normalized.as_os_str().is_empty() {
        return Err(HostToolError::Arguments {
            tool: ContextReadTool::NAME,
            detail: "path is empty".to_owned(),
        });
    }
    Ok(Cow::Owned(normalized))
}

fn io_storage(error: std::io::Error) -> HostToolError {
    HostToolError::Storage {
        tool: ContextReadTool::NAME,
        detail: format!("context read failed: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use odin_domain::{Scope, SeatId, SessionId};
    use serde_json::json;

    use super::*;

    fn scope() -> Scope {
        Scope {
            seat: Some(SeatId::new("architect").expect("seat")),
            session: Some(SessionId::new("session-context-test").expect("session")),
            ..Scope::default()
        }
    }

    #[test]
    fn reads_utf8_and_rejects_escape_and_symlink() {
        let root = std::env::temp_dir().join(format!("odin-context-read-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).expect("root");
        fs::write(root.join("plan.txt"), "approved context\n").expect("write context");
        let outside = root.with_extension("outside");
        fs::write(&outside, "private\n").expect("write outside");
        symlink(&outside, root.join("escape")).expect("symlink");
        let tool = ContextReadTool::new(&root, 64).expect("tool");

        let value = tool
            .invoke(HostInvocation {
                scope: scope(),
                arguments: json!({"path": "plan.txt", "maxBytes": 64}),
            })
            .expect("read");
        assert_eq!(value["content"], "approved context\n");
        assert_eq!(value["truncated"], false);

        for path in ["../outside", "/etc/passwd", "escape"] {
            let error = tool
                .invoke(HostInvocation {
                    scope: scope(),
                    arguments: json!({"path": path, "maxBytes": 64}),
                })
                .expect_err("escape rejected");
            assert!(matches!(error, HostToolError::Arguments { .. }));
        }

        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_file(&outside);
    }

    #[test]
    fn replaced_context_root_refuses_reads_until_original_identity_returns() {
        let parent =
            std::env::temp_dir().join(format!("odin-context-root-{}", uuid::Uuid::new_v4()));
        let root = parent.join("context");
        let retired = parent.join("retired");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("brief.txt"), "original brief").unwrap();
        let tool = ContextReadTool::new(&root, 64).unwrap();
        let read = || {
            tool.invoke(HostInvocation {
                scope: scope(),
                arguments: json!({"path": "brief.txt", "maxBytes": 64}),
            })
        };
        assert_eq!(read().unwrap()["content"], "original brief");
        fs::rename(&root, &retired).unwrap();
        fs::create_dir(&root).unwrap();
        fs::write(root.join("brief.txt"), "replacement brief").unwrap();
        assert!(matches!(read(), Err(HostToolError::Arguments { .. })));
        fs::remove_dir_all(&root).unwrap();
        fs::rename(&retired, &root).unwrap();
        assert_eq!(read().unwrap()["content"], "original brief");
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn dot_components_are_read_and_parent_components_are_refused() {
        let root = std::env::temp_dir().join(format!("odin-context-dot-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("notes")).expect("root");
        fs::write(root.join("plan.txt"), "approved context\n").expect("write");
        fs::write(root.join("notes/brief.txt"), "nested\n").expect("write nested");
        let tool = ContextReadTool::new(&root, 64).expect("tool");
        let read = |path: &str| {
            tool.invoke(HostInvocation {
                scope: scope(),
                arguments: json!({"path": path, "maxBytes": 64}),
            })
        };
        assert_eq!(
            read("./plan.txt").expect("dot")["content"],
            "approved context\n"
        );
        assert_eq!(
            read("notes/./brief.txt").expect("interior dot")["content"],
            "nested\n"
        );
        for path in ["../plan.txt", "notes/../plan.txt", "./../plan.txt", "."] {
            assert!(read(path).is_err(), "{path} must stay refused");
        }
        let _ = fs::remove_dir_all(&root);
    }
}
