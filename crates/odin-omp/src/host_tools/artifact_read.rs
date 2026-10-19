//! `odin_artifact_read` — verified, scope-authorized artifact reads.
//!
//! Bytes are served only from the ledger-registered storage path beneath the artifact root, are
//! bounded by the caller's `maxBytes` and a hard protocol ceiling, and are BLAKE3-verified against
//! the registered metadata. The read is authorized exclusively through ledger references that bind
//! the artifact to a dimension of the invocation scope; denials leak no metadata.

use std::borrow::Cow;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use odin_confined_fs::{Capability, ConfinedError};
use odin_domain::{ArtifactId, Digest, Scope};
use odin_ledger::artifact::{ArtifactMetadata, ArtifactReference, RetentionClass};
use odin_ledger::{Ledger, LedgerError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::host_tools::{
    bound_scope_dimension, lock_ledger, response, HostInvocation, HostTool, HostToolError,
    RpcHostToolDefinition, ToolLoadMode, SCOPE_DIMENSIONS,
};

/// Hard ceiling for one read, pinned to the protocol chunk payload size so a single result always
/// fits inside a physical RPC frame even after base64 inflation.
pub const MAX_ARTIFACT_READ_BYTES: u64 = 262_144;

/// Reads ledger-registered artifact bytes for the calling scope.
pub struct ArtifactReadTool {
    ledger: Arc<Mutex<Ledger>>,
    artifact_root: PathBuf,
    definition: RpcHostToolDefinition,
}

impl ArtifactReadTool {
    pub const NAME: &str = "odin_artifact_read";

    /// Builds the tool over shared ledger state and one absolute artifact storage root.
    pub fn new(ledger: Arc<Mutex<Ledger>>, artifact_root: impl Into<PathBuf>) -> Self {
        Self {
            ledger,
            artifact_root: artifact_root.into(),
            definition: RpcHostToolDefinition {
                name: Cow::Borrowed(Self::NAME),
                label: Cow::Borrowed("Artifact Read"),
                description: Cow::Borrowed(
                    "Read the BLAKE3-verified bytes of a ledger-registered artifact that \
                     a ledger reference binds to this session's scope. Returns base64 content with \
                     its digest, size, media type, retention class, and revision. Reads are capped \
                     by maxBytes and by a hard protocol ceiling; unknown fields, symlinks, and \
                     content that fails digest verification are rejected.",
                ),
                parameters: parameters(),
                hidden: false,
                load_mode: ToolLoadMode::Essential,
            },
        }
    }
}

impl HostTool for ArtifactReadTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn preflight(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        // Check authorization, file accessibility, and size without reading content.
        // Invocation reopens the file and verifies its bytes.
        let (arguments, metadata) = self.resolve(scope, arguments)?;
        if metadata.size_bytes > arguments.max_bytes {
            return Err(HostToolError::Arguments {
                tool: Self::NAME,
                detail: format!(
                    "registered artifact size {} exceeds maxBytes {}",
                    metadata.size_bytes, arguments.max_bytes
                ),
            });
        }
        let file = capability_open(&self.artifact_root, &metadata.storage_path)?;
        let opened = file.metadata().map_err(io_storage)?;
        if opened.len() != metadata.size_bytes {
            return Err(size_race(&metadata));
        }
        Ok(())
    }

    fn invoke(&self, invocation: HostInvocation) -> Result<Value, HostToolError> {
        let (arguments, metadata) = self.resolve(&invocation.scope, &invocation.arguments)?;

        if metadata.size_bytes > arguments.max_bytes {
            return Err(HostToolError::Arguments {
                tool: Self::NAME,
                detail: format!(
                    "registered artifact size {} exceeds maxBytes {}",
                    metadata.size_bytes, arguments.max_bytes
                ),
            });
        }

        let bytes = read_verified_bytes(&self.artifact_root, &metadata, arguments.max_bytes)?;
        response(Self::NAME, &ArtifactReadView::new(&metadata, bytes))
    }
}

impl ArtifactReadTool {
    /// The one authorization seam both preflight and the executed read run:
    /// strict argument decoding, the byte bounds, and — under one ledger
    /// lock — reference authorization before the registration lookup, so a
    /// cross-scope caller cannot distinguish an unregistered id from an
    /// existing out-of-scope artifact. Read-only.
    fn resolve(
        &self,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(ArtifactReadArguments, ArtifactMetadata), HostToolError> {
        let arguments: ArtifactReadArguments =
            serde_json::from_value(arguments.clone()).map_err(|error| {
                HostToolError::Arguments {
                    tool: Self::NAME,
                    detail: format!("arguments violate the odin_artifact_read schema: {error}"),
                }
            })?;
        if arguments.max_bytes == 0 {
            return Err(HostToolError::Arguments {
                tool: Self::NAME,
                detail: "maxBytes must be at least 1".to_owned(),
            });
        }
        if arguments.max_bytes > MAX_ARTIFACT_READ_BYTES {
            return Err(HostToolError::Arguments {
                tool: Self::NAME,
                detail: format!(
                    "maxBytes must not exceed the hard ceiling of {MAX_ARTIFACT_READ_BYTES}"
                ),
            });
        }

        // The lock is held only while evidence is collected; file I/O happens without it.
        let metadata = {
            let ledger = lock_ledger(Self::NAME, &self.ledger)?;
            // References authorize before the metadata fetch, so a cross-scope caller cannot
            // distinguish an unregistered id from an existing out-of-scope artifact.
            let references = ledger.artifact_references(&arguments.artifact_id)?;
            authorize_scope(scope, &references)?;
            ledger
                .artifact(&arguments.artifact_id)?
                .ok_or_else(|| HostToolError::Arguments {
                    tool: Self::NAME,
                    detail: format!("artifact {} is not registered", arguments.artifact_id),
                })?
        };
        Ok((arguments, metadata))
    }
}

/// Proves the invocation scope against ledger references before any data path is opened.
///
/// Denial reasons are static on purpose: reference ids, storage paths, media types, and digests
/// never reach a cross-scope caller.
fn authorize_scope(scope: &Scope, references: &[ArtifactReference]) -> Result<(), HostToolError> {
    let has_bound_dimension = SCOPE_DIMENSIONS
        .iter()
        .any(|kind| bound_scope_dimension(scope, kind).is_some());
    if !has_bound_dimension {
        return Err(HostToolError::Scope {
            tool: ArtifactReadTool::NAME,
            reason: "the invocation scope has no bound dimension",
        });
    }
    let authorized = references.iter().any(|reference| {
        bound_scope_dimension(scope, &reference.object_kind) == Some(reference.object_id.as_str())
    });
    if !authorized {
        return Err(HostToolError::Scope {
            tool: ArtifactReadTool::NAME,
            reason: "no ledger reference binds the artifact to the invocation scope",
        });
    }
    Ok(())
}

/// Reads exactly the registered bytes from the registered path and verifies them.
///
/// The confined capability resolves the path against the root descriptor with `RESOLVE_BENEATH`,
/// `RESOLVE_NO_SYMLINKS`, `RESOLVE_NO_MAGICLINKS`, and `O_NOFOLLOW`, so resolution can never
/// leave the artifact root however the store's directories race, and only a stable regular file
/// is ever opened. Size divergence before or during the read is a storage race; only content
/// matching the registered BLAKE3 digest is returned.
fn read_verified_bytes(
    root: &Path,
    metadata: &ArtifactMetadata,
    max_bytes: u64,
) -> Result<Vec<u8>, HostToolError> {
    let mut file = capability_open(root, &metadata.storage_path)?;

    let opened = file.metadata().map_err(io_storage)?;
    if opened.len() != metadata.size_bytes {
        return Err(size_race(metadata));
    }

    let mut bytes = Vec::new();
    (&mut file)
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(io_storage)?;
    if bytes.len() as u64 != metadata.size_bytes {
        return Err(size_race(metadata));
    }

    if Digest::hash(&bytes) != metadata.digest {
        return Err(HostToolError::Ledger(LedgerError::invalid_data(format!(
            "artifact {} content does not match its registered digest",
            metadata.artifact_id
        ))));
    }
    Ok(bytes)
}

/// Opens the registered storage path as a stable regular file beneath the artifact root. The
/// confined capability is the only path authority; a rejection is a storage failure, never a
/// fallback to a wider resolution.
fn capability_open(root: &Path, storage_path: &str) -> Result<File, HostToolError> {
    let capability = Capability::seal(root).map_err(confinement)?;
    capability
        .open_read(Path::new(storage_path))
        .map_err(confinement)
}

fn confinement(error: ConfinedError) -> HostToolError {
    HostToolError::Storage {
        tool: ArtifactReadTool::NAME,
        detail: format!("registered artifact path is unavailable: {error}"),
    }
}

fn size_race(metadata: &ArtifactMetadata) -> HostToolError {
    HostToolError::Ledger(LedgerError::invalid_data(format!(
        "artifact {} storage size diverged from its registered metadata",
        metadata.artifact_id
    )))
}

fn io_storage(error: std::io::Error) -> HostToolError {
    HostToolError::Storage {
        tool: ArtifactReadTool::NAME,
        detail: format!("artifact storage I/O failed: {error}"),
    }
}

/// The durable artifact projected as model-facing camelCase JSON.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactReadView {
    artifact_id: ArtifactId,
    digest: Digest,
    size_bytes: u64,
    media_type: String,
    retention: &'static str,
    revision: i64,
    bytes_base64: String,
}

impl ArtifactReadView {
    fn new(metadata: &ArtifactMetadata, bytes: Vec<u8>) -> Self {
        Self {
            artifact_id: metadata.artifact_id.clone(),
            digest: metadata.digest,
            size_bytes: metadata.size_bytes,
            media_type: metadata.media_type.clone(),
            retention: retention_label(metadata.retention),
            revision: metadata.revision,
            bytes_base64: STANDARD.encode(bytes),
        }
    }
}

fn retention_label(retention: RetentionClass) -> &'static str {
    match retention {
        RetentionClass::Canonical => "canonical",
        RetentionClass::Pinned => "pinned",
        RetentionClass::Regenerable => "regenerable",
        RetentionClass::Scratch => "scratch",
    }
}

/// Model-facing input. The schema and this parser are one contract: unknown fields never pass.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ArtifactReadArguments {
    artifact_id: ArtifactId,
    max_bytes: u64,
}

fn parameters() -> Value {
    json!({
        "type": "object",
        "properties": {
            "artifactId": {
                "type": "string",
                "minLength": 1,
                "description": "Registered artifact identifier in `blake3:` digest form."
            },
            "maxBytes": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAX_ARTIFACT_READ_BYTES,
                "description": "Largest number of artifact bytes the caller will accept."
            }
        },
        "required": ["artifactId", "maxBytes"],
        "additionalProperties": false
    })
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use odin_domain::LaneId;
    use odin_ledger::artifact::{ArtifactRegistration, AttachReference, NewArtifactReference};
    use time::OffsetDateTime;

    use super::*;

    fn at(second: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(second).expect("test timestamp")
    }

    fn unique_root(label: &str) -> PathBuf {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "odin-artifact-read-{label}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(path.join("objects")).expect("test artifact root");
        path
    }

    struct Fixture {
        tool: ArtifactReadTool,
        ledger: Arc<Mutex<Ledger>>,
        root: PathBuf,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let ledger = Arc::new(Mutex::new(
                Ledger::open_in_memory().expect("in-memory ledger opens"),
            ));
            let root = unique_root(label);
            let tool = ArtifactReadTool::new(Arc::clone(&ledger), root.clone());
            Self { tool, ledger, root }
        }

        /// Registers bytes with a real file in the root and one lane reference, returning the
        /// current artifact metadata after the reference attaches.
        fn register(&self, bytes: &[u8], lane: &str) -> ArtifactMetadata {
            let digest = Digest::hash(bytes);
            let storage_path = format!("objects/{digest}");
            fs::write(self.root.join(&storage_path), bytes).expect("artifact file");
            let mut ledger = self.ledger.lock().expect("ledger lock");
            let metadata = ledger
                .register_artifact(ArtifactRegistration {
                    bytes,
                    media_type: "text/plain",
                    storage_path: &storage_path,
                    retention: RetentionClass::Canonical,
                    created_at: at(1),
                })
                .expect("artifact registers");
            match ledger
                .attach_artifact_reference(
                    &metadata.artifact_id,
                    metadata.revision,
                    NewArtifactReference {
                        object_kind: "lane",
                        object_id: lane,
                        relation: "produced",
                        created_at: at(2),
                    },
                )
                .expect("reference attaches")
            {
                AttachReference::Added(metadata) | AttachReference::Existing(metadata) => metadata,
            }
        }
    }

    fn lane_scope(lane: &str) -> Scope {
        Scope {
            lane: Some(LaneId::new(lane).expect("lane id")),
            ..Scope::default()
        }
    }

    fn invocation(scope: Scope, artifact: &ArtifactId, max_bytes: u64) -> HostInvocation {
        HostInvocation {
            scope,
            arguments: json!({ "artifactId": artifact.to_string(), "maxBytes": max_bytes }),
        }
    }

    #[test]
    fn read_returns_verified_content() {
        let fixture = Fixture::new("verified");
        let bytes = b"approved artifact body";
        let metadata = fixture.register(bytes, "lane-a");

        let result = fixture
            .tool
            .invoke(invocation(
                lane_scope("lane-a"),
                &metadata.artifact_id,
                1024,
            ))
            .expect("in-scope read succeeds");

        assert_eq!(result["artifactId"], metadata.artifact_id.to_string());
        assert_eq!(result["digest"], metadata.digest.to_string());
        assert_eq!(result["sizeBytes"], bytes.len() as u64);
        assert_eq!(result["mediaType"], "text/plain");
        assert_eq!(result["retention"], "canonical");
        assert_eq!(result["revision"], metadata.revision);
        assert_eq!(
            STANDARD
                .decode(result["bytesBase64"].as_str().expect("base64"))
                .expect("base64 decodes"),
            bytes,
        );
        let _ = fs::remove_dir_all(&fixture.root);
    }

    #[test]
    fn cross_scope_and_unbound_scopes_are_denied_without_metadata() {
        let fixture = Fixture::new("denied");
        let metadata = fixture.register(b"secret body", "lane-a");

        let cross_scope = fixture
            .tool
            .invoke(invocation(
                lane_scope("lane-b"),
                &metadata.artifact_id,
                1024,
            ))
            .expect_err("another lane's reference must not authorize the read");
        assert!(matches!(
            cross_scope,
            HostToolError::Scope {
                tool: ArtifactReadTool::NAME,
                ..
            }
        ));
        let rendered = cross_scope.to_string();
        assert!(!rendered.contains("objects/"));
        assert!(!rendered.contains("text/plain"));
        assert!(!rendered.contains(&metadata.digest.to_string()));

        let unbound = fixture
            .tool
            .invoke(invocation(Scope::default(), &metadata.artifact_id, 1024))
            .expect_err("a scope with no bound dimension must be rejected");
        assert!(matches!(
            unbound,
            HostToolError::Scope {
                tool: ArtifactReadTool::NAME,
                ..
            }
        ));

        // A denial is independent of the budget: a huge maxBytes changes nothing.
        let greedy = fixture
            .tool
            .invoke(invocation(
                lane_scope("lane-b"),
                &metadata.artifact_id,
                MAX_ARTIFACT_READ_BYTES,
            ))
            .expect_err("scope denial precedes any budget decision");
        assert!(matches!(
            greedy,
            HostToolError::Scope {
                tool: ArtifactReadTool::NAME,
                ..
            }
        ));
        let _ = fs::remove_dir_all(&fixture.root);
    }

    #[test]
    fn unreferenced_artifact_is_denied() {
        let fixture = Fixture::new("unreferenced");
        let bytes = b"orphan bytes";
        let digest = Digest::hash(bytes);
        let storage_path = format!("objects/{digest}");
        fs::write(fixture.root.join(&storage_path), bytes).expect("artifact file");
        let metadata = fixture
            .ledger
            .lock()
            .expect("ledger lock")
            .register_artifact(ArtifactRegistration {
                bytes,
                media_type: "text/plain",
                storage_path: &storage_path,
                retention: RetentionClass::Scratch,
                created_at: at(1),
            })
            .expect("artifact registers");

        let result = fixture
            .tool
            .invoke(invocation(
                lane_scope("lane-a"),
                &metadata.artifact_id,
                1024,
            ))
            .expect_err("an artifact without references must be denied");
        assert!(matches!(
            result,
            HostToolError::Scope {
                tool: ArtifactReadTool::NAME,
                ..
            }
        ));
        let _ = fs::remove_dir_all(&fixture.root);
    }

    #[test]
    fn tampered_content_is_rejected() {
        let fixture = Fixture::new("tamper");
        let metadata = fixture.register(b"0123456789abcdef", "lane-a");
        fs::write(
            fixture.root.join(&metadata.storage_path),
            b"0123456789abcdeg",
        )
        .expect("tampered file");

        let result = fixture
            .tool
            .invoke(invocation(
                lane_scope("lane-a"),
                &metadata.artifact_id,
                1024,
            ))
            .expect_err("digest mismatch must be rejected");
        assert!(matches!(
            result,
            HostToolError::Ledger(LedgerError::InvalidData { .. })
        ));
        let _ = fs::remove_dir_all(&fixture.root);
    }

    #[test]
    fn storage_size_race_is_rejected() {
        let fixture = Fixture::new("race");
        let metadata = fixture.register(b"stable bytes", "lane-a");
        fs::write(
            fixture.root.join(&metadata.storage_path),
            b"stable bytes and more",
        )
        .expect("resized file");

        let result = fixture
            .tool
            .invoke(invocation(
                lane_scope("lane-a"),
                &metadata.artifact_id,
                1024,
            ))
            .expect_err("a size divergence must be rejected before any byte is trusted");
        assert!(matches!(
            result,
            HostToolError::Ledger(LedgerError::InvalidData { .. })
        ));
        let _ = fs::remove_dir_all(&fixture.root);
    }

    #[test]
    fn oversize_and_invalid_budgets_are_rejected() {
        let fixture = Fixture::new("oversize");
        let metadata = fixture.register(b"bounded bytes", "lane-a");

        let below_size = fixture
            .tool
            .invoke(invocation(lane_scope("lane-a"), &metadata.artifact_id, 4))
            .expect_err("a budget below the registered size must be rejected");
        assert!(matches!(
            below_size,
            HostToolError::Arguments {
                tool: ArtifactReadTool::NAME,
                ..
            }
        ));

        let zero = fixture
            .tool
            .invoke(invocation(lane_scope("lane-a"), &metadata.artifact_id, 0))
            .expect_err("a zero budget must be rejected");
        assert!(matches!(
            zero,
            HostToolError::Arguments {
                tool: ArtifactReadTool::NAME,
                ..
            }
        ));

        let above_ceiling = fixture
            .tool
            .invoke(invocation(
                lane_scope("lane-a"),
                &metadata.artifact_id,
                MAX_ARTIFACT_READ_BYTES + 1,
            ))
            .expect_err("the hard ceiling binds every caller");
        assert!(matches!(
            above_ceiling,
            HostToolError::Arguments {
                tool: ArtifactReadTool::NAME,
                ..
            }
        ));
        let _ = fs::remove_dir_all(&fixture.root);
    }

    #[test]
    fn symlinked_storage_path_is_rejected() {
        let fixture = Fixture::new("symlink");
        let metadata = fixture.register(b"linked bytes", "lane-a");
        let external = unique_root("symlink-external").join("payload");
        fs::rename(fixture.root.join(&metadata.storage_path), &external).expect("file moved out");
        symlink(&external, fixture.root.join(&metadata.storage_path)).expect("symlink planted");

        let result = fixture
            .tool
            .invoke(invocation(
                lane_scope("lane-a"),
                &metadata.artifact_id,
                1024,
            ))
            .expect_err("a symlinked registered path must never be opened");
        assert!(matches!(result, HostToolError::Storage { .. }));
        let _ = fs::remove_dir_all(&fixture.root);
        let _ = fs::remove_dir_all(external.parent().expect("external parent"));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let fixture = Fixture::new("unknown");
        let metadata = fixture.register(b"strict bytes", "lane-a");

        let result = fixture
            .tool
            .invoke(HostInvocation {
                scope: lane_scope("lane-a"),
                arguments: json!({
                    "artifactId": metadata.artifact_id.to_string(),
                    "maxBytes": 64,
                    "path": "../../etc/passwd",
                }),
            })
            .expect_err("unknown fields must never smuggle a path authority");
        assert!(matches!(
            result,
            HostToolError::Arguments {
                tool: ArtifactReadTool::NAME,
                ..
            }
        ));
        let _ = fs::remove_dir_all(&fixture.root);
    }
}
