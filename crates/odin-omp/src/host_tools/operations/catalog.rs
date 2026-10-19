//! Schema and operation catalogs describe admission; they do not grant permission.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use odin_domain::knowledge::ToolSchema;
use odin_domain::{CapabilityId, Digest};
use odin_kernel::{
    AdmittedCapability, CapabilityContract, HandlerBinding, KernelError, KernelResult,
    OperationCatalog, SchemaCatalog,
};

use crate::host_tools::executor::internal_key_of;
use crate::host_tools::HostToolRegistry;

use super::HostToolOperationError;

/// Schemas resolved from the repository filesystem. Missing, escaping, or
/// undecodable references fail closed; there is no fallback source.
///
/// Cache entries require matching length, mtime, ctime, and inode before and after parsing.
pub struct FilesystemSchemaCatalog {
    root: PathBuf,
    cache: Mutex<HashMap<String, CachedSchema>>,
}

/// A full cache stops retaining new references rather than evicting existing ones.
const SCHEMA_CACHE_CAP: usize = 512;

/// Identity of the bytes a schema was parsed from. Lookup and remember
/// compare this whole value; a same-length or timestamp-preserving rewrite
/// still changes ctime or inode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SchemaFingerprint {
    len: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
    inode: u64,
}

impl SchemaFingerprint {
    fn from_metadata(meta: &fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            len: meta.len(),
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
            ctime: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
            inode: meta.ino(),
        }
    }
}

struct CachedSchema {
    fingerprint: SchemaFingerprint,
    schema: ToolSchema,
}

impl FilesystemSchemaCatalog {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, HashMap<String, CachedSchema>> {
        self.cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl SchemaCatalog for FilesystemSchemaCatalog {
    fn schema(&self, reference: &str) -> KernelResult<ToolSchema> {
        if reference.is_empty()
            || reference.starts_with('/')
            || reference
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(KernelError::Schema(format!(
                "schema reference {reference:?} is not a confined relative path"
            )));
        }
        let path = self.root.join(reference);
        // Stat before the read. A stat failure falls through so the caller's
        // error text stays the read error, and a parse with no fingerprint
        // is not remembered.
        let before = fs::metadata(&path)
            .ok()
            .map(|meta| SchemaFingerprint::from_metadata(&meta));
        if let Some(fingerprint) = before {
            if let Some(cached) = self.cached(reference, fingerprint) {
                return Ok(cached);
            }
        }
        let bytes = fs::read(&path).map_err(|error| {
            KernelError::Schema(format!("cannot read {}: {error}", path.display()))
        })?;
        let value = serde_json::from_slice(&bytes).map_err(|error| {
            KernelError::Schema(format!("cannot decode {}: {error}", path.display()))
        })?;
        let schema = ToolSchema::from_value(value).map_err(KernelError::from)?;
        if let Some(fingerprint) = before {
            self.remember(&path, reference, fingerprint, bytes.len() as u64, &schema);
        }
        Ok(schema)
    }
}

impl FilesystemSchemaCatalog {
    fn cached(&self, reference: &str, fingerprint: SchemaFingerprint) -> Option<ToolSchema> {
        let cache = self.cache();
        let hit = cache
            .get(reference)
            .filter(|hit| hit.fingerprint == fingerprint)?;
        Some(hit.schema.clone())
    }

    fn remember(
        &self,
        path: &Path,
        reference: &str,
        before: SchemaFingerprint,
        parsed_len: u64,
        schema: &ToolSchema,
    ) {
        let Ok(meta) = fs::metadata(path) else {
            return;
        };
        // Do not cache bytes if the file changed during the read, even at the same length.
        let after = SchemaFingerprint::from_metadata(&meta);
        if parsed_len != before.len || after != before {
            return;
        }
        let mut cache = self.cache();
        if cache.len() >= SCHEMA_CACHE_CAP && !cache.contains_key(reference) {
            return;
        }
        cache.insert(
            reference.to_owned(),
            CachedSchema {
                fingerprint: before,
                schema: schema.clone(),
            },
        );
    }
}

/// In-memory schema catalog over caller-supplied schemas. Missing references
/// fail closed. Used by harnesses that pin exact schema values.
#[derive(Default)]
pub struct StaticSchemaCatalog {
    schemas: BTreeMap<String, ToolSchema>,
}

impl StaticSchemaCatalog {
    /// Builds the catalog, rejecting duplicate references.
    pub fn new(
        schemas: impl IntoIterator<Item = (String, ToolSchema)>,
    ) -> Result<Self, KernelError> {
        let mut catalog = Self::default();
        for (reference, schema) in schemas {
            if catalog.schemas.insert(reference.clone(), schema).is_some() {
                return Err(KernelError::Schema(format!(
                    "schema reference {reference:?} is declared twice"
                )));
            }
        }
        Ok(catalog)
    }
}

impl SchemaCatalog for StaticSchemaCatalog {
    fn schema(&self, reference: &str) -> KernelResult<ToolSchema> {
        self.schemas.get(reference).cloned().ok_or_else(|| {
            KernelError::Schema(format!("schema reference {reference:?} is not cataloged"))
        })
    }
}

/// The production operation catalog over the host's declared admission set:
/// exactly the contracts the host assembled from validated registry
/// declarations, pinned to one admission revision and digest, resolving
/// bindings only against the concrete host-tool registry. It never grants
/// permission by itself; admission is data, not authority.
pub struct DeclaredOperationCatalog {
    admitted: BTreeMap<CapabilityId, AdmittedCapability>,
    registry: Arc<HostToolRegistry>,
    /// Ids deliberately kept out of this dispatch catalog because their
    /// concrete owner is the one-shot operator CLI.
    operator_owned: BTreeSet<CapabilityId>,
    equivalence: Option<Arc<dyn AdmissionEquivalence>>,
}

/// Checks whether a token's revision composes like the catalog's admission revision.
pub trait AdmissionEquivalence: Send + Sync {
    fn equivalent(&self, digest: Digest) -> bool;
}

impl DeclaredOperationCatalog {
    /// Admits exactly the supplied contracts, failing closed when any
    /// contract's handler or evidence extractor does not resolve against the
    /// concrete registry.
    ///
    /// `operator_owned` names the capabilities whose concrete owner is the
    /// one-shot operator CLI rather than a session HostTool. They are admitted
    /// at registry publication by the operator catalog and are deliberately
    /// absent here: the kernel never dispatches them, so no HostTool owner is
    /// required or invented, and a session can never invoke them.
    pub fn from_contracts(
        contracts: &BTreeMap<CapabilityId, CapabilityContract>,
        snapshot_revision: i64,
        snapshot_digest: Digest,
        registry: Arc<HostToolRegistry>,
        operator_owned: &BTreeSet<CapabilityId>,
    ) -> Result<Self, HostToolOperationError> {
        if snapshot_revision <= 0 {
            return Err(HostToolOperationError::Composition {
                detail: "admission revision must be positive".to_owned(),
            });
        }
        let mut admitted = BTreeMap::new();
        let mut excluded = BTreeSet::new();
        for (id, contract) in contracts {
            if operator_owned.contains(id) {
                excluded.insert(id.clone());
                continue;
            }
            for (field, binding) in [
                ("handler", &contract.handler),
                ("evidence extractor", &contract.evidence_extractor),
            ] {
                if !registry.resolves_key(&internal_key_of(binding)) {
                    return Err(HostToolOperationError::Composition {
                        detail: format!(
                            "capability {id} {field} binding does not resolve against the concrete registry"
                        ),
                    });
                }
            }
            admitted.insert(
                id.clone(),
                AdmittedCapability {
                    contract: contract.clone(),
                    snapshot_revision,
                    snapshot_digest,
                },
            );
        }
        Ok(Self {
            admitted,
            registry,
            operator_owned: excluded,
            equivalence: None,
        })
    }

    /// Also admits the admission digests of composition-identical revisions,
    /// so a session kept across a restart is not refused for a digest
    /// mismatch.
    pub fn with_equivalence(mut self, equivalence: Arc<dyn AdmissionEquivalence>) -> Self {
        self.equivalence = Some(equivalence);
        self
    }
}

impl OperationCatalog for DeclaredOperationCatalog {
    fn admitted(&self, capability: &CapabilityId) -> Option<AdmittedCapability> {
        self.admitted.get(capability).cloned()
    }

    fn resolves(&self, binding: &HandlerBinding) -> bool {
        self.registry.resolves_key(&internal_key_of(binding))
    }

    fn is_operator_owned(&self, id: &CapabilityId) -> bool {
        self.operator_owned.contains(id)
    }

    fn admits_policy_digest(&self, admitted: &AdmittedCapability, digest: Digest) -> bool {
        admitted.snapshot_digest == digest
            || self
                .equivalence
                .as_ref()
                .is_some_and(|equivalence| equivalence.equivalent(digest))
    }
}

/// Adds deployment constraints, such as per-seat project enums, after canonical validation.
/// Top-level `additionalProperties` is omitted because the host inserts derived arguments there.
/// The canonical schema still rejects unknown keys; nested constraints are retained.
pub(super) fn declared_narrowing_schema(
    definition: &crate::host_tools::RpcHostToolDefinition,
) -> Result<ToolSchema, HostToolOperationError> {
    let mut narrowing = definition.parameters.clone();
    if let Some(object) = narrowing.as_object_mut() {
        object.remove("additionalProperties");
    }
    ToolSchema::from_value(narrowing).map_err(|error| HostToolOperationError::Composition {
        detail: format!(
            "model surface of {} does not compile into an argument narrowing: {error}",
            definition.name
        ),
    })
}

#[cfg(test)]
mod schema_cache_tests {
    use std::fs::File;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use std::time::{Duration, SystemTime};

    use odin_domain::knowledge::ToolSchema;
    use odin_kernel::SchemaCatalog;

    use super::FilesystemSchemaCatalog;

    const REFERENCE: &str = "schemas/tool.input.json";

    fn schema_of(bytes: &[u8]) -> ToolSchema {
        ToolSchema::from_value(serde_json::from_slice(bytes).expect("schema json"))
            .expect("schema value")
    }

    fn restore_mtime(path: &Path, mtime: SystemTime) {
        File::options()
            .write(true)
            .open(path)
            .expect("reopen schema")
            .set_modified(mtime)
            .expect("restore mtime");
    }

    /// Measurement: 200 lookups of an unchanged file must stay under 500 ms.
    /// The hit itself is pinned by planting a schema in the cache and
    /// observing that lookup returns it — a re-read would return the file.
    /// A same-length rewrite that preserves mtime (in place, and by rename)
    /// must be observed; length and mtime alone are not the fingerprint.
    #[test]
    fn remembered_schema_matches_until_the_file_changes() {
        let root = std::env::temp_dir().join(format!(
            "odin-schema-cache-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("schemas")).expect("temp schema dir");
        let path = root.join(REFERENCE);
        let bytes_a = br#"{"type":"object","title":"a"}"#;
        let bytes_b = br#"{"type":"object","title":"b"}"#;
        let bytes_c = br#"{"type":"object","title":"c"}"#;
        std::fs::write(&path, bytes_a).expect("write schema");
        let original = std::fs::metadata(&path).expect("stat schema");
        let original_mtime = original.modified().expect("mtime");
        let catalog = FilesystemSchemaCatalog::new(&root);
        let first = catalog.schema(REFERENCE).expect("schema reads");
        assert_eq!(first.digest(), schema_of(bytes_a).digest());

        let sentinel = schema_of(br#"{"type":"object","title":"cached"}"#);
        {
            let mut cache = catalog.cache();
            let hit = cache.get_mut(REFERENCE).expect("first read is remembered");
            hit.schema = sentinel.clone();
        }
        let served = catalog.schema(REFERENCE).expect("cached schema");
        assert_eq!(
            served.digest(),
            sentinel.digest(),
            "lookup re-read the file instead of serving the remembered schema"
        );
        assert_ne!(served.digest(), first.digest());
        {
            let mut cache = catalog.cache();
            cache.get_mut(REFERENCE).expect("still remembered").schema = first.clone();
        }

        let started = std::time::Instant::now();
        for _ in 0..200 {
            let again = catalog.schema(REFERENCE).expect("cached schema");
            assert_eq!(again.digest(), first.digest());
            assert_eq!(again.canonical_json(), first.canonical_json());
        }
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "cached schema lookups re-parsed; elapsed {:?}",
            started.elapsed()
        );

        // Same-length in-place rewrite with mtime restored. A length+mtime
        // cache would keep serving the remembered schema.
        std::fs::write(&path, bytes_b).expect("rewrite schema");
        restore_mtime(&path, original_mtime);
        let rewritten = std::fs::metadata(&path).expect("stat rewrite");
        assert_eq!(rewritten.len(), original.len());
        assert_eq!(rewritten.modified().expect("mtime"), original_mtime);
        {
            let cache = catalog.cache();
            let hit = cache.get(REFERENCE).expect("still cached");
            assert_eq!(hit.fingerprint.len, rewritten.len());
            assert_eq!(hit.fingerprint.mtime, rewritten.mtime());
            assert_eq!(hit.fingerprint.mtime_nsec, rewritten.mtime_nsec());
            assert_ne!(
                (hit.fingerprint.ctime, hit.fingerprint.ctime_nsec),
                (rewritten.ctime(), rewritten.ctime_nsec()),
                "in-place rewrite did not change ctime; this fixture would not pin the fingerprint"
            );
        }
        let changed = catalog.schema(REFERENCE).expect("changed schema reads");
        assert_eq!(changed.digest(), schema_of(bytes_b).digest());
        assert_ne!(changed.digest(), first.digest());
        assert_ne!(changed.digest(), sentinel.digest());

        // Timestamp-preserving replace: new inode, same length, mtime restored
        // to the value a length+mtime cache still holds.
        let sibling = root.join("schemas/tool.input.json.next");
        std::fs::write(&sibling, bytes_c).expect("write replacement");
        restore_mtime(&sibling, original_mtime);
        let sibling_meta = std::fs::metadata(&sibling).expect("stat replacement");
        {
            let cache = catalog.cache();
            let hit = cache.get(REFERENCE).expect("rewritten schema is cached");
            assert_eq!(hit.fingerprint.len, sibling_meta.len());
            assert_eq!(hit.fingerprint.mtime, sibling_meta.mtime());
            assert_eq!(hit.fingerprint.mtime_nsec, sibling_meta.mtime_nsec());
            assert_ne!(
                hit.fingerprint.inode,
                sibling_meta.ino(),
                "rename replacement reused the inode; this fixture would not pin inode"
            );
        }
        std::fs::rename(&sibling, &path).expect("replace schema");
        let replaced = catalog.schema(REFERENCE).expect("replaced schema reads");
        assert_eq!(replaced.digest(), schema_of(bytes_c).digest());

        std::fs::remove_file(&path).expect("remove schema");
        let missing = catalog.schema(REFERENCE).expect_err("missing schema");
        let text = missing.to_string();
        assert!(
            text.contains("cannot read"),
            "miss path error text changed: {text}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
