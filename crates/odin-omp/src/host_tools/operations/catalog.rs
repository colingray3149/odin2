//! Schema and operation catalogs describe admission; they do not grant permission.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use odin_domain::knowledge::ToolSchema;
use odin_domain::{CapabilityId, Digest};
use odin_kernel::{
    AdmittedCapability, CapabilityContract, HandlerBinding, KernelError, KernelResult,
    OperationCatalog, SchemaCatalog,
};
use serde_json::Value;

use crate::host_tools::executor::internal_key_of;
use crate::host_tools::HostToolRegistry;

use super::{CompositionEquivalence, HostToolOperationError, RevisionMaterial};

/// Schemas resolved from the repository filesystem. Missing, escaping, or
/// undecodable references fail closed; there is no fallback source. A parsed
/// schema is kept until its file's length or modification time changes: the
/// listing reads every admitted schema on each dispatch.
pub struct FilesystemSchemaCatalog {
    root: PathBuf,
    cache: Mutex<HashMap<String, CachedSchema>>,
}

struct CachedSchema {
    len: u64,
    modified: Option<SystemTime>,
    schema: ToolSchema,
}

impl FilesystemSchemaCatalog {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            cache: Mutex::new(HashMap::new()),
        }
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
        let stat = fs::metadata(&path)
            .ok()
            .map(|meta| (meta.len(), meta.modified().ok()));
        let cache = || {
            self.cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        };
        if let (Some((len, modified)), Some(hit)) = (stat, cache().get(reference)) {
            if hit.len == len && hit.modified == modified {
                return Ok(hit.schema.clone());
            }
        }
        let bytes = fs::read(&path).map_err(|error| {
            KernelError::Schema(format!("cannot read {}: {error}", path.display()))
        })?;
        let value = serde_json::from_slice(&bytes).map_err(|error| {
            KernelError::Schema(format!("cannot decode {}: {error}", path.display()))
        })?;
        let schema = ToolSchema::from_value(value).map_err(KernelError::from)?;
        if let Some((len, modified)) = stat {
            cache().insert(
                reference.to_owned(),
                CachedSchema {
                    len,
                    modified,
                    schema: schema.clone(),
                },
            );
        }
        Ok(schema)
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
    equivalence: Option<Arc<CompositionEquivalence>>,
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
    pub fn with_equivalence(mut self, equivalence: Arc<CompositionEquivalence>) -> Self {
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

/// One session's generation: the contracts and admission digest its token
/// binds, with handler resolution and operator ownership from the running host.
pub(super) struct GenerationCatalog<'a> {
    pub material: &'a RevisionMaterial,
    pub base: &'a dyn OperationCatalog,
}

impl OperationCatalog for GenerationCatalog<'_> {
    fn admitted(&self, capability: &CapabilityId) -> Option<AdmittedCapability> {
        if self.base.is_operator_owned(capability) {
            return None;
        }
        Some(AdmittedCapability {
            contract: self.material.contracts.get(capability)?.clone(),
            snapshot_revision: i64::try_from(self.material.revision).ok()?,
            snapshot_digest: self.material.admission_digest,
        })
    }

    fn resolves(&self, binding: &HandlerBinding) -> bool {
        self.base.resolves(binding)
    }

    fn is_operator_owned(&self, id: &CapabilityId) -> bool {
        self.base.is_operator_owned(id)
    }
}

/// Adds deployment constraints, such as per-seat project enums, after canonical validation.
/// Top-level `additionalProperties` is omitted because the host inserts derived arguments there.
/// The canonical schema still rejects unknown keys; nested constraints are retained.
pub(super) fn declared_narrowing_schema(
    tool_name: &str,
    mut narrowing: Value,
) -> Result<ToolSchema, HostToolOperationError> {
    if let Some(object) = narrowing.as_object_mut() {
        object.remove("additionalProperties");
    }
    ToolSchema::from_value(narrowing).map_err(|error| HostToolOperationError::Composition {
        detail: format!(
            "model surface of {} does not compile into an argument narrowing: {error}",
            tool_name
        ),
    })
}

#[cfg(test)]
mod schema_cache_tests {
    use odin_kernel::SchemaCatalog;

    use super::FilesystemSchemaCatalog;

    const REFERENCE: &str = "schemas/tool.input.json";

    #[test]
    fn a_schema_follows_its_file_and_a_missing_one_names_its_path() {
        let root = tempfile::tempdir().expect("schema root");
        std::fs::create_dir_all(root.path().join("schemas")).expect("schema dir");
        let path = root.path().join(REFERENCE);
        let catalog = FilesystemSchemaCatalog::new(root.path());

        std::fs::write(&path, br#"{"type":"object","title":"a"}"#).expect("write schema");
        let first = catalog.schema(REFERENCE).expect("schema reads");
        assert_eq!(
            catalog.schema(REFERENCE).expect("second read").digest(),
            first.digest()
        );

        std::fs::write(&path, br#"{"type":"object","title":"changed"}"#).expect("rewrite schema");
        let changed = catalog.schema(REFERENCE).expect("changed schema reads");
        assert_ne!(changed.digest(), first.digest());

        std::fs::remove_file(&path).expect("remove schema");
        let missing = catalog.schema(REFERENCE).expect_err("missing schema");
        assert!(missing.to_string().contains(REFERENCE), "{missing}");
    }
}
