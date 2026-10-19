//! `odin_atlas_query` — scope-filtered queries over the generated knowledge index.
//!
//! The tool is constructed with an immutable [`Atlas`] snapshot and one fixed
//! allowed [`AtlasScope`]. A request can only narrow that allowed scope: an
//! empty request means exactly the allowed scope, and any refinement that
//! would widen it — a foreign source class, a prefix outside the allowed
//! subtrees, a parent-relative escape, or a foreign seat category — is a
//! typed rejection before the index is read.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use odin_atlas::{Atlas, AtlasError, AtlasScope, SourceClass, Subtree};
use odin_domain::Scope;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::host_tools::{
    response, HostInvocation, HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode,
};

/// Answers scope-filtered atlas queries for the bound seat.
pub struct AtlasQueryTool {
    atlas: Arc<Atlas>,
    allowed: AtlasScope,
    definition: RpcHostToolDefinition,
}

/// One rejection reason for every attempted scope broadening.
const WIDENED_SCOPE: &str =
    "the request would widen the allowed atlas scope; only narrowing refinements are accepted";

impl AtlasQueryTool {
    pub const NAME: &str = "odin_atlas_query";

    /// Builds the tool over an immutable atlas snapshot and its fixed allowed
    /// scope.
    ///
    /// The allowed scope is re-validated through the atlas constructors so a
    /// hand-built scope cannot smuggle absolute or parent-relative prefixes.
    pub fn new(atlas: Arc<Atlas>, allowed: AtlasScope) -> Result<Self, AtlasError> {
        Ok(Self {
            atlas,
            allowed: Self::validated(allowed)?,
            definition: RpcHostToolDefinition {
                name: Cow::Borrowed(Self::NAME),
                label: Cow::Borrowed("Atlas Query"),
                description: Cow::Borrowed(
                    "Query the generated knowledge index within the scope granted to this session: source classes, path prefixes, node prefixes, and seat categories. Refinements can only narrow the granted scope; an empty query returns exactly that scope, and unknown fields or escaping paths are rejected.",
                ),
                parameters: parameters(),
                hidden: false,
                load_mode: ToolLoadMode::Essential,
            },
        })
    }

    fn scope(reason: &'static str) -> HostToolError {
        HostToolError::Scope {
            tool: Self::NAME,
            reason,
        }
    }

    fn arguments(detail: String) -> HostToolError {
        HostToolError::Arguments {
            tool: Self::NAME,
            detail,
        }
    }

    /// Rebuilds the scope through the validating atlas constructors.
    fn validated(scope: AtlasScope) -> Result<AtlasScope, AtlasError> {
        let path_prefixes = AtlasScope::paths(scope.path_prefixes)?.path_prefixes;
        let node_prefixes = AtlasScope::nodes(scope.node_prefixes)?.node_prefixes;
        let seat_categories = match scope.seat_categories {
            None => None,
            Some(categories) => Some(
                AtlasScope::seat(categories)?
                    .seat_categories
                    .unwrap_or_default(),
            ),
        };
        Ok(AtlasScope {
            source_classes: scope.source_classes,
            path_prefixes,
            node_prefixes,
            seat_categories,
        })
    }

    /// Narrows the allowed scope with the request. Every present refinement
    /// must stay inside the allowed restriction; absent refinements inherit
    /// the allowed value, so an empty request means exactly the allowed scope.
    fn narrowed(
        allowed: &AtlasScope,
        request: &AtlasQueryArguments,
    ) -> Result<AtlasScope, HostToolError> {
        let source_classes = if request.source_classes.is_empty() {
            allowed.source_classes.clone()
        } else {
            let mut requested = BTreeSet::new();
            for class in &request.source_classes {
                requested.insert(parse_source_class(class)?);
            }
            if !allowed.source_classes.is_empty() && !requested.is_subset(&allowed.source_classes) {
                return Err(Self::scope(WIDENED_SCOPE));
            }
            requested
        };

        let path_prefixes = if request.path_prefixes.is_empty() {
            allowed.path_prefixes.clone()
        } else {
            let requested = AtlasScope::paths(request.path_prefixes.clone())
                .map_err(|error| Self::arguments(error.to_string()))?
                .path_prefixes;
            if !allowed.path_prefixes.is_empty()
                && !requested.iter().all(|prefix| {
                    allowed
                        .path_prefixes
                        .iter()
                        .any(|allowed_prefix| path_within(prefix, allowed_prefix))
                })
            {
                return Err(Self::scope(WIDENED_SCOPE));
            }
            requested
        };

        let node_prefixes = if request.node_prefixes.is_empty() {
            allowed.node_prefixes.clone()
        } else {
            let requested = AtlasScope::nodes(request.node_prefixes.clone())
                .map_err(|error| Self::arguments(error.to_string()))?
                .node_prefixes;
            if !allowed.node_prefixes.is_empty()
                && !requested.iter().all(|prefix| {
                    allowed
                        .node_prefixes
                        .iter()
                        .any(|allowed_prefix| node_within(prefix, allowed_prefix))
                })
            {
                return Err(Self::scope(WIDENED_SCOPE));
            }
            requested
        };

        let seat_categories = match (&allowed.seat_categories, &request.seat_categories) {
            (None, None) => None,
            (None, Some(categories)) => Some(validated_categories(categories)?),
            (Some(allowed_categories), None) => Some(allowed_categories.clone()),
            (Some(allowed_categories), Some(categories)) => {
                let requested = validated_categories(categories)?;
                if !allowed_categories.contains("*") && !requested.is_subset(allowed_categories) {
                    return Err(Self::scope(WIDENED_SCOPE));
                }
                Some(requested)
            }
        };

        Ok(AtlasScope {
            source_classes,
            path_prefixes,
            node_prefixes,
            seat_categories,
        })
    }

    /// Shared seat, argument, and allowed-scope validation without querying the atlas.
    fn resolve(
        &self,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(AtlasQueryArguments, AtlasScope), HostToolError> {
        // The atlas is not ledger-backed: the bound seat is the only
        // authority this tool can prove, so an unbound scope is rejected.
        if scope.seat.is_none() {
            return Err(Self::scope("the invocation scope is not bound to a seat"));
        }
        let request: AtlasQueryArguments =
            serde_json::from_value(arguments.clone()).map_err(|error| {
                Self::arguments(format!(
                    "arguments violate the odin_atlas_query schema: {error}"
                ))
            })?;
        let narrowed = Self::narrowed(&self.allowed, &request)?;
        Ok((request, narrowed))
    }
}

impl HostTool for AtlasQueryTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn preflight(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        // Validate without querying; invocation repeats resolution.
        self.resolve(scope, arguments)?;
        Ok(())
    }

    fn invoke(&self, invocation: HostInvocation) -> Result<Value, HostToolError> {
        let (_request, scope) = self.resolve(&invocation.scope, &invocation.arguments)?;

        let subtree = self.atlas.query(&scope);
        response(Self::NAME, &AtlasQueryView::from(&subtree))
    }
}

fn parameters() -> Value {
    json!({
        "type": "object",
        "properties": {
            "sourceClasses": {
                "type": "array",
                "items": { "enum": ["rust", "typescript", "registry", "skeleton"] },
                "description": "Narrow to these source classes; omitted or empty keeps the allowed classes."
            },
            "pathPrefixes": {
                "type": "array",
                "items": { "type": "string", "minLength": 1 },
                "description": "Narrow to repository paths under these prefixes; each must stay inside the allowed prefixes."
            },
            "nodePrefixes": {
                "type": "array",
                "items": { "type": "string", "minLength": 1 },
                "description": "Narrow to atlas node ids under these prefixes; each must stay inside the allowed prefixes."
            },
            "seatCategories": {
                "type": "array",
                "items": { "type": "string", "minLength": 1 },
                "description": "Narrow to nodes carrying one of these seat-category tags; must stay inside the allowed categories."
            }
        },
        "additionalProperties": false
    })
}

fn parse_source_class(name: &str) -> Result<SourceClass, HostToolError> {
    match name {
        "rust" => Ok(SourceClass::Rust),
        "typescript" => Ok(SourceClass::TypeScript),
        "registry" => Ok(SourceClass::Registry),
        "skeleton" => Ok(SourceClass::Skeleton),
        other => Err(HostToolError::Arguments {
            tool: AtlasQueryTool::NAME,
            detail: format!(
                "unknown source class {other}; expected one of rust, typescript, registry, skeleton"
            ),
        }),
    }
}

/// Delegates seat-category validation to the atlas constructor so the rules
/// cannot drift from `AtlasScope::seat`.
fn validated_categories(categories: &[String]) -> Result<BTreeSet<String>, HostToolError> {
    let scoped =
        AtlasScope::seat(categories.to_vec()).map_err(|error| HostToolError::Arguments {
            tool: AtlasQueryTool::NAME,
            detail: error.to_string(),
        })?;
    Ok(scoped.seat_categories.unwrap_or_default())
}

/// True when every path matched by `prefix` is also matched by `allowed`:
/// the atlas matches a prefix itself or any deeper segment below it.
fn path_within(prefix: &str, allowed: &str) -> bool {
    prefix == allowed
        || prefix
            .strip_prefix(allowed)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// True when every node id matched by `prefix` is also matched by `allowed`:
/// the atlas matches a node id itself or any `:`/`#`-separated child below it.
fn node_within(prefix: &str, allowed: &str) -> bool {
    prefix == allowed
        || prefix
            .strip_prefix(allowed)
            .is_some_and(|rest| rest.starts_with(':') || rest.starts_with('#'))
}

/// The frozen `Subtree` projection plus generation and source revisions as
/// direct model-facing fields.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AtlasQueryView<'a> {
    generation: &'a str,
    source_revisions: BTreeMap<&'a str, &'a str>,
    subtree: Value,
}

impl<'a> From<&'a Subtree> for AtlasQueryView<'a> {
    fn from(subtree: &'a Subtree) -> Self {
        Self {
            generation: &subtree.generation,
            source_revisions: subtree
                .source_revisions
                .iter()
                .map(|(class, revision)| (class.as_str(), revision.as_str()))
                .collect(),
            subtree: subtree.to_json(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AtlasQueryArguments {
    #[serde(default)]
    source_classes: Vec<String>,
    #[serde(default)]
    path_prefixes: Vec<String>,
    #[serde(default)]
    node_prefixes: Vec<String>,
    #[serde(default)]
    seat_categories: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;

    use odin_atlas::{Atlas, AtlasError, AtlasScope, AtlasSources, SourceClass};
    use odin_domain::Scope;
    use serde_json::{json, Value};

    use super::AtlasQueryTool;
    use crate::host_tools::{HostInvocation, HostTool, HostToolError};

    const SEAT_ID: &str = "seat:1700000000000:atlas-query";

    /// Builds a small deterministic atlas: one Rust crate whose lib.rs
    /// declares a reachable public submodule, and one TypeScript module.
    /// All four `AtlasSources` roots exist; registry and skeletons stay empty.
    fn atlas_fixture(label: &str) -> (PathBuf, Atlas) {
        let root = std::env::temp_dir().join(format!(
            "odin-omp-atlas-query-{label}-{}",
            std::process::id()
        ));
        for directory in ["crates/demo/src", "extension", "registry", "skeletons"] {
            fs::create_dir_all(root.join(directory)).expect("create atlas fixture directory");
        }
        fs::write(
            root.join("crates/demo/src/lib.rs"),
            "pub mod other;\npub fn stable(value: u64) -> u64 { value }\n",
        )
        .expect("write Rust crate root fixture");
        fs::write(root.join("crates/demo/src/other.rs"), "pub fn extra() {}\n")
            .expect("write reachable submodule fixture");
        fs::write(
            root.join("extension/index.ts"),
            "export interface PublicShape { value: string }\n",
        )
        .expect("write TypeScript fixture");
        let atlas = odin_atlas::build(AtlasSources::new(&root)).expect("build atlas fixture");
        (root, atlas)
    }

    fn allowed_scope() -> Result<AtlasScope, AtlasError> {
        // Rust node ids use the module namespace (`rust:demo::…`), not the
        // repository path, so the allowed node prefix is the crate module.
        AtlasScope::seat(["coding".to_owned()])?
            .with_sources([SourceClass::Rust])
            .with_paths(["crates/demo".to_owned()])?
            .with_nodes(["rust:demo".to_owned()])
    }

    fn invocation(arguments: Value) -> HostInvocation {
        HostInvocation {
            scope: Scope {
                seat: Some(SEAT_ID.parse().expect("seat id")),
                ..Scope::default()
            },
            arguments,
        }
    }

    fn node_ids(result: &Value) -> BTreeSet<String> {
        result["subtree"]["nodes"]
            .as_array()
            .expect("subtree nodes array")
            .iter()
            .map(|node| node["id"].as_str().expect("node id").to_owned())
            .collect()
    }

    #[test]
    fn empty_request_returns_exactly_the_allowed_scope() {
        let (root, atlas) = atlas_fixture("empty");
        let allowed = allowed_scope().expect("valid allowed scope");
        let atlas = Arc::new(atlas);
        let tool = AtlasQueryTool::new(Arc::clone(&atlas), allowed.clone())
            .expect("the allowed scope validates");

        let first = tool
            .invoke(invocation(json!({})))
            .expect("an empty request is exactly the allowed scope");
        let repeated = tool
            .invoke(invocation(json!({})))
            .expect("repeated queries are idempotent");
        assert_eq!(first, repeated);

        // Never global authority: only the allowed source class appears, and
        // the subtree equals the frozen Atlas API output exactly.
        assert_eq!(
            first["subtree"],
            atlas.query(&allowed).to_json(),
            "the response is the allowed scope, not the whole atlas"
        );
        assert_eq!(first["generation"], first["subtree"]["generation"]);
        let revisions = first["sourceRevisions"]
            .as_object()
            .expect("source revisions object");
        assert_eq!(revisions.len(), 1);
        assert!(revisions.contains_key("rust"));
        for id in node_ids(&first) {
            assert!(
                id.starts_with("rust:"),
                "TypeScript knowledge must not leak"
            );
        }

        fs::remove_dir_all(root).expect("remove atlas fixture");
    }

    #[test]
    fn requests_cannot_broaden_the_allowed_scope() {
        let (root, atlas) = atlas_fixture("widen");
        let atlas = Arc::new(atlas);
        let tool = AtlasQueryTool::new(
            Arc::clone(&atlas),
            allowed_scope().expect("valid allowed scope"),
        )
        .expect("the allowed scope validates");

        for request in [
            json!({ "sourceClasses": ["typescript"] }),
            json!({ "pathPrefixes": ["extension"] }),
            json!({ "nodePrefixes": ["typescript:extension"] }),
            json!({ "seatCategories": ["operations"] }),
        ] {
            let error = tool
                .invoke(invocation(request))
                .expect_err("every broadening refinement must be rejected");
            assert!(
                matches!(
                    error,
                    HostToolError::Scope {
                        tool: AtlasQueryTool::NAME,
                        ..
                    }
                ),
                "a foreign refinement is a scope rejection"
            );
        }

        fs::remove_dir_all(root).expect("remove atlas fixture");
    }

    #[test]
    fn path_escapes_are_rejected_as_arguments() {
        let (root, atlas) = atlas_fixture("escape");
        let atlas = Arc::new(atlas);
        let tool = AtlasQueryTool::new(
            Arc::clone(&atlas),
            allowed_scope().expect("valid allowed scope"),
        )
        .expect("the allowed scope validates");

        let error = tool
            .invoke(invocation(json!({
                "pathPrefixes": ["crates/demo/../../extension"]
            })))
            .expect_err("a parent-relative escape must be rejected");

        assert!(matches!(
            error,
            HostToolError::Arguments {
                tool: AtlasQueryTool::NAME,
                ..
            }
        ));

        fs::remove_dir_all(root).expect("remove atlas fixture");
    }

    #[test]
    fn narrowing_refinements_are_accepted_and_strictly_smaller() {
        let (root, atlas) = atlas_fixture("narrow");
        let atlas = Arc::new(atlas);
        let tool = AtlasQueryTool::new(
            Arc::clone(&atlas),
            allowed_scope().expect("valid allowed scope"),
        )
        .expect("the allowed scope validates");

        let broad = tool
            .invoke(invocation(json!({})))
            .expect("the allowed scope queries");
        let narrowed = tool
            .invoke(invocation(json!({
                "pathPrefixes": ["crates/demo/src/lib.rs"]
            })))
            .expect("a refinement inside the allowed prefix narrows");

        let broad_ids = node_ids(&broad);
        let narrowed_ids = node_ids(&narrowed);
        assert!(narrowed_ids.len() < broad_ids.len());
        assert!(narrowed_ids.iter().all(|id| broad_ids.contains(id)));
        // Strict real narrowing: the broad query names the reachable
        // other-module node that the exact lib.rs refinement cuts, the
        // refinement keeps lib.rs's own symbol, and the result shrinks.
        assert!(broad_ids.contains("rust:demo::other::extra"));
        assert!(!narrowed_ids.contains("rust:demo::other::extra"));
        assert!(narrowed_ids.contains("rust:demo::stable"));

        for node in narrowed["subtree"]["nodes"]
            .as_array()
            .expect("subtree nodes array")
        {
            assert_eq!(
                node["path"].as_str().expect("node path"),
                "crates/demo/src/lib.rs",
                "every narrowed node must live in exactly lib.rs"
            );
        }

        fs::remove_dir_all(root).expect("remove atlas fixture");
    }

    #[test]
    fn unbound_scope_and_unknown_fields_are_rejected() {
        let (root, atlas) = atlas_fixture("unbound");
        let atlas = Arc::new(atlas);
        let tool = AtlasQueryTool::new(
            Arc::clone(&atlas),
            allowed_scope().expect("valid allowed scope"),
        )
        .expect("the allowed scope validates");

        let error = tool
            .invoke(HostInvocation {
                scope: Scope::default(),
                arguments: json!({}),
            })
            .expect_err("atlas authority requires a bound seat");
        assert!(matches!(
            error,
            HostToolError::Scope {
                tool: AtlasQueryTool::NAME,
                ..
            }
        ));

        let error = tool
            .invoke(invocation(json!({ "run": "run:1700000000000:smuggled" })))
            .expect_err("unknown fields must never smuggle a scope dimension");
        assert!(matches!(
            error,
            HostToolError::Arguments {
                tool: AtlasQueryTool::NAME,
                ..
            }
        ));

        fs::remove_dir_all(root).expect("remove atlas fixture");
    }

    #[test]
    fn hand_built_escape_scopes_are_rejected_at_construction() {
        let (root, atlas) = atlas_fixture("constructor");
        let escaped = AtlasScope {
            path_prefixes: vec!["crates/../secrets".to_owned()],
            ..AtlasScope::default()
        };

        let error = AtlasQueryTool::new(Arc::new(atlas), escaped)
            .err()
            .expect("a hand-built escape scope is rejected at construction");
        assert!(matches!(error, AtlasError::InvalidScope(_)));

        fs::remove_dir_all(root).expect("remove atlas fixture");
    }
}
