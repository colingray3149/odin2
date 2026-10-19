#![forbid(unsafe_code)]
#![deny(dead_code)]

//! Source-derived index of Odin code, registry objects, and authoring skeletons.

pub mod code;
pub mod registry_map;
pub mod skeleton_catalog;

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::path::{Component, Path, PathBuf};

pub const ATLAS_SCHEMA: &str = "odin.atlas.v1";
pub const ATLAS_VERSION: u32 = 1;

const MAX_SOURCE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SourceClass {
    Rust,
    TypeScript,
    Registry,
    Skeleton,
}

impl SourceClass {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::TypeScript => "typescript",
            Self::Registry => "registry",
            Self::Skeleton => "skeleton",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtlasSources {
    pub root: PathBuf,
    pub rust: PathBuf,
    pub typescript: PathBuf,
    pub registry: PathBuf,
    pub skeletons: PathBuf,
}

impl AtlasSources {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            rust: PathBuf::from("crates"),
            typescript: PathBuf::from("extension"),
            registry: PathBuf::from("registry"),
            skeletons: PathBuf::from("skeletons"),
            root,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtlasFile {
    pub source_class: SourceClass,
    pub path: String,
    pub blake3: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtlasParseError {
    pub source_class: SourceClass,
    pub path: String,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AtlasNode {
    pub id: String,
    pub source_class: SourceClass,
    pub path: String,
    pub source_blake3: String,
    pub name: String,
    pub kind: String,
    pub signature: Option<String>,
    pub summary: Option<String>,
    pub properties: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SourceCounts {
    pub files: usize,
    pub nodes: usize,
    pub parse_errors: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtlasCounts {
    pub files: usize,
    pub nodes: usize,
    pub parse_errors: usize,
    pub by_source: BTreeMap<SourceClass, SourceCounts>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Atlas {
    pub schema: String,
    pub version: u32,
    pub generation: String,
    pub source_paths: BTreeMap<SourceClass, String>,
    pub source_hashes: BTreeMap<SourceClass, String>,
    pub counts: AtlasCounts,
    pub files: Vec<AtlasFile>,
    pub parse_errors: Vec<AtlasParseError>,
    pub nodes: Vec<AtlasNode>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AtlasScope {
    pub source_classes: BTreeSet<SourceClass>,
    pub path_prefixes: Vec<String>,
    pub node_prefixes: Vec<String>,
    pub seat_categories: Option<BTreeSet<String>>,
}

impl AtlasScope {
    pub fn all() -> Self {
        Self::default()
    }

    pub fn source(source_class: SourceClass) -> Self {
        Self {
            source_classes: BTreeSet::from([source_class]),
            path_prefixes: Vec::new(),
            node_prefixes: Vec::new(),
            seat_categories: None,
        }
    }

    pub fn paths(path_prefixes: impl IntoIterator<Item = String>) -> Result<Self, AtlasError> {
        let mut normalized = Vec::new();
        for prefix in path_prefixes {
            normalized.push(normalize_scope_prefix(&prefix)?);
        }
        normalized.sort();
        normalized.dedup();
        Ok(Self {
            source_classes: BTreeSet::new(),
            path_prefixes: normalized,
            node_prefixes: Vec::new(),
            seat_categories: None,
        })
    }

    pub fn nodes(node_prefixes: impl IntoIterator<Item = String>) -> Result<Self, AtlasError> {
        let mut normalized = Vec::new();
        for prefix in node_prefixes {
            if prefix.is_empty()
                || prefix
                    .chars()
                    .any(|character| character.is_control() || character.is_whitespace())
            {
                return Err(AtlasError::InvalidScope(prefix));
            }
            normalized.push(prefix);
        }
        normalized.sort();
        normalized.dedup();
        Ok(Self {
            source_classes: BTreeSet::new(),
            path_prefixes: Vec::new(),
            node_prefixes: normalized,
            seat_categories: None,
        })
    }

    pub fn seat(categories: impl IntoIterator<Item = String>) -> Result<Self, AtlasError> {
        let mut normalized = BTreeSet::new();
        for category in categories {
            if category.is_empty()
                || category
                    .chars()
                    .any(|character| character.is_control() || character.is_whitespace())
            {
                return Err(AtlasError::InvalidScope(category));
            }
            normalized.insert(category);
        }
        Ok(Self {
            source_classes: BTreeSet::new(),
            path_prefixes: Vec::new(),
            node_prefixes: Vec::new(),
            seat_categories: Some(normalized),
        })
    }

    pub fn with_sources(mut self, source_classes: impl IntoIterator<Item = SourceClass>) -> Self {
        self.source_classes = source_classes.into_iter().collect();
        self
    }

    pub fn with_paths(
        mut self,
        path_prefixes: impl IntoIterator<Item = String>,
    ) -> Result<Self, AtlasError> {
        self.path_prefixes = Self::paths(path_prefixes)?.path_prefixes;
        Ok(self)
    }

    pub fn with_nodes(
        mut self,
        node_prefixes: impl IntoIterator<Item = String>,
    ) -> Result<Self, AtlasError> {
        self.node_prefixes = Self::nodes(node_prefixes)?.node_prefixes;
        Ok(self)
    }

    fn includes(&self, node: &AtlasNode) -> bool {
        let source_matches =
            self.source_classes.is_empty() || self.source_classes.contains(&node.source_class);
        let path_matches = self.path_prefixes.is_empty()
            || self.path_prefixes.iter().any(|prefix| {
                let path = node.path.as_str();
                path == prefix
                    || path
                        .strip_prefix(prefix.as_str())
                        .is_some_and(|rest| rest.starts_with('/'))
            });
        let node_matches = self.node_prefixes.is_empty()
            || self.node_prefixes.iter().any(|prefix| {
                node.id.as_str() == prefix
                    || node
                        .id
                        .strip_prefix(prefix)
                        .is_some_and(|suffix| suffix.starts_with(':') || suffix.starts_with('#'))
            });
        let seat_matches = self.seat_categories.as_ref().is_none_or(|categories| {
            categories.contains("*")
                || node.properties.get("scope_tags").is_none_or(|tags| {
                    tags.as_array().is_some_and(|tags| {
                        tags.is_empty()
                            || tags.iter().any(|tag| {
                                tag.as_str()
                                    .is_some_and(|tag| tag == "*" || categories.contains(tag))
                            })
                    })
                })
        });
        source_matches && path_matches && node_matches && seat_matches
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Subtree {
    pub schema: String,
    pub generation: String,
    pub source_revisions: BTreeMap<SourceClass, String>,
    pub scope: AtlasScope,
    pub nodes: Vec<AtlasNode>,
}

impl Subtree {
    pub fn to_json(&self) -> Value {
        object([
            ("generation", Value::String(self.generation.clone())),
            (
                "nodes",
                Value::Array(self.nodes.iter().map(node_json).collect()),
            ),
            ("schema", Value::String(self.schema.clone())),
            (
                "source_revisions",
                Value::Object(
                    self.source_revisions
                        .iter()
                        .map(|(class, revision)| {
                            (class.as_str().to_owned(), Value::String(revision.clone()))
                        })
                        .collect(),
                ),
            ),
            (
                "scope",
                object([
                    (
                        "node_prefixes",
                        Value::Array(
                            self.scope
                                .node_prefixes
                                .iter()
                                .cloned()
                                .map(Value::String)
                                .collect(),
                        ),
                    ),
                    (
                        "path_prefixes",
                        Value::Array(
                            self.scope
                                .path_prefixes
                                .iter()
                                .cloned()
                                .map(Value::String)
                                .collect(),
                        ),
                    ),
                    (
                        "source_classes",
                        Value::Array(
                            self.scope
                                .source_classes
                                .iter()
                                .map(|class| Value::String(class.as_str().to_owned()))
                                .collect(),
                        ),
                    ),
                    (
                        "seat_categories",
                        self.scope
                            .seat_categories
                            .as_ref()
                            .map_or(Value::Null, |categories| {
                                Value::Array(
                                    categories.iter().cloned().map(Value::String).collect(),
                                )
                            }),
                    ),
                ]),
            ),
        ])
    }
}

impl Atlas {
    pub fn query(&self, scope: &AtlasScope) -> Subtree {
        let source_revisions = self
            .source_hashes
            .iter()
            .filter(|(source_class, _)| {
                scope.source_classes.is_empty() || scope.source_classes.contains(*source_class)
            })
            .map(|(source_class, revision)| (*source_class, revision.clone()))
            .collect();
        Subtree {
            schema: self.schema.clone(),
            generation: self.generation.clone(),
            source_revisions,
            scope: scope.clone(),
            nodes: self
                .nodes
                .iter()
                .filter(|node| scope.includes(node))
                .cloned()
                .collect(),
        }
    }

    pub fn to_json(&self) -> Value {
        let source_paths = self
            .source_paths
            .iter()
            .map(|(class, path)| (class.as_str().to_owned(), Value::String(path.clone())))
            .collect();
        let source_hashes = self
            .source_hashes
            .iter()
            .map(|(class, hash)| (class.as_str().to_owned(), Value::String(hash.clone())))
            .collect();
        let by_source = self
            .counts
            .by_source
            .iter()
            .map(|(class, counts)| {
                (
                    class.as_str().to_owned(),
                    object([
                        ("files", Value::from(counts.files)),
                        ("nodes", Value::from(counts.nodes)),
                        ("parse_errors", Value::from(counts.parse_errors)),
                    ]),
                )
            })
            .collect();
        object([
            (
                "counts",
                object([
                    ("by_source", Value::Object(by_source)),
                    ("files", Value::from(self.counts.files)),
                    ("nodes", Value::from(self.counts.nodes)),
                    ("parse_errors", Value::from(self.counts.parse_errors)),
                ]),
            ),
            (
                "files",
                Value::Array(self.files.iter().map(file_json).collect()),
            ),
            ("generation", Value::String(self.generation.clone())),
            (
                "nodes",
                Value::Array(self.nodes.iter().map(node_json).collect()),
            ),
            (
                "parse_errors",
                Value::Array(self.parse_errors.iter().map(parse_error_json).collect()),
            ),
            ("schema", Value::String(self.schema.clone())),
            ("source_hashes", Value::Object(source_hashes)),
            ("source_paths", Value::Object(source_paths)),
            ("version", Value::from(self.version)),
        ])
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, AtlasError> {
        let mut bytes = serde_json::to_vec_pretty(&self.to_json())
            .map_err(|error| AtlasError::Serialize(error.to_string()))?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

#[derive(Debug)]
pub enum AtlasError {
    InvalidRoot {
        path: PathBuf,
        detail: String,
    },
    PathEscape {
        path: PathBuf,
        root: PathBuf,
    },
    InvalidScope(String),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Serialize(String),
}

impl Display for AtlasError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRoot { path, detail } => {
                write!(
                    formatter,
                    "invalid atlas source root {}: {detail}",
                    path.display()
                )
            }
            Self::PathEscape { path, root } => write!(
                formatter,
                "atlas path {} escapes source root {}",
                path.display(),
                root.display()
            ),
            Self::InvalidScope(scope) => write!(formatter, "invalid atlas scope path {scope:?}"),
            Self::Io { path, source } => {
                write!(
                    formatter,
                    "atlas I/O failed for {}: {source}",
                    path.display()
                )
            }
            Self::Serialize(detail) => write!(formatter, "atlas serialization failed: {detail}"),
        }
    }
}

impl Error for AtlasError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub fn build(sources: impl Into<AtlasSources>) -> Result<Atlas, AtlasError> {
    let sources = ResolvedSources::resolve(sources.into())?;
    let rust = code::scan_rust(&sources.root, &sources.rust);
    let typescript = code::scan_typescript(&sources.root, &sources.typescript);
    let registry = registry_map::scan(&sources.root, &sources.registry);
    let skeletons = skeleton_catalog::scan(&sources.root, &sources.skeletons);
    let scans = [rust, typescript, registry, skeletons];

    let mut files = Vec::new();
    let mut parse_errors = Vec::new();
    let mut nodes = Vec::new();
    for mut scan in scans {
        files.append(&mut scan.files);
        parse_errors.append(&mut scan.parse_errors);
        nodes.append(&mut scan.nodes);
    }
    files.sort_by(|left, right| {
        (left.source_class, &left.path).cmp(&(right.source_class, &right.path))
    });
    parse_errors.sort_by(|left, right| {
        (left.source_class, &left.path, &left.message).cmp(&(
            right.source_class,
            &right.path,
            &right.message,
        ))
    });
    nodes.sort_by(|left, right| {
        (&left.id, left.source_class, &left.path, &left.name).cmp(&(
            &right.id,
            right.source_class,
            &right.path,
            &right.name,
        ))
    });

    let source_hashes = source_hashes(&files);
    let generation = generation_hash(&source_hashes, &parse_errors, &nodes);
    let counts = counts(&files, &parse_errors, &nodes);
    Ok(Atlas {
        schema: ATLAS_SCHEMA.to_owned(),
        version: ATLAS_VERSION,
        generation,
        source_paths: sources.source_paths,
        source_hashes,
        counts,
        files,
        parse_errors,
        nodes,
    })
}

#[derive(Debug)]
pub(crate) struct ScannedClass {
    pub(crate) files: Vec<AtlasFile>,
    pub(crate) parse_errors: Vec<AtlasParseError>,
    pub(crate) nodes: Vec<AtlasNode>,
}

impl ScannedClass {
    pub(crate) fn new() -> Self {
        Self {
            files: Vec::new(),
            parse_errors: Vec::new(),
            nodes: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct SourceInput {
    pub(crate) relative: String,
    pub(crate) hash: String,
    pub(crate) text: String,
}

pub(crate) fn load_text_sources(
    root: &Path,
    source_root: &Path,
    source_class: SourceClass,
    extensions: &[&str],
) -> (ScannedClass, Vec<SourceInput>) {
    let mut scan = ScannedClass::new();
    let mut candidates = Vec::new();
    // Exclude installed packages without hiding registry or skeleton objects with the same name.
    let mut walk = walkdir::WalkDir::new(source_root)
        .follow_links(false)
        .into_iter();
    while let Some(entry) = walk.next() {
        match entry {
            Ok(entry) => {
                if matches!(source_class, SourceClass::Rust | SourceClass::TypeScript)
                    && entry.file_type().is_dir()
                    && entry.file_name() == "node_modules"
                {
                    walk.skip_current_dir();
                    continue;
                }
                let path = entry.path();
                let matches = path
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| extensions.contains(&extension));
                if entry.file_type().is_symlink() {
                    let message = if matches {
                        Some("symlink source entry is not followed".to_owned())
                    } else {
                        match path.canonicalize() {
                            Ok(canonical) if canonical.starts_with(root) => None,
                            Ok(canonical) => Some(format!(
                                "source symlink resolves outside configured root: {}",
                                canonical.display()
                            )),
                            Err(error) => {
                                Some(format!("source symlink resolution failed: {error}"))
                            }
                        }
                    };
                    if let Some(message) = message {
                        scan.parse_errors.push(AtlasParseError {
                            source_class,
                            path: display_relative(root, path),
                            message,
                        });
                    }
                    continue;
                }
                if entry.file_type().is_file() && matches {
                    candidates.push(path.to_path_buf());
                }
            }
            Err(error) => {
                let path = error
                    .path()
                    .map_or_else(|| source_root.to_path_buf(), Path::to_path_buf);
                scan.parse_errors.push(AtlasParseError {
                    source_class,
                    path: display_relative(root, &path),
                    message: format!("source walk failed: {error}"),
                });
            }
        }
    }
    candidates.sort();

    let mut inputs = Vec::new();
    for path in candidates {
        let relative = display_relative(root, &path);
        let confined = match path.canonicalize() {
            Ok(canonical) if canonical.starts_with(root) && canonical.starts_with(source_root) => {
                canonical
            }
            Ok(canonical) => {
                scan.files.push(AtlasFile {
                    source_class,
                    path: relative.clone(),
                    blake3: None,
                });
                scan.parse_errors.push(AtlasParseError {
                    source_class,
                    path: relative,
                    message: format!(
                        "source path resolves outside configured root: {}",
                        canonical.display()
                    ),
                });
                continue;
            }
            Err(error) => {
                scan.files.push(AtlasFile {
                    source_class,
                    path: relative.clone(),
                    blake3: None,
                });
                scan.parse_errors.push(AtlasParseError {
                    source_class,
                    path: relative,
                    message: format!("source path resolution failed: {error}"),
                });
                continue;
            }
        };
        let metadata = match fs::metadata(&confined) {
            Ok(metadata) => metadata,
            Err(error) => {
                scan.files.push(AtlasFile {
                    source_class,
                    path: relative.clone(),
                    blake3: None,
                });
                scan.parse_errors.push(AtlasParseError {
                    source_class,
                    path: relative,
                    message: format!("source metadata read failed: {error}"),
                });
                continue;
            }
        };
        if metadata.len() > MAX_SOURCE_BYTES {
            scan.files.push(AtlasFile {
                source_class,
                path: relative.clone(),
                blake3: None,
            });
            scan.parse_errors.push(AtlasParseError {
                source_class,
                path: relative,
                message: format!("source exceeds {} byte atlas input bound", MAX_SOURCE_BYTES),
            });
            continue;
        }
        let bytes = match fs::read(&confined) {
            Ok(bytes) => bytes,
            Err(error) => {
                scan.files.push(AtlasFile {
                    source_class,
                    path: relative.clone(),
                    blake3: None,
                });
                scan.parse_errors.push(AtlasParseError {
                    source_class,
                    path: relative,
                    message: format!("source read failed: {error}"),
                });
                continue;
            }
        };
        let hash = blake3::hash(&bytes).to_hex().to_string();
        scan.files.push(AtlasFile {
            source_class,
            path: relative.clone(),
            blake3: Some(hash.clone()),
        });
        match String::from_utf8(bytes) {
            Ok(text) => inputs.push(SourceInput {
                relative,
                hash,
                text,
            }),
            Err(error) => scan.parse_errors.push(AtlasParseError {
                source_class,
                path: relative,
                message: format!("source is not UTF-8: {error}"),
            }),
        }
    }
    (scan, inputs)
}

pub(crate) fn object<const N: usize>(entries: [(&str, Value); N]) -> Value {
    Value::Object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn file_json(file: &AtlasFile) -> Value {
    object([
        (
            "blake3",
            file.blake3
                .as_ref()
                .map_or(Value::Null, |hash| Value::String(hash.clone())),
        ),
        ("path", Value::String(file.path.clone())),
        (
            "source_class",
            Value::String(file.source_class.as_str().to_owned()),
        ),
    ])
}

fn parse_error_json(error: &AtlasParseError) -> Value {
    object([
        ("message", Value::String(error.message.clone())),
        ("path", Value::String(error.path.clone())),
        (
            "source_class",
            Value::String(error.source_class.as_str().to_owned()),
        ),
    ])
}

fn node_json(node: &AtlasNode) -> Value {
    object([
        ("id", Value::String(node.id.clone())),
        ("kind", Value::String(node.kind.clone())),
        ("name", Value::String(node.name.clone())),
        ("path", Value::String(node.path.clone())),
        (
            "properties",
            Value::Object(node.properties.clone().into_iter().collect()),
        ),
        (
            "signature",
            node.signature
                .as_ref()
                .map_or(Value::Null, |value| Value::String(value.clone())),
        ),
        ("source_blake3", Value::String(node.source_blake3.clone())),
        (
            "source_class",
            Value::String(node.source_class.as_str().to_owned()),
        ),
        (
            "summary",
            node.summary
                .as_ref()
                .map_or(Value::Null, |value| Value::String(value.clone())),
        ),
    ])
}

fn source_hashes(files: &[AtlasFile]) -> BTreeMap<SourceClass, String> {
    [
        SourceClass::Rust,
        SourceClass::TypeScript,
        SourceClass::Registry,
        SourceClass::Skeleton,
    ]
    .into_iter()
    .map(|source_class| {
        let mut hasher = blake3::Hasher::new();
        for file in files
            .iter()
            .filter(|file| file.source_class == source_class)
        {
            hasher.update(file.path.as_bytes());
            hasher.update(&[0]);
            hasher.update(file.blake3.as_deref().unwrap_or("<unreadable>").as_bytes());
            hasher.update(&[0]);
        }
        (source_class, hasher.finalize().to_hex().to_string())
    })
    .collect()
}

fn generation_hash(
    source_hashes: &BTreeMap<SourceClass, String>,
    parse_errors: &[AtlasParseError],
    nodes: &[AtlasNode],
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ATLAS_SCHEMA.as_bytes());
    hasher.update(&ATLAS_VERSION.to_le_bytes());
    for (source_class, hash) in source_hashes {
        hasher.update(source_class.as_str().as_bytes());
        hasher.update(&[0]);
        hasher.update(hash.as_bytes());
        hasher.update(&[0]);
    }
    for error in parse_errors {
        hasher.update(parse_error_json(error).to_string().as_bytes());
        hasher.update(&[0]);
    }
    for node in nodes {
        hasher.update(node_json(node).to_string().as_bytes());
        hasher.update(&[0]);
    }
    hasher.finalize().to_hex().to_string()
}

fn counts(
    files: &[AtlasFile],
    parse_errors: &[AtlasParseError],
    nodes: &[AtlasNode],
) -> AtlasCounts {
    let by_source = [
        SourceClass::Rust,
        SourceClass::TypeScript,
        SourceClass::Registry,
        SourceClass::Skeleton,
    ]
    .into_iter()
    .map(|source_class| {
        (
            source_class,
            SourceCounts {
                files: files
                    .iter()
                    .filter(|file| file.source_class == source_class)
                    .count(),
                nodes: nodes
                    .iter()
                    .filter(|node| node.source_class == source_class)
                    .count(),
                parse_errors: parse_errors
                    .iter()
                    .filter(|error| error.source_class == source_class)
                    .count(),
            },
        )
    })
    .collect();
    AtlasCounts {
        files: files.len(),
        nodes: nodes.len(),
        parse_errors: parse_errors.len(),
        by_source,
    }
}

#[derive(Debug)]
struct ResolvedSources {
    root: PathBuf,
    rust: PathBuf,
    typescript: PathBuf,
    registry: PathBuf,
    skeletons: PathBuf,
    source_paths: BTreeMap<SourceClass, String>,
}

impl ResolvedSources {
    fn resolve(sources: AtlasSources) -> Result<Self, AtlasError> {
        let root = sources
            .root
            .canonicalize()
            .map_err(|error| AtlasError::InvalidRoot {
                path: sources.root.clone(),
                detail: error.to_string(),
            })?;
        if !root.is_dir() {
            return Err(AtlasError::InvalidRoot {
                path: root,
                detail: "root is not a directory".to_owned(),
            });
        }
        let rust = resolve_source(&root, &sources.rust)?;
        let typescript = resolve_source(&root, &sources.typescript)?;
        let registry = resolve_source(&root, &sources.registry)?;
        let skeletons = resolve_source(&root, &sources.skeletons)?;
        let source_paths = [
            (SourceClass::Rust, display_relative(&root, &rust)),
            (
                SourceClass::TypeScript,
                display_relative(&root, &typescript),
            ),
            (SourceClass::Registry, display_relative(&root, &registry)),
            (SourceClass::Skeleton, display_relative(&root, &skeletons)),
        ]
        .into_iter()
        .collect();
        Ok(Self {
            root,
            rust,
            typescript,
            registry,
            skeletons,
            source_paths,
        })
    }
}

fn resolve_source(root: &Path, configured: &Path) -> Result<PathBuf, AtlasError> {
    let candidate = if configured.is_absolute() {
        configured.to_path_buf()
    } else {
        root.join(configured)
    };
    let canonical = candidate
        .canonicalize()
        .map_err(|error| AtlasError::InvalidRoot {
            path: candidate.clone(),
            detail: error.to_string(),
        })?;
    if !canonical.is_dir() {
        return Err(AtlasError::InvalidRoot {
            path: canonical,
            detail: "source is not a directory".to_owned(),
        });
    }
    if !canonical.starts_with(root) {
        return Err(AtlasError::PathEscape {
            path: canonical,
            root: root.to_path_buf(),
        });
    }
    Ok(canonical)
}

fn display_relative(root: &Path, path: &Path) -> String {
    let relative = path.strip_prefix(root).unwrap_or(path);
    relative
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().into_owned()),
            Component::ParentDir => Some("..".to_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn normalize_scope_prefix(prefix: &str) -> Result<String, AtlasError> {
    let path = Path::new(prefix);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(AtlasError::InvalidScope(prefix.to_owned()));
    }
    let normalized = display_relative(Path::new(""), path);
    if normalized.is_empty() {
        return Err(AtlasError::InvalidScope(prefix.to_owned()));
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::{build, AtlasScope, AtlasSources, SourceClass};
    use serde_json::Value;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    fn fixture_root(label: &str) -> PathBuf {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "odin-atlas-lib-{label}-{}-{sequence}",
            std::process::id()
        ));
        for directory in ["crates/demo/src", "extension", "registry", "skeletons"] {
            fs::create_dir_all(root.join(directory)).expect("create atlas fixture directory");
        }
        fs::write(
            root.join("crates/demo/src/lib.rs"),
            "pub fn stable(value: u64) -> u64 { value }\n",
        )
        .expect("write Rust fixture");
        fs::write(
            root.join("extension/index.ts"),
            r#"
                export interface PublicShape { value: string }
                export const first = 1, second = 2;
            "#,
        )
        .expect("write TypeScript fixture");
        root
    }

    #[test]
    fn identical_sources_rebuild_to_identical_graph_and_revision() {
        let root = fixture_root("stable");
        let first = build(AtlasSources::new(&root)).expect("build first atlas");
        let second = build(AtlasSources::new(&root)).expect("build second atlas");

        assert_eq!(first.generation, second.generation);
        assert_eq!(first.source_hashes, second.source_hashes);
        assert_eq!(first.nodes, second.nodes);
        assert_eq!(
            first.to_bytes().expect("serialize first atlas"),
            second.to_bytes().expect("serialize second atlas")
        );

        fs::remove_dir_all(root).expect("remove stable atlas fixture");
    }

    #[test]
    fn installed_packages_are_not_code_but_declared_objects_and_target_modules_remain() {
        let root = fixture_root("deps");
        fs::create_dir_all(root.join("extension/node_modules/pkg")).expect("package dir");
        fs::write(
            root.join("extension/node_modules/pkg/generated.d.ts"),
            "export const dependency_only_symbol = 1;\n",
        )
        .expect("write dependency source");
        fs::create_dir_all(root.join("extension/target")).expect("source directory");
        fs::write(
            root.join("extension/target/own.ts"),
            "export const target_source_symbol = 1;\n",
        )
        .expect("write project source");
        fs::create_dir_all(root.join("registry/projects/node_modules"))
            .expect("declared project directory");
        fs::write(
            root.join("registry/projects/node_modules/project.toml"),
            "schema = \"odin.registry.v1\"\nkind = \"project\"\nenabled = true\n\
             description = \"An ordinary declared project\"\nsource_root = \"\"\n\
             default_seat = \"reader\"\nmemory_namespaces = []\nartifact_policy = \"standard\"\n",
        )
        .expect("write declared project");
        let atlas = build(AtlasSources::new(&root)).expect("build atlas");
        let names = atlas
            .nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>();
        assert!(
            names.contains(&"PublicShape"),
            "declared extension source is still indexed: {names:?}"
        );
        assert!(
            !names.contains(&"dependency_only_symbol"),
            "installed packages are not source: {names:?}"
        );
        assert!(
            names.contains(&"target_source_symbol"),
            "a project module named target remains source: {names:?}"
        );
        assert!(
            atlas.nodes.iter().any(|node| {
                node.source_class == SourceClass::Registry && node.name == "node_modules"
            }),
            "dependency pruning must not hide a declared project"
        );
        fs::remove_dir_all(root).expect("remove dependency fixture");
    }

    #[test]
    fn query_intersects_requested_tree_with_seat_categories() {
        let root = fixture_root("seat");
        let mut atlas = build(AtlasSources::new(&root)).expect("build scoped atlas");
        for node in &mut atlas.nodes {
            match node.name.as_str() {
                "PublicShape" => {
                    node.properties.insert(
                        "scope_tags".to_owned(),
                        Value::Array(vec![Value::String("coding".to_owned())]),
                    );
                }
                "first" => {
                    node.properties.insert(
                        "scope_tags".to_owned(),
                        Value::Array(vec![Value::String("operations".to_owned())]),
                    );
                }
                _ => {}
            }
        }
        let scope = AtlasScope::seat(["coding".to_owned()])
            .expect("valid seat category")
            .with_sources([SourceClass::TypeScript])
            .with_paths(["extension".to_owned()])
            .expect("valid path scope")
            .with_nodes(["typescript:extension_index".to_owned()])
            .expect("valid node scope");

        let subtree = atlas.query(&scope);
        let names = subtree
            .nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>();
        assert!(names.contains(&"PublicShape"));
        assert!(names.contains(&"second"));
        assert!(!names.contains(&"first"));
        assert!(!names.contains(&"stable"));
        assert_eq!(subtree.source_revisions.len(), 1);
        assert_eq!(
            subtree.source_revisions.get(&SourceClass::TypeScript),
            atlas.source_hashes.get(&SourceClass::TypeScript)
        );

        fs::remove_dir_all(root).expect("remove scoped atlas fixture");
    }
}
