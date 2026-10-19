//! Cache parsed files by content and assemble parallel results in input order for deterministic output.

use super::rust_signature::{
    is_public, render_bounds, render_enum, render_generics, render_generics_without_where,
    render_signature, render_struct, render_trait_type, render_type, render_where,
};
use crate::{
    load_text_sources, AtlasNode, AtlasParseError, ScannedClass, SourceClass, SourceInput,
};
use rayon::prelude::*;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::{Arc, LazyLock, Mutex};
use syn::{ForeignItem, ImplItem, Item, ItemFn, ItemTrait, TraitItem, Type, UseTree};

const FRAGMENT_CACHE_MAX: usize = 16_384;
const FRAGMENT_CACHE_MAX_BYTES: usize = 64 * 1024 * 1024;
const PARSE_THREADS: usize = 8;

static FRAGMENTS: LazyLock<Mutex<FragmentCache>> = LazyLock::new(Mutex::default);
static PARSE_POOL: LazyLock<Option<rayon::ThreadPool>> = LazyLock::new(|| {
    rayon::ThreadPoolBuilder::new()
        .num_threads(PARSE_THREADS)
        .thread_name(|index| format!("atlas-parse-{index}"))
        .build()
        .ok()
});

/// Scopes are relative to the file's module so cached symbols can be reused at different paths.
pub(super) struct RawNode {
    scope: String,
    name: String,
    kind: &'static str,
    signature: String,
}

struct ChildModule {
    module: String,
    directory: String,
}

#[derive(Default)]
pub(crate) struct RustFragment {
    parse_error: Option<String>,
    nodes: Vec<RawNode>,
    children: Vec<ChildModule>,
}

#[derive(Default)]
struct FragmentCache {
    entries: HashMap<String, (Arc<RustFragment>, usize)>,
    oldest: VecDeque<String>,
    bytes: usize,
}

impl FragmentCache {
    fn insert(&mut self, key: String, fragment: Arc<RustFragment>) {
        if self.entries.contains_key(&key) {
            return;
        }
        let bytes = fragment.string_bytes();
        if bytes > FRAGMENT_CACHE_MAX_BYTES {
            return;
        }
        while self.entries.len() >= FRAGMENT_CACHE_MAX
            || self.bytes > FRAGMENT_CACHE_MAX_BYTES - bytes
        {
            let oldest = self.oldest.pop_front().expect("cache entry has an age");
            let (_, removed_bytes) = self
                .entries
                .remove(&oldest)
                .expect("cache age has an entry");
            self.bytes -= removed_bytes;
        }
        self.bytes += bytes;
        self.oldest.push_back(key.clone());
        self.entries.insert(key, (fragment, bytes));
    }
}

impl RustFragment {
    fn string_bytes(&self) -> usize {
        self.parse_error.as_ref().map_or(0, String::capacity)
            + self
                .nodes
                .iter()
                .map(|node| {
                    node.scope.capacity() + node.name.capacity() + node.signature.capacity()
                })
                .sum::<usize>()
            + self
                .children
                .iter()
                .map(|child| child.module.capacity() + child.directory.capacity())
                .sum::<usize>()
    }
}

fn fragment(text: &str) -> RustFragment {
    match syn::parse_file(text) {
        Ok(file) => {
            let mut fragment = RustFragment::default();
            scan_items(&file.items, "", &mut fragment.nodes);
            external_modules(&file.items, "", "", &mut fragment.children);
            fragment
        }
        Err(error) => RustFragment {
            parse_error: Some(format!("Rust parse failed: {error}")),
            ..RustFragment::default()
        },
    }
}

/// Preserve input order across cache hits and parallel parses.
fn fragments(inputs: &[SourceInput]) -> (Vec<Arc<RustFragment>>, usize) {
    let cached: Vec<Option<Arc<RustFragment>>> = {
        let cache = FRAGMENTS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inputs
            .iter()
            .map(|input| {
                cache
                    .entries
                    .get(&input.hash)
                    .map(|(fragment, _)| Arc::clone(fragment))
            })
            .collect()
    };
    let missing: Vec<usize> = (0..inputs.len())
        .filter(|index| cached[*index].is_none())
        .collect();
    let parse = || -> Vec<Arc<RustFragment>> {
        missing
            .par_iter()
            .map(|index| Arc::new(fragment(&inputs[*index].text)))
            .collect()
    };
    let parsed = match PARSE_POOL.as_ref() {
        Some(pool) => pool.install(parse),
        None => parse(),
    };
    let mut cache = FRAGMENTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for (index, fragment) in missing.iter().zip(&parsed) {
        cache.insert(inputs[*index].hash.clone(), Arc::clone(fragment));
    }
    tracing::debug!(
        entries = cache.entries.len(),
        string_bytes = cache.bytes,
        max_entries = FRAGMENT_CACHE_MAX,
        max_string_bytes = FRAGMENT_CACHE_MAX_BYTES,
        "atlas_fragment_cache"
    );
    drop(cache);
    let mut parsed = parsed.into_iter();
    let all = cached
        .into_iter()
        .map(|cached| cached.or_else(|| parsed.next()).unwrap_or_default())
        .collect();
    (all, missing.len())
}

struct RustScanState<'a> {
    parsed: &'a [(SourceInput, Arc<RustFragment>)],
    by_path: &'a BTreeMap<String, usize>,
    visited: &'a mut BTreeSet<usize>,
    occurrences: &'a mut BTreeMap<String, usize>,
    nodes: &'a mut Vec<AtlasNode>,
}

pub(crate) fn scan_rust(root: &std::path::Path, source_root: &std::path::Path) -> ScannedClass {
    let started = std::time::Instant::now();
    let (mut scan, inputs) = load_text_sources(root, source_root, SourceClass::Rust, &["rs"]);
    let (fragments, parsed_count) = fragments(&inputs);
    let mut parsed = Vec::new();
    for (input, fragment) in inputs.into_iter().zip(fragments) {
        match &fragment.parse_error {
            None => parsed.push((input, fragment)),
            Some(message) => scan.parse_errors.push(AtlasParseError {
                source_class: SourceClass::Rust,
                path: input.relative,
                message: message.clone(),
            }),
        }
    }

    let by_path = parsed
        .iter()
        .enumerate()
        .map(|(index, (input, _))| (input.relative.clone(), index))
        .collect::<BTreeMap<_, _>>();
    let roots = parsed
        .iter()
        .enumerate()
        .filter_map(|(index, (input, _))| {
            rust_crate_root(&input.relative).map(|(module, directory)| (index, module, directory))
        })
        .collect::<Vec<_>>();
    let mut occurrences = BTreeMap::new();
    let mut visited = BTreeSet::new();

    if roots.is_empty() {
        for (input, fragment) in &parsed {
            let module = rust_module_path(&input.relative);
            emit(fragment, &module, input, &mut occurrences, &mut scan.nodes);
        }
    } else {
        let mut state = RustScanState {
            parsed: &parsed,
            by_path: &by_path,
            visited: &mut visited,
            occurrences: &mut occurrences,
            nodes: &mut scan.nodes,
        };
        for (index, module, directory) in roots {
            scan_rust_module(index, &module, &directory, &mut state);
        }
    }
    tracing::debug!(
        files = by_path.len(),
        parsed = parsed_count,
        ms = started.elapsed().as_millis(),
        "rust scan"
    );
    scan
}

fn scan_rust_module(
    index: usize,
    module: &str,
    module_directory: &str,
    state: &mut RustScanState<'_>,
) {
    if !state.visited.insert(index) {
        return;
    }
    let parsed = state.parsed;
    let (input, fragment) = &parsed[index];
    emit(fragment, module, input, state.occurrences, state.nodes);
    for child in &fragment.children {
        let child_module = format!("{module}{}", child.module);
        let child_directory = if module_directory.is_empty() {
            child.directory.clone()
        } else {
            format!("{module_directory}/{}", child.directory)
        };
        let flat = format!("{child_directory}.rs");
        let nested = format!("{child_directory}/mod.rs");
        if let Some(index) = state
            .by_path
            .get(&flat)
            .or_else(|| state.by_path.get(&nested))
            .copied()
        {
            scan_rust_module(index, &child_module, &child_directory, state);
        }
    }
}

fn external_modules(
    items: &[Item],
    module: &str,
    directory: &str,
    children: &mut Vec<ChildModule>,
) {
    for item in items {
        let Item::Mod(item) = item else {
            continue;
        };
        if !is_public(&item.vis) {
            continue;
        }
        let name = item.ident.to_string();
        let child_module = format!("{module}::{name}");
        let child_directory = if directory.is_empty() {
            name.clone()
        } else {
            format!("{directory}/{name}")
        };
        match &item.content {
            Some((_, nested)) => {
                external_modules(nested, &child_module, &child_directory, children);
            }
            None => children.push(ChildModule {
                module: child_module,
                directory: child_directory,
            }),
        }
    }
}

/// Occurrence counts distinguish duplicate symbols in traversal order.
fn emit(
    fragment: &RustFragment,
    module: &str,
    input: &SourceInput,
    occurrences: &mut BTreeMap<String, usize>,
    nodes: &mut Vec<AtlasNode>,
) {
    for raw in &fragment.nodes {
        let module = format!("{module}{}", raw.scope);
        let name = &raw.name;
        let id = super::node_id(&format!("rust:{module}::{name}"), occurrences);
        let properties = BTreeMap::from([
            ("module".to_owned(), Value::String(module.clone())),
            ("parent".to_owned(), Value::String(format!("rust:{module}"))),
            (
                "qualified_name".to_owned(),
                Value::String(format!("{module}::{name}")),
            ),
            ("visibility".to_owned(), Value::String("public".to_owned())),
        ]);
        nodes.push(AtlasNode {
            id,
            source_class: SourceClass::Rust,
            path: input.relative.clone(),
            source_blake3: input.hash.clone(),
            name: name.clone(),
            kind: raw.kind.to_owned(),
            signature: Some(raw.signature.clone()),
            summary: None,
            properties,
        });
    }
}

fn rust_crate_root(relative: &str) -> Option<(String, String)> {
    let parts = relative.split('/').collect::<Vec<_>>();
    let crates = parts.iter().position(|part| *part == "crates")?;
    let crate_name = normalize_rust_component(parts.get(crates + 1)?);
    if parts.get(crates + 2) != Some(&"src") {
        return None;
    }
    let source = &parts[crates + 3..];
    let source_directory = parts[..crates + 3].join("/");
    let (module, directory) = match source {
        ["lib.rs" | "main.rs"] => (crate_name, source_directory),
        ["bin", file] if file.ends_with(".rs") => {
            let stem = file.trim_end_matches(".rs");
            let binary = normalize_rust_component(stem);
            (
                format!("{crate_name}::bin::{binary}"),
                format!("{source_directory}/bin/{stem}"),
            )
        }
        ["bin", directory, "main.rs"] => {
            let binary = normalize_rust_component(directory);
            (
                format!("{crate_name}::bin::{binary}"),
                format!("{source_directory}/bin/{directory}"),
            )
        }
        _ => return None,
    };
    Some((module, directory))
}

fn normalize_rust_component(component: &str) -> String {
    component.replace('-', "_")
}

fn scan_items(items: &[Item], module: &str, nodes: &mut Vec<RawNode>) {
    let local_types = items
        .iter()
        .filter_map(|item| match item {
            Item::Enum(item) => Some((item.ident.to_string(), is_public(&item.vis))),
            Item::Struct(item) => Some((item.ident.to_string(), is_public(&item.vis))),
            Item::Union(item) => Some((item.ident.to_string(), is_public(&item.vis))),
            Item::Type(item) => Some((item.ident.to_string(), is_public(&item.vis))),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    for item in items {
        match item {
            Item::Const(item) if is_public(&item.vis) => {
                let signature = format!(
                    "pub const {}{}: {}",
                    item.ident,
                    render_generics(&item.generics),
                    render_type(&item.ty)
                );
                push_rust_node(nodes, module, item.ident.to_string(), "const", signature);
            }
            Item::Enum(item) if is_public(&item.vis) => {
                push_rust_node(
                    nodes,
                    module,
                    item.ident.to_string(),
                    "enum",
                    render_enum(item),
                );
            }
            Item::ExternCrate(item) if is_public(&item.vis) => {
                let name = item
                    .rename
                    .as_ref()
                    .map_or_else(|| item.ident.to_string(), |(_, rename)| rename.to_string());
                let signature = item.rename.as_ref().map_or_else(
                    || format!("pub extern crate {}", item.ident),
                    |(_, rename)| format!("pub extern crate {} as {rename}", item.ident),
                );
                push_rust_node(nodes, module, name, "extern_crate", signature);
            }
            Item::Fn(item) if is_public(&item.vis) => {
                push_function(nodes, module, item);
            }
            Item::ForeignMod(item) => {
                for foreign in &item.items {
                    match foreign {
                        ForeignItem::Fn(function) if is_public(&function.vis) => push_rust_node(
                            nodes,
                            module,
                            function.sig.ident.to_string(),
                            "foreign_function",
                            format!("pub {}", render_signature(&function.sig)),
                        ),
                        ForeignItem::Static(value) if is_public(&value.vis) => {
                            let mutability =
                                if matches!(&value.mutability, syn::StaticMutability::Mut(_)) {
                                    " mut"
                                } else {
                                    ""
                                };
                            push_rust_node(
                                nodes,
                                module,
                                value.ident.to_string(),
                                "foreign_static",
                                format!(
                                    "pub static{mutability} {}: {}",
                                    value.ident,
                                    render_type(&value.ty)
                                ),
                            );
                        }
                        ForeignItem::Type(value) if is_public(&value.vis) => push_rust_node(
                            nodes,
                            module,
                            value.ident.to_string(),
                            "foreign_type",
                            format!(
                                "pub type {}{}",
                                value.ident,
                                render_generics(&value.generics)
                            ),
                        ),
                        _ => {}
                    }
                }
            }
            Item::Impl(item) if impl_has_public_surface(item, &local_types) => {
                let implementation = render_type(&item.self_ty);
                let impl_scope = format!("{module}::impl {implementation}");
                for member in &item.items {
                    match member {
                        ImplItem::Fn(function) if is_public(&function.vis) => push_rust_node(
                            nodes,
                            &impl_scope,
                            function.sig.ident.to_string(),
                            "method",
                            format!("pub {}", render_signature(&function.sig)),
                        ),
                        ImplItem::Const(value) if is_public(&value.vis) => push_rust_node(
                            nodes,
                            &impl_scope,
                            value.ident.to_string(),
                            "associated_const",
                            format!(
                                "pub const {}{}: {}",
                                value.ident,
                                render_generics(&value.generics),
                                render_type(&value.ty)
                            ),
                        ),
                        ImplItem::Type(value) if is_public(&value.vis) => push_rust_node(
                            nodes,
                            &impl_scope,
                            value.ident.to_string(),
                            "associated_type",
                            format!(
                                "pub type {}{} = {}",
                                value.ident,
                                render_generics(&value.generics),
                                render_type(&value.ty)
                            ),
                        ),
                        _ => {}
                    }
                }
            }
            Item::Macro(item)
                if item
                    .attrs
                    .iter()
                    .any(|attribute| attribute.path().is_ident("macro_export")) =>
            {
                if let Some(ident) = &item.ident {
                    let name = ident.to_string();
                    push_rust_node(
                        nodes,
                        module,
                        name.clone(),
                        "macro",
                        format!("#[macro_export] macro_rules! {name}"),
                    );
                }
            }
            Item::Mod(item) if is_public(&item.vis) => {
                let name = item.ident.to_string();
                push_rust_node(
                    nodes,
                    module,
                    name.clone(),
                    "module",
                    format!("pub mod {name}"),
                );
                if let Some((_, nested)) = &item.content {
                    scan_items(nested, &format!("{module}::{name}"), nodes);
                }
            }
            Item::Static(item) if is_public(&item.vis) => {
                let mutability = match &item.mutability {
                    syn::StaticMutability::Mut(_) => " mut",
                    syn::StaticMutability::None => "",
                    _ => "",
                };
                push_rust_node(
                    nodes,
                    module,
                    item.ident.to_string(),
                    "static",
                    format!(
                        "pub static{mutability} {}: {}",
                        item.ident,
                        render_type(&item.ty)
                    ),
                );
            }
            Item::Struct(item) if is_public(&item.vis) => {
                push_rust_node(
                    nodes,
                    module,
                    item.ident.to_string(),
                    "struct",
                    render_struct(item),
                );
            }
            Item::Trait(item) if is_public(&item.vis) => {
                push_trait(nodes, module, item);
            }
            Item::TraitAlias(item) if is_public(&item.vis) => {
                let bounds = render_bounds(item.bounds.iter());
                push_rust_node(
                    nodes,
                    module,
                    item.ident.to_string(),
                    "trait_alias",
                    format!(
                        "pub trait {}{} = {bounds}{}",
                        item.ident,
                        render_generics_without_where(&item.generics),
                        render_where(&item.generics)
                    ),
                );
            }
            Item::Type(item) if is_public(&item.vis) => {
                push_rust_node(
                    nodes,
                    module,
                    item.ident.to_string(),
                    "type",
                    format!(
                        "pub type {}{} = {}{}",
                        item.ident,
                        render_generics_without_where(&item.generics),
                        render_type(&item.ty),
                        render_where(&item.generics)
                    ),
                );
            }
            Item::Union(item) if is_public(&item.vis) => {
                let fields = item
                    .fields
                    .named
                    .iter()
                    .filter(|field| is_public(&field.vis))
                    .map(|field| {
                        format!(
                            "pub {}: {}",
                            field
                                .ident
                                .as_ref()
                                .map_or("_".to_owned(), ToString::to_string),
                            render_type(&field.ty)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                push_rust_node(
                    nodes,
                    module,
                    item.ident.to_string(),
                    "union",
                    format!(
                        "pub union {}{} {{ {fields} }}{}",
                        item.ident,
                        render_generics_without_where(&item.generics),
                        render_where(&item.generics)
                    ),
                );
            }
            Item::Use(item) if is_public(&item.vis) => {
                for (name, path) in flatten_use_tree(&item.tree, String::new()) {
                    push_rust_node(nodes, module, name, "reexport", format!("pub use {path}"));
                }
            }
            _ => {}
        }
    }
}

fn impl_has_public_surface(item: &syn::ItemImpl, local_types: &BTreeMap<String, bool>) -> bool {
    if item.trait_.is_some() {
        return false;
    }
    let Type::Path(implementation) = item.self_ty.as_ref() else {
        return true;
    };
    let Some(ident) = implementation
        .path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
    else {
        return true;
    };
    local_types.get(&ident).copied().unwrap_or(true)
}

fn push_function(nodes: &mut Vec<RawNode>, module: &str, item: &ItemFn) {
    push_rust_node(
        nodes,
        module,
        item.sig.ident.to_string(),
        "function",
        format!("pub {}", render_signature(&item.sig)),
    );
}

fn push_trait(nodes: &mut Vec<RawNode>, module: &str, item: &ItemTrait) {
    let bounds = if item.supertraits.is_empty() {
        String::new()
    } else {
        format!(": {}", render_bounds(item.supertraits.iter()))
    };
    let qualifier = match (item.unsafety.is_some(), item.auto_token.is_some()) {
        (true, true) => "unsafe auto ",
        (true, false) => "unsafe ",
        (false, true) => "auto ",
        (false, false) => "",
    };
    let signature = format!(
        "pub {qualifier}trait {}{}{bounds}{}",
        item.ident,
        render_generics_without_where(&item.generics),
        render_where(&item.generics)
    );
    let trait_name = item.ident.to_string();
    push_rust_node(nodes, module, trait_name.clone(), "trait", signature);
    let trait_scope = format!("{module}::{trait_name}");
    for member in &item.items {
        match member {
            TraitItem::Fn(function) => push_rust_node(
                nodes,
                &trait_scope,
                function.sig.ident.to_string(),
                "trait_method",
                render_signature(&function.sig),
            ),
            TraitItem::Const(value) => push_rust_node(
                nodes,
                &trait_scope,
                value.ident.to_string(),
                "trait_const",
                format!("const {}: {}", value.ident, render_type(&value.ty)),
            ),
            TraitItem::Type(value) => push_rust_node(
                nodes,
                &trait_scope,
                value.ident.to_string(),
                "trait_type",
                render_trait_type(value),
            ),
            _ => {}
        }
    }
}

fn push_rust_node(
    nodes: &mut Vec<RawNode>,
    module: &str,
    name: String,
    kind: &'static str,
    signature: String,
) {
    nodes.push(RawNode {
        scope: module.to_owned(),
        name,
        kind,
        signature,
    });
}

fn flatten_use_tree(tree: &UseTree, prefix: String) -> Vec<(String, String)> {
    match tree {
        UseTree::Path(path) => {
            let prefix = if prefix.is_empty() {
                path.ident.to_string()
            } else {
                format!("{prefix}::{}", path.ident)
            };
            flatten_use_tree(&path.tree, prefix)
        }
        UseTree::Name(name) => {
            let full = if prefix.is_empty() {
                name.ident.to_string()
            } else {
                format!("{prefix}::{}", name.ident)
            };
            vec![(name.ident.to_string(), full)]
        }
        UseTree::Rename(rename) => {
            let source = if prefix.is_empty() {
                rename.ident.to_string()
            } else {
                format!("{prefix}::{}", rename.ident)
            };
            vec![(
                rename.rename.to_string(),
                format!("{source} as {}", rename.rename),
            )]
        }
        UseTree::Glob(_) => vec![("*".to_owned(), format!("{prefix}::*"))],
        UseTree::Group(group) => group
            .items
            .iter()
            .flat_map(|item| flatten_use_tree(item, prefix.clone()))
            .collect(),
    }
}

fn rust_module_path(relative: &str) -> String {
    let parts = relative.split('/').collect::<Vec<_>>();
    if parts.len() >= 4 && parts[0] == "crates" && parts[2] == "src" {
        let crate_name = normalize_rust_component(parts[1]);
        let rest = &parts[3..];
        let mut modules = vec![crate_name];
        for (index, part) in rest.iter().enumerate() {
            let is_last = index + 1 == rest.len();
            let stem = part.strip_suffix(".rs").unwrap_or(part);
            if is_last && matches!(stem, "lib" | "main" | "mod") {
                continue;
            }
            modules.push(normalize_rust_component(stem));
        }
        modules.join("::")
    } else {
        relative
            .trim_end_matches(".rs")
            .split('/')
            .map(normalize_rust_component)
            .collect::<Vec<_>>()
            .join("::")
    }
}

#[cfg(test)]
mod fragment_tests {
    use super::*;

    fn input(relative: &str, text: &str) -> SourceInput {
        SourceInput {
            relative: relative.to_owned(),
            hash: blake3::hash(text.as_bytes()).to_hex().to_string(),
            text: text.to_owned(),
        }
    }

    #[test]
    fn fragment_cache_enforces_entry_and_string_byte_budgets() {
        let mut cache = FragmentCache::default();
        let small = Arc::new(fragment("pub fn cache_budget() {}"));
        for index in 0..=FRAGMENT_CACHE_MAX {
            cache.insert(index.to_string(), Arc::clone(&small));
        }
        assert_eq!(cache.entries.len(), FRAGMENT_CACHE_MAX);
        assert!(!cache.entries.contains_key("0"));
        assert_eq!(cache.bytes, FRAGMENT_CACHE_MAX * small.string_bytes());
        let large = Arc::new(RustFragment {
            nodes: vec![RawNode {
                scope: String::new(),
                name: String::new(),
                kind: "function",
                signature: "x".repeat(FRAGMENT_CACHE_MAX_BYTES / 2),
            }],
            ..RustFragment::default()
        });
        cache.insert("large-first".into(), Arc::clone(&large));
        cache.insert("large-second".into(), Arc::clone(&large));
        assert_eq!(cache.bytes, FRAGMENT_CACHE_MAX_BYTES);
        assert_eq!(cache.entries.len(), 2);
        cache.insert("large-third".into(), Arc::clone(&large));
        assert!(!cache.entries.contains_key("large-first"));
        assert!(cache.entries.contains_key("large-second"));
        assert_eq!(cache.bytes, FRAGMENT_CACHE_MAX_BYTES);
        assert_eq!(cache.entries.len(), 2);
        let oversized = Arc::new(RustFragment {
            parse_error: Some("x".repeat(FRAGMENT_CACHE_MAX_BYTES + 1)),
            ..RustFragment::default()
        });
        cache.insert("oversized".into(), oversized);
        assert!(!cache.entries.contains_key("oversized"));
        assert_eq!(cache.bytes, FRAGMENT_CACHE_MAX_BYTES);
        assert_eq!(cache.oldest.len(), cache.entries.len());
        assert_eq!(large.nodes[0].signature.len(), FRAGMENT_CACHE_MAX_BYTES / 2);
    }

    fn assembled(inputs: &[SourceInput], fragments: &[Arc<RustFragment>]) -> Vec<AtlasNode> {
        let mut occurrences = BTreeMap::new();
        let mut nodes = Vec::new();
        for (input, fragment) in inputs.iter().zip(fragments) {
            emit(fragment, "x", input, &mut occurrences, &mut nodes);
        }
        nodes
    }

    #[test]
    fn a_rebuild_parses_only_changed_content_and_assembles_identical_nodes() {
        let a = "// a_rebuild_parses_only_changed_content_and_assembles_identical_nodes: a\npub struct A;\nimpl A { pub fn new() -> Self { A } }\npub trait T { fn t(&self); }\n";
        let mut inputs = vec![
            input(
                "crates/x/src/lib.rs",
                "// a_rebuild_parses_only_changed_content_and_assembles_identical_nodes: lib\npub mod a;\npub mod inline { pub mod deep; }\n",
            ),
            input("crates/x/src/a.rs", a),
            input(
                "crates/x/src/inline/deep.rs",
                "// a_rebuild_parses_only_changed_content_and_assembles_identical_nodes: deep\npub fn deep() {}\npub fn deep() {}\n",
            ),
        ];
        let (cold, parsed) = fragments(&inputs);
        assert_eq!(parsed, 3);
        let (warm, parsed) = fragments(&inputs);
        assert_eq!(parsed, 0, "unchanged content is never parsed again");
        let sequential: Vec<_> = inputs
            .iter()
            .map(|input| Arc::new(fragment(&input.text)))
            .collect();
        assert_eq!(assembled(&inputs, &warm), assembled(&inputs, &cold));
        assert_eq!(assembled(&inputs, &sequential), assembled(&inputs, &cold));
        let children: Vec<_> = cold[0]
            .children
            .iter()
            .map(|child| (child.module.as_str(), child.directory.as_str()))
            .collect();
        assert_eq!(children, [("::a", "a"), ("::inline::deep", "inline/deep")]);
        inputs[1] = input("crates/x/src/a.rs", &format!("{a}pub fn added() {{}}\n"));
        let (_, parsed) = fragments(&inputs);
        assert_eq!(parsed, 1, "one edited file, one parse");
    }
}
