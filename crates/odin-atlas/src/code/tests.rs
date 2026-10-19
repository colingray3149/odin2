//! Syntax discovery and source provenance invariants.

use super::{scan_rust, scan_typescript};
use crate::{build, Atlas, AtlasSources, SourceClass};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

fn fixture_root(label: &str) -> PathBuf {
    let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "odin-atlas-code-{label}-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("create atlas code fixture");
    root
}

fn committed_fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/typescript-adversarial")
        .join(name)
}

fn production_atlas_from_committed_fixtures() -> (PathBuf, Atlas) {
    let root = fixture_root("committed");
    for directory in ["crates", "extension", "registry", "skeletons"] {
        fs::create_dir_all(root.join(directory)).expect("create atlas fixture directory");
    }
    let extension = root.join("extension");
    for name in ["multiline.ts", "nested-arrow.tsx", "parse-error.ts"] {
        fs::copy(committed_fixture(name), extension.join(name))
            .unwrap_or_else(|error| panic!("copy committed {name}: {error}"));
    }
    let atlas = build(AtlasSources::new(&root)).expect("production atlas build");
    (root, atlas)
}

fn nodes_for<'a>(atlas: &'a Atlas, file_name: &str) -> Vec<&'a crate::AtlasNode> {
    atlas
        .nodes
        .iter()
        .filter(|node| {
            node.source_class == SourceClass::TypeScript
                && Path::new(&node.path)
                    .file_name()
                    .is_some_and(|name| name == file_name)
        })
        .collect()
}

fn node_named<'a>(nodes: &[&'a crate::AtlasNode], name: &str) -> &'a crate::AtlasNode {
    nodes
        .iter()
        .copied()
        .find(|node| node.name == name)
        .unwrap_or_else(|| panic!("missing TypeScript node {name}"))
}

#[test]
fn scans_only_reachable_public_rust_and_exported_typescript_symbols() {
    let root = fixture_root("visibility");
    let rust = root.join("crates/demo-core/src");
    let typescript = root.join("extension");
    fs::create_dir_all(&rust).expect("create Rust fixture");
    fs::create_dir_all(&typescript).expect("create TypeScript fixture");
    fs::write(
        rust.join("lib.rs"),
        r#"
                pub mod visible;
                mod hidden;
                pub struct Public {
                    pub shown: u64,
                    secret: u64,
                }
                struct Private;
                impl Private {
                    pub fn leaked() {}
                }
                impl Public {
                    pub fn exposed(&self) -> u64 { self.shown }
                    fn internal(&self) {}
                }
                pub fn top_level(value: &Public) -> u64 { value.shown }
                fn private_function() {}
            "#,
    )
    .expect("write Rust root");
    fs::write(
        rust.join("visible.rs"),
        "pub fn external() {}\nfn private_external() {}\n",
    )
    .expect("write public Rust module");
    fs::write(rust.join("hidden.rs"), "pub fn unreachable() {}\n")
        .expect("write private Rust module");
    fs::write(
        typescript.join("index.ts"),
        r#"
                function privateFunction(): void {}
                export interface PublicShape { value: string }
                export const first: number = 1, second = 2;
            "#,
    )
    .expect("write TypeScript fixture");

    let rust_scan = scan_rust(&root, &root.join("crates"));
    let rust_names = rust_scan
        .nodes
        .iter()
        .map(|node| node.name.as_str())
        .collect::<Vec<_>>();
    assert!(rust_names.contains(&"Public"));
    assert!(rust_names.contains(&"top_level"));
    assert!(rust_names.contains(&"external"));
    assert!(rust_names.contains(&"exposed"));
    assert!(!rust_names.contains(&"Private"));
    assert!(!rust_names.contains(&"leaked"));
    assert!(!rust_names.contains(&"private_function"));
    assert!(!rust_names.contains(&"private_external"));
    assert!(!rust_names.contains(&"unreachable"));
    let public = rust_scan
        .nodes
        .iter()
        .find(|node| node.name == "Public")
        .and_then(|node| node.signature.as_deref())
        .expect("public struct signature");
    assert!(public.contains("pub shown: u64"));
    assert!(!public.contains("secret"));
    assert!(rust_scan
        .nodes
        .iter()
        .any(|node| node.id == "rust:demo_core::visible::external"));

    let ts_scan = scan_typescript(&root, &typescript);
    let ts_names = ts_scan
        .nodes
        .iter()
        .map(|node| node.name.as_str())
        .collect::<Vec<_>>();
    assert!(ts_names.contains(&"PublicShape"));
    assert!(ts_names.contains(&"first"));
    assert!(ts_names.contains(&"second"));
    assert!(!ts_names.contains(&"privateFunction"));
    assert!(ts_scan
        .nodes
        .iter()
        .all(|node| node.id.starts_with("typescript:extension_index::")));

    fs::remove_dir_all(root).expect("remove atlas code fixture");
}

#[test]
fn typescript_multiline_signature() {
    let (root, atlas) = production_atlas_from_committed_fixtures();
    let source =
        fs::read_to_string(committed_fixture("multiline.ts")).expect("read committed multiline.ts");
    let nodes = nodes_for(&atlas, "multiline.ts");

    let overloads = nodes
        .iter()
        .copied()
        .filter(|node| node.name == "overload")
        .collect::<Vec<_>>();
    assert_eq!(overloads.len(), 3);
    assert_eq!(overloads[0].id, "typescript:extension_multiline::overload");
    assert_eq!(
        overloads[1].id,
        "typescript:extension_multiline::overload:2"
    );
    assert_eq!(
        overloads[2].id,
        "typescript:extension_multiline::overload:3"
    );
    assert_eq!(overloads[0].kind, "function_signature");
    assert_eq!(overloads[1].kind, "function_signature");
    assert_eq!(overloads[2].kind, "function_declaration");
    for overload in &overloads {
        let signature = overload.signature.as_deref().expect("overload signature");
        assert!(
            signature.contains('\n'),
            "overload signature must keep multiline UTF-8 span: {signature:?}"
        );
        assert!(source.contains(signature));
        assert!(signature.starts_with("export function overload"));
    }
    assert!(overloads[0]
        .signature
        .as_deref()
        .expect("first overload")
        .contains("value: string"));
    assert!(overloads[1]
        .signature
        .as_deref()
        .expect("second overload")
        .contains("value: number"));
    assert!(!overloads[2]
        .signature
        .as_deref()
        .expect("implemented overload")
        .contains("return value"));

    let generic = node_named(&nodes, "genericFn");
    assert_eq!(generic.kind, "function_declaration");
    let generic_signature = generic.signature.as_deref().expect("generic signature");
    assert!(generic_signature.contains('\n'));
    assert!(generic_signature.contains("<T extends { map: (fn: (x: T) => T) => T }>"));
    assert!(source.contains(generic_signature));
    assert!(!generic_signature.contains("return input"));

    let nested_fn = node_named(&nodes, "NestedFn");
    assert_eq!(nested_fn.kind, "type_alias_declaration");
    let nested_signature = nested_fn.signature.as_deref().expect("nested fn signature");
    assert!(nested_signature.contains('\n'));
    assert!(nested_signature.contains("(y: string) => number"));
    assert!(nested_signature.contains("(z: boolean) => void"));
    assert!(source.contains(nested_signature));

    let reexport = node_named(&nodes, "overloaded");
    assert_eq!(reexport.kind, "export_specifier");
    assert_eq!(reexport.id, "typescript:extension_multiline::overloaded");

    let class = node_named(&nodes, "Box");
    assert_eq!(class.kind, "class_declaration");
    let class_signature = class.signature.as_deref().expect("class signature");
    assert!(class_signature.contains("export class Box<T>"));
    assert!(!class_signature.contains("constructor"));

    let interface = node_named(&nodes, "Shape");
    assert_eq!(interface.kind, "interface_declaration");

    let namespace = node_named(&nodes, "Outer");
    assert_eq!(namespace.kind, "internal_module");
    let inner = node_named(&nodes, "inner");
    assert_eq!(inner.id, "typescript:extension_multiline::Outer::inner");
    assert_eq!(inner.kind, "function_declaration");

    let constant = node_named(&nodes, "multilineConst");
    let constant_signature = constant.signature.as_deref().expect("const signature");
    assert!(constant_signature.contains('\n'));
    assert!(constant_signature.contains("(x: string) => number"));
    assert!(source.contains(constant_signature));
    assert!(!constant_signature.contains("x.length"));

    assert!(nodes_for(&atlas, "nested-arrow.tsx")
        .iter()
        .any(|node| node.name == "nested"));
    assert!(atlas.parse_errors.iter().any(|error| {
        error.source_class == SourceClass::TypeScript
            && Path::new(&error.path)
                .file_name()
                .is_some_and(|name| name == "parse-error.ts")
    }));

    fs::remove_dir_all(root).expect("remove committed atlas fixture");
}

#[test]
fn typescript_nested_arrow_signature() {
    let (root, atlas) = production_atlas_from_committed_fixtures();
    let source = fs::read_to_string(committed_fixture("nested-arrow.tsx"))
        .expect("read committed nested-arrow.tsx");
    let nodes = nodes_for(&atlas, "nested-arrow.tsx");
    let nested = node_named(&nodes, "nested");
    assert_eq!(nested.kind, "variable_declarator");
    assert_eq!(nested.id, "typescript:extension_nested-arrow::nested");
    let signature = nested.signature.as_deref().expect("nested arrow signature");
    assert!(signature.contains('\n'));
    assert!(signature.contains("(inner: (y: string) => number) => boolean"));
    assert!(source.contains(signature));
    assert!(!signature.contains("x((y) => y.length)"));
    assert!(!signature.contains("Icon"));

    fs::remove_dir_all(root).expect("remove committed atlas fixture");
}

#[test]
fn typescript_tsx_and_errors() {
    let (root, atlas) = production_atlas_from_committed_fixtures();
    let source = fs::read_to_string(committed_fixture("nested-arrow.tsx"))
        .expect("read committed nested-arrow.tsx");
    let tsx_nodes = nodes_for(&atlas, "nested-arrow.tsx");
    let icon = node_named(&tsx_nodes, "Icon");
    assert_eq!(icon.kind, "function_declaration");
    assert_eq!(icon.id, "typescript:extension_nested-arrow::Icon");
    let icon_signature = icon.signature.as_deref().expect("tsx signature");
    assert!(icon_signature.starts_with("export function Icon"));
    assert!(icon_signature.contains("props: { label: string }"));
    assert!(!icon_signature.contains("<span>"));
    assert!(source.contains(icon_signature));
    assert!(atlas.parse_errors.iter().all(|error| {
        Path::new(&error.path)
            .file_name()
            .is_none_or(|name| name != "nested-arrow.tsx")
    }));

    let error_nodes = nodes_for(&atlas, "parse-error.ts");
    assert!(
        error_nodes.is_empty(),
        "ERROR/MISSING trees must not invent TypeScript nodes: {error_nodes:?}"
    );
    let errors = atlas
        .parse_errors
        .iter()
        .filter(|error| {
            error.source_class == SourceClass::TypeScript
                && Path::new(&error.path)
                    .file_name()
                    .is_some_and(|name| name == "parse-error.ts")
        })
        .collect::<Vec<_>>();
    assert!(
        !errors.is_empty(),
        "parse-error.ts must surface a TypeScript parse error"
    );
    assert!(errors.iter().any(|error| {
        error.message.contains("ERROR")
            || error.message.contains("MISSING")
            || error.message.contains("root error")
    }));

    assert!(nodes_for(&atlas, "multiline.ts")
        .iter()
        .any(|node| node.name == "overload"));

    fs::remove_dir_all(root).expect("remove committed atlas fixture");
}

#[test]
fn rust_modules_resolve_through_inline_modules_and_a_rebuild_is_byte_identical() {
    let root = fixture_root("incremental");
    for directory in ["extension", "registry", "skeletons"] {
        fs::create_dir_all(root.join(directory)).expect("fixture dirs");
    }
    let src = root.join("crates/x/src");
    fs::create_dir_all(src.join("inline")).expect("fixture dirs");
    fs::write(
        src.join("lib.rs"),
        "pub mod a;\npub mod inline { pub mod deep; }\n",
    )
    .expect("lib");
    fs::write(src.join("a.rs"), "pub fn a() {}\n").expect("a");
    fs::write(
        src.join("inline/deep.rs"),
        "pub fn deep() {}\npub fn deep() {}\n",
    )
    .expect("deep");
    let cold = build(AtlasSources::new(&root)).expect("cold build");
    let warm = build(AtlasSources::new(&root)).expect("warm build");
    assert_eq!(
        cold.to_bytes().expect("bytes"),
        warm.to_bytes().expect("bytes")
    );
    let ids: Vec<_> = cold
        .nodes
        .iter()
        .filter(|node| node.source_class == SourceClass::Rust)
        .map(|node| node.id.as_str())
        .collect();
    for id in [
        "rust:x::a::a",
        "rust:x::inline::deep::deep",
        "rust:x::inline::deep::deep:2",
    ] {
        assert!(ids.contains(&id), "{id} in {ids:?}");
    }
}

#[test]
fn an_impl_method_of_a_parent_module_type_gets_a_canonical_id() {
    let root = fixture_root("impl-super");
    for directory in ["extension", "registry", "skeletons"] {
        fs::create_dir_all(root.join(directory)).expect("fixture dirs");
    }
    let src = root.join("crates/x/src");
    fs::create_dir_all(&src).expect("fixture dirs");
    fs::write(
        src.join("lib.rs"),
        "pub struct HermesRuntime;\npub mod review {\n    impl super::HermesRuntime {\n        pub fn review_registered(&self) {}\n    }\n}\n",
    )
    .expect("lib");
    let atlas = build(AtlasSources::new(&root)).expect("build");
    let method = atlas
        .nodes
        .iter()
        .find(|node| node.name == "review_registered")
        .expect("impl method node");
    assert_eq!(
        method.id,
        "rust:x::review::impl_super::HermesRuntime::review_registered"
    );

    fs::remove_dir_all(root).expect("remove atlas code fixture");
}
