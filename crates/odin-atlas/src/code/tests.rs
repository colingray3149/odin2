//! Syntax discovery and source provenance invariants.

use super::{scan_rust, scan_typescript};
use crate::{build, Atlas, AtlasSources, SourceClass};
use std::fs;
use std::path::{Path, PathBuf};

fn committed_fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/typescript-adversarial")
        .join(name)
}

fn production_atlas_from_committed_fixtures() -> Atlas {
    let scratch = tempfile::tempdir().expect("create atlas code fixture");
    let root = scratch.path();
    for directory in ["crates", "extension", "registry", "skeletons"] {
        fs::create_dir_all(root.join(directory)).expect("create atlas fixture directory");
    }
    let extension = root.join("extension");
    for name in ["multiline.ts", "nested-arrow.tsx", "parse-error.ts"] {
        fs::copy(committed_fixture(name), extension.join(name))
            .unwrap_or_else(|error| panic!("copy committed {name}: {error}"));
    }
    build(AtlasSources::new(root)).expect("production atlas build")
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
    let scratch = tempfile::tempdir().expect("create atlas code fixture");
    let root = scratch.path();
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

    let rust_scan = scan_rust(root, &root.join("crates"));
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

    let ts_scan = scan_typescript(root, &typescript);
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
}

#[test]
fn typescript_multiline_signature() {
    let atlas = production_atlas_from_committed_fixtures();
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
}

#[test]
fn an_impl_method_of_a_parent_module_type_gets_a_canonical_id() {
    let scratch = tempfile::tempdir().expect("create atlas code fixture");
    let root = scratch.path();
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
    let atlas = build(AtlasSources::new(root)).expect("build");
    let method = atlas
        .nodes
        .iter()
        .find(|node| node.name == "review_registered")
        .expect("impl method node");
    assert_eq!(
        method.id,
        "rust:x::review::impl_super::HermesRuntime::review_registered"
    );
}
