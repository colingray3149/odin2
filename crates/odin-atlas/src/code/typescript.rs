//! Tree-sitter TypeScript/TSX scanning and symbol traversal.

use crate::{
    load_text_sources, AtlasNode, AtlasParseError, ScannedClass, SourceClass, SourceInput,
};
use serde_json::Value;
use std::collections::BTreeMap;
use tree_sitter::{Node, Parser, Tree};
use tree_sitter_typescript::{LANGUAGE_TSX, LANGUAGE_TYPESCRIPT};

pub(crate) fn scan_typescript(
    root: &std::path::Path,
    source_root: &std::path::Path,
) -> ScannedClass {
    let (mut scan, inputs) =
        load_text_sources(root, source_root, SourceClass::TypeScript, &["ts", "tsx"]);
    for input in inputs {
        match parse_typescript_tree(&input) {
            Ok(tree) => scan_ts_tree(&tree, &input, &mut scan),
            Err(message) => scan.parse_errors.push(AtlasParseError {
                source_class: SourceClass::TypeScript,
                path: input.relative.clone(),
                message,
            }),
        }
    }
    scan
}

fn parse_typescript_tree(input: &SourceInput) -> Result<Tree, String> {
    let mut parser = Parser::new();
    let language = if input.relative.ends_with(".tsx") {
        LANGUAGE_TSX.into()
    } else {
        LANGUAGE_TYPESCRIPT.into()
    };
    parser
        .set_language(&language)
        .map_err(|error| format!("TypeScript language: {error}"))?;
    let tree = parser
        .parse(input.text.as_bytes(), None)
        .ok_or_else(|| "TypeScript parser returned no tree".to_owned())?;
    if let Some(message) = rejected_tree_message(tree.root_node()) {
        return Err(message);
    }
    Ok(tree)
}

fn rejected_tree_message(root: Node<'_>) -> Option<String> {
    if root.is_error() {
        return Some(format!(
            "TypeScript ERROR root at UTF-8 bytes {}..{}",
            root.start_byte(),
            root.end_byte()
        ));
    }
    if root.is_missing() {
        return Some(format!(
            "TypeScript MISSING root at UTF-8 bytes {}..{}",
            root.start_byte(),
            root.end_byte()
        ));
    }
    if let Some((kind, start, end)) = first_error_or_missing(root) {
        return Some(format!(
            "TypeScript {kind} node at UTF-8 bytes {start}..{end}"
        ));
    }
    if root.has_error() {
        return Some(format!(
            "TypeScript root error at UTF-8 bytes {}..{}",
            root.start_byte(),
            root.end_byte()
        ));
    }
    None
}

fn first_error_or_missing(node: Node<'_>) -> Option<(&'static str, usize, usize)> {
    if node.is_error() {
        return Some(("ERROR", node.start_byte(), node.end_byte()));
    }
    if node.is_missing() {
        return Some(("MISSING", node.start_byte(), node.end_byte()));
    }
    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return None;
    }
    loop {
        if let Some(found) = first_error_or_missing(cursor.node()) {
            return Some(found);
        }
        if !cursor.goto_next_sibling() {
            return None;
        }
    }
}

fn scan_ts_tree(tree: &Tree, input: &SourceInput, scan: &mut ScannedClass) {
    let mut occurrences = BTreeMap::new();
    visit_ts_node(tree.root_node(), "", input, &mut occurrences, scan);
}

fn visit_ts_node(
    node: Node<'_>,
    namespace_scope: &str,
    input: &SourceInput,
    occurrences: &mut BTreeMap<String, usize>,
    scan: &mut ScannedClass,
) {
    match node.kind() {
        "export_statement" => {
            emit_ts_export(node, namespace_scope, input, occurrences, scan);
            if let Some(declaration) = node.child_by_field_name("declaration") {
                visit_ts_declaration_body(declaration, namespace_scope, input, occurrences, scan);
            }
        }
        "internal_module" | "module" => {
            visit_ts_declaration_body(node, namespace_scope, input, occurrences, scan);
        }
        _ => visit_named_children(node, |child| {
            visit_ts_node(child, namespace_scope, input, occurrences, scan);
        }),
    }
}

fn visit_ts_declaration_body(
    node: Node<'_>,
    namespace_scope: &str,
    input: &SourceInput,
    occurrences: &mut BTreeMap<String, usize>,
    scan: &mut ScannedClass,
) {
    match node.kind() {
        "internal_module" | "module" => {
            let Some(name) = field_name_text(node, input) else {
                return;
            };
            let nested = if namespace_scope.is_empty() {
                name
            } else {
                format!("{namespace_scope}::{name}")
            };
            if let Some(body) = node.child_by_field_name("body") {
                visit_named_children(body, |child| {
                    visit_ts_node(child, &nested, input, occurrences, scan);
                });
            }
        }
        "ambient_declaration" => visit_named_children(node, |child| {
            visit_ts_declaration_body(child, namespace_scope, input, occurrences, scan);
        }),
        _ => {}
    }
}

fn emit_ts_export(
    node: Node<'_>,
    namespace_scope: &str,
    input: &SourceInput,
    occurrences: &mut BTreeMap<String, usize>,
    scan: &mut ScannedClass,
) {
    if let Some(declaration) = node.child_by_field_name("declaration") {
        emit_ts_declaration(declaration, node, namespace_scope, input, occurrences, scan);
        return;
    }
    if let Some(value) = node.child_by_field_name("value") {
        let Some(signature) = signature_utf8(node, value, input, scan) else {
            return;
        };
        push_ts_node(
            scan,
            occurrences,
            input,
            namespace_scope,
            "default".to_owned(),
            node.kind(),
            signature,
        );
        return;
    }
    let Some(signature) = node_utf8(node, &input.text) else {
        push_span_error(node, input, scan);
        return;
    };
    let mut saw_named_export = false;
    visit_named_children(node, |child| match child.kind() {
        "export_clause" => {
            saw_named_export = true;
            emit_export_clause(child, namespace_scope, signature, input, occurrences, scan);
        }
        "namespace_export" => {
            saw_named_export = true;
            if let Some(name) = first_named_text(child, input) {
                push_ts_node(
                    scan,
                    occurrences,
                    input,
                    namespace_scope,
                    name,
                    child.kind(),
                    signature,
                );
            }
        }
        _ => {}
    });
    if !saw_named_export && has_anonymous_kind(node, "*") {
        push_ts_node(
            scan,
            occurrences,
            input,
            namespace_scope,
            "*".to_owned(),
            node.kind(),
            signature,
        );
    }
}

fn emit_export_clause(
    clause: Node<'_>,
    namespace_scope: &str,
    signature: &str,
    input: &SourceInput,
    occurrences: &mut BTreeMap<String, usize>,
    scan: &mut ScannedClass,
) {
    visit_named_children(clause, |child| {
        if child.kind() != "export_specifier" {
            return;
        }
        let name_node = child
            .child_by_field_name("alias")
            .or_else(|| child.child_by_field_name("name"));
        if let Some(name) = name_node.and_then(|node| node_name_text(node, input)) {
            push_ts_node(
                scan,
                occurrences,
                input,
                namespace_scope,
                name,
                child.kind(),
                signature,
            );
        }
    });
}

fn emit_ts_declaration(
    declaration: Node<'_>,
    export: Node<'_>,
    namespace_scope: &str,
    input: &SourceInput,
    occurrences: &mut BTreeMap<String, usize>,
    scan: &mut ScannedClass,
) {
    match declaration.kind() {
        "lexical_declaration" | "variable_declaration" => {
            visit_named_children(declaration, |child| {
                if child.kind() != "variable_declarator" {
                    return;
                }
                let Some(name_node) = child.child_by_field_name("name") else {
                    return;
                };
                if name_node.kind() != "identifier" {
                    return;
                }
                let Some(name) = node_name_text(name_node, input) else {
                    return;
                };
                let Some(signature) = signature_utf8(export, child, input, scan) else {
                    return;
                };
                push_ts_node(
                    scan,
                    occurrences,
                    input,
                    namespace_scope,
                    name,
                    child.kind(),
                    signature,
                );
            });
        }
        "function_declaration"
        | "function_signature"
        | "generator_function_declaration"
        | "class_declaration"
        | "abstract_class_declaration"
        | "interface_declaration"
        | "type_alias_declaration"
        | "enum_declaration"
        | "internal_module"
        | "module" => {
            let name = match field_name_text(declaration, input) {
                Some(name) => name,
                None if has_anonymous_kind(export, "default") => "default".to_owned(),
                None => return,
            };
            let Some(signature) = signature_utf8(export, declaration, input, scan) else {
                return;
            };
            push_ts_node(
                scan,
                occurrences,
                input,
                namespace_scope,
                name,
                declaration.kind(),
                signature,
            );
        }
        "ambient_declaration" => visit_named_children(declaration, |child| {
            emit_ts_declaration(child, export, namespace_scope, input, occurrences, scan);
        }),
        _ if has_anonymous_kind(export, "default") => {
            let Some(signature) = signature_utf8(export, declaration, input, scan) else {
                return;
            };
            push_ts_node(
                scan,
                occurrences,
                input,
                namespace_scope,
                "default".to_owned(),
                declaration.kind(),
                signature,
            );
        }
        _ => {}
    }
}

fn signature_utf8<'a>(
    export: Node<'_>,
    focus: Node<'_>,
    input: &'a SourceInput,
    scan: &mut ScannedClass,
) -> Option<&'a str> {
    let start = export.start_byte();
    let mut end = export.end_byte();
    if let Some(body_start) = implementation_body_start(focus) {
        end = end.min(body_start);
    }
    match input.text.get(start..end) {
        Some(signature) => Some(signature),
        None => {
            push_span_error(export, input, scan);
            None
        }
    }
}

fn implementation_body_start(node: Node<'_>) -> Option<usize> {
    if let Some(body) = node.child_by_field_name("body") {
        return Some(body.start_byte());
    }
    if node.kind() == "variable_declarator" {
        let value = node.child_by_field_name("value")?;
        return implementation_body_start(value).or(Some(value.start_byte()));
    }
    None
}

fn push_span_error(node: Node<'_>, input: &SourceInput, scan: &mut ScannedClass) {
    scan.parse_errors.push(AtlasParseError {
        source_class: SourceClass::TypeScript,
        path: input.relative.clone(),
        message: format!(
            "TypeScript node span {}..{} is not a UTF-8 boundary",
            node.start_byte(),
            node.end_byte()
        ),
    });
}

fn push_ts_node(
    scan: &mut ScannedClass,
    occurrences: &mut BTreeMap<String, usize>,
    input: &SourceInput,
    namespace_scope: &str,
    name: String,
    kind: &str,
    signature: &str,
) {
    let base_module = typescript_module_path(&input.relative);
    let module = if namespace_scope.is_empty() {
        base_module
    } else {
        format!("{base_module}::{namespace_scope}")
    };
    let id = super::node_id(&format!("typescript:{module}::{name}"), occurrences);
    let qualified_name = format!("{module}::{name}");
    scan.nodes.push(AtlasNode {
        id,
        source_class: SourceClass::TypeScript,
        path: input.relative.clone(),
        source_blake3: input.hash.clone(),
        name,
        kind: kind.to_owned(),
        signature: Some(signature.to_owned()),
        summary: None,
        properties: BTreeMap::from([
            ("module".to_owned(), Value::String(module.clone())),
            (
                "parent".to_owned(),
                Value::String(format!("typescript:{module}")),
            ),
            ("qualified_name".to_owned(), Value::String(qualified_name)),
            ("visibility".to_owned(), Value::String("export".to_owned())),
        ]),
    });
}

fn visit_named_children(node: Node<'_>, mut visit: impl FnMut(Node<'_>)) {
    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return;
    }
    loop {
        let child = cursor.node();
        if child.is_named() {
            visit(child);
        }
        if !cursor.goto_next_sibling() {
            return;
        }
    }
}

fn node_utf8<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    source.get(node.start_byte()..node.end_byte())
}

fn node_name_text(node: Node<'_>, input: &SourceInput) -> Option<String> {
    let text = input.text.get(node.start_byte()..node.end_byte())?;
    Some(match node.kind() {
        "string" => text
            .trim_matches(|character| matches!(character, '\'' | '"' | '`'))
            .to_owned(),
        _ => text.to_owned(),
    })
}

fn field_name_text(node: Node<'_>, input: &SourceInput) -> Option<String> {
    node.child_by_field_name("name")
        .and_then(|name| node_name_text(name, input))
}

fn first_named_text(node: Node<'_>, input: &SourceInput) -> Option<String> {
    let mut found = None;
    visit_named_children(node, |child| {
        if found.is_none() {
            found = node_name_text(child, input);
        }
    });
    found
}

fn has_anonymous_kind(node: Node<'_>, kind: &str) -> bool {
    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return false;
    }
    loop {
        let child = cursor.node();
        if !child.is_named() && child.kind() == kind {
            return true;
        }
        if !cursor.goto_next_sibling() {
            return false;
        }
    }
}

fn typescript_module_path(relative: &str) -> String {
    relative
        .strip_suffix(".d.ts")
        .or_else(|| relative.strip_suffix(".tsx"))
        .or_else(|| relative.strip_suffix(".ts"))
        .unwrap_or(relative)
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>()
        .join("/")
}
