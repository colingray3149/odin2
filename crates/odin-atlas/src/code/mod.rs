//! Syntax-derived Rust and TypeScript symbol discovery.

use std::collections::BTreeMap;

mod rust;
mod rust_signature;
mod typescript;

#[cfg(test)]
mod tests;

pub(crate) use rust::scan_rust;
pub(crate) use typescript::scan_typescript;

/// A canonical node id (ASCII alphanumerics and `.`, `_`, `:`, `-`) for the
/// symbol `raw` names: any other character (`impl Foo<T>` scopes, globs, file
/// paths) becomes `_`, and the n-th repeat of one id gets `:n`.
fn node_id(raw: &str, occurrences: &mut BTreeMap<String, usize>) -> String {
    let base: String = raw
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | ':' | '-') {
                character
            } else {
                '_'
            }
        })
        .collect();
    let occurrence = occurrences.entry(base.clone()).or_insert(0);
    *occurrence += 1;
    if *occurrence == 1 {
        base
    } else {
        format!("{base}:{occurrence}")
    }
}
