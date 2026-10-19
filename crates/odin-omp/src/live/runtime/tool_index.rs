//! The kernel-first tool surface of an OMP seat session: the stable-prefix
//! guidance line every seat carries, and, for a seat declaring
//! `[tools] always`, the index the extension lists from — the always set
//! first, the rest of the grant found through `odin_kernel_search`.

use std::collections::BTreeSet;

use serde_json::json;

use crate::host_tools::operations::HostToolOperations;

pub(super) const TOOL_INDEX_ENV: &str = "ODIN_TOOL_INDEX";

pub(super) const KERNEL_FIRST: &str = "Odin's tools are how you act: every action goes \
    through the tools this session lists, never through a shell, a raw web request or a file \
    edit outside them.";

pub(super) const KERNEL_SEARCH: &str = "When none of the listed tools fits what you need, call \
    odin_kernel_search with a few words naming the action (\"purchase\", \"open a workspace\", \
    \"drain a node\"): it lists the matching tools you hold and makes them callable for the rest \
    of this session.";

/// Longest summary the index carries per tool.
const SUMMARY_CHARS: usize = 240;

/// The index of a seat's admitted tools: every tool with its group (its
/// capability id without the last segment) and the first sentence of its
/// description, plus the names `always` lists from the first turn.
pub(super) fn tool_index(
    operations: &HostToolOperations,
    admitted: &BTreeSet<String>,
    always: &BTreeSet<String>,
) -> Result<String, String> {
    let definitions = operations
        .admitted_definitions(admitted, true)
        .map_err(|error| error.to_string())?;
    let mut listed = Vec::new();
    let mut tools = Vec::with_capacity(definitions.len());
    for definition in &definitions {
        let name = definition.name.as_ref();
        let capability = operations
            .capability_of(name)
            .ok_or_else(|| format!("admitted tool {name} has no capability"))?
            .as_str();
        if always
            .iter()
            .any(|entry| odin_registry::schema::always_covers(entry, capability))
        {
            listed.push(name);
        }
        let group = capability
            .rsplit_once('.')
            .map_or(capability, |(group, _)| group);
        tools.push(json!({
            "name": name,
            "group": group,
            "summary": summary(&definition.description),
        }));
    }
    Ok(json!({ "always": listed, "tools": tools }).to_string())
}

fn summary(description: &str) -> String {
    let first = description
        .split_once(". ")
        .map_or(description, |(sentence, _)| sentence);
    first.chars().take(SUMMARY_CHARS).collect()
}
