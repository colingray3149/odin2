//! Structural-tree projections: accessibility facts that never carry a
//! runtime value, and the sanitized DOM where runtime form/script/style/
//! template values and every non-structural attribute are removed before the
//! projection exists.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::error::CapabilityError;
use super::read::{
    add_string_bytes, collect_reason, metadata, validate_fragment, validate_projection_bytes,
    BoundReport, ProjectionBudget, ReadBasis, ReadMetadata,
};
use super::{MAX_ACCESSIBILITY_NODES, MAX_DOM_NODES, MAX_FRAGMENT_BYTES};

/// One accessibility-tree node. Role and name are structural facts; no node
/// ever carries a runtime value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessibilityNode {
    pub role: String,
    pub name: String,
    pub children: Vec<AccessibilityNode>,
}

impl AccessibilityNode {
    pub fn new(role: String, name: String, children: Vec<AccessibilityNode>) -> Self {
        Self {
            role,
            name,
            children,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "AccessibilityProjectionParts")]
pub struct AccessibilityProjection {
    pub metadata: ReadMetadata,
    pub root: AccessibilityNode,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccessibilityProjectionParts {
    metadata: ReadMetadata,
    root: AccessibilityNode,
}

impl TryFrom<AccessibilityProjectionParts> for AccessibilityProjection {
    type Error = CapabilityError;

    fn try_from(parts: AccessibilityProjectionParts) -> Result<Self, Self::Error> {
        let projection = Self {
            metadata: parts.metadata,
            root: parts.root,
        };
        projection.validate()?;
        Ok(projection)
    }
}

impl AccessibilityProjection {
    pub fn build(basis: ReadBasis, root: AccessibilityNode) -> Result<Self, CapabilityError> {
        basis.validate()?;
        let (visited, total_bytes) = accessibility_stats(&root);
        let mut budget = ProjectionBudget::new(basis.max_bytes);
        let (root, kept) = prune_accessibility(root, MAX_ACCESSIBILITY_NODES, &mut budget);
        let truncated = kept < visited || total_bytes > budget.emitted;
        let bound = BoundReport::new(
            basis.max_bytes,
            budget.emitted,
            Some(total_bytes),
            truncated,
        )?;
        let reason = collect_reason(
            &basis,
            &bound,
            &format!("{visited} nodes observed, {kept} kept (bound {MAX_ACCESSIBILITY_NODES})"),
        );
        Ok(Self {
            metadata: metadata(&basis, bound, &reason),
            root,
        })
    }

    pub fn validate(&self) -> Result<(), CapabilityError> {
        let (nodes, bytes) = validate_accessibility_node(&self.root)?;
        if nodes > MAX_ACCESSIBILITY_NODES {
            return Err(CapabilityError::BoundExceeded {
                limit: MAX_ACCESSIBILITY_NODES as u64,
                requested: nodes as u64,
            });
        }
        validate_projection_bytes(&self.metadata, bytes)
    }
}

fn accessibility_stats(node: &AccessibilityNode) -> (usize, u64) {
    let mut nodes = 1_usize;
    let mut bytes = 0_u64;
    add_string_bytes(&mut bytes, &node.role);
    add_string_bytes(&mut bytes, &node.name);
    for child in &node.children {
        let (child_nodes, child_bytes) = accessibility_stats(child);
        nodes = nodes.saturating_add(child_nodes);
        bytes = bytes.saturating_add(child_bytes);
    }
    (nodes, bytes)
}

fn prune_accessibility(
    node: AccessibilityNode,
    node_budget: usize,
    byte_budget: &mut ProjectionBudget,
) -> (AccessibilityNode, usize) {
    let mut kept = 1_usize;
    let role = byte_budget.take_fragment(node.role);
    let name = byte_budget.take_fragment(node.name);
    let mut children = Vec::new();
    for child in node.children {
        if kept >= node_budget || byte_budget.remaining() == 0 {
            break;
        }
        let (pruned, child_kept) = prune_accessibility(child, node_budget - kept, byte_budget);
        kept += child_kept;
        children.push(pruned);
    }
    (
        AccessibilityNode {
            role,
            name,
            children,
        },
        kept,
    )
}

fn validate_accessibility_node(node: &AccessibilityNode) -> Result<(usize, u64), CapabilityError> {
    validate_fragment(&node.role)?;
    validate_fragment(&node.name)?;
    let mut nodes = 1_usize;
    let mut bytes = 0_u64;
    add_string_bytes(&mut bytes, &node.role);
    add_string_bytes(&mut bytes, &node.name);
    for child in &node.children {
        let (child_nodes, child_bytes) = validate_accessibility_node(child)?;
        nodes = nodes.saturating_add(child_nodes);
        bytes = bytes.saturating_add(child_bytes);
    }
    Ok((nodes, bytes))
}

/// One DOM node with attributes and children. Constructed forms must not
/// embed runtime values; [`SanitizedDomProjection::build`] strips them
/// regardless.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomNode {
    pub tag: String,
    pub attributes: BTreeMap<String, String>,
    pub text: Option<String>,
    pub children: Vec<DomNode>,
}

impl DomNode {
    pub fn new(
        tag: String,
        attributes: BTreeMap<String, String>,
        text: Option<String>,
        children: Vec<DomNode>,
    ) -> Self {
        Self {
            tag,
            attributes,
            text,
            children,
        }
    }
}

/// Evidence counters for the mechanical sanitization applied to a DOM
/// projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomSanitization {
    pub removed_runtime_values: u32,
    pub removed_sensitive_attributes: u32,
}

/// Bounded sanitized-DOM projection. Runtime form/script/style/template values
/// and every non-structural attribute are removed before the projection exists.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "SanitizedDomProjectionParts")]
pub struct SanitizedDomProjection {
    pub metadata: ReadMetadata,
    pub root: DomNode,
    pub sanitization: DomSanitization,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SanitizedDomProjectionParts {
    metadata: ReadMetadata,
    root: DomNode,
    sanitization: DomSanitization,
}

impl TryFrom<SanitizedDomProjectionParts> for SanitizedDomProjection {
    type Error = CapabilityError;

    fn try_from(parts: SanitizedDomProjectionParts) -> Result<Self, Self::Error> {
        let projection = Self {
            metadata: parts.metadata,
            root: parts.root,
            sanitization: parts.sanitization,
        };
        projection.validate()?;
        Ok(projection)
    }
}

impl SanitizedDomProjection {
    pub fn build(basis: ReadBasis, root: DomNode) -> Result<Self, CapabilityError> {
        basis.validate()?;
        let (root, sanitization, visited, kept, total_bytes, emitted_bytes) =
            sanitize_dom(root, basis.max_bytes);
        let truncated = kept < visited || total_bytes > emitted_bytes;
        let bound = BoundReport::new(basis.max_bytes, emitted_bytes, Some(total_bytes), truncated)?;
        let reason = collect_reason(
            &basis,
            &bound,
            &format!(
                "{visited} nodes observed, {kept} kept (bound {MAX_DOM_NODES}); {} runtime \
                 values and {} sensitive attributes removed",
                sanitization.removed_runtime_values, sanitization.removed_sensitive_attributes
            ),
        );
        Ok(Self {
            metadata: metadata(&basis, bound, &reason),
            root,
            sanitization,
        })
    }

    pub fn validate(&self) -> Result<(), CapabilityError> {
        let (nodes, bytes) = validate_dom_node(&self.root, false)?;
        if nodes > MAX_DOM_NODES {
            return Err(CapabilityError::BoundExceeded {
                limit: MAX_DOM_NODES as u64,
                requested: nodes as u64,
            });
        }
        validate_projection_bytes(&self.metadata, bytes)
    }
}

const RUNTIME_VALUE_TAGS: [&str; 8] = [
    "input", "textarea", "select", "option", "script", "style", "template", "noscript",
];
const DOM_ATTRIBUTE_ALLOWLIST: [&str; 3] = ["contenteditable", "role", "type"];

#[derive(Clone, Copy)]
enum RemovedDomAttribute {
    RuntimeValue,
    Sensitive,
}

fn removed_dom_attribute(runtime_container: bool, key: &str) -> Option<RemovedDomAttribute> {
    if key.eq_ignore_ascii_case("aria-valuenow")
        || key.eq_ignore_ascii_case("aria-valuetext")
        || (runtime_container && key.eq_ignore_ascii_case("value"))
    {
        return Some(RemovedDomAttribute::RuntimeValue);
    }
    if !DOM_ATTRIBUTE_ALLOWLIST
        .iter()
        .any(|attribute| key.eq_ignore_ascii_case(attribute))
    {
        return Some(RemovedDomAttribute::Sensitive);
    }
    None
}

fn is_runtime_container(tag: &str, attributes: &BTreeMap<String, String>) -> bool {
    RUNTIME_VALUE_TAGS
        .iter()
        .any(|candidate| tag.eq_ignore_ascii_case(candidate))
        || attributes.iter().any(|(key, value)| {
            key.eq_ignore_ascii_case("contenteditable")
                && !value.trim().eq_ignore_ascii_case("false")
        })
}

fn dom_stats(node: &DomNode, suppress_runtime_text: bool) -> (usize, u64) {
    let runtime_container = is_runtime_container(&node.tag, &node.attributes);
    let suppress_runtime_text = suppress_runtime_text || runtime_container;
    let mut nodes = 1_usize;
    let mut bytes = 0_u64;
    add_string_bytes(&mut bytes, &node.tag);
    for (key, value) in &node.attributes {
        if removed_dom_attribute(runtime_container, key).is_none() {
            add_string_bytes(&mut bytes, key);
            add_string_bytes(&mut bytes, value);
        }
    }
    if !suppress_runtime_text {
        if let Some(text) = &node.text {
            add_string_bytes(&mut bytes, text);
        }
    }
    for child in &node.children {
        let (child_nodes, child_bytes) = dom_stats(child, suppress_runtime_text);
        nodes = nodes.saturating_add(child_nodes);
        bytes = bytes.saturating_add(child_bytes);
    }
    (nodes, bytes)
}

fn sanitize_dom(
    root: DomNode,
    max_bytes: u64,
) -> (DomNode, DomSanitization, usize, usize, u64, u64) {
    let (visited, total_bytes) = dom_stats(&root, false);
    let mut counters = DomSanitization {
        removed_runtime_values: 0,
        removed_sensitive_attributes: 0,
    };
    let mut byte_budget = ProjectionBudget::new(max_bytes);
    let (node, kept) = sanitize_node(root, MAX_DOM_NODES, &mut byte_budget, &mut counters, false);
    (
        node,
        counters,
        visited,
        kept,
        total_bytes,
        byte_budget.emitted,
    )
}

fn sanitize_node(
    node: DomNode,
    node_budget: usize,
    byte_budget: &mut ProjectionBudget,
    counters: &mut DomSanitization,
    suppress_runtime_text: bool,
) -> (DomNode, usize) {
    let DomNode {
        mut tag,
        attributes: source_attributes,
        text,
        children: source_children,
    } = node;
    let runtime_container = is_runtime_container(&tag, &source_attributes);
    let suppress_runtime_text = suppress_runtime_text || runtime_container;
    tag.make_ascii_lowercase();
    let tag = byte_budget.take_fragment(tag);

    let mut attributes = BTreeMap::new();
    for (key, value) in source_attributes {
        if let Some(removed) = removed_dom_attribute(runtime_container, &key) {
            match removed {
                RemovedDomAttribute::RuntimeValue => {
                    counters.removed_runtime_values =
                        counters.removed_runtime_values.saturating_add(1);
                }
                RemovedDomAttribute::Sensitive => {
                    counters.removed_sensitive_attributes =
                        counters.removed_sensitive_attributes.saturating_add(1);
                }
            }
            continue;
        }
        if key.len() > MAX_FRAGMENT_BYTES || !byte_budget.take_exact(key.len() as u64) {
            continue;
        }
        attributes.insert(key, byte_budget.take_fragment(value));
    }

    let text = match text {
        Some(_) if suppress_runtime_text => {
            counters.removed_runtime_values = counters.removed_runtime_values.saturating_add(1);
            None
        }
        Some(text) => Some(byte_budget.take_fragment(text)),
        None => None,
    };

    let mut kept = 1_usize;
    let mut children = Vec::new();
    for child in source_children {
        if kept >= node_budget || byte_budget.remaining() == 0 {
            break;
        }
        let (pruned, child_kept) = sanitize_node(
            child,
            node_budget - kept,
            byte_budget,
            counters,
            suppress_runtime_text,
        );
        kept += child_kept;
        children.push(pruned);
    }
    (
        DomNode {
            tag,
            attributes,
            text,
            children,
        },
        kept,
    )
}

fn validate_dom_node(
    node: &DomNode,
    suppress_runtime_text: bool,
) -> Result<(usize, u64), CapabilityError> {
    validate_fragment(&node.tag)?;
    if node.tag.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(CapabilityError::InvalidRequest {
            reason: "sanitized DOM tags must be ASCII lowercase".to_owned(),
        });
    }
    let runtime_container = is_runtime_container(&node.tag, &node.attributes);
    let suppress_runtime_text = suppress_runtime_text || runtime_container;
    let mut bytes = 0_u64;
    add_string_bytes(&mut bytes, &node.tag);
    for (key, value) in &node.attributes {
        if removed_dom_attribute(runtime_container, key).is_some() {
            return Err(CapabilityError::InvalidRequest {
                reason: "sanitized DOM contains a runtime or sensitive attribute".to_owned(),
            });
        }
        validate_fragment(key)?;
        validate_fragment(value)?;
        add_string_bytes(&mut bytes, key);
        add_string_bytes(&mut bytes, value);
    }
    if suppress_runtime_text && node.text.is_some() {
        return Err(CapabilityError::InvalidRequest {
            reason: "sanitized DOM contains a runtime form value".to_owned(),
        });
    }
    if let Some(text) = &node.text {
        validate_fragment(text)?;
        add_string_bytes(&mut bytes, text);
    }

    let mut nodes = 1_usize;
    for child in &node.children {
        let (child_nodes, child_bytes) = validate_dom_node(child, suppress_runtime_text)?;
        nodes = nodes.saturating_add(child_nodes);
        bytes = bytes.saturating_add(child_bytes);
    }
    Ok((nodes, bytes))
}
