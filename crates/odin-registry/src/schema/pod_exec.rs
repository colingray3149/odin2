//! Pod-exec capabilities: a CLI tool from the agent pod's own image, run as
//! one declared argv. Model input fills only declared placeholders and
//! options, each as exactly one argv element; nothing is ever a shell.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::workload::valid_pod_path;

/// The `implementation` of a pod-exec capability.
pub const POD_EXEC_IMPLEMENTATION: &str = "pod-exec";
/// The reserved handler marker every pod-exec capability binds.
pub const POD_EXEC_HANDLER_ID: &str = "odin_pod_exec.run";
/// The reserved evidence marker every pod-exec capability binds.
pub const POD_EXEC_RECEIPT_ID: &str = "odin_pod_exec.receipt";

/// The `[exec]` table of a pod-exec capability.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PodExecToml {
    pub executable: String,
    /// Fixed tokens; `{field}` in a token is that input field's value
    /// (`{path}`, `if={path}`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argv: Vec<String>,
    /// Optional input field -> flag, appended as `flag value` (`flag` alone for `true`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub options: BTreeMap<String, String>,
    /// The required string input field naming the page PNG this call shows.
    /// The host reads that file's bytes back whole and returns them as an
    /// image block; the text result does not carry them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view: Option<String>,
    /// What the tool reads on stdin. Absent when the tool reads nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin: Option<PodExecStdin>,
    /// Absent means `direct`. `vpn-required` runs only in a protected pod.
    #[serde(
        default,
        skip_serializing_if = "super::workload::WorkloadTransport::is_direct"
    )]
    pub transport: super::workload::WorkloadTransport,
}

/// What a pod tool reads on stdin. `url` fetches a public page. `source`
/// hands one required string field through as UTF-8 bytes. The two are exclusive.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PodExecStdin {
    /// The required string input field holding a public page URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// The optional boolean input field asking for that page as the browser
    /// draws it (a PNG) instead of its bytes as published.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub render: Option<String>,
    /// The required string input field written to the tool as UTF-8 bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl PodExecStdin {
    /// Whether this table fetches a page.
    pub fn fetches(&self) -> bool {
        self.url.is_some()
    }

    /// The web-save mode `input` asks for: `render` or `document`.
    pub fn mode(&self, input: &Value) -> &'static str {
        let render = self
            .render
            .as_ref()
            .and_then(|field| input.get(field))
            .and_then(Value::as_bool);
        if render == Some(true) {
            "render"
        } else {
            "document"
        }
    }

    /// The UTF-8 bytes of the declared source field.
    pub fn source_bytes(&self, input: &Value) -> Result<Vec<u8>, String> {
        let field = self
            .source
            .as_deref()
            .ok_or_else(|| "[exec] stdin has no source field".to_owned())?;
        let text = input
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("input field {field:?} is required as a string"))?;
        Ok(text.as_bytes().to_vec())
    }
}

/// A token's placeholder: the text before it, the field it names, and the text after.
fn placeholder(token: &str) -> Option<(&str, &str, &str)> {
    let (before, rest) = token.split_once('{')?;
    let (field, after) = rest.split_once('}')?;
    (!field.is_empty()).then_some((before, field, after))
}

impl PodExecToml {
    /// Checks the table against the capability's input schema. The error
    /// names the field at fault; the caller names the capability.
    pub fn validate(&self, input_schema: &Value) -> Result<(), String> {
        if !valid_pod_path(&self.executable) {
            return Err(format!(
                "[exec] executable {:?} is not an absolute in-image path",
                self.executable
            ));
        }
        let properties = input_schema.get("properties").and_then(Value::as_object);
        let property_type = |field: &str| {
            properties
                .and_then(|properties| properties.get(field))
                .and_then(|property| property.get("type"))
                .and_then(Value::as_str)
        };
        let required = |field: &str| {
            input_schema
                .get("required")
                .and_then(Value::as_array)
                .is_some_and(|required| required.iter().any(|name| name.as_str() == Some(field)))
        };
        let scalar = |field: &str, place: &str| match property_type(field) {
            Some("string" | "integer" | "boolean") => Ok(()),
            Some(other) => Err(format!(
                "[exec] {place} names input field {field:?} of type {other:?}; only string, \
                 integer and boolean fields become argv"
            )),
            None => Err(format!(
                "[exec] {place} names input field {field:?}, which its input schema does not \
                 declare with a type"
            )),
        };
        for token in &self.argv {
            if token.is_empty() || token.contains('\0') {
                return Err("[exec] argv holds an empty or NUL-bearing token".to_owned());
            }
            let malformed = match placeholder(token) {
                Some((before, field, after)) => {
                    before.contains(['{', '}'])
                        || field.contains(['{', '}'])
                        || after.contains(['{', '}'])
                }
                None => token.contains(['{', '}']),
            };
            if malformed {
                return Err(format!(
                    "[exec] argv token {token:?} must contain at most one complete {{field}} slot"
                ));
            }
            if let Some((_, field, _)) = placeholder(token) {
                if !required(field) {
                    return Err(format!(
                        "[exec] argv placeholder {token} is not a required property of its input \
                         schema"
                    ));
                }
                scalar(field, "argv placeholder")?;
            }
        }
        for (field, flag) in &self.options {
            if !flag.starts_with('-') || flag.len() < 2 || flag.chars().any(char::is_whitespace) {
                return Err(format!(
                    "[exec] option {field:?} maps to {flag:?}, which is not one flag token"
                ));
            }
            scalar(field, "option")?;
        }
        if let Some(stdin) = &self.stdin {
            match (&stdin.url, &stdin.source) {
                (Some(url), None) => {
                    if !required(url) || property_type(url) != Some("string") {
                        return Err(format!(
                            "[exec] stdin url names input field {url:?}, which is not a required \
                             string property of its input schema"
                        ));
                    }
                    if let Some(render) = stdin
                        .render
                        .as_ref()
                        .filter(|render| property_type(render) != Some("boolean"))
                    {
                        return Err(format!(
                            "[exec] stdin render names input field {render:?}, which its input \
                             schema does not declare as a boolean"
                        ));
                    }
                }
                (None, Some(source)) => {
                    if stdin.render.is_some() {
                        return Err("[exec] stdin source does not take a render field".to_owned());
                    }
                    if !required(source) || property_type(source) != Some("string") {
                        return Err(format!(
                            "[exec] stdin source names input field {source:?}, which is not a \
                             required string property of its input schema"
                        ));
                    }
                }
                _ => return Err("[exec] stdin must name exactly one of url or source".to_owned()),
            }
        }
        if self.view.is_some() && self.stdin.as_ref().is_some_and(PodExecStdin::fetches) {
            return Err("[exec] view cannot share a table that fetches a page".to_owned());
        }
        if let Some(view) = &self.view {
            if !self
                .argv
                .iter()
                .any(|token| placeholder(token).is_some_and(|(_, field, _)| field == view))
            {
                return Err(format!(
                    "[exec] view names input field {view:?}, which no argv placeholder carries"
                ));
            }
            if !required(view) || property_type(view) != Some("string") {
                return Err(format!(
                    "[exec] view names input field {view:?}, which is not a required string \
                     property of its input schema"
                ));
            }
        }
        Ok(())
    }

    /// The tool's argv after the executable, rendered from schema-validated
    /// input. The error names the input field at fault.
    pub fn render(&self, input: &Value) -> Result<Vec<String>, String> {
        let input = input
            .as_object()
            .ok_or_else(|| "the input is not an object".to_owned())?;
        let mut argv = Vec::with_capacity(self.argv.len() + 2 * self.options.len());
        for token in &self.argv {
            match placeholder(token) {
                Some((before, field, after)) => {
                    let value = input
                        .get(field)
                        .ok_or_else(|| format!("input field {field:?} is required"))?;
                    argv.push(format!("{before}{}{after}", value_token(field, value)?));
                }
                None => argv.push(token.clone()),
            }
        }
        for (field, flag) in &self.options {
            match input.get(field) {
                None | Some(Value::Null) | Some(Value::Bool(false)) => {}
                Some(Value::Bool(true)) => argv.push(flag.clone()),
                Some(value) => {
                    argv.push(flag.clone());
                    argv.push(value_token(field, value)?);
                }
            }
        }
        Ok(argv)
    }
}

/// One input value as one argv element; a value that could read as a flag is refused.
fn value_token(field: &str, value: &Value) -> Result<String, String> {
    let token = match value {
        Value::String(text) => text.clone(),
        Value::Number(number) if number.is_i64() || number.is_u64() => number.to_string(),
        Value::Bool(flag) => flag.to_string(),
        _ => {
            return Err(format!(
                "input field {field:?} is not a string, integer or boolean"
            ))
        }
    };
    if token.is_empty() || token.contains('\0') {
        return Err(format!(
            "input field {field:?} is empty or holds a NUL byte"
        ));
    }
    if token.starts_with('-') {
        return Err(format!(
            "input field {field:?} begins with '-', so the tool could read it as a flag"
        ));
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;



}
