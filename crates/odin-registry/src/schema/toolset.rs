//! A model-facing category: one line saying what it is for and a few call shapes.

use serde::{Deserialize, Serialize};

use super::RegistryKind;

/// A model-facing category: one line saying what it is for and a few call shapes.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolsetToml {
    pub schema: String,
    pub kind: RegistryKind,
    pub enabled: bool,
    /// One line (`TOOLSET_DESCRIPTION_MAX_CHARS`): what the category is for, in the owner's words.
    pub description: String,
    /// Call shapes (`TOOLSET_EXAMPLES_MIN`..=`TOOLSET_EXAMPLES_MAX`), each `{op: "…", field: …}`; only shapes whose op a seat holds are shown to it.
    pub examples: Vec<String>,
}
