//! Brain roles: which engine, lanes and limits each stage of the knowledge build uses.
//! One file per role: registry/brain-roles/<role>/brain-role.toml. The folder name is the role.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::object::RegistryKind;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BrainRoleName {
    Parse,
    Ocr,
    Transcribe,
    Extract,
    Distil,
    Compile,
    Review,
    Consolidate,
    Caption,
    Embed,
    Rerank,
}

impl BrainRoleName {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Parse => "parse",
            Self::Ocr => "ocr",
            Self::Transcribe => "transcribe",
            Self::Extract => "extract",
            Self::Distil => "distil",
            Self::Compile => "compile",
            Self::Review => "review",
            Self::Consolidate => "consolidate",
            Self::Caption => "caption",
            Self::Embed => "embed",
            Self::Rerank => "rerank",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BrainEngine {
    Lane,
    Local,
}

/// A free-form knob: bool, integer, float or string. Readers take the keys they know and ignore the rest.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum BrainParam {
    Bool(bool),
    Int(i64),
    Float(f64),
    Text(String),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrainRoleToml {
    pub schema: String,
    pub kind: RegistryKind,
    pub enabled: bool,
    pub description: String,
    pub role: BrainRoleName,
    pub engine: BrainEngine,
    /// Gateway lanes in try order (bare card name, or `local/<id>`). `embed`: the embedding card.
    #[serde(default)]
    pub lanes: Vec<String>,
    /// Folder id under the models root and weight file (engine `local`; not `parse`, which uses kb-parse's built-in tools).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// `embed` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dims: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, BrainParam>,
}

impl BrainRoleToml {
    /// Every lane this role names; the relation check requires a model card for each.
    pub fn lanes(&self) -> impl Iterator<Item = &str> {
        self.lanes.iter().map(String::as_str)
    }

    /// Shape problems, each naming its cause. Empty = valid.
    pub fn check(&self) -> Vec<String> {
        let role = self.role.as_str();
        let mut problems = Vec::new();
        let allowed: &[BrainEngine] = match self.role {
            BrainRoleName::Parse
            | BrainRoleName::Transcribe
            | BrainRoleName::Embed
            | BrainRoleName::Rerank => &[BrainEngine::Local],
            _ => &[BrainEngine::Lane],
        };
        if !allowed.contains(&self.engine) {
            problems.push(format!(
                "role {role} cannot use engine {:?}; it runs only {:?}",
                self.engine, allowed
            ));
        }
        if self.engine == BrainEngine::Lane && self.lanes.is_empty() {
            problems.push(format!(
                "role {role} has engine lane and needs at least one lane"
            ));
        }
        if self.engine == BrainEngine::Local
            && self.role != BrainRoleName::Parse
            && (self.model.is_none() || self.file.is_none())
        {
            problems.push(format!("role {role} needs model and file"));
        }
        if self.role == BrainRoleName::Embed
            && (self.lanes.len() != 1
                || self.dims.is_none()
                || self.space.is_none()
                || self.sha256.is_none())
        {
            problems.push("role embed needs exactly one lane, dims, space and sha256".to_owned());
        }
        problems
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEAD: &str = "schema = \"odin.registry.v1\"\nkind = \"brain-role\"\nenabled = true\ndescription = \"d\"\n";

    fn parse(body: &str) -> BrainRoleToml {
        toml::from_str(&format!("{HEAD}{body}")).expect("role parses")
    }

    #[test]
    fn a_lane_role_needs_lanes() {
        let problems = parse("role = \"extract\"\nengine = \"lane\"\n")
            .check()
            .join(" | ");
        assert!(problems.contains("at least one lane"), "{problems}");
    }

    #[test]
    fn ocr_with_a_local_engine_is_refused() {
        let role = parse("role = \"ocr\"\nengine = \"local\"\nmodel = \"m\"\nfile = \"f\"\n");
        assert!(role.check().iter().any(|p| p.contains("cannot use engine")));
    }

    #[test]
    fn rerank_with_a_lane_engine_is_refused() {
        let role = parse("role = \"rerank\"\nengine = \"lane\"\nlanes = [\"luna\"]\n");
        assert!(role.check().iter().any(|p| p.contains("cannot use engine")));
    }

    #[test]
    fn embed_needs_its_facts() {
        let role = parse("role = \"embed\"\nengine = \"local\"\nlanes = [\"q\"]\nmodel = \"m\"\nfile = \"f.gguf\"\n");
        assert!(role
            .check()
            .iter()
            .any(|p| p.contains("dims, space and sha256")));
    }
}
