use std::collections::BTreeMap;
use std::fs::File;
use std::path::Path;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use odin_domain::huginn::{HuginnProtocolError, RenderKind, RenderLimits, RendererId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::files::roots::{file_conflict, file_not_found, file_unavailable, invalid_file};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RendererDescriptor {
    pub renderer: RendererId,
    pub version: String,
    pub accepted_media_types: Vec<String>,
    pub output_kind: RenderKind,
    pub output_media_type: String,
}

impl RendererDescriptor {
    pub fn validate(&self) -> Result<(), HuginnProtocolError> {
        if self.version.is_empty() || self.version.as_bytes().contains(&0) {
            return Err(invalid_file("renderer version is invalid"));
        }
        if self.accepted_media_types.is_empty() {
            return Err(invalid_file(
                "renderer must declare at least one input media type",
            ));
        }
        for media in &self.accepted_media_types {
            validate_passive_media(media)?;
        }
        if !self
            .output_kind
            .media_type_is_valid(&self.output_media_type)
        {
            return Err(invalid_file(
                "renderer output media does not match its safe output kind",
            ));
        }
        validate_passive_media(&self.output_media_type)
    }

    pub fn accepts(&self, media_type: &str) -> bool {
        self.accepted_media_types
            .iter()
            .any(|accepted| accepted == media_type)
    }
}

pub struct RenderInput {
    pub file: File,
    pub media_type: String,
    pub byte_len: u64,
    pub source_revision: Option<odin_domain::Digest>,
}

#[async_trait]
pub trait Renderer: Send + Sync {
    async fn render(
        &self,
        input: RenderInput,
        parameters: Value,
        limits: RenderLimits,
        output: &Path,
    ) -> Result<(), HuginnProtocolError>;
}

#[derive(Clone)]
pub struct RegisteredRenderer {
    pub descriptor: RendererDescriptor,
    pub executor: Arc<dyn Renderer>,
}

#[derive(Clone, Default)]
pub struct RendererRegistry {
    entries: Arc<RwLock<BTreeMap<(RendererId, String), RegisteredRenderer>>>,
}

impl RendererRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        &self,
        descriptor: RendererDescriptor,
        executor: Arc<dyn Renderer>,
    ) -> Result<(), HuginnProtocolError> {
        descriptor.validate()?;
        let key = (descriptor.renderer.clone(), descriptor.version.clone());
        let mut entries = self
            .entries
            .write()
            .map_err(|_| file_unavailable("render-registry"))?;
        if entries.contains_key(&key) {
            return Err(file_conflict(
                "rendererExists",
                "renderer id and version are already registered",
            ));
        }
        entries.insert(
            key,
            RegisteredRenderer {
                descriptor,
                executor,
            },
        );
        Ok(())
    }

    pub fn resolve(
        &self,
        renderer: &RendererId,
        version: &str,
    ) -> Result<RegisteredRenderer, HuginnProtocolError> {
        self.entries
            .read()
            .map_err(|_| file_unavailable("render-registry"))?
            .get(&(renderer.clone(), version.to_owned()))
            .cloned()
            .ok_or_else(|| file_not_found("renderer", format!("{renderer}@{version}")))
    }

    pub fn descriptors(&self) -> Result<Vec<RendererDescriptor>, HuginnProtocolError> {
        Ok(self
            .entries
            .read()
            .map_err(|_| file_unavailable("render-registry"))?
            .values()
            .map(|entry| entry.descriptor.clone())
            .collect())
    }
}

fn validate_passive_media(media_type: &str) -> Result<(), HuginnProtocolError> {
    if media_type.is_empty()
        || media_type.split_once('/').is_none()
        || media_type.bytes().any(|byte| {
            byte.is_ascii_control() || byte.is_ascii_whitespace() || matches!(byte, b';' | b',')
        })
    {
        return Err(invalid_file("renderer media type must be a bare MIME type"));
    }
    if matches!(media_type, "text/html" | "application/xhtml+xml") {
        return Err(invalid_file("active HTML renderers are prohibited"));
    }
    Ok(())
}
