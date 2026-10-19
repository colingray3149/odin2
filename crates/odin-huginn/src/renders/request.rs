use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use async_trait::async_trait;
use odin_domain::huginn::{ContentSource, HuginnProtocolError, RenderLimits};
use serde_json::Value;

use super::registry::{RenderInput, Renderer};
use crate::files::roots::{file_limit, file_unavailable, invalid_file};
use crate::files::BrowseEngine;

#[async_trait]
pub trait RenderSourceResolver: Send + Sync {
    async fn resolve(&self, source: &ContentSource) -> Result<RenderInput, HuginnProtocolError>;
}

#[derive(Clone)]
pub struct FileRenderSource {
    browse: BrowseEngine,
}

impl FileRenderSource {
    pub fn new(browse: BrowseEngine) -> Self {
        Self { browse }
    }
}

#[async_trait]
impl RenderSourceResolver for FileRenderSource {
    async fn resolve(&self, source: &ContentSource) -> Result<RenderInput, HuginnProtocolError> {
        let ContentSource::File {
            root,
            relative,
            expected_revision,
        } = source
        else {
            return Err(HuginnProtocolError::Unsupported {
                operation: "render source is not a declared file root".to_owned(),
            });
        };
        let (file, metadata) = self
            .browse
            .open_for_render(root, relative, *expected_revision)?;
        let media_type = metadata
            .media_type
            .ok_or_else(|| invalid_file("render source media is not declared by its root"))?;
        if matches!(media_type.as_str(), "text/html" | "application/xhtml+xml") {
            return Err(invalid_file(
                "active HTML cannot be used as a render source",
            ));
        }
        Ok(RenderInput {
            file,
            media_type,
            byte_len: metadata.byte_len,
            source_revision: metadata.revision,
        })
    }
}

#[derive(Clone, Default)]
pub struct CopyRenderer;

#[async_trait]
impl Renderer for CopyRenderer {
    async fn render(
        &self,
        input: RenderInput,
        parameters: Value,
        limits: RenderLimits,
        output: &Path,
    ) -> Result<(), HuginnProtocolError> {
        if !parameters.is_null() && parameters.as_object().is_none_or(|value| !value.is_empty()) {
            return Err(invalid_file("copy renderer does not accept parameters"));
        }
        if input.byte_len > limits.max_output_bytes.get() {
            return Err(file_limit("render-output-bytes"));
        }
        // Owned by the calling job until it returns, never a detached task.
        super::blocking(|| {
            let mut target = create_output(output)?;
            let mut source = input
                .file
                .take(limits.max_output_bytes.get().saturating_add(1));
            let copied = std::io::copy(&mut source, &mut target)
                .map_err(|_| file_unavailable("renderer-copy"))?;
            if copied > limits.max_output_bytes.get() {
                return Err(file_limit("render-output-bytes"));
            }
            target
                .flush()
                .and_then(|()| target.sync_all())
                .map_err(|_| file_unavailable("renderer-output-sync"))
        })
    }
}

#[derive(Clone, Default)]
pub struct SvgSanitizingRenderer;

#[async_trait]
impl Renderer for SvgSanitizingRenderer {
    async fn render(
        &self,
        input: RenderInput,
        parameters: Value,
        limits: RenderLimits,
        output: &Path,
    ) -> Result<(), HuginnProtocolError> {
        if input.media_type != "image/svg+xml" {
            return Err(invalid_file("SVG renderer requires image/svg+xml input"));
        }
        if !parameters.is_null() && parameters.as_object().is_none_or(|value| !value.is_empty()) {
            return Err(invalid_file("SVG renderer does not accept parameters"));
        }
        let maximum = limits.max_output_bytes.get();
        if input.byte_len > maximum {
            return Err(file_limit("render-output-bytes"));
        }
        let capacity =
            usize::try_from(input.byte_len).map_err(|_| file_limit("render-output-bytes"))?;
        // Owned by the calling job until it returns, never a detached task.
        super::blocking(|| {
            let mut bytes = Vec::with_capacity(capacity);
            input
                .file
                .take(maximum.saturating_add(1))
                .read_to_end(&mut bytes)
                .map_err(|_| file_unavailable("renderer-svg-read"))?;
            if bytes.len() as u64 > maximum {
                return Err(file_limit("render-output-bytes"));
            }
            let sanitized = super::sanitize_svg(&bytes, capacity)?;
            let mut target = create_output(output)?;
            target
                .write_all(&sanitized)
                .and_then(|()| target.flush())
                .and_then(|()| target.sync_all())
                .map_err(|_| file_unavailable("renderer-output-write"))
        })
    }
}

fn create_output(path: &Path) -> Result<File, HuginnProtocolError> {
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| file_unavailable("renderer-output-create"))
}
