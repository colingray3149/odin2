//! Workflow capabilities on the authority: stages a call's input files, runs
//! the compiled workflow, then turns its `artifacts` into shared artifacts,
//! its `preview` images into image blocks, and its `pages` into generated
//! vault pages. A step after the run that fails is reported in `failed`, since
//! the workflow's effect already happened.

use super::tools::NO_ARTIFACTS;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};

use odin_domain::{CapabilityId, Scope};
use odin_omp::host_tools::workflow::WorkflowRunner;
use odin_omp::host_tools::{ConsumedHostCommand, HostToolError};
use odin_registry::schema::WORKFLOW_HANDLER_ID;
use odin_workflows::{Call, Catalog, Failure, FailureKind};
use serde_json::{json, Value};

use super::images::{image_block, view_jpeg, TURN_IMAGE_BASE64};
use super::HermesRuntime;

const TOOL: &str = WORKFLOW_HANDLER_ID;

/// The zone a call carries when the owner's clock names none.
const FALLBACK_ZONE: &str = "UTC";

/// Composes the authority's workflow runner over `catalog` and binds it for
/// approval plans.
pub fn workflow_runner(runtime: &Arc<HermesRuntime>, catalog: Catalog) -> Arc<dyn WorkflowRunner> {
    runtime
        .workflows
        .get_or_init(|| {
            let catalog = super::desktop::with_workflow_desk(runtime, catalog);
            Arc::new(HermesWorkflows {
                runtime: Arc::downgrade(runtime),
                catalog,
            })
        })
        .clone()
}

impl HermesRuntime {
    /// The owner's current IANA time zone.
    pub fn owner_time_zone(&self) -> String {
        self.clock
            .zone()
            .iana_name()
            .unwrap_or(FALLBACK_ZONE)
            .to_owned()
    }

    /// The owner's calendar date (`YYYY-MM-DD`) at an RFC 3339 instant.
    pub fn owner_date(&self, instant: &str) -> Result<String, String> {
        let at: jiff::Timestamp = instant
            .parse()
            .map_err(|error| format!("{instant:?} is not an RFC 3339 time: {error}"))?;
        Ok(at.to_zoned(self.clock.zone()).date().to_string())
    }

    /// The exact plan an approval card shows for a workflow capability.
    pub(super) fn workflow_plan(
        &self,
        capability: &str,
        request: &Value,
    ) -> Result<String, String> {
        let runner = self
            .workflows
            .get()
            .ok_or("workflow plans are not composed on this host")?;
        let id = CapabilityId::new(capability).map_err(|error| error.to_string())?;
        runner.plan(&id, request)
    }

    /// Preflights the same registered docs workflow before authority report completion uses its context.
    pub fn workflow_context(&self) -> Result<&odin_workflows::Ctx, String> {
        let runner = self
            .workflows
            .get()
            .ok_or("workflows are not composed on this host")?;
        runner
            .catalog
            .preflight("docs.render")
            .map_err(|failure| failure.cause)?;
        Ok(runner.catalog.ctx())
    }

    /// The shared workflow context without any family's preflight: for tools that declare their own executables.
    pub fn tool_context(&self) -> Result<&odin_workflows::Ctx, String> {
        self.workflows
            .get()
            .map(|runner| runner.catalog.ctx())
            .ok_or_else(|| "workflows are not composed on this host".to_owned())
    }
}

pub(super) struct HermesWorkflows {
    runtime: Weak<HermesRuntime>,
    catalog: Catalog,
}

impl HermesWorkflows {
    fn runtime(&self) -> Result<Arc<HermesRuntime>, HostToolError> {
        self.runtime
            .upgrade()
            .ok_or_else(|| HostToolError::unavailable(TOOL, "the hermes runtime has stopped"))
    }

    /// Stages, runs `work`, and removes the call's folders whatever happened.
    fn with_call<T>(
        &self,
        runtime: &HermesRuntime,
        scope: &Scope,
        key: String,
        arguments: &Value,
        work: impl FnOnce(&Call) -> Result<T, HostToolError>,
    ) -> Result<T, HostToolError> {
        let mut call = Call {
            key,
            seat: scope
                .seat
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default(),
            tz: runtime.owner_time_zone(),
            files: Vec::new(),
        };
        let outcome =
            stage_inputs(runtime, &self.catalog, scope, &call, arguments).and_then(|files| {
                call.files = files;
                work(&call)
            });
        if let Err(error) = self.catalog.ctx().release(&call) {
            tracing::warn!("hermes: workflow {} scratch not removed: {error}", call.key);
        }
        outcome
    }

    /// Plans run for the conversation owner, whose approval they ask for.
    fn owner_plan(
        &self,
        capability: &CapabilityId,
        arguments: &Value,
    ) -> Result<String, HostToolError> {
        let runtime = self.runtime()?;
        let scope = runtime
            .ownership
            .as_ref()
            .map(|owner| Scope {
                seat: Some(owner.seat.clone()),
                project: Some(owner.project.clone()),
                ..Scope::default()
            })
            .unwrap_or_default();
        let key = format!("plan-{}", uuid::Uuid::new_v4());
        self.with_call(&runtime, &scope, key, arguments, |call| {
            self.catalog
                .plan(capability.as_str(), call, arguments)
                .map_err(to_host)
        })
    }
}

impl WorkflowRunner for HermesWorkflows {
    fn compiled(&self, capability: &CapabilityId) -> bool {
        self.catalog.compiled(capability.as_str())
    }

    fn preflight(
        &self,
        capability: &CapabilityId,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        self.catalog
            .preflight(capability.as_str())
            .map_err(to_host)?;
        let Some(plan) = self
            .catalog
            .workflow(capability.as_str())
            .and_then(|workflow| workflow.plan)
        else {
            return Ok(());
        };
        // A digest-dependent preview discovers mutable intake identity from the
        // caller's own artifacts.
        if plan.intake_sha256
            && arguments.get("intake").is_some()
            && arguments.get("sha256").is_none()
        {
            let runtime = self.runtime()?;
            let key = format!("preflight-{}", uuid::Uuid::new_v4());
            return self.with_call(&runtime, scope, key, arguments, |call| {
                self.catalog
                    .plan(capability.as_str(), call, arguments)
                    .map(|_| ())
                    .map_err(to_host)
            });
        }
        // Every other preview runs as the owner's question will, before any approval
        // is asked for: a call the preview refuses (an ambiguous title, a missing
        // file) comes back to the caller instead of an approval no question can show.
        // A preview that merely cannot run (a service is down) still lets the question
        // be asked, with the exact arguments in its place.
        match self.owner_plan(capability, arguments) {
            Ok(_) => Ok(()),
            Err(HostToolError::Unavailable { reason, .. }) => {
                tracing::warn!(
                    "odin-hermes: {capability} has no preview, asking with its arguments: {reason}"
                );
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn run(
        &self,
        capability: &CapabilityId,
        scope: &Scope,
        arguments: &Value,
        consumed: &ConsumedHostCommand,
    ) -> Result<Value, HostToolError> {
        let runtime = self.runtime()?;
        let key = consumed.command_id().to_string();
        self.with_call(&runtime, scope, key, arguments, |call| {
            let mut out = self
                .catalog
                .run(capability.as_str(), call, arguments)
                .map_err(to_host)?;
            for step in [
                share_artifacts(&runtime, scope, &mut out),
                attach_previews(&mut out),
                write_pages(&runtime, &mut out),
            ] {
                if let Err(cause) = step {
                    note_failed(&mut out, &cause);
                }
            }
            out["capability"] = json!(capability.as_str());
            Ok(out)
        })
    }

    fn plan(&self, capability: &CapabilityId, arguments: &Value) -> Result<String, String> {
        self.owner_plan(capability, arguments)
            .map_err(|error| error.to_string())
    }
}

/// Copies inputs in the order artifact, artifacts, intake, asset, reference.
fn stage_inputs(
    runtime: &HermesRuntime,
    catalog: &Catalog,
    scope: &Scope,
    call: &Call,
    arguments: &Value,
) -> Result<Vec<PathBuf>, HostToolError> {
    let text = |key: &str| arguments.get(key).and_then(Value::as_str);
    let mut artifacts: Vec<&str> = text("artifact").into_iter().collect();
    artifacts.extend(
        arguments
            .get("artifacts")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str),
    );
    let (intake, asset, reference) = (text("intake"), text("asset"), text("reference"));
    if artifacts.is_empty() && intake.is_none() && asset.is_none() && reference.is_none() {
        return Ok(Vec::new());
    }
    let dir = catalog.ctx().inputs(call).map_err(to_host)?;
    let refused = |id: &str, cause: String| HostToolError::Arguments {
        tool: TOOL,
        detail: format!("input {id} could not be staged: {cause}"),
    };
    let mut files = Vec::new();
    if !artifacts.is_empty() {
        let route = runtime
            .coding_route()
            .ok_or_else(|| HostToolError::unavailable(TOOL, NO_ARTIFACTS))?;
        for artifact in artifacts {
            let (mut file, media_type) = route
                .artifact_file(scope, artifact)
                .map_err(|cause| refused(artifact, cause))?;
            let name = super::files::artifact_file_name(artifact, &media_type);
            files
                .push(copy_into(&dir, &name, &mut file).map_err(|cause| refused(artifact, cause))?);
        }
    }
    if let Some(intake) = intake {
        let root = runtime.settings.state_dir.join("intake");
        let (path, name) = super::files::staged_file(&root, Some(intake), None)
            .map_err(|cause| refused(intake, cause))?;
        let mut file =
            std::fs::File::open(&path).map_err(|error| refused(intake, error.to_string()))?;
        files.push(copy_into(&dir, &name, &mut file).map_err(|cause| refused(intake, cause))?);
    }
    if let Some(asset) = asset {
        let (name, mut file) = runtime
            .original_asset(asset)
            .map_err(|cause| refused(asset, cause))?;
        files.push(copy_into(&dir, &name, &mut file).map_err(|cause| refused(asset, cause))?);
    }
    if let Some(reference) = reference {
        let route = runtime
            .coding_route()
            .ok_or_else(|| HostToolError::unavailable(TOOL, NO_ARTIFACTS))?;
        let (mut file, media_type) = route
            .artifact_file(scope, reference)
            .map_err(|cause| refused(reference, cause))?;
        let name = super::files::artifact_file_name(reference, &media_type);
        files.push(copy_into(&dir, &name, &mut file).map_err(|cause| refused(reference, cause))?);
    }
    Ok(files)
}

fn copy_into(dir: &Path, name: &str, source: &mut std::fs::File) -> Result<PathBuf, String> {
    let plain = Path::new(name).file_name().map_or_else(
        || "input".to_owned(),
        |base| base.to_string_lossy().into_owned(),
    );
    let target = odin_workflows::paths::unique(dir, &plain);
    let mut copy = std::fs::File::create(&target)
        .map_err(|error| format!("{} could not be created: {error}", target.display()))?;
    std::io::copy(source, &mut copy)
        .map_err(|error| format!("{} could not be written: {error}", target.display()))?;
    Ok(target)
}

/// `"artifacts": [path]` → `[{artifact: "blake3:…", name, bytes}]`.
fn share_artifacts(runtime: &HermesRuntime, scope: &Scope, out: &mut Value) -> Result<(), String> {
    let Some(paths) = out.get("artifacts").and_then(Value::as_array).cloned() else {
        return Ok(());
    };
    let route = runtime
        .coding_route()
        .ok_or("artifacts are not composed on this host, so the result's files were not shared")?;
    let mut shared = Vec::new();
    for path in &paths {
        let path = Path::new(path.as_str().ok_or("an artifacts entry is not a path")?);
        let mut file = std::fs::File::open(path)
            .map_err(|error| format!("{} could not be shared: {error}", path.display()))?;
        let bytes = file.metadata().map_or(0, |meta| meta.len());
        let artifact = route.share_file(scope, &mut file, media_type(path))?;
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned());
        shared.push(json!({ "artifact": artifact, "name": name, "bytes": bytes }));
    }
    out["artifacts"] = Value::Array(shared);
    Ok(())
}

/// `"preview": [path]` → `"images": [image block]`.
fn attach_previews(out: &mut Value) -> Result<(), String> {
    let Some(paths) = out
        .as_object_mut()
        .and_then(|fields| fields.remove("preview"))
    else {
        return Ok(());
    };
    let mut images = Vec::new();
    for path in paths
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        let bytes = std::fs::read(path).map_err(|error| format!("preview {path}: {error}"))?;
        let jpeg = view_jpeg(&bytes, TURN_IMAGE_BASE64)
            .map_err(|cause| format!("preview {path} cannot be shown: {cause}"))?;
        images.push(image_block(&jpeg));
    }
    out["images"] = Value::Array(images);
    Ok(())
}

/// `"pages": [{path, text}]` → generated vault pages, summarized in `done`.
fn write_pages(runtime: &HermesRuntime, out: &mut Value) -> Result<(), String> {
    let Some(pages) = out
        .as_object_mut()
        .and_then(|fields| fields.remove("pages"))
    else {
        return Ok(());
    };
    let pages = pages.as_array().cloned().unwrap_or_default();
    let vault = runtime.vault.as_ref().ok_or_else(|| {
        format!(
            "the vault is not configured, so {} page(s) were not written",
            pages.len()
        )
    })?;
    let mut written = Vec::new();
    for page in &pages {
        let (Some(path), Some(text)) = (page["path"].as_str(), page["text"].as_str()) else {
            return Err("a pages entry needs a path and a text".to_owned());
        };
        let page_name = format!("{}/{path}", vault.config().generated_namespace);
        vault
            .write_generated(&crate::vault::VaultWriteGeneratedInput {
                page_name: page_name.clone(),
                content: text.to_owned(),
            })
            .map_err(|error| format!("page {path} was not written: {error}"))?;
        written.push(path.to_owned());
    }
    if let Some(done) = out["done"].as_str() {
        out["done"] = json!(format!("{done} Wrote vault pages: {}.", written.join(", ")));
    }
    Ok(())
}

fn note_failed(out: &mut Value, cause: &str) {
    let failed = match out["failed"].as_str() {
        Some(earlier) => format!("{earlier}; {cause}"),
        None => cause.to_owned(),
    };
    out["failed"] = json!(failed);
}

/// The media type a released file is stored under: the shared extension
/// table, plus the few types workflows produce that it does not list.
fn media_type(path: &Path) -> &'static str {
    let extension = path
        .extension()
        .map(|extension| extension.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    match extension.as_str() {
        "mkv" => "video/x-matroska",
        "epub" => "application/epub+zip",
        "srt" | "vtt" => "text/plain",
        _ => path
            .to_str()
            .and_then(odin_domain::huginn::media_type_for_name)
            .unwrap_or("application/octet-stream"),
    }
}

fn to_host(failure: Failure) -> HostToolError {
    match failure.kind {
        FailureKind::Arguments => HostToolError::Arguments {
            tool: TOOL,
            detail: failure.cause,
        },
        FailureKind::Unavailable | FailureKind::Upstream => HostToolError::Unavailable {
            tool: TOOL,
            reason: failure.cause,
        },
        FailureKind::Uncertain => HostToolError::Uncertain {
            tool: TOOL,
            detail: failure.cause,
        },
    }
}

#[cfg(test)]
#[path = "workflows_tests.rs"]
mod tests;
