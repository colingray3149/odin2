//! Confined host-file operations. Reads and saves use binary streams on stdout/stdin.

use clap::Args;
use odin_domain::huginn::{FileRoot, RelativePath};
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Args)]
pub(crate) struct HostFileArgs {
    /// JSON request; file bytes travel separately over stdin/stdout.
    request: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HostFileRequest {
    root: FileRoot,
    directory: Option<RelativePath>,
    find: Option<String>,
    read: Option<RelativePath>,
    stat: Option<RelativePath>,
    remove: Option<RemoveRequest>,
    save: Option<SaveRequest>,
    max_bytes: u64,
    limit: u16,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RemoveRequest {
    path: RelativePath,
    digest: odin_domain::Digest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SaveRequest {
    id: uuid::Uuid,
    folder: Option<RelativePath>,
    name: String,
    byte_len: u64,
    digest: odin_domain::Digest,
}

pub(crate) fn host_file(
    arguments: HostFileArgs,
    output: &mut impl std::io::Write,
) -> Result<(), String> {
    use std::io::Read;
    let request: HostFileRequest = serde_json::from_str(&arguments.request)
        .map_err(|error| format!("host-file request is malformed: {error}"))?;
    let root = &request.root;
    if let Some(remove) = &request.remove {
        odin_huginn::files::browse::remove_verified_source(
            &request.root,
            &remove.path,
            remove.digest,
        )
        .map_err(|error| error.to_string())?;
        serde_json::to_writer(output, &json!({"closed":true}))
            .map_err(|error| error.to_string())?;
        return Ok(());
    }
    let reply = if let Some(save) = &request.save {
        let saved = odin_huginn::files::save::save_stream_into_root_with_id(
            root,
            save.folder.as_ref(),
            &save.name,
            &mut std::io::stdin().lock(),
            save.byte_len,
            save.digest,
            save.id,
        )
        .map_err(|error| format!("{} {}: {error}", root.root_id, save.name))?;
        json!({ "saved": saved, "byteLen": save.byte_len, "digest": save.digest })
    } else if let Some(relative) = request.read.as_ref().or(request.stat.as_ref()) {
        let (metadata, file) = odin_huginn::files::open_from_root(root, relative)
            .map_err(|error| format!("{} {relative}: {error}", root.root_id))?;
        if request.stat.is_some() {
            json!({ "metadata": metadata })
        } else {
            if metadata.byte_len > request.max_bytes {
                return Err("file-object-bytes".to_owned());
            }
            let copied = std::io::copy(&mut file.take(metadata.byte_len.saturating_add(1)), output)
                .map_err(|error| error.to_string())?;
            if copied != metadata.byte_len {
                return Err("file changed length while it was read".to_owned());
            }
            return Ok(());
        }
    } else {
        let found = odin_huginn::files::find_in_root(
            root,
            request.directory.as_ref(),
            request.find.as_deref(),
            request.limit.max(1),
        )
        .map_err(|error| format!("{}: {error}", root.root_id))?;
        json!({ "entries": found.entries, "truncated": found.truncated })
    };
    serde_json::to_writer(&mut *output, &reply).map_err(|error| error.to_string())?;
    writeln!(output).map_err(|error| error.to_string())
}
