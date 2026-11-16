//! Workspace file access and content-addressed artifact storage and sharing.

use std::path::{Path, PathBuf};

use odin_domain::Scope;
use odin_hermes::runtime::coding::MAX_ARTIFACT_TEXT;

use super::DaemonCodingRoute;

const MAX_ARTIFACT_BYTES: u64 = 32 * 1024 * 1024;
/// The in-pod export mount that research profiles declare as `[export] pod_path`.
const POD_EXPORT_ROOT: &str = "/export";
impl DaemonCodingRoute {
    /// The bytes of one file inside the calling session's workspace.
    pub(super) fn workspace_file(&self, scope: &Scope, path: &str) -> Result<Vec<u8>, String> {
        if Path::new(path).starts_with(POD_EXPORT_ROOT) {
            return Err(format!(
                "{path:?} is inside the pod's export folder, which lives in the pod until its run \
                 settles and is then delivered; to hand over its content now, pass the text \
                 (up to {MAX_ARTIFACT_TEXT} bytes) as `text` instead"
            ));
        }
        let workspace = self.workspace(scope)?;
        let relative = Path::new(path);
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(format!("{path:?} is not a path inside your workspace"));
        }
        let canonical = workspace
            .join(relative)
            .canonicalize()
            .map_err(|error| format!("{path}: {error}"))?;
        let root = workspace
            .canonicalize()
            .map_err(|error| format!("the workspace is unreadable: {error}"))?;
        if !canonical.starts_with(&root) || !canonical.is_file() {
            return Err(format!("{path:?} is not a file inside your workspace"));
        }
        let size = canonical
            .metadata()
            .map_err(|error| format!("{path}: {error}"))?
            .len();
        if size > MAX_ARTIFACT_BYTES {
            return Err(format!(
                "{path} is {size} bytes; an artifact holds at most {MAX_ARTIFACT_BYTES}"
            ));
        }
        std::fs::read(&canonical).map_err(|error| format!("{path}: {error}"))
    }

    /// The calling session's capsule workspace, git repository or not.
    pub(super) fn workspace(&self, scope: &Scope) -> Result<PathBuf, String> {
        let session = scope
            .session
            .as_ref()
            .ok_or("this dispatch is not bound to a session")?;
        let capsule_id = odin_omp::host_tools::operations::session_capsule_id(session)
            .map_err(|error| error.to_string())?;
        let path = self
            .state_root
            .join("session-authorities")
            .join(format!("capsule-{}", capsule_id.as_str().replace(':', "-")))
            .join("capsule")
            .join("project");
        if !path.is_dir() {
            return Err("this session has no workspace capsule".to_owned());
        }
        Ok(path)
    }

    pub(super) fn artifact_root(&self) -> PathBuf {
        self.state_root.join("huginn").join("artifacts")
    }

    pub(super) fn ledger(&self) -> Result<odin_ledger::Ledger, String> {
        odin_ledger::Ledger::open(self.state_root.join("ledger.sqlite3"))
            .map_err(|error| format!("the controller ledger could not be opened: {error}"))
    }

    pub(super) fn share_existing_artifact(
        &self,
        scope: &Scope,
        id: &str,
        media_type: Option<&str>,
        shares: &[(&'static str, String)],
    ) -> Result<odin_ledger::artifact::ArtifactMetadata, String> {
        use odin_hermes::runtime::coding::CodingRoute;

        // Verify both the caller's authority and the complete original before granting access.
        let (_file, original_type) = self.artifact_file(scope, id)?;
        if media_type.is_some_and(|requested| requested != original_type) {
            return Err("an existing artifact retains its original media type".to_owned());
        }
        let mut ledger = self.ledger()?;
        let mut metadata = ledger
            .artifact(&controller_artifact_id(id)?)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("no artifact {id} is shared with you"))?;
        metadata = attach_shares(&mut ledger, metadata, shares)?;
        Ok(metadata)
    }
}

/// Grants each `(kind, id)` read access to the artifact and returns its metadata at the final revision.
fn attach_shares(
    ledger: &mut odin_ledger::Ledger,
    mut metadata: odin_ledger::artifact::ArtifactMetadata,
    shares: &[(&'static str, String)],
) -> Result<odin_ledger::artifact::ArtifactMetadata, String> {
    for (kind, id) in shares {
        let attached = ledger
            .attach_artifact_reference(
                &metadata.artifact_id,
                metadata.revision,
                odin_ledger::artifact::NewArtifactReference {
                    object_kind: kind,
                    object_id: id,
                    relation: "readable",
                    created_at: time::OffsetDateTime::now_utc(),
                },
            )
            .map_err(|error| format!("the artifact could not be shared with {id}: {error}"))?;
        metadata = match attached {
            odin_ledger::artifact::AttachReference::Added(metadata)
            | odin_ledger::artifact::AttachReference::Existing(metadata) => metadata,
        };
    }
    Ok(metadata)
}

/// A media type from the file name, when the caller named none.
pub(crate) fn media_type_of(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("txt" | "log") => "text/plain",
        Some("md") => "text/markdown",
        Some("json") => "application/json",
        Some("csv") => "text/csv",
        Some("toml") => "application/toml",
        Some("py" | "rs" | "sh" | "nix") => "text/plain",
        Some("html") => "text/html",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("svg") => "image/svg+xml",
        Some("pdf") => "application/pdf",
        _ => "application/octet-stream",
    }
}

/// Stores content-addressed bytes and grants access to each `(kind, id)` reference.
pub(crate) fn store_artifact(
    state_root: &Path,
    bytes: &[u8],
    media_type: &str,
    shares: &[(&'static str, String)],
) -> Result<odin_ledger::artifact::ArtifactMetadata, String> {
    let digest = odin_domain::Digest::hash(bytes).to_string();
    let hex = digest.trim_start_matches("blake3:");
    let storage_path = format!("cas/{}/{hex}", &hex[..2]);
    let mut ledger = odin_ledger::Ledger::open(state_root.join("ledger.sqlite3"))
        .map_err(|error| format!("the controller ledger could not be opened: {error}"))?;
    let metadata = ledger
        .register_artifact(odin_ledger::artifact::ArtifactRegistration {
            bytes,
            media_type,
            storage_path: &storage_path,
            retention: odin_ledger::artifact::RetentionClass::Canonical,
            created_at: time::OffsetDateTime::now_utc(),
        })
        .map_err(|error| format!("the artifact could not be registered: {error}"))?;
    // The bytes live at the registered path (an earlier registration of
    // the same content keeps its own); written atomically, once.
    let stored = state_root
        .join("huginn")
        .join("artifacts")
        .join(&metadata.storage_path);
    if !stored.is_file() {
        let parent = stored.parent().ok_or("the artifact path has no parent")?;
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("the artifact store is not writable: {error}"))?;
        let stage = || -> std::io::Result<()> {
            use std::io::Write;
            let mut staging = tempfile::NamedTempFile::new_in(parent)?;
            staging.write_all(bytes)?;
            match staging.persist_noclobber(&stored) {
                Err(error) if error.error.kind() != std::io::ErrorKind::AlreadyExists => {
                    Err(error.error)
                }
                _ => Ok(()),
            }
        };
        stage().map_err(|error| format!("the artifact bytes could not be stored: {error}"))?;
    }
    attach_shares(&mut ledger, metadata, shares)
}

/// Stores a stream atomically in the same canonical CAS as byte artifacts.
pub(crate) fn store_artifact_file(
    state_root: &Path,
    source: &mut std::fs::File,
    media_type: &str,
    shares: &[(&'static str, String)],
) -> Result<odin_ledger::artifact::ArtifactMetadata, String> {
    use std::io::{Read, Seek, SeekFrom, Write};
    let root = state_root.join("huginn/artifacts");
    std::fs::create_dir_all(&root).map_err(|error| error.to_string())?;
    let mut staging = tempfile::NamedTempFile::new_in(&root).map_err(|error| error.to_string())?;
    source
        .seek(SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = source
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        staging
            .write_all(&buffer[..count])
            .map_err(|error| error.to_string())?;
        hasher.update(&buffer[..count]);
    }
    staging
        .as_file()
        .sync_all()
        .map_err(|error| error.to_string())?;
    let hex = hasher.finalize().to_hex().to_string();
    let storage_path = format!("cas/{}/{hex}", &hex[..2]);
    let mut ledger = odin_ledger::Ledger::open(state_root.join("ledger.sqlite3"))
        .map_err(|error| error.to_string())?;
    let existing = ledger
        .artifact_by_digest(&odin_domain::Digest::new(*hasher.finalize().as_bytes()))
        .map_err(|error| error.to_string())?;
    let path = existing.as_ref().map_or(storage_path.as_str(), |metadata| {
        metadata.storage_path.as_str()
    });
    let destination = root.join(path);
    let parent = destination
        .parent()
        .ok_or("the artifact path has no parent")?;
    std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    match staging.persist_noclobber(&destination) {
        Ok(_) => {}
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.to_string()),
    }
    std::fs::File::open(parent)
        .and_then(|dir| dir.sync_all())
        .map_err(|error| error.to_string())?;
    let mut stored = std::fs::File::open(&destination).map_err(|error| error.to_string())?;
    let metadata = match existing {
        Some(metadata) => {
            let mut verified = blake3::Hasher::new();
            verified
                .update_reader(&mut stored)
                .map_err(|error| error.to_string())?;
            if verified.finalize().as_bytes() != metadata.digest.as_bytes()
                || stored.metadata().map_err(|error| error.to_string())?.len()
                    != metadata.size_bytes
            {
                return Err(format!(
                    "{}'s stored bytes fail their digest",
                    metadata.artifact_id
                ));
            }
            metadata
        }
        None => ledger
            .register_artifact_file(
                &mut stored,
                media_type,
                &storage_path,
                odin_ledger::artifact::RetentionClass::Canonical,
                time::OffsetDateTime::now_utc(),
            )
            .map_err(|error| error.to_string())?,
    };
    if metadata.digest.as_bytes() != hasher.finalize().as_bytes() {
        return Err("stored artifact differs from the streamed original".to_owned());
    }
    attach_shares(&mut ledger, metadata, shares)
}

/// The controller id of an artifact: `blake3:<hex>` as written, or a Huginn
/// upload's `artifact:<session>:<hex>`, which names the same bytes.
pub(crate) fn controller_artifact_id(raw: &str) -> Result<odin_domain::ArtifactId, String> {
    let digest = match raw
        .strip_prefix("artifact:")
        .and_then(|rest| rest.split_once(':'))
    {
        Some((_session, hex)) => format!("blake3:{hex}"),
        None => raw.to_owned(),
    };
    odin_domain::ArtifactId::new(&digest)
        .ok()
        .filter(|_| digest.parse::<odin_domain::Digest>().is_ok())
        .ok_or_else(|| {
            format!("{raw:?} is not an artifact id (blake3:<hex> or artifact:<session>:<hex>)")
        })
}

/// One `shareWith` entry as a ledger reference: `project:<id>` names a
/// project, anything else a seat.
pub(super) fn share_reference(entry: &str) -> Result<(&'static str, String), String> {
    let (kind, id) = match entry.strip_prefix("project:") {
        Some(project) => ("project", project),
        None => ("seat", entry.strip_prefix("seat:").unwrap_or(entry)),
    };
    if !odin_registry::schema::valid_id(id) {
        return Err(format!("shareWith {entry:?} is not a seat or project:<id>"));
    }
    Ok((kind, id.to_owned()))
}
