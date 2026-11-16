//! The daemon's `files.*` route over the declared `[[file_roots]]` a seat
//! may read. A root on this host is read with the file gateway's confined
//! code in process; a root on another fleet host runs that same code there
//! (`odin host-file`) over the registered SSH binding.

#[path = "host_files/queue.rs"]
mod queue;

use std::sync::Arc;

use odin_domain::huginn::{FileMetadata, FileRoot, RelativePath};
use odin_hermes::runtime::shared_files::HostFileRoute;
use serde_json::{json, Value};
use std::io::{Seek, SeekFrom};

use crate::claude_host_transport::ClaudeHostTransport;

/// Most entries one listing or search returns.
const LIST_LIMIT: u16 = 200;

pub(crate) struct DaemonHostFiles {
    pub(crate) roots: Vec<FileRoot>,
    /// The host this daemon runs on; roots without a host are here too.
    pub(crate) here: Option<String>,
    pub(crate) pin: Arc<odin_registry::SnapshotHandle>,
    pub(crate) transport: ClaudeHostTransport,
    pub(crate) state_dir: std::path::PathBuf,
    pub(crate) queue_gate: std::sync::Mutex<()>,
}

fn entry(metadata: &FileMetadata) -> Value {
    json!({
        "path": metadata.relative_path.as_str(),
        "kind": metadata.entry_kind,
        "sizeBytes": metadata.byte_len,
        "mediaType": metadata.media_type,
        "modifiedAt": metadata
            .modified_at
            .and_then(|at| at.format(&time::format_description::well_known::Rfc3339).ok()),
    })
}

fn relative(path: &str) -> Result<RelativePath, String> {
    RelativePath::parse(path.trim_matches('/'))
        .map_err(|error| format!("{path:?} is not a path inside the folder: {error}"))
}

/// The one root declaring `seat`'s save default, and that folder.
fn save_default<'r>(roots: &'r [FileRoot], seat: &str) -> Result<(&'r FileRoot, &'r str), String> {
    let mut defaults = roots.iter().filter_map(|root| {
        root.save_default
            .as_deref()
            .filter(|_| {
                root.allowed_seats
                    .iter()
                    .any(|allowed| allowed.as_str() == seat)
            })
            .map(|folder| (root, folder))
    });
    match (defaults.next(), defaults.next()) {
        (Some(default), None) => Ok(default),
        (None, _) => Err(format!(
            "no declared folder is seat {seat}'s save default; name a root"
        )),
        (Some(_), Some(_)) => Err(format!(
            "more than one declared folder is seat {seat}'s save default"
        )),
    }
}

/// The folders `seat` may read, one annotated entry each, for errors
/// that name the next move.
fn folder_line(roots: &[FileRoot], here: Option<&str>, seat: &str) -> String {
    let folders: Vec<String> = roots
        .iter()
        .filter(|root| {
            root.allowed_seats
                .iter()
                .any(|allowed| allowed.as_str() == seat)
        })
        .map(|root| {
            let host = root.host.as_deref().or(here).unwrap_or("this host");
            format!(
                "{} ({} {})",
                root.root_id.as_str(),
                host,
                root.canonical_path.display()
            )
        })
        .collect();
    if folders.is_empty() {
        "no declared folder is open to this seat".to_owned()
    } else {
        folders.join(", ")
    }
}

/// The declared root `root_id` when `seat` may read it; otherwise a refusal naming the seat's folders.
fn open_root<'r>(
    roots: &'r [FileRoot],
    here: Option<&str>,
    seat: &str,
    root_id: &str,
) -> Result<&'r FileRoot, String> {
    roots
        .iter()
        .find(|root| {
            root.root_id.as_str() == root_id
                && root
                    .allowed_seats
                    .iter()
                    .any(|allowed| allowed.as_str() == seat)
        })
        .ok_or_else(|| {
            format!(
                "no folder {root_id:?} is open to seat {seat}; folders: {}",
                folder_line(roots, here, seat)
            )
        })
}

impl DaemonHostFiles {
    fn root(&self, seat: &str, root_id: &str) -> Result<&FileRoot, String> {
        open_root(&self.roots, self.here.as_deref(), seat, root_id)
    }

    fn host_of<'r>(&'r self, root: &'r FileRoot) -> Option<&'r str> {
        root.host
            .as_deref()
            .filter(|host| Some(*host) != self.here.as_deref())
    }

    /// Runs `odin host-file` for `root` on its host; `request` adds the operation.
    fn remote(
        &self,
        host: &str,
        root: &FileRoot,
        request: Value,
        input: Option<&[u8]>,
        limit: usize,
    ) -> Result<Value, String> {
        let (tailscale, command) = self.remote_command(host, root, request)?;
        let bytes = self
            .transport
            .run_remote(&tailscale, command, input, limit)
            .map_err(|error| format!("reading {} on {host} failed: {error}", root.root_id))?;
        serde_json::from_slice(&bytes)
            .map_err(|error| format!("{host} sent an unreadable host-file reply: {error}"))
    }

    fn remote_command(
        &self,
        host: &str,
        root: &FileRoot,
        mut request: Value,
    ) -> Result<(String, String), String> {
        let registry = self.pin.current();
        let tailscale = registry
            .listed_objects(odin_registry::RegistryKind::Host)
            .into_iter()
            .find_map(|object| match &object.config {
                odin_registry::ObjectConfig::Host(declared)
                    if object.id == host && declared.enabled && declared.enrolled =>
                {
                    Some(declared.tailscale.clone())
                }
                _ => None,
            })
            .filter(|name| !name.is_empty() && !name.starts_with('-'))
            .ok_or_else(|| format!("host {host} is not an enabled, enrolled fleet host"))?;
        request["root"] = serde_json::to_value(root).map_err(|error| error.to_string())?;
        let command = format!(
            "odin host-file {}",
            odin_process::shell_quote(&request.to_string())
        );
        Ok((tailscale, command))
    }
}

impl HostFileRoute for DaemonHostFiles {
    fn save_status(&self, seat: &str, id: &str) -> Result<Value, String> {
        self.queued_status(seat, id)
    }
    fn roots(&self, seat: &str) -> Vec<Value> {
        self.roots
            .iter()
            .filter(|root| {
                root.allowed_seats
                    .iter()
                    .any(|allowed| allowed.as_str() == seat)
            })
            .map(|root| {
                json!({
                    "root": root.root_id.as_str(),
                    "host": root.host.as_deref().or(self.here.as_deref()),
                    "name": root.display_name,
                })
            })
            .collect()
    }

    fn list(
        &self,
        seat: &str,
        root_id: &str,
        directory: Option<&str>,
        find: Option<&str>,
    ) -> Result<(Vec<Value>, bool), String> {
        let root = self.root(seat, root_id)?;
        let directory = directory.map(relative).transpose()?;
        let (entries, truncated): (Vec<FileMetadata>, bool) = match self.host_of(root) {
            None => {
                let found =
                    odin_huginn::files::find_in_root(root, directory.as_ref(), find, LIST_LIMIT)
                        .map_err(|error| format!("{root_id}: {error}"))?;
                (found.entries, found.truncated)
            }
            Some(host) => {
                let reply = self.remote(
                    host,
                    root,
                    json!({ "directory": directory, "find": find, "maxBytes": 0, "limit": LIST_LIMIT }),
                    None,
                    4 * 1024 * 1024,
                )?;
                let entries = serde_json::from_value(reply["entries"].clone())
                    .map_err(|error| format!("{host} sent an unreadable listing: {error}"))?;
                (entries, reply["truncated"] == true)
            }
        };
        Ok((entries.iter().map(entry).collect(), truncated))
    }

    fn read(
        &self,
        seat: &str,
        root_id: &str,
        path: &str,
    ) -> Result<(String, String, std::fs::File), String> {
        let root = self.root(seat, root_id)?;
        let relative = relative(path)?;
        let (metadata, file) = match self.host_of(root) {
            None => odin_huginn::files::open_from_root(root, &relative)
                .map_err(|error| format!("{root_id} {path}: {error}"))?,
            Some(host) => {
                let reply = self.remote(
                    host,
                    root,
                    json!({ "stat": relative, "maxBytes": 0, "limit": 1 }),
                    None,
                    64 * 1024,
                )?;
                let metadata: FileMetadata = serde_json::from_value(reply["metadata"].clone())
                    .map_err(|error| format!("{host} sent unreadable file metadata: {error}"))?;
                let (tailscale, command) = self.remote_command(host, root,
                    json!({ "read": relative, "maxBytes": root.max_object_bytes.get(), "limit": 1 }))?;
                let mut file = tempfile::tempfile().map_err(|error| error.to_string())?;
                self.transport.run_remote_file(
                    &tailscale,
                    command,
                    None,
                    Some(file.try_clone().map_err(|error| error.to_string())?),
                )?;
                if file.metadata().map_err(|error| error.to_string())?.len() != metadata.byte_len {
                    return Err(format!(
                        "{host} sent a different number of bytes than {}",
                        metadata.byte_len
                    ));
                }
                file.seek(SeekFrom::Start(0))
                    .map_err(|error| error.to_string())?;
                (metadata, file)
            }
        };
        let name = metadata.relative_path.as_path().file_name().map_or_else(
            || path.to_owned(),
            |name| name.to_string_lossy().into_owned(),
        );
        Ok((
            name,
            metadata
                .media_type
                .unwrap_or_else(|| "application/octet-stream".to_owned()),
            file,
        ))
    }

    fn save(
        &self,
        seat: &str,
        root_id: Option<&str>,
        folder: Option<&str>,
        name: &str,
        source: &mut std::fs::File,
        original: Option<&odin_hermes::runtime::shared_files::RootSource>,
    ) -> Result<Value, String> {
        let (root, folder) = match root_id {
            Some(root_id) => (self.root(seat, root_id)?, folder.map(str::to_owned)),
            None => {
                let (root, base) = save_default(&self.roots, seat)?;
                let folder = match folder {
                    Some(folder) => format!("{base}/{}", folder.trim_matches('/')),
                    None => base.to_owned(),
                };
                (root, Some(folder))
            }
        };
        let folder = folder.as_deref().map(relative).transpose()?;
        self.save_or_queue(seat, root, folder.as_ref(), name, source, original)
    }

    fn save_new(
        &self,
        seat: &str,
        root_id: &str,
        name: &str,
        source: &mut std::fs::File,
    ) -> Result<Value, String> {
        save_new(
            &self.roots,
            self.here.as_deref(),
            seat,
            root_id,
            name,
            source,
        )
    }
}

/// `intake.copy`'s write: a new file at the top of a declared readWrite root
/// on this host, refused when the name is taken.
fn save_new(
    roots: &[FileRoot],
    here: Option<&str>,
    seat: &str,
    root_id: &str,
    name: &str,
    source: &mut std::fs::File,
) -> Result<Value, String> {
    let root = open_root(roots, here, seat, root_id)?;
    if root.access != odin_domain::huginn::FileRootAccess::ReadWrite {
        return Err(format!("{root_id} is read-only"));
    }
    if let Some(host) = root.host.as_deref().filter(|host| Some(*host) != here) {
        return Err(format!(
            "{root_id} is on {host}; only a root on this host takes a copy"
        ));
    }
    let (byte_len, digest) = queue::identity(source)?;
    let saved = odin_huginn::files::save::save_new_into_root(root, name, source, byte_len, digest)
        .map_err(|error| format!("{root_id}: {error}"))?;
    Ok(json!({
        "host": here.unwrap_or_default(),
        "root": root_id,
        "path": saved.as_str(),
        "sizeBytes": byte_len,
    }))
}

#[cfg(test)]
#[path = "host_files/streaming_tests.rs"]
mod streaming_tests;

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use odin_domain::huginn::{
        FileMediaPolicy, FileRootAccess, FileRootId, FileRootInit, FileWatchPolicy,
    };
    use odin_domain::SeatId;

    use super::*;

    fn init(id: &str, seat: &str, save_default: Option<&str>) -> FileRootInit {
        FileRootInit {
            root_id: FileRootId::parse(id).unwrap(),
            display_name: id.to_owned(),
            canonical_path: "/srv/files".into(),
            access: FileRootAccess::ReadWrite,
            media_policy: FileMediaPolicy {
                allowed_media_types: Vec::new(),
            },
            max_object_bytes: NonZeroU64::new(1).unwrap(),
            watch_policy: FileWatchPolicy::Disabled,
            allowed_seats: vec![SeatId::new(seat).unwrap()],
            host: None,
            save_default: save_default.map(str::to_owned),
        }
    }

    fn root(id: &str, seat: &str, save_default: Option<&str>) -> FileRoot {
        FileRoot::new(init(id, seat, save_default)).unwrap()
    }

    #[test]
    fn a_save_default_is_a_folder_of_a_writable_root() {
        let read_only = FileRootInit {
            access: FileRootAccess::ReadOnly,
            ..init("documents", "sinmara", Some("Sinmara"))
        };
        assert!(FileRoot::new(read_only).is_err());
        assert!(FileRoot::new(init("downloads", "sinmara", Some("../up"))).is_err());
    }

    #[test]
    fn a_root_not_open_to_the_seat_is_refused_by_name() {
        let roots = [root("downloads", "sinmara", None)];
        let refusal = open_root(&roots, Some("pc"), "kubert", "downloads").unwrap_err();
        assert!(refusal.contains("no folder"), "{refusal}");
        assert!(open_root(&roots, Some("pc"), "sinmara", "downloads").is_ok());
    }

    #[test]
    fn a_copy_lands_once_in_a_writable_root_here_and_is_refused_otherwise() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().canonicalize().unwrap();
        let writable = |id: &str, access, host: Option<&str>| {
            FileRoot::new(FileRootInit {
                canonical_path: path.clone(),
                access,
                media_policy: FileMediaPolicy {
                    allowed_media_types: vec!["application/octet-stream".to_owned()],
                },
                max_object_bytes: NonZeroU64::new(1 << 20).unwrap(),
                host: host.map(str::to_owned),
                ..init(id, "sinmara", None)
            })
            .unwrap()
        };
        let roots = [
            writable("cfd-incoming", FileRootAccess::ReadWrite, None),
            writable("recon", FileRootAccess::ReadOnly, None),
            writable(
                "laptop-downloads",
                FileRootAccess::ReadWrite,
                Some("laptop"),
            ),
        ];
        let source = path.join("staged");
        std::fs::write(&source, b"tdms bytes").unwrap();
        let copy = |root: &str, name: &str| {
            let mut file = std::fs::File::open(&source).unwrap();
            save_new(&roots, Some("mini"), "sinmara", root, name, &mut file)
        };

        let saved = copy("cfd-incoming", "run1.tdms").unwrap();
        assert_eq!(saved["path"], "run1.tdms");
        assert_eq!(saved["sizeBytes"], 10);
        assert_eq!(
            std::fs::read(path.join("run1.tdms")).unwrap(),
            b"tdms bytes"
        );

        let taken = copy("cfd-incoming", "run1.tdms").unwrap_err();
        assert!(taken.contains("already exists"), "{taken}");
        let undeclared = copy("elsewhere", "run2.tdms").unwrap_err();
        assert!(
            undeclared.contains("no folder \"elsewhere\""),
            "{undeclared}"
        );
        let read_only = copy("recon", "run2.tdms").unwrap_err();
        assert!(read_only.contains("recon is read-only"), "{read_only}");
        let remote = copy("laptop-downloads", "run2.tdms").unwrap_err();
        assert!(remote.contains("is on laptop"), "{remote}");
        assert!(!path.join("run2.tdms").exists());
    }
}
