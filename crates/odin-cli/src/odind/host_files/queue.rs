//! Durable, bounded-memory saves. A private spool is the retry source, never
//! a kept artifact or an original asset. Completed records survive restart.
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use odin_domain::{
    huginn::{FileRoot, RelativePath},
    Digest,
};
use odin_hermes::runtime::shared_files::RootSource;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::DaemonHostFiles;

const SAVE_QUEUE_RETRY_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Deserialize, Serialize)]
struct SaveJob {
    id: uuid::Uuid,
    seat: String,
    root: String,
    folder: Option<RelativePath>,
    name: String,
    byte_len: u64,
    digest: Digest,
    result: Option<Value>,
    error: Option<String>,
    #[serde(default)]
    original: Option<RootSource>,
}

pub(super) fn identity(file: &mut File) -> Result<(u64, Digest), String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    let mut hasher = blake3::Hasher::new();
    hasher
        .update_reader(&mut *file)
        .map_err(|error| error.to_string())?;
    let size = file.stream_position().map_err(|error| error.to_string())?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    Ok((size, Digest::new(*hasher.finalize().as_bytes())))
}

fn persist(directory: &Path, job: &SaveJob) -> Result<(), String> {
    let mut staging =
        tempfile::NamedTempFile::new_in(directory).map_err(|error| error.to_string())?;
    serde_json::to_writer(staging.as_file_mut(), job).map_err(|error| error.to_string())?;
    staging
        .flush()
        .and_then(|()| staging.as_file().sync_all())
        .map_err(|error| error.to_string())?;
    staging
        .persist(directory.join(format!("{}.json", job.id)))
        .map_err(|error| error.to_string())?;
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| error.to_string())
}

fn offline(error: &str) -> bool {
    if [
        "Permission denied",
        "Host key verification failed",
        "REMOTE HOST IDENTIFICATION HAS CHANGED",
    ]
    .iter()
    .any(|reason| error.contains(reason))
    {
        return false;
    }
    // SSH reserves 255 for transport failure. Remote helper errors have their
    // own nonzero status and continue to be returned, not disguised as queues.
    error.contains("exit 255")
        || error.contains("exceeded its deadline")
        || error.contains("No route to host")
        || error.contains("Connection refused")
        || error.contains("Connection timed out")
}

impl DaemonHostFiles {
    pub(crate) fn start_queue(self: &Arc<Self>) -> Result<(), String> {
        std::fs::create_dir_all(&self.state_dir).map_err(|error| error.to_string())?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&self.state_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
        let weak = Arc::downgrade(self);
        std::thread::Builder::new()
            .name("host-file-saves".to_owned())
            .spawn(move || loop {
                let Some(route) = weak.upgrade() else {
                    return;
                };
                if let Err(error) = route.retry_saves() {
                    tracing::error!("host file queue: {error}");
                }
                drop(route);
                std::thread::sleep(SAVE_QUEUE_RETRY_INTERVAL);
            })
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub(super) fn save_or_queue(
        &self,
        seat: &str,
        root: &FileRoot,
        folder: Option<&RelativePath>,
        name: &str,
        source: &mut File,
        original: Option<&RootSource>,
    ) -> Result<Value, String> {
        let host = root
            .host
            .as_deref()
            .or(self.here.as_deref())
            .unwrap_or_default();
        let (byte_len, digest) = identity(source)?;
        odin_huginn::files::save::validate_save(root, name, byte_len)
            .map_err(|error| error.to_string())?;
        if let Some(original) = original {
            let source_root = self.root(seat, &original.root)?;
            super::relative(&original.path)?;
            if original.move_source
                && !original.keep
                && source_root.access != odin_domain::huginn::FileRootAccess::ReadWrite
            {
                return Err(format!("{} is read-only", source_root.root_id));
            }
        }
        if let Some(host) = self.host_of(root) {
            self.remote_command(host, root, json!({"maxBytes":0,"limit":1}))?;
        }
        let _guard = self.queue_gate.lock().map_err(|error| error.to_string())?;
        std::fs::create_dir_all(&self.state_dir).map_err(|error| error.to_string())?;
        if original.is_some_and(|original| original.keep) {
            let marker = self.keep_marker(digest);
            File::create(marker)
                .and_then(|file| file.sync_all())
                .map_err(|error| error.to_string())?;
        }
        let mut job = SaveJob {
            id: uuid::Uuid::new_v4(),
            seat: seat.to_owned(),
            root: root.root_id.to_string(),
            folder: folder.cloned(),
            name: name.to_owned(),
            byte_len,
            digest,
            result: None,
            error: None,
            original: original
                .filter(|source| source.move_source && !source.keep)
                .cloned(),
        };
        let mut spool =
            tempfile::NamedTempFile::new_in(&self.state_dir).map_err(|error| error.to_string())?;
        let copied = std::io::copy(
            &mut std::io::Read::take(source, byte_len.saturating_add(1)),
            spool.as_file_mut(),
        )
        .map_err(|error| error.to_string())?;
        if copied != byte_len {
            return Err("source changed length while it was queued".to_owned());
        }
        spool
            .as_file()
            .sync_all()
            .map_err(|error| error.to_string())?;
        spool
            .persist_noclobber(self.state_dir.join(format!("{}.data", job.id)))
            .map_err(|error| error.to_string())?;
        persist(&self.state_dir, &job)?;
        match self.deliver(&job) {
            Ok(result) => {
                job.result = Some(result);
                self.finish(&mut job)?;
                Ok(job.result.expect("finish retains the verified result"))
            }
            Err(error) if offline(&error) => Ok(json!({
                "save_id":job.id,"status":"queued","host":host,"root":root.root_id,
                "sizeBytes":byte_len,"note":"Destination is offline; the durable save will complete when it wakes."
            })),
            Err(error) => {
                job.error = Some(error.clone());
                persist(&self.state_dir, &job)?;
                Err(error)
            }
        }
    }

    fn keep_marker(&self, digest: Digest) -> std::path::PathBuf {
        self.state_dir.join(format!(
            "keep-{}",
            digest.to_string().trim_start_matches("blake3:")
        ))
    }

    /// Commit the verified destination before touching an explicitly movable
    /// source. Source unavailability never turns a successful copy into failure.
    fn finish(&self, job: &mut SaveJob) -> Result<(), String> {
        persist(&self.state_dir, job)?;
        if let Some(original) = &job.original {
            let closed: Result<bool, String> =
                if self.keep_marker(job.digest).exists() {
                    Ok(false)
                } else {
                    (|| {
                        let root = self.root(&job.seat, &original.root)?;
                        let path = super::relative(&original.path)?;
                        if let Some(host) = self.host_of(root) {
                            self.remote(host, root, json!({
                            "remove":{"path":path,"digest":job.digest},"maxBytes":0,"limit":1,
                        }), None, 64 * 1024)?;
                        } else {
                            odin_huginn::files::browse::remove_verified_source(
                                root, &path, job.digest,
                            )
                            .map_err(|error| error.to_string())?;
                        }
                        Ok(true)
                    })()
                };
            let result = job
                .result
                .as_mut()
                .expect("only a verified copy can close a source");
            match closed {
                Ok(closed) => {
                    result["sourceRetained"] = json!(!closed);
                    result["sourceClosePending"] = json!(false);
                    job.original = None;
                }
                Err(error) if offline(&error) => {
                    result["sourceClosePending"] = json!(true);
                }
                Err(error) => {
                    result["sourceRetained"] = json!(true);
                    result["sourceNote"] = json!(error);
                    job.original = None;
                }
            }
            persist(&self.state_dir, job)?;
        }
        let spool = self.state_dir.join(format!("{}.data", job.id));
        match std::fs::remove_file(spool) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
        Ok(())
    }

    fn deliver(&self, job: &SaveJob) -> Result<Value, String> {
        let root = self.root(&job.seat, &job.root)?;
        let host = root
            .host
            .as_deref()
            .or(self.here.as_deref())
            .unwrap_or_default();
        let mut source = File::open(self.state_dir.join(format!("{}.data", job.id)))
            .map_err(|error| error.to_string())?;
        if identity(&mut source)? != (job.byte_len, job.digest) {
            return Err("queued source fails its digest".to_owned());
        }
        let saved = if let Some(remote) = self.host_of(root) {
            let (tailscale, command) = self.remote_command(remote, root, json!({
                "save":{"id":job.id,"folder":job.folder,"name":job.name,"byteLen":job.byte_len,"digest":job.digest},
                "maxBytes":job.byte_len,"limit":1,
            }))?;
            let bytes = self
                .transport
                .run_remote_file(&tailscale, command, Some(source), None)?;
            let reply: Value = serde_json::from_slice(&bytes)
                .map_err(|error| format!("{remote} sent an unreadable save reply: {error}"))?;
            if reply["byteLen"].as_u64() != Some(job.byte_len)
                || reply["digest"]
                    != serde_json::to_value(job.digest).map_err(|error| error.to_string())?
            {
                return Err(format!("{remote} did not verify the saved destination"));
            }
            reply["saved"]
                .as_str()
                .ok_or_else(|| format!("{remote} sent an unreadable save reply"))?
                .to_owned()
        } else {
            odin_huginn::files::save::save_stream_into_root_with_id(
                root,
                job.folder.as_ref(),
                &job.name,
                &mut source,
                job.byte_len,
                job.digest,
                job.id,
            )
            .map_err(|error| error.to_string())?
            .to_string()
        };
        Ok(
            json!({"save_id":job.id,"status":"completed","host":host,"root":job.root,"path":saved,"sizeBytes":job.byte_len}),
        )
    }

    /// Retries every queued save once. A job that cannot be read or finished is reported and
    /// skipped, so one bad record never holds back the saves queued behind it.
    pub(super) fn retry_saves(&self) -> Result<(), String> {
        let _guard = self.queue_gate.lock().map_err(|error| error.to_string())?;
        for entry in std::fs::read_dir(&self.state_dir).map_err(|error| error.to_string())? {
            let path = entry.map_err(|error| error.to_string())?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            if let Err(error) = self.retry_job(&path) {
                tracing::error!("queued save {} was not retried: {error}", path.display());
            }
        }
        Ok(())
    }

    fn retry_job(&self, path: &std::path::Path) -> Result<(), String> {
        let mut job: SaveJob =
            serde_json::from_reader(File::open(path).map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())?;
        if job.error.is_some() {
            return Ok(());
        }
        if job.result.is_some() {
            if job.original.is_some() {
                self.finish(&mut job)?;
            }
            return Ok(());
        }
        match self.deliver(&job) {
            Ok(result) => {
                job.result = Some(result);
                self.finish(&mut job)
            }
            Err(error) if offline(&error) => Ok(()),
            Err(error) => {
                job.error = Some(error);
                persist(&self.state_dir, &job)
            }
        }
    }

    pub(super) fn queued_status(&self, seat: &str, id: &str) -> Result<Value, String> {
        let id = uuid::Uuid::parse_str(id).map_err(|error| error.to_string())?;
        let job: SaveJob = serde_json::from_reader(
            File::open(self.state_dir.join(format!("{id}.json")))
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        if job.seat != seat {
            return Err("this save belongs to another seat".to_owned());
        }
        Ok(job.result.unwrap_or_else(|| json!({"save_id":id,"status":if job.error.is_some(){"failed"}else{"queued"},"error":job.error})))
    }
}
