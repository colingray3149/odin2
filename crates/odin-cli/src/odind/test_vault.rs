//! Test-only loopback SilverBullet fixture: one isolated vault root on disk
//! served over the real `/.fs/` HTTP API on 127.0.0.1.
//!
//! Vault sources read only over HTTP, so serve the temporary root's current pages
//! to make writes visible at the next pin without touching a private vault.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::UNIX_EPOCH;

/// One isolated loopback vault: an exclusive temporary root directory plus
/// the HTTP server that exposes it. Dropping the handle stops the accept
/// loop and removes the root.
pub(crate) struct LoopbackVault {
    root: PathBuf,
    port: u16,
    _directory: tempfile::TempDir,
    stopped: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl LoopbackVault {
    /// Opens a fresh isolated vault root and starts serving its `/.fs/`
    /// API on a kernel-assigned loopback port.
    pub(crate) fn open(label: &str) -> Self {
        let directory = tempfile::tempdir().expect("isolated vault root");
        let root = directory.path().to_path_buf();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private vault root");
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback vault listener");
        let port = listener.local_addr().expect("bound port").port();
        let stopped = Arc::new(AtomicBool::new(false));
        let thread_stopped = Arc::clone(&stopped);
        let thread_root = root.clone();
        let thread = std::thread::Builder::new()
            .name(format!("loopback-vault-{label}"))
            .spawn(move || serve(thread_root, listener, thread_stopped))
            .expect("vault server thread");
        Self {
            root,
            port,
            _directory: directory,
            stopped,
            thread: Some(thread),
        }
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) const fn port(&self) -> u16 {
        self.port
    }

    /// The `X-Space-Path` this server reports, for
    /// [`odin_brain::source::silverbullet::SilverBulletSource::with_expected_space_root`].
    pub(crate) fn expected_space_root(&self) -> String {
        self.root().display().to_string()
    }
}

impl Drop for LoopbackVault {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        // Wake the blocking accept; join before the temporary root disappears.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        self.thread
            .take()
            .unwrap()
            .join()
            .expect("vault server exits");
    }
}

/// Serves one connection at a time until the listener closes. Every request
/// reads the live state of `root`, so the served revision is exactly the
/// on-disk truth at request time.
fn serve(root: PathBuf, listener: TcpListener, stopped: Arc<AtomicBool>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { break };
        if stopped.load(Ordering::Acquire) {
            break;
        }
        if handle(&root, stream).is_err() {
            // One malformed request never stops the fixture.
            continue;
        }
    }
}

fn handle(root: &Path, mut stream: TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    // Drain the remaining request head; the fixture reads no body.
    let mut line = String::new();
    while reader.read_line(&mut line)? > 0 && !line.trim().is_empty() {
        line.clear();
    }
    let path = request_line.split_whitespace().nth(1).unwrap_or("");
    let (status, headers, body) = match path {
        "/.fs/" => {
            let entries = list_entries(root);
            let body = serde_json::to_vec(&entries).expect("listing serializes");
            (
                "200 OK",
                format!("X-Space-Path: {}\r\n", root.display()),
                body,
            )
        }
        rest => match rest.strip_prefix("/.fs/") {
            Some(requested)
                if odin_brain::source::silverbullet::addressable_page_name(requested) =>
            {
                let requested = requested.replace("%20", " ");
                match std::fs::read(root.join(&requested)) {
                    Ok(body) => ("200 OK", String::new(), body),
                    Err(_) => ("404 Not Found", String::new(), Vec::new()),
                }
            }
            _ => ("404 Not Found", String::new(), Vec::new()),
        },
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\n{headers}Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.write_all(&body)?;
    stream.flush()
}

/// The recursive `/.fs/` listing: every Markdown page under `root`, sorted
/// by name, with live sizes and modification times.
fn list_entries(root: &Path) -> Vec<serde_json::Value> {
    let mut names = Vec::new();
    collect_pages(root, root, &mut names);
    names.sort();
    names
        .iter()
        .filter_map(|relative| {
            let path = root.join(relative);
            let metadata = std::fs::metadata(&path).ok()?;
            Some(serde_json::json!({
                "name": relative,
                "size": metadata.len(),
                "lastModified": modified_millis(&metadata),
                "perm": "rw",
            }))
        })
        .collect()
}

fn collect_pages(root: &Path, directory: &Path, names: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let kind = entry.file_type().expect("fixture file type");
        if kind.is_dir() {
            collect_pages(root, &path, names);
        } else if kind.is_file() && path.extension().is_some_and(|extension| extension == "md") {
            if let Ok(relative) = path.strip_prefix(root) {
                names.push(relative.to_string_lossy().replace('\\', "/"));
            }
        }
    }
}

fn modified_millis(metadata: &std::fs::Metadata) -> u64 {
    metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}
