//! Fresh, marked, isolated profile roots for one browser session.
//!
//! A session creates an opaque profile root beneath the configured parent and
//! a separate short runtime root directly beneath `/tmp`. Every created
//! directory has `0700` permissions. The Chromium user-data directory,
//! isolated `HOME`, XDG config/cache/data directories, download quarantine,
//! and Xvfb material live under the opaque profile root. The short runtime
//! root is used for `TMPDIR`, `XDG_RUNTIME_DIR`, and the create-once embedded
//! worker script, keeping Chromium's `SingletonSocket` path bounded
//! independently of the configured profile parent. Nothing is inherited from
//! the host.
//!
//! Deletion is *guarded*: both trees are removed only through
//! [`IsolatedProfile::remove`], which re-verifies every directory mode and both
//! per-profile ownership markers. The session calls it only after Chromium and
//! Xvfb have been observed to reap. Dropping this value never deletes anything;
//! unremoved trees survive for audit and sweep.

use odin_domain::huginn::ids::BrowserSessionId;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// File mode applied to every directory this module creates.
const MARKED_MODE: u32 = 0o700;
/// Marker proving that this exact generated tree belongs to the browser arm.
const MARKER_NAME: &str = ".odin-browser-profile";
const MARKER_MODE: u32 = 0o600;
const MARKER_VERSION: &str = "odin-browser-profile-v1";
const PROFILE_ID_PREFIX: &str = "odin-browser-";
const RUNTIME_PARENT: &str = "/tmp";
const RUNTIME_ROOT_PREFIX: &str = "ob-";
const SIMPLE_UUID_LEN: usize = 32;
const UNIX_SOCKET_PATH_LIMIT: usize = 108;
const CHROMIUM_SINGLETON_SUFFIX_LEN: usize = "/org.chromium.Chromium.XXXXXX/SingletonSocket".len();

// Linux `sockaddr_un.sun_path` includes its terminating NUL. Both the runtime
// root and Chromium's singleton suffix are fixed-width ASCII.
const _: () = assert!(
    RUNTIME_PARENT.len()
        + 1
        + RUNTIME_ROOT_PREFIX.len()
        + SIMPLE_UUID_LEN
        + CHROMIUM_SINGLETON_SUFFIX_LEN
        < UNIX_SOCKET_PATH_LIMIT
);

#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("profile parent cannot be created: {path}: {source}")]
    ParentUncreatable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("isolated root cannot be created at {path}: {source}")]
    RootUncreatable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("isolated root already exists after repeated generation: {path}")]
    RootCollision { path: PathBuf },
    #[error("profile directory {path} cannot be created: {source}")]
    DirectoryUncreatable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("profile ownership marker cannot be created at {path}: {source}")]
    MarkerUncreatable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("embedded worker cannot be materialized at {path}: {source}")]
    WorkerMaterialization {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("profile ownership marker is invalid at {path}: {reason}")]
    InvalidMarker { path: PathBuf, reason: &'static str },
    #[error("profile ownership marker {path} lost its 0600 mark (mode {mode:o})")]
    UnmarkedMarker { path: PathBuf, mode: u32 },
    #[error("profile directory {path} is not a directory")]
    NotADirectory { path: PathBuf },
    #[error("profile root is a symlink: {path}")]
    SymlinkedRoot { path: PathBuf },
    #[error("profile directory {path} lost its 0700 mark (mode {mode:o})")]
    Unmarked { path: PathBuf, mode: u32 },
    #[error("profile tree cannot be removed at {path}: {source}")]
    RemovalFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// One isolated profile and runtime-root pair. Creating this value performs all
/// filesystem work; nothing is created lazily.
#[derive(Clone, Debug)]
pub struct IsolatedProfile {
    /// Opaque projection identifier, also used as the profile directory name.
    id: String,
    root: PathBuf,
    marker: PathBuf,
    runtime: PathBuf,
    runtime_marker: PathBuf,
    chromium_data: PathBuf,
    home: PathBuf,
    xdg_config: PathBuf,
    xdg_cache: PathBuf,
    xdg_data: PathBuf,
    downloads: PathBuf,
    xvfb: PathBuf,
}

impl IsolatedProfile {
    /// Creates a fresh marked profile tree beneath `profile_parent` and a short
    /// marked runtime tree directly beneath `/tmp`.
    ///
    /// Both names share a fresh random UUID. Creation retries a handful of
    /// times on the (astronomically unlikely) collision rather than reusing or
    /// removing an existing tree.
    pub fn create(profile_parent: &Path) -> Result<Self, ProfileError> {
        fs::create_dir_all(profile_parent).map_err(|source| ProfileError::ParentUncreatable {
            path: profile_parent.to_path_buf(),
            source,
        })?;

        let mut last_collision: Option<PathBuf> = None;
        for _ in 0..8 {
            let opaque_id = uuid::Uuid::new_v4().simple().to_string();
            let id = format!("{PROFILE_ID_PREFIX}{opaque_id}");
            let root = profile_parent.join(&id);
            let runtime =
                Path::new(RUNTIME_PARENT).join(format!("{RUNTIME_ROOT_PREFIX}{opaque_id}"));

            match create_private_directory(&root) {
                Ok(()) => {}
                Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                    last_collision = Some(root);
                    continue;
                }
                Err(source) => return Err(ProfileError::RootUncreatable { path: root, source }),
            }

            match create_private_directory(&runtime) {
                Ok(()) => {}
                Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                    cleanup_created_roots(&[root.as_path()])?;
                    last_collision = Some(runtime);
                    continue;
                }
                Err(source) => {
                    let error = ProfileError::RootUncreatable {
                        path: runtime,
                        source,
                    };
                    return match cleanup_created_roots(&[root.as_path()]) {
                        Ok(()) => Err(error),
                        Err(cleanup_error) => Err(cleanup_error),
                    };
                }
            }

            return match Self::build(id, root.clone(), runtime.clone()) {
                Ok(profile) => Ok(profile),
                Err(error) => match cleanup_created_roots(&[runtime.as_path(), root.as_path()]) {
                    Ok(()) => Err(error),
                    Err(cleanup_error) => Err(cleanup_error),
                },
            };
        }
        Err(ProfileError::RootCollision {
            path: last_collision.unwrap_or_else(|| profile_parent.to_path_buf()),
        })
    }

    /// Adopts only existing private 0700 directories without mutating them.
    /// Creation is exclusive; symlinked, non-directory, or unmarked paths are rejected.
    pub(crate) fn ensure_serve_state_dir(state_dir: &Path) -> Result<(), ProfileError> {
        match create_private_directory(state_dir) {
            Ok(()) => {}
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                // Adopt only a real directory that already carries the
                // 0700 mark; this verification is the mutation gate.
                verify_marked(state_dir)?;
            }
            Err(source) => {
                return Err(ProfileError::RootUncreatable {
                    path: state_dir.to_path_buf(),
                    source,
                });
            }
        }
        Ok(())
    }

    /// Creates the deterministic per-session profile tree: the session UUID
    /// owns both names — the same names the host derives through
    /// [`session_profile_dir`] and [`session_runtime_dir`] — so the host
    /// composes identical remote paths before the pod creates them. An
    /// existing tree is a typed refusal: never adopted, never reused, and
    /// a tree this call did not create is never removed.
    pub fn create_for_session(
        profile_parent: &Path,
        session: &BrowserSessionId,
    ) -> Result<Self, ProfileError> {
        let id = format!("{PROFILE_ID_PREFIX}{}", session.as_uuid().simple());
        let root = session_profile_dir(profile_parent, session);
        let runtime = session_runtime_dir(session);
        let mut created: [Option<std::path::PathBuf>; 2] = [None, None];
        let opened = (|| {
            for (slot, path) in created.iter_mut().zip([&root, &runtime]) {
                match create_private_directory(path) {
                    Ok(()) => *slot = Some(path.clone()),
                    Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                        return Err(ProfileError::RootCollision {
                            path: path.to_path_buf(),
                        });
                    }
                    Err(source) => {
                        return Err(ProfileError::RootUncreatable {
                            path: path.to_path_buf(),
                            source,
                        });
                    }
                }
            }
            Self::build(id, root.clone(), runtime.clone())
        })();
        match opened {
            Ok(profile) => Ok(profile),
            // A tree this call created is removed on the way out; a tree
            // that already existed (the collision refusal) never is.
            Err(error) => match cleanup_created_roots(
                created
                    .iter()
                    .flatten()
                    .map(|path| path.as_path())
                    .collect::<Vec<&std::path::Path>>()
                    .as_slice(),
            ) {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(cleanup_error),
            },
        }
    }

    fn build(id: String, root: PathBuf, runtime: PathBuf) -> Result<Self, ProfileError> {
        mark_directory(&root)?;
        mark_directory(&runtime)?;
        let marker = create_marker(&root, &id)?;
        let runtime_marker = create_marker(&runtime, &id)?;

        let chromium_data = root.join("chromium-user-data");
        let home = root.join("home");
        let xdg_config = root.join("xdg-config");
        let xdg_cache = root.join("xdg-cache");
        let xdg_data = root.join("xdg-data");
        let downloads = root.join("downloads");
        let xvfb = root.join("xvfb");
        for directory in [
            &chromium_data,
            &home,
            &xdg_config,
            &xdg_cache,
            &xdg_data,
            &downloads,
            &xvfb,
        ] {
            create_private_directory(directory).map_err(|source| {
                ProfileError::DirectoryUncreatable {
                    path: directory.clone(),
                    source,
                }
            })?;
            mark_directory(directory)?;
        }
        for directory in [&root, &runtime] {
            sync_directory(directory).map_err(|source| ProfileError::DirectoryUncreatable {
                path: directory.clone(),
                source,
            })?;
        }
        Ok(Self {
            id,
            root,
            marker,
            runtime,
            runtime_marker,
            chromium_data,
            home,
            xdg_config,
            xdg_cache,
            xdg_data,
            downloads,
            xvfb,
        })
    }

    /// Opaque projection identifier for this profile. It carries no meaning
    /// beyond linking the live tree to projections.
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Chromium `--user-data-dir` target inside the isolated tree.
    pub fn chromium_data_dir(&self) -> &Path {
        &self.chromium_data
    }

    /// Create-once path for the statically embedded Playwright worker. The
    /// script is materialized inside the marked short runtime root so it is
    /// covered by the same guarded lifecycle as every process-private socket.
    pub fn materialize_worker(&self, source: &[u8]) -> Result<PathBuf, ProfileError> {
        self.verify_marks()?;
        let path = self.runtime.join("worker.cjs");
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o500)
                .open(&path)?;
            file.write_all(source)?;
            file.sync_all()?;
            sync_directory(&self.runtime)
        })();
        if let Err(source) = result {
            let _ = fs::remove_file(&path);
            return Err(ProfileError::WorkerMaterialization { path, source });
        }
        Ok(path)
    }

    /// Isolated `HOME` for the browser process.
    pub fn home_dir(&self) -> &Path {
        &self.home
    }

    /// Isolated `XDG_CONFIG_HOME`.
    pub fn xdg_config_dir(&self) -> &Path {
        &self.xdg_config
    }

    /// Isolated `XDG_CACHE_HOME`.
    pub fn xdg_cache_dir(&self) -> &Path {
        &self.xdg_cache
    }

    /// Isolated `XDG_DATA_HOME`.
    pub fn xdg_data_dir(&self) -> &Path {
        &self.xdg_data
    }

    /// Fresh private runtime root used for `TMPDIR` and `XDG_RUNTIME_DIR`.
    /// Its fixed-width path keeps Chromium's singleton socket below `sun_path`.
    pub fn scratch_dir(&self) -> &Path {
        &self.runtime
    }

    /// Download quarantine root. All staged download bytes live beneath it.
    pub fn download_dir(&self) -> &Path {
        &self.downloads
    }

    /// Directory for owned-Xvfb logs and authority material.
    pub fn xvfb_dir(&self) -> &Path {
        &self.xvfb
    }

    /// Re-verifies every created directory and both exact ownership markers.
    pub fn verify_marks(&self) -> Result<(), ProfileError> {
        for directory in [
            &self.root,
            &self.runtime,
            &self.chromium_data,
            &self.home,
            &self.xdg_config,
            &self.xdg_cache,
            &self.xdg_data,
            &self.downloads,
            &self.xvfb,
        ] {
            verify_marked(directory)?;
        }
        verify_marker(&self.root, &self.marker, &self.id, &self.id)?;
        let runtime_name =
            runtime_root_name(&self.id).ok_or_else(|| ProfileError::InvalidMarker {
                path: self.runtime_marker.clone(),
                reason: "profile identity is not a generated browser identifier",
            })?;
        verify_marker(&self.runtime, &self.runtime_marker, &self.id, &runtime_name)
    }

    /// Returns true when `candidate` lies beneath either owned root. Existing
    /// candidates retain normal filesystem resolution. For a future path, the
    /// nearest existing ancestor is resolved first and only ordinary missing
    /// path components are appended, so a symlink cannot make lexical
    /// containment escape an owned root.
    pub fn contains(&self, candidate: &Path) -> bool {
        let Some(resolved) = resolve_containment_candidate(candidate) else {
            return false;
        };
        [&self.root, &self.runtime].into_iter().any(|root| {
            root.canonicalize()
                .is_ok_and(|prefix| resolved.starts_with(prefix))
        })
    }

    /// Guarded removal. Verifies both roots, all directory marks, and both exact
    /// ownership markers before removing either tree. Callers must first reap
    /// every process holding either tree open.
    pub fn remove(self) -> Result<(), ProfileError> {
        self.verify_marks()?;
        remove_and_sync(&self.runtime)?;
        remove_and_sync(&self.root)
    }
}

fn marker_body(id: &str) -> String {
    format!("{MARKER_VERSION}\n{id}\n")
}

/// The deterministic per-session profile root beneath the state dir the
/// pod plan declares. The pod supervisor creates exactly this tree and the
/// host derives exactly these remote paths — one layout constructor, no
/// duplicated prefixes.
pub fn session_profile_dir(state_dir: &Path, session: &BrowserSessionId) -> PathBuf {
    state_dir.join(format!("{PROFILE_ID_PREFIX}{}", session.as_uuid().simple()))
}

pub fn session_runtime_dir(session: &BrowserSessionId) -> PathBuf {
    Path::new(RUNTIME_PARENT).join(format!(
        "{RUNTIME_ROOT_PREFIX}{}",
        session.as_uuid().simple()
    ))
}

fn profile_id_suffix(id: &str) -> Option<&str> {
    let suffix = id.strip_prefix(PROFILE_ID_PREFIX)?;
    (suffix.len() == SIMPLE_UUID_LEN
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then_some(suffix)
}

fn runtime_root_name(id: &str) -> Option<String> {
    profile_id_suffix(id).map(|suffix| format!("{RUNTIME_ROOT_PREFIX}{suffix}"))
}

fn create_private_directory(path: &Path) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(MARKED_MODE).create(path)
}

fn create_marker(root: &Path, id: &str) -> Result<PathBuf, ProfileError> {
    let marker = root.join(MARKER_NAME);
    let mut marker_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(MARKER_MODE)
        .open(&marker)
        .map_err(|source| ProfileError::MarkerUncreatable {
            path: marker.clone(),
            source,
        })?;
    marker_file
        .set_permissions(fs::Permissions::from_mode(MARKER_MODE))
        .and_then(|()| marker_file.write_all(marker_body(id).as_bytes()))
        .and_then(|()| marker_file.sync_all())
        .map_err(|source| ProfileError::MarkerUncreatable {
            path: marker.clone(),
            source,
        })?;
    Ok(marker)
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    fs::File::open(path)?.sync_all()
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn remove_and_sync(root: &Path) -> Result<(), ProfileError> {
    fs::remove_dir_all(root).map_err(|source| ProfileError::RemovalFailed {
        path: root.to_path_buf(),
        source,
    })?;
    let parent = parent_directory(root);
    sync_directory(parent).map_err(|source| ProfileError::RemovalFailed {
        path: parent.to_path_buf(),
        source,
    })
}

fn cleanup_created_roots(roots: &[&Path]) -> Result<(), ProfileError> {
    let mut first_error = None;
    for root in roots {
        match fs::remove_dir_all(root) {
            Ok(()) => {
                let parent = parent_directory(root);
                if let Err(source) = sync_directory(parent) {
                    if first_error.is_none() {
                        first_error = Some(ProfileError::RemovalFailed {
                            path: parent.to_path_buf(),
                            source,
                        });
                    }
                }
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                if first_error.is_none() {
                    first_error = Some(ProfileError::RemovalFailed {
                        path: root.to_path_buf(),
                        source,
                    });
                }
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}

/// Resolves an existing path normally. For a path that does not exist yet,
/// resolves its nearest existing directory and rebuilds the missing suffix
/// without interpreting special path components.
fn resolve_containment_candidate(candidate: &Path) -> Option<PathBuf> {
    if let Ok(resolved) = candidate.canonicalize() {
        return Some(resolved);
    }

    let mut ancestor = candidate;
    let mut missing = Vec::new();
    loop {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || (!missing.is_empty() && !metadata.is_dir())
                {
                    return None;
                }

                let mut resolved = ancestor.canonicalize().ok()?;
                for component in missing.into_iter().rev() {
                    resolved.push(component);
                }
                return Some(resolved);
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                let component = ancestor.components().next_back()?;
                let std::path::Component::Normal(component) = component else {
                    return None;
                };
                missing.push(component);

                let parent = ancestor.parent()?;
                ancestor = if parent.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    parent
                };
            }
            Err(_) => return None,
        }
    }
}

fn verify_marker(
    root: &Path,
    marker: &Path,
    id: &str,
    expected_root_name: &str,
) -> Result<(), ProfileError> {
    if profile_id_suffix(id).is_none() {
        return Err(ProfileError::InvalidMarker {
            path: marker.to_path_buf(),
            reason: "profile identity is not a generated browser identifier",
        });
    }
    if root.file_name().and_then(|name| name.to_str()) != Some(expected_root_name) {
        return Err(ProfileError::InvalidMarker {
            path: marker.to_path_buf(),
            reason: "root name does not match the marker identity",
        });
    }
    let metadata =
        fs::symlink_metadata(marker).map_err(|source| ProfileError::MarkerUncreatable {
            path: marker.to_path_buf(),
            source,
        })?;
    if metadata.is_symlink() || !metadata.is_file() {
        return Err(ProfileError::InvalidMarker {
            path: marker.to_path_buf(),
            reason: "marker is not a regular file",
        });
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode != MARKER_MODE {
        return Err(ProfileError::UnmarkedMarker {
            path: marker.to_path_buf(),
            mode,
        });
    }
    let contents =
        fs::read_to_string(marker).map_err(|source| ProfileError::MarkerUncreatable {
            path: marker.to_path_buf(),
            source,
        })?;
    if contents != marker_body(id) {
        return Err(ProfileError::InvalidMarker {
            path: marker.to_path_buf(),
            reason: "marker content does not match the profile identity",
        });
    }
    Ok(())
}

fn mark_directory(directory: &Path) -> Result<(), ProfileError> {
    let metadata =
        fs::symlink_metadata(directory).map_err(|source| ProfileError::DirectoryUncreatable {
            path: directory.to_path_buf(),
            source,
        })?;
    if metadata.is_symlink() {
        return Err(ProfileError::SymlinkedRoot {
            path: directory.to_path_buf(),
        });
    }
    if !metadata.is_dir() {
        return Err(ProfileError::NotADirectory {
            path: directory.to_path_buf(),
        });
    }
    let mut permissions = metadata.permissions();
    if permissions.mode() & 0o777 != MARKED_MODE {
        permissions.set_mode(MARKED_MODE);
        fs::set_permissions(directory, permissions).map_err(|source| {
            ProfileError::DirectoryUncreatable {
                path: directory.to_path_buf(),
                source,
            }
        })?;
    }
    Ok(())
}

fn verify_marked(directory: &Path) -> Result<(), ProfileError> {
    let metadata =
        fs::symlink_metadata(directory).map_err(|source| ProfileError::DirectoryUncreatable {
            path: directory.to_path_buf(),
            source,
        })?;
    if metadata.is_symlink() {
        return Err(ProfileError::SymlinkedRoot {
            path: directory.to_path_buf(),
        });
    }
    if !metadata.is_dir() {
        return Err(ProfileError::NotADirectory {
            path: directory.to_path_buf(),
        });
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode != MARKED_MODE {
        return Err(ProfileError::Unmarked {
            path: directory.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn test_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "odin-browser-profile-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("test root directory");
        root
    }

    fn mode_of(path: &Path) -> u32 {
        fs::symlink_metadata(path)
            .expect("path metadata")
            .permissions()
            .mode()
            & 0o777
    }

    /// A 0755 directory stands in for foreign material the profile arm
    /// does not own.
    fn foreign_directory(path: &Path) {
        fs::DirBuilder::new()
            .recursive(true)
            .create(path)
            .expect("directory");
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("0755 mode");
    }

    fn fresh_session() -> BrowserSessionId {
        BrowserSessionId::parse(&uuid::Uuid::new_v4().to_string()).expect("session id")
    }

    #[test]
    fn serve_state_dir_refuses_final_symlink_without_touching_the_target() {
        let base = test_root("symlink");
        let target = base.join("elsewhere");
        foreign_directory(&target);
        let link = base.join("state");
        symlink(&target, &link).expect("state symlink");

        let result = IsolatedProfile::ensure_serve_state_dir(&link);
        assert!(
            matches!(result, Err(ProfileError::SymlinkedRoot { .. })),
            "a symlinked final component must refuse typed: {result:?}"
        );
        assert!(link
            .symlink_metadata()
            .expect("link survives")
            .file_type()
            .is_symlink());
        assert_eq!(mode_of(&target), 0o755, "the symlink target keeps its mode");

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn serve_state_dir_refuses_foreign_unmarked_directory_without_chmod() {
        let base = test_root("foreign");
        let state = base.join("state");
        foreign_directory(&state);

        let result = IsolatedProfile::ensure_serve_state_dir(&state);
        assert!(
            matches!(result, Err(ProfileError::Unmarked { mode: 0o755, .. })),
            "a foreign unmarked parent must refuse typed: {result:?}"
        );
        assert_eq!(
            mode_of(&state),
            0o755,
            "a foreign directory is never chmod'ed"
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn serve_state_dir_retains_marked_parent_across_sessions() {
        let base = test_root("retain");
        let state = base.join("state");

        IsolatedProfile::ensure_serve_state_dir(&state).expect("first creation");
        assert_eq!(mode_of(&state), 0o700);
        IsolatedProfile::ensure_serve_state_dir(&state).expect("later session adopts it");
        assert_eq!(mode_of(&state), 0o700);

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn create_for_session_never_adopts_a_pre_existing_root() {
        let base = test_root("collision");
        let session = fresh_session();
        let state = base.join("state");
        IsolatedProfile::ensure_serve_state_dir(&state).expect("state dir");
        let root = session_profile_dir(&state, &session);
        foreign_directory(&root);
        fs::write(root.join("sentinel"), b"prior incarnation").expect("sentinel");

        let result = IsolatedProfile::create_for_session(&state, &session);
        assert!(
            matches!(result, Err(ProfileError::RootCollision { ref path }) if path == &root),
            "a pre-existing session root must refuse typed: {result:?}"
        );
        assert!(
            root.join("sentinel").exists(),
            "the prior tree is never removed"
        );
        assert_eq!(mode_of(&root), 0o755, "the prior tree is never re-marked");
        assert!(
            !root.join(MARKER_NAME).exists(),
            "no marker is claimed in a foreign tree"
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn create_for_session_removes_only_its_own_root_on_runtime_collision() {
        let base = test_root("runtime-collision");
        let session = fresh_session();
        let state = base.join("state");
        IsolatedProfile::ensure_serve_state_dir(&state).expect("state dir");
        let root = session_profile_dir(&state, &session);
        let runtime = session_runtime_dir(&session);
        let _ = fs::remove_dir_all(&runtime);
        foreign_directory(&runtime);

        let result = IsolatedProfile::create_for_session(&state, &session);
        assert!(
            matches!(result, Err(ProfileError::RootCollision { ref path }) if path == &runtime),
            "a pre-existing runtime root must refuse typed: {result:?}"
        );
        assert_eq!(
            mode_of(&runtime),
            0o755,
            "the prior runtime root is never adopted or re-marked"
        );
        assert!(
            !root.exists(),
            "the session root this call created is removed; the collision never is"
        );

        let _ = fs::remove_dir_all(&base);
        let _ = fs::remove_dir_all(&runtime);
    }
}
