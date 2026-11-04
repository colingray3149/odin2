pub mod browse;
pub mod roots;
pub mod save;
pub mod watch;

use std::sync::Arc;

use async_trait::async_trait;
use odin_domain::huginn::{
    FileDeltaStream, FileGateway, FileListPage, FileListRequest, FileMetadata, FileReadRequest,
    FileReadStream, FileWatchRequest, HuginnProtocolError, RelativePath,
};

pub use browse::{find_in_root, open_from_root, BrowseEngine, FileSearchQuery, Found};
pub use roots::{RootCatalog, RootHandle};
pub use save::{save_into_root, save_stream_into_root};
pub use watch::WatchManager;

use crate::config::FileLimits;

#[derive(Clone)]
pub struct HuginnFileService {
    browse: BrowseEngine,
    watches: WatchManager,
}

impl HuginnFileService {
    pub fn new(catalog: RootCatalog, limits: FileLimits) -> Self {
        let catalog = Arc::new(catalog);
        Self {
            browse: BrowseEngine::new(catalog.clone(), limits.clone()),
            watches: WatchManager::new(catalog, limits, watch::WATCH_POLL_INTERVAL),
        }
    }

    pub fn roots(&self) -> Vec<RootHandle> {
        self.browse.catalog().handles()
    }

    pub async fn stat(
        &self,
        root_id: &odin_domain::huginn::FileRootId,
        relative: &RelativePath,
    ) -> Result<FileMetadata, HuginnProtocolError> {
        self.browse.stat(root_id, relative).await
    }

    pub async fn search(
        &self,
        query: FileSearchQuery,
    ) -> Result<Vec<FileMetadata>, HuginnProtocolError> {
        self.browse.search(query).await
    }

    pub fn browse_engine(&self) -> &BrowseEngine {
        &self.browse
    }
}

#[async_trait]
impl FileGateway for HuginnFileService {
    async fn list(&self, request: FileListRequest) -> Result<FileListPage, HuginnProtocolError> {
        self.browse.list(request).await
    }

    async fn read(&self, request: FileReadRequest) -> Result<FileReadStream, HuginnProtocolError> {
        self.browse.read(request)
    }

    async fn watch(
        &self,
        request: FileWatchRequest,
    ) -> Result<FileDeltaStream, HuginnProtocolError> {
        self.watches.watch(request).await
    }
}

/// A declared root over `dir` for tests: one allowed media type, 1 KiB objects, no watch, no host.
/// Callers override fields with struct-update syntax.
#[cfg(test)]
pub(crate) fn test_root_init(
    id: &str,
    dir: &std::path::Path,
    access: odin_domain::huginn::FileRootAccess,
    media_type: &str,
) -> odin_domain::huginn::FileRootInit {
    use odin_domain::huginn::{FileMediaPolicy, FileRootId, FileWatchPolicy};

    odin_domain::huginn::FileRootInit {
        root_id: FileRootId::parse(id).unwrap(),
        display_name: id.to_owned(),
        canonical_path: dir.canonicalize().unwrap(),
        access,
        media_policy: FileMediaPolicy {
            allowed_media_types: vec![media_type.to_owned()],
        },
        max_object_bytes: std::num::NonZeroU64::new(1024).unwrap(),
        watch_policy: FileWatchPolicy::Disabled,
        allowed_seats: Vec::new(),
        host: None,
        save_default: None,
    }
}
