pub mod browse;
pub mod preview;
pub mod roots;
pub mod watch;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use odin_domain::huginn::{
    FileDeltaStream, FileGateway, FileListPage, FileListRequest, FileMetadata, FileReadRequest,
    FileReadStream, FileWatchRequest, HuginnProtocolError, RelativePath,
};

pub use browse::{BrowseEngine, FileSearchQuery};
pub use preview::{PreviewKind, PreviewPlan, PreviewService};
pub use roots::{RootCatalog, RootHandle};
pub use watch::WatchManager;

use crate::config::FileLimits;

#[derive(Clone)]
pub struct HuginnFileService {
    browse: BrowseEngine,
    watches: WatchManager,
    previews: PreviewService,
}

impl HuginnFileService {
    pub fn new(catalog: RootCatalog, limits: FileLimits) -> Self {
        Self::with_poll_interval(catalog, limits, Duration::from_millis(500))
    }

    pub fn with_poll_interval(
        catalog: RootCatalog,
        limits: FileLimits,
        poll_interval: Duration,
    ) -> Self {
        let catalog = Arc::new(catalog);
        Self {
            browse: BrowseEngine::new(catalog.clone(), limits.clone()),
            watches: WatchManager::new(catalog, limits, poll_interval),
            previews: PreviewService::new(),
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

    pub async fn preview(
        &self,
        root_id: &odin_domain::huginn::FileRootId,
        relative: &RelativePath,
    ) -> Result<PreviewPlan, HuginnProtocolError> {
        let metadata = self.browse.stat(root_id, relative).await?;
        self.previews.for_file(&metadata)
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
