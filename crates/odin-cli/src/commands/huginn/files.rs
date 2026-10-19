//! The `files` command domain: file roots, listing, search, reads, watches,
//! uploads, and downloads.

use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::path::PathBuf;

use clap::{Args, Subcommand};
use odin_domain::huginn as live;

use super::surface::{non_empty, snapshot_plan, HuginnPageArgs, HuginnPlan};

#[derive(Debug, Args)]
pub(crate) struct HuginnFilesArgs {
    #[command(subcommand)]
    pub(super) command: HuginnFilesCommand,
}

#[derive(Debug, Subcommand)]
pub(super) enum HuginnFilesCommand {
    Roots(HuginnPageArgs),
    Ls(HuginnFileListArgs),
    Find(HuginnFileFindArgs),
    Stat(HuginnFilePathArgs),
    Read(HuginnFileReadArgs),
    Watch(HuginnFileWatchArgs),
    Upload(HuginnFileUploadArgs),
    Download(HuginnFileDownloadArgs),
    /// Download a published artifact by id (FetchArtifact, then
    /// GrantDownloadCredit after every non-final chunk).
    Fetch(HuginnArtifactFetchArgs),
    SendToLane(HuginnFileUploadArgs),
    /// Declare an upload and cancel it before any chunk (BeginTransfer then
    /// CancelTransfer): nothing is published.
    CancelUpload(HuginnFileUploadArgs),
}

#[derive(Debug, Args)]
pub(super) struct HuginnArtifactFetchArgs {
    #[arg(value_name = "ARTIFACT_ID")]
    artifact: String,
    #[arg(long, value_name = "PATH")]
    output: PathBuf,
}

#[derive(Debug, Args)]
pub(super) struct HuginnFileListArgs {
    #[arg(long, value_name = "ID")]
    root: String,
    #[arg(value_name = "RELATIVE")]
    directory: Option<String>,
    #[arg(long, value_name = "DIGEST")]
    expected_revision: Option<String>,
    #[arg(long, value_name = "RELATIVE")]
    after: Option<String>,
    #[arg(long, default_value = "128")]
    limit: NonZeroU16,
}

#[derive(Debug, Args)]
pub(super) struct HuginnFileFindArgs {
    #[arg(value_name = "TEXT")]
    text: String,
    #[command(flatten)]
    page: HuginnPageArgs,
}

#[derive(Clone, Debug, Args)]
pub(super) struct HuginnFilePathArgs {
    #[arg(long, value_name = "ID")]
    root: String,
    #[arg(value_name = "RELATIVE")]
    relative: String,
}

#[derive(Debug, Args)]
pub(super) struct HuginnFileReadArgs {
    #[command(flatten)]
    path: HuginnFilePathArgs,
    #[arg(long, value_name = "DIGEST")]
    expected_revision: Option<String>,
    #[arg(long, value_name = "BYTES")]
    offset: Option<u64>,
    #[arg(long, requires = "offset", value_name = "BYTES")]
    length: Option<NonZeroU64>,
    #[arg(long, default_value = "8388608", value_name = "BYTES")]
    max_bytes: NonZeroU64,
}

#[derive(Debug, Args)]
pub(super) struct HuginnFileWatchArgs {
    #[arg(long, value_name = "UUID")]
    watch_id: String,
    #[arg(long, value_name = "ID")]
    root: String,
    #[arg(value_name = "RELATIVE")]
    relative: Option<String>,
    #[arg(long)]
    recursive: bool,
    #[arg(long, value_name = "DIGEST")]
    expected_revision: Option<String>,
}

#[derive(Debug, Args)]
pub(super) struct HuginnFileUploadArgs {
    #[arg(value_name = "PATH")]
    source: PathBuf,
    #[arg(long, value_name = "UUID")]
    session: String,
    #[arg(long, value_name = "TYPE")]
    media_type: String,
    #[arg(long, value_name = "NAME")]
    display_name: Option<String>,
    #[arg(long, default_value = "262144", value_name = "BYTES")]
    chunk_bytes: NonZeroU32,
}

#[derive(Debug, Args)]
pub(super) struct HuginnFileDownloadArgs {
    #[command(flatten)]
    path: HuginnFilePathArgs,
    #[arg(long, value_name = "DIGEST")]
    expected_revision: Option<String>,
    #[arg(long, value_name = "PATH")]
    output: PathBuf,
}

impl HuginnFilesCommand {
    pub(super) fn into_plan(self) -> Result<HuginnPlan, String> {
        match self {
            Self::Roots(page) => Ok(snapshot_plan(live::ObjectKind::File, page)),
            Self::Ls(arguments) => Ok(HuginnPlan::request(live::HuginnRequest::ListFiles(
                live::FileListRequest {
                    root_id: live::FileRootId::parse(&arguments.root)
                        .map_err(|error| error.to_string())?,
                    directory: arguments
                        .directory
                        .map(|path| live::RelativePath::parse(&path))
                        .transpose()
                        .map_err(|error| error.to_string())?,
                    expected_revision: arguments
                        .expected_revision
                        .map(|digest| digest.parse())
                        .transpose()
                        .map_err(|error: odin_domain::DomainError| error.to_string())?,
                    after: arguments
                        .after
                        .map(|path| live::RelativePath::parse(&path))
                        .transpose()
                        .map_err(|error| error.to_string())?,
                    limit: arguments.limit,
                },
            ))),
            Self::Find(arguments) => Ok(HuginnPlan::request(live::HuginnRequest::Search(
                live::SearchQuery {
                    text: non_empty(arguments.text, "file search text")?,
                    scope: live::QueryScope::All,
                    kinds: vec![live::ObjectKind::File],
                    cursor: arguments.page.cursor,
                    limit: arguments.page.limit,
                    include_stale: arguments.page.include_stale,
                },
            ))),
            Self::Stat(arguments) => Ok(HuginnPlan::FileStat {
                root: live::FileRootId::parse(&arguments.root)
                    .map_err(|error| error.to_string())?,
                path: live::RelativePath::parse(&arguments.relative)
                    .map_err(|error| error.to_string())?,
            }),
            Self::Read(arguments) => file_read_plan(arguments),
            Self::Watch(arguments) => Ok(HuginnPlan::request_stream(
                live::HuginnRequest::WatchFiles(live::FileWatchRequest {
                    watch_id: live::FileWatchId::parse(&arguments.watch_id)
                        .map_err(|error| error.to_string())?,
                    root_id: live::FileRootId::parse(&arguments.root)
                        .map_err(|error| error.to_string())?,
                    relative_path: arguments
                        .relative
                        .map(|path| live::RelativePath::parse(&path))
                        .transpose()
                        .map_err(|error| error.to_string())?,
                    recursive: arguments.recursive,
                    expected_revision: arguments
                        .expected_revision
                        .map(|digest| digest.parse())
                        .transpose()
                        .map_err(|error: odin_domain::DomainError| error.to_string())?,
                }),
            )),
            Self::Upload(arguments) | Self::SendToLane(arguments) => file_upload_plan(arguments),
            Self::Download(arguments) => file_download_plan(arguments),
            Self::Fetch(arguments) => Ok(HuginnPlan::Download {
                source: live::ContentSource::Artifact(super::surface::parse_id(
                    &arguments.artifact,
                    "artifact ID",
                )?),
                output: arguments.output,
            }),
            Self::CancelUpload(arguments) => match file_upload_plan(arguments)? {
                HuginnPlan::Upload {
                    source,
                    session,
                    display_name,
                    media_type,
                    chunk_bytes,
                } => Ok(HuginnPlan::CancelUpload {
                    source,
                    session,
                    display_name,
                    media_type,
                    chunk_bytes,
                }),
                _ => Err("cancel-upload: unexpected plan".to_owned()),
            },
        }
    }
}

fn file_read_plan(arguments: HuginnFileReadArgs) -> Result<HuginnPlan, String> {
    let range = match (arguments.offset, arguments.length) {
        (Some(offset), Some(length)) => Some(live::FileByteRange { offset, length }),
        (None, None) => None,
        _ => return Err("--offset and --length must be supplied together".to_owned()),
    };
    Ok(HuginnPlan::FileRead(live::FileReadRequest {
        root_id: live::FileRootId::parse(&arguments.path.root)
            .map_err(|error| error.to_string())?,
        relative_path: live::RelativePath::parse(&arguments.path.relative)
            .map_err(|error| error.to_string())?,
        expected_revision: arguments
            .expected_revision
            .map(|digest| digest.parse())
            .transpose()
            .map_err(|error: odin_domain::DomainError| error.to_string())?,
        range,
        max_bytes: arguments.max_bytes,
    }))
}

fn file_upload_plan(arguments: HuginnFileUploadArgs) -> Result<HuginnPlan, String> {
    let session =
        live::LiveSessionId::parse(&arguments.session).map_err(|error| error.to_string())?;
    let display_name = arguments
        .display_name
        .map(|name| non_empty(name, "display name"))
        .transpose()?
        .or_else(|| {
            arguments
                .source
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned)
        })
        .ok_or_else(|| "upload source requires a UTF-8 file name or --display-name".to_owned())?;
    Ok(HuginnPlan::Upload {
        source: arguments.source,
        session,
        display_name,
        media_type: non_empty(arguments.media_type, "media type")?,
        chunk_bytes: arguments.chunk_bytes,
    })
}

fn file_download_plan(arguments: HuginnFileDownloadArgs) -> Result<HuginnPlan, String> {
    Ok(HuginnPlan::Download {
        source: live::ContentSource::File {
            root: live::FileRootId::parse(&arguments.path.root)
                .map_err(|error| error.to_string())?,
            relative: live::RelativePath::parse(&arguments.path.relative)
                .map_err(|error| error.to_string())?,
            expected_revision: arguments
                .expected_revision
                .map(|digest| digest.parse())
                .transpose()
                .map_err(|error: odin_domain::DomainError| error.to_string())?,
        },
        output: arguments.output,
    })
}
