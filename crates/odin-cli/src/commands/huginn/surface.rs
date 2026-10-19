//! The operator command surface: the argument grammar, the shared
//! bounded-read vocabulary (paging, snapshot/search/watch planning, kind
//! selectors), the [`HuginnPlan`] wire, top-level plan dispatch, and plan
//! execution against the production Huginn client.

use std::io::Write;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};
use odin_cli::authority_provision;
use odin_domain::huginn as live;

use super::super::output::{write_huginn_message, write_huginn_value, HuginnDownloadReport};
use super::{
    approvals::HuginnApprovalsArgs, browser::HuginnBrowserArgs, chat::HuginnChatArgs,
    devices::HuginnDevicesArgs, files::HuginnFilesArgs, lane::HuginnLaneArgs,
    render::HuginnRenderArgs, session::HuginnSessionArgs, simulation::HuginnSimulationArgs,
    terminal::HuginnTerminalArgs,
};

#[derive(Debug, Args)]
pub(crate) struct HuginnArgs {
    /// Private Huginn endpoint (default: the paired authority the host
    /// declares). The client independently authenticates its Tailscale peer.
    #[arg(long, global = true, env = "ODIN_HUGINN_ENDPOINT", value_name = "URL")]
    endpoint: Option<String>,
    /// Odin state root containing the enrolled device credential store.
    #[arg(
        long,
        global = true,
        env = "ODIN_HUGINN_STATE_ROOT",
        default_value = "state",
        value_name = "PATH"
    )]
    state_root: PathBuf,
    /// Emit compact redacted JSON rather than indented redacted JSON.
    #[arg(long, global = true)]
    json: bool,
    /// Stop a streaming command after this many messages.
    #[arg(long, global = true, default_value = "256", value_name = "N")]
    max_messages: NonZeroU16,
    #[command(subcommand)]
    pub(crate) command: HuginnCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum HuginnCommand {
    Status(HuginnPageArgs),
    Snapshot(HuginnSnapshotArgs),
    /// Read-model deltas after a delta cursor, one bounded page
    /// (incremental sync; each page's checkpoint is where the next one
    /// resumes, also across separate invocations against the same daemon;
    /// a cursor from an earlier daemon or older than the retained window
    /// answers CursorExpired: take a snapshot).
    Deltas(HuginnDeltasArgs),
    Watch(HuginnWatchArgs),
    Search(HuginnSearchArgs),
    Seats(HuginnPageArgs),
    Agents(HuginnPageArgs),
    Lanes(HuginnPageArgs),
    /// Pause, resume, restart, checkpoint, abort or rehome every live session of one lane.
    Lane(HuginnLaneArgs),
    Sessions(HuginnPageArgs),
    Nodes(HuginnPageArgs),
    Kube(HuginnPageArgs),
    /// One typed workload command (retry, suspend, resume, delete, rehome) as the shared KubeCommand JSON.
    KubeCommand(HuginnProtocolJsonArgs),
    Containers(HuginnPageArgs),
    Session(HuginnSessionArgs),
    Approvals(HuginnApprovalsArgs),
    Files(HuginnFilesArgs),
    Render(HuginnRenderArgs),
    Browser(HuginnBrowserArgs),
    Simulation(HuginnSimulationArgs),
    Terminal(HuginnTerminalArgs),
    Devices(HuginnDevicesArgs),
    /// The owner conversation (the same thread as Discord): follow and say.
    Chat(HuginnChatArgs),
    /// What the model gateway spent per day, lane and seat (no caps: visibility).
    Spend(HuginnSpendArgs),
    /// Report one smart-ring gesture (ringd on the device the ring is bonded
    /// to): the routines that follow `ring_gesture` fire once per id.
    RingGesture(HuginnRingGestureArgs),
    /// Stop all agent work on the authority (Colin's `ohshit`): every worker
    /// and pod, then Sinmara and the model gateway. `ohshit --resume` on the
    /// authority brings it back.
    EmergencyStop(HuginnEmergencyStopArgs),
    /// Reconstruct captured model requests from the local authority ledger.
    ///
    /// Does not use a Huginn endpoint. `--endpoint` that is not this host is
    /// rejected. Each JSONL row is `odin.trace.export.v1` with `schema`,
    /// `session_id`, `seat_id`, `entry_id`, `occurred_at`, `provider`,
    /// `model`, `api`, `request_id`, `response_id`,
    /// `request` (exact reconstructed body), `messages`, `tools`, `response`,
    /// `tool_calls`, `tool_results`, `usage`, `outcome`, `lessons`
    /// (`memory_remember` / `memory_forget` from the call, plus later
    /// session corrections after that response), and `trace_error` when
    /// an id or blob is missing. The row is still written; a missing body
    /// is never invented.
    Export(super::export::HuginnExportArgs),
}

#[derive(Clone, Debug, Args)]
pub(crate) struct HuginnEmergencyStopArgs {
    /// Required: this stops everything.
    #[arg(long)]
    pub(super) yes: bool,
}

#[derive(Clone, Debug, Args)]
pub(crate) struct HuginnRingGestureArgs {
    /// The gesture name, e.g. `double-tap`.
    pub(super) gesture: String,
    /// Unique per gesture on this device (a retry with the same id fires
    /// nothing new). Default: the current Unix time in nanoseconds.
    #[arg(long, value_name = "ID")]
    pub(super) id: Option<String>,
}

#[derive(Clone, Debug, Args)]
pub(crate) struct HuginnSpendArgs {
    /// The last N days, today included (1..=31).
    #[arg(long, default_value = "7", value_name = "N")]
    pub(super) days: u8,
}

#[derive(Clone, Debug, Args)]
pub(crate) struct HuginnPageArgs {
    #[arg(long, default_value = "128", value_name = "N")]
    pub(super) limit: NonZeroU16,
    #[arg(long, value_name = "CURSOR")]
    pub(super) cursor: Option<String>,
    #[arg(long)]
    pub(super) include_stale: bool,
}

#[derive(Debug, Args)]
pub(crate) struct HuginnDeltasArgs {
    /// The opaque delta cursor of the state the client already holds: an
    /// unfiltered snapshot's `deltaCursor` (`snapshot --include-stale`, no
    /// `--kind`, scope `all`), or a previous page's `checkpoint`; `0`
    /// replays from the empty model. A bare revision number is not a
    /// cursor.
    #[arg(long, value_name = "CURSOR")]
    after: String,
    /// Most deltas in this page (the server caps it too); when more remain
    /// the page carries `nextAfter`, the cursor of the next page.
    #[arg(long, value_name = "N")]
    limit: Option<std::num::NonZeroU16>,
}

#[derive(Debug, Args)]
pub(crate) struct HuginnSnapshotArgs {
    #[arg(long, default_value = "all", value_name = "SCOPE")]
    scope: String,
    #[arg(long, value_enum, value_name = "KIND")]
    kind: Vec<HuginnObjectKindArg>,
    #[command(flatten)]
    page: HuginnPageArgs,
}

#[derive(Debug, Args)]
pub(crate) struct HuginnSearchArgs {
    #[arg(value_name = "TEXT")]
    text: String,
    #[arg(long, default_value = "all", value_name = "SCOPE")]
    scope: String,
    #[arg(long, value_enum, value_name = "KIND")]
    kind: Vec<HuginnObjectKindArg>,
    #[command(flatten)]
    page: HuginnPageArgs,
}

#[derive(Debug, Args)]
pub(crate) struct HuginnWatchArgs {
    #[arg(long, value_enum)]
    pub(super) kind: HuginnStreamKindArg,
    #[arg(long, value_name = "UUID")]
    pub(super) stream: String,
    #[arg(long, value_name = "SEQUENCE")]
    pub(super) after: Option<u64>,
    #[arg(long, default_value = "64")]
    pub(super) credit_items: NonZeroU32,
    #[arg(long, default_value = "1048576")]
    pub(super) credit_bytes: NonZeroU64,
    #[arg(long, default_value = "128")]
    pub(super) max_buffered_items: NonZeroU32,
    #[arg(long, default_value = "8388608")]
    pub(super) max_buffered_bytes: NonZeroU64,
    #[arg(long, default_value = "2097152")]
    pub(super) max_item_bytes: NonZeroU64,
    #[arg(long, default_value = "60")]
    pub(super) max_items_per_second: NonZeroU32,
    #[arg(long, default_value = "8388608")]
    pub(super) max_in_flight_bytes: NonZeroU64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum HuginnObjectKindArg {
    Status,
    Seat,
    Agent,
    Lane,
    Session,
    Node,
    KubeResource,
    Container,
    Approval,
    Artifact,
    Browser,
    Simulation,
    Device,
    File,
    Render,
    Terminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(super) enum HuginnStreamKindArg {
    AgentEvents,
    Terminal,
    Logs,
    BrowserFrames,
    RenderFrames,
    SimulationTelemetry,
    SimulationFrames,
    FileChanges,
    KubeEvents,
}

#[derive(Clone, Debug, Args)]
pub(crate) struct HuginnProtocolJsonArgs {
    /// Exact JSON encoding of the named shared-protocol request payload.
    #[arg(long, value_name = "JSON")]
    pub(super) request_json: String,
}

#[derive(Clone, Debug, Args)]
pub(super) struct HuginnIdArgs {
    #[arg(value_name = "ID")]
    pub(super) id: String,
}

#[derive(Debug)]
pub(crate) enum HuginnPlan {
    Request(live::HuginnRequest),
    RequestStream(live::HuginnRequest),
    Stream(live::SubscriptionSet),
    FileRead(live::FileReadRequest),
    Upload {
        source: PathBuf,
        session: live::LiveSessionId,
        display_name: String,
        media_type: String,
        chunk_bytes: NonZeroU32,
    },
    CancelUpload {
        source: PathBuf,
        session: live::LiveSessionId,
        display_name: String,
        media_type: String,
        chunk_bytes: NonZeroU32,
    },
    PairDevice {
        label: String,
        node: String,
        force: bool,
        out: Option<PathBuf>,
    },
    RevokeDevice(live::DeviceId),
    /// One entry's metadata: its parent directory's listing, paged until the
    /// entry (the protocol has no single-entry request).
    FileStat {
        root: live::FileRootId,
        path: live::RelativePath,
    },
    Download {
        source: live::ContentSource,
        output: PathBuf,
    },
    Chat(HuginnChatArgs),
    Spend(u8),
    RingGesture(live::RingGestureReport),
}

impl HuginnPlan {
    pub(super) fn request(request: live::HuginnRequest) -> Self {
        Self::Request(request)
    }

    pub(super) fn request_stream(request: live::HuginnRequest) -> Self {
        Self::RequestStream(request)
    }

    pub(super) fn stream(set: live::SubscriptionSet) -> Self {
        Self::Stream(set)
    }
}

impl HuginnCommand {
    pub(crate) fn into_plan(self) -> Result<HuginnPlan, String> {
        match self {
            Self::Status(page) => Ok(snapshot_plan(live::ObjectKind::Status, page)),
            Self::Deltas(arguments) => Ok(HuginnPlan::request(live::HuginnRequest::Deltas(
                live::DeltaQuery {
                    after: arguments.after,
                    limit: arguments.limit,
                },
            ))),
            Self::Snapshot(arguments) => Ok(HuginnPlan::request(live::HuginnRequest::Snapshot(
                live::SnapshotQuery {
                    scope: parse_scope(&arguments.scope)?,
                    kinds: arguments.kind.into_iter().map(Into::into).collect(),
                    if_revision: None,
                    cursor: arguments.page.cursor,
                    limit: arguments.page.limit,
                    include_stale: arguments.page.include_stale,
                },
            ))),
            Self::Watch(arguments) => watch_plan(arguments),
            Self::Search(arguments) => Ok(HuginnPlan::request(live::HuginnRequest::Search(
                live::SearchQuery {
                    text: non_empty(arguments.text, "search text")?,
                    scope: parse_scope(&arguments.scope)?,
                    kinds: arguments.kind.into_iter().map(Into::into).collect(),
                    cursor: arguments.page.cursor,
                    limit: arguments.page.limit,
                    include_stale: arguments.page.include_stale,
                },
            ))),
            Self::Seats(page) => Ok(snapshot_plan(live::ObjectKind::Seat, page)),
            Self::Agents(page) => Ok(snapshot_plan(live::ObjectKind::Agent, page)),
            Self::Lanes(page) => Ok(snapshot_plan(live::ObjectKind::Lane, page)),
            Self::Lane(arguments) => arguments.into_plan(),
            Self::Sessions(page) => Ok(snapshot_plan(live::ObjectKind::Session, page)),
            Self::Nodes(page) => Ok(snapshot_plan(live::ObjectKind::Node, page)),
            Self::Kube(page) => Ok(snapshot_plan(live::ObjectKind::KubeResource, page)),
            Self::KubeCommand(arguments) => {
                Ok(HuginnPlan::request(live::HuginnRequest::KubeCommand(
                    parse_protocol_json(&arguments.request_json, "kube command")?,
                )))
            }
            Self::Containers(page) => Ok(snapshot_plan(live::ObjectKind::Container, page)),
            Self::Session(arguments) => arguments.command.into_plan(),
            Self::Approvals(arguments) => arguments.command.into_plan(),
            Self::Files(arguments) => arguments.command.into_plan(),
            Self::Render(arguments) => arguments.command.into_plan(),
            Self::Browser(arguments) => arguments.command.into_plan(),
            Self::Simulation(arguments) => arguments.command.into_plan(),
            Self::Terminal(arguments) => arguments.command.into_plan(),
            Self::Devices(arguments) => arguments.command.into_plan(),
            Self::Chat(arguments) => Ok(HuginnPlan::Chat(arguments)),
            Self::Spend(arguments) => Ok(HuginnPlan::Spend(arguments.days)),
            Self::RingGesture(arguments) => {
                let gesture_id = match arguments.id {
                    Some(id) => id,
                    None => std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|error| format!("the clock is before 1970: {error}"))?
                        .as_nanos()
                        .to_string(),
                };
                let report = live::RingGestureReport {
                    gesture_id,
                    gesture: arguments.gesture,
                };
                report.check()?;
                Ok(HuginnPlan::RingGesture(report))
            }
            Self::EmergencyStop(arguments) => {
                if !arguments.yes {
                    return Err("this stops all agent work; pass --yes".to_owned());
                }
                Ok(HuginnPlan::request(live::HuginnRequest::EmergencyStop(
                    live::EmergencyStopRequest {
                        command_id: authority_provision::random_command_uuid()?,
                    },
                )))
            }
            Self::Export(_) => Err("export is a local ledger read, not a Huginn plan".to_owned()),
        }
    }
}

impl From<HuginnObjectKindArg> for live::ObjectKind {
    fn from(value: HuginnObjectKindArg) -> Self {
        match value {
            HuginnObjectKindArg::Status => Self::Status,
            HuginnObjectKindArg::Seat => Self::Seat,
            HuginnObjectKindArg::Agent => Self::Agent,
            HuginnObjectKindArg::Lane => Self::Lane,
            HuginnObjectKindArg::Session => Self::Session,
            HuginnObjectKindArg::Node => Self::Node,
            HuginnObjectKindArg::KubeResource => Self::KubeResource,
            HuginnObjectKindArg::Container => Self::Container,
            HuginnObjectKindArg::Approval => Self::Approval,
            HuginnObjectKindArg::Artifact => Self::Artifact,
            HuginnObjectKindArg::Browser => Self::Browser,
            HuginnObjectKindArg::Simulation => Self::Simulation,
            HuginnObjectKindArg::Device => Self::Device,
            HuginnObjectKindArg::File => Self::File,
            HuginnObjectKindArg::Render => Self::Render,
            HuginnObjectKindArg::Terminal => Self::Terminal,
        }
    }
}

impl From<HuginnStreamKindArg> for live::LiveStreamKind {
    fn from(value: HuginnStreamKindArg) -> Self {
        match value {
            HuginnStreamKindArg::AgentEvents => Self::AgentEvents,
            HuginnStreamKindArg::Terminal => Self::Terminal,
            HuginnStreamKindArg::Logs => Self::Logs,
            HuginnStreamKindArg::BrowserFrames => Self::BrowserFrames,
            HuginnStreamKindArg::RenderFrames => Self::RenderFrames,
            HuginnStreamKindArg::SimulationTelemetry => Self::SimulationTelemetry,
            HuginnStreamKindArg::SimulationFrames => Self::SimulationFrames,
            HuginnStreamKindArg::FileChanges => Self::FileChanges,
            HuginnStreamKindArg::KubeEvents => Self::KubeEvents,
        }
    }
}

pub(super) fn snapshot_plan(kind: live::ObjectKind, page: HuginnPageArgs) -> HuginnPlan {
    HuginnPlan::request(live::HuginnRequest::Snapshot(live::SnapshotQuery {
        scope: live::QueryScope::All,
        kinds: vec![kind],
        if_revision: None,
        cursor: page.cursor,
        limit: page.limit,
        include_stale: page.include_stale,
    }))
}

pub(super) fn search_plan(kind: live::ObjectKind, text: String, limit: NonZeroU16) -> HuginnPlan {
    HuginnPlan::request(live::HuginnRequest::Search(live::SearchQuery {
        text,
        scope: live::QueryScope::All,
        kinds: vec![kind],
        cursor: None,
        limit,
        include_stale: true,
    }))
}

pub(super) fn watch_plan(arguments: HuginnWatchArgs) -> Result<HuginnPlan, String> {
    let kind = arguments.kind.into();
    watch_plan_as(arguments, kind)
}

pub(super) fn watch_plan_for(
    arguments: HuginnWatchArgs,
    expected: live::LiveStreamKind,
    operation: &str,
) -> Result<HuginnPlan, String> {
    let kind = arguments.kind.into();
    if kind != expected {
        return Err(format!(
            "{operation} requires --kind {}",
            stream_kind_name(expected)
        ));
    }
    watch_plan_as(arguments, kind)
}

fn watch_plan_as(
    arguments: HuginnWatchArgs,
    kind: live::LiveStreamKind,
) -> Result<HuginnPlan, String> {
    let stream_id = live::StreamId::parse(&arguments.stream).map_err(|error| error.to_string())?;
    let cursor = match kind.mode() {
        live::LiveStreamMode::Durable => live::StreamCursor::Durable {
            stream_id,
            after: arguments.after.map(live::Sequence::new),
        },
        live::LiveStreamMode::LatestFrame => {
            if arguments.after.is_some() {
                return Err("latest-frame streams do not accept --after".to_owned());
            }
            live::StreamCursor::LatestFrame { stream_id }
        }
    };
    let set = live::SubscriptionSet {
        subscriptions: vec![live::StreamSubscription {
            kind,
            cursor,
            credit: live::StreamCredit {
                items: arguments.credit_items,
                bytes: arguments.credit_bytes,
            },
            limits: live::StreamBackpressureLimits {
                max_buffered_items: arguments.max_buffered_items,
                max_buffered_bytes: arguments.max_buffered_bytes,
                max_item_bytes: arguments.max_item_bytes,
                max_items_per_second: arguments.max_items_per_second,
                max_in_flight_bytes: arguments.max_in_flight_bytes,
            },
        }],
    };
    if !set.is_valid() {
        return Err("invalid bounded stream subscription".to_owned());
    }
    Ok(HuginnPlan::stream(set))
}

fn stream_kind_name(kind: live::LiveStreamKind) -> &'static str {
    match kind {
        live::LiveStreamKind::AgentEvents => "agent-events",
        live::LiveStreamKind::Terminal => "terminal",
        live::LiveStreamKind::Logs => "logs",
        live::LiveStreamKind::BrowserFrames => "browser-frames",
        live::LiveStreamKind::RenderFrames => "render-frames",
        live::LiveStreamKind::SimulationTelemetry => "simulation-telemetry",
        live::LiveStreamKind::SimulationFrames => "simulation-frames",
        live::LiveStreamKind::FileChanges => "file-changes",
        live::LiveStreamKind::KubeEvents => "kube-events",
    }
}

fn parse_scope(value: &str) -> Result<live::QueryScope, String> {
    if value == "all" {
        return Ok(live::QueryScope::All);
    }
    let (kind, id) = value.split_once(':').ok_or_else(|| {
        "scope must be all or KIND:ID (seat, project, lane, run, session, node, artifact)"
            .to_owned()
    })?;
    match kind {
        "seat" => Ok(live::QueryScope::Seat(parse_id(id, "seat ID")?)),
        "project" => Ok(live::QueryScope::Project(parse_id(id, "project ID")?)),
        "lane" => Ok(live::QueryScope::Lane(parse_id(id, "lane ID")?)),
        "run" => Ok(live::QueryScope::Run(parse_id(id, "run ID")?)),
        "session" => Ok(live::QueryScope::Session(
            live::LiveSessionId::parse(id).map_err(|error| error.to_string())?,
        )),
        "node" => Ok(live::QueryScope::Node(parse_id(id, "node ID")?)),
        "artifact" => Ok(live::QueryScope::Artifact(parse_id(id, "artifact ID")?)),
        _ => Err(format!("unsupported Huginn query scope {kind:?}")),
    }
}

pub(super) fn parse_id<T>(value: &str, label: &str) -> Result<T, String>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    value
        .parse()
        .map_err(|error| format!("invalid {label} {value:?}: {error}"))
}

pub(super) fn parse_protocol_json<T>(value: &str, label: &str) -> Result<T, String>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_str(value).map_err(|error| format!("invalid {label} JSON: {error}"))
}

pub(super) fn non_empty(value: String, label: &str) -> Result<String, String> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(value)
    }
}

/// A failed Huginn call as Colin reads it: with `--json` the typed error
/// (its `kind` and code kept), otherwise one plain sentence.
pub(crate) fn client_failure(error: &odin_huginn::client::ClientError, json: bool) -> String {
    use odin_huginn::client::ClientError;
    let ClientError::Protocol(protocol) = error else {
        return error.to_string();
    };
    if json {
        return serde_json::json!({ "error": protocol }).to_string();
    }
    match protocol {
        live::HuginnProtocolError::InvalidRequest { message, .. } => message.clone(),
        live::HuginnProtocolError::NotFound {
            object_kind,
            object_id,
        } => format!("there is no {} {object_id}", words(object_kind)),
        other => other.to_string(),
    }
}

/// `simulationMission` → `simulation mission`.
fn words(camel: &str) -> String {
    let mut out = String::with_capacity(camel.len() + 4);
    for character in camel.chars() {
        if character.is_ascii_uppercase() && !out.is_empty() {
            out.push(' ');
        }
        out.push(character.to_ascii_lowercase());
    }
    out
}

fn is_remote_endpoint(endpoint: &str) -> bool {
    url::Url::parse(endpoint).map_or(true, |url| {
        !matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))
    })
}

fn local_device_refusal(code: &str, message: &str, json: bool) -> String {
    client_failure(
        &odin_huginn::client::ClientError::Protocol(live::HuginnProtocolError::InvalidRequest {
            code: code.to_owned(),
            message: message.to_owned(),
        }),
        json,
    )
}

pub(crate) fn run_huginn(arguments: HuginnArgs, output: &mut impl Write) -> Result<(), String> {
    let HuginnArgs {
        endpoint,
        state_root,
        json,
        max_messages,
        command,
    } = arguments;
    if let HuginnCommand::Export(export) = command {
        if endpoint.as_deref().is_some_and(is_remote_endpoint) {
            return Err(
                "huginn export reads the local authority ledger and rejects a remote --endpoint"
                    .to_owned(),
            );
        }
        return super::export::export_local(&state_root, export, output);
    }
    let plan = command.into_plan()?;
    let limits = odin_huginn::protocol::CodecLimits::default();
    // The host's own loopback endpoint (the declared default on the
    // authority) is not a remote one.
    let remote = endpoint.as_deref().is_some_and(is_remote_endpoint);
    if let HuginnPlan::PairDevice {
        label,
        node,
        force,
        out,
    } = &plan
    {
        if remote {
            return Err(local_device_refusal(
                "localPairingRequired",
                "devices pair is loopback-local setup and does not accept a remote --endpoint; remote pairing is unsupported",
                json,
            ));
        }
        if out.is_some() && *force {
            return Err(local_device_refusal(
                "conflictingPairingOptions",
                "devices pair --out enrolls another device without replacing anything; --force only replaces this workstation's own stored credential and cannot be combined with --out",
                json,
            ));
        }
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|error| format!("could not start the local pairing runtime: {error}"))?;
        let report = match out {
            Some(out) => runtime.block_on(authority_provision::enroll_device(
                &state_root,
                label,
                node,
                out,
            ))?,
            None => runtime.block_on(authority_provision::pair_device(
                &state_root,
                label,
                node,
                *force,
            ))?,
        };
        return write_huginn_value(output, &report, json, &limits);
    }
    if let HuginnPlan::RevokeDevice(device) = &plan {
        if remote {
            return Err(local_device_refusal(
                "localRevocationRequired",
                "devices revoke is loopback-local administration on the authority and does not accept a remote --endpoint",
                json,
            ));
        }
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|error| format!("could not start the local revoke runtime: {error}"))?;
        let report = runtime.block_on(authority_provision::revoke_device(&state_root, *device))?;
        return write_huginn_value(output, &report, json, &limits);
    }
    let endpoint = endpoint.ok_or_else(|| {
        "--endpoint (or ODIN_HUGINN_ENDPOINT) is required for `odin huginn`".to_owned()
    })?;
    let endpoint = url::Url::parse(&endpoint)
        .map_err(|error| format!("invalid Huginn endpoint URL: {error}"))?;
    let transport =
        odin_huginn::client::EndpointTransport::new(endpoint).map_err(|error| error.to_string())?;
    let credentials = odin_huginn::client::FileCredentialStore::open(state_root.join("huginn"))
        .map_err(|error| error.to_string())?;
    let client = odin_huginn::ColinRemoteClient::with_limits(transport, credentials, limits);
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|error| format!("could not start the Huginn client runtime: {error}"))?;

    runtime.block_on(async {
        match plan {
            HuginnPlan::Request(request) => {
                let response = client
                    .request(request)
                    .await
                    .map_err(|error| client_failure(&error, json))?;
                if let (false, live::HuginnResponse::Snapshot(page)) = (json, &response) {
                    if let Some(text) = super::super::output::human_status(page) {
                        return output
                            .write_all(text.as_bytes())
                            .map_err(|error| format!("could not write the status: {error}"));
                    }
                }
                write_huginn_value(output, &response, json, &limits)
            }
            HuginnPlan::RequestStream(request) => {
                let (response, mut stream) = client
                    .request_stream(request)
                    .await
                    .map_err(|error| client_failure(&error, json))?;
                write_huginn_value(output, &response, json, &limits)?;
                for _ in 0..max_messages.get() {
                    let Some(message) = stream.next().await else {
                        return Ok(());
                    };
                    let message = message.map_err(|error| client_failure(&error, json))?;
                    write_huginn_message(output, &message, json, &limits)?;
                }
                Ok(())
            }
            HuginnPlan::Stream(set) => {
                let mut open: std::collections::BTreeSet<live::StreamId> = set
                    .subscriptions
                    .iter()
                    .map(|subscription| *subscription.cursor.stream_id())
                    .collect();
                let mut stream = client
                    .subscribe(set)
                    .await
                    .map_err(|error| client_failure(&error, json))?;
                for _ in 0..max_messages.get() {
                    let message = next_or_resume(&mut stream)
                        .await
                        .map_err(|error| client_failure(&error, json))?;
                    write_huginn_message(output, &message, json, &limits)?;
                    // A watch ends when the server ends every stream it
                    // watches, never because the connection dropped.
                    if let live::HuginnMessage::StreamStatus(status) = &message {
                        if matches!(
                            status.lifecycle,
                            live::StreamLifecycle::Closed | live::StreamLifecycle::Failed
                        ) {
                            open.remove(&status.stream_id);
                            if open.is_empty() {
                                return Ok(());
                            }
                        }
                    }
                }
                Ok(())
            }
            HuginnPlan::FileRead(request) => {
                let mut connection = client
                    .connect()
                    .await
                    .map_err(|error| client_failure(&error, json))?;
                let response = connection
                    .request(live::HuginnRequest::ReadFile(request))
                    .await
                    .map_err(|error| client_failure(&error, json))?;
                if !matches!(&response, live::HuginnResponse::Ack) {
                    return Err(format!("unexpected response to ReadFile: {response:?}"));
                }
                write_huginn_value(output, &response, json, &limits)?;
                for _ in 0..max_messages.get() {
                    let Some(message) = connection.next().await else {
                        return Err("file read closed before its final chunk".to_owned());
                    };
                    let message = message.map_err(|error| client_failure(&error, json))?;
                    let final_chunk = matches!(
                        &message,
                        live::HuginnMessage::BinaryChunk(chunk) if chunk.final_chunk
                    );
                    write_huginn_message(output, &message, json, &limits)?;
                    if final_chunk {
                        return Ok(());
                    }
                }
                Err("file read exceeded --max-messages before its final chunk".to_owned())
            }
            HuginnPlan::Upload {
                source,
                session,
                display_name,
                media_type,
                chunk_bytes,
            } => {
                let source = odin_huginn::client::UploadSource::Path {
                    path: source,
                    display_name: display_name.clone(),
                    media_type: media_type.clone(),
                };
                let target = odin_huginn::client::UploadTarget {
                    session_id: session,
                    kind: live::ArtifactKind::File,
                    display_name,
                    media_type,
                    chunk_len: chunk_bytes,
                };
                let result = client
                    .upload(source, target)
                    .await
                    .map_err(|error| error.to_string())?;
                write_huginn_value(output, &result, json, &limits)
            }
            HuginnPlan::CancelUpload {
                source,
                session,
                display_name,
                media_type,
                chunk_bytes,
            } => {
                let bytes = std::fs::read(&source)
                    .map_err(|error| format!("could not read {}: {error}", source.display()))?;
                let transfer_id = live::TransferId::new(uuid::Uuid::new_v4())
                    .map_err(|error| error.to_string())?;
                let manifest = live::TransferManifest::new(
                    odin_domain::huginn::artifact::TransferManifestInit {
                        transfer_id,
                        session_id: session,
                        kind: live::ArtifactKind::File,
                        direction: live::ArtifactDirection::DeviceToSession,
                        display_name,
                        media_type,
                        byte_len: bytes.len() as u64,
                        chunk_len: chunk_bytes,
                        content_digest: odin_domain::Digest::hash(&bytes),
                    },
                )
                .map_err(|error| error.to_string())?;
                let begun = client
                    .request(live::HuginnRequest::BeginTransfer(manifest))
                    .await
                    .map_err(|error| error.to_string())?;
                write_huginn_value(output, &begun, json, &limits)?;
                let cancelled = client
                    .request(live::HuginnRequest::CancelTransfer(
                        live::TransferCancelRequest {
                            command_id: odin_domain::CommandId::new(format!(
                                "cancel-upload:{transfer_id}"
                            ))
                            .map_err(|error| error.to_string())?,
                            transfer_id,
                        },
                    ))
                    .await
                    .map_err(|error| error.to_string())?;
                write_huginn_value(output, &cancelled, json, &limits)
            }
            HuginnPlan::Chat(arguments) => super::chat::run(&client, arguments, output).await,
            HuginnPlan::FileStat { root, path } => {
                let parent = path
                    .as_path()
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty());
                let directory = parent
                    .map(|parent| live::RelativePath::parse(&parent.to_string_lossy()))
                    .transpose()
                    .map_err(|error| error.to_string())?;
                let mut after = None;
                loop {
                    let response = client
                        .request(live::HuginnRequest::ListFiles(live::FileListRequest {
                            root_id: root.clone(),
                            directory: directory.clone(),
                            expected_revision: None,
                            after: after.clone(),
                            limit: std::num::NonZeroU16::new(500).ok_or("page limit")?,
                        }))
                        .await
                        .map_err(|error| error.to_string())?;
                    let live::HuginnResponse::Files(page) = response else {
                        return Err(format!("files stat: unexpected response {response:?}"));
                    };
                    if let Some(entry) = page
                        .entries
                        .iter()
                        .find(|entry| entry.relative_path == path)
                    {
                        return write_huginn_value(output, entry, json, &limits);
                    }
                    match page.next_after {
                        Some(next) => after = Some(next),
                        None => {
                            return Err(format!("{} has no entry {}", root.as_str(), path.as_str()))
                        }
                    }
                }
            }
            HuginnPlan::RevokeDevice(_) => {
                unreachable!("devices revoke is handled before the remote client opens")
            }
            HuginnPlan::Spend(days) => {
                let response = client
                    .request(live::HuginnRequest::Spend(live::SpendRequest { days }))
                    .await
                    .map_err(|error| error.to_string())?;
                match response {
                    live::HuginnResponse::Spend(view) if !json => write_spend(output, &view),
                    spend @ live::HuginnResponse::Spend(_) => {
                        write_huginn_value(output, &spend, json, &limits)
                    }
                    other => Err(format!("unexpected spend response: {other:?}")),
                }
            }
            HuginnPlan::RingGesture(report) => {
                let response = client
                    .request(live::HuginnRequest::RingGesture(report.clone()))
                    .await
                    .map_err(|error| error.to_string())?;
                match response {
                    live::HuginnResponse::Ack => writeln!(
                        output,
                        "ring gesture {} reported (id {})",
                        report.gesture, report.gesture_id
                    )
                    .map_err(|error| format!("could not write the receipt: {error}")),
                    other => Err(format!("unexpected ring gesture response: {other:?}")),
                }
            }
            HuginnPlan::PairDevice { .. } => {
                Err("internal error: local device pairing reached the remote transport".to_owned())
            }
            HuginnPlan::Download {
                source,
                output: path,
            } => {
                let mut sink = odin_huginn::client::FileSink::create(&path)
                    .map_err(|error| error.to_string())?;
                let digest = client
                    .download(source, &mut sink)
                    .await
                    .map_err(|error| error.to_string())?;
                write_huginn_value(
                    output,
                    &HuginnDownloadReport {
                        output: path,
                        digest,
                    },
                    json,
                    &limits,
                )
            }
        }
    })
}

fn dollars(cents: u64) -> String {
    format!("${}.{:02}", cents / 100, cents % 100)
}

/// The spend view as plain rows: total, per day, per lane, per seat.
pub(super) fn write_spend(output: &mut impl Write, view: &live::SpendView) -> Result<(), String> {
    let io = |error: std::io::Error| format!("could not write the spend view: {error}");
    let row = |output: &mut dyn Write, line: &live::SpendLine| {
        writeln!(
            output,
            "  {:<28} {:>10}  {:>12} tokens  {:>8} requests",
            line.label,
            dollars(line.usd_cents),
            line.tokens,
            line.requests
        )
    };
    writeln!(
        output,
        "Model spend {} to {}: {} ({} tokens, {} requests)",
        view.from,
        view.to,
        dollars(view.total.usd_cents),
        view.total.tokens,
        view.total.requests
    )
    .map_err(io)?;
    for (title, lines) in [
        ("per day", &view.days),
        ("per lane", &view.lanes),
        ("per seat", &view.seats),
    ] {
        writeln!(output, "{title}:").map_err(io)?;
        if lines.is_empty() {
            writeln!(output, "  (none)").map_err(io)?;
        }
        for line in lines {
            row(output, line).map_err(io)?;
        }
    }
    if view.untagged_usd_cents > 0 {
        writeln!(
            output,
            "  {:<28} {:>10}",
            "(no seat tag)",
            dollars(view.untagged_usd_cents)
        )
        .map_err(io)?;
    }
    if !view.workloads.is_empty() {
        writeln!(output, "per pod workload (within its seat):").map_err(io)?;
        for line in &view.workloads {
            row(output, line).map_err(io)?;
        }
    }
    writeln!(output, "{}", view.note).map_err(io)
}

/// The longest wait between attempts to resume a lost watch.
const RESUME_MAX: std::time::Duration = std::time::Duration::from_secs(30);

/// The next message of a watch; a lost connection (odind restarting, the
/// network dropping) is resumed from the stream's own cursors with backoff;
/// any refusal is returned at once.
async fn next_or_resume<S, T>(
    stream: &mut odin_huginn::client::HuginnStream<S, T>,
) -> Result<live::HuginnMessage, odin_huginn::client::ClientError>
where
    S: odin_huginn::client::TransportFrame,
    T: odin_huginn::client::HuginnTransport<Socket = S>,
{
    use odin_huginn::client::ClientError;
    let mut delay = std::time::Duration::from_secs(1);
    loop {
        let lost = match stream.next().await {
            Some(Ok(message)) => return Ok(message),
            None => ClientError::ConnectionClosed,
            Some(Err(
                error @ (ClientError::ConnectionClosed
                | ClientError::Transport(_)
                | ClientError::Io(_)),
            )) => error,
            Some(Err(error)) => return Err(error),
        };
        loop {
            tracing::warn!(
                error = %lost,
                delay_seconds = delay.as_secs(),
                "huginn watch lost; resuming"
            );
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(RESUME_MAX);
            // Only a connection that could not be made is tried again; a
            // refusal (an expired cursor, a limit) is the watch's answer.
            match stream.reconnect().await {
                Ok(()) => break,
                Err(
                    error @ (ClientError::ConnectionClosed
                    | ClientError::Transport(_)
                    | ClientError::Io(_)),
                ) => {
                    tracing::warn!(%error, "huginn watch resume failed");
                }
                Err(error) => return Err(error),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;
    use odin_domain::huginn as live;

    use super::{client_failure, HuginnPlan};

    fn parsed_huginn_plan(arguments: &[&str]) -> Result<HuginnPlan, String> {
        let cli = crate::Cli::try_parse_from(arguments).map_err(|error| error.to_string())?;
        match cli.command {
            Some(crate::Command::Huginn(arguments)) => arguments.command.into_plan(),
            _ => Err("fixture did not parse as a Huginn command".to_owned()),
        }
    }

    /// L12 (laptop 10-05): a missing simulation printed "simulationMission
    /// run:kinds-probe was not found" even under --json, and a refused watch
    /// "invalid request invalidRequest: invalid scope: invalid file
    /// operation: root does not permit watches".
    #[test]
    fn a_failed_call_is_one_plain_sentence_or_its_typed_json() {
        use odin_huginn::client::ClientError;
        let missing = ClientError::Protocol(live::HuginnProtocolError::NotFound {
            object_kind: "simulationMission".to_owned(),
            object_id: "run:kinds-probe".to_owned(),
        });
        assert_eq!(
            client_failure(&missing, false),
            "there is no simulation mission run:kinds-probe"
        );
        let typed: serde_json::Value =
            serde_json::from_str(&client_failure(&missing, true)).unwrap();
        assert_eq!(typed["error"]["kind"], "notFound");
        assert_eq!(typed["error"]["objectKind"], "simulationMission");
        let refused = ClientError::Protocol(live::HuginnProtocolError::InvalidRequest {
            code: "invalidScope".to_owned(),
            message: "this folder cannot be watched".to_owned(),
        });
        assert_eq!(
            client_failure(&refused, false),
            "this folder cannot be watched"
        );
    }

    #[test]
    fn emergency_stop_requires_yes_and_plans_the_request() {
        let error = parsed_huginn_plan(&["odin", "huginn", "emergency-stop"]).unwrap_err();
        assert!(
            error.contains("this stops all agent work; pass --yes"),
            "{error}"
        );
        let plan = parsed_huginn_plan(&["odin", "huginn", "emergency-stop", "--yes"]).unwrap();
        assert!(matches!(
            plan,
            HuginnPlan::Request(live::HuginnRequest::EmergencyStop(_))
        ));
    }
}

#[cfg(test)]
mod endpoint_tests {
    /// Q36: the host declares its paired authority as the default endpoint;
    /// on the authority that is its own loopback, which local pairing and
    /// revocation must still accept.
    #[test]
    fn only_a_non_loopback_endpoint_is_remote() {
        assert!(!super::is_remote_endpoint("http://127.0.0.1:18420"));
        assert!(!super::is_remote_endpoint("http://localhost:18420"));
        assert!(!super::is_remote_endpoint("http://[::1]:18420"));
        assert!(super::is_remote_endpoint("https://mini.example.ts.net"));
        assert!(super::is_remote_endpoint("not a url"));
    }
}

#[cfg(test)]
mod pairing_refusal_tests {
    use clap::Parser as _;

    #[test]
    fn remote_or_malformed_revoke_endpoint_refuses_before_creating_state() {
        for endpoint in ["https://remote.example", "not a url"] {
            let temporary = tempfile::TempDir::new().unwrap();
            let state = temporary.path().join("untouched");
            let cli = crate::Cli::try_parse_from([
                "odin",
                "huginn",
                "--json",
                "--state-root",
                state.to_str().unwrap(),
                "--endpoint",
                endpoint,
                "devices",
                "revoke",
                "00000000-0000-4000-8000-000000000009",
            ])
            .unwrap();
            let Some(crate::Command::Huginn(arguments)) = cli.command else {
                panic!("expected Huginn command");
            };
            let mut output = Vec::new();
            let error = super::run_huginn(arguments, &mut output).unwrap_err();
            let typed: serde_json::Value = serde_json::from_str(&error).unwrap();
            assert_eq!(typed["error"]["kind"], "invalidRequest");
            assert_eq!(typed["error"]["code"], "localRevocationRequired");
            assert!(output.is_empty());
            assert!(!state.exists());
        }
    }

    #[test]
    fn enrollment_options_refuse_with_typed_errors_before_creating_state() {
        for (extra, code) in [
            (vec!["--force"], "conflictingPairingOptions"),
            (
                vec!["--endpoint", "https://remote.example"],
                "localPairingRequired",
            ),
            (vec!["--endpoint", "not a url"], "localPairingRequired"),
        ] {
            let temporary = tempfile::TempDir::new().unwrap();
            let state = temporary.path().join("untouched");
            let mut args = vec![
                "odin",
                "huginn",
                "--json",
                "--state-root",
                state.to_str().unwrap(),
                "devices",
                "pair",
                "--label",
                "phone",
                "--node",
                "00000000-0000-4000-8000-000000000009",
                "--out",
                "phone.credential",
            ];
            args.extend(extra);
            let cli = crate::Cli::try_parse_from(args).unwrap();
            let Some(crate::Command::Huginn(mut arguments)) = cli.command else {
                panic!("expected Huginn command");
            };
            if code == "conflictingPairingOptions" {
                arguments.endpoint = None;
            }
            let mut output = Vec::new();
            let error = super::run_huginn(arguments, &mut output).unwrap_err();
            let typed: serde_json::Value = serde_json::from_str(&error).unwrap();
            assert_eq!(typed["error"]["kind"], "invalidRequest");
            assert_eq!(typed["error"]["code"], code);
            assert!(output.is_empty());
            assert!(!state.exists());
        }
    }
}
