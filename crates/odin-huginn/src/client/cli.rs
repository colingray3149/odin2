use odin_domain::huginn::{HuginnRequest, LiveStreamKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandRoute {
    Request(&'static str),
    Stream {
        request: &'static str,
        kind: Option<LiveStreamKind>,
    },
    Transfer {
        upload: bool,
    },
    Local {
        reason: &'static str,
    },
    Unsupported {
        reason: &'static str,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CliCommandMapping {
    pub path: &'static str,
    pub route: CommandRoute,
    pub notes: &'static str,
}

const fn request(
    path: &'static str,
    variant: &'static str,
    notes: &'static str,
) -> CliCommandMapping {
    CliCommandMapping {
        path,
        route: CommandRoute::Request(variant),
        notes,
    }
}

const fn stream(
    path: &'static str,
    kind: Option<LiveStreamKind>,
    notes: &'static str,
) -> CliCommandMapping {
    CliCommandMapping {
        path,
        route: CommandRoute::Stream {
            request: "Subscribe",
            kind,
        },
        notes,
    }
}

pub const CLI_COMMAND_MAPPINGS: &[CliCommandMapping] = &[
    request("huginn status", "Snapshot", "service/status objects"),
    request(
        "huginn snapshot",
        "Snapshot",
        "bounded materialized snapshot",
    ),
    stream("huginn watch", None, "object snapshot and delta projection"),
    request("huginn search", "Search", "bounded materialized search"),
    request("huginn seats", "Snapshot", "Seat objects"),
    request("huginn agents", "Snapshot", "Agent objects"),
    request("huginn lanes", "Snapshot", "Lane objects"),
    request("huginn sessions", "Snapshot", "Session objects"),
    request("huginn nodes", "Snapshot", "Node objects"),
    request("huginn kube", "Snapshot", "KubeResource objects"),
    request("huginn containers", "Snapshot", "Container objects"),
    request(
        "huginn session open",
        "OpenSession",
        "persistent tab or headless identity",
    ),
    request(
        "huginn session prompt",
        "SessionCommand",
        "LiveCommandBody::Prompt",
    ),
    request(
        "huginn session follow-up",
        "SessionCommand",
        "LiveCommandBody::FollowUp",
    ),
    request(
        "huginn session steer",
        "SessionCommand",
        "LiveCommandBody::Steer",
    ),
    request(
        "huginn session pause",
        "SessionCommand",
        "LiveCommandBody::Pause",
    ),
    request(
        "huginn session resume",
        "SessionCommand",
        "LiveCommandBody::Resume",
    ),
    request(
        "huginn session checkpoint",
        "SessionCommand",
        "LiveCommandBody::Checkpoint",
    ),
    request(
        "huginn session restart",
        "SessionCommand",
        "LiveCommandBody::Restart",
    ),
    request(
        "huginn session rehome",
        "SessionCommand",
        "LiveCommandBody::Rehome",
    ),
    request(
        "huginn session set-model",
        "SessionCommand",
        "LiveCommandBody::SetModel",
    ),
    request(
        "huginn session permission",
        "SessionCommand",
        "LiveCommandBody::DecidePermission",
    ),
    request(
        "huginn session abort",
        "SessionCommand",
        "LiveCommandBody::Abort",
    ),
    request("huginn approvals list", "Snapshot", "Approval objects"),
    request(
        "huginn approvals show",
        "Search",
        "one revision-bound Approval object",
    ),
    request(
        "huginn approvals approve",
        "ApprovalDecision",
        "typed approval decision",
    ),
    request(
        "huginn approvals reject",
        "ApprovalDecision",
        "typed approval decision",
    ),
    request(
        "huginn files roots",
        "Snapshot",
        "declared FileRoot objects",
    ),
    request(
        "huginn files ls",
        "ListFiles",
        "declared-root relative listing",
    ),
    request("huginn files find", "Search", "bounded file search"),
    CliCommandMapping {
        path: "huginn files stat",
        route: CommandRoute::Unsupported {
            reason: "exact file metadata lookup is absent from protocol version 1",
        },
        notes: "fails explicitly rather than substituting a listing or search",
    },
    request("huginn files read", "ReadFile", "bounded chunk stream"),
    request(
        "huginn files watch",
        "WatchFiles",
        "bounded durable file-delta stream",
    ),
    CliCommandMapping {
        path: "huginn files upload",
        route: CommandRoute::Transfer { upload: true },
        notes: "BeginUpload, UploadChunk, CommitUpload",
    },
    CliCommandMapping {
        path: "huginn files download",
        route: CommandRoute::Transfer { upload: false },
        notes: "ReadFile then BinaryChunk stream",
    },
    CliCommandMapping {
        path: "huginn files send-to-lane",
        route: CommandRoute::Transfer { upload: true },
        notes: "configured ingress lane through the shared upload path",
    },
    request(
        "huginn render request",
        "RequestRender",
        "versioned safe renderer",
    ),
    request(
        "huginn render status",
        "RenderStatus",
        "exact render lifecycle status",
    ),
    request(
        "huginn render watch",
        "WatchRender",
        "bounded render lifecycle stream",
    ),
    request(
        "huginn render open",
        "IssueContentTicket",
        "short-lived source- and size-bound content ticket",
    ),
    request("huginn browser list", "Snapshot", "Browser objects"),
    stream(
        "huginn browser watch",
        Some(LiveStreamKind::BrowserFrames),
        "lossy latest-frame stream",
    ),
    request(
        "huginn browser observe",
        "BrowserObserve",
        "bounded authenticated browser.observe request",
    ),
    request(
        "huginn browser takeover",
        "BrowserCommand",
        "typed takeover command",
    ),
    request(
        "huginn browser release",
        "BrowserCommand",
        "typed release command",
    ),
    request(
        "huginn browser command",
        "BrowserCommand",
        "revision-bound browser command",
    ),
    request("huginn simulation list", "Snapshot", "Simulation objects"),
    request("huginn simulation show", "Search", "one Simulation object"),
    stream(
        "huginn simulation telemetry",
        Some(LiveStreamKind::SimulationTelemetry),
        "durable compact telemetry",
    ),
    request(
        "huginn simulation render",
        "SimulationCommand",
        "typed simulation render command",
    ),
    stream(
        "huginn simulation watch",
        Some(LiveStreamKind::SimulationFrames),
        "lossy latest-frame stream",
    ),
    request(
        "huginn simulation checkpoint",
        "SimulationCommand",
        "typed checkpoint command",
    ),
    request(
        "huginn simulation command",
        "SimulationCommand",
        "revision-bound simulation command",
    ),
    request("huginn terminal list", "Snapshot", "Terminal objects"),
    stream(
        "huginn terminal attach",
        Some(LiveStreamKind::Terminal),
        "managed read-only mirror; --control first acquires a lease",
    ),
    request(
        "huginn terminal write",
        "WriteTerminal",
        "idempotent raw input under an operator lease",
    ),
    request(
        "huginn terminal resize",
        "ResizeTerminal",
        "idempotent resize under an operator lease",
    ),
    request(
        "huginn terminal release",
        "ReleaseTerminalControl",
        "release explicit operator PTY lease",
    ),
    request(
        "huginn chat",
        "ConversationSay",
        "the owner conversation: ConversationThread (the Discord channel itself), ConversationSay",
    ),
    request(
        "huginn spend",
        "Spend",
        "the model gateway's spend per day, lane and seat",
    ),
    request(
        "huginn emergency-stop",
        "EmergencyStop",
        "stop all agent work on the authority (ohshit)",
    ),
    CliCommandMapping {
        path: "huginn devices list",
        route: CommandRoute::Local {
            reason: "device administration is host-local",
        },
        notes: "DeviceAdmin::list",
    },
    CliCommandMapping {
        path: "huginn devices pair",
        route: CommandRoute::Local {
            reason: "pairing is loopback-local by contract",
        },
        notes: "DeviceAdmin::pair_local",
    },
    CliCommandMapping {
        path: "huginn devices revoke",
        route: CommandRoute::Local {
            reason: "device administration is host-local",
        },
        notes: "DeviceAdmin::revoke and connection closure",
    },
];

pub fn protocol_request_for(path: &str) -> Option<&'static CliCommandMapping> {
    CLI_COMMAND_MAPPINGS
        .iter()
        .find(|mapping| mapping.path == path)
}

pub const fn request_kind(request: &HuginnRequest) -> &'static str {
    match request {
        HuginnRequest::Snapshot(_) => "Snapshot",
        HuginnRequest::Deltas(_) => "Deltas",
        HuginnRequest::Search(_) => "Search",
        HuginnRequest::Subscribe(_) => "Subscribe",
        HuginnRequest::SubscribeObjects(_) => "SubscribeObjects",
        HuginnRequest::OpenSession(_) => "OpenSession",
        HuginnRequest::SessionCommand(_) => "SessionCommand",
        HuginnRequest::LaneCommand(_) => "LaneCommand",
        HuginnRequest::KubeCommand(_) => "KubeCommand",
        HuginnRequest::ApprovalDecision(_) => "ApprovalDecision",
        HuginnRequest::ListFiles(_) => "ListFiles",
        HuginnRequest::ReadFile(_) => "ReadFile",
        HuginnRequest::WatchFiles(_) => "WatchFiles",
        HuginnRequest::BeginTransfer(_) => "BeginTransfer",
        HuginnRequest::TransferChunk(_) => "TransferChunk",
        HuginnRequest::CommitTransfer(_) => "CommitTransfer",
        HuginnRequest::CancelTransfer(_) => "CancelTransfer",
        HuginnRequest::GrantDownloadCredit(_) => "GrantDownloadCredit",
        HuginnRequest::RequestRender(_) => "RequestRender",
        HuginnRequest::RenderStatus(_) => "RenderStatus",
        HuginnRequest::WatchRender(_) => "WatchRender",
        HuginnRequest::IssueContentTicket(_) => "IssueContentTicket",
        HuginnRequest::BrowserCommand(_) => "BrowserCommand",
        HuginnRequest::BrowserObserve(_) => "BrowserObserve",
        HuginnRequest::SimulationCommand(_) => "SimulationCommand",
        HuginnRequest::AcquireTerminalControl(_) => "AcquireTerminalControl",
        HuginnRequest::WriteTerminal(_) => "WriteTerminal",
        HuginnRequest::ResizeTerminal(_) => "ResizeTerminal",
        HuginnRequest::ReleaseTerminalControl(_) => "ReleaseTerminalControl",
        HuginnRequest::ConversationStatus => "ConversationStatus",
        HuginnRequest::ConversationSay(_) => "ConversationSay",
        HuginnRequest::ConversationThread(_) => "ConversationThread",
        HuginnRequest::ConversationReply(_) => "ConversationReply",
        HuginnRequest::Spend(_) => "Spend",
        HuginnRequest::RingGesture(_) => "RingGesture",
        HuginnRequest::EmergencyStop(_) => "EmergencyStop",
    }
}
