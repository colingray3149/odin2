//! Desktop look, common actions and declared device/scene/headless controls:
//! The conversation seat sees and
//! drives the owner's desktop through the daemon's channel to `odin desk serve`
//! on the node declaring the `desktop` capability, only while answering his
//! own message (or a report of a job started for it) within
//! [`ASK_WINDOW`] of it — never in a routine, a scheduled wake or an event.
//! Action steps share one desktop.act capability, including typing and closing windows.
//! Every act is a life effect in the shared ledger, recorded before it runs
//! and settled with what was done, like a Drive change; a look is a read.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use odin_domain::huginn::OpaqueCredentialHandle;
use odin_domain::{CapabilityId, Scope};
use odin_omp::host_tools::{
    ConsumedHostCommand, HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode,
};
use odin_workflows::desk::{Desk, Transfer};
use odin_workflows::Catalog;
use serde_json::{json, Value};
use time::OffsetDateTime;

use super::images::image_block;
use super::tools::{require_prepared, CapabilityTool};
use super::{HermesRuntime, RUNTIME_ISSUER};
use crate::account::{
    record_dispatch_intent, run_ungated_effect, settle_gated_effect, BatchFault, CredentialLeases,
    DurableEffect, EffectIdentity, EffectIntent, EffectRoute, HostConsumeProof, LeaseRejection,
    ScopedCredentialLease, TransportFault, LEASE_TTL_SECONDS,
};
use crate::conversation::Provenance;

/// Desktop tools whose call takes no screenshot unless one is asked for.
const QUIET_TOOLS: &[&str] = &["desktop_display"];

/// How long after the owner's message the seat may still use his desktop.
const ASK_WINDOW: Duration = Duration::from_secs(15 * 60);

/// The account desktop acts are recorded under; its bound route stands in
/// for a credential.
const DESKTOP: &str = "desktop";

/// The workflow executable that moves files to and from a desk host.
const RSYNC: &str = "rsync";

/// The daemon's channel to `odin desk serve` on the desktop node.
pub trait DesktopRoute: Send + Sync {
    /// Sends one request line and waits at most `bound` for its reply.
    fn call(&self, request: &Value, bound: Duration) -> Result<Value, String>;

    /// Copies files between the authority and a desk host over the desk's ssh.
    fn transfer(&self, _request: &TransferRequest<'_>) -> Result<Transfer, String> {
        Err("this desktop route moves no files".to_owned())
    }
}

/// Which way a desk transfer copies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    /// From the desk host into the authority.
    Pull,
    /// From the authority to the same path on the desk host.
    Push,
}

/// One rsync between the authority and a desk host: `files` are relative to
/// `from` and land under `to` (Pull: `from` is on the desk host; Push: `to` is).
pub struct TransferRequest<'a> {
    pub device: Option<&'a str>,
    pub rsync: &'a Path,
    pub direction: Direction,
    pub from: &'a Path,
    pub files: &'a [PathBuf],
    pub to: &'a Path,
    pub bound: Duration,
}

/// The bound route and the turn it may serve.
#[derive(Default)]
pub(super) struct DeskCell {
    route: Mutex<Option<Arc<dyn DesktopRoute>>>,
    turn: Mutex<Turn>,
}

#[derive(Default)]
struct Turn {
    /// The owner's latest message: its idempotency key and when its turn began.
    ask: Option<(String, Instant)>,
    /// A routine, scheduled wake or event turn began after it.
    own: bool,
}

impl DeskCell {
    fn turn(&self) -> std::sync::MutexGuard<'_, Turn> {
        self.turn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A turn opened for `provenance`: the owner's message starts his ask
    /// afresh, a routine or event closes his desktop to the turn, and only a
    /// job report continues the ask.
    pub(super) fn turn_opened(&self, provenance: Provenance, ask: &str) {
        let mut turn = self.turn();
        match provenance {
            Provenance::Owner => {
                *turn = Turn {
                    ask: Some((ask.to_owned(), Instant::now())),
                    own: false,
                };
            }
            Provenance::Wake => turn.own = true,
            Provenance::Report | Provenance::Continuation => {}
        }
    }

    /// The ask the current turn serves, or why there is none.
    fn ask(&self) -> Result<String, String> {
        let turn = self.turn();
        let (key, at) = turn
            .ask
            .as_ref()
            .ok_or("the owner has not asked anything since odind started; his desktop is only used for his asks")?;
        if turn.own {
            return Err(
                "this turn is a routine, scheduled wake or event, not the owner's ask; his desktop is \
                        only used while answering him"
                    .to_owned(),
            );
        }
        let minutes = at.elapsed().as_secs() / 60;
        if at.elapsed() > ASK_WINDOW {
            let window = ASK_WINDOW.as_secs() / 60;
            return Err(format!(
                "the owner's last message was {minutes} min ago; his desktop is only used within {window} min of an ask"
            ));
        }
        Ok(key.clone())
    }

    fn route(&self) -> Result<Arc<dyn DesktopRoute>, String> {
        self.route
            .lock()
            .ok()
            .and_then(|cell| cell.clone())
            .ok_or_else(|| "the desktop route is not bound on this daemon".to_owned())
    }
}

impl DeskCell {
    /// Desk steps a workflow sends within the owner's current ask; a stop or
    /// error is Err saying what was already done.
    fn workflow_steps(
        &self,
        device: Option<&str>,
        steps: Vec<Value>,
        bound: Duration,
    ) -> Result<Vec<String>, String> {
        let ask = self.ask()?;
        let request = without_nulls(json!({ "ask": ask, "device": device, "steps": steps }));
        let reply = self.route()?.call(&request, bound)?;
        let did = did_lines(&reply);
        match reply["stopped"].as_str().or(reply["error"].as_str()) {
            Some(failure) => Err(format!("{failure} ({})", done(&did))),
            None => Ok(did),
        }
    }

    /// A workflow's file transfer, within the owner's current ask.
    fn workflow_transfer(&self, request: &TransferRequest<'_>) -> Result<Transfer, String> {
        self.ask()?;
        self.route()?.transfer(request)
    }
}

/// The owner's desktop as workflows see it.
struct HermesDesk {
    runtime: Weak<HermesRuntime>,
    rsync: PathBuf,
}

impl HermesDesk {
    fn runtime(&self) -> Result<Arc<HermesRuntime>, String> {
        self.runtime
            .upgrade()
            .ok_or_else(|| "the hermes runtime has stopped".to_owned())
    }
}

impl Desk for HermesDesk {
    fn steps(
        &self,
        device: Option<&str>,
        steps: Vec<Value>,
        bound: Duration,
    ) -> Result<Vec<String>, String> {
        self.runtime()?.desk.workflow_steps(device, steps, bound)
    }

    fn pull(
        &self,
        device: Option<&str>,
        remote_dir: &Path,
        files: &[PathBuf],
        local_dir: &Path,
        bound: Duration,
    ) -> Result<Transfer, String> {
        self.runtime()?.desk.workflow_transfer(&TransferRequest {
            device,
            rsync: &self.rsync,
            direction: Direction::Pull,
            from: remote_dir,
            files,
            to: local_dir,
            bound,
        })
    }

    fn push(
        &self,
        device: Option<&str>,
        local_dir: &Path,
        files: &[PathBuf],
        bound: Duration,
    ) -> Result<Transfer, String> {
        self.runtime()?.desk.workflow_transfer(&TransferRequest {
            device,
            rsync: &self.rsync,
            direction: Direction::Push,
            from: local_dir,
            files,
            to: local_dir,
            bound,
        })
    }
}

/// Composes the owner's desktop into the workflow catalog when rsync is
/// declared; without it, workflows that use the desktop preflight naming rsync.
pub(super) fn with_workflow_desk(runtime: &Arc<HermesRuntime>, catalog: Catalog) -> Catalog {
    let Ok(rsync) = catalog.ctx().exe(RSYNC) else {
        return catalog;
    };
    let desk = HermesDesk {
        runtime: Arc::downgrade(runtime),
        rsync: rsync.to_path_buf(),
    };
    catalog.with_desk(Arc::new(desk))
}

impl CredentialLeases for DeskCell {
    fn availability(&self, account: &str) -> Result<(), LeaseRejection> {
        if account != DESKTOP {
            return Err(LeaseRejection::UnknownAccount);
        }
        self.route()
            .map(drop)
            .map_err(LeaseRejection::CredentialsUnavailable)
    }

    fn issue(
        &self,
        capability: &CapabilityId,
        account: &str,
        now: OffsetDateTime,
    ) -> Result<ScopedCredentialLease, LeaseRejection> {
        self.availability(account)?;
        Ok(ScopedCredentialLease::new(
            account,
            capability.clone(),
            OpaqueCredentialHandle::new("cred:desktop-route").expect("a valid handle"),
            now,
            now + time::Duration::seconds(LEASE_TTL_SECONDS),
        ))
    }
}

impl HermesRuntime {
    /// The conversation opened a turn; its provenance decides whether the
    /// seat may use the owner's desktop in it.
    pub(crate) fn turn_opened(&self, provenance: Provenance, ask: &str) {
        self.desk.turn_opened(provenance, ask);
    }

    /// Binds the daemon's channel to `odin desk serve` on the desktop node.
    pub fn set_desktop_route(&self, route: Arc<dyn DesktopRoute>) {
        if let Ok(mut cell) = self.desk.route.lock() {
            *cell = Some(route);
        }
    }

    /// One look through the channel; the result carries the layout when
    /// asked and the screenshot as an image block.
    fn desk_look(&self, arguments: &Value) -> Result<Value, HostToolError> {
        let request = self.desk_request(LOOK, arguments)?;
        let route = self
            .desk
            .route()
            .map_err(|reason| HostToolError::Unavailable { tool: LOOK, reason })?;
        let reply = route
            .call(&request, bound(&request))
            .map_err(|reason| HostToolError::Unavailable { tool: LOOK, reason })?;
        reply_result(LOOK, reply)
    }

    /// One act as a life effect, like a Drive change: the intent is recorded
    /// under `key` before the desktop is called and settled with what was
    /// done. `consumed` is the approved command, verified against the ledger
    /// first. A stop after some steps leaves them as partial evidence.
    fn desk_act(
        &self,
        tool: &'static str,
        capability: &'static str,
        key: String,
        consumed: Option<&ConsumedHostCommand>,
        arguments: &Value,
    ) -> Result<Value, HostToolError> {
        let request = self.desk_request(tool, arguments)?;
        let capability = CapabilityId::new(capability).expect("declared desktop capability ids");
        let identity = EffectIdentity {
            idempotency_key: key.clone(),
            correlation_id: key,
        };
        let effect = || DurableEffect {
            ledger: &self.adapter_ledger,
            issuer: RUNTIME_ISSUER,
            identity: &identity,
        };
        let route = EffectRoute {
            capability: &capability,
            account: DESKTOP,
            result_key: "did",
        };
        let mut intent = without_nulls(arguments.clone());
        if let Some(object) = intent.as_object_mut() {
            object.remove("approvalId");
            object.insert("account".to_owned(), json!(DESKTOP));
        }
        let mut cause = None;
        let mut reply = None;
        let execute = |_lease: &ScopedCredentialLease, _arguments: &Value| {
            let answer = self
                .desk
                .route()
                .and_then(|route| route.call(&request, bound(&request)))
                .map_err(|reason| {
                    cause = Some(reason);
                    BatchFault::from(TransportFault::Protocol("the desktop channel failed"))
                })?;
            let did = did_lines(&answer);
            if let Some(failure) = answer["stopped"].as_str().or(answer["error"].as_str()) {
                cause = Some(format!("{failure} ({})", done(&did)));
                let fault = if did.is_empty() {
                    TransportFault::Refused("the desktop did nothing")
                } else {
                    TransportFault::Protocol("the desktop stopped partway")
                };
                return Err(BatchFault::after(did, fault));
            }
            reply = Some(answer);
            Ok(serde_json::to_string(&did).expect("lines serialize"))
        };
        let now = OffsetDateTime::now_utc();
        let settled = match consumed {
            None => run_ungated_effect(effect(), &self.desk, route, intent, now, execute),
            Some(consumed) => {
                let target = EffectIntent {
                    target_kind: capability.as_str(),
                    target_id: DESKTOP,
                    arguments: intent,
                };
                record_dispatch_intent(effect(), &capability, target, now).and_then(|()| {
                    let command_id = consumed.command_id().clone();
                    let scope = consumed.approval_scope();
                    let proof = HostConsumeProof {
                        approval_id: None,
                        command_id: &command_id,
                        scope: &scope,
                    };
                    settle_gated_effect(effect(), &self.desk, route, &proof, now, execute)
                })
            }
        }
        .map_err(|error| HostToolError::Unavailable {
            tool,
            reason: match &cause {
                Some(cause) => format!("{cause} ({error})"),
                None => error.to_string(),
            },
        })?;
        tracing::info!(
            "odin-hermes: {tool} command={} replayed={}",
            settled.command_id,
            settled.replayed
        );
        match reply {
            Some(reply) => reply_result(tool, reply),
            None => Ok(json!({
                "did": settled.result["did"].as_str().and_then(|did| serde_json::from_str::<Value>(did).ok()),
            })),
        }
    }

    /// The request for `odin desk serve`, refused unless the turn serves
    /// the owner's recent ask.
    fn desk_request(&self, tool: &'static str, arguments: &Value) -> Result<Value, HostToolError> {
        let ask = self
            .desk
            .ask()
            .map_err(|reason| HostToolError::Unavailable { tool, reason })?;
        let mut arguments = without_nulls(arguments.clone());
        let steps = arguments
            .get_mut("steps")
            .map(Value::take)
            .unwrap_or_else(|| json!([]));
        let shot = match arguments.get("shot").and_then(Value::as_str).unwrap_or(
            if QUIET_TOOLS.contains(&tool) {
                "none"
            } else {
                "screen"
            },
        ) {
            "none" => Value::Null,
            "screen" => json!({ "of": "screen", "output": arguments.get("output") }),
            "all" => json!({ "of": "all" }),
            "window" => json!({ "of": "window", "window": arguments.get("window") }),
            "zoom" => {
                let mut zoom = arguments.get("zoom").cloned().unwrap_or_else(|| json!({}));
                zoom["of"] = json!("zoom");
                zoom
            }
            other => {
                return Err(HostToolError::Arguments {
                    tool,
                    detail: format!("shot {other:?} is not screen, all, window, zoom or none"),
                })
            }
        };
        Ok(without_nulls(json!({
            "device": arguments.get("device"),
            "ask": ask,
            "steps": steps,
            "layout": arguments.get("layout").and_then(Value::as_bool).unwrap_or(tool == LOOK),
            "shot": shot,
        })))
    }
}

/// Includes nested scene waits and bounded app/device discovery, not only pointer waits.
fn bound(request: &Value) -> Duration {
    fn step_ms(step: &Value) -> u64 {
        let own = step["ms"].as_u64().unwrap_or(0).min(10_000)
            + step["seconds"].as_u64().unwrap_or(0).min(120) * 1000;
        let action = match step["do"].as_str() {
            Some("structure" | "media" | "device" | "headless") => 120_000,
            Some("audio" | "play" | "player" | "edit") => 20_000,
            Some("drag") => step["path"]
                .as_array()
                .map_or(0, |path| path.len() as u64 * 100),
            _ => 0,
        };
        own + action
            + step["steps"]
                .as_array()
                .into_iter()
                .flatten()
                .map(step_ms)
                .sum::<u64>()
    }
    let waits = request["steps"]
        .as_array()
        .into_iter()
        .flatten()
        .map(step_ms)
        .sum::<u64>();
    Duration::from_millis(20_000 + waits)
}

/// The model sends every optional property, null when unused.
fn without_nulls(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .filter(|(_, value)| !value.is_null())
                .map(|(key, value)| (key, without_nulls(value)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(without_nulls).collect()),
        other => other,
    }
}

/// The helper's reply as the tool result: refusals and failures are errors
/// that say what was already done.
fn reply_result(tool: &'static str, reply: Value) -> Result<Value, HostToolError> {
    let did = did_lines(&reply);
    let done = done(&did);
    let failure = |reason: String| Err(HostToolError::Unavailable { tool, reason });
    if let Some(stopped) = reply["stopped"].as_str() {
        return failure(format!("{stopped} ({done})"));
    }
    if let Some(error) = reply["error"].as_str() {
        return failure(format!("{error} ({done})"));
    }
    let mut result = json!({ "did": did, "stepsMs": reply["stepsMs"] });
    for key in ["device", "devices"] {
        if let Some(value) = reply.get(key) {
            result[key] = value.clone();
        }
    }
    if let Some(layout) = reply.get("layout") {
        result["layout"] = layout.clone();
    }
    for key in ["layoutError", "shotError"] {
        if let Some(error) = reply.get(key) {
            result[key] = error.clone();
        }
    }
    if let Some(shot) = reply.get("shot") {
        let jpeg = shot["jpeg"]
            .as_str()
            .and_then(|data| {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.decode(data).ok()
            })
            .ok_or_else(|| HostToolError::Unavailable {
                tool,
                reason: "the desktop's screenshot came back unreadable".to_owned(),
            })?;
        result["shot"] = json!({
            "size": format!("{}x{}", shot["width"], shot["height"]),
            "ms": shot["ms"],
            "savedOnDesktopHost": shot["saved"],
            "pointer": "x, y in click, point, drag, scroll and zoom are pixels of this image",
        });
        result["images"] = json!([image_block(&jpeg)]);
    }
    Ok(result)
}

/// The steps the helper reports done, in order.
fn did_lines(reply: &Value) -> Vec<String> {
    reply["did"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|line| line.as_str().map(str::to_owned))
        .collect()
}

fn done(did: &[String]) -> String {
    if did.is_empty() {
        "nothing was done".to_owned()
    } else {
        format!("done first: {}", did.join("; "))
    }
}

const LOOK: &str = "desktop_look";
const ACT: &str = "desktop_act";

/// A tool's parameters are its capability's declared input schema.
fn declared(schema: &str) -> Value {
    serde_json::from_str(schema).expect("a declared desktop input schema")
}

pub(super) fn desktop_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    let gate = |runtime: &Arc<HermesRuntime>, tool: &'static str| {
        let runtime = Arc::clone(runtime);
        Box::new(move |_scope: &Scope, _arguments: &Value| {
            runtime
                .desk
                .ask()
                .and(runtime.desk.route().map(drop))
                .map_err(|reason| HostToolError::Unavailable { tool, reason })
        })
    };
    let look_runtime = Arc::clone(runtime);
    tools.push(Arc::new(CapabilityTool::plain(
        RpcHostToolDefinition {
            name: LOOK.into(),
            label: "Look at the owner's desktop".into(),
            description:
                "See the owner's desktop: its monitors, workspaces and windows with their ids, \
                 and a screenshot as an image. Only while answering his own ask."
                    .into(),
            parameters: declared(include_str!(
                "../../../../schemas/capability/desktop.look.input.json"
            )),
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
        },
        Box::new(move |_scope, arguments| look_runtime.desk_look(&arguments)),
        gate(runtime, LOOK),
    )));
    let act_runtime = Arc::clone(runtime);
    tools.push(Arc::new(CapabilityTool::prepared(
        RpcHostToolDefinition {
            name: ACT.into(),
            label: "Use the owner's desktop".into(),
            description: "Used on the desktop only when the owner asks.".into(),
            parameters: declared(include_str!(
                "../../../../schemas/capability/desktop.act.input.json"
            )),
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
        },
        Box::new(move |effect, _scope, arguments| {
            require_prepared(effect, "desktop.act", ACT, &arguments)?;
            let key = format!("desktop-act:{}", effect.correlation_id().as_str());
            act_runtime.desk_act(ACT, "desktop.act", key, None, &arguments)
        }),
        gate(runtime, ACT),
    )));
    for (tool, capability, label, schema) in [
        (
            "desktop_display",
            "desktop.display",
            "Turn desktop monitors on or off",
            include_str!("../../../../schemas/capability/desktop.display.input.json"),
        ),
        (
            "desktop_device",
            "desktop.device",
            "Control desktop devices",
            include_str!("../../../../schemas/capability/desktop.device.input.json"),
        ),
        (
            "desktop_scene",
            "desktop.scene",
            "Run a desktop scene",
            include_str!("../../../../schemas/capability/desktop.scene.input.json"),
        ),
        (
            "desktop_headless",
            "desktop.headless",
            "Control the private desktop",
            include_str!("../../../../schemas/capability/desktop.headless.input.json"),
        ),
    ] {
        let runtime = Arc::clone(runtime);
        let preflight = gate(&runtime, tool);
        tools.push(Arc::new(CapabilityTool::prepared(
            RpcHostToolDefinition {
                name: tool.into(),
                label: label.into(),
                description: "Used only when the owner asks. Optional device selects a declared desktop by friendly name; omitted uses the declared conversation desktop. Display alone supports device=all. A sleeping or away device fails by name; other devices remain usable.".into(),
                parameters: declared(schema),
                hidden: false,
                load_mode: ToolLoadMode::Discoverable,
            },
            Box::new(move |effect, _scope, arguments| {
                require_prepared(effect, capability, tool, &arguments)?;
                let key = format!("desktop-act-{tool}:{}", effect.correlation_id().as_str());
                runtime.desk_act(tool, capability, key, None, &arguments)
            }),
            preflight,
        )));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_desktop_serves_only_a_recent_owner_ask() {
        let desk = DeskCell::default();
        assert!(desk.ask().unwrap_err().contains("not asked anything"));
        desk.turn_opened(Provenance::Owner, "discord:v1:1");
        assert_eq!(desk.ask().unwrap(), "discord:v1:1");
        desk.turn_opened(Provenance::Report, "schedule:job:1");
        assert_eq!(
            desk.ask().unwrap(),
            "discord:v1:1",
            "a job report continues the ask"
        );
        desk.turn_opened(Provenance::Wake, "schedule:wake");
        assert!(desk.ask().unwrap_err().contains("routine"));
        desk.turn_opened(Provenance::Owner, "discord:v1:2");
        assert_eq!(desk.ask().unwrap(), "discord:v1:2");
        desk.turn().ask = Some((
            "old".into(),
            Instant::now() - ASK_WINDOW - Duration::from_secs(60),
        ));
        assert!(desk.ask().unwrap_err().contains("16 min ago"));
    }

    #[test]
    fn replies_become_results_or_errors_that_say_what_was_done() {
        let ok = reply_result(
            ACT,
            json!({"ok": true, "did": ["focused Player (player, window 9)"], "stepsMs": 3,
                   "shot": {"jpeg": "/9j/", "width": 1568, "height": 882, "saved": "/tmp/odin-desk/1-1.jpg", "ms": 120}}),
        )
        .unwrap();
        assert_eq!(ok["shot"]["size"], "1568x882");
        assert_eq!(ok["images"][0]["mimeType"], "image/jpeg");
        let stopped = reply_result(
            ACT,
            json!({"ok": false, "did": ["clicked Left at (1, 2)"], "stopped": "the owner moved his mouse (G502) at 12:00:01; she stops until he asks again"}),
        )
        .unwrap_err()
        .to_string();
        assert!(
            stopped.contains("moved his mouse") && stopped.contains("done first: clicked"),
            "{stopped}"
        );
    }
}
