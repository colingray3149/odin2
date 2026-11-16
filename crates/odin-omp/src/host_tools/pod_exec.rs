//! Pod-exec capabilities: one host tool runs every declared in-image CLI
//! tool, in the calling session's own workload pod.
//!
//! A capability with `implementation = "pod-exec"` binds the reserved
//! markers [`POD_EXEC_HANDLER_ID`] and [`POD_EXEC_RECEIPT_ID`] and declares
//! an `[exec]` table (`odin_registry::schema::PodExecToml`). The call runs
//! `/bin/timeout <timeout_seconds> <executable> <rendered argv>` in the pod's
//! worker container (no shell), then lists the files under the pod's export
//! dir. A table with `stdin.url` first has the authority fetch the input URL
//! with the declared web-save executable (`<web_save> <url> document|render`),
//! and the tool reads those bytes on stdin. A table with `stdin.source` hands that string through as UTF-8. A table with `view` reads that page PNG back whole and returns it as one
//! image block of the result. The text result:
//!
//! `{ capability, argv, exitCode, timedOut, stdout, stderr, stdoutBytes,
//!   stderrBytes, exportDir, files: [{ path, bytes }], filesUnreadable?,
//!   viewed?, images? }`
//!
//! `stdout`/`stderr` are the last [`POD_EXEC_OUTPUT_TAIL_BYTES`] of each
//! stream, except a viewed page: its bytes are the image block, and `stdout`
//! is empty. The byte counts are the full lengths. The kernel journals the
//! call with the receipt digest like every governed effect.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use odin_adapter_core::{FETCH_REFUSED, FETCH_TIMED_OUT};
use odin_domain::{CapabilityId, RunId, Scope, SessionId};
use odin_kernel::{CapabilityContract, HandlerBinding, PreparedEffect, SchemaCatalog};
use odin_registry::schema::{PodExecStdin, PodExecToml, POD_EXEC_HANDLER_ID, POD_EXEC_RECEIPT_ID};
use serde_json::{json, Map, Value};

use super::research::{Attempt, ResearchExit, Way, DIRECT_ENV};
use super::{
    HostInvocation, HostTool, HostToolError, HostToolRegistry, InternalBindingKey,
    RpcHostToolDefinition, ToolLoadMode,
};

/// The bound on each output stream a pod-exec call returns: its last bytes.
pub const POD_EXEC_OUTPUT_TAIL_BYTES: usize = 16 * 1024;
/// The largest page PNG `report.view` brings back whole to show.
const PAGE_VIEW_MAX_BYTES: usize = crate::host_tools::page_view::MAX_PAGE_PNG_BYTES;

/// The total bytes brought back from one pod's export folder.
pub const MAX_EXPORT_BYTES: u64 = 256 * 1024 * 1024;

/// Time the authority waits beyond the in-pod `timeout` for the exec to report.
const POD_EXEC_REPORT_GRACE: Duration = Duration::from_secs(30);
/// Recon's own reads leave pages a site refused, challenged or timed out; this many of them are
/// read again by Odin's browser, each within this long and kept to this many characters, then
/// handed back to recon, which works them in a second pass of this many seconds. The first pass
/// leaves the browser and the second pass their time.
const BROWSED_PAGES: usize = 8;
const BROWSE_TIMEOUT: Duration = Duration::from_secs(45);
const BROWSED_CHARS: usize = 1 << 20;
const SECOND_PASS_SECONDS: u32 = 240;
const BROWSE_RESERVE_SECONDS: u32 = 600;

/// How long the export-dir listing may take, and the most of it that is read back: a pod that
/// exported many files still lists them all.
const POD_EXPORT_LIST_WAIT: Duration = Duration::from_secs(30);
const POD_EXPORT_LISTING_TAIL_BYTES: usize = 1024 * 1024;

/// The most a fetch or sandbox run may print on either stream.
const FETCH_OUTPUT_LIMIT: usize = 256 << 20;

/// coreutils `timeout`'s exit code when its command could not be found.
const TIMEOUT_COMMAND_NOT_FOUND: i32 = 127;
/// coreutils `timeout`'s exit code when the command ran out of time.
const TIMEOUT_EXPIRED: i32 = 124;

const TOOL: &str = POD_EXEC_HANDLER_ID;

/// The pod a workload session runs in.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PodTarget {
    pub run: RunId,
    /// The pod's declared export dir, e.g. `/export`.
    pub export_dir: String,
    /// The admitted workload transport. A protected spec refuses anything else.
    pub network_transport: odin_registry::WorkloadTransport,
    /// The recon plan of the pod's profile: the granted tools that join recon chains.
    pub recon: Option<Arc<Value>>,
}

/// What odin-recon reads: the pod's recon plan, bounded by the call's own timeout, and the request.
pub fn recon_input(
    target: &PodTarget,
    request: &Value,
    budget_seconds: u32,
) -> Result<Vec<u8>, HostToolError> {
    let plan = target.recon.as_deref().ok_or(HostToolError::Scope {
        tool: TOOL,
        reason: "this pod's profile grants no tool that joins recon chains",
    })?;
    plan_input(plan, request, budget_seconds)
}

/// The pages a recon summary says it could not read (`- page <url>: <cause>`), but not those
/// the site said are gone.
fn unread_pages(summary: &str) -> Vec<String> {
    summary
        .lines()
        .filter_map(|line| {
            let (url, cause) = line.strip_prefix("- page ")?.split_once(": ")?;
            (!cause.starts_with("HTTP 404") && !cause.starts_with("HTTP 410"))
                .then(|| url.to_owned())
        })
        .take(BROWSED_PAGES)
        .collect()
}

/// The run folder a recon summary ends with (`Run folder: <path>`).
fn recon_folder(summary: &str) -> Option<&str> {
    summary
        .lines()
        .rev()
        .find_map(|line| line.strip_prefix("Run folder: "))
        .map(str::trim)
}

/// The second pass's request: the first run continued on the pages the browser read.
fn second_request(arguments: &Value, folder: &str, pages: Map<String, Value>) -> Value {
    let mut request = json!({ "continue": folder, "browsed": pages });
    for field in ["deep", "person"] {
        if let Some(value) = arguments.get(field) {
            request[field] = value.clone();
        }
    }
    request
}

/// The first pass's budget: the call's time less what the browser and the second pass need.
fn first_pass_seconds(timeout: u32, browses: bool) -> u32 {
    if browses && timeout > 2 * BROWSE_RESERVE_SECONDS {
        timeout - BROWSE_RESERVE_SECONDS
    } else {
        timeout
    }
}

fn plan_input(
    plan: &Value,
    request: &Value,
    budget_seconds: u32,
) -> Result<Vec<u8>, HostToolError> {
    let mut plan = plan.clone();
    plan["budget"] = json!(budget_seconds);
    serde_json::to_vec(&json!({ "plan": plan, "request": request })).map_err(|error| {
        HostToolError::Unavailable {
            tool: TOOL,
            reason: format!("the recon input does not serialize: {error}"),
        }
    })
}

/// The workload sessions of this authority and their pods, bound by the
/// workload carrier when it attaches a session to its pod.
#[derive(Debug, Default)]
pub struct PodSessions {
    pods: Mutex<BTreeMap<SessionId, PodTarget>>,
}

impl PodSessions {
    pub fn bind(&self, session: SessionId, target: PodTarget) {
        self.pods
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(session, target);
    }

    /// The pod bound to this session, when the carrier has attached one.
    pub fn target_of(&self, session: &SessionId) -> Option<PodTarget> {
        self.target(Some(session))
    }

    fn target(&self, session: Option<&SessionId>) -> Option<PodTarget> {
        let pods = self
            .pods
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        pods.get(session?).cloned()
    }
}

/// One finished command in a pod's worker container.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerOutput {
    pub exit_code: i32,
    pub stdout_tail: Vec<u8>,
    pub stderr_tail: Vec<u8>,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
}

/// Why a worker exec gave no output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkerExecFault {
    /// Nothing ran: the pod is gone, not running, or foreign.
    NotStarted(String),
    /// The command may have run; its end was not observed.
    Unknown(String),
}

/// Runs one fixed argv in a pod's worker container (no shell), given
/// `stdin` when present, keeping the last `tail_bytes` of each stream.
pub trait PodWorkerExec: Send + Sync {
    fn exec(
        &self,
        run: &RunId,
        argv: &[String],
        stdin: Option<&[u8]>,
        wait: Duration,
        tail_bytes: usize,
    ) -> Result<WorkerOutput, WorkerExecFault>;
}

/// What the pod-exec tool needs: each capability's `[exec]` table, the
/// session-to-pod bindings, the exec transport, the authority's
/// declared web-save executable for tables that fetch their stdin, and the
/// research exit that fetch is retried through when a site refuses it.
#[derive(Clone)]
pub struct PodExecBinding {
    pub specs: BTreeMap<CapabilityId, PodExecToml>,
    pub pods: Arc<PodSessions>,
    pub exec: Arc<dyn PodWorkerExec>,
    pub web_save: Option<PathBuf>,
    pub research: Option<Arc<ResearchExit>>,
    /// osint.recon from a seat: the authority's own recon sandbox. Absent, recon runs only in pods.
    pub host_recon: Option<HostRecon>,
}

/// The authority's recon sandbox (`<executable> <root>`: odin-recon with the pod tools at /bin and
/// `root` at /export, through the research exit) and the plan of every tool that joins recon.
#[derive(Clone, Debug)]
pub struct HostRecon {
    pub executable: PathBuf,
    pub root: PathBuf,
    pub plan: Arc<Value>,
}

impl HostRecon {
    /// A seat's plan: every declared tool, at its declared depth.
    fn plan_for(&self, _request: &Value) -> Value {
        (*self.plan).clone()
    }
}

/// The handler every pod-exec capability binds.
pub struct PodExecTool {
    binding: PodExecBinding,
    definition: RpcHostToolDefinition,
}

impl PodExecTool {
    pub fn new(binding: PodExecBinding) -> Self {
        Self {
            binding,
            definition: marker_definition(POD_EXEC_HANDLER_ID),
        }
    }

    /// The caller's pod, the full argv, and the stdin table; refuses before anything runs.
    fn prepare<'s>(
        &'s self,
        contract: &CapabilityContract,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(PodTarget, Vec<String>, &'s PodExecToml), HostToolError> {
        let target =
            self.binding
                .pods
                .target(scope.session.as_ref())
                .ok_or(HostToolError::Scope {
                    tool: TOOL,
                    reason: "a pod-exec capability runs only inside a workload pod",
                })?;
        let spec = self
            .binding
            .specs
            .get(&contract.id)
            .ok_or_else(|| HostToolError::Catalog {
                detail: format!(
                    "pod-exec capability {} declares no [exec] table",
                    contract.id
                ),
            })?;
        if spec.transport == odin_registry::WorkloadTransport::VpnRequired
            && target.network_transport != odin_registry::WorkloadTransport::VpnRequired
        {
            return Err(HostToolError::Scope {
                tool: TOOL,
                reason: "this capability requires VPN transport but this pod has direct transport",
            });
        }
        let rendered = spec
            .render(arguments)
            .map_err(|cause| HostToolError::Arguments {
                tool: TOOL,
                detail: format!("{}: {cause}", contract.id),
            })?;
        if spec.stdin.as_ref().is_some_and(PodExecStdin::fetches) && self.binding.web_save.is_none()
        {
            return Err(HostToolError::Unavailable {
                tool: TOOL,
                reason: format!(
                    "{} fetches a page for the pod, and this authority declares no \
                     executables.web_save",
                    contract.id
                ),
            });
        }
        let mut argv = vec![
            "/bin/timeout".to_owned(),
            contract.timeout_seconds.get().to_string(),
            spec.executable.clone(),
        ];
        argv.extend(rendered);
        Ok((target, argv, spec))
    }

    /// Bytes the declared stdin table hands the tool: a fetched page, or the source field.
    fn stdin_bytes(
        &self,
        contract: &CapabilityContract,
        stdin: &PodExecStdin,
        arguments: &Value,
        target: &PodTarget,
    ) -> Result<Vec<u8>, HostToolError> {
        if stdin.plan {
            let budget = first_pass_seconds(
                contract.timeout_seconds.get(),
                self.binding.web_save.is_some(),
            );
            return recon_input(target, arguments, budget);
        }
        if stdin.fetches() {
            return self.fetch(contract, stdin, arguments);
        }
        stdin
            .source_bytes(arguments)
            .map_err(|cause| HostToolError::Arguments {
                tool: TOOL,
                detail: format!("{}: {cause}", contract.id),
            })
    }

    /// The page `stdin` names, fetched on the authority by the declared web-save executable. A
    /// site that refuses it, or times out (exit 124 or 67), is fetched again from the next
    /// research region; a failure names the cause the fetch printed.
    fn fetch(
        &self,
        contract: &CapabilityContract,
        stdin: &PodExecStdin,
        arguments: &Value,
    ) -> Result<Vec<u8>, HostToolError> {
        let arguments_error = |detail: &str| HostToolError::Arguments {
            tool: TOOL,
            detail: format!("{}: {detail}", contract.id),
        };
        let web_save =
            self.binding
                .web_save
                .as_ref()
                .ok_or_else(|| HostToolError::Unavailable {
                    tool: TOOL,
                    reason: format!("{} declares no executables.web_save", contract.id),
                })?;
        let field = stdin
            .url
            .as_deref()
            .ok_or_else(|| arguments_error("the [exec] table names no url field"))?;
        let url = arguments
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| arguments_error(&format!("{field} must be a string")))?;
        let timeout = Duration::from_secs(u64::from(contract.timeout_seconds.get()));
        self.browser_fetch(web_save, url, stdin.mode(arguments), timeout)
            .map_err(|reason| HostToolError::Unavailable {
                tool: TOOL,
                reason: format!("{}: {url}: {reason}", contract.id),
            })
    }

    /// One page through Odin's own browser (`<web_save> <url> <mode>`), from the next research
    /// region when a site refuses or times out.
    fn browser_fetch(
        &self,
        web_save: &std::path::Path,
        url: &str,
        mode: &str,
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        let attempt = |way: Way, within: Duration| {
            let mut command = std::process::Command::new(web_save);
            command.arg(url).arg(mode);
            if way == Way::Direct {
                command.env(DIRECT_ENV, "1");
            }
            let output = match output_within(command, within, None) {
                Ok(Some(output)) => output,
                Ok(None) => {
                    let said = format!("the fetch did not finish within {} s", within.as_secs());
                    return Attempt::Refused(said);
                }
                Err(error) => {
                    let said = format!("{} could not start: {error}", web_save.display());
                    return Attempt::Done(Err(said));
                }
            };
            if output.status.success() {
                return Attempt::Done(Ok(output.stdout));
            }
            let said = String::from_utf8_lossy(&output.stderr);
            let said = match said.trim().lines().last() {
                Some(line) => line.to_owned(),
                None => format!("the fetch ended with {}", output.status),
            };
            match output.status.code() {
                Some(FETCH_TIMED_OUT | FETCH_REFUSED) => Attempt::Refused(said),
                _ => Attempt::Done(Err(said)),
            }
        };
        let fetched = match &self.binding.research {
            Some(research) => research.fetch(url, timeout, attempt),
            None => attempt(Way::Exit, timeout).once(),
        };
        fetched.and_then(|saved| saved)
    }

    /// The pages a recon run could not read itself, read by Odin's browser: each one's HTML by URL,
    /// and a line per page that failed there too.
    fn browse_unread(&self, summary: &str) -> (Map<String, Value>, Vec<String>) {
        let mut pages = Map::new();
        let mut failed = Vec::new();
        let Some(web_save) = self.binding.web_save.as_ref() else {
            return (pages, failed);
        };
        for url in unread_pages(summary) {
            match self.browser_fetch(web_save, &url, "document", BROWSE_TIMEOUT) {
                Ok(bytes) => {
                    let text = String::from_utf8_lossy(&bytes);
                    let cut = text
                        .char_indices()
                        .nth(BROWSED_CHARS)
                        .map_or(text.len(), |(at, _)| at);
                    pages.insert(url, Value::String(text[..cut].to_owned()));
                }
                Err(reason) => failed.push(format!("- browser {url}: {reason}")),
            }
        }
        (pages, failed)
    }

    /// A recon call from a session with no pod runs on the authority, in its recon sandbox.
    fn on_authority(&self, contract: &CapabilityContract, scope: &Scope) -> bool {
        let planned = self
            .binding
            .specs
            .get(&contract.id)
            .and_then(|spec| spec.stdin.as_ref())
            .is_some_and(|stdin| stdin.plan);
        planned && self.binding.pods.target(scope.session.as_ref()).is_none()
    }

    /// osint.recon from a seat: the same engine and tools, in the authority's recon sandbox.
    fn run_on_authority(
        &self,
        contract: &CapabilityContract,
        arguments: &Value,
    ) -> Result<Value, HostToolError> {
        let host = self
            .binding
            .host_recon
            .as_ref()
            .ok_or(HostToolError::Unavailable {
                tool: TOOL,
                reason: format!(
                    "{} outside a pod runs in the authority's recon sandbox, and this authority \
                 declares no executables.recon",
                    contract.id
                ),
            })?;
        std::fs::create_dir_all(&host.root).map_err(|error| HostToolError::Unavailable {
            tool: TOOL,
            reason: format!("{}: {error}", host.root.display()),
        })?;
        let timeout = contract.timeout_seconds.get();
        let budget = first_pass_seconds(timeout, self.binding.web_save.is_some());
        let sandbox = |request: &Value, seconds: u32| {
            let input = plan_input(&host.plan_for(arguments), request, seconds)?;
            let mut command = std::process::Command::new(&host.executable);
            command.arg(&host.root);
            let within = Duration::from_secs(u64::from(seconds)) + POD_EXEC_REPORT_GRACE;
            output_within(command, within, Some(input)).map_err(|error| {
                HostToolError::Unavailable {
                    tool: TOOL,
                    reason: format!("{} could not start: {error}", host.executable.display()),
                }
            })
        };
        let mut output = sandbox(arguments, budget)?;
        // The pages recon could not read go through Odin's browser, and recon works them.
        if let Some(first) = output.as_mut().filter(|first| first.status.success()) {
            let summary = String::from_utf8_lossy(&first.stdout).into_owned();
            if let Some(folder) = recon_folder(&summary) {
                let (pages, failed) = self.browse_unread(&summary);
                let mut more = String::new();
                if !pages.is_empty() {
                    let read = pages.len();
                    let request = second_request(arguments, folder, pages);
                    if let Some(second) = sandbox(&request, SECOND_PASS_SECONDS)? {
                        more = format!(
                            "\n\n# After Odin's browser read {read} page(s) recon could not\n\n{}",
                            String::from_utf8_lossy(&second.stdout)
                        );
                    }
                }
                if !failed.is_empty() {
                    more.push_str(&format!(
                        "\n\nThe browser could not read:\n{}\n",
                        failed.join("\n")
                    ));
                }
                first.stdout.extend_from_slice(more.as_bytes());
            }
        }
        let tail = |bytes: &[u8]| {
            let start = bytes.len().saturating_sub(POD_EXEC_OUTPUT_TAIL_BYTES);
            String::from_utf8_lossy(&bytes[start..]).into_owned()
        };
        // The same output contract as a pod's run, so its receipt and journal read it alike.
        let argv = [
            host.executable.display().to_string(),
            host.root.display().to_string(),
        ];
        Ok(match output {
            Some(output) => json!({
                "capability": contract.id.as_str(),
                "argv": argv,
                "exitCode": output.status.code().unwrap_or(-1),
                "timedOut": false,
                "stdout": tail(&output.stdout),
                "stderr": tail(&output.stderr),
                "stdoutBytes": output.stdout.len(),
                "stderrBytes": output.stderr.len(),
                "exportDir": host.root.display().to_string(),
                "files": [],
            }),
            None => json!({
                "capability": contract.id.as_str(),
                "argv": argv,
                "exitCode": TIMEOUT_EXPIRED,
                "timedOut": true,
                "stdout": "",
                "stderr": format!("recon did not finish within {} s", u64::from(budget) + POD_EXEC_REPORT_GRACE.as_secs()),
                "stdoutBytes": 0,
                "stderrBytes": 0,
                "exportDir": host.root.display().to_string(),
                "files": [],
            }),
        })
    }

    fn run(
        &self,
        contract: &CapabilityContract,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<Value, HostToolError> {
        if self.on_authority(contract, scope) {
            return self.run_on_authority(contract, arguments);
        }
        let (target, argv, spec) = self.prepare(contract, scope, arguments)?;
        let fetched = spec
            .stdin
            .as_ref()
            .map(|stdin| self.stdin_bytes(contract, stdin, arguments, &target))
            .transpose()?;
        let wait =
            Duration::from_secs(u64::from(contract.timeout_seconds.get())) + POD_EXEC_REPORT_GRACE;
        let tail = if spec.view.is_some() {
            PAGE_VIEW_MAX_BYTES
        } else {
            POD_EXEC_OUTPUT_TAIL_BYTES
        };
        let output = self
            .binding
            .exec
            .exec(&target.run, &argv, fetched.as_deref(), wait, tail)
            .map_err(|fault| match fault {
                WorkerExecFault::NotStarted(reason) => HostToolError::Unavailable {
                    tool: TOOL,
                    reason: format!("{}: {reason}", contract.id),
                },
                WorkerExecFault::Unknown(detail) => HostToolError::Uncertain {
                    tool: TOOL,
                    detail: format!("{}: {detail}", contract.id),
                },
            })?;
        if output.exit_code == TIMEOUT_COMMAND_NOT_FOUND {
            return Err(HostToolError::Unavailable {
                tool: TOOL,
                reason: format!(
                    "`{}` is not in the pod image; add its package to nix/pod-tools.nix",
                    argv[2]
                ),
            });
        }
        let mut result = json!({
            "capability": contract.id.as_str(),
            "argv": argv,
            "exitCode": output.exit_code,
            "timedOut": output.exit_code == TIMEOUT_EXPIRED,
            "stdout": if spec.view.is_some() {
                String::new()
            } else {
                String::from_utf8_lossy(&output.stdout_tail).into_owned()
            },
            "stderr": String::from_utf8_lossy(&output.stderr_tail),
            "stdoutBytes": output.stdout_bytes,
            "stderrBytes": output.stderr_bytes,
            "exportDir": target.export_dir,
            "files": [],
        });
        if let Some(field) = &spec.view {
            let path = arguments
                .get(field)
                .and_then(Value::as_str)
                .ok_or_else(|| HostToolError::Arguments {
                    tool: TOOL,
                    detail: format!("{}: {field} must be a string", contract.id),
                })?;
            if output.exit_code != 0 {
                return Err(HostToolError::Unavailable {
                    tool: TOOL,
                    reason: format!(
                        "{}: viewing {path} failed: {}",
                        contract.id,
                        String::from_utf8_lossy(&output.stderr_tail).trim()
                    ),
                });
            }
            if output.stdout_bytes != output.stdout_tail.len() as u64 {
                return Err(HostToolError::Unavailable {
                    tool: TOOL,
                    reason: format!(
                        "{}: {path} is {} bytes, over the {PAGE_VIEW_MAX_BYTES}-byte page limit",
                        contract.id, output.stdout_bytes
                    ),
                });
            }
            let image = crate::host_tools::page_view::page_image(&output.stdout_tail).map_err(
                |reason| HostToolError::Unavailable {
                    tool: TOOL,
                    reason: format!("{}: {path} cannot be shown: {reason}", contract.id),
                },
            )?;
            result["viewed"] = Value::String(path.to_owned());
            result["images"] = json!([image]);
        }
        if spec.stdin.as_ref().is_some_and(|stdin| stdin.plan) && output.exit_code == 0 {
            let more = self.browse_in_pod(&target, &argv, arguments, &result["stdout"], wait);
            if let (Some(stdout), false) = (result["stdout"].as_str(), more.is_empty()) {
                result["stdout"] = Value::String(format!("{stdout}{more}"));
            }
        }
        match self.export_files(&target) {
            Ok(files) => result["files"] = files,
            Err(reason) => result["filesUnreadable"] = Value::String(reason),
        }
        Ok(result)
    }

    /// A pod's recon pass on the pages its own reads could not get: Odin's browser reads them and
    /// recon, run again in the pod, continues on them. What it adds to the summary.
    fn browse_in_pod(
        &self,
        target: &PodTarget,
        argv: &[String],
        arguments: &Value,
        summary: &Value,
        wait: Duration,
    ) -> String {
        let Some(summary) = summary.as_str() else {
            return String::new();
        };
        let Some(folder) = recon_folder(summary) else {
            return String::new();
        };
        let (pages, failed) = self.browse_unread(summary);
        let mut more = String::new();
        if !pages.is_empty() {
            let read = pages.len();
            let request = second_request(arguments, folder, pages);
            let second = recon_input(target, &request, SECOND_PASS_SECONDS)
                .ok()
                .and_then(|stdin| {
                    self.binding
                        .exec
                        .exec(
                            &target.run,
                            argv,
                            Some(&stdin),
                            wait,
                            POD_EXEC_OUTPUT_TAIL_BYTES,
                        )
                        .ok()
                });
            match second {
                Some(second) => {
                    more = format!(
                        "\n\n# After Odin's browser read {read} page(s) recon could not\n\n{}",
                        String::from_utf8_lossy(&second.stdout_tail)
                    )
                }
                None => {
                    more = format!(
                    "\n\nOdin's browser read {read} page(s), but recon's second pass did not run."
                )
                }
            }
        }
        if !failed.is_empty() {
            more.push_str(&format!(
                "\n\nThe browser could not read:\n{}\n",
                failed.join("\n")
            ));
        }
        more
    }

    /// The files under the pod's export dir after the run, with their sizes.
    fn export_files(&self, target: &PodTarget) -> Result<Value, String> {
        Ok(Value::Array(
            export_listing(self.binding.exec.as_ref(), target)?
                .into_iter()
                .map(|(path, bytes)| json!({ "path": path, "bytes": bytes }))
                .collect(),
        ))
    }
}

/// The files under a pod's export dir: each path (relative to it) and size.
fn export_listing(
    exec: &dyn PodWorkerExec,
    target: &PodTarget,
) -> Result<Vec<(String, u64)>, String> {
    let argv = [
        "/bin/find",
        target.export_dir.as_str(),
        "-type",
        "f",
        "-printf",
        "%s %P\\0",
    ]
    .map(str::to_owned);
    let listing = exec
        .exec(
            &target.run,
            &argv,
            None,
            POD_EXPORT_LIST_WAIT,
            POD_EXPORT_LISTING_TAIL_BYTES,
        )
        .map_err(|fault| match fault {
            WorkerExecFault::NotStarted(reason) | WorkerExecFault::Unknown(reason) => reason,
        })?;
    if listing.exit_code != 0 {
        return Err(format!(
            "listing {} exited {}: {}",
            target.export_dir,
            listing.exit_code,
            String::from_utf8_lossy(&listing.stderr_tail).trim()
        ));
    }
    if listing.stdout_bytes > listing.stdout_tail.len() as u64 {
        return Err(format!(
            "the export listing exceeds the {POD_EXPORT_LISTING_TAIL_BYTES}-byte limit"
        ));
    }
    let text = std::str::from_utf8(&listing.stdout_tail)
        .map_err(|error| format!("the export listing has a non-UTF-8 file name: {error}"))?;
    text.split_terminator('\0')
        .map(|entry| {
            let (bytes, path) = entry
                .split_once(' ')
                .ok_or_else(|| "the export listing has no file size".to_owned())?;
            let bytes = bytes
                .parse::<u64>()
                .map_err(|error| format!("the export listing has an invalid size: {error}"))?;
            Ok((path.to_owned(), bytes))
        })
        .collect()
}

/// Runs `command` on the authority, killing its whole process group when it has not exited within
/// `within` (`Ok(None)`), so a hung fetch cannot hold the tool call or leave a writer behind.
fn output_within(
    mut command: std::process::Command,
    within: Duration,
    input: Option<Vec<u8>>,
) -> std::io::Result<Option<std::process::Output>> {
    let output = odin_process::run_bounded(
        &mut command,
        input,
        odin_process::ChildBounds {
            timeout: within,
            max_stdout_bytes: FETCH_OUTPUT_LIMIT,
            max_stderr_bytes: FETCH_OUTPUT_LIMIT,
        },
    )?;
    if output.stdout.truncated() || output.stderr.truncated() {
        return Err(std::io::Error::other(format!(
            "its output passed the {FETCH_OUTPUT_LIMIT}-byte limit"
        )));
    }
    Ok(output.status.map(|status| std::process::Output {
        status,
        stdout: output.stdout.into_bytes(),
        stderr: output.stderr.into_bytes(),
    }))
}

/// One file a finished pod exported: its path under the export dir, its
/// size, and its bytes, or why they were not brought back.
pub struct ExportedFile {
    pub path: String,
    pub bytes: u64,
    pub content: Result<Vec<u8>, String>,
}

/// Brings back every file under a pod's export dir while its worker is
/// still up: files over `max_file_bytes` are named, not read.
pub fn collect_exports(
    exec: &dyn PodWorkerExec,
    target: &PodTarget,
    max_file_bytes: u64,
) -> Result<Vec<ExportedFile>, String> {
    let mut remaining = MAX_EXPORT_BYTES;
    let mut read = |path: &str, bytes: u64| -> Result<Vec<u8>, String> {
        if bytes > max_file_bytes {
            return Err(format!("it is over the {max_file_bytes}-byte limit"));
        }
        if bytes > remaining {
            return Err(format!(
                "the exports exceed the {MAX_EXPORT_BYTES}-byte total limit"
            ));
        }
        remaining -= bytes;
        let argv = [
            "/bin/cat".to_owned(),
            format!("{}/{path}", target.export_dir.trim_end_matches('/')),
        ];
        let tail = usize::try_from(bytes).map_err(|error| error.to_string())?;
        let output = exec
            .exec(&target.run, &argv, None, POD_EXPORT_LIST_WAIT, tail)
            .map_err(|fault| match fault {
                WorkerExecFault::NotStarted(reason) | WorkerExecFault::Unknown(reason) => reason,
            })?;
        if output.exit_code != 0 || output.stdout_bytes != bytes {
            return Err(format!(
                "reading it exited {} after {} of {bytes} bytes: {}",
                output.exit_code,
                output.stdout_bytes,
                String::from_utf8_lossy(&output.stderr_tail).trim()
            ));
        }
        Ok(output.stdout_tail)
    };
    Ok(export_listing(exec, target)?
        .into_iter()
        .map(|(path, bytes)| ExportedFile {
            content: read(&path, bytes),
            path,
            bytes,
        })
        .collect())
}

impl HostTool for PodExecTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn invoke(&self, _invocation: HostInvocation) -> Result<Value, HostToolError> {
        Err(HostToolError::Catalog {
            detail: format!("{TOOL} requires a kernel-minted prepared operation"),
        })
    }

    fn invoke_prepared(
        &self,
        effect: &PreparedEffect,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        self.run(effect.contract(), &invocation.scope, &invocation.arguments)
    }

    fn preflight(
        &self,
        contract: &CapabilityContract,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        if self.on_authority(contract, scope) {
            return match self.binding.host_recon {
                Some(_) => Ok(()),
                None => Err(HostToolError::Unavailable {
                    tool: TOOL,
                    reason: format!(
                        "{} outside a pod runs in the authority's recon sandbox, and this \
                         authority declares no executables.recon",
                        contract.id
                    ),
                }),
            };
        }
        self.prepare(contract, scope, arguments).map(|_| ())
    }
}

/// The receipt of one pod-exec call: what ran, how it ended, what it left.
struct PodExecReceipt {
    definition: RpcHostToolDefinition,
}

impl HostTool for PodExecReceipt {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn invoke(&self, invocation: HostInvocation) -> Result<Value, HostToolError> {
        let output = invocation.arguments.get("output");
        let field = |name: &str| output.and_then(|output| output.get(name)).cloned();
        let (Some(argv), Some(exit_code)) = (field("argv"), field("exitCode")) else {
            return Err(HostToolError::Arguments {
                tool: POD_EXEC_RECEIPT_ID,
                detail: "the pod-exec output carries no argv or exitCode".to_owned(),
            });
        };
        Ok(json!({
            "capability": field("capability"),
            "argv": argv,
            "exitCode": exit_code,
            "stdoutBytes": field("stdoutBytes"),
            "stderrBytes": field("stderrBytes"),
            "files": field("files"),
        }))
    }

    fn preflight(
        &self,
        _contract: &CapabilityContract,
        _scope: &Scope,
        _arguments: &Value,
    ) -> Result<(), HostToolError> {
        Ok(())
    }
}

/// The model-visible face of one pod-exec capability; calls reach the
/// handler through the operation authority, never this name.
struct DeclaredPodExecTool {
    definition: RpcHostToolDefinition,
}

impl HostTool for DeclaredPodExecTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn invoke(&self, _invocation: HostInvocation) -> Result<Value, HostToolError> {
        Err(HostToolError::Catalog {
            detail: format!(
                "{} must be dispatched through the operation authority",
                self.definition.name
            ),
        })
    }

    fn preflight(
        &self,
        _contract: &CapabilityContract,
        _scope: &Scope,
        _arguments: &Value,
    ) -> Result<(), HostToolError> {
        Ok(())
    }
}

fn marker_definition(name: &'static str) -> RpcHostToolDefinition {
    RpcHostToolDefinition {
        name: Cow::Borrowed(name),
        label: Cow::Borrowed("Pod exec"),
        description: Cow::Borrowed("Pod-exec marker binding; never listed."),
        parameters: json!({"type": "object"}),
        hidden: true,
        load_mode: ToolLoadMode::Essential,
    }
}

/// Registers the pod-exec handler and receipt, and each pod-exec
/// capability's model-visible tool from its declared name, description and
/// input schema.
pub fn register(
    registry: &mut HostToolRegistry,
    binding: PodExecBinding,
    contracts: &BTreeMap<CapabilityId, CapabilityContract>,
    schemas: &dyn SchemaCatalog,
) -> Result<(), HostToolError> {
    let marker = HandlerBinding::Builtin {
        name: POD_EXEC_HANDLER_ID.to_owned(),
    };
    for contract in contracts
        .values()
        .filter(|contract| contract.handler == marker)
    {
        if !binding.specs.contains_key(&contract.id) {
            return Err(HostToolError::Catalog {
                detail: format!(
                    "pod-exec capability {} declares no [exec] table",
                    contract.id
                ),
            });
        }
        let schema = schemas
            .schema(&contract.input_schema_ref)
            .map_err(|error| HostToolError::Catalog {
                detail: format!(
                    "pod-exec capability {} input schema {}: {error}",
                    contract.id, contract.input_schema_ref
                ),
            })?;
        registry.register(Arc::new(DeclaredPodExecTool {
            definition: RpcHostToolDefinition {
                name: Cow::Owned(contract.tool_name.as_str().to_owned()),
                label: Cow::Owned(contract.id.as_str().to_owned()),
                description: Cow::Owned(contract.description.clone()),
                parameters: schema.canonical_json().clone(),
                hidden: false,
                load_mode: ToolLoadMode::Essential,
            },
        }))?;
    }
    registry.register_internal(
        InternalBindingKey::Builtin(POD_EXEC_HANDLER_ID.to_owned()),
        Arc::new(PodExecTool::new(binding)),
    )?;
    registry.register_internal(
        InternalBindingKey::Builtin(POD_EXEC_RECEIPT_ID.to_owned()),
        Arc::new(PodExecReceipt {
            definition: marker_definition(POD_EXEC_RECEIPT_ID),
        }),
    )
}

#[cfg(test)]
#[path = "pod_exec_tests.rs"]
mod tests;
