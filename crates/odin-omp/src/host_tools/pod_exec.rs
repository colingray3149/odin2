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
use serde_json::{json, Value};

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

/// How long the export-dir listing may take, and the most of it that is read back: a pod that
/// exported many files still lists them all.
const POD_EXPORT_LIST_WAIT: Duration = Duration::from_secs(30);
const POD_EXPORT_LISTING_TAIL_BYTES: usize = 1024 * 1024;

/// How often a running fetch is checked against its deadline.
const FETCH_POLL: Duration = Duration::from_millis(20);

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
    ) -> Result<Vec<u8>, HostToolError> {
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
        let attempt = |way: Way, within: Duration| {
            let mut command = std::process::Command::new(web_save);
            command.arg(url).arg(stdin.mode(arguments));
            if way == Way::Direct {
                command.env(DIRECT_ENV, "1");
            }
            let output = match output_within(command, within) {
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
        let timeout = Duration::from_secs(u64::from(contract.timeout_seconds.get()));
        let fetched = match &self.binding.research {
            Some(research) => research.fetch(url, timeout, attempt),
            None => attempt(Way::Exit, timeout).once(),
        };
        fetched
            .and_then(|saved| saved)
            .map_err(|reason| HostToolError::Unavailable {
                tool: TOOL,
                reason: format!("{}: {url}: {reason}", contract.id),
            })
    }

    fn run(
        &self,
        contract: &CapabilityContract,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<Value, HostToolError> {
        let (target, argv, spec) = self.prepare(contract, scope, arguments)?;
        let fetched = spec
            .stdin
            .as_ref()
            .map(|stdin| self.stdin_bytes(contract, stdin, arguments))
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
        match self.export_files(&target) {
            Ok(files) => result["files"] = files,
            Err(reason) => result["filesUnreadable"] = Value::String(reason),
        }
        Ok(result)
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
) -> std::io::Result<Option<std::process::Output>> {
    use std::io::Read;
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command.spawn()?;
    let drain = |pipe: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_end(&mut bytes);
            }
            bytes
        })
    };
    let stdout = drain(child.stdout.take().map(|pipe| Box::new(pipe) as _));
    let stderr = drain(child.stderr.take().map(|pipe| Box::new(pipe) as _));
    let deadline = std::time::Instant::now() + within;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if std::time::Instant::now() >= deadline {
            if let Some(group) = i32::try_from(child.id())
                .ok()
                .and_then(rustix::process::Pid::from_raw)
            {
                let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
            }
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(FETCH_POLL);
    };
    let (stdout, stderr) = (
        stdout.join().unwrap_or_default(),
        stderr.join().unwrap_or_default(),
    );
    Ok(status.map(|status| std::process::Output {
        status,
        stdout,
        stderr,
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
