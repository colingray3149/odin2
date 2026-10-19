//! Scoped coding operations and read-only checkout navigation.

use std::sync::Arc;

use odin_domain::Scope;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode};
use serde_json::{json, Value};

use super::tools::{object_schema, parse_string, CapabilityTool};
use super::HermesRuntime;

pub mod report;

/// Symbol navigation in the session workspace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CodeQuery {
    /// Where the symbol is declared (fn, struct, def, class, ...).
    Definition(String),
    /// Every whole-word use of the symbol.
    References(String),
}

impl CodeQuery {
    pub fn symbol(&self) -> &str {
        match self {
            Self::Definition(symbol) | Self::References(symbol) => symbol,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CheckoutQuery {
    Code(CodeQuery),
    Read { path: String, start_line: usize },
    List(String),
    Search(String),
    Log,
    Diff(Option<String>),
    Show(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NixLog {
    pub ok: bool,
    pub log: String,
    pub seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TestSelection {
    /// Exactly these capsule-relative pytest files, in the registered
    /// session's sandbox with its project dev environment.
    Paths(Vec<String>),
    /// One flake output that runs the tests (`Some`), or every flake check.
    Attr(Option<String>),
}

/// Whether a coding publication was refused or may already have committed/
/// published work that must be reconciled rather than retried blindly.
#[derive(Debug)]
pub enum ProposalFailure {
    Refused(String),
    Uncertain(String),
}

impl From<String> for ProposalFailure {
    fn from(reason: String) -> Self {
        Self::Refused(reason)
    }
}

impl std::fmt::Display for ProposalFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(reason) | Self::Uncertain(reason) => formatter.write_str(reason),
        }
    }
}

impl std::error::Error for ProposalFailure {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NixVerb {
    /// `nix build` of one flake output (default `default`).
    Build,
    /// `nix flake check`.
    Check,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactSource {
    /// A file of the calling session's workspace, by its relative path.
    File(String),
    /// Text given inline, such as a pod's question.
    Text(String),
}

/// The longest inline artifact text, in bytes.
pub const MAX_ARTIFACT_TEXT: usize = 1 << 20;

/// The daemon's coding route over the calling session's capsule. Every
/// operation that runs Git or Nix takes `effect`, the admitted permit of
/// `scope`'s session: its cancellation and expiry bound every step.
pub trait CodingRoute: Send + Sync {
    /// Runs the verb; `Ok` carries `{ok, outputs, log, seconds}` (a failed
    /// build is a successful dispatch with `ok = false`).
    fn nix(
        &self,
        effect: &odin_kernel::operation::PreparedEffect,
        scope: &Scope,
        verb: NixVerb,
        attr: Option<String>,
    ) -> Result<Value, String>;
    /// Commits every capsule change onto the session branch in the project
    /// repository, or the exact seat branch named by `branch`:
    /// `{branch, commit, files, changed, local, remote}`. Unreadable
    /// publication outcomes are uncertainty, not effect-free refusals.
    fn propose(
        &self,
        effect: &odin_kernel::operation::PreparedEffect,
        scope: &Scope,
        summary: String,
        branch: Option<String>,
    ) -> Result<Value, ProposalFailure>;
    /// Merges an independently reviewed exact head against an expected main
    /// base: `{project, branch, mergeCommit, remote}`. Declaration decides.
    /// Every step runs under `effect`, the admitted permit of `scope`'s
    /// session: its cancellation and expiry bound the whole merge.
    fn merge(
        &self,
        effect: &odin_kernel::operation::PreparedEffect,
        scope: &Scope,
        project: &str,
        branch: &str,
        expected_base: &str,
        expected_head: &str,
    ) -> Result<Value, ProposalFailure> {
        let _ = (effect, scope, project, branch, expected_base, expected_head);
        Err("merging is not composed on this host".to_owned().into())
    }
    /// Searches the calling session's capsule for one symbol:
    /// `{mode, symbol, matches: [{file, line, text}], truncated}`.
    fn search_code(
        &self,
        effect: &odin_kernel::operation::PreparedEffect,
        scope: &Scope,
        query: CodeQuery,
        limit: usize,
    ) -> Result<Value, String> {
        let _ = (effect, scope, query, limit);
        Err("code navigation is not composed on this host".to_owned())
    }
    fn inspect_project(
        &self,
        effect: &odin_kernel::operation::PreparedEffect,
        scope: &Scope,
        project: &str,
        query: CheckoutQuery,
        limit: usize,
    ) -> Result<Value, String> {
        let _ = (effect, scope, project, query, limit);
        Err("project checkout reading is not composed on this host".to_owned())
    }
    /// Runs the verb with full build logs for diagnostics and test parsing.
    fn nix_log(
        &self,
        effect: &odin_kernel::operation::PreparedEffect,
        scope: &Scope,
        verb: NixVerb,
        attr: Option<String>,
    ) -> Result<NixLog, String> {
        let _ = (effect, scope, verb, attr);
        Err("logged Nix runs are not composed on this host".to_owned())
    }
    /// Freezes the registered capsule's complete pending tree, runs the
    /// selected tests on exactly that snapshot (scoped files under the
    /// prepared operation's stop authority, or a flake output) and returns
    /// the parsed report ([`test_report`]) only after recording it with
    /// that run for the review lane.
    fn run_tests(
        &self,
        effect: &odin_kernel::operation::PreparedEffect,
        scope: &Scope,
        selection: TestSelection,
    ) -> Result<Value, String> {
        let _ = (effect, scope, selection);
        Err("test runs are not composed on this host".to_owned())
    }
    /// Carries a superseded session's exact test and review evidence to its
    /// trusted successor (the conversation rollover), for the successor's
    /// own seat, project and base only.
    fn carry_review_evidence(
        &self,
        predecessor: &odin_domain::SessionId,
        successor: &odin_domain::SessionId,
    ) -> Result<(), String> {
        let _ = (predecessor, successor);
        Err("the review lane is not composed on this host".to_owned())
    }
    /// Snapshots the capsule diff and its test report for `reviewer`:
    /// `{diffDigest, artifactId, reviewer, tests}`.
    fn request_review(
        &self,
        effect: &odin_kernel::operation::PreparedEffect,
        scope: &Scope,
        reviewer: String,
    ) -> Result<Value, String> {
        let _ = (effect, scope, reviewer);
        Err("the review lane is not composed on this host".to_owned())
    }
    /// Records the calling (reviewer) seat's verdict on one requested diff.
    fn record_verdict(
        &self,
        scope: &Scope,
        diff_digest: String,
        approve: bool,
        notes: String,
    ) -> Result<Value, String> {
        let _ = (scope, diff_digest, approve, notes);
        Err("the review lane is not composed on this host".to_owned())
    }
    /// `propose`, but only on an approving independent verdict for the
    /// exact pending diff (lanes declaring `requires_independent_review`).
    fn propose_reviewed(
        &self,
        effect: &odin_kernel::operation::PreparedEffect,
        scope: &Scope,
        summary: String,
        branch: Option<String>,
    ) -> Result<Value, ProposalFailure> {
        let _ = (effect, scope, summary, branch);
        Err(ProposalFailure::Refused(
            "the review lane is not composed on this host; this lane requires one".to_owned(),
        ))
    }
    /// Stores a capsule file or inline text as a content-addressed artifact readable
    /// by the writer's seat/project and `share_with`: `{artifactId, sizeBytes, mediaType, readableBy}`.
    fn write_artifact(
        &self,
        scope: &Scope,
        source: ArtifactSource,
        media_type: Option<String>,
        share_with: Vec<String>,
    ) -> Result<Value, String> {
        let _ = (scope, source, media_type, share_with);
        Err("artifacts are not composed on this host".to_owned())
    }
    /// Reads one artifact the caller's seat or project may read:
    /// `{artifactId, sizeBytes, mediaType, text | base64}`.
    fn read_artifact(&self, scope: &Scope, artifact_id: String) -> Result<Value, String> {
        let _ = (scope, artifact_id);
        Err("artifacts are not composed on this host".to_owned())
    }
    /// The verified bytes and media type of one artifact the caller may
    /// read, for sending it on (bounded at `max_bytes`).
    fn artifact_bytes(
        &self,
        scope: &Scope,
        artifact_id: &str,
        max_bytes: u64,
    ) -> Result<(Vec<u8>, String), String> {
        let _ = (scope, artifact_id, max_bytes);
        Err("artifacts are not composed on this host".to_owned())
    }
}

fn route(
    runtime: &HermesRuntime,
    tool: &'static str,
) -> Result<Arc<dyn CodingRoute>, HostToolError> {
    runtime
        .coding_route()
        .ok_or_else(|| HostToolError::Unavailable {
            tool,
            reason: "coding tools are not composed on this host".to_owned(),
        })
}

/// A coding tool that runs Git or Nix: its handler receives the admitted
/// permit whose cancellation and expiry bound every step, so it is reachable
/// only through a kernel-prepared effect.
fn prepared_tool(
    name: &'static str,
    label: &'static str,
    description: &'static str,
    parameters: Value,
    handler: impl Fn(&odin_kernel::operation::PreparedEffect, Scope, Value) -> Result<Value, HostToolError>
        + Send
        + Sync
        + 'static,
) -> Arc<dyn HostTool> {
    Arc::new(CapabilityTool::prepared(
        RpcHostToolDefinition {
            name: name.into(),
            label: label.into(),
            description: description.into(),
            parameters,
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
        },
        Box::new(handler),
        Box::new(|_, _| Ok(())),
    ))
}

fn tool(
    name: &'static str,
    label: &'static str,
    description: &'static str,
    parameters: Value,
    handler: impl Fn(Scope, Value) -> Result<Value, HostToolError> + Send + Sync + 'static,
) -> Arc<dyn HostTool> {
    Arc::new(CapabilityTool::plain_without_prerequisites(
        RpcHostToolDefinition {
            name: name.into(),
            label: label.into(),
            description: description.into(),
            parameters,
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
        },
        Box::new(handler),
    ))
}

fn merge_arguments(arguments: &Value) -> Result<(String, String, String, String), HostToolError> {
    let commit = |name| {
        let value = parse_string(arguments, name, 64)?;
        if !matches!(value.len(), 40 | 64) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(HostToolError::Arguments {
                tool: "git_branch_merge",
                detail: format!("{name} must be a full commit identity"),
            });
        }
        Ok(value)
    };
    Ok((
        parse_string(arguments, "project", 64)?,
        parse_string(arguments, "branch", 128)?,
        commit("expectedBase")?,
        commit("expectedHead")?,
    ))
}

pub(super) fn coding_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    // Merging requires independent approval of the exact branch-tip commit.
    {
        let gate_runtime = Arc::clone(runtime);
        let gate = move |_scope: &Scope, arguments: &Value| -> Result<(), HostToolError> {
            merge_arguments(arguments)?;
            route(&gate_runtime, "git_branch_merge").map(|_| ())
        };
        let runtime = Arc::clone(runtime);
        let handler = move |effect: &odin_kernel::operation::PreparedEffect,
                            _consumed: &odin_omp::host_tools::ConsumedHostCommand,
                            scope: Scope,
                            arguments: Value| {
            let (project, branch, base, head) = merge_arguments(&arguments)?;
            route(&runtime, "git_branch_merge")?
                .merge(effect, &scope, &project, &branch, &base, &head)
                .map_err(|failure| match failure {
                    ProposalFailure::Refused(reason) => HostToolError::Unavailable {
                        tool: "git_branch_merge",
                        reason,
                    },
                    ProposalFailure::Uncertain(detail) => HostToolError::Uncertain {
                        tool: "git_branch_merge",
                        detail,
                    },
                })
        };
        tools.push(Arc::new(CapabilityTool::approved(
            RpcHostToolDefinition {
                name: "git_branch_merge".into(),
                label: "Merge a work branch".into(),
                description: "Merges one seat work branch (seat/<seat>/<id>, as a worker handed \
                              it back) into the project's main and pushes main to its remote. \
                              Supply the observed full expectedBase (remote main) and \
                              expectedHead (the offered branch). Stale identities refuse; \
                              the exact head needs independent review and the merged tree \
                              must pass its checks. Declaration decides without asking Colin."
                    .into(),
                parameters: object_schema(
                    "git_branch_merge",
                    json!({
                        "project": { "type": "string", "minLength": 1, "maxLength": 64 },
                        "branch": { "type": "string", "minLength": 1, "maxLength": 128 },
                        "expectedBase": { "type": "string", "pattern": "^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$" },
                        "expectedHead": { "type": "string", "pattern": "^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$" },
                        "approvalId": { "type": "string", "minLength": 1, "maxLength": 128 },
                    }),
                    &["project", "branch", "expectedBase", "expectedHead"],
                ),
                hidden: false,
                load_mode: ToolLoadMode::Discoverable,
            },
            "git.branch.merge",
            Box::new(handler),
            Box::new(gate),
        )));
    }
    {
        let runtime = Arc::clone(runtime);
        let handler = move |scope: Scope, arguments: Value| {
            let given = |field: &str| !matches!(arguments.get(field), None | Some(Value::Null));
            let source = match (given("path"), given("text")) {
                (true, false) => ArtifactSource::File(parse_string(&arguments, "path", 512)?),
                (false, true) => {
                    ArtifactSource::Text(parse_string(&arguments, "text", MAX_ARTIFACT_TEXT)?)
                }
                _ => {
                    return Err(HostToolError::Arguments {
                        tool: "artifact_write",
                        detail: "give exactly one of path or text".to_owned(),
                    })
                }
            };
            let media_type = match arguments.get("mediaType") {
                None | Some(Value::Null) => None,
                Some(_) => Some(parse_string(&arguments, "mediaType", 128)?),
            };
            let share_with = arguments
                .get("shareWith")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .take(8)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            route(&runtime, "artifact_write")?
                .write_artifact(&scope, source, media_type, share_with)
                .map_err(|reason| HostToolError::Unavailable {
                    tool: "artifact_write",
                    reason,
                })
        };
        tools.push(tool(
            "artifact_write",
            "Save an artifact",
            "Saves one file from your workspace (a build output, report, plot, dataset), or the \
             text you give (a pod's question or input), as a content-addressed artifact and \
             returns its artifactId (blake3:…). Your seat and project can read it; name other \
             seats (e.g. sinmara, kubert) or projects (project:<id>) in shareWith so they can \
             read it, send it to Colin, or hand it to a pod. Give exactly one of path (relative \
             to your workspace) or text.",
            object_schema(
                "artifact_write",
                json!({
                    "path": { "type": "string", "minLength": 1, "maxLength": 512 },
                    "text": { "type": "string", "minLength": 1, "maxLength": MAX_ARTIFACT_TEXT },
                    "mediaType": { "type": "string", "minLength": 3, "maxLength": 128 },
                    "shareWith": {
                        "type": "array", "maxItems": 8,
                        "items": { "type": "string", "minLength": 1, "maxLength": 72 }
                    },
                }),
                &[],
            ),
            handler,
        ));
    }
    {
        let runtime = Arc::clone(runtime);
        let handler = move |scope: Scope, arguments: Value| {
            let artifact_id = parse_string(&arguments, "artifactId", 80)?;
            route(&runtime, "artifact_read")?
                .read_artifact(&scope, artifact_id)
                .map_err(|reason| HostToolError::Unavailable {
                    tool: "artifact_read",
                    reason,
                })
        };
        tools.push(tool(
            "artifact_read",
            "Read an artifact",
            "Reads one artifact shared with your seat or project by its artifactId (blake3:…): \
             text comes back as text, other content as base64 (up to 256 KiB).",
            object_schema(
                "artifact_read",
                json!({ "artifactId": { "type": "string", "pattern": "^blake3:[0-9a-f]{64}$" } }),
                &["artifactId"],
            ),
            handler,
        ));
    }
    for (name, verb) in [("build_run", NixVerb::Build), ("check_run", NixVerb::Check)] {
        let runtime = Arc::clone(runtime);
        let handler = move |effect: &odin_kernel::operation::PreparedEffect,
                            scope: Scope,
                            arguments: Value| {
            let attr = match arguments.get("attr") {
                None | Some(Value::Null) => None,
                Some(_) => Some(parse_string(&arguments, "attr", 128)?),
            };
            route(&runtime, name)?
                .nix(effect, &scope, verb, attr)
                .map_err(|reason| HostToolError::Unavailable { tool: name, reason })
        };
        let (label, description, parameters) = match verb {
            NixVerb::Build => (
                "Build with Nix",
                "Builds one flake output of your capsule (all your changes included) with Nix in \
                 its build sandbox and returns the store paths or the failure log tail. Write a \
                 flake.nix first if the project has none.",
                object_schema(
                    name,
                    json!({ "attr": { "type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$" } }),
                    &[],
                ),
            ),
            NixVerb::Check => (
                "Check with Nix",
                "Runs `nix flake check` on your capsule (all your changes included) and returns \
                 success or the failure log tail.",
                object_schema(name, json!({}), &[]),
            ),
        };
        tools.push(prepared_tool(name, label, description, parameters, handler));
    }
    engineering_tools(runtime, tools);
    review_tools(runtime, tools);
    let runtime = Arc::clone(runtime);
    let handler =
        move |effect: &odin_kernel::operation::PreparedEffect, scope: Scope, arguments: Value| {
            let summary = parse_string(&arguments, "summary", 200)?;
            let branch = match arguments.get("branch") {
                None | Some(Value::Null) => None,
                Some(_) => Some(parse_string(&arguments, "branch", 128)?),
            };
            let route = route(&runtime, "git_patch_propose")?;
            let outcome = if lane_requires_review(&runtime, &scope) {
                route.propose_reviewed(effect, &scope, summary, branch)
            } else {
                route.propose(effect, &scope, summary, branch)
            };
            outcome.map_err(|failure| match failure {
                ProposalFailure::Refused(reason) => HostToolError::Unavailable {
                    tool: "git_patch_propose",
                    reason,
                },
                ProposalFailure::Uncertain(detail) => HostToolError::Uncertain {
                    tool: "git_patch_propose",
                    detail,
                },
            })
        };
    tools.push(prepared_tool(
        "git_patch_propose",
        "Hand back your work",
        "Commits every change in your capsule and attempts publication as your session branch; \
         main is never touched. Inspect the returned local and remote publication flags before \
         reporting where the work is available. Pass `branch` for exactly that seat branch \
         (seat/<seat>/<id>); any other ref is refused.",
        object_schema(
            "git_patch_propose",
            json!({
                "summary": { "type": "string", "minLength": 1, "maxLength": 200 },
                "branch": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 128,
                    "pattern": "^seat/[a-z0-9-]+/[a-z0-9-]+$"
                }
            }),
            &["summary"],
        ),
        handler,
    ));
}

/// The optional flake output an engineering run builds (`None` runs every
/// flake check).
fn engineering_attr(arguments: &Value) -> Result<Option<String>, HostToolError> {
    match arguments.get("attr") {
        None | Some(Value::Null) => Ok(None),
        Some(_) => parse_string(arguments, "attr", 128).map(Some),
    }
}

/// The most capsule-relative test files one scoped `test_run` names.
const MAX_TEST_PATHS: usize = 8;

/// The optional capsule-relative test files a scoped `test_run` runs
/// (`None` runs the capsule's flake checks instead).
fn engineering_paths(arguments: &Value) -> Result<Option<Vec<String>>, HostToolError> {
    match arguments.get("paths") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) => {
            if items.is_empty() || items.len() > MAX_TEST_PATHS {
                return Err(HostToolError::Arguments {
                    tool: "test_run",
                    detail: "paths must name 1 to 8 capsule-relative test files".to_owned(),
                });
            }
            for item in items {
                let path = item.as_str().ok_or_else(|| HostToolError::Arguments {
                    tool: "test_run",
                    detail: "every path must be a string".to_owned(),
                })?;
                if path.is_empty() || path.len() > 200 {
                    return Err(HostToolError::Arguments {
                        tool: "test_run",
                        detail: "every path must be 1 to 200 bytes".to_owned(),
                    });
                }
            }
            Ok(Some(
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect(),
            ))
        }
        Some(_) => Err(HostToolError::Arguments {
            tool: "test_run",
            detail: "paths must be an array of capsule-relative test files".to_owned(),
        }),
    }
}

/// The parsed report of one test run, as `test_run` returns it and the
/// daemon records it with that run for the review lane.
pub fn test_report(run: &NixLog, selection: &TestSelection) -> Value {
    let tests = report::parse_tests(&run.log);
    // Tests that never built report why: the compile errors.
    let diagnostics = if run.ok {
        Vec::new()
    } else {
        report::parse_diagnostics(&run.log)
            .diagnostics
            .into_iter()
            .filter(|diagnostic| diagnostic.severity == report::Severity::Error)
            .collect()
    };
    let mut report = json!({
        "ok": run.ok,
        "frameworks": tests.frameworks,
        "passed": tests.passed,
        "failed": tests.failed,
        "ignored": tests.ignored,
        "failures": tests.failures,
        "diagnostics": diagnostics,
        "seconds": run.seconds,
        "logTail": report_tail(&run.log),
    });
    // A scoped run says so: the reviewer reads exactly what ran.
    if let (TestSelection::Paths(paths), Some(object)) = (selection, report.as_object_mut()) {
        object.insert("paths".into(), json!(paths));
    }
    report
}

impl HermesRuntime {
    /// The review lane's explicit rollover transfer, at the conversation's
    /// trusted predecessor→successor transition. A host without a composed
    /// coding route has no review lane, so there is no evidence to carry.
    pub(crate) fn carry_review_evidence(
        &self,
        predecessor: &odin_domain::huginn::LiveSessionId,
        successor: &odin_domain::huginn::LiveSessionId,
    ) -> Result<(), String> {
        let Some(route) = self.coding_route() else {
            return Ok(());
        };
        let session = |id: &odin_domain::huginn::LiveSessionId| {
            odin_domain::SessionId::new(id.to_string())
                .map_err(|error| format!("rollover session {id}: {error}"))
        };
        route.carry_review_evidence(&session(predecessor)?, &session(successor)?)
    }
}

fn logged_run(
    runtime: &HermesRuntime,
    tool: &'static str,
    effect: &odin_kernel::operation::PreparedEffect,
    scope: &Scope,
    attr: Option<String>,
) -> Result<NixLog, HostToolError> {
    let verb = if attr.is_some() {
        NixVerb::Build
    } else {
        NixVerb::Check
    };
    route(runtime, tool)?
        .nix_log(effect, scope, verb, attr)
        .map_err(|reason| HostToolError::Unavailable { tool, reason })
}

const REPORT_LOG_TAIL_BYTES: usize = 2_000;

fn report_tail(log: &str) -> String {
    let start = log.len().saturating_sub(REPORT_LOG_TAIL_BYTES);
    let start = (start..=log.len())
        .find(|index| log.is_char_boundary(*index))
        .unwrap_or(log.len());
    log[start..].to_owned()
}

fn checkout_query(arguments: &Value) -> Result<CheckoutQuery, HostToolError> {
    let invalid = |detail: &str| HostToolError::Arguments {
        tool: "code_navigate",
        detail: detail.to_owned(),
    };
    let revision = || -> Result<String, HostToolError> {
        let value = parse_string(arguments, "revision", 256)?;
        if value.starts_with('-') || value.chars().any(char::is_control) {
            return Err(invalid(
                "revision must not start with '-' or contain control characters",
            ));
        }
        Ok(value)
    };
    let mode = arguments.get("mode").and_then(Value::as_str);
    if let None | Some("definition" | "references") = mode {
        let symbol = parse_string(arguments, "symbol", 128)?;
        let valid = symbol.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && symbol
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            return Err(invalid(&format!("{symbol:?} is not an identifier")));
        }
        return Ok(CheckoutQuery::Code(if mode == Some("references") {
            CodeQuery::References(symbol)
        } else {
            CodeQuery::Definition(symbol)
        }));
    }
    if arguments.get("project").is_none() {
        return Err(invalid(
            "modes read, list, search, log, diff and show need the project to read",
        ));
    }
    match mode {
        Some("read") => {
            let start_line = match arguments.get("startLine") {
                None => 1,
                Some(value) => value
                    .as_u64()
                    .filter(|line| *line > 0)
                    .and_then(|line| usize::try_from(line).ok())
                    .ok_or_else(|| invalid("startLine must be a positive integer"))?,
            };
            Ok(CheckoutQuery::Read {
                path: parse_string(arguments, "path", 4096)?,
                start_line,
            })
        }
        Some("list") => Ok(CheckoutQuery::List(match arguments.get("path") {
            None => ".".to_owned(),
            Some(_) => parse_string(arguments, "path", 4096)?,
        })),
        Some("search") => Ok(CheckoutQuery::Search(parse_string(
            arguments, "query", 1024,
        )?)),
        Some("log") => Ok(CheckoutQuery::Log),
        Some("diff") => Ok(CheckoutQuery::Diff(
            arguments.get("revision").map(|_| revision()).transpose()?,
        )),
        Some("show") => Ok(CheckoutQuery::Show(revision()?)),
        _ => Err(invalid(
            "mode must be definition, references, read, list, search, log, diff or show",
        )),
    }
}

/// Navigation, diagnostics and test reports.
fn engineering_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    {
        let runtime = Arc::clone(runtime);
        let handler = move |effect: &odin_kernel::operation::PreparedEffect,
                            scope: Scope,
                            arguments: Value| {
            let query = checkout_query(&arguments)?;
            let limit = arguments
                .get("limit")
                .and_then(Value::as_u64)
                .map_or(50, |limit| limit.clamp(1, 200)) as usize;
            let route = route(&runtime, "code_navigate")?;
            let result = match (arguments.get("project"), query) {
                (None, CheckoutQuery::Code(query)) => {
                    route.search_code(effect, &scope, query, limit)
                }
                (_, query) => {
                    let project = parse_string(&arguments, "project", 128)?;
                    route.inspect_project(effect, &scope, &project, query, limit)
                }
            };
            result.map_err(|reason| HostToolError::Unavailable {
                tool: "code_navigate",
                reason,
            })
        };
        tools.push(prepared_tool(
            "code_navigate",
            "Read or search code",
            "Find symbol definitions/references (mode definition or references, with symbol) in \
             your session workspace, or in a declared checkout when project is named. With project, \
             also read that checkout using mode read, list, search, log, diff or show; no writes or \
             shell commands. read uses path and optional startLine; list takes an optional directory path; \
             search uses query; diff accepts an optional revision; show requires revision. limit \
             bounds lines, entries, matches or commits (1–200).",
            object_schema(
                "code_navigate",
                json!({
                    "symbol": { "type": "string", "pattern": "^[A-Za-z_][A-Za-z0-9_]{0,127}$" },
                    "mode": { "type": "string", "enum": ["definition", "references", "read", "list", "search", "log", "diff", "show"] },
                    "project": { "type": "string", "minLength": 1, "maxLength": 128 },
                    "path": { "type": "string", "minLength": 1, "maxLength": 4096 },
                    "query": { "type": "string", "minLength": 1, "maxLength": 1024 },
                    "revision": { "type": "string", "minLength": 1, "maxLength": 256 },
                    "startLine": { "type": "integer", "minimum": 1 },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 200 },
                }),
                &[],
            ),
            handler,
        ));
    }
    let attr_schema =
        || json!({ "attr": { "type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$" } });
    {
        let runtime = Arc::clone(runtime);
        let handler = move |effect: &odin_kernel::operation::PreparedEffect,
                            scope: Scope,
                            arguments: Value| {
            let attr = engineering_attr(&arguments)?;
            let run = logged_run(&runtime, "code_diagnostics", effect, &scope, attr)?;
            let report = report::parse_diagnostics(&run.log);
            Ok(json!({
                "ok": run.ok,
                "errors": report.errors,
                "warnings": report.warnings,
                "diagnostics": report.diagnostics,
                "truncated": report.truncated,
                "seconds": run.seconds,
                "logTail": report_tail(&run.log),
            }))
        };
        tools.push(prepared_tool(
            "code_diagnostics",
            "Compiler diagnostics",
            "Builds your capsule with Nix (attr: one flake output such as \
             checks.x86_64-linux.clippy; omitted: every flake check) and returns the compiler, \
             linter and type-checker findings as located diagnostics (file, line, column, code, \
             message). Use it before and after a change to see exactly what broke.",
            object_schema("code_diagnostics", attr_schema(), &[]),
            handler,
        ));
    }
    {
        let runtime = Arc::clone(runtime);
        let handler = move |effect: &odin_kernel::operation::PreparedEffect,
                            scope: Scope,
                            arguments: Value| {
            let selection = match engineering_paths(&arguments)? {
                Some(_) if !matches!(arguments.get("attr"), None | Some(Value::Null)) => {
                    return Err(HostToolError::Arguments {
                        tool: "test_run",
                        detail: "give either attr or paths, not both".to_owned(),
                    });
                }
                Some(paths) => TestSelection::Paths(paths),
                None => TestSelection::Attr(engineering_attr(&arguments)?),
            };
            // The daemon records the report with the frozen run that
            // produced it before answering; a failed record is the error.
            route(&runtime, "test_run")?
                .run_tests(effect, &scope, selection)
                .map_err(|reason| HostToolError::Unavailable {
                    tool: "test_run",
                    reason,
                })
        };
        tools.push(Arc::new(CapabilityTool::prepared(
            RpcHostToolDefinition {
            name: "test_run".into(),
            label: "Run the tests".into(),
            description: "Runs your capsule's tests with Nix and returns parsed results: \
             passed/failed/ignored counts and each failing test with its message, plus the \
             compile errors when the tests did not build. With neither argument it runs every \
             flake check; attr names the one flake output that runs them (such as \
             checks.x86_64-linux.tests); paths instead runs exactly those capsule-relative \
             test files with pytest in a task-owned sandbox using the capsule's Nix dev environment (\"tools/test_x.py\") — \
             the scoped run when the checks would run unrelated suites; its report backs the \
             same review. Give either attr or paths, never both. An empty frameworks list \
             means no test output was recognized, not that tests passed.".into(),
            parameters: object_schema(
                "test_run",
                {
                    let mut properties = attr_schema();
                    properties
                        .as_object_mut()
                        .expect("an object schema")
                        .insert(
                            "paths".into(),
                            json!({
                                "type": "array",
                                "minItems": 1,
                                "maxItems": MAX_TEST_PATHS,
                                "items": { "type": "string", "minLength": 1, "maxLength": 200 },
                            }),
                        );
                    properties
                },
                &[],
            ),
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
            },
            Box::new(handler),
            Box::new(|_, _| Ok(())),
        )));
    }
}

/// Whether the calling session's lane declares
/// `requires_independent_review` in the pinned registry.
fn lane_requires_review(runtime: &HermesRuntime, scope: &Scope) -> bool {
    let Some(lane) = scope.lane.as_ref() else {
        return false;
    };
    runtime.registry_pin().is_some_and(|pin| {
        pin.current().objects.iter().any(|object| {
            object.id == lane.as_str()
                && matches!(
                    &object.config,
                    odin_registry::ObjectConfig::Lane(declared) if declared.requires_independent_review
                )
        })
    })
}

/// Reviewed lanes require another seat's approval of the exact diff and test report.
pub(super) fn review_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    {
        let runtime = Arc::clone(runtime);
        let handler = move |effect: &odin_kernel::operation::PreparedEffect,
                            scope: Scope,
                            arguments: Value| {
            let reviewer = parse_string(&arguments, "reviewer", 64)?;
            route(&runtime, "code_review_request")?
                .request_review(effect, &scope, reviewer)
                .map_err(|reason| HostToolError::Unavailable {
                    tool: "code_review_request",
                    reason,
                })
        };
        tools.push(prepared_tool(
            "code_review_request",
            "Ask for a review",
            "Prepares your work for an independent review: snapshots the complete change from \
             your capsule's base (earlier commits included) and the test_run report of exactly \
             this tree as an artifact the reviewer seat and your own seat can read — your \
             successor session after a rollover re-reads it to re-offer the same reviewed tree. \
             Then ask that \
             seat (seat_ask_<reviewer>) to review the artifactId and diffDigest this \
             returns. On a lane that requires review, git_patch_propose pushes only after \
             the reviewer approves this exact diff; any later edit needs a new test_run and \
             review.",
            object_schema(
                "code_review_request",
                json!({ "reviewer": { "type": "string", "minLength": 1, "maxLength": 64 } }),
                &["reviewer"],
            ),
            handler,
        ));
    }
    {
        let runtime = Arc::clone(runtime);
        let handler = move |scope: Scope, arguments: Value| {
            let diff_digest = parse_string(&arguments, "diffDigest", 80)?;
            let approve = arguments
                .get("approve")
                .and_then(Value::as_bool)
                .ok_or_else(|| HostToolError::Arguments {
                    tool: "code_review_verdict",
                    detail: "approve must be true or false".to_owned(),
                })?;
            let notes = parse_string(&arguments, "notes", 4_000)?;
            route(&runtime, "code_review_verdict")?
                .record_verdict(&scope, diff_digest, approve, notes)
                .map_err(|reason| HostToolError::Unavailable {
                    tool: "code_review_verdict",
                    reason,
                })
        };
        tools.push(tool(
            "code_review_verdict",
            "Record a review verdict",
            "Records your independent verdict on a change another seat asked you to review: \
             approve (true) only after reading its diff and test report (artifact_read) and \
             checking what you doubt (code_navigate, code_diagnostics, test_run); otherwise \
             false with the changes you require in notes. Name the diffDigest from the request.",
            object_schema(
                "code_review_verdict",
                json!({
                    "diffDigest": { "type": "string", "minLength": 8, "maxLength": 80 },
                    "approve": { "type": "boolean" },
                    "notes": { "type": "string", "minLength": 1, "maxLength": 4000 },
                }),
                &["diffDigest", "approve", "notes"],
            ),
            handler,
        ));
    }
}

#[cfg(test)]
mod checkout_query_tests {
    use super::*;

    #[test]
    fn the_shipped_schema_admits_exactly_the_calls_the_handler_accepts() {
        let raw = include_str!("../../../../schemas/capability/code.navigate.input.json");
        let schema =
            odin_domain::knowledge::ToolSchema::from_value(serde_json::from_str(raw).unwrap())
                .unwrap();
        for (call, accepted) in [
            (json!({"symbol": "mean"}), true),
            (json!({"mode": "references", "symbol": "mean"}), true),
            (
                json!({"limit": 20, "mode": "definition", "project": "surtr", "symbol": "mean"}),
                true,
            ),
            (
                json!({"mode": "read", "project": "odin", "path": "README.md"}),
                true,
            ),
            (json!({"mode": "list", "project": "odin"}), true),
            (
                json!({"mode": "search", "project": "odin", "query": "fn main"}),
                true,
            ),
            (json!({"mode": "log", "project": "odin", "limit": 5}), true),
            (json!({"mode": "diff", "project": "odin"}), true),
            (
                json!({"mode": "show", "project": "odin", "revision": "HEAD"}),
                true,
            ),
            (json!({"mode": "definition"}), false),
            (json!({"mode": "list"}), false),
            (json!({"mode": "read", "project": "odin"}), false),
            (json!({"mode": "search", "project": "odin"}), false),
            (json!({"mode": "show", "project": "odin"}), false),
            (
                json!({"mode": "show", "project": "odin", "revision": "--output=/tmp/f"}),
                false,
            ),
            (json!({"mode": "exec", "project": "odin"}), false),
        ] {
            let valid = odin_kernel::validate_input_arguments(&schema, &call).is_ok();
            let handled = checkout_query(&call).is_ok();
            assert_eq!((valid, handled), (accepted, accepted), "{call}");
        }
    }
}
