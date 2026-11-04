//! Settlement of a research run's report contract.
//!
//! A profile with `[report] pdf = true` owes one phone PDF beside its
//! markdown. The report is the PDF named by a validated renderer receipt.
//! While the worker is still up, this writes the final measured run stats,
//! re-renders through docs.render's research template so the footer is that
//! measurement, and sends every final page image to the pod model. Review is
//! accepted only when a later turn ends without failure and that exact render
//! is unchanged. The Drive copy completes before release; the laptop save is handed to the durable
//! files.save queue, where queued counts — the laptop is optional — and a
//! save the queue refuses pins the pod. Queued and completed copies are
//! reported as exactly that.
//!
//! A final answer that lists launch-input items as unmet while two review cycles of wall time
//! remain goes back to the pod, once per review cycle, with those items and the methods to try
//! next: at most [`MAX_UNMET_RESUMES`] times, and not again once the pod's list names the same
//! items as the one it was last sent back with. Items that name a receipt only the authority
//! writes are not the pod's to finish and are left out of that list. The render review is
//! bounded too: the pod is offered at most [`MAX_RERENDERS`] re-renders (a source that does not
//! compile counts as one) before the latest render is accepted as it stands, and a review the
//! pod cannot finish (a failed turn, content it will not add) settles the same way. A report
//! settled that way is delivered as partial work, with its unmet items and the methods tried
//! named in the note the launching seat receives.
//!
//! The exact validated render is also saved outside the pod (the laptop's
//! report state directory) from the first settlement pass that holds it, so
//! the report survives its pod: if the carrier is gone before review and the
//! copies finish — released, failed, timed out, cancelled — settlement degrades to that
//! saved report, shared with the launching seat as artifacts. Without one, the authority reads
//! the pod's export back from the node that retains it (once: the first read that works is kept
//! in the run's report state, and a failed one is retried once per review cycle, at most
//! [`MAX_EXPORT_READS`] times) and, when it holds a report.md, renders that itself and delivers
//! it unreviewed as partial work. Without that, the ledger answer is returned as partial work
//! with the unmet contract.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use odin_domain::huginn::LiveSessionId;
use odin_domain::{RunId, Scope, SeatId};
use odin_omp::host_tools::pod_exec::{collect_exports, ExportedFile, PodTarget, PodWorkerExec};
use serde_json::{json, Value};

use super::report_completion::{
    absolute_export, complete_fallback_source, content_gaps, embedded_figures, find_named,
    is_page_raster, report_contract, report_identity, run_tool, run_tool_output, unmet_items,
    unmet_name, ReportCompletion, ReportIdentity,
};

#[path = "report_settle/copies.rs"]
mod copies;
pub(crate) use copies::save_into_root;
use copies::{copies_are_durable, copy_destinations, delivery_note, write_copies};
#[path = "report_settle/names.rs"]
mod names;
use names::{copy_name, delivered_name, report_stem, report_subject};
#[path = "report_settle/persistence.rs"]
mod persistence;
use persistence::{
    finish_gone, gone_export, persist_report, read_retained_export, remember_node, GoneExport,
};
#[path = "report_settle/resume.rs"]
mod resume;
use resume::{resume_decision, resume_with_unmet, unmet_note, Resume, Undone};

const MAX_REPORT_FILE_BYTES: u64 = 25 * 1024 * 1024;
const PAGE_VIEW_MAX_BYTES: u64 = 8 * 1024 * 1024;
const REVIEW_BATCH_BYTES: usize = 600_000;
const MAX_CONTENT_ASKS: u8 = 2;
/// Re-renders after the first the pod is offered: the review loop ends here, with the latest
/// render accepted as it stands.
const MAX_RERENDERS: u8 = 2;
/// Times unmet launch-input items go back to the pod: after the last the report is settled as it
/// stands, with them named.
const MAX_UNMET_RESUMES: u8 = 2;
/// Reads of a gone pod's export from its node, one per review cycle, before it is given up on.
const MAX_EXPORT_READS: u8 = 3;
const SETTLEMENT: &str = "report-settlement.json";
const COPIES: &str = "report-copies.json";
const DELIVERED: &str = "report-delivered.json";
const RENDER: &str = "report-render.json";
/// The receipts the authority writes itself. The pod's tools cannot, so an unmet item naming one
/// is not the pod's to finish.
pub(crate) const AUTHORITY_RECEIPTS: [&str; 3] = [RENDER, COPIES, DELIVERED];
const COMPANION: &str = "report.md";
const PAGES_DIR: &str = "pages";
const PAGES_RECEIPT: &str = "pages/pages.json";
/// The render saved outside the pod, with its digest: the record that
/// makes a lost pod degrade to a readable report instead of a total loss.
const SAVED: &str = "report-saved.json";

/// One resumed model turn. Images are `(mime, base64)` blocks.
#[derive(Debug)]
pub(crate) struct ReviewTurn {
    pub text: String,
    pub images: Vec<(String, String)>,
}

/// Whether the pod may be ended and its carrier released.
#[derive(Debug)]
pub(crate) enum ReportSettlement {
    /// Report, review and both durable copies are done.
    Delivered { note: String, files: String },
    /// The pod is gone and its contract cannot finish. Share an intact saved
    /// render when available; otherwise preserve the ledger answer as partial
    /// work. The run ends here without claiming delivery.
    Salvaged { note: String, files: String },
    /// The pod stays up. `follow_up` is the turn the caller starts.
    Pending {
        note: String,
        follow_up: Option<ReviewTurn>,
    },
    /// The contract cannot be completed from this export. The pod stays up.
    Failed { note: String },
}

/// Collects the pod's export and settles the report contract when the profile
/// owes a PDF. A non-report pod is [`ReportSettlement::Delivered`] so its
/// existing end path still runs.
pub(crate) async fn settle_pod_report(
    cell: &Arc<crate::kube::KubeRuntimeCell>,
    control: &odin_huginn::kube::KubeControl,
    runtime: &Arc<odin_hermes::runtime::HermesRuntime>,
    seat: &SeatId,
    pod: &odin_omp::host_tools::delegation::SettledPod,
) -> ReportSettlement {
    let reconciler = control.reconciler();
    let (run, launch) = match reconciler.operation_launch(&pod.operation) {
        Ok(Some(found)) => found,
        Ok(None) => {
            return ReportSettlement::Delivered {
                note: String::new(),
                files: String::new(),
            }
        }
        Err(error) => {
            return ReportSettlement::Pending {
                note: format!("Its saved files could not be found: {error}"),
                follow_up: None,
            }
        }
    };
    let deadline = launch.deadline_seconds;
    let Some(plan) = launch.workload else {
        return ReportSettlement::Delivered {
            note: String::new(),
            files: String::new(),
        };
    };
    // Salvage needs the carrier to be verifiably gone, not a transient
    // exec failure: read the run's workload state from the reconciler.
    // A missing Job, a terminal state or a Job being deleted is gone; an
    // unreadable answer leaves the pod treated as alive.
    let (pod_gone, started_at, node) = match reconciler.observe_run(&run).await {
        Ok(Some(observation)) => (
            matches!(
                observation.workload.state,
                odin_domain::huginn::KubeWorkloadState::Succeeded
                    | odin_domain::huginn::KubeWorkloadState::Failed
                    | odin_domain::huginn::KubeWorkloadState::Terminating
            ),
            observation.workload.started_at,
            observation.workload.node_id.map(|node| node.to_string()),
        ),
        Ok(None) => (true, None, None),
        Err(_) => (false, None, None),
    };
    let now = time::OffsetDateTime::now_utc();
    let wall = Wall {
        now: now.unix_timestamp(),
        left: deadline
            .zip(started_at)
            .map(|(deadline, started)| i64::from(deadline) - (now - started).whole_seconds()),
        cycle: review_cycle(cell, &plan.profile),
    };
    // A gone carrier's export is read back from the node that retains it.
    let retained = match plan.report_pdf {
        true => {
            let node = remember_node(runtime, &run, node);
            let records = records_path(runtime, &run);
            match pod_gone && !copies_are_durable(&records) {
                true => Some(
                    gone_export(&records, wall, || {
                        read_retained_export(cell, &run, &plan.export_host_folder, node)
                    })
                    .await,
                ),
                false => None,
            }
        }
        false => None,
    };
    let target = PodTarget {
        run,
        export_dir: plan.export_mount,
        network_transport: plan.transport,
    };
    let session = pod.session;
    let answer = pod.answer.clone();
    let failed = pod.failed;
    let failure = pod
        .failure
        .as_ref()
        .map(|failure| format!("{}: {}", failure.code, failure.message));
    let answer_key = pod.key.clone();
    let seat = seat.clone();
    let runtime = Arc::clone(runtime);
    let cell = Arc::clone(cell);
    let run = ReportRun {
        runtime,
        seat,
        session,
        target,
        owes_pdf: plan.report_pdf,
        company: plan.company,
        downloads_root: plan.report_downloads_root,
        wall,
        render: render_with_docs,
    };
    let finished = tokio::task::spawn_blocking(move || {
        finish_export(
            &cell,
            &run,
            &answer,
            &answer_key,
            failed,
            failure.as_deref(),
            retained,
        )
    })
    .await;
    match finished {
        Ok(done) => done,
        Err(error) => ReportSettlement::Pending {
            note: format!("The report contract could not be completed: {error}"),
            follow_up: None,
        },
    }
}

struct ReportRun {
    runtime: Arc<odin_hermes::runtime::HermesRuntime>,
    seat: SeatId,
    session: LiveSessionId,
    target: PodTarget,
    owes_pdf: bool,
    company: Option<String>,
    downloads_root: Option<String>,
    wall: Wall,
    render: Renderer,
}

/// Renders the report source: the one place docs.render runs. `meta` is the footer's run facts
/// and `files` the export the source's figures come from.
type Renderer = fn(&ReportRun, &str, &Value, &[ExportedFile]) -> Result<Rendered, RenderError>;

/// A compiled report, before anything is written for it.
struct Rendered {
    pdf: Vec<u8>,
    page_count: u32,
    warnings: Vec<String>,
    /// Digest of the Typst source and the figures it embeds.
    content: String,
}

/// The pod's clock at one settlement pass.
#[derive(Clone, Copy, Debug)]
struct Wall {
    /// Unix seconds.
    now: i64,
    /// Seconds left of the pod's deadline; `None` when its start or deadline is unknown.
    left: Option<i64>,
    /// The pod's review cycle in seconds: its profile's monitoring cadence.
    cycle: Option<i64>,
}

/// The pod's review cycle, declared as its profile's monitoring cadence.
fn review_cycle(cell: &crate::kube::KubeRuntimeCell, profile: &str) -> Option<i64> {
    let label = odin_kube::job::bounded_label_value(profile);
    cell.monitored_workloads()
        .into_iter()
        .find(|(declared, _)| *declared == label)
        .map(|(_, monitoring)| i64::from(monitoring.cadence_seconds.get()))
}

/// `retained` is the pod's export when its carrier is verifiably gone.
fn finish_export(
    cell: &Arc<crate::kube::KubeRuntimeCell>,
    run: &ReportRun,
    answer: &str,
    answer_key: &str,
    failed: bool,
    failure: Option<&str>,
    retained: Option<GoneExport>,
) -> ReportSettlement {
    let records = record_dir(run);
    if copies_are_durable(&records) {
        return ReportSettlement::Delivered {
            note: delivery_note(&records)
                .unwrap_or_else(|| "The report copies are already durable.".to_owned()),
            files: String::new(),
        };
    }
    let exec = crate::kube::KubePodWorkerExec::new(Some(Arc::clone(cell)));
    if !run.owes_pdf {
        return ReportSettlement::Delivered {
            note: String::new(),
            files: share_collected(&exec, &run.target, &run.runtime, &run.seat),
        };
    }
    if let Some(retained) = retained {
        return finish_gone(run, answer, failed, retained);
    }
    let files = match collect_exports(&exec, &run.target, MAX_REPORT_FILE_BYTES) {
        Ok(files) => files,
        Err(error) => {
            return ReportSettlement::Pending {
                note: format!("Its saved files could not be brought back: {error}"),
                follow_up: None,
            }
        }
    };
    finish_collected(&exec, run, files, answer, answer_key, failed, failure)
}

fn finish_collected(
    exec: &dyn PodWorkerExec,
    run: &ReportRun,
    files: Vec<ExportedFile>,
    answer: &str,
    answer_key: &str,
    failed: bool,
    failure: Option<&str>,
) -> ReportSettlement {
    let records = record_dir(run);
    if copies_are_durable(&records) {
        let note = delivery_note(&records)
            .unwrap_or_else(|| "The report copies are already durable.".to_owned());
        let stem = report_stem(
            run,
            &authoritative_body(&files, answer),
            &read_state(&records).captured_at,
        )
        .ok();
        return ReportSettlement::Delivered {
            note,
            files: share_files(&files, &run.runtime, &run.seat, stem.as_deref()),
        };
    }
    let contract = report_contract(
        &files,
        &run.target.export_dir,
        failed,
        answer.trim().is_empty(),
    );
    if let ReportCompletion::Unmet(note) = contract {
        return ReportSettlement::Failed { note };
    }
    let mut state = read_state(&records);
    let seen = Undone::of(answer, failed);
    state.undone.name_receipts(&seen.receipts);
    if !seen.items.is_empty() {
        match resume_decision(run.wall, &state, &seen.items) {
            Resume::Now => return resume_with_unmet(&records, &mut state, run.wall, &seen.items),
            Resume::Wait => {
                return ReportSettlement::Pending {
                    note: "The pod's unmet items go back to it at the next review cycle".to_owned(),
                    follow_up: None,
                }
            }
            Resume::Spent => {}
        }
    }
    // The pod is not sent back. What it left undone goes into the note the launching seat reads,
    // and stays there through the review's later answers, which do not list it.
    if !seen.items.is_empty() {
        state.undone.items = seen.items;
    }
    let mut undone = state.undone.clone();
    let body = authoritative_body(&files, answer);
    let (subject, subject_source) = report_subject(run, &body);
    if let Err(error) = write_bytes(
        exec,
        &run.target.run,
        &absolute_export(&run.target.export_dir, COMPANION),
        body.as_bytes(),
    ) {
        return ReportSettlement::Pending {
            note: format!("The companion markdown was not written: {error}"),
            follow_up: None,
        };
    }
    let mut files = files;
    let identity = match ensure_render(exec, run, &body, &contract, &state, &mut files, false) {
        Ok(identity) => identity,
        Err(RenderError::Other(reason)) => {
            return ReportSettlement::Pending {
                note: reason,
                follow_up: None,
            }
        }
        // A source that does not compile is a round of the review loop: the pod is asked to
        // fix it, and past the bound the authority renders the markdown itself.
        Err(RenderError::Compile(reason)) => {
            state.renders = state.renders.saturating_add(1);
            state.dispatched_answer = None;
            if state.renders <= MAX_RERENDERS {
                return fix_source(&records, &state, reason);
            }
            undone.items.push(format!(
                "layout: {reason}; the pod was asked {MAX_RERENDERS} times to fix it, so the \
                 report is rendered from report.md instead of its own Typst source"
            ));
            match ensure_render(exec, run, &body, &contract, &state, &mut files, true) {
                Ok(identity) => identity,
                Err(error) => {
                    return ReportSettlement::Pending {
                        note: error.into_reason(),
                        follow_up: None,
                    }
                }
            }
        }
    };
    if state.pdf != identity.pdf
        || state.bytes != identity.bytes
        || state.captured_at != identity.captured_at
        || state.content != identity.content
    {
        if state.dispatched_answer.is_some() {
            state.renders = state.renders.saturating_add(1);
        }
        state.pdf = identity.pdf.clone();
        state.bytes = identity.bytes;
        state.captured_at = identity.captured_at.clone();
        state.content = identity.content.clone();
        state.offered = 0;
        state.confirmed = 0;
        state.page_count = 0;
        state.dispatched_answer = None;
        if let Err(error) = write_copies(&records, &[]) {
            return ReportSettlement::Pending {
                note: format!("The changed report's copy state was not reset: {error}"),
                follow_up: None,
            };
        }
    }
    // The exact render is saved outside the pod from the first pass that
    // holds it, so a pod lost mid-settlement degrades to this saved report
    // instead of a total loss.
    if let Err(error) = persist_report(run, &files, &identity, &body) {
        return ReportSettlement::Pending {
            note: format!("The report was not saved outside its pod: {error}"),
            follow_up: None,
        };
    }
    let finish = |state: &SettlementState, undone: &Undone| {
        copy_and_finish(
            exec,
            run,
            &subject,
            subject_source,
            &identity,
            state,
            undone,
        )
    };
    if state.renders > MAX_RERENDERS {
        undone.items.push(format!(
            "page review: the report was re-rendered {} times after its review began, so the \
             latest render is accepted without another review of its pages",
            state.renders
        ));
        // Recorded as the render under review, so a copy that has to be retried finds it again
        // instead of rendering a new one under copies already made.
        state
            .dispatched_answer
            .get_or_insert_with(|| answer_key.to_owned());
        return finish(&state, &undone);
    }
    let source = export_text(&files, file_name(&identity.source)).unwrap_or_default();
    let gaps = content_gaps(&body, &source, &files, Some(identity.pdf_relative.as_str()));
    // A review turn that failed (a provider fault, a context refusal) is answered by nothing:
    // the pages it was shown stay unreviewed and the latest render is accepted.
    if failed && state.dispatched_answer.is_some() {
        undone.items.push(format!(
            "page review: the review turn failed ({}), so the latest render is accepted without \
             it",
            failure.unwrap_or("no error event was journaled")
        ));
        return finish(&state, &undone);
    }
    // Only a later turn that ended without failure accepts pages.
    let advanced = !failed
        && state
            .dispatched_answer
            .as_deref()
            .is_some_and(|previous| previous != answer_key);
    if advanced {
        state.confirmed = state.offered;
        if !gaps.is_empty() {
            state.content_asks = state.content_asks.saturating_add(1);
        }
    }
    if gaps.is_empty() && state.page_count > 0 && state.confirmed == state.page_count {
        return finish(&state, &undone);
    }
    if !gaps.is_empty() && state.content_asks >= MAX_CONTENT_ASKS && advanced {
        undone.items.extend(gaps.iter().map(|gap| {
            format!(
                "report content: {gap} (the pod was asked {} times to complete it and did not)",
                state.content_asks
            )
        }));
        return finish(&state, &undone);
    }
    let pages = match page_images(exec, &run.target.run, &identity.pdf_absolute) {
        Ok(pages) => pages,
        Err(reason) => {
            return ReportSettlement::Pending {
                note: reason,
                follow_up: None,
            }
        }
    };
    state.page_count = pages.len();
    let start = state.confirmed;
    let batch = next_batch(&pages, start);
    state.offered = start + batch.len();
    state.dispatched_answer = Some(answer_key.to_owned());
    if let Err(error) = write_state(&records, &state) {
        return ReportSettlement::Pending {
            note: format!("The review state was not recorded: {error}"),
            follow_up: None,
        };
    }
    let follow_up = ReviewTurn {
        text: review_text(&identity, &gaps, &files, start, &batch, pages.len()),
        images: batch
            .into_iter()
            .map(|page| ("image/jpeg".to_owned(), page.data))
            .collect(),
    };
    ReportSettlement::Pending {
        note: format!(
            "Waiting for the model to review {} page(s) of {} ({})",
            follow_up.images.len(),
            identity.pdf_absolute,
            identity.captured_at
        ),
        follow_up: Some(follow_up),
    }
}

/// Sends a source that did not compile back to the pod, as one round of the review loop.
fn fix_source(records: &Path, state: &SettlementState, reason: String) -> ReportSettlement {
    if let Err(error) = write_state(records, state) {
        return ReportSettlement::Pending {
            note: format!("The render state was not recorded: {error}"),
            follow_up: None,
        };
    }
    ReportSettlement::Pending {
        note: format!("Asking the pod to fix its report source: {reason}"),
        follow_up: Some(ReviewTurn {
            text: format!(
                "docs.render could not compile your report source: {reason}. report.source \
                 writes a correction to /export/report.typ; reply when it is fixed so the \
                 authority renders again."
            ),
            images: Vec::new(),
        }),
    }
}

#[derive(Default)]
struct SettlementState {
    pdf: String,
    bytes: u64,
    captured_at: String,
    content: String,
    offered: usize,
    confirmed: usize,
    page_count: usize,
    dispatched_answer: Option<String>,
    content_asks: u8,
    /// Re-renders after the review began, and source compile failures sent back to the pod.
    renders: u8,
    /// When unmet launch-input items last went back to the pod (unix seconds; 0 never), how many
    /// times they have, and which items the last time.
    resumed_at: i64,
    resumes: u8,
    resumed_unmet: String,
    /// What the pod's answer left undone when it stopped being sent back.
    undone: Undone,
    /// The node the pod's Job last ran on, where its export stays once the Job is gone.
    node: String,
    /// Failed reads of a gone pod's export, when the last was (unix seconds) and why.
    export_failures: u8,
    export_failed_at: i64,
    export_failure: String,
}

/// Why a render did not happen.
enum RenderError {
    /// The pod's Typst source does not compile: the pod can fix it.
    Compile(String),
    /// Anything else: the carrier, the stats or the renderer's own tools.
    Other(String),
}

impl RenderError {
    fn into_reason(self) -> String {
        match self {
            Self::Compile(reason) | Self::Other(reason) => reason,
        }
    }
}

impl From<String> for RenderError {
    fn from(reason: String) -> Self {
        Self::Other(reason)
    }
}

/// Renders the report unless the export already holds the render under review. `files` is
/// refreshed after a render. `from_markdown` renders `body` itself, ignoring the pod's source.
fn ensure_render(
    exec: &dyn PodWorkerExec,
    run: &ReportRun,
    body: &str,
    contract: &ReportCompletion,
    state: &SettlementState,
    files: &mut Vec<ExportedFile>,
    from_markdown: bool,
) -> Result<ReportIdentity, RenderError> {
    if let Some(identity) = report_identity(files, &run.target.export_dir)
        .ok()
        .flatten()
    {
        if reviewed_bytes_match(files, &identity, state) {
            return Ok(identity);
        }
    }
    let owner = odin_domain::SessionId::new(run.session.to_string())
        .map_err(|error| format!("the session id could not be named ({error})"))?;
    let stats_path = run
        .runtime
        .complete_run_stats(&owner)
        .map_err(|error| format!("the final measured run stats were not written: {error}"))?;
    let stats = read_text(
        exec,
        &run.target.run,
        &absolute_export(&run.target.export_dir, "run-stats.json"),
        64 * 1024,
    )?;
    let stats: Value = serde_json::from_str(&stats)
        .map_err(|error| format!("{stats_path} is not JSON: {error}"))?;
    let captured_at = stats["capturedAt"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("{stats_path} has no capturedAt timestamp"))?;
    let source = match contract {
        _ if from_markdown => complete_fallback_source(body, files)?,
        ReportCompletion::Met(identity)
            if identity.body != odin_domain::Digest::hash(body.as_bytes()).to_string() =>
        {
            complete_fallback_source(body, files)?
        }
        ReportCompletion::Met(identity) => {
            read_text(exec, &run.target.run, &identity.source, MAX_SOURCE_BYTES)?
        }
        ReportCompletion::Owed => match read_named(files, "/export/report.typ") {
            Some(source) if !source.trim().is_empty() => source,
            _ => complete_fallback_source(body, files)?,
        },
        ReportCompletion::Unmet(_) => return Err("the report contract is unmet".to_owned().into()),
    };
    let rendered = (run.render)(run, &source, &footer_meta(&stats), files)?;
    write_render(exec, run, &rendered, &source, body, &captured_at)?;
    *files = collect_exports(exec, &run.target, MAX_REPORT_FILE_BYTES)?;
    let identity = report_identity(files, &run.target.export_dir)?
        .ok_or_else(|| "the re-render wrote no validated receipt".to_owned())?;
    if identity.captured_at != captured_at {
        return Err(format!(
            "{} was rendered at {}, not from the measured stats at {captured_at}",
            identity.pdf_absolute, identity.captured_at
        )
        .into());
    }
    Ok(identity)
}

const MAX_SOURCE_BYTES: usize = 256 * 1024;
const PDF_NAME: &str = "report.pdf";

fn render_with_docs(
    run: &ReportRun,
    source: &str,
    meta: &Value,
    files: &[ExportedFile],
) -> Result<Rendered, RenderError> {
    let ctx = run.runtime.workflow_context()?;
    let call = odin_workflows::Call {
        key: format!("research-{}", run.target.run.as_str()),
        seat: run.seat.to_string(),
        tz: run.runtime.owner_time_zone(),
        files: Vec::new(),
    };
    let job = ctx
        .scratch(&call)
        .map_err(|error| format!("the research job folder was not created: {error}"))?;
    let compiled = compile_source(source);
    let staged = stage_figures(&job, &compiled, files)?;
    let content = content_digest(&compiled, &staged);
    let rendered =
        odin_workflows::docs::render::research(ctx, &job, &compiled, true, None, meta, PDF_NAME)
            .map_err(|error| {
                let reason = format!("docs.render did not compile the report: {error}");
                match error.kind == odin_workflows::FailureKind::Arguments {
                    true => RenderError::Compile(reason),
                    false => RenderError::Other(reason),
                }
            })?;
    let pdf = std::fs::read(&rendered.pdf)
        .map_err(|error| format!("the rendered PDF could not be read: {error}"))?;
    if pdf.is_empty() {
        return Err("docs.render wrote an empty PDF".to_owned().into());
    }
    let _ = ctx.release(&call);
    Ok(Rendered {
        pdf,
        page_count: rendered.page_count,
        warnings: rendered.warnings,
        content,
    })
}

/// Writes a render into the pod's export with the receipt the contract validates.
fn write_render(
    exec: &dyn PodWorkerExec,
    run: &ReportRun,
    rendered: &Rendered,
    source: &str,
    body: &str,
    captured_at: &str,
) -> Result<(), String> {
    let output = absolute_export(&run.target.export_dir, PDF_NAME);
    write_bytes(exec, &run.target.run, &output, &rendered.pdf)?;
    let source_path = absolute_export(&run.target.export_dir, "report.typ");
    write_bytes(exec, &run.target.run, &source_path, source.as_bytes())?;
    let receipt = json!({
        "source": source_path,
        "output": output,
        "page_count": rendered.page_count,
        "bytes": rendered.pdf.len() as u64,
        "pdf": odin_domain::Digest::hash(&rendered.pdf).to_string(),
        "capturedAt": captured_at,
        "content": rendered.content,
        "body": odin_domain::Digest::hash(body.as_bytes()).to_string(),
        "template": "research",
        "warnings": rendered.warnings,
    });
    let receipt_bytes = serde_json::to_vec_pretty(&receipt).map_err(|error| error.to_string())?;
    write_bytes(
        exec,
        &run.target.run,
        &absolute_export(&run.target.export_dir, RENDER),
        &receipt_bytes,
    )
}

fn reviewed_bytes_match(
    files: &[ExportedFile],
    identity: &ReportIdentity,
    state: &SettlementState,
) -> bool {
    if state.dispatched_answer.is_none()
        || state.pdf != identity.pdf
        || state.bytes != identity.bytes
        || state.captured_at != identity.captured_at
        || state.content != identity.content
    {
        return false;
    }
    let Some(pdf) = file_bytes(files, &identity.pdf_relative) else {
        return false;
    };
    if pdf.len() as u64 != identity.bytes
        || odin_domain::Digest::hash(pdf).to_string() != identity.pdf
    {
        return false;
    }
    let Some(saved) = read_named(files, &identity.source) else {
        return false;
    };
    if odin_domain::Digest::hash(body_of(files).as_bytes()).to_string() != identity.body {
        return false;
    }
    let compiled = compile_source(&saved);
    let figures = match staged_figure_bytes(&compiled, files) {
        Ok(figures) => figures,
        Err(_) => return false,
    };
    content_digest(&compiled, &figures) == identity.content
}

fn file_bytes<'a>(files: &'a [ExportedFile], relative: &str) -> Option<&'a [u8]> {
    files
        .iter()
        .find(|file| file.path == relative)
        .and_then(|file| file.content.as_ref().ok())
        .map(Vec::as_slice)
}

fn read_named(files: &[ExportedFile], path: &str) -> Option<String> {
    let relative = path.strip_prefix("/export/").unwrap_or(path);
    String::from_utf8(file_bytes(files, relative)?.to_vec()).ok()
}

/// Paths the compiler sees. The saved source keeps `/export/` so history is unchanged.
fn compile_source(source: &str) -> String {
    source.replace("\"/export/", "\"")
}

fn body_of(files: &[ExportedFile]) -> String {
    read_named(files, "report.md").unwrap_or_default()
}

fn staged_figure_bytes<'a>(
    source: &str,
    files: &'a [ExportedFile],
) -> Result<Vec<(&'a str, &'a [u8])>, String> {
    let mut staged = Vec::new();
    for file in embedded_figures(source, files) {
        let bytes = file.content.as_ref().map_err(|error| {
            format!(
                "{} was named by the report but could not be read: {error}",
                file.path
            )
        })?;
        if !super::report_completion::safe_relative(&file.path) {
            return Err(format!("refusing to stage figure {}", file.path));
        }
        staged.push((file.path.as_str(), bytes.as_slice()));
    }
    staged.sort_by(|left, right| left.0.cmp(right.0));
    Ok(staged)
}
fn stage_figures<'a>(
    job: &std::path::Path,
    source: &str,
    files: &'a [ExportedFile],
) -> Result<Vec<(&'a str, &'a [u8])>, String> {
    let staged = staged_figure_bytes(source, files)?;
    for (path, bytes) in &staged {
        let dest = job.join(path);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("could not stage {path}: {error}"))?;
        }
        std::fs::write(&dest, bytes).map_err(|error| format!("could not stage {path}: {error}"))?;
    }
    Ok(staged)
}

fn content_digest(source: &str, figures: &[(&str, &[u8])]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(source.len() as u64).to_le_bytes());
    hasher.update(source.as_bytes());
    for (path, bytes) in figures {
        hasher.update(&(path.len() as u64).to_le_bytes());
        hasher.update(path.as_bytes());
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    odin_domain::Digest::new(*hasher.finalize().as_bytes()).to_string()
}

/// The report footer's run facts, from the measured stats.
fn footer_meta(stats: &Value) -> Value {
    json!({
        "model": meta_text(stats, "servedModel"),
        "wall_time": meta_number(stats, "wallSeconds", "s"),
        "tool_calls": meta_number(stats, "toolCalls", ""),
        "sites": meta_number(stats, "websites", ""),
        "cost": meta_cost(stats),
    })
}

fn field_unavailable(stats: &Value, field: &str) -> bool {
    stats[field].is_null()
        || stats["unavailable"]
            .as_array()
            .is_some_and(|names| names.iter().any(|name| name.as_str() == Some(field)))
}

fn meta_text(stats: &Value, field: &str) -> String {
    if field_unavailable(stats, field) {
        return "unavailable".to_owned();
    }
    stats[field]
        .as_str()
        .filter(|text| !text.is_empty())
        .unwrap_or("unavailable")
        .to_owned()
}

fn meta_number(stats: &Value, field: &str, suffix: &str) -> String {
    if field_unavailable(stats, field) {
        return "unavailable".to_owned();
    }
    match stats[field].as_u64() {
        Some(value) => format!("{value}{suffix}"),
        None => "unavailable".to_owned(),
    }
}

fn meta_cost(stats: &Value) -> String {
    if field_unavailable(stats, "listPriceUsd") {
        return "unavailable".to_owned();
    }
    let Some(price) = stats["listPriceUsd"].as_f64() else {
        return "unavailable".to_owned();
    };
    let dollars = format!("${price:.2} list price");
    if stats["subscriptionIncluded"] == true {
        format!("{dollars} (included, not billed)")
    } else {
        dollars
    }
}

struct PageImage {
    data: String,
}

fn page_images(exec: &dyn PodWorkerExec, run: &RunId, pdf: &str) -> Result<Vec<PageImage>, String> {
    let pages_dir = absolute_export("/export", PAGES_DIR);
    clear_foreign_review(exec, run)?;
    run_tool(
        exec,
        run,
        &["/bin/odin-pages", pdf, &pages_dir],
        None,
        "rasterizing the final pages",
    )?;
    let receipt = read_text(
        exec,
        run,
        &absolute_export("/export", PAGES_RECEIPT),
        1024 * 1024,
    )?;
    let parsed: Value = serde_json::from_str(&receipt)
        .map_err(|error| format!("the page receipt is not JSON: {error}"))?;
    let files = parsed["files"]
        .as_array()
        .ok_or_else(|| "the page receipt lists no files".to_owned())?;
    if files.is_empty() {
        return Err(format!("{pdf} produced no pages"));
    }
    let mut images = Vec::new();
    for file in files {
        let path = file["path"]
            .as_str()
            .ok_or_else(|| "a page receipt entry has no path".to_owned())?;
        let bytes = file["bytes"].as_u64().unwrap_or(0);
        if bytes == 0 || bytes > PAGE_VIEW_MAX_BYTES {
            return Err(format!(
                "{path} is {bytes} bytes, outside the page view bound of {PAGE_VIEW_MAX_BYTES}"
            ));
        }
        let tail = usize::try_from(bytes).map_err(|error| error.to_string())?;
        let output = run_tool_output(
            exec,
            run,
            &["/bin/odin-view", path],
            None,
            tail,
            "viewing a final page",
        )?;
        if output.stdout_bytes != bytes || output.stdout_tail.len() != tail {
            return Err(format!(
                "{path}: viewed {} of {bytes} bytes",
                output.stdout_bytes
            ));
        }
        let image = odin_omp::host_tools::page_view::page_image(&output.stdout_tail)
            .map_err(|reason| format!("{path}: {reason}"))?;
        let data = image["data"]
            .as_str()
            .ok_or_else(|| format!("{path}: the page image has no data"))?
            .to_owned();
        images.push(PageImage { data });
    }
    Ok(images)
}

fn clear_foreign_review(exec: &dyn PodWorkerExec, run: &RunId) -> Result<(), String> {
    let path = absolute_export("/export", "report-review.json");
    let Ok(text) = read_text(exec, run, &path, 64 * 1024) else {
        return Ok(());
    };
    let keep = serde_json::from_str::<Value>(&text)
        .ok()
        .and_then(|parsed| {
            parsed["reviewer"]
                .as_str()
                .map(|reviewer| reviewer == "pod")
        })
        .unwrap_or(false);
    if keep {
        return Ok(());
    }
    run_tool(
        exec,
        run,
        &["/bin/rm", "-f", &path],
        None,
        "clearing a foreign page receipt",
    )
}

fn next_batch(pages: &[PageImage], start: usize) -> Vec<PageImage> {
    let mut batch = Vec::new();
    let mut bytes = 0usize;
    for page in pages.iter().skip(start) {
        if !batch.is_empty() && bytes.saturating_add(page.data.len()) > REVIEW_BATCH_BYTES {
            break;
        }
        bytes = bytes.saturating_add(page.data.len());
        batch.push(PageImage {
            data: page.data.clone(),
        });
        if bytes >= REVIEW_BATCH_BYTES {
            break;
        }
    }
    batch
}

fn review_text(
    identity: &ReportIdentity,
    gaps: &[String],
    files: &[ExportedFile],
    start: usize,
    batch: &[PageImage],
    total: usize,
) -> String {
    let evidence: Vec<&str> = files
        .iter()
        .filter(|file| file.bytes > 0)
        .map(|file| file.path.as_str())
        .collect();
    let mut text = format!(
        "docs.render (template research) stamped {pdf} ({bytes} bytes, captured {captured}) from \
         the measured run stats. Pages {}-{} of {total} are attached as images of that exact \
         render. The companion markdown is /export/report.md and the Typst source is {source}. \
         report.source writes a correction to either file. A change to report.md is rendered again \
         from that markdown. A change to the Typst source is rendered as that source. A text reply \
         that leaves both files and this PDF's bytes unchanged accepts the attached pages.",
        start + 1,
        start + batch.len(),
        pdf = identity.pdf_absolute,
        bytes = identity.bytes,
        captured = identity.captured_at,
        source = identity.source,
    );
    if !gaps.is_empty() {
        text.push_str(&format!(
            " Complete these from the export before the report is finished: {}.",
            gaps.join("; ")
        ));
    }
    text.push_str(&format!(" Export files: {}.", evidence.join(", ")));
    text
}

/// Copies the accepted render and delivers it. `undone` names what the report leaves
/// unfinished: with items in it the report is delivered as partial work and says so.
fn copy_and_finish(
    exec: &dyn PodWorkerExec,
    run: &ReportRun,
    subject: &str,
    subject_source: &str,
    identity: &ReportIdentity,
    state: &SettlementState,
    undone: &Undone,
) -> ReportSettlement {
    let files = match collect_exports(exec, &run.target, MAX_REPORT_FILE_BYTES) {
        Ok(files) => files,
        Err(error) => {
            return ReportSettlement::Pending {
                note: format!("The finished files could not be brought back for the copy: {error}"),
                follow_up: None,
            }
        }
    };
    if let Err(error) = write_state(&record_dir(run), state) {
        return ReportSettlement::Pending {
            note: format!("The accepted review state was not recorded: {error}"),
            follow_up: None,
        };
    }
    finish_copies(run, &files, subject, subject_source, identity, undone)
}

/// Saves `files` to their copy destinations and, once every copy is durable, records the
/// delivery and hands the launching seat the files.
fn finish_copies(
    run: &ReportRun,
    files: &[ExportedFile],
    subject: &str,
    subject_source: &str,
    identity: &ReportIdentity,
    undone: &Undone,
) -> ReportSettlement {
    let stem = match report_stem(run, &body_of(files), &identity.captured_at) {
        Ok(stem) => stem,
        Err(error) => {
            return ReportSettlement::Pending {
                note: format!("The report's file name could not be made: {error}"),
                follow_up: None,
            }
        }
    };
    let (note, durable) = copy_destinations(run, subject, subject_source, files, &stem);
    if !durable {
        return ReportSettlement::Pending {
            note,
            follow_up: None,
        };
    }
    let delivered = match undone.items.is_empty() {
        true => format!(
            "The report contract is met. {pdf} ({bytes} bytes, captured {captured}) was accepted \
             after the model saw all {pages} page(s) of that exact render. The subject folder \
             {subject} comes from {subject_source}.{unmet}\n\n{note}",
            pdf = identity.pdf_absolute,
            bytes = identity.bytes,
            captured = identity.captured_at,
            pages = identity.page_count,
            unmet = unmet_note(undone),
        ),
        false => format!(
            "The report is settled as partial work. {pdf} ({bytes} bytes, captured {captured}) \
             is the latest render and is delivered as it stands. The subject folder {subject} \
             comes from {subject_source}.{unmet}\n\n{note}",
            pdf = identity.pdf_absolute,
            bytes = identity.bytes,
            captured = identity.captured_at,
            unmet = unmet_note(undone),
        ),
    };
    if let Err(error) = write_record(
        &record_dir(run),
        DELIVERED,
        &json!({"note": delivered, "status": "delivered"}),
    ) {
        return ReportSettlement::Pending {
            note: format!("The delivery state was not recorded: {error}"),
            follow_up: None,
        };
    }
    ReportSettlement::Delivered {
        note: delivered,
        files: share_files(files, &run.runtime, &run.seat, Some(&stem)),
    }
}

fn read_state(directory: &Path) -> SettlementState {
    let Some(parsed) = read_record(directory, SETTLEMENT) else {
        return SettlementState::default();
    };
    SettlementState {
        pdf: parsed["pdf"].as_str().unwrap_or_default().to_owned(),
        bytes: parsed["bytes"].as_u64().unwrap_or(0),
        captured_at: parsed["capturedAt"].as_str().unwrap_or_default().to_owned(),
        content: parsed["content"].as_str().unwrap_or_default().to_owned(),
        offered: parsed["offered"].as_u64().unwrap_or(0) as usize,
        confirmed: parsed["confirmed"].as_u64().unwrap_or(0) as usize,
        page_count: parsed["pageCount"].as_u64().unwrap_or(0) as usize,
        dispatched_answer: parsed["dispatchedAnswer"].as_str().map(str::to_owned),
        content_asks: parsed["contentAsks"].as_u64().unwrap_or(0) as u8,
        renders: parsed["renders"].as_u64().unwrap_or(0) as u8,
        resumed_at: parsed["resumedAt"].as_i64().unwrap_or(0),
        resumes: parsed["resumes"].as_u64().unwrap_or(0) as u8,
        resumed_unmet: parsed["resumedUnmet"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        undone: Undone {
            items: strings(&parsed["undone"]["items"]),
            receipts: strings(&parsed["undone"]["receipts"]),
        },
        node: parsed["node"].as_str().unwrap_or_default().to_owned(),
        export_failures: parsed["exportFailures"].as_u64().unwrap_or(0) as u8,
        export_failed_at: parsed["exportFailedAt"].as_i64().unwrap_or(0),
        export_failure: parsed["exportFailure"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
    }
}

fn strings(list: &Value) -> Vec<String> {
    list.as_array()
        .map(|list| {
            list.iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn write_state(directory: &Path, state: &SettlementState) -> Result<(), String> {
    write_record(
        directory,
        SETTLEMENT,
        &json!({
            "pdf": state.pdf,
            "bytes": state.bytes,
            "capturedAt": state.captured_at,
            "content": state.content,
            "offered": state.offered,
            "confirmed": state.confirmed,
            "pageCount": state.page_count,
            "dispatchedAnswer": state.dispatched_answer,
            "contentAsks": state.content_asks,
            "renders": state.renders,
            "resumedAt": state.resumed_at,
            "resumes": state.resumes,
            "resumedUnmet": state.resumed_unmet,
            "undone": {"items": state.undone.items, "receipts": state.undone.receipts},
            "node": state.node,
            "exportFailures": state.export_failures,
            "exportFailedAt": state.export_failed_at,
            "exportFailure": state.export_failure,
        }),
    )
}

fn record_dir(run: &ReportRun) -> PathBuf {
    records_path(&run.runtime, &run.target.run)
}

fn records_path(runtime: &odin_hermes::runtime::HermesRuntime, run: &RunId) -> PathBuf {
    runtime
        .settings()
        .state_dir
        .join("reports")
        .join(run.as_str())
}

fn read_record(directory: &Path, name: &str) -> Option<Value> {
    serde_json::from_slice(&std::fs::read(directory.join(name)).ok()?).ok()
}

fn write_record(directory: &Path, name: &str, value: &Value) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    write_file(directory, name, &bytes)
}

fn write_file(directory: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt as _;

    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)
        .map_err(|error| format!("could not create report state: {error}"))?;
    odin_cli::authority_provision::write_private_atomic(&directory.join(name), bytes)
}

fn authoritative_body(files: &[ExportedFile], answer: &str) -> String {
    if let Some(text) = read_named(files, COMPANION) {
        if !text.trim().is_empty() {
            return text;
        }
    }
    answer.to_owned()
}

fn export_text(files: &[ExportedFile], name: &str) -> Option<String> {
    let file = find_named(files, file_name(name))?;
    let bytes = file.content.as_ref().ok()?;
    String::from_utf8(bytes.clone()).ok()
}

fn share_collected(
    exec: &dyn PodWorkerExec,
    target: &PodTarget,
    runtime: &odin_hermes::runtime::HermesRuntime,
    seat: &SeatId,
) -> String {
    match collect_exports(exec, target, MAX_REPORT_FILE_BYTES) {
        Ok(files) if files.is_empty() => String::new(),
        Ok(files) => share_files(&files, runtime, seat, None),
        Err(error) => format!("Its saved files could not be brought back: {error}\n"),
    }
}

/// `stem` names the report's own PDF and companion as the owner will see
/// them; the files are listed under those names.
fn share_files(
    files: &[ExportedFile],
    runtime: &odin_hermes::runtime::HermesRuntime,
    seat: &SeatId,
    stem: Option<&str>,
) -> String {
    let Some(route) = runtime.coding_route() else {
        return "Its saved files could not be shared: the artifact store is not composed.\n"
            .to_owned();
    };
    let scope = Scope {
        seat: Some(seat.clone()),
        ..Scope::default()
    };
    let lines: Vec<String> = files
        .iter()
        .map(|file| {
            let media_type = crate::coding_route::media_type_of(std::path::Path::new(&file.path));
            let shared = file
                .content
                .as_ref()
                .map_err(|error| error.clone())
                .and_then(|bytes| route.share_bytes(&scope, bytes, media_type));
            let shown = stem.map_or_else(
                || file.path.clone(),
                |stem| delivered_name(&file.path, stem),
            );
            match shared {
                Ok(artifact) => format!(
                    "- {shown} ({media_type}, {} bytes): artifact {artifact}",
                    file.bytes
                ),
                Err(reason) => format!(
                    "- {shown} ({} bytes): not brought back, {reason}",
                    file.bytes
                ),
            }
        })
        .collect();
    if lines.is_empty() {
        return String::new();
    }
    format!(
        "The files it saved, each an artifact for discord_file_send or files_save (the artifact, \
         and the name shown as file_name):\n{}\n",
        lines.join("\n")
    )
}

fn read_text(
    exec: &dyn PodWorkerExec,
    run: &RunId,
    path: &str,
    max: usize,
) -> Result<String, String> {
    let output = run_tool_output(
        exec,
        run,
        &["/bin/cat", path],
        None,
        max,
        &format!("reading {path}"),
    )?;
    if output.stdout_bytes > max as u64 || output.stdout_tail.len() != output.stdout_bytes as usize
    {
        return Err(format!("{path} is over the {max}-byte read"));
    }
    String::from_utf8(output.stdout_tail).map_err(|error| format!("{path} is not UTF-8: {error}"))
}

fn write_bytes(
    exec: &dyn PodWorkerExec,
    run: &RunId,
    path: &str,
    bytes: &[u8],
) -> Result<(), String> {
    if !allowed_write(path) {
        return Err(format!(
            "refusing to write outside the pod's report paths: {path}"
        ));
    }
    run_tool(
        exec,
        run,
        &[
            "/bin/dd",
            &format!("of={path}"),
            "conv=fsync",
            "status=none",
        ],
        Some(bytes),
        &format!("writing {path}"),
    )
}

fn allowed_write(path: &str) -> bool {
    (path.starts_with("/export/") || path.starts_with("/state/"))
        && !path.contains('\0')
        && !path.split('/').any(|part| matches!(part, "." | ".."))
}

fn fallback_subject(run: &RunId) -> String {
    let slug = sanitize_subject(run.as_str());
    let slug = if slug.is_empty() {
        "research".to_owned()
    } else {
        slug.chars().take(48).collect()
    };
    format!("research-{slug}")
}

fn sanitize_subject(value: &str) -> String {
    let mut out = String::new();
    let mut space = false;
    for character in value.chars() {
        let keep = character.is_ascii_alphanumeric() || matches!(character, '-' | '&' | '\'' | '.');
        if character.is_whitespace() {
            space = !out.is_empty();
            continue;
        }
        if !keep {
            continue;
        }
        if space {
            out.push(' ');
            space = false;
        }
        out.push(character);
        if out.chars().count() == 80 {
            break;
        }
    }
    out.trim().to_owned()
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::copies::{is_deliverable, CopyRecord};

    use super::*;

    /// When the run's stats were measured: the instant a report's file name takes its date from.
    const MEASURED: &str = "2026-11-02T18:00:00Z";

    /// Half an hour into a pod with an hour's deadline and a three-minute review cycle.
    fn wall() -> Wall {
        Wall {
            now: 1_800_000_000,
            left: Some(1_800),
            cycle: Some(180),
        }
    }

    #[tokio::test]
    async fn guest_delivery_records_cannot_release_a_report_without_a_pdf() {
        let root = tempfile::tempdir().expect("state");
        let runtime = odin_hermes::runtime::HermesRuntime::open(
            odin_hermes::config::HermesSettings::new(
                root.path().to_path_buf(),
                None,
                None,
                Vec::new(),
            )
            .expect("settings"),
            odin_hermes::runtime::HermesLedgers {
                conversation: odin_ledger::Ledger::open_in_memory().expect("conversation"),
                adapter: Arc::new(parking_lot::Mutex::new(
                    odin_ledger::Ledger::open_in_memory().expect("adapter"),
                )),
                purchase: Arc::new(std::sync::Mutex::new(
                    odin_ledger::Ledger::open_in_memory().expect("purchase"),
                )),
            },
            &std::collections::BTreeMap::new(),
            None,
            8192,
            std::collections::BTreeMap::new(),
            None,
        )
        .expect("runtime");
        let run = ReportRun {
            runtime,
            seat: SeatId::new("research").expect("seat"),
            session: LiveSessionId::parse("00000000-0000-4000-8000-00000000c0de").expect("session"),
            target: PodTarget {
                run: RunId::new("report-forged").expect("run"),
                export_dir: "/export".into(),
                network_transport: odin_registry::WorkloadTransport::Direct,
            },
            owes_pdf: true,
            company: Some("Example".into()),
            downloads_root: Some("downloads".into()),
            wall: wall(),
            render: render_with_docs,
        };
        let files = [
            (
                COPIES,
                json!({"files": [{
                    "name": "report.pdf", "downloads": "queued", "drive": "completed",
                    "saveId": "invented-save", "driveId": "invented-drive"
                }]}),
            ),
            (
                DELIVERED,
                json!({"note": "Already accepted and copied", "status": "delivered"}),
            ),
            (
                SETTLEMENT,
                json!({"offered": 9, "confirmed": 9, "pageCount": 9,
                "dispatchedAnswer": "old-answer"}),
            ),
        ]
        .into_iter()
        .map(|(path, value)| {
            let content = serde_json::to_vec(&value).expect("record");
            ExportedFile {
                path: path.into(),
                bytes: content.len() as u64,
                content: Ok(content),
            }
        })
        .collect();
        let exec = crate::kube::KubePodWorkerExec::new(None);
        let result = finish_collected(
            &exec,
            &run,
            files,
            "",
            "failed-answer",
            true,
            Some("failed"),
        );
        assert!(
            matches!(result, ReportSettlement::Failed { .. }),
            "guest-authored completion records released a failed report without a PDF"
        );
    }

    #[test]
    fn a_changed_embedded_figure_invalidates_the_existing_review() {
        let source = "#image(\"chart.svg\")\n#text(\"A finding\")";
        let body = "A finding";
        let figure = b"figure-a";
        let pdf = b"%PDF-a";
        let identity = ReportIdentity {
            pdf_relative: "report.pdf".into(),
            pdf_absolute: "/export/report.pdf".into(),
            source: "/export/report.typ".into(),
            bytes: pdf.len() as u64,
            page_count: 1,
            content: content_digest(source, &[("chart.svg", figure)]),
            pdf: odin_domain::Digest::hash(pdf).to_string(),
            body: odin_domain::Digest::hash(body.as_bytes()).to_string(),
            captured_at: MEASURED.into(),
        };
        let state = SettlementState {
            pdf: identity.pdf.clone(),
            bytes: identity.bytes,
            captured_at: identity.captured_at.clone(),
            content: identity.content.clone(),
            dispatched_answer: Some("review-1".into()),
            ..SettlementState::default()
        };
        let export = |path: &str, bytes: &[u8]| ExportedFile {
            path: path.into(),
            bytes: bytes.len() as u64,
            content: Ok(bytes.to_vec()),
        };
        let mut files = vec![
            export("report.pdf", pdf),
            export("report.typ", source.as_bytes()),
            export("report.md", body.as_bytes()),
            export("chart.svg", figure),
        ];
        assert!(reviewed_bytes_match(&files, &identity, &state));
        let root = tempfile::tempdir().expect("authority state");
        write_state(root.path(), &state).expect("save review");
        let state = read_state(root.path());
        let mut replaced = identity.clone();
        files[0].content = Ok(b"%PDF-b".to_vec());
        replaced.pdf = odin_domain::Digest::hash(b"%PDF-b").to_string();
        assert!(!reviewed_bytes_match(&files, &replaced, &state));
        files[0].content = Ok(pdf.to_vec());
        files[3].content = Ok(b"figure-b".to_vec());
        assert!(!reviewed_bytes_match(&files, &identity, &state));
    }


    fn runtime_under(root: &std::path::Path) -> Arc<odin_hermes::runtime::HermesRuntime> {
        // `open` returns the runtime already wrapped in its Arc.
        odin_hermes::runtime::HermesRuntime::open(
            odin_hermes::config::HermesSettings::new(
                root.to_path_buf(),
                None,
                None,
                None,
                Vec::new(),
            )
            .expect("settings"),
            odin_hermes::runtime::HermesLedgers {
                conversation: odin_ledger::Ledger::open_in_memory().expect("conversation"),
                adapter: Arc::new(parking_lot::Mutex::new(
                    odin_ledger::Ledger::open_in_memory().expect("adapter"),
                )),
                purchase: Arc::new(std::sync::Mutex::new(
                    odin_ledger::Ledger::open_in_memory().expect("purchase"),
                )),
            },
            &std::collections::BTreeMap::new(),
            None,
            8192,
            std::collections::BTreeMap::new(),
            None,
        )
        .expect("runtime")
    }

    fn report_run(runtime: Arc<odin_hermes::runtime::HermesRuntime>, run: &str) -> ReportRun {
        ReportRun {
            runtime,
            seat: SeatId::new("research").expect("seat"),
            session: LiveSessionId::parse("00000000-0000-4000-8000-00000000c0de").expect("session"),
            target: PodTarget {
                run: RunId::new(run).expect("run"),
                export_dir: "/export".into(),
                network_transport: odin_registry::WorkloadTransport::Direct,
            },
            owes_pdf: true,
            company: None,
            downloads_root: Some("downloads".into()),
            wall: wall(),
            render: render_with_docs,
        }
    }

    /// The exact render a settlement pass saves, and its identity.
    fn saved_render() -> (Vec<ExportedFile>, ReportIdentity, &'static str) {
        let pdf = b"%PDF-final-render";
        let body = "The report body.";
        let identity = ReportIdentity {
            pdf_relative: PDF_NAME.into(),
            pdf_absolute: "/export/report.pdf".into(),
            source: "/export/report.typ".into(),
            bytes: pdf.len() as u64,
            page_count: 2,
            content: "content".into(),
            pdf: odin_domain::Digest::hash(pdf).to_string(),
            body: odin_domain::Digest::hash(body.as_bytes()).to_string(),
            captured_at: MEASURED.into(),
        };
        let export = |path: &str, bytes: &[u8]| ExportedFile {
            path: path.into(),
            bytes: bytes.len() as u64,
            content: Ok(bytes.to_vec()),
        };
        (
            vec![
                export("report.pdf", pdf),
                export("report.md", body.as_bytes()),
                export("report.typ", b"#let page = \"typst\""),
            ],
            identity,
            body,
        )
    }

    #[test]
    fn the_exact_render_is_saved_outside_the_pod_and_repaired_when_damaged() {
        let root = tempfile::tempdir().expect("state");
        let run = report_run(runtime_under(root.path()), "report-saved");
        let (files, identity, body) = saved_render();
        persist_report(&run, &files, &identity, body).expect("the render is saved");
        let directory = record_dir(&run);
        assert_eq!(
            std::fs::read(directory.join(PDF_NAME)).expect("saved pdf"),
            file_bytes(&files, "report.pdf").expect("pdf bytes")
        );
        assert_eq!(
            std::fs::read(directory.join(COMPANION)).expect("saved body"),
            body.as_bytes()
        );
        // A damaged or missing save is rewritten on the next pass.
        std::fs::write(directory.join(COMPANION), b"tampered").expect("damage");
        persist_report(&run, &files, &identity, body).expect("the save is repaired");
        assert_eq!(
            std::fs::read(directory.join(COMPANION)).expect("repaired body"),
            body.as_bytes()
        );
    }

    /// A cell that never connected: its exec transport answers immediately
    /// with a refusal, the stand-in for a carrier that cannot be read.
    fn unreachable_cell() -> Arc<crate::kube::KubeRuntimeCell> {
        let dir = tempfile::tempdir().expect("cell tempdir");
        let ledger = Arc::new(std::sync::Mutex::new(
            odin_ledger::Ledger::open_in_memory().expect("ledger"),
        ));
        let bus = odin_process::BusAddress::unix_socket(dir.path().join("bus.sock"))
            .expect("bus address");
        let channel = odin_process::WorkerChannel::for_recovery(bus).expect("worker channel");
        // `new` returns the cell already wrapped in its Arc.
        crate::kube::KubeRuntimeCell::new(crate::kube::CellInputs {
            config: odin_kube::config::KubeConfig {
                kubeconfig: dir.path().join("kubeconfig"),
                cluster: "unit-cluster".to_owned(),
                namespace: "unit-namespace".to_owned(),
                allowed_nodes: std::collections::BTreeSet::new(),
                request_timeout: std::time::Duration::from_secs(1),
                teardown_timeout: std::time::Duration::from_secs(1),
                vpn_transport: None,
            },
            ledger,
            stops: Arc::new(odin_kernel::stop::StopAuthority::new(
                Arc::new(std::sync::Mutex::new(
                    odin_ledger::Ledger::open_in_memory().expect("stop ledger"),
                )),
                channel,
            )),
            artifact_root: dir.path().join("artifacts"),
            snapshot: Arc::new(
                odin_registry::Snapshot::build(1, Vec::new()).expect("fixture snapshot"),
            ),
            config_revision: 1,
            launch_binding: None,
            workload_identity: crate::kube::WorkloadExtensionIdentity {
                artifact: odin_domain::ArtifactId::new(
                    odin_domain::Digest::hash(b"salvage-identity").to_string(),
                )
                .expect("artifact id"),
                deployment: Default::default(),
            },
        })
    }

    /// The incident shape: the worker finished and rests, its carrier is
    /// gone, and only the save outside the pod is left. A settlement that
    /// cannot collect must degrade to that save — and a pod that still
    /// looks alive is never prematurely salvaged.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lost_pod_degrades_to_its_saved_report_and_a_live_one_does_not() {
        let root = tempfile::tempdir().expect("state");
        let cell = unreachable_cell();
        let run = report_run(runtime_under(root.path()), "report-wiring");
        let (files, identity, body) = saved_render();
        persist_report(&run, &files, &identity, body).expect("the render is saved");
        let unread = || Some(GoneExport::Lost("its node could not be reached".to_owned()));
        let gone = finish_export(
            &cell,
            &run,
            "The answer.",
            "answer-1",
            false,
            None,
            unread(),
        );
        assert!(
            matches!(gone, ReportSettlement::Salvaged { .. }),
            "a gone carrier delivers the saved report, not {gone:?}"
        );
        let pending = finish_export(&cell, &run, "The answer.", "answer-1", false, None, None);
        match pending {
            ReportSettlement::Pending { follow_up, .. } => {
                assert!(follow_up.is_none());
            }
            other => panic!("a pod that may still be alive is never salvaged: {other:?}"),
        }
        // What the pod said it left undone reaches the seat with the saved report.
        let gone = finish_export(&cell, &run, UNMET, "answer-2", false, None, unread());
        match gone {
            ReportSettlement::Salvaged { note, .. } => assert!(
                note.contains(
                    "Nine manufacturers: Obscura, the browser and Wayback all answered 403"
                ),
                "{note}"
            ),
            other => panic!("a gone carrier delivers the saved report: {other:?}"),
        }
        std::fs::write(record_dir(&run).join(PDF_NAME), b"corrupt").expect("damage snapshot");
        let gone = finish_export(&cell, &run, UNMET, "answer-1", false, None, unread());
        assert!(
            matches!(&gone, ReportSettlement::Salvaged { files, note }
                if files.is_empty() && note.contains("Nine manufacturers")),
            "no snapshot still names the unmet items: {gone:?}"
        );
        let unsaved = report_run(runtime_under(root.path()), "report-without-snapshot");
        let gone = finish_export(
            &cell,
            &unsaved,
            "The answer.",
            "answer-1",
            false,
            None,
            unread(),
        );
        assert!(matches!(gone, ReportSettlement::Salvaged { files, .. } if files.is_empty()));
        assert!(!copies_are_durable(&record_dir(&unsaved)));
    }

    #[test]
    fn only_the_companion_can_override_the_settled_answer() {
        let mut files = vec![ExportedFile {
            path: "evidence/report.md".into(),
            bytes: 8,
            content: Ok(b"Evidence".to_vec()),
        }];
        assert_eq!(authoritative_body(&files, "Answer"), "Answer");
        files.push(ExportedFile {
            path: COMPANION.into(),
            bytes: 9,
            content: Ok(b"Corrected".to_vec()),
        });
        assert_eq!(authoritative_body(&files, "Answer"), "Corrected");
    }

    /// A pod's export held in memory, answering the few commands a settlement runs in the pod.
    #[derive(Default)]
    struct FakePod {
        files: std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>,
    }

    impl FakePod {
        fn put(&self, path: &str, bytes: &[u8]) {
            let path = format!("/export/{path}");
            self.files.lock().unwrap().insert(path, bytes.to_vec());
        }
    }

    impl PodWorkerExec for FakePod {
        fn exec(
            &self,
            _: &RunId,
            argv: &[String],
            stdin: Option<&[u8]>,
            _: std::time::Duration,
            _: usize,
        ) -> Result<
            odin_omp::host_tools::pod_exec::WorkerOutput,
            odin_omp::host_tools::pod_exec::WorkerExecFault,
        > {
            let output =
                |exit_code: i32, stdout: Vec<u8>| odin_omp::host_tools::pod_exec::WorkerOutput {
                    exit_code,
                    stdout_bytes: stdout.len() as u64,
                    stdout_tail: stdout,
                    stderr_tail: Vec::new(),
                    stderr_bytes: 0,
                };
            let mut files = self.files.lock().unwrap();
            let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
            Ok(match argv.as_slice() {
                ["/bin/find", directory, ..] => output(
                    0,
                    files
                        .iter()
                        .filter_map(|(path, bytes)| {
                            let relative = path.strip_prefix(&format!("{directory}/"))?;
                            Some(format!("{} {relative}\0", bytes.len()))
                        })
                        .collect::<String>()
                        .into_bytes(),
                ),
                ["/bin/cat", path] => match files.get(*path) {
                    Some(bytes) => output(0, bytes.clone()),
                    None => output(1, Vec::new()),
                },
                ["/bin/dd", target, ..] => {
                    let path = target.strip_prefix("of=").expect("dd of=").to_owned();
                    files.insert(path, stdin.unwrap_or_default().to_vec());
                    output(0, Vec::new())
                }
                ["/bin/rm", "-f", path] => {
                    files.remove(*path);
                    output(0, Vec::new())
                }
                ["/bin/odin-pages", _, directory] => {
                    let png = page_png();
                    let page = format!("{directory}/page-01.png");
                    let receipt = json!({"files": [{"path": page, "bytes": png.len()}]});
                    files.insert(page, png);
                    files.insert(
                        format!("{directory}/pages.json"),
                        serde_json::to_vec(&receipt).unwrap(),
                    );
                    output(0, Vec::new())
                }
                ["/bin/odin-view", path] => output(0, files[*path].clone()),
                other => output(127, format!("no such command {other:?}").into_bytes()),
            })
        }
    }

    /// A one-pixel PNG: the page image the fake rasterizer returns.
    fn page_png() -> Vec<u8> {
        base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
        )
        .expect("png")
    }

    /// The laptop's files route: every save completes, and the folder and name of each is kept.
    #[derive(Default)]
    struct Laptop {
        saved: std::sync::Mutex<Vec<(Option<String>, String)>>,
    }

    impl odin_hermes::runtime::shared_files::HostFileRoute for Laptop {
        fn roots(&self, _: &str) -> Vec<Value> {
            Vec::new()
        }
        fn list(
            &self,
            _: &str,
            _: &str,
            _: Option<&str>,
            _: Option<&str>,
        ) -> Result<(Vec<Value>, bool), String> {
            Err("the settlement lists nothing".to_owned())
        }
        fn read(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<(String, String, std::fs::File), String> {
            Err("the settlement reads nothing".to_owned())
        }
        fn save(
            &self,
            _: &str,
            _: Option<&str>,
            folder: Option<&str>,
            name: &str,
            _: &mut std::fs::File,
            _: Option<&odin_hermes::runtime::shared_files::RootSource>,
        ) -> Result<Value, String> {
            self.saved
                .lock()
                .unwrap()
                .push((folder.map(str::to_owned), name.to_owned()));
            Ok(json!({"status": "completed", "save_id": "save"}))
        }
        fn save_status(&self, _: &str, _: &str) -> Result<Value, String> {
            Ok(json!({"status": "completed"}))
        }
    }

    const CONTACTS: &str = "## Contacts\n\n| Name | Role |\n| --- | --- |\n| Ada | CTO |\n";

    /// One pod run settling: its export, the authority's records and the laptop route.
    struct Scene {
        _root: tempfile::TempDir,
        run: ReportRun,
        pod: Arc<FakePod>,
        laptop: Arc<Laptop>,
    }

    /// The run's measured stats, written into the pod's export as the daemon's route does.
    struct Stats(Arc<FakePod>);

    impl odin_hermes::runtime::RunStatsRoute for Stats {
        fn capture(&self, _: &str) -> Result<Value, String> {
            Ok(json!({"capturedAt": "2026-11-02T18:00:00Z"}))
        }
        fn tools_called(&self, _: &str) -> Result<BTreeSet<String>, String> {
            Ok(BTreeSet::new())
        }
        fn write(&self, _: &odin_domain::SessionId, document: &Value) -> Result<String, String> {
            self.0
                .put("run-stats.json", &serde_json::to_vec(document).unwrap());
            Ok("/export/run-stats.json".to_owned())
        }
    }

    /// A renderer that cannot compile a source marked BROKEN and otherwise renders one PDF per
    /// source, counting its renders in the run's records.
    fn fake_render(
        run: &ReportRun,
        source: &str,
        _: &Value,
        _: &[ExportedFile],
    ) -> Result<Rendered, RenderError> {
        if source.contains("BROKEN") {
            return Err(RenderError::Compile(
                "docs.render did not compile the report: unclosed delimiter".to_owned(),
            ));
        }
        let counted = record_dir(run).join("render-count");
        let renders = std::fs::read_to_string(&counted)
            .ok()
            .and_then(|count| count.parse::<u32>().ok())
            .unwrap_or(0);
        std::fs::create_dir_all(record_dir(run)).map_err(|error| error.to_string())?;
        std::fs::write(&counted, (renders + 1).to_string()).map_err(|error| error.to_string())?;
        Ok(Rendered {
            pdf: format!("%PDF-{}", odin_domain::Digest::hash(source.as_bytes())).into_bytes(),
            page_count: 1,
            warnings: Vec::new(),
            content: content_digest(&compile_source(source), &[]),
        })
    }

    impl Scene {
        fn new() -> Self {
            let root = tempfile::tempdir().expect("state");
            let mut run = report_run(runtime_under(root.path()), "report-scene");
            let (pod, laptop) = (Arc::new(FakePod::default()), Arc::new(Laptop::default()));
            run.runtime.set_host_file_route(laptop.clone());
            run.runtime
                .set_run_stats_route(Arc::new(Stats(pod.clone())));
            run.render = fake_render;
            Self {
                _root: root,
                run,
                pod,
                laptop,
            }
        }

        /// Every deliverable in the export is already copied to the laptop and to Drive.
        fn copied(&self) {
            self.copied_files(&self.export());
        }

        /// Every deliverable in `files` is already copied to the laptop and to Drive.
        fn copied_files(&self, files: &[ExportedFile]) {
            let stem = report_stem(&self.run, &body_of(files), MEASURED).expect("stem");
            let mut used = BTreeSet::new();
            let records: Vec<CopyRecord> = files
                .iter()
                .filter(|file| is_deliverable(file, files))
                .map(|file| CopyRecord {
                    name: copy_name(&file.path, &stem, &mut used),
                    save_id: Some("save".into()),
                    laptop: "completed".into(),
                    drive_id: Some("drive".into()),
                    drive: "completed".into(),
                    drive_name: None,
                    drive_link: None,
                })
                .collect();
            write_copies(&record_dir(&self.run), &records).expect("copies recorded");
        }

        fn export(&self) -> Vec<ExportedFile> {
            collect_exports(self.pod.as_ref(), &self.run.target, MAX_REPORT_FILE_BYTES)
                .expect("export")
        }

        /// The pass the pump runs when the pod's turn settled with `answer`.
        fn settle(&self, answer: &str, key: &str) -> ReportSettlement {
            finish_collected(
                self.pod.as_ref(),
                &self.run,
                self.export(),
                answer,
                key,
                false,
                None,
            )
        }
    }

    fn pending(settled: ReportSettlement) -> (String, Option<ReviewTurn>) {
        match settled {
            ReportSettlement::Pending { note, follow_up } => (note, follow_up),
            other => panic!("the report stays pending: {other:?}"),
        }
    }

    fn delivered(settled: ReportSettlement) -> String {
        match settled {
            ReportSettlement::Delivered { note, .. } => note,
            other => panic!("the report is delivered: {other:?}"),
        }
    }

    const UNMET: &str = "The cylinder prices are in.\n\n## Unmet items\n\n\
                         - Nine manufacturers: Obscura, the browser and Wayback all answered 403";

    /// The pod's review of its render ends the run: the pages are accepted and the copies done.
    fn accept_pages(scene: &Scene) -> String {
        scene.copied();
        delivered(scene.settle("Pages accepted.", "review-1"))
    }

    #[test]
    fn unmet_items_go_back_to_the_pod_once_per_review_cycle_while_time_remains() {
        let mut scene = Scene::new();
        let (note, turn) = pending(scene.settle(UNMET, "answer-1"));
        let turn = turn.expect("the pod is resumed with its unmet items");
        assert!(note.contains("1 unmet"), "{note}");
        assert!(
            turn.text.contains("Nine manufacturers") && turn.text.contains("not tried on it yet"),
            "{}",
            turn.text
        );
        assert!(turn.images.is_empty());
        // The pod answers again within the cycle: it waits for the next one.
        scene.run.wall.now += 60;
        let more = "## Unmet items\n- Nine manufacturers: Obscura, the browser and Wayback all answered 403\n- DOT permits";
        let (_, turn) = pending(scene.settle(more, "answer-2"));
        assert!(turn.is_none(), "one resume per review cycle at most");
        // A cycle after the first, with something new to try, it goes back once more.
        scene.run.wall.now += 120;
        let (_, turn) = pending(scene.settle(more, "answer-2"));
        assert!(turn
            .expect("the next cycle's resume")
            .text
            .contains("DOT permits"));
    }

    /// The incident: the pod answered with the same blocked items, reworded, every review cycle
    /// until its deadline, and its report was never rendered.
    #[test]
    fn a_pod_is_sent_back_at_most_twice_and_its_report_then_settles_partial_with_the_list() {
        let mut scene = Scene::new();
        scene.pod.put(COMPANION, CONTACTS.as_bytes());
        let answer = |round: u32| {
            format!("## Unmet items\n- Cabot PDF: blocked, try {round}\n- Gap {round}: still open")
        };
        for round in 1..=u32::from(MAX_UNMET_RESUMES) {
            let (_, turn) = pending(scene.settle(&answer(round), &format!("answer-{round}")));
            assert!(turn.is_some(), "round {round} goes back to the pod");
            scene.run.wall.now += 180;
        }
        // The next answer, with items the last did not name, is not sent back: its report is
        // rendered and offered for review.
        let (_, turn) = pending(scene.settle(&answer(3), "answer-3"));
        assert_eq!(turn.expect("pages offered").images.len(), 1);
        // The review's own reply lists nothing; the report still goes out as partial work.
        let note = accept_pages(&scene);
        assert!(
            note.contains("partial work")
                && note.contains("Cabot PDF: blocked, try 3")
                && note.contains("Gap 3: still open"),
            "{note}"
        );
    }

    /// The incident: a pod's Typst source that never compiled left its run pending for 25
    /// minutes, the pod idle and nothing telling it why.
    #[test]
    fn a_source_that_does_not_compile_is_sent_back_twice_then_the_markdown_is_rendered() {
        let scene = Scene::new();
        scene.pod.put("report.md", CONTACTS.as_bytes());
        scene.pod.put("report.typ", b"#text(\"BROKEN\"");
        for round in 1..=MAX_RERENDERS {
            let (note, turn) = pending(scene.settle("Done.", &format!("answer-{round}")));
            let turn = turn.expect("the pod is asked to fix its source");
            assert!(turn.text.contains("unclosed delimiter"), "{}", turn.text);
            assert!(note.contains("fix its report source"), "{note}");
        }
        let settled = scene.settle("Done.", "answer-3");
        assert!(
            !matches!(
                settled,
                ReportSettlement::Pending {
                    follow_up: Some(_),
                    ..
                }
            ),
            "out of rounds the pod is not asked again: {settled:?}"
        );
        let saved = scene.laptop.saved.lock().unwrap().clone();
        assert!(
            saved
                .iter()
                .any(|(_, name)| name.starts_with("Research report ") && name.ends_with(".pdf")),
            "the render is copied: {saved:?}"
        );
        let source = scene.pod.files.lock().unwrap()["/export/report.typ"].clone();
        assert!(!String::from_utf8_lossy(&source).contains("BROKEN"));
        // The copies are retried on the render that was accepted, not under a new one.
        scene.settle("Done.", "answer-3");
        assert_eq!(
            std::fs::read(record_dir(&scene.run).join("render-count")).expect("render count"),
            b"1"
        );
    }
}
