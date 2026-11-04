//! Durable report snapshots and terminal salvage: the report saved outside the pod, and the
//! report a gone pod left on its node.

use super::*;

/// Saves the exact validated render outside the pod — PDF, companion
/// markdown and Typst source under the run's report state directory — so
/// the report survives its carrier. Idempotent per render: an unchanged,
/// intact save is left alone.
pub(super) fn persist_report(
    run: &ReportRun,
    files: &[ExportedFile],
    identity: &ReportIdentity,
    body: &str,
) -> Result<(), String> {
    let directory = record_dir(run);
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&directory)
            .map_err(|error| format!("could not create report state: {error}"))?;
    }
    let pdf = file_bytes(files, &identity.pdf_relative)
        .ok_or_else(|| "the rendered PDF was not among the exports".to_owned())?;
    let body_id = odin_domain::Digest::hash(body.as_bytes()).to_string();
    let source = read_named(files, &identity.source);
    let intact = |bytes: &[u8]| {
        odin_domain::Digest::hash(bytes).to_string() == identity.pdf
            && bytes.len() as u64 == identity.bytes
    };
    let already = std::fs::read(directory.join(PDF_NAME))
        .map(|bytes| intact(&bytes))
        .unwrap_or(false)
        && read_record(&directory, SAVED).is_some_and(|saved| {
            saved["pdf"] == json!(identity.pdf) && saved["body"] == json!(body_id)
        })
        && std::fs::read(directory.join(COMPANION)).is_ok_and(|saved| saved == body.as_bytes())
        && source.as_deref().is_some_and(|source| {
            std::fs::read(directory.join(file_name(&identity.source)))
                .is_ok_and(|saved| saved == source.as_bytes())
        });
    if already {
        return Ok(());
    }
    odin_cli::authority_provision::write_private_atomic(&directory.join(PDF_NAME), pdf)
        .map_err(|error| format!("report.pdf was not saved: {error}"))?;
    odin_cli::authority_provision::write_private_atomic(
        &directory.join(COMPANION),
        body.as_bytes(),
    )
    .map_err(|error| format!("{COMPANION} was not saved: {error}"))?;
    if let Some(source) = source.as_deref() {
        odin_cli::authority_provision::write_private_atomic(
            &directory.join(file_name(&identity.source)),
            source.as_bytes(),
        )
        .map_err(|error| format!("{} was not saved: {error}", file_name(&identity.source)))?;
    }
    write_record(
        &directory,
        SAVED,
        &json!({
            "pdf": identity.pdf,
            "bytes": identity.bytes,
            "capturedAt": identity.captured_at,
            "body": body_id,
            "source": identity.source,
        }),
    )
}

/// The report saved before its pod was lost, shared with the launching
/// seat as artifacts: the readable degradation of a settlement whose
/// carrier is gone. `unmet` is the note of the items the pod left, appended to its own.
/// `None` when no intact save exists.
pub(super) fn salvage_saved_report(run: &ReportRun, unmet: &str) -> Option<ReportSettlement> {
    let directory = record_dir(run);
    let saved = read_record(&directory, SAVED)?;
    let pdf = std::fs::read(directory.join(PDF_NAME)).ok()?;
    let digest = odin_domain::Digest::hash(&pdf).to_string();
    if digest != saved["pdf"].as_str()? || pdf.len() != saved["bytes"].as_u64()? as usize {
        return None;
    }
    let captured = saved["capturedAt"].as_str().unwrap_or("unknown");
    let body = std::fs::read(directory.join(COMPANION))
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok());
    let note = format!(
        "Its carrier is gone, so the report's review and the declared copies did not finish and \
         the report contract is unmet. The exact render saved before the pod was lost — \
         {PDF_NAME}, {} bytes, captured {captured} — is shared above as artifacts.{unmet}",
        pdf.len()
    );
    let stem = report_stem(run, body.as_deref().unwrap_or_default(), captured).ok();
    let mut files = vec![ExportedFile {
        path: PDF_NAME.to_owned(),
        bytes: pdf.len() as u64,
        content: Ok(pdf),
    }];
    if let Some(body) = body {
        if !body.trim().is_empty() {
            files.push(ExportedFile {
                path: COMPANION.to_owned(),
                bytes: body.len() as u64,
                content: Ok(body.into_bytes()),
            });
        }
    }
    if let Some(source_name) = saved["source"].as_str().map(file_name) {
        if let Ok(source) = std::fs::read(directory.join(source_name)) {
            files.push(ExportedFile {
                path: source_name.to_owned(),
                bytes: source.len() as u64,
                content: Ok(source),
            });
        }
    }
    Some(ReportSettlement::Salvaged {
        note,
        files: share_files(&files, &run.runtime, &run.seat, stem.as_deref()),
    })
}

/// The node a report pod's Job runs on, kept in its settlement state: once the Job is gone
/// nothing else names the node that retains its export.
pub(super) fn remember_node(
    runtime: &odin_hermes::runtime::HermesRuntime,
    run: &RunId,
    seen: Option<String>,
) -> Option<String> {
    let records = records_path(runtime, run);
    let mut state = read_state(&records);
    let Some(node) = seen else {
        return Some(state.node).filter(|node| !node.is_empty());
    };
    if state.node != node {
        state.node.clone_from(&node);
        if let Err(error) = write_state(&records, &state) {
            tracing::error!("pod node not recorded run={} {error}", run.as_str());
        }
    }
    Some(node)
}

/// What a gone pod's export came to this settlement pass.
pub(super) enum GoneExport {
    /// The export, from the copy kept in the run's report state or one read from its node.
    Read(Vec<ExportedFile>),
    /// The last read failed (the cause) and the next is not due before the next review cycle.
    Later(String),
    /// No read is due and none worked (the cause).
    Lost(String),
}

/// A gone pod's export as read from the node that retains it, kept in the run's report state.
const RETAINED_EXPORT: &str = "retained-export.tar";

/// A gone pod's export. The first read that works is kept in the run's report state and every
/// later pass uses that copy, so a settlement that waits on its copies reads the node once. A
/// read that fails is tried again once per review cycle, at most [`MAX_EXPORT_READS`] times; a
/// pod whose cycle is unknown is read once.
pub(super) async fn gone_export<Read, Tar>(records: &Path, wall: Wall, read: Read) -> GoneExport
where
    Read: FnOnce() -> Tar,
    Tar: std::future::Future<Output = Result<Vec<u8>, String>>,
{
    if let Ok(tar) = std::fs::read(records.join(RETAINED_EXPORT)) {
        return exported(&tar).map_or_else(GoneExport::Lost, GoneExport::Read);
    }
    let mut state = read_state(records);
    let retry_cycle = |failures: u8| wall.cycle.filter(|_| failures < MAX_EXPORT_READS);
    if state.export_failures > 0 {
        match retry_cycle(state.export_failures) {
            None => return GoneExport::Lost(state.export_failure),
            Some(cycle) if wall.now - state.export_failed_at < cycle => {
                return GoneExport::Later(state.export_failure)
            }
            Some(_) => {}
        }
    }
    let tar = match read().await {
        Ok(tar) => tar,
        Err(reason) => {
            state.export_failures = state.export_failures.saturating_add(1);
            state.export_failed_at = wall.now;
            state.export_failure.clone_from(&reason);
            if let Err(error) = write_state(records, &state) {
                tracing::error!("pod export failure not recorded: {error}");
            }
            return match retry_cycle(state.export_failures) {
                Some(_) => GoneExport::Later(reason),
                None => GoneExport::Lost(reason),
            };
        }
    };
    if let Err(error) = write_file(records, RETAINED_EXPORT, &tar) {
        tracing::error!("pod export not kept, so it is read again: {error}");
    }
    exported(&tar).map_or_else(GoneExport::Lost, GoneExport::Read)
}

/// A pod's export folder survives its Job on the node the pod ran on. Reads it there through a
/// helper pod, the way a finished run's exports are captured, as a tar. `node` is where the
/// Job's pod ran when last seen, else where the run's state volume is bound.
pub(super) async fn read_retained_export(
    cell: &crate::kube::KubeRuntimeCell,
    run: &RunId,
    host_folder: &str,
    node: Option<String>,
) -> Result<Vec<u8>, String> {
    let (_, client) = cell
        .parts()
        .await
        .map_err(|error| format!("the cluster is unreachable: {error}"))?;
    let node = match node {
        Some(node) => node,
        None => odin_kube::state_carry::state_node(&client, run)
            .await
            .map_err(|error| format!("the node that ran it could not be read: {error}"))?
            .ok_or_else(|| "no node is recorded for it".to_owned())?,
    };
    let site = odin_kube::state_carry::ExportSite {
        node,
        image: cell.workload_identity().deployment.image_reference.clone(),
        host_folder: host_folder.to_owned(),
        subfolder: odin_kube::workload::export_subfolder(run),
    };
    odin_kube::state_carry::export_tar(
        &client,
        &cell.stop_authority(),
        &site,
        odin_omp::host_tools::pod_exec::MAX_EXPORT_BYTES,
    )
    .await
    .map_err(|error| format!("its export on {} could not be read: {error}", site.node))
}

/// The files of an export tar; one over the report file bound is named, not read.
fn exported(tar: &[u8]) -> Result<Vec<ExportedFile>, String> {
    let files = odin_kube::state_carry::tar_regular_files(tar)?;
    Ok(files
        .into_iter()
        .map(|(path, bytes)| ExportedFile {
            path,
            bytes: bytes.len() as u64,
            content: match bytes.len() as u64 > MAX_REPORT_FILE_BYTES {
                true => Err(format!("it is over the {MAX_REPORT_FILE_BYTES}-byte limit")),
                false => Ok(bytes.to_vec()),
            },
        })
        .collect())
}

/// A carrier that is gone can never be read again. The report saved outside the pod is
/// delivered as artifacts; failing that, the pod's own report.md is rendered here and delivered
/// unreviewed as partial work. The unmet items are the last answer's, else those its settlement
/// carried, else (when that answer failed) the list the pod was last sent back with.
pub(super) fn finish_gone(
    run: &ReportRun,
    answer: &str,
    failed: bool,
    export: GoneExport,
) -> ReportSettlement {
    let state = read_state(&record_dir(run));
    let mut undone = Undone::of(answer, failed);
    undone.name_receipts(&state.undone.receipts);
    if undone.items.is_empty() {
        undone.items = state.undone.items;
    }
    if undone.items.is_empty() && failed {
        undone.items = state.resumed_unmet.lines().map(str::to_owned).collect();
    }
    if let Some(salvaged) = salvage_saved_report(run, &unmet_note(&undone)) {
        return salvaged;
    }
    let reason = match export {
        GoneExport::Read(files) => match deliver_retained(run, files, &mut undone) {
            Ok(delivered) => return delivered,
            Err(reason) => reason,
        },
        GoneExport::Later(reason) => {
            return ReportSettlement::Pending {
                note: format!(
                    "Its export could not be read back from its node ({reason}); the read is \
                     tried again at the next review cycle"
                ),
                follow_up: None,
            }
        }
        GoneExport::Lost(reason) => reason,
    };
    ReportSettlement::Salvaged {
        note: format!(
            "Its carrier is gone and no intact authority-side report snapshot exists. The PDF \
             review and declared copies did not finish; the report contract is unmet. The ledger \
             answer below is partial work, not a delivered report. Retained node exports and \
             persistent volumes have not been deleted. Its export could not be rendered: \
             {reason}{}",
            unmet_note(&undone)
        ),
        files: String::new(),
    }
}

/// Renders the report.md a gone pod left in its export and delivers it as partial work: nobody
/// reviewed its pages. The measured stats are the last the pod's settlement wrote, when it
/// wrote any.
fn deliver_retained(
    run: &ReportRun,
    mut files: Vec<ExportedFile>,
    undone: &mut Undone,
) -> Result<ReportSettlement, String> {
    let body = read_named(&files, COMPANION)
        .filter(|body| !body.trim().is_empty())
        .ok_or_else(|| format!("it holds no {COMPANION} to render"))?;
    let stats = read_named(&files, "run-stats.json")
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .unwrap_or(Value::Null);
    let captured_at = match stats["capturedAt"].as_str() {
        Some(captured) => captured.to_owned(),
        None => time::OffsetDateTime::from_unix_timestamp(run.wall.now)
            .map_err(|error| error.to_string())?
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|error| error.to_string())?,
    };
    let source = complete_fallback_source(&body, &files)?;
    let rendered = (run.render)(run, &source, &footer_meta(&stats), &files)
        .map_err(RenderError::into_reason)?;
    let identity = ReportIdentity {
        pdf_relative: PDF_NAME.to_owned(),
        pdf_absolute: absolute_export(&run.target.export_dir, PDF_NAME),
        source: absolute_export(&run.target.export_dir, "report.typ"),
        bytes: rendered.pdf.len() as u64,
        page_count: u64::from(rendered.page_count),
        content: rendered.content,
        pdf: odin_domain::Digest::hash(&rendered.pdf).to_string(),
        body: odin_domain::Digest::hash(body.as_bytes()).to_string(),
        captured_at,
    };
    files.push(ExportedFile {
        path: PDF_NAME.to_owned(),
        bytes: identity.bytes,
        content: Ok(rendered.pdf),
    });
    undone.items.push(
        "page review: the pod's job ended before its pages were reviewed, so the authority \
         rendered report.md and delivered it unreviewed"
            .to_owned(),
    );
    let (subject, subject_source) = report_subject(run, &body);
    Ok(finish_copies(
        run,
        &files,
        &subject,
        subject_source,
        &identity,
        undone,
    ))
}
