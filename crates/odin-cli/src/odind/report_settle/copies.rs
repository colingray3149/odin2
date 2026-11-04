//! The copy stage of a report's settlement: each deliverable saved to the laptop's downloads
//! and, on the personal deployment, to Drive, with what each copy came to recorded so a retried
//! settlement finds the copies already made.

use super::*;
use std::io::Write;

#[derive(Clone, Debug)]
pub(super) struct CopyRecord {
    pub(super) name: String,
    pub(super) save_id: Option<String>,
    pub(super) laptop: String,
    pub(super) drive_id: Option<String>,
    pub(super) drive: String,
    /// The name Drive gave the file (a numbered one when the folder already
    /// held that name) and where it opens.
    pub(super) drive_name: Option<String>,
    pub(super) drive_link: Option<String>,
}

impl CopyRecord {
    pub(super) fn line(&self) -> String {
        let mut drive = self.drive.clone();
        if let Some(name) = self.drive_name.as_deref().filter(|name| *name != self.name) {
            drive.push_str(&format!(" as {name}"));
        }
        if let Some(link) = &self.drive_link {
            drive.push_str(&format!(" {link}"));
        }
        format!("- {}: downloads {} ; Drive {drive}", self.name, self.laptop)
    }
}

pub(super) fn copy_destinations(
    run: &ReportRun,
    subject: &str,
    subject_source: &str,
    files: &[ExportedFile],
    stem: &str,
) -> (String, bool) {
    let laptop_folder = format!("business/{subject}");
    let drive_folder = format!("Agentic Business/Profiles/{subject}");
    let directory = record_dir(run);
    let mut records = read_copies(&directory);
    let mut used = BTreeSet::new();
    let mut lines = Vec::new();
    let mut durable = true;
    let mut any = false;
    for file in files.iter().filter(|file| is_deliverable(file, files)) {
        any = true;
        let name = copy_name(&file.path, stem, &mut used);
        let record = records
            .iter_mut()
            .find(|record| record.name == name)
            .map(|record| record.clone());
        let mut record = record.unwrap_or(CopyRecord {
            name: name.clone(),
            save_id: None,
            laptop: "absent".to_owned(),
            drive_id: None,
            drive: "absent".to_owned(),
            drive_name: None,
            drive_link: None,
        });
        let Some(bytes) = file.content.as_ref().ok() else {
            durable = false;
            lines.push(format!("- {} was not copied: unread", file.path));
            continue;
        };
        match observe_laptop(run, &laptop_folder, &name, bytes, &mut record) {
            Ok(status) => {
                if status != "completed" && status != "queued" {
                    durable = false;
                }
            }
            // A file the downloads folder does not take (a tool's .jsonl log) is left out of it, not a failed copy.
            Err(error) if error.contains("its type is not one") => {
                record.laptop = NOT_TAKEN.to_owned();
            }
            Err(error) => {
                durable = false;
                record.laptop = "failed".to_owned();
                lines.push(format!("- {name}: downloads {error}"));
                store_copy(&mut records, record);
                continue;
            }
        }
        lines.push(record.line());
        store_copy(&mut records, record);
    }
    if let Err(error) = write_copies(&directory, &records) {
        durable = false;
        lines.push(format!("The copy state was not recorded: {error}"));
    }
    if !any {
        return (
            format!(
                "No deliverable file was available to copy to {laptop_folder} or {drive_folder} \
                 ({subject_source})."
            ),
            false,
        );
    }
    (
        format!(
            "Copies to declared downloads/{laptop_folder} and Drive {drive_folder} \
             ({subject_source}):\n{}",
            lines.join("\n")
        ),
        durable,
    )
}

fn observe_laptop(
    run: &ReportRun,
    folder: &str,
    name: &str,
    bytes: &[u8],
    record: &mut CopyRecord,
) -> Result<String, String> {
    let route = run
        .runtime
        .host_file_route()
        .ok_or_else(|| "host folders are not composed".to_owned())?;
    if let Some(id) = record.save_id.clone() {
        if let Ok(status) = route.save_status(run.seat.as_str(), &id) {
            let kind = status["status"].as_str().unwrap_or("unknown");
            if kind == "queued" || kind == "completed" {
                record.laptop = kind.to_owned();
                return Ok(record.laptop.clone());
            }
        }
        record.save_id = None;
    }
    let saved = save_laptop(run, folder, name, bytes)?;
    record.save_id = saved["save_id"].as_str().map(str::to_owned);
    record.laptop = saved["status"].as_str().unwrap_or("unknown").to_owned();
    Ok(record.laptop.clone())
}


fn save_laptop(run: &ReportRun, folder: &str, name: &str, bytes: &[u8]) -> Result<Value, String> {
    let root = run
        .downloads_root
        .as_deref()
        .filter(|root| !root.is_empty())
        .ok_or_else(|| "report.downloads_root is required for PDF delivery".to_owned())?;
    let route = run
        .runtime
        .host_file_route()
        .ok_or_else(|| "host folders are not composed".to_owned())?;
    save_into_root(
        route.as_ref(),
        run.seat.as_str(),
        root,
        Some(folder),
        name,
        bytes,
    )
}

/// Saves `bytes` as `name` in `folder` of the declared files root `root`
/// through the files route: the one save path report copies and exports use.
pub(crate) fn save_into_root(
    route: &dyn odin_hermes::runtime::shared_files::HostFileRoute,
    seat: &str,
    root: &str,
    folder: Option<&str>,
    name: &str,
    bytes: &[u8],
) -> Result<Value, String> {
    let mut file = tempfile::NamedTempFile::new()
        .map_err(|error| format!("a temporary copy could not be opened: {error}"))?;
    file.write_all(bytes)
        .map_err(|error| format!("the temporary copy could not be written: {error}"))?;
    let mut read = std::fs::File::open(file.path())
        .map_err(|error| format!("the temporary copy could not be read: {error}"))?;
    route.save(seat, Some(root), folder, name, &mut read, None)
}


fn store_copy(records: &mut Vec<CopyRecord>, record: CopyRecord) {
    if let Some(existing) = records.iter_mut().find(|item| item.name == record.name) {
        *existing = record;
    } else {
        records.push(record);
    }
}

/// A downloads copy left out because the folder does not take the file's type.
pub(super) const NOT_TAKEN: &str = "not taken by downloads";

pub(super) fn copies_are_durable(directory: &Path) -> bool {
    let Some(note) = delivery_note(directory) else {
        return false;
    };
    if note.is_empty() {
        return false;
    }
    let records = read_copies(directory);
    !records.is_empty()
        && records.iter().all(|record| {
            matches!(record.laptop.as_str(), "completed" | "queued" | NOT_TAKEN)
        })
}

pub(super) fn delivery_note(directory: &Path) -> Option<String> {
    let parsed = read_record(directory, DELIVERED)?;
    parsed["note"].as_str().map(str::to_owned)
}

pub(super) fn read_copies(directory: &Path) -> Vec<CopyRecord> {
    let Some(parsed) = read_record(directory, COPIES) else {
        return Vec::new();
    };
    parsed["files"]
        .as_array()
        .map(|files| {
            files
                .iter()
                .filter_map(|file| {
                    Some(CopyRecord {
                        name: file["name"].as_str()?.to_owned(),
                        save_id: file["saveId"].as_str().map(str::to_owned),
                        laptop: file["downloads"].as_str().unwrap_or("absent").to_owned(),
                        drive_id: file["driveId"].as_str().map(str::to_owned),
                        drive: file["drive"].as_str().unwrap_or("absent").to_owned(),
                        drive_name: file["driveName"].as_str().map(str::to_owned),
                        drive_link: file["driveLink"].as_str().map(str::to_owned),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn write_copies(directory: &Path, records: &[CopyRecord]) -> Result<(), String> {
    let files: Vec<Value> = records
        .iter()
        .map(|record| {
            json!({
                "name": record.name,
                "saveId": record.save_id,
                "downloads": record.laptop,
                "driveId": record.drive_id,
                "drive": record.drive,
                "driveName": record.drive_name,
                "driveLink": record.drive_link,
            })
        })
        .collect();
    write_record(directory, COPIES, &json!({"files": files}))
}

pub(super) fn is_deliverable(file: &ExportedFile, files: &[ExportedFile]) -> bool {
    file.bytes > 0 && !is_report_machinery(&file.path) && !is_page_raster(file, files)
}

fn is_report_machinery(path: &str) -> bool {
    let name = file_name(path);
    matches!(
        name,
        "run-stats.json"
            | "report-render.json"
            | "report-review.json"
            | "report-delivered.json"
            | "report-copies.json"
            | "report-settlement.json"
            | "pages.json"
    ) || name.ends_with(".typ")
}
