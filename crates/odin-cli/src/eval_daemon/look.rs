//! code.look's result: odin-look's report plus each screenshot as an image block the seat sees.

use std::io::Read;
use std::path::Path;

use odin_confined_fs::Capability;
use odin_hermes::runtime::images::{image_block, view_jpeg, TURN_IMAGE_BASE64};
use odin_omp::host_tools::HostToolError;
use serde_json::{json, Value};

use super::receipts::Captured;

const TOOL: &str = "odin_code.look";
/// Largest screenshot read back from the capsule.
const MAX_SHOT_BYTES: u64 = 8 * 1024 * 1024;

pub(super) fn project(run: &Captured, capsule_root: &Path) -> Result<Value, HostToolError> {
    let unavailable = |reason: String| HostToolError::Unavailable { tool: TOOL, reason };
    let report = match serde_json::from_str(run.stdout.trim()) {
        Ok(Value::Object(report)) => Value::Object(report),
        Ok(_) => {
            return Err(unavailable(
                "odin-look's report is not an object".to_owned(),
            ))
        }
        Err(_) => {
            let last = run
                .stderr
                .lines()
                .rev()
                .find(|line| !line.trim().is_empty());
            let code = run
                .exit_code
                .map_or_else(|| "without a code".to_owned(), |code| code.to_string());
            return Err(unavailable(format!(
                "odin-look exited {code} with no report: {}",
                last.unwrap_or("no output")
            )));
        }
    };
    if let Some(error) = report.get("error").and_then(Value::as_str) {
        return Err(unavailable(error.to_owned()));
    }
    let shots = report["shots"].as_array().map_or(&[][..], Vec::as_slice);
    let mut images = Vec::with_capacity(shots.len());
    for shot in shots {
        let path = shot["path"].as_str().unwrap_or_default();
        images.push(image_block(
            &shot_jpeg(capsule_root, path).map_err(unavailable)?,
        ));
    }
    let widths: Vec<String> = shots
        .iter()
        .filter_map(|shot| shot["width"].as_u64())
        .map(|width| width.to_string())
        .collect();
    let entries = |key: &str| report[key].as_array().map_or(0, Vec::len);
    let warnings = report["console"].as_array().map_or(0, |console| {
        console
            .iter()
            .filter(|entry| entry["type"] == "warning")
            .count()
    });
    let errors = entries("console") - warnings;
    let failed = entries("failed");
    let url = report["url"].as_str().unwrap_or_default();
    let done = format!(
        "Looked at {url} at {} px: {errors} console error{}, {failed} failed request{}.",
        widths.join(" and "),
        if errors == 1 { "" } else { "s" },
        if failed == 1 { "" } else { "s" },
    );
    let mut result = report;
    result["done"] = json!(done);
    result["images"] = Value::Array(images);
    Ok(result)
}

/// One screenshot from the capsule's scratch, sized for a tool result.
/// The open refuses a symlink at any component, so a report path cannot leave the capsule.
fn shot_jpeg(capsule_root: &Path, path: &str) -> Result<Vec<u8>, String> {
    if !path.starts_with(".odin-eval/look") || path.contains("//") {
        return Err(format!(
            "screenshot path {path:?} is not inside the capsule scratch"
        ));
    }
    let root = Capability::seal(capsule_root)
        .map_err(|error| format!("capsule is not a confined root: {error}"))?;
    let file = root
        .open_read(Path::new(path))
        .map_err(|error| format!("screenshot {path} is unreadable: {error}"))?;
    let mut bytes = Vec::new();
    file.take(MAX_SHOT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("screenshot {path} is unreadable: {error}"))?;
    if bytes.len() as u64 > MAX_SHOT_BYTES {
        return Err(format!(
            "screenshot {path} is larger than {MAX_SHOT_BYTES} bytes"
        ));
    }
    view_jpeg(&bytes, TURN_IMAGE_BASE64).map_err(|cause| format!("screenshot {path}: {cause}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One red pixel.
    const PIXEL_PNG: &[u8] = &[
        137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1, 8, 2,
        0, 0, 0, 144, 119, 83, 222, 0, 0, 0, 12, 73, 68, 65, 84, 120, 156, 99, 248, 207, 192, 0, 0,
        3, 1, 1, 0, 201, 254, 146, 239, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
    ];

    fn run(stdout: &str) -> Captured {
        Captured {
            exit_code: Some(0),
            stdout: stdout.to_owned(),
            stderr: String::new(),
            stdout_truncated: false,
            changed: Vec::new(),
        }
    }

    #[test]
    fn error_json_becomes_unavailable_with_its_text() {
        let error = r#"{"error":"the dev command exited 3 before listening: boom"}"#;
        let refused = project(
            &Captured {
                exit_code: Some(2),
                ..run(error)
            },
            Path::new("/capsule"),
        );
        assert!(
            matches!(refused, Err(HostToolError::Unavailable { reason, .. })
            if reason == "the dev command exited 3 before listening: boom")
        );
    }

    #[test]
    fn shots_become_image_blocks_and_done_counts_errors() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join(".odin-eval/look-op");
        std::fs::create_dir_all(&dir).unwrap();
        for width in [390, 1280] {
            std::fs::write(dir.join(format!("look-{width}.png")), PIXEL_PNG).unwrap();
        }
        let page = loopback_page();
        let report = json!({
            "url": page,
            "shots": [
                {"width": 390, "title": "App", "path": ".odin-eval/look-op/look-390.png"},
                {"width": 1280, "title": "App", "path": ".odin-eval/look-op/look-1280.png"}
            ],
            "console": [
                {"width": 390, "type": "error", "text": "boom"},
                {"width": 390, "type": "warning", "text": "careful"},
                {"width": 1280, "type": "pageerror", "text": "boom"}
            ],
            "failed": [{"width": 390, "url": format!("{page}x.png"), "status": 404}]
        });
        let result = project(&run(&report.to_string()), root.path()).unwrap();
        assert_eq!(
            result["done"],
            format!("Looked at {page} at 390 and 1280 px: 2 console errors, 1 failed request.")
        );
        assert_eq!(result["images"].as_array().unwrap().len(), 2);
        assert_eq!(result["images"][0]["mimeType"], "image/jpeg");
        assert_eq!(result["shots"][1]["width"], 1280);
    }

    #[test]
    fn a_symlink_shot_path_is_not_read() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), PIXEL_PNG).unwrap();
        let dir = root.path().join(".odin-eval/look-op");
        std::fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.join("look-390.png")).unwrap();
        let report = json!({
            "url": loopback_page(),
            "shots": [{"width": 390, "title": "App", "path": ".odin-eval/look-op/look-390.png"}]
        });
        let refused = project(&run(&report.to_string()), root.path());
        assert!(
            matches!(&refused, Err(HostToolError::Unavailable { reason, .. }) if reason.contains("unreadable")),
            "{refused:?}"
        );
    }

    fn loopback_page() -> String {
        format!("http://{}:5173/", std::net::Ipv4Addr::LOCALHOST)
    }
}
