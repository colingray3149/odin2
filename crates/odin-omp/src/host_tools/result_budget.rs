//! Enforces declared tool-result ceilings at the common model dispatch boundary.
//! UTF-8 byte length is the existing pinned conservative token upper bound:
//! it never undercounts an unsupported provider tokenizer. A result over its
//! ceiling spills whole to an artifact; only an `artifact_read` page is cut,
//! because the spill itself is read back through that tool.
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use odin_domain::{Scope, SeatId};
use odin_ledger::artifact::{AttachReference, NewArtifactReference, RetentionClass};
use odin_ledger::Ledger;
use serde_json::{json, Value};

use super::operations::ResultTransformer;

/// The compiled name of the tool that pages through artifact bytes.
const ARTIFACT_READ: &str = "artifact_read";

#[derive(Default)]
struct ByteCount(u64);
impl Write for ByteCount {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len() as u64);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The compact JSON size of `value`.
fn json_size(value: &(impl serde::Serialize + ?Sized)) -> Result<u64, String> {
    let mut count = ByteCount::default();
    serde_json::to_writer(&mut count, value).map_err(|error| error.to_string())?;
    Ok(count.0)
}

pub fn transformer(
    budgets: BTreeMap<SeatId, u32>,
    root: PathBuf,
    ledger: Arc<Mutex<Ledger>>,
) -> ResultTransformer {
    Arc::new(move |scope, tool, result| {
        let Some(budget) = scope.seat.as_ref().and_then(|seat| budgets.get(seat)) else {
            return Ok(result);
        };
        let result = if tool == ARTIFACT_READ {
            clamp_page(result, *budget)?
        } else {
            result
        };
        enforce(scope, result, *budget, &root, &ledger)
    })
}

/// Cuts an artifact page to the budget instead of spilling it: a spilled page
/// is read back as another page of the same size, which spills again. The cut
/// is at a character boundary for text and a quad boundary for base64, and
/// `next_offset` names the first byte left unread.
fn clamp_page(mut page: Value, budget: u32) -> Result<Value, String> {
    let total = json_size(&page)?;
    if total <= u64::from(budget) {
        return Ok(page);
    }
    let Some(fields) = page.as_object_mut() else {
        return Ok(page);
    };
    let Some(key) = ["text", "base64"]
        .into_iter()
        .find(|key| fields.get(*key).is_some_and(Value::is_string))
    else {
        return Ok(page);
    };
    let (Some(offset), Some(body)) = (
        fields.get("offset").and_then(Value::as_u64),
        fields[key].as_str(),
    ) else {
        return Ok(page);
    };
    // What the body may spend: the budget less every other field of the page
    // and the one byte `eof` gains by turning false.
    let room = u64::from(budget).saturating_sub(total - json_size(body)? + 1);
    let (kept, bytes) = if key == "text" {
        let kept = fit_text(body, room);
        (kept, kept)
    } else {
        // Four base64 characters carry three bytes.
        let fits = usize::try_from(room.saturating_sub(2)).unwrap_or(usize::MAX);
        let kept = body.len().min(fits) / 4 * 4;
        (kept, kept / 4 * 3)
    };
    // A budget too small for even one character cuts nothing and spills instead.
    if bytes == 0 {
        return Ok(page);
    }
    let body = Value::String(body[..kept].to_owned());
    fields.insert(key.to_owned(), body);
    fields.insert("sizeBytes".to_owned(), json!(bytes));
    fields.insert("next_offset".to_owned(), json!(offset + bytes as u64));
    fields.insert("eof".to_owned(), json!(false));
    Ok(page)
}

/// The longest prefix of `text`, ending between characters, whose JSON string
/// form (quotes and escapes included) fits in `room` bytes.
fn fit_text(text: &str, room: u64) -> usize {
    let mut used = 2;
    let mut kept = 0;
    for (at, c) in text.char_indices() {
        used += match c {
            '"' | '\\' | '\n' | '\r' | '\t' | '\u{8}' | '\u{c}' => 2,
            c if c < ' ' => 6,
            c => c.len_utf8() as u64,
        };
        if used > room {
            break;
        }
        kept = at + c.len_utf8();
    }
    kept
}

/// An error mapper that names the step of the spill that failed.
fn cannot<E: std::fmt::Display>(step: &'static str) -> impl Fn(E) -> String {
    move |error| format!("cannot {step}: {error}")
}

fn enforce(
    scope: &Scope,
    result: Value,
    budget: u32,
    root: &std::path::Path,
    ledger: &Mutex<Ledger>,
) -> Result<Value, String> {
    // Image blocks ride the tool result outside the text budget: taking them
    // out first keeps base64 data from spilling the result as JSON text
    // before the side channel can attach them as image blocks.
    let mut result = result;
    let images = take_images(&mut result);
    let size = json_size(&result)?;
    if size <= u64::from(budget) {
        return Ok(reattach_images(result, images));
    }
    let directory = root.join("tool-results");
    std::fs::create_dir_all(&directory).map_err(cannot("create the tool-results directory"))?;
    let mut staging =
        tempfile::NamedTempFile::new_in(&directory).map_err(cannot("stage the spilled result"))?;
    serde_json::to_writer(staging.as_file_mut(), &result)
        .map_err(cannot("write the spilled result"))?;
    staging
        .as_file()
        .sync_all()
        .map_err(cannot("sync the spilled result"))?;
    let storage_path = format!("tool-results/{}.json", uuid::Uuid::new_v4());
    let destination = root.join(&storage_path);
    let mut file = staging
        .persist_noclobber(&destination)
        .map_err(cannot("store the spilled result"))?;
    std::fs::File::open(&directory)
        .and_then(|file| file.sync_all())
        .map_err(cannot("sync the tool-results directory"))?;
    let mut ledger = ledger.lock().map_err(cannot("lock the artifact ledger"))?;
    let mut metadata = ledger
        .register_artifact_file(
            &mut file,
            "application/json",
            &storage_path,
            RetentionClass::Canonical,
            time::OffsetDateTime::now_utc(),
        )
        .map_err(cannot("register the spilled result as an artifact"))?;
    if metadata.storage_path != storage_path {
        // Digest deduplication keeps the pre-existing original, never removes it.
        std::fs::remove_file(&destination).map_err(cannot("remove the duplicate spill"))?;
    }
    let mut references = Vec::with_capacity(2);
    if let Some(seat) = &scope.seat {
        references.push(("seat", seat.to_string()));
    }
    if let Some(project) = &scope.project {
        references.push(("project", project.to_string()));
    }
    for (kind, id) in references {
        metadata = match ledger
            .attach_artifact_reference(
                &metadata.artifact_id,
                metadata.revision,
                NewArtifactReference {
                    object_kind: kind,
                    object_id: &id,
                    relation: "readable",
                    created_at: time::OffsetDateTime::now_utc(),
                },
            )
            .map_err(cannot("attach the artifact reference"))?
        {
            AttachReference::Added(metadata) | AttachReference::Existing(metadata) => metadata,
        };
    }
    let mut replacement = json!({
        "artifact":metadata.artifact_id.to_string(), "totalBytes":size, "spilled":true,
        "mediaType":"application/json", "note":"Complete tool result; page it with files {op: \"artifact\", artifactId, offset, limit}.",
    });
    // Transport acknowledgement still needs the existing delegation receipt
    // identity after its large answer has moved out of the inline frame.
    if result["status"] == "settled" {
        for key in ["status", "session", "answer_key"] {
            if let Some(value) = result.get(key).filter(|value| value.is_string()) {
                replacement[key] = value.clone();
            }
        }
    }
    if json_size(&replacement)? > u64::from(budget) {
        return Err(format!(
            "tool_result_tokens={budget} cannot hold the spilled artifact reference {}",
            metadata.artifact_id
        ));
    }
    Ok(reattach_images(replacement, images))
}

/// Takes a result's `images` out for budgeting: an `images` array of image
/// blocks (OMP `ImageContent`) is never counted or spilled as text. Anything
/// else under `images` stays ordinary data.
fn take_images(result: &mut Value) -> Vec<Value> {
    let is_image = |block: &Value| {
        block.get("type").and_then(Value::as_str) == Some("image")
            && block.get("data").is_some_and(Value::is_string)
            && block.get("mimeType").is_some_and(Value::is_string)
    };
    let all_images = result
        .get("images")
        .and_then(Value::as_array)
        .is_some_and(|images| images.iter().all(is_image));
    if !all_images {
        return Vec::new();
    }
    match result
        .as_object_mut()
        .and_then(|object| object.remove("images"))
    {
        Some(Value::Array(images)) => images,
        _ => Vec::new(),
    }
}

/// Puts image blocks back on whichever result the boundary returns, so no
/// image data is lost to budget enforcement.
fn reattach_images(mut result: Value, images: Vec<Value>) -> Value {
    if images.is_empty() {
        return result;
    }
    if let Some(object) = result.as_object_mut() {
        object.insert("images".to_owned(), Value::Array(images));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_at_ceiling_is_inline_and_larger_result_spills_without_loss() {
        let directory = tempfile::tempdir().unwrap();
        let ledger = Mutex::new(Ledger::open(directory.path().join("ledger.sqlite3")).unwrap());
        let scope = Scope {
            seat: Some(SeatId::new("sinmara").unwrap()),
            ..Scope::default()
        };
        let boundary = json!({"text":"x".repeat(6133)});
        assert_eq!(serde_json::to_vec(&boundary).unwrap().len(), 6144);
        assert_eq!(
            enforce(&scope, boundary.clone(), 6144, directory.path(), &ledger).unwrap(),
            boundary
        );
        let large = json!({"text":"€😀".repeat(200_000),"tail":"complete end",
            "status":"settled","session":"child-session","answer_key":"receipt-key"});
        let spilled = enforce(&scope, large.clone(), 6144, directory.path(), &ledger).unwrap();
        assert_eq!(spilled["spilled"], true);
        assert_eq!(spilled["status"], "settled");
        assert_eq!(spilled["session"], "child-session");
        assert_eq!(spilled["answer_key"], "receipt-key");
        let id = odin_domain::ArtifactId::new(spilled["artifact"].as_str().unwrap()).unwrap();
        let metadata = ledger.lock().unwrap().artifact(&id).unwrap().unwrap();
        let bytes = std::fs::read(directory.path().join(metadata.storage_path)).unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), large);
        assert_eq!(bytes.len() as u64, spilled["totalBytes"].as_u64().unwrap());
        assert_eq!(metadata.retention, RetentionClass::Canonical);
        assert_eq!(
            ledger.lock().unwrap().artifact_references(&id).unwrap()[0].object_id,
            "sinmara"
        );
    }

    /// The transformer spills only for a seat with a declared budget, and spilling the same result
    /// twice names one artifact whose file still exists.
    #[test]
    fn only_a_budgeted_seat_spills_and_a_repeated_spill_keeps_its_file() {
        let directory = tempfile::tempdir().unwrap();
        let ledger = Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()));
        let seat = |name: &str| Scope {
            seat: Some(SeatId::new(name).unwrap()),
            ..Scope::default()
        };
        let transform = transformer(
            BTreeMap::from([(SeatId::new("sinmara").unwrap(), 6144)]),
            directory.path().to_path_buf(),
            Arc::clone(&ledger),
        );
        let large = json!({"text": "x".repeat(20_000)});
        assert_eq!(
            transform(&seat("gungnir"), "any_tool", large.clone()).unwrap(),
            large,
            "a seat with no declared budget is never spilled"
        );
        let first = transform(&seat("sinmara"), "any_tool", large.clone()).unwrap();
        let second = transform(&seat("sinmara"), "any_tool", large.clone()).unwrap();
        assert_eq!(first["spilled"], true);
        assert_eq!(first["artifact"], second["artifact"]);
        let id = odin_domain::ArtifactId::new(first["artifact"].as_str().unwrap()).unwrap();
        let stored = ledger.lock().unwrap().artifact(&id).unwrap().unwrap();
        assert!(directory.path().join(stored.storage_path).is_file());
        let files = std::fs::read_dir(directory.path().join("tool-results"))
            .unwrap()
            .count();
        assert_eq!(files, 1, "the repeated spill left no second copy");
    }
}

#[cfg(test)]
mod page_tests {
    use super::*;
    use base64::Engine as _;

    const BUDGET: u32 = 1024;

    /// A page as `artifact_read` returns it: `limit` bytes from `offset`.
    fn page(bytes: &[u8], offset: usize, text: bool) -> Value {
        let mut end = (offset + 4096).min(bytes.len());
        while text && std::str::from_utf8(&bytes[offset..end]).is_err() {
            end -= 1;
        }
        let chunk = &bytes[offset..end];
        let mut page = json!({"artifactId":"blake3:a1", "sizeBytes":chunk.len(), "mediaType":"text/plain",
            "offset":offset, "next_offset":end, "eof":end == bytes.len(), "totalBytes":bytes.len()});
        if text {
            page["text"] = json!(std::str::from_utf8(chunk).unwrap());
        } else {
            page["base64"] = json!(base64::engine::general_purpose::STANDARD.encode(chunk));
        }
        page
    }

    #[test]
    fn an_artifact_is_read_through_in_pages_that_fit_the_budget_without_spilling() {
        let directory = tempfile::tempdir().unwrap();
        let ledger = Arc::new(Mutex::new(
            Ledger::open(directory.path().join("ledger.sqlite3")).unwrap(),
        ));
        let seat = SeatId::new("sinmara").unwrap();
        let transform = transformer(
            BTreeMap::from([(seat.clone(), BUDGET)]),
            directory.path().to_owned(),
            ledger,
        );
        let scope = Scope {
            seat: Some(seat),
            ..Scope::default()
        };
        let words = "α😀€ \"quoted\"\n".repeat(1500);
        let binary: Vec<u8> = (0..=255).cycle().take(20_000).collect();
        for (original, text) in [(words.as_bytes(), true), (binary.as_slice(), false)] {
            let mut restored = Vec::new();
            let mut offset = 0;
            while offset < original.len() {
                let read =
                    transform(&scope, "artifact_read", page(original, offset, text)).unwrap();
                assert_ne!(read["spilled"], true, "{read}");
                assert!(serde_json::to_vec(&read).unwrap().len() <= BUDGET as usize);
                let bytes = match text {
                    true => read["text"].as_str().unwrap().as_bytes().to_vec(),
                    false => base64::engine::general_purpose::STANDARD
                        .decode(read["base64"].as_str().unwrap())
                        .unwrap(),
                };
                assert_eq!(read["sizeBytes"].as_u64(), Some(bytes.len() as u64));
                assert_eq!(
                    read["next_offset"].as_u64(),
                    Some((offset + bytes.len()) as u64)
                );
                assert_eq!(read["eof"], offset + bytes.len() == original.len());
                restored.extend_from_slice(&bytes);
                offset += bytes.len();
            }
            assert_eq!(restored, original);
        }
        // Any other tool's result of that size still spills whole.
        let spilled = transform(&scope, "files", page(words.as_bytes(), 0, true)).unwrap();
        assert_eq!(spilled["spilled"], true);
    }
}

#[cfg(test)]
mod image_tests {
    use super::*;

    #[test]
    fn image_blocks_survive_inline_and_spilled_results() {
        let directory = tempfile::tempdir().unwrap();
        let ledger = Mutex::new(Ledger::open(directory.path().join("ledger.sqlite3")).unwrap());
        let scope = Scope::default();
        let image = json!({"type":"image","mimeType":"image/jpeg","data":"QUJD"});
        // Inline: the image data does not count toward the text budget, so a
        // result over the ceiling only through its images stays inline intact.
        let inline = json!({"viewed":"IMG_1.jpg","images":[image.clone()]});
        let inline_budget = serde_json::to_vec(&json!({"viewed":"IMG_1.jpg"}))
            .unwrap()
            .len() as u32;
        assert_eq!(
            enforce(
                &scope,
                inline.clone(),
                inline_budget,
                directory.path(),
                &ledger
            )
            .unwrap(),
            inline
        );
        // Spilled: large text forces a spill; the image block comes back on
        // the replacement frame with its data intact, and the artifact holds
        // the complete text result.
        let big = json!({"type":"image","mimeType":"image/png","data":"A".repeat(5000)});
        let large = json!({"text":"x".repeat(20_000),"images":[big.clone()]});
        let spilled = enforce(&scope, large.clone(), 6144, directory.path(), &ledger).unwrap();
        assert_eq!(spilled["spilled"], true);
        assert_eq!(spilled["images"], json!([big]));
        let id = odin_domain::ArtifactId::new(spilled["artifact"].as_str().unwrap()).unwrap();
        let metadata = ledger.lock().unwrap().artifact(&id).unwrap().unwrap();
        let bytes = std::fs::read(directory.path().join(metadata.storage_path)).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap(),
            json!({"text":"x".repeat(20_000)})
        );
        assert_eq!(bytes.len() as u64, spilled["totalBytes"].as_u64().unwrap());
    }
}

#[cfg(test)]
mod pod_tests {}
