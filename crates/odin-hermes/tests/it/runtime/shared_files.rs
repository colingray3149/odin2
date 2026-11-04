//! `files_list` and `files_share`: a seat reads the owner's declared folders and is handed a file as an artifact with its text.

use crate::runtime::fixtures::{gate_runtime, tool_named};
use odin_domain::Scope;
use odin_hermes::runtime::coding::{CodingRoute, NixVerb, ProposalFailure};
use odin_hermes::runtime::shared_files::HostFileRoute;
use odin_omp::host_tools::HostInvocation;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;

/// One declared root, `downloads`, over a real folder.
struct Downloads(PathBuf);

impl HostFileRoute for Downloads {
    fn roots(&self, _seat: &str) -> Vec<Value> {
        vec![json!({ "root": "downloads", "host": "pc", "name": "Downloads" })]
    }

    fn list(
        &self,
        _seat: &str,
        root: &str,
        _directory: Option<&str>,
        find: Option<&str>,
    ) -> Result<(Vec<Value>, bool), String> {
        assert_eq!(root, "downloads");
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(&self.0).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if find.is_none_or(|find| name.contains(find)) {
                entries.push(json!({ "path": name, "kind": "file" }));
            }
        }
        Ok((entries, false))
    }

    fn read(
        &self,
        _seat: &str,
        _root: &str,
        path: &str,
    ) -> Result<(String, String, std::fs::File), String> {
        let file = std::fs::File::open(self.0.join(path))
            .map_err(|_| format!("{path} is not in the downloads folder"))?;
        Ok((path.to_owned(), "text/plain".to_owned(), file))
    }

    fn save(
        &self,
        _: &str,
        _: Option<&str>,
        _: Option<&str>,
        _: &str,
        _: &mut std::fs::File,
        _: Option<&odin_hermes::runtime::shared_files::RootSource>,
    ) -> Result<Value, String> {
        unreachable!("sharing saves nothing")
    }

    fn save_status(&self, _: &str, _: &str) -> Result<Value, String> {
        unreachable!("sharing saves nothing")
    }
}

/// The artifacts a seat's sharing stored, in order.
#[derive(Default)]
struct Shelf(Mutex<Vec<Vec<u8>>>);

impl CodingRoute for Shelf {
    fn nix(
        &self,
        _: &odin_kernel::operation::PreparedEffect,
        _: &Scope,
        _: NixVerb,
        _: Option<String>,
    ) -> Result<Value, String> {
        unreachable!("sharing runs no Nix")
    }

    fn propose(
        &self,
        _: &odin_kernel::operation::PreparedEffect,
        _: &Scope,
        _: String,
        _: Option<String>,
    ) -> Result<Value, ProposalFailure> {
        unreachable!("sharing publishes no code")
    }

    fn share_bytes(&self, _: &Scope, bytes: &[u8], _: &str) -> Result<String, String> {
        let mut shelf = self.0.lock();
        shelf.push(bytes.to_vec());
        Ok(format!("blake3:{:064x}", shelf.len()))
    }
}

#[test]
fn a_seat_lists_the_declared_folders_and_shares_one_file_with_its_text() {
    let dir = tempfile::tempdir().unwrap();
    let downloads = dir.path().join("downloads");
    std::fs::create_dir(&downloads).unwrap();
    std::fs::write(downloads.join("syllabus.txt"), "Week 1: statics").unwrap();
    std::fs::write(downloads.join("holiday.jpg"), "not text").unwrap();
    let runtime = gate_runtime(dir.path());
    let shelf = Arc::new(Shelf::default());
    runtime.set_host_file_route(Arc::new(Downloads(downloads)));
    runtime.set_coding_route(shelf.clone());
    let as_seat = |tool: &str, arguments: Value| {
        tool_named(&runtime, tool).invoke(HostInvocation {
            scope: Scope {
                seat: Some("sinmara".parse().unwrap()),
                ..Scope::default()
            },
            arguments,
        })
    };

    let roots = as_seat("files_list", json!({})).unwrap();
    assert_eq!(roots["roots"][0]["root"], "downloads");
    let found = as_seat(
        "files_list",
        json!({ "root": "downloads", "find": "syllabus" }),
    )
    .unwrap();
    assert_eq!(
        found["entries"],
        json!([{ "path": "syllabus.txt", "kind": "file" }])
    );

    let shared = as_seat(
        "files_share",
        json!({ "root": "downloads", "path": "syllabus.txt" }),
    )
    .unwrap();
    assert_eq!(shared["text"], "Week 1: statics");
    assert_eq!(shared["path"], "syllabus.txt");
    assert!(shared["artifact"].as_str().unwrap().starts_with("blake3:"));
    assert_eq!(shelf.0.lock().as_slice(), [b"Week 1: statics".to_vec()]);

    let missing = as_seat(
        "files_share",
        json!({ "root": "downloads", "path": "gone.txt" }),
    )
    .unwrap_err()
    .to_string();
    assert!(
        missing.contains("gone.txt is not in the downloads folder"),
        "{missing}"
    );

    let unbound = tool_named(&runtime, "files_share")
        .invoke(HostInvocation {
            scope: Scope::default(),
            arguments: json!({ "root": "downloads", "path": "syllabus.txt" }),
        })
        .unwrap_err()
        .to_string();
    assert!(unbound.contains("a bound seat is required"), "{unbound}");
}
