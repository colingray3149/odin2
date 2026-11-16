use std::io::{Seek, SeekFrom, Write};

use base64::Engine;
use odin_domain::Scope;
use odin_hermes::runtime::coding::CodingRoute;
use serde_json::Value;

use super::DaemonCodingRoute;

fn route(root: &std::path::Path) -> DaemonCodingRoute {
    DaemonCodingRoute {
        state_root: root.to_owned(),
        session_pool: None,
        supervisor: std::sync::Weak::new(),
        projects: Default::default(),
        registry: None,
        manifest: None,
        merge_lock_bound: crate::coding_route::MERGE_LOCK_BOUND,
    }
}

fn page_bytes(page: &Value) -> Vec<u8> {
    if let Some(text) = page["text"].as_str() {
        text.as_bytes().to_vec()
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(page["base64"].as_str().unwrap())
            .unwrap()
    }
}

#[test]
fn artifact_pages_reassemble_every_byte_including_utf8_splits_and_binary() {
    let directory = tempfile::tempdir().unwrap();
    let route = route(directory.path());
    let scope = Scope {
        seat: Some("sinmara".parse().unwrap()),
        ..Scope::default()
    };
    for original in [
        "α😀€".repeat(100_000).into_bytes(),
        (0..=255).cycle().take(300_001).collect(),
    ] {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&original).unwrap();
        let id = route
            .share_file(&scope, &mut file, "application/octet-stream")
            .unwrap();
        let mut restored = Vec::new();
        let mut offset = 0;
        loop {
            let page = route
                .read_artifact(&scope, id.clone(), offset, 4093)
                .unwrap();
            assert_eq!(page["offset"].as_u64(), Some(offset));
            assert_eq!(page["totalBytes"].as_u64(), Some(original.len() as u64));
            let bytes = page_bytes(&page);
            assert!(bytes.len() <= 4093);
            restored.extend_from_slice(&bytes);
            let next = page["next_offset"].as_u64().unwrap();
            assert_eq!(next, offset + bytes.len() as u64);
            if page["eof"] == true {
                assert_eq!(next, original.len() as u64);
                break;
            }
            assert!(next > offset);
            offset = next;
        }
        assert_eq!(restored, original);
        for offset in [original.len() as u64, u64::MAX] {
            let page = route.read_artifact(&scope, id.clone(), offset, 1).unwrap();
            assert_eq!(page["eof"], true);
            assert_eq!(page["next_offset"].as_u64(), Some(original.len() as u64));
            assert!(page_bytes(&page).is_empty());
        }
        assert!(route.read_artifact(&scope, id.clone(), 0, 0).is_err());
        assert!(route
            .read_artifact(&scope, id.clone(), 0, super::MAX_ARTIFACT_PAGE_BYTES + 1)
            .is_err());
        let stranger = Scope {
            seat: Some("kubert".parse().unwrap()),
            ..Scope::default()
        };
        assert!(route.artifact_file(&stranger, &id).is_err());
        assert!(route.read_artifact(&stranger, id, 0, 4096).is_err());
    }
}

#[test]
fn streaming_keeps_complete_large_artifacts_and_refuses_corrupt_originals() {
    let directory = tempfile::tempdir().unwrap();
    let route = route(directory.path());
    let scope = Scope {
        seat: Some("sinmara".parse().unwrap()),
        ..Scope::default()
    };
    let mut source = tempfile::tempfile().unwrap();
    let length = 26 * 1024 * 1024 + 7;
    std::io::copy(
        &mut std::io::Read::take(std::io::repeat(0xb2), length),
        &mut source,
    )
    .unwrap();
    let id = route
        .share_file(&scope, &mut source, "application/pdf")
        .unwrap();
    let (mut stored, media) = route.artifact_file(&scope, &id).unwrap();
    assert_eq!(media, "application/pdf");
    assert_eq!(stored.metadata().unwrap().len(), length);
    let hash = |file: &mut std::fs::File| {
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut hash = blake3::Hasher::new();
        hash.update_reader(file).unwrap();
        hash.finalize()
    };
    assert_eq!(hash(&mut source), hash(&mut stored));
    let metadata = route
        .ledger()
        .unwrap()
        .artifact(&super::controller_artifact_id(&id).unwrap())
        .unwrap()
        .unwrap();
    let mut corrupt = std::fs::OpenOptions::new()
        .write(true)
        .open(route.artifact_root().join(metadata.storage_path))
        .unwrap();
    corrupt.seek(SeekFrom::Start(length - 1)).unwrap();
    corrupt.write_all(b"x").unwrap();
    assert!(route.read_artifact(&scope, id.clone(), 0, 4096).is_err());
    assert!(route.artifact_file(&scope, &id).is_err());
    assert_eq!(source.metadata().unwrap().len(), length);
}

#[test]
fn a_readable_original_can_be_handed_to_a_child_project_and_reported_back() {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use odin_hermes::runtime::{HermesLedgers, HermesRuntime};
    use odin_omp::host_tools::HostInvocation;
    use serde_json::json;

    let directory = tempfile::tempdir().unwrap();
    let route = Arc::new(route(directory.path()));
    let owner = Scope {
        seat: Some("sinmara".parse().unwrap()),
        ..Scope::default()
    };
    let child = Scope {
        seat: Some("gungnir".parse().unwrap()),
        project: Some("orbit".parse().unwrap()),
        session: Some("child-session".parse().unwrap()),
        ..Scope::default()
    };
    let stranger = Scope {
        seat: Some("kubert".parse().unwrap()),
        project: Some("other".parse().unwrap()),
        ..Scope::default()
    };
    let original =
        br#"{"messages":[{"content":"2 https://merchant/item 2 https://merchant/item"}]}"#;
    let id = route
        .share_bytes(&owner, original, "application/json")
        .unwrap();
    assert!(route.artifact_file(&child, &id).is_err());
    let runtime = HermesRuntime::open(
        odin_hermes::config::HermesSettings::new(
            directory.path().join("hermes"),
            None,
            None,
            Vec::new(),
        )
        .unwrap(),
        HermesLedgers {
            conversation: odin_ledger::Ledger::open_in_memory().unwrap(),
            adapter: Arc::new(parking_lot::Mutex::new(
                odin_ledger::Ledger::open_in_memory().unwrap(),
            )),
            purchase: Arc::new(Mutex::new(odin_ledger::Ledger::open_in_memory().unwrap())),
        },
        &BTreeMap::new(),
        None,
        8192,
        BTreeMap::new(),
        None,
    )
    .unwrap();
    runtime.set_coding_route(route.clone());
    let tools = odin_hermes::runtime::hermes_host_tools(&runtime);
    let forward = tools
        .iter()
        .find(|tool| tool.definition().name == "artifact_write")
        .unwrap();
    let request = json!({"artifactId": id, "shareWith": ["project:orbit"]});
    assert!(forward
        .invoke(HostInvocation {
            scope: stranger.clone(),
            arguments: request.clone(),
        })
        .is_err());
    let shared = forward
        .invoke(HostInvocation {
            scope: owner.clone(),
            arguments: request,
        })
        .expect("a readable original can be shared without a workspace or inline copy");
    assert_eq!(shared["artifactId"], id);
    assert_eq!(
        route.artifact_bytes(&child, &id, 4096).unwrap(),
        (original.to_vec(), "application/json".to_owned())
    );
    assert!(route.artifact_file(&stranger, &id).is_err());
    assert!(forward
        .invoke(HostInvocation {
            scope: stranger.clone(),
            arguments: json!({"artifactId": id, "shareWith": ["kubert"]}),
        })
        .is_err());
    assert!(route.artifact_file(&stranger, &id).is_err());
    let report = forward.invoke(HostInvocation {
        scope: child,
        arguments: json!({"text": "Two links; stated quantity 2 each.", "shareWith": ["sinmara"]}),
    }).unwrap();
    let report_id = report["artifactId"].as_str().unwrap();
    assert_eq!(
        route.artifact_bytes(&owner, report_id, 4096).unwrap().0,
        b"Two links; stated quantity 2 each."
    );
    assert!(route.artifact_file(&stranger, report_id).is_err());
}

#[test]
fn a_pod_export_path_is_refused_with_how_to_hand_it_over() {
    let directory = tempfile::tempdir().unwrap();
    let route = route(directory.path());
    let scope = Scope {
        session: Some("pod-session".parse().unwrap()),
        ..Scope::default()
    };
    let workspace = directory
        .path()
        .join("session-authorities/capsule-capsule-pod-session/capsule/project");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::write(workspace.join("report.md"), b"# Report").unwrap();
    assert_eq!(
        route.workspace_file(&scope, "report.md").unwrap(),
        b"# Report"
    );
    let error = route
        .workspace_file(&scope, "/export/report.md")
        .unwrap_err();
    assert!(error.contains("until its run settles"), "{error}");
    assert!(error.contains("pass the text"), "{error}");
}
