use std::fs::File;
use std::io::Read;
use std::num::NonZeroU64;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use super::DaemonHostFiles;
use odin_domain::huginn::{
    FileMediaPolicy, FileRoot, FileRootAccess, FileRootId, FileRootInit, FileWatchPolicy,
    RelativePath,
};
use odin_hermes::runtime::shared_files::{HostFileRoute, RootSource};

#[test]
fn worker_bootstrap_fixture_entry() {
    odin_process::test_support::run_bootstrap_if_active();
}

fn root(path: &std::path::Path, id: &str, host: &str) -> FileRoot {
    FileRoot::new(FileRootInit {
        root_id: FileRootId::parse(id).unwrap(),
        display_name: id.to_owned(),
        canonical_path: path.canonicalize().unwrap(),
        access: FileRootAccess::ReadWrite,
        media_policy: FileMediaPolicy {
            allowed_media_types: vec!["application/pdf".to_owned()],
        },
        max_object_bytes: NonZeroU64::new(128 * 1024 * 1024).unwrap(),
        watch_policy: FileWatchPolicy::Disabled,
        allowed_seats: vec!["sinmara".parse().unwrap()],
        host: Some(host.to_owned()),
        save_default: None,
    })
    .unwrap()
}

#[test]
fn offline_saves_survive_restart_wake_stream_and_only_then_close_unkept_sources() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path().canonicalize().unwrap();
    let pc = directory.join("pc");
    let laptop = directory.join("laptop");
    std::fs::create_dir_all(&pc).unwrap();
    std::fs::create_dir_all(&laptop).unwrap();
    let awake = directory.join("awake");
    let python = crate::test_fixture::on_path("python3").expect("python3 test helper");
    let executable = directory.join("ssh-fixture");
    // The far end is scripted; the production registered SSH transport still
    // carries binary stdin/stdout through independently drained bounded pipes.
    std::fs::write(&executable, format!(r#"#!{}
import sys, json, pathlib, shlex
if not pathlib.Path({:?}).exists(): sys.exit(255)
request = json.loads(shlex.split(sys.argv[-1])[2])
root = pathlib.Path(request['root']['canonicalPath'])
if 'save' in request:
    save = request['save']
    folder = root / (save.get('folder') or '')
    folder.mkdir(parents=True, exist_ok=True)
    name = save['name']
    path = folder / name
    index = 2
    while path.exists():
        path = folder / (pathlib.Path(name).stem + ' (' + str(index) + ')' + pathlib.Path(name).suffix)
        index += 1
    count = 0
    with path.open('xb') as output:
        while True:
            data = sys.stdin.buffer.read(65536)
            if not data: break
            output.write(data)
            count += len(data)
    print(json.dumps({{'saved':str(path.relative_to(root)), 'byteLen':count, 'digest':save['digest']}}))
elif 'stat' in request:
    print((root / (request['stat'] + '.metadata')).read_text())
elif 'read' in request:
    with (root / request['read']).open('rb') as source:
        while True:
            data = source.read(65536)
            if not data: break
            sys.stdout.buffer.write(data)
else: sys.exit(3)
"#, python.display(), awake.to_string_lossy())).unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
    let worker = odin_process::test_support::RegisteredWorkerFixture::new().unwrap();
    let channel = worker
        .channel_for_harness(
            &std::env::current_exe().unwrap(),
            "host_files::streaming_tests::worker_bootstrap_fixture_entry",
            &crate::test_fixture::on_path("unshare").unwrap(),
        )
        .unwrap();
    let binding = odin_process::RegisteredServiceBinding::new(
        executable.clone(),
        blake3::hash(&std::fs::read(&executable).unwrap())
            .to_hex()
            .to_string(),
    )
    .unwrap();
    let launch = odin_omp::process::OmpWorkerLaunch::new(
        Arc::new(odin_kernel::StopAuthority::new(
            Arc::new(std::sync::Mutex::new(
                odin_ledger::Ledger::open_in_memory().unwrap(),
            )),
            channel,
        )),
        odin_types::CorrelationId::new("0123456789abcdef0123456789abcdef").unwrap(),
        "odin-cli",
        "files-streaming",
        1,
        binding,
        odin_process::ScopeLimits::default(),
    )
    .unwrap();
    let published = crate::test_fixture::PublishedStore::new("laptop", true);
    let pin = Arc::new(odin_registry::SnapshotHandle::open(published.store()).unwrap());
    let roots = vec![
        root(&pc, "pc-downloads", "pc"),
        root(&laptop, "laptop-downloads", "laptop-host"),
    ];
    let make_route = || DaemonHostFiles {
        roots: roots.clone(),
        here: Some("pc".to_owned()),
        pin: Arc::clone(&pin),
        transport: crate::claude_host_transport::ClaudeHostTransport::new(
            launch.clone(),
            executable.clone(),
            directory.clone(),
        ),
        state_dir: directory.join("queue"),
        queue_gate: std::sync::Mutex::new(()),
    };
    let source_path = pc.join("original.pdf");
    let mut source = File::create(&source_path).unwrap();
    let size = 26 * 1024 * 1024 + 17;
    std::io::copy(&mut std::io::repeat(0x8e).take(size), &mut source).unwrap();
    drop(source);
    let mut source = File::open(&source_path).unwrap();
    let expected = super::queue::identity(&mut source).unwrap();
    let original = RootSource {
        root: "pc-downloads".to_owned(),
        path: "original.pdf".to_owned(),
        move_source: true,
        keep: false,
    };
    let route = make_route();
    let queued = route
        .save(
            "sinmara",
            Some("laptop-downloads"),
            Some("Business"),
            "original.pdf",
            &mut source,
            Some(&original),
        )
        .unwrap();
    assert_eq!(queued["status"], "queued");
    assert!(source_path.exists());
    assert!(!laptop.join("Business/original.pdf").exists());
    let id = queued["save_id"].as_str().unwrap();
    assert!(route.save_status("kubert", id).is_err());
    drop(route);
    drop(source);
    std::fs::write(&awake, "awake").unwrap();
    // Unreadable records in the queue never hold back the saves behind them.
    for index in 0..8 {
        std::fs::write(directory.join(format!("queue/corrupt-{index}.json")), "{").unwrap();
    }
    let route = make_route();
    route.retry_saves().unwrap();
    let completed = route.save_status("sinmara", id).unwrap();
    assert_eq!(completed["status"], "completed");
    assert_eq!(completed["sourceRetained"], false);
    assert!(!source_path.exists());
    let destination = laptop.join("Business/original.pdf");
    let mut saved = File::open(&destination).unwrap();
    assert_eq!(super::queue::identity(&mut saved).unwrap(), expected);
    // The same large destination can be shared back over raw binary stdout.
    let relative = RelativePath::parse("Business/original.pdf").unwrap();
    let (metadata, _) = odin_huginn::files::open_from_root(&roots[1], &relative).unwrap();
    std::fs::write(
        laptop.join("Business/original.pdf.metadata"),
        serde_json::to_vec(&serde_json::json!({"metadata":metadata})).unwrap(),
    )
    .unwrap();
    let (_, _, mut shared) = route
        .read("sinmara", "laptop-downloads", "Business/original.pdf")
        .unwrap();
    assert_eq!(super::queue::identity(&mut shared).unwrap(), expected);
    route.retry_saves().unwrap();
    assert!(
        !laptop.join("Business/original (2).pdf").exists(),
        "completed jobs are never delivered again"
    );
    // A kept source remains, including a later move request without keep.
    std::fs::write(pc.join("kept.pdf"), b"kept original").unwrap();
    let mut kept = File::open(pc.join("kept.pdf")).unwrap();
    let mut original = RootSource {
        path: "kept.pdf".to_owned(),
        keep: true,
        ..original
    };
    route
        .save(
            "sinmara",
            Some("pc-downloads"),
            None,
            "copy.pdf",
            &mut kept,
            Some(&original),
        )
        .unwrap();
    original.keep = false;
    let result = route
        .save(
            "sinmara",
            Some("pc-downloads"),
            None,
            "copy.pdf",
            &mut kept,
            Some(&original),
        )
        .unwrap();
    assert_eq!(result["sourceRetained"], true);
    assert_eq!(
        std::fs::read(pc.join("kept.pdf")).unwrap(),
        b"kept original"
    );
    assert_eq!(
        std::fs::read(pc.join("copy.pdf")).unwrap(),
        b"kept original"
    );
}
