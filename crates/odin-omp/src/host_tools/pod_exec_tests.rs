use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use odin_domain::{CapabilityId, RunId, Scope, SessionId};
use odin_kernel::{CapabilityContract, HandlerBinding};
use serde_json::json;

use super::*;
use crate::host_tools::fixtures::fixture_contract;

/// Records every exec it is asked for and answers with the queued outputs.
#[derive(Default)]
struct RecordingExec {
    calls: Mutex<Vec<(RunId, Vec<String>)>>,
    stdins: Mutex<Vec<Option<Vec<u8>>>>,
    outputs: Mutex<Vec<WorkerOutput>>,
}

impl PodWorkerExec for RecordingExec {
    fn exec(
        &self,
        run: &RunId,
        argv: &[String],
        stdin: Option<&[u8]>,
        _wait: Duration,
        _tail_bytes: usize,
    ) -> Result<WorkerOutput, WorkerExecFault> {
        self.calls.lock().push((run.clone(), argv.to_vec()));
        self.stdins.lock().push(stdin.map(<[u8]>::to_vec));
        Ok(self.outputs.lock().remove(0))
    }
}

fn output(exit_code: i32, stdout: &str) -> WorkerOutput {
    WorkerOutput {
        exit_code,
        stdout_tail: stdout.as_bytes().to_vec(),
        stderr_tail: Vec::new(),
        stdout_bytes: stdout.len() as u64,
        stderr_bytes: 0,
    }
}

fn contract() -> CapabilityContract {
    let mut contract = fixture_contract();
    contract.id = CapabilityId::new("pod.probe").unwrap();
    contract.handler = HandlerBinding::Builtin {
        name: POD_EXEC_HANDLER_ID.to_owned(),
    };
    contract.timeout_seconds = std::num::NonZeroU32::new(600).unwrap();
    contract
}

fn run_id() -> RunId {
    "run:live:pod-session:pod:research".parse().unwrap()
}

fn tool(exec: Arc<RecordingExec>) -> PodExecTool {
    let spec: PodExecToml = toml::from_str(
        r#"
executable = "/bin/probe-tool"
argv = ["-d", "{domain}", "-f", "/export/harvest"]
options = { limit = "-l" }
"#,
    )
    .unwrap();
    PodExecTool::new(PodExecBinding {
        specs: BTreeMap::from([(contract().id, spec)]),
        pods: bound_pod(),
        exec,
        web_save: None,
        research: None,
    })
}

fn direct_target() -> PodTarget {
    PodTarget {
        run: run_id(),
        export_dir: "/export".to_owned(),
        network_transport: odin_registry::WorkloadTransport::Direct,
    }
}

fn bound_pod() -> Arc<PodSessions> {
    let pods = Arc::new(PodSessions::default());
    pods.bind(SessionId::new("pod-session").unwrap(), direct_target());
    pods
}

/// The shipped web.save declaration and its contract.
fn web_save() -> (CapabilityContract, PodExecToml) {
    let declared: odin_registry::schema::CapabilityToml = toml::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../registry/capabilities/web.save/capability.toml"),
        )
        .expect("shipped capability"),
    )
    .expect("capability toml");
    let mut contract = contract();
    contract.id = CapabilityId::new("web.save").unwrap();
    contract.timeout_seconds = declared.timeout_seconds;
    (contract, declared.exec.expect("[exec]"))
}

fn scope(session: &str) -> Scope {
    Scope {
        session: Some(SessionId::new(session).unwrap()),
        ..Scope::default()
    }
}

#[test]
fn a_session_that_is_not_a_workload_pod_is_refused_before_anything_runs() {
    let exec = Arc::new(RecordingExec::default());
    let tool = tool(Arc::clone(&exec));
    let arguments = json!({"domain": "example.com"});
    for refused in [
        tool.preflight(&contract(), &scope("sinmara-session"), &arguments),
        tool.run(&contract(), &scope("sinmara-session"), &arguments)
            .map(|_| ()),
        tool.run(&contract(), &Scope::default(), &arguments)
            .map(|_| ()),
    ] {
        let error = refused.expect_err("not a pod").to_string();
        assert!(error.contains("runs only inside a workload pod"), "{error}");
    }
    assert!(exec.calls.lock().is_empty(), "nothing ran");
}

#[test]
fn a_vpn_required_capability_cannot_escape_through_a_direct_pod() {
    let exec = Arc::new(RecordingExec::default());
    let mut tool = tool(Arc::clone(&exec));
    tool.binding
        .specs
        .get_mut(&contract().id)
        .unwrap()
        .transport = odin_registry::WorkloadTransport::VpnRequired;
    let arguments = json!({"domain": "example.com"});
    for result in [
        tool.preflight(&contract(), &scope("pod-session"), &arguments),
        tool.run(&contract(), &scope("pod-session"), &arguments)
            .map(|_| ()),
    ] {
        assert!(matches!(result, Err(HostToolError::Scope { .. })));
    }
    assert!(exec.calls.lock().is_empty());
}

#[test]
fn a_flag_like_value_and_a_missing_tool_are_refused_by_name() {
    let exec = Arc::new(RecordingExec::default());
    let tool = tool(Arc::clone(&exec));
    let error = tool
        .preflight(&contract(), &scope("pod-session"), &json!({"domain": "-h"}))
        .expect_err("flag-like value")
        .to_string();
    assert!(
        error.contains("pod.probe") && error.contains("\"domain\""),
        "{error}"
    );
    assert!(exec.calls.lock().is_empty());

    *exec.outputs.lock() = vec![output(127, "")];
    let error = tool
        .run(
            &contract(),
            &scope("pod-session"),
            &json!({"domain": "example.com"}),
        )
        .expect_err("tool absent from the image")
        .to_string();
    assert!(
        error.contains(
            "`/bin/probe-tool` is not in the pod image; add its package to nix/pod-tools.nix"
        ),
        "{error}"
    );
}

#[test]
fn a_failed_fetch_never_writes_to_the_pod() {
    let stubs = tempfile::tempdir().expect("stub dir");
    let fetcher = stubs.path().join("web-save");
    // A fetch failure must stop before the in-pod write.
    std::fs::write(
        &fetcher,
        "#!/bin/sh\necho 'the page answered HTTP 404' >&2\nexit 66\n",
    )
    .expect("stub");
    std::fs::set_permissions(
        &fetcher,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .expect("executable");
    let (contract, spec) = web_save();
    let exec = Arc::new(RecordingExec::default());
    let tool = PodExecTool::new(PodExecBinding {
        specs: BTreeMap::from([(contract.id.clone(), spec)]),
        pods: bound_pod(),
        exec: Arc::clone(&exec) as Arc<dyn PodWorkerExec>,
        web_save: Some(fetcher),
        research: None,
    });
    let refused = tool
        .run(
            &contract,
            &scope("pod-session"),
            &json!({"url": "https://a.example/missing.pdf", "path": "/export/a.pdf"}),
        )
        .expect_err("a missing page is refused")
        .to_string();
    assert!(
        refused.contains("web.save: https://a.example/missing.pdf: the page answered HTTP 404"),
        "{refused}"
    );
    assert_eq!(
        exec.calls.lock().len(),
        0,
        "nothing ran for the refused page"
    );
}

#[test]
fn changed_export_size_is_not_shared_as_a_complete_file() {
    let exec = RecordingExec::default();
    let target = direct_target();
    *exec.outputs.lock() = vec![output(0, "4 page.pdf\0"), output(0, "short")];
    let files = collect_exports(&exec, &target, 4).unwrap();
    assert!(files[0]
        .content
        .as_ref()
        .unwrap_err()
        .contains("5 of 4 bytes"));
}

/// Every pod-exec capability the registry ships, with a call that satisfies its input schema and
/// the argv its `[exec]` table must render. `web.save` and `report.view` have their own tests.
fn shipped_calls() -> Vec<(&'static str, serde_json::Value, Vec<&'static str>)> {
    let calls = vec![
        (
            "report.pages",
            json!({"pdf": "/export/r.pdf", "dir": "/export/pages"}),
            vec!["/export/r.pdf", "/export/pages"],
        ),
        (
            "report.source",
            json!({"path": "/export/r.typ", "source": "= Title"}),
            vec!["/export/r.typ"],
        ),
        (
            "export.read",
            json!({"path": "/export/a.txt", "offset": 0}),
            vec![
                "if=/export/a.txt",
                "iflag=skip_bytes,count_bytes",
                "skip=0",
                "count=16384",
                "status=none",
            ],
        ),
    ];
    calls
}

#[test]
fn every_shipped_pod_exec_capability_runs_its_declared_argv_and_fails_typed() {
    let registry =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../registry/capabilities");
    let mut shipped = BTreeMap::new();
    for entry in std::fs::read_dir(&registry).expect("registry capabilities") {
        let dir = entry.expect("entry").path();
        let Ok(text) = std::fs::read_to_string(dir.join("capability.toml")) else {
            continue;
        };
        let raw: toml::Value = toml::from_str(&text).expect("capability toml");
        if raw.get("implementation").and_then(toml::Value::as_str) != Some("pod-exec") {
            continue;
        }
        let declared: odin_registry::schema::CapabilityToml =
            toml::from_str(&text).expect("capability toml");
        let id = dir.file_name().unwrap().to_string_lossy().into_owned();
        shipped.insert(
            id,
            (declared.timeout_seconds, declared.exec.expect("[exec]")),
        );
    }
    // A tree without the personal capabilities has no rows to run for them.
    let mut calls = shipped_calls();
    calls.retain(|call| shipped.contains_key(call.0));
    let mut covered: Vec<&str> = calls.iter().map(|call| call.0).collect();
    covered.extend(["web.save", "report.view"]);
    covered.sort_unstable();
    assert_eq!(
        covered,
        shipped.keys().map(String::as_str).collect::<Vec<_>>(),
        "a shipped pod-exec capability has no row in shipped_calls"
    );

    let pods = Arc::new(PodSessions::default());
    pods.bind(
        SessionId::new("pod-session").unwrap(),
        PodTarget {
            network_transport: odin_registry::WorkloadTransport::VpnRequired,
            ..direct_target()
        },
    );
    for (id, arguments, rendered) in calls {
        let (timeout, spec) = shipped[id].clone();
        let mut contract = contract();
        contract.id = CapabilityId::new(id).unwrap();
        contract.timeout_seconds = timeout;
        let executable = spec.executable.clone();
        let exec = Arc::new(RecordingExec::default());
        let tool = PodExecTool::new(PodExecBinding {
            specs: BTreeMap::from([(contract.id.clone(), spec)]),
            pods: Arc::clone(&pods),
            exec: Arc::clone(&exec) as Arc<dyn PodWorkerExec>,
            web_save: None,
            research: None,
        });
        let run = |outputs: Vec<WorkerOutput>| {
            *exec.outputs.lock() = outputs;
            exec.calls.lock().clear();
            tool.run(&contract, &scope("pod-session"), &arguments)
        };

        let result = run(vec![output(0, "found\n"), output(0, "12 out.json\0")])
            .unwrap_or_else(|error| panic!("{id}: {error}"));
        let mut argv = vec![
            "/bin/timeout".to_owned(),
            timeout.get().to_string(),
            executable.clone(),
        ];
        argv.extend(rendered.iter().map(|part| (*part).to_owned()));
        assert_eq!(exec.calls.lock()[0].1, argv, "{id}");
        assert_eq!(result["stdout"], "found\n", "{id}");
        assert_eq!(
            result["files"],
            json!([{"path": "out.json", "bytes": 12}]),
            "{id}"
        );
        if id == "report.source" {
            assert_eq!(
                exec.stdins.lock()[0].as_deref(),
                Some(b"= Title".as_slice())
            );
        }

        let failed = run(vec![
            WorkerOutput {
                stderr_tail: b"boom".to_vec(),
                stderr_bytes: 4,
                ..output(2, "")
            },
            output(0, ""),
        ])
        .unwrap_or_else(|error| panic!("{id}: {error}"));
        assert_eq!(
            (
                failed["exitCode"].as_i64(),
                failed["timedOut"].as_bool(),
                failed["stderr"].as_str()
            ),
            (Some(2), Some(false), Some("boom")),
            "{id}"
        );

        let missing = run(vec![output(127, "")]).expect_err("tool absent from the image");
        assert!(
            matches!(&missing, HostToolError::Unavailable { reason, .. } if reason.contains(&executable)),
            "{id}: {missing:?}"
        );
    }
}

#[test]
fn report_view_returns_the_page_as_an_image_block_not_a_text_tail() {
    let png = {
        let mut bytes = Vec::new();
        image::ImageEncoder::write_image(
            image::codecs::png::PngEncoder::new(&mut bytes),
            &[0x3a, 0x7a, 0xc2, 0xff, 0x11, 0x22, 0x33, 0xff],
            2,
            1,
            image::ExtendedColorType::Rgba8,
        )
        .expect("png");
        bytes
    };
    let exec = Arc::new(RecordingExec::default());
    *exec.outputs.lock() = vec![
        WorkerOutput {
            exit_code: 0,
            stdout_tail: png.clone(),
            stderr_tail: Vec::new(),
            stdout_bytes: png.len() as u64,
            stderr_bytes: 0,
        },
        output(0, ""),
    ];
    let spec: PodExecToml = toml::from_str(
        r#"
executable = "/bin/odin-view"
argv = ["{path}"]
view = "path"
"#,
    )
    .unwrap();
    let mut contract = contract();
    contract.id = CapabilityId::new("report.view").unwrap();
    let tool = PodExecTool::new(PodExecBinding {
        specs: BTreeMap::from([(contract.id.clone(), spec)]),
        pods: bound_pod(),
        exec: Arc::clone(&exec) as Arc<dyn PodWorkerExec>,
        web_save: None,
        research: None,
    });
    let result = tool
        .run(
            &contract,
            &scope("pod-session"),
            &json!({"path": "/export/pages/page-01.png"}),
        )
        .expect("viewed page");
    assert_eq!(result["stdout"], "");
    assert_eq!(result["viewed"], "/export/pages/page-01.png");
    assert_eq!(result["images"][0]["type"], "image");
    assert_eq!(result["images"][0]["mimeType"], "image/jpeg");
    let jpeg = base64_decode(result["images"][0]["data"].as_str().expect("jpeg data"));
    assert_eq!(&jpeg[..2], [0xff, 0xd8], "the block carries a JPEG");
    let shown = image::load_from_memory(&jpeg).expect("the block decodes");
    assert_eq!(
        (shown.width(), shown.height()),
        (2, 1),
        "it is the page's own pixels"
    );
    assert!(exec.stdins.lock()[0].is_none());
}

fn base64_decode(text: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .expect("base64")
}

/// A fetch that never finishes is killed at the capability's timeout, whole process group
/// included, and nothing reaches the pod.
#[test]
fn a_hung_fetch_is_killed_at_the_contract_timeout() {
    let stubs = tempfile::tempdir().expect("stub dir");
    let fetcher = stubs.path().join("web-save");
    let pid_file = stubs.path().join("pid");
    std::fs::write(
        &fetcher,
        format!(
            "#!/bin/sh\necho $$ > {}\nexec sleep 60\n",
            pid_file.display()
        ),
    )
    .expect("stub");
    std::fs::set_permissions(
        &fetcher,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .expect("executable");
    let (mut contract, spec) = web_save();
    contract.timeout_seconds = std::num::NonZeroU32::new(1).unwrap();
    let exec = Arc::new(RecordingExec::default());
    let tool = PodExecTool::new(PodExecBinding {
        specs: BTreeMap::from([(contract.id.clone(), spec)]),
        pods: bound_pod(),
        exec: Arc::clone(&exec) as Arc<dyn PodWorkerExec>,
        web_save: Some(fetcher),
        research: None,
    });
    let refused = tool
        .run(
            &contract,
            &scope("pod-session"),
            &json!({"url": "https://a.example/slow", "path": "/export/a.pdf"}),
        )
        .expect_err("a hung fetch is refused")
        .to_string();
    assert!(refused.contains("did not finish within 1 s"), "{refused}");
    let pid = std::fs::read_to_string(&pid_file).expect("the fetcher ran");
    assert!(
        !std::path::Path::new(&format!("/proc/{}", pid.trim())).exists(),
        "the fetcher was killed and reaped"
    );
    assert!(exec.calls.lock().is_empty(), "nothing ran in the pod");
}

/// A web.save whose fetch is `script`, with the research exit `helper` binding.
fn saved_through(
    script: &str,
    research: crate::host_tools::research::ResearchExit,
) -> (Arc<RecordingExec>, Result<serde_json::Value, HostToolError>) {
    let stubs = tempfile::tempdir().expect("stub dir");
    let fetcher = stubs.path().join("web-save");
    std::fs::write(&fetcher, format!("#!/bin/sh\n{script}\n")).expect("stub");
    std::fs::set_permissions(
        &fetcher,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .expect("executable");
    let (contract, spec) = web_save();
    let exec = Arc::new(RecordingExec::default());
    exec.outputs.lock().extend((0..3).map(|_| output(0, "")));
    let tool = PodExecTool::new(PodExecBinding {
        specs: BTreeMap::from([(contract.id.clone(), spec)]),
        pods: bound_pod(),
        exec: Arc::clone(&exec) as Arc<dyn PodWorkerExec>,
        web_save: Some(fetcher),
        research: Some(Arc::new(research)),
    });
    let result = tool.run(
        &contract,
        &scope("pod-session"),
        &json!({"url": "https://a.example/report.pdf", "path": "/export/a.pdf"}),
    );
    (exec, result)
}

#[test]
fn a_refused_fetch_is_tried_again_from_the_next_region() {
    let dir = tempfile::tempdir().expect("dir");
    let (research, asked) = crate::host_tools::research::tests::helper(
        dir.path(),
        &[json!({"ok": true, "region": "b", "tried": ["a", "b"]})],
    );
    // Refused (67) on its first run, bytes on its second.
    let marker = dir.path().join("ran");
    let script = format!(
        "[ -e {0} ] && printf bytes && exit 0\ntouch {0}\necho 'the site refused this exit (HTTP 403)' >&2\nexit 67",
        marker.display()
    );
    let (exec, result) = saved_through(&script, research);
    result.expect("the second region served it");
    assert_eq!(exec.stdins.lock()[0].as_deref(), Some(b"bytes".as_slice()));
    assert_eq!(asked.lock().unwrap().len(), 1);
}

#[test]
fn an_allowed_site_is_fetched_directly() {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::create_dir(dir.path().join("direct")).unwrap();
    std::fs::write(dir.path().join("direct/a.example"), "").unwrap();
    let (research, asked) = crate::host_tools::research::tests::helper(dir.path(), &[]);
    let (exec, result) = saved_through("printf '%s' \"$ODIN_RESEARCH_DIRECT\"", research);
    result.expect("fetched");
    assert_eq!(exec.stdins.lock()[0].as_deref(), Some(b"1".as_slice()));
    assert!(asked.lock().unwrap().is_empty());
}
