//! Shared bridge fixtures for the bridge test modules: one real pinned-child
//! harness over a private in-memory ledger, the durable row a scenario starts
//! from, and the fixture carrier itself.

use super::*;

use std::os::unix::fs::PermissionsExt;

use crate::probe::{
    CaseContext, ConformanceCaseId, FaultFixtureRuntime, OmpLaunchTemplate, ProbeConfig,
    PINNED_OMP_SOURCE_REVISION,
};

/// One real bridge fixture over a Python pinned-child script: `script` is the whole
/// program after the interpreter line. The child's HOME is an isolated `<root>/home`,
/// so recovery never reads the developer's transcript store.
pub(super) fn child_context(
    root: &std::path::Path,
    case: u8,
    name: &'static str,
    script: &str,
    explicit_args: Vec<String>,
) -> CaseContext {
    let python = std::process::Command::new("python3")
        .args(["-c", "import sys; print(sys.executable)"])
        .output()
        .expect("fixture interpreter");
    assert!(python.status.success());
    let interpreter = String::from_utf8(python.stdout).unwrap();
    let executable = root.join(format!("{name}-child.py"));
    std::fs::write(&executable, format!("#!{}\n{script}", interpreter.trim()))
        .expect("child script");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
        .expect("child script executable bit");
    let atlas_root = root.join("atlas");
    for directory in ["crates", "extension", "registry", "skeletons"] {
        fs::create_dir_all(atlas_root.join(directory)).unwrap();
    }
    let atlas = Arc::new(odin_atlas::build(odin_atlas::AtlasSources::new(&atlas_root)).unwrap());
    let home = root.join("home");
    fs::create_dir_all(&home).unwrap();
    let explicit_env = vec![("HOME".to_owned(), home.to_string_lossy().into_owned())];
    let worker = crate::process::launch_for_fixture(&executable);
    let config = Arc::new(ProbeConfig::new(
        OmpLaunchTemplate {
            executable: executable.clone(),
            explicit_args,
            explicit_env: explicit_env.clone(),
            expected_source_revision: PINNED_OMP_SOURCE_REVISION.to_owned(),
            startup_timeout: Duration::from_secs(10),
            drain_timeout: Duration::from_secs(10),
            kill_timeout: Duration::from_secs(10),
            worker: worker.clone(),
        },
        FaultFixtureRuntime {
            bun: executable,
            explicit_env,
            worker,
        },
        root.join("work"),
        atlas,
    ));
    CaseContext::for_case(&config, ConformanceCaseId::new(case), name).unwrap()
}

/// A child requiring exactly one host-owned `--mode rpc` before emitting frames.
pub(super) async fn fixture_context(
    root: &std::path::Path,
    case: u8,
    name: &'static str,
) -> CaseContext {
    child_context(
        root,
        case,
        name,
        r#"import json, sys
if '--version' in sys.argv:
    print('omp epoch fixture')
    sys.exit(0)
launcher = sys.argv[1:]
modes = [index for index, arg in enumerate(launcher) if arg == '--mode']
if len(modes) != 1 or modes[0] + 1 >= len(launcher) or launcher[modes[0] + 1] != 'rpc':
    sys.stderr.write('carrier started without exactly one host-owned --mode rpc\n')
    sys.exit(3)
def emit(value):
    print(json.dumps(value), flush=True)
emit({'type':'ready','protocolVersion':1,'supportedProtocolVersions':[1,2],
      'maxFrameBytes':1048576,'maxReassembledFrameBytes':67108864})
for line in sys.stdin:
    command = json.loads(line)
    kind = command['type']
    data = {}
    if kind == 'negotiate_protocol':
        data = {'protocolVersion':2}
    elif kind == 'set_host_tools':
        data = {'toolNames':[tool['name'] for tool in command['tools']]}
    elif kind == 'set_host_uri_schemes':
        data = {'schemes':[scheme['scheme'] for scheme in command['schemes']]}
    elif kind == 'get_state':
        data = {'approvedActions':0,'deniedActions':0,
                'cancelledInputs':0,'waiting':False}
    emit({'type':'response','id':command['id'],'command':kind,'success':True,'data':data})
"#,
        Vec::new(),
    )
}

/// The durable row a lagging-or-ahead binding scenario starts from:
/// identical immutable host bindings to what `bridge_config` would write,
/// published `ready`, at an arbitrary epoch.
pub(super) fn row_for(
    context: &CaseContext,
    descriptor: &LiveSessionDescriptor,
) -> odin_ledger::live::NewLiveSession {
    let ids = context.ids();
    let scope = context.scope();
    odin_ledger::live::NewLiveSession {
        session_id: ids.session.clone(),
        seat_id: scope
            .seat
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default(),
        project_id: scope
            .project
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default(),
        slice_id: descriptor.slice_id.clone(),
        lane_id: ids.lane.to_string(),
        target_node_id: descriptor.target_node_id.clone(),
        provider: descriptor.provider.clone(),
        model: descriptor.model.clone(),
        title: descriptor.title.clone(),
        manifest: descriptor.manifest.clone(),
        open_tab: descriptor.open_tab,
        state: "ready".to_owned(),
        created_at: OffsetDateTime::now_utc(),
    }
}
