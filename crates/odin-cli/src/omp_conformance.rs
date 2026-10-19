//! `odind omp-conformance`: run the pinned OMP probe suite through
//! [`odin_omp::probe::run_suite`] with a strict [`ProbeConfig`] assembled
//! only from `ODIN_RUNTIME_MANIFEST` plus the explicit fixture work root.

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use odin_huginn::{OdindConfig, RuntimeManifest};
use odin_kernel::{ParentAuthorityClient, StopAuthority};
use odin_omp::probe::{
    default_fixture_root, run_suite, FaultFixtureRuntime, OmpLaunchTemplate, ProbeConfig,
    SuiteDeadlines, PINNED_OMP_SOURCE_REVISION, PROVIDER_FIXTURE_FILE,
};
use odin_omp::process::OmpWorkerLaunch;
use odin_process::{
    BusAddress, RegisteredServiceBinding, ScopeLifetime, ScopeLimits, WorkerChannel,
};
use odin_types::CorrelationId;

pub fn run(config_path: &Path, fixture_root: &Path, output_path: &Path) -> Result<(), String> {
    if !fixture_root.is_absolute() {
        return Err("omp-conformance --fixture-root must be absolute".to_owned());
    }
    if !output_path.is_absolute() {
        return Err("omp-conformance --output must be absolute".to_owned());
    }
    let config = OdindConfig::load(config_path).map_err(|error| error.to_string())?;
    if config.executables.omp_revision != PINNED_OMP_SOURCE_REVISION {
        return Err(format!(
            "OMP revision must be the pinned {PINNED_OMP_SOURCE_REVISION}"
        ));
    }
    let manifest = load_runtime_manifest()?;
    let omp = manifest
        .executable("omp")
        .map_err(|error| format!("runtime manifest omp: {error}"))?;
    let bun = manifest
        .executable("bun")
        .map_err(|error| format!("runtime manifest bun: {error}"))?;
    if omp.path != config.executables.omp_bin {
        return Err(
            "runtime manifest omp path does not match the configured pinned executable".to_owned(),
        );
    }

    let work_root = fixture_root.join("omp-conformance-work");
    fs::create_dir_all(&work_root)
        .map_err(|error| format!("could not create omp-conformance work root: {error}"))?;
    let fixtures = resolve_omp_fixtures(&config)?;
    let environment = isolated_environment(&work_root, &[&omp.path, &bun.path])?;
    let (authority, correlation) = worker_authority(&config, &manifest, &work_root)?;
    let omp_worker = worker_launch(&authority, &correlation, &manifest, "omp", &omp.path, "omp")?;
    let bun_worker = worker_launch(
        &authority,
        &correlation,
        &manifest,
        "bun",
        &bun.path,
        "fault-bun",
    )?;
    let probe = ProbeConfig {
        omp: OmpLaunchTemplate {
            executable: omp.path.clone(),
            worker: omp_worker,
            explicit_args: Vec::new(),
            explicit_env: environment.clone(),
            expected_source_revision: PINNED_OMP_SOURCE_REVISION.to_owned(),
            startup_timeout: Duration::from_secs(30),
            drain_timeout: Duration::from_secs(10),
            kill_timeout: Duration::from_secs(5),
        },
        fault: FaultFixtureRuntime {
            bun: bun.path.clone(),
            worker: bun_worker,
            explicit_env: environment,
        },
        fixture_root: fixtures,
        work_root,
        atlas: std::sync::Arc::new(build_atlas(&config)?),
        deadlines: SuiteDeadlines {
            default_case: Duration::from_secs(60),
            suite: Duration::from_secs(960),
        },
    };
    probe
        .validate()
        .map_err(|error| format!("omp-conformance ProbeConfig rejected: {error}"))?;

    let runtime = tokio::runtime::Runtime::new()
        .map_err(|error| format!("could not start omp-conformance runtime: {error}"))?;
    let report = runtime
        .block_on(run_suite(probe))
        .map_err(|error| format!("omp-conformance suite failed: {error}"))?;
    let bytes = report.to_canonical_bytes();
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("could not create omp-conformance output parent: {error}"))?;
    }
    fs::write(output_path, bytes)
        .map_err(|error| format!("could not write omp-conformance report: {error}"))?;
    Ok(())
}

fn load_runtime_manifest() -> Result<RuntimeManifest, String> {
    let path = env::var_os("ODIN_RUNTIME_MANIFEST")
        .ok_or_else(|| "ODIN_RUNTIME_MANIFEST is required for odind omp-conformance".to_owned())?;
    RuntimeManifest::load(path).map_err(|error| format!("runtime manifest rejected: {error}"))
}

fn worker_authority(
    config: &OdindConfig,
    manifest: &RuntimeManifest,
    work_root: &Path,
) -> Result<(Arc<StopAuthority>, CorrelationId), String> {
    let parent = ParentAuthorityClient::from_env()
        .map_err(|error| format!("parent worker authority rejected: {error}"))?;
    let authority = if parent.is_remote() {
        let store_path = parent
            .expected_store_path()
            .map_err(|error| format!("parent worker store rejected: {error}"))?;
        let ledger = odin_ledger::Ledger::open(&store_path)
            .map_err(|error| format!("could not open scoped parent worker ledger: {error}"))?;
        StopAuthority::from_parent(Arc::new(Mutex::new(ledger)), parent)
            .map_err(|error| format!("could not open scoped parent worker authority: {error}"))?
    } else {
        let bootstrap = manifest
            .executable("worker_bootstrap")
            .map_err(|error| format!("runtime manifest worker_bootstrap: {error}"))?;
        let unshare = manifest
            .executable("unshare")
            .map_err(|error| format!("runtime manifest unshare: {error}"))?;
        let bus = BusAddress::parse(&config.worker_bus)
            .map_err(|error| format!("omp-conformance worker bus rejected: {error}"))?;
        let channel = WorkerChannel::new(bus, bootstrap.path.clone(), unshare.path.clone())
            .map_err(|error| format!("omp-conformance worker channel rejected: {error}"))?;
        let authority_root = work_root.join("worker-authority");
        fs::create_dir_all(&authority_root)
            .map_err(|error| format!("could not create worker authority root: {error}"))?;
        fs::set_permissions(&authority_root, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("could not protect worker authority root: {error}"))?;
        let ledger = odin_ledger::Ledger::open(authority_root.join("ledger.sqlite3"))
            .map_err(|error| format!("could not open worker authority ledger: {error}"))?;
        StopAuthority::new(Arc::new(Mutex::new(ledger)), channel)
    };
    let authority = Arc::new(authority);

    let material = format!(
        "{}\0{}\0{}",
        config.revision,
        config.executables.omp_revision,
        work_root.display()
    );
    let digest = odin_domain::Digest::hash(material.as_bytes()).to_string();
    let hex = digest
        .strip_prefix("blake3:")
        .ok_or_else(|| "worker authority correlation digest is not BLAKE3".to_owned())?;
    let correlation = CorrelationId::new(&hex[..32])
        .map_err(|error| format!("worker authority correlation rejected: {error}"))?;
    Ok((authority, correlation))
}

fn worker_launch(
    authority: &Arc<StopAuthority>,
    correlation: &CorrelationId,
    manifest: &RuntimeManifest,
    executable_id: &str,
    expected_path: &Path,
    role: &str,
) -> Result<OmpWorkerLaunch, String> {
    let executable = manifest
        .executable(executable_id)
        .map_err(|error| format!("runtime manifest {executable_id}: {error}"))?;
    if executable.path != expected_path {
        return Err(format!(
            "runtime manifest {executable_id} path changed during worker binding"
        ));
    }
    let digest = executable
        .digest
        .strip_prefix("blake3:")
        .ok_or_else(|| format!("runtime manifest {executable_id} digest lacks blake3 prefix"))?;
    let binding = RegisteredServiceBinding::new(executable.path.clone(), digest.to_owned())
        .map_err(|error| format!("{executable_id} worker binding rejected: {error}"))?;
    OmpWorkerLaunch::new(
        Arc::clone(authority),
        correlation.clone(),
        "odin-readmission",
        format!("omp-conformance-{role}"),
        1,
        binding,
        ScopeLimits {
            lifetime: ScopeLifetime::Bounded(Duration::from_secs(960)),
            timeout_stop: Duration::from_secs(5),
            ..ScopeLimits::default()
        },
    )
    .map_err(|error| format!("{executable_id} worker launch contract rejected: {error}"))
}

fn resolve_omp_fixtures(config: &OdindConfig) -> Result<PathBuf, String> {
    let shipped = default_fixture_root();
    if shipped.join(PROVIDER_FIXTURE_FILE).is_file() {
        return Ok(shipped);
    }
    let from_repo = config
        .paths
        .registry_root
        .parent()
        .map(|root| root.join("crates/odin-omp/fixtures"));
    if let Some(path) = from_repo {
        if path.join(PROVIDER_FIXTURE_FILE).is_file() {
            return Ok(path);
        }
    }
    Err("could not locate the pinned OMP conformance fixtures".to_owned())
}

fn build_atlas(config: &OdindConfig) -> Result<odin_atlas::Atlas, String> {
    let odin_root = config
        .paths
        .registry_root
        .parent()
        .ok_or_else(|| "registry root has no Odin repository parent".to_owned())?;
    odin_atlas::build(odin_atlas::AtlasSources::new(odin_root))
        .map_err(|error| format!("could not build Atlas for omp-conformance: {error}"))
}

fn isolated_environment(
    work_root: &Path,
    executables: &[&Path],
) -> Result<Vec<(String, String)>, String> {
    let mut path_entries = Vec::new();
    for executable in executables {
        let parent = executable.parent().ok_or_else(|| {
            format!(
                "runtime executable {} has no parent directory",
                executable.display()
            )
        })?;
        let rendered = parent
            .to_str()
            .ok_or_else(|| "runtime executable parent is not valid UTF-8".to_owned())?;
        if !path_entries.iter().any(|entry| entry == rendered) {
            path_entries.push(rendered.to_owned());
        }
    }
    for name in ["home", "config", "data", "cache", "state", "tmp"] {
        fs::create_dir_all(work_root.join(name))
            .map_err(|error| format!("could not create isolated OMP {name}: {error}"))?;
    }
    Ok(vec![
        ("PATH".to_owned(), path_entries.join(":")),
        ("HOME".to_owned(), path_string(&work_root.join("home"))?),
        (
            "XDG_CONFIG_HOME".to_owned(),
            path_string(&work_root.join("config"))?,
        ),
        (
            "XDG_DATA_HOME".to_owned(),
            path_string(&work_root.join("data"))?,
        ),
        (
            "XDG_CACHE_HOME".to_owned(),
            path_string(&work_root.join("cache"))?,
        ),
        (
            "XDG_STATE_HOME".to_owned(),
            path_string(&work_root.join("state"))?,
        ),
        ("TMPDIR".to_owned(), path_string(&work_root.join("tmp"))?),
        ("TERM".to_owned(), "dumb".to_owned()),
        ("LANG".to_owned(), "C.UTF-8".to_owned()),
        ("LC_ALL".to_owned(), "C.UTF-8".to_owned()),
        ("USER".to_owned(), "odin-probe".to_owned()),
        ("LOGNAME".to_owned(), "odin-probe".to_owned()),
    ])
}

fn path_string(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("path {} is not valid UTF-8", path.display()))
}
