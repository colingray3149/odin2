use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use std::path::{Path, PathBuf};

use clap::Parser;
use odin_sweep::{probe_registry, report, runner, syscheck};

#[derive(Debug, Parser)]
#[command(
    name = "sweep",
    version,
    about = "Run Odin code-quality, host-security, or integration checks"
)]
struct Cli {
    /// Run the live host/security checks.
    #[arg(long, conflicts_with = "integration")]
    system: bool,

    /// Run the real-fleet integration suites (OMP, browser, ledger, K3s, kube Jobs, life, vault).
    #[arg(long, conflicts_with = "system")]
    integration: bool,
    /// Odin workspace (otherwise ODIN_ROOT, the current workspace, or configured project).
    #[arg(long, value_name = "DIR")]
    root: Option<PathBuf>,
    /// Dotfiles source root for host checks.
    #[arg(long, value_name = "DIR")]
    dotfiles_root: Option<PathBuf>,
    /// Installed runtime manifest (otherwise ODIN_RUNTIME_MANIFEST).
    #[arg(long, value_name = "PATH")]
    runtime_manifest: Option<PathBuf>,
}

fn main() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .compact()
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let code = match run(cli) {
        Ok(code) => code,
        Err(error) => {
            tracing::error!(%error, "sweep failed");
            1
        }
    };
    std::process::exit(code);
}

fn run(cli: Cli) -> Result<i32, String> {
    let runtime_manifest = cli
        .runtime_manifest
        .or_else(|| std::env::var_os("ODIN_RUNTIME_MANIFEST").map(PathBuf::from));
    let root = resolve_root(cli.root, runtime_manifest.as_deref())?;
    let explicit_dotfiles_root = cli
        .dotfiles_root
        .or_else(|| std::env::var_os("DOTFILES_ROOT").map(PathBuf::from));
    let dotfiles_root =
        syscheck::resolve_dotfiles_root(explicit_dotfiles_root, syscheck::declared_dotfiles_root());
    let scratch = runner::Scratch::new()?;
    if !cli.system && !cli.integration {
        return runner::run_development_checks(&root, scratch.path(), runtime_manifest.as_deref());
    }
    let context = syscheck::SystemContext {
        odin_root: root,
        dotfiles_root,
        runtime_manifest,
        scratch_root: scratch.path().to_path_buf(),
    };
    let checks = if cli.system {
        let checks = syscheck::run_all_system_checks(&context);
        if checks.len() != 11 {
            return Err(format!(
                "system dispatcher returned {} checks, expected 11",
                checks.len()
            ));
        }
        checks
    } else {
        probe_registry::run_integration_checks(&context)
    };
    write_report(&mut std::io::stdout().lock(), &checks).map_err(|error| error.to_string())?;
    Ok(report::exit_code(&checks))
}

fn write_report(
    output: &mut impl std::io::Write,
    checks: &[report::CheckResult],
) -> std::io::Result<()> {
    for check in checks {
        writeln!(
            output,
            "{} {} — {}: {}",
            check.status, check.id, check.name, check.summary
        )?;
        if let Some(reason) = &check.reason {
            writeln!(output, "  {reason}")?;
        }
        writeln!(output, "  duration_ms: {}", check.duration_ms)?;
        for evidence in &check.evidence {
            for line in evidence.lines() {
                writeln!(output, "  evidence: {line}")?;
            }
        }
    }
    writeln!(
        output,
        "{} checks; {} passed; {} not applicable",
        checks.len(),
        checks
            .iter()
            .filter(|check| check.status == report::CheckStatus::Pass)
            .count(),
        checks
            .iter()
            .filter(|check| check.status == report::CheckStatus::NotApplicable)
            .count()
    )
}

fn resolve_root(explicit: Option<PathBuf>, runtime: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(root) = explicit.or_else(|| std::env::var_os("ODIN_ROOT").map(PathBuf::from)) {
        return validate_root(root);
    }
    let cwd = std::env::current_dir().map_err(|error| error.to_string())?;
    for directory in cwd.ancestors() {
        let manifest = directory.join("Cargo.toml");
        if let Ok(source) = std::fs::read_to_string(&manifest) {
            if toml::from_str::<toml::Value>(&source)
                .is_ok_and(|value| value.get("workspace").is_some())
            {
                return validate_root(directory.to_path_buf());
            }
        }
    }
    if let Some(path) = runtime {
        let manifest =
            odin_huginn::RuntimeManifest::load(path).map_err(|error| error.to_string())?;
        let config = manifest.load_config().map_err(|error| error.to_string())?;
        if let Some(project) = config.projects.get("odin") {
            return validate_root(project.root.clone());
        }
    }
    Err("run inside the Odin workspace, set ODIN_ROOT, or pass --root DIR".to_owned())
}

fn validate_root(root: PathBuf) -> Result<PathBuf, String> {
    let root = std::fs::canonicalize(&root)
        .map_err(|error| format!("workspace {}: {error}", root.display()))?;
    if !root.join("Cargo.toml").is_file() {
        return Err(format!("{} is not a Cargo workspace", root.display()));
    }
    Ok(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_preserves_status_counts_and_failure_diagnostics() {
        let checks = [report::CheckResult::new(
            "SYS-08",
            "ledger",
            report::CheckStatus::Fail,
            120_000,
            "interrupted",
            vec!["phase=integrity elapsed_ms=120000 outcome=interrupted".to_owned()],
        )
        .with_reason("ledger-integrity-timeout")];
        let mut output = Vec::new();
        write_report(&mut output, &checks).expect("render report");
        assert_eq!(
            String::from_utf8(output).expect("UTF-8"),
            "FAIL SYS-08 — ledger: interrupted\n  ledger-integrity-timeout\n  duration_ms: 120000\n  evidence: phase=integrity elapsed_ms=120000 outcome=interrupted\n1 checks; 0 passed; 0 not applicable\n"
        );
        assert_ne!(report::exit_code(&checks), 0);
    }

    #[test]
    fn retired_grader_options_are_not_accepted() {
        assert!(Cli::try_parse_from(["sweep", "--grader", "/missing"]).is_err());
        assert!(Cli::try_parse_from(["sweep", "--profile", "candidate"]).is_err());
    }
}
