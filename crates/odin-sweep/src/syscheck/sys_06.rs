use super::*;

pub(super) fn run_sys_06(context: &SystemContext, deadline: Instant) -> CheckResult {
    super::run_check("SYS-06", sys_06_body, context, deadline)
}

/// The generation the running system booted or switched into.
const CURRENT_SYSTEM: &str = "/run/current-system";
/// The generation the last `switch` (or `boot`) recorded.
const SYSTEM_PROFILE: &str = "/nix/var/nix/profiles/system";

fn sys_06_body(context: &SystemContext, deadline: Instant) -> Outcome {
    let scratch = command_scratch(context, "SYS-06")?;
    // The running odind identity is one user-manager read; SYS-06 owns the
    // /proc provenance of that PID, not the service health verdict.
    let mut units = UnitStateReader::for_host(ManagerScope::UserOnly)?;
    let odind = units.unit("odind.service")?;
    let exe = match odind
        .get("MainPID")
        .and_then(|pid| pid.parse::<u32>().ok())
        .filter(|pid| *pid > 0)
    {
        Some(pid) => Some(fs::read_link(format!("/proc/{pid}/exe")).map_err(|error| {
            CheckFailure::fail(
                "odind-binary-unresolved",
                format!("odind (pid {pid}) has no readable executable: {error}"),
            )
        })?),
        None => None,
    };
    let nix_store = require_tool("nix-store", None)?;
    activation_verdict(
        Path::new(CURRENT_SYSTEM),
        Path::new(SYSTEM_PROFILE),
        exe.as_deref(),
        |system| {
            let outcome = run_bounded(
                &nix_store,
                &[
                    OsString::from("--query"),
                    OsString::from("--requisites"),
                    system.as_os_str().to_owned(),
                ],
                &scratch,
                &context.odin_root,
                deadline,
            )
            .map_err(|error| {
                CheckFailure::fail(
                    "closure-query-failed",
                    format!("the active system's closure could not be read: {error}"),
                )
            })?;
            if let Some(problem) = command_problem(&outcome) {
                return Err(CheckFailure::fail(
                    problem,
                    "the active system's closure could not be read",
                ));
            }
            Ok(trimmed_stdout(&outcome)
                .lines()
                .map(str::to_owned)
                .collect())
        },
    )
}

/// SYS-06 on resolved facts: the running system is the generation the last
/// switch recorded, and a running odind executes a binary that generation
/// holds — a switch that did not restart odind leaves the previous build
/// serving. `closure` lists the store paths a system generation holds.
fn activation_verdict(
    current: &Path,
    profile: &Path,
    odind: Option<&Path>,
    closure: impl FnOnce(&Path) -> Result<Vec<String>, CheckFailure>,
) -> Outcome {
    let mut evidence = Vec::new();
    let current = fs::canonicalize(current).map_err(|error| {
        CheckFailure::fail(
            "active-generation-unresolved",
            format!("the active system generation cannot be resolved: {error}"),
        )
    })?;
    let recorded = fs::canonicalize(profile).map_err(|error| {
        CheckFailure::fail(
            "system-profile-unresolved",
            format!("the recorded system generation cannot be resolved: {error}"),
        )
    })?;
    note_evidence(
        &mut evidence,
        format!("active-generation={}", current.display()),
    );
    if current != recorded {
        note_evidence(
            &mut evidence,
            format!("recorded-generation={}", recorded.display()),
        );
        return CheckOutcome::flagged(
            "activation-drift",
            "the active system is not the generation the last switch recorded; activation remains a human action",
            evidence,
        );
    }
    let Some(exe) = odind else {
        note_evidence(&mut evidence, "odind=not-running");
        return CheckOutcome::pass("the active system is the recorded generation", evidence);
    };
    note_evidence(&mut evidence, format!("odind-binary={}", exe.display()));
    let package: PathBuf = exe.components().take(4).collect();
    if !package.starts_with("/nix/store") || package.components().count() < 4 {
        return Err(CheckFailure::fail(
            "odind-binary-outside-store",
            format!("odind runs {}, which is no Nix store binary", exe.display()),
        ));
    }
    let package = package.to_string_lossy().into_owned();
    if !closure(&current)?.contains(&package) {
        return Err(CheckFailure::fail(
            "odind-binary-stale",
            format!(
                "odind runs {}, which the active system does not hold: it was not restarted after the switch",
                exe.display()
            ),
        ));
    }
    CheckOutcome::pass(
        "the active system is the recorded generation and odind runs its binary",
        evidence,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const ODIND: &str = "/nix/store/ivy9z65r5v5h7c6pb1zgmjbjbj7b93iy-odin-0.0.0/bin/odind";

    fn generations() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let root = tempfile::tempdir().expect("fixture root");
        let first = root.path().join("system-1");
        let second = root.path().join("system-2");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        (root, first, second)
    }

    fn link(root: &Path, name: &str, target: &Path) -> PathBuf {
        let path = root.join(name);
        std::os::unix::fs::symlink(target, &path).unwrap();
        path
    }

    /// Detect drift by comparing running and recorded generations without evaluating a flake.
    #[test]
    fn a_recorded_generation_that_is_not_running_flags_drift() {
        let (root, first, second) = generations();
        let current = link(root.path(), "current", &first);
        let profile = link(root.path(), "profile", &second);
        let flagged = activation_verdict(&current, &profile, None, |_| unreachable!())
            .expect("drift is a flag");
        assert_eq!(flagged.status, CheckStatus::Flag);
        assert_eq!(flagged.reason.as_deref(), Some("activation-drift"));
        let profile = link(root.path(), "profile-2", &first);
        let passed = activation_verdict(&current, &profile, None, |_| unreachable!())
            .expect("the recorded generation runs");
        assert_eq!(passed.status, CheckStatus::Pass);
    }

    #[test]
    fn an_odind_binary_the_active_system_does_not_hold_fails() {
        let (root, first, _) = generations();
        let current = link(root.path(), "current", &first);
        let profile = link(root.path(), "profile", &first);
        let package = "/nix/store/ivy9z65r5v5h7c6pb1zgmjbjbj7b93iy-odin-0.0.0".to_owned();
        let held = activation_verdict(&current, &profile, Some(Path::new(ODIND)), |system| {
            assert_eq!(system, fs::canonicalize(&first).unwrap());
            Ok(vec![package.clone()])
        })
        .expect("the held binary passes");
        assert_eq!(held.status, CheckStatus::Pass);
        let stale = activation_verdict(&current, &profile, Some(Path::new(ODIND)), |_| {
            Ok(vec![
                "/nix/store/0000000000000000000000000000000a-odin-0.0.0".to_owned(),
            ])
        })
        .expect_err("a stale binary fails");
        assert_eq!(stale.reason, "odind-binary-stale");
        let outside = activation_verdict(
            &current,
            &profile,
            Some(Path::new("/home/colin/target/odind")),
            |_| unreachable!(),
        )
        .expect_err("a binary outside the store fails");
        assert_eq!(outside.reason, "odind-binary-outside-store");
    }
}
