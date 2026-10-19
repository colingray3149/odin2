use super::*;

const BACKUP_MAX_AGE: Duration = Duration::from_secs(30 * 3600);

pub(super) fn run_sys_11(context: &SystemContext, deadline: Instant) -> CheckResult {
    super::run_check("SYS-11", sys_11_body, context, deadline)
}

fn sys_11_body(context: &SystemContext, deadline: Instant) -> Outcome {
    let mut evidence = Vec::new();
    let facts = load_host_facts()?;
    let host = facts.as_ref().and_then(|facts| {
        facts
            .backup_replica_host
            .as_deref()
            .filter(|host| !host.is_empty())
    });
    let path = facts.as_ref().and_then(|facts| {
        facts
            .backup_path
            .as_deref()
            .filter(|path| !path.as_os_str().is_empty())
    });
    let (Some(host), Some(path)) = (host, path) else {
        return Err(CheckFailure::fail(
            "backup-undeclared",
            "host facts do not declare both backupReplicaHost and backupPath; declare the replica that holds the nightly backup",
        ));
    };
    let host = ssh_destination(host)?;
    let completed = path.join("completed");
    let completed_arg = completed.to_str().ok_or_else(|| {
        CheckFailure::fail(
            "backup-stamp-unreadable",
            format!(
                "ssh stat cannot read {}; backupPath is not UTF-8 — declare a UTF-8 backupPath",
                completed.display()
            ),
        )
    })?;
    let ssh = require_tool("ssh", None).map_err(|failure| {
        CheckFailure::fail(
            "backup-stamp-unreadable",
            format!(
                "ssh stat of {host}:{completed_arg} cannot run: {}; install ssh and confirm the declared replica is reachable",
                failure.summary
            ),
        )
    })?;
    let scratch = command_scratch(context, "SYS-11")?;
    let printed = query_completed_stamp(&ssh, &scratch, host, completed_arg, deadline)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            CheckFailure::fail(
                "backup-stamp-unreadable",
                format!(
                    "the local clock cannot age the backup stamp from ssh stat of {host}:{completed_arg}: {error}; fix the system clock"
                ),
            )
        })?
        .as_secs();
    let age = match classify_backup_stamp(&printed, now) {
        StampAge::Fresh(age) => age,
        StampAge::Stale(age) => {
            return Err(CheckFailure::fail(
                "backup-stale",
                format!(
                    "ssh stat of {host}:{completed_arg} is {age}s old, not younger than 30h; run the nightly backup so completed is refreshed"
                ),
            ));
        }
        StampAge::Unparsable => {
            return Err(CheckFailure::fail(
                "backup-stamp-unreadable",
                format!(
                    "ssh stat of {host}:{completed_arg} printed {printed:?}, not an epoch; restore the nightly backup so completed exists and prints its mtime"
                ),
            ));
        }
    };
    note_evidence(&mut evidence, format!("backup-host={host}"));
    note_evidence(&mut evidence, format!("backup-completed={completed_arg}"));
    note_evidence(&mut evidence, format!("backup-age-seconds={age}"));
    CheckOutcome::pass(
        format!("last backup on {host} at {completed_arg} is {age}s old, younger than 30h"),
        evidence,
    )
}

/// A declared replica host that can be passed as one SSH destination.
fn ssh_destination(host: &str) -> Result<&str, CheckFailure> {
    if host.starts_with('-')
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(CheckFailure::fail(
            "backup-replica-invalid",
            format!(
                "backupReplicaHost {host:?} is not an SSH destination; declare the replica host that holds the nightly backup"
            ),
        ));
    }
    Ok(host)
}

fn query_completed_stamp(
    ssh: &Path,
    scratch: &Path,
    host: &str,
    completed: &str,
    deadline: Instant,
) -> Result<String, CheckFailure> {
    let remote = format!("stat -c %Y {}", shell_single_quote(completed));
    let outcome = run_bounded(
        ssh,
        &[
            OsString::from("-o"),
            OsString::from("BatchMode=yes"),
            OsString::from("-o"),
            OsString::from("ConnectTimeout=10"),
            OsString::from(host),
            OsString::from(remote),
        ],
        scratch,
        scratch,
        deadline,
    )
    .map_err(|error| {
        CheckFailure::fail(
            "backup-stamp-unreadable",
            format!(
                "ssh stat of {host}:{completed} failed to start ({error}); fix SSH to the declared backup replica and ensure completed exists"
            ),
        )
    })?;
    if let Some(problem) = command_problem(&outcome) {
        let detail = String::from_utf8_lossy(&outcome.stderr);
        let detail = detail.trim().lines().next().unwrap_or("");
        let detail: String = detail.chars().take(160).collect();
        return Err(CheckFailure::fail(
            "backup-stamp-unreadable",
            format!(
                "ssh stat of {host}:{completed} failed ({problem}: {detail}); fix SSH to the declared backup replica and ensure the nightly backup writes completed"
            ),
        ));
    }
    Ok(trimmed_stdout(&outcome))
}

/// SSH executes the remote path through a shell.
fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[derive(Debug, PartialEq, Eq)]
enum StampAge {
    Fresh(u64),
    Stale(u64),
    Unparsable,
}

/// Passes only when `printed` is one epoch strictly younger than 30 hours.
fn classify_backup_stamp(printed: &str, now_epoch: u64) -> StampAge {
    let Ok(epoch) = printed.trim().parse::<u64>() else {
        return StampAge::Unparsable;
    };
    let age = now_epoch.saturating_sub(epoch);
    if age >= BACKUP_MAX_AGE.as_secs() {
        StampAge::Stale(age)
    } else {
        StampAge::Fresh(age)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_stamp_must_be_strictly_younger_than_thirty_hours() {
        let now = 1_700_000_000;
        let fresh = format!("{}\n", now - 29 * 3600);
        assert!(matches!(
            classify_backup_stamp(&fresh, now),
            StampAge::Fresh(age) if age == 29 * 3600
        ));
        let boundary = format!("{}", now - 30 * 3600);
        assert!(matches!(
            classify_backup_stamp(&boundary, now),
            StampAge::Stale(age) if age == 30 * 3600
        ));
        assert_eq!(
            classify_backup_stamp("not-an-epoch\n", now),
            StampAge::Unparsable
        );
    }
}
