//! Check worker identity against `/proc` and cgroup v2 before signaling or reporting survivors.

use super::*;

pub(super) fn leader_pidfd(leader_pid: u32) -> Result<OwnedFd, WorkerError> {
    let pid = Pid::from_raw(i32::try_from(leader_pid).map_err(|_| {
        WorkerError::new(
            WorkerErrorCode::IdentityProof,
            format!("leader pid {leader_pid} does not fit a pid"),
        )
    })?)
    .ok_or_else(|| {
        WorkerError::new(
            WorkerErrorCode::IdentityProof,
            format!("leader pid {leader_pid} is not a valid pid"),
        )
    })?;
    pidfd_open(pid, PidfdFlags::empty()).map_err(|error| {
        WorkerError::new(
            WorkerErrorCode::IdentityProof,
            format!("pidfd_open failed for leader {leader_pid}: {error}"),
        )
    })
}

/// Reject parent traversal and paths outside this worker's transient unit.
pub(super) fn cgroup_directory(
    channel: &WorkerChannel,
    cgroup_path: &str,
    unit: &str,
) -> Result<PathBuf, WorkerError> {
    use std::path::Component;

    if !cgroup_path.starts_with('/') {
        return Err(WorkerError::new(
            WorkerErrorCode::IdentityProof,
            format!("unit {unit} ControlGroup is not hierarchy-absolute"),
        ));
    }
    let relative = Path::new(cgroup_path.trim_start_matches('/'));
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || relative.file_name().and_then(|name| name.to_str()) != Some(unit)
    {
        return Err(WorkerError::new(
            WorkerErrorCode::IdentityProof,
            format!("unit {unit} ControlGroup {cgroup_path:?} is not its exact cgroup"),
        ));
    }
    Ok(channel.cgroup_root().join(relative))
}

/// A missing root is handled by the caller; read failures must not look like an empty cgroup.
pub(super) fn recursive_cgroup_process_count(root: &Path) -> Result<u64, WorkerError> {
    const DIRECTORY_CAP: usize = 4_096;
    let mut pending = vec![root.to_path_buf()];
    let mut directories = 0_usize;
    let mut processes = 0_u64;
    while let Some(directory) = pending.pop() {
        directories = directories.checked_add(1).ok_or_else(|| {
            WorkerError::new(WorkerErrorCode::Io, "cgroup directory count overflow")
        })?;
        if directories > DIRECTORY_CAP {
            return Err(WorkerError::new(
                WorkerErrorCode::Io,
                format!("cgroup tree {} exceeds directory cap", root.display()),
            ));
        }
        let members = std::fs::read_to_string(directory.join("cgroup.procs")).map_err(|error| {
            WorkerError::new(
                WorkerErrorCode::Io,
                format!(
                    "cannot read recursive cgroup members in {}: {error}",
                    directory.display()
                ),
            )
        })?;
        for member in members.lines().filter(|member| !member.trim().is_empty()) {
            member.trim().parse::<u32>().map_err(|_| {
                WorkerError::new(
                    WorkerErrorCode::Io,
                    format!(
                        "cgroup {} contains malformed PID {member:?}",
                        directory.display()
                    ),
                )
            })?;
            processes = processes.checked_add(1).ok_or_else(|| {
                WorkerError::new(WorkerErrorCode::Io, "cgroup process count overflow")
            })?;
        }
        let entries = std::fs::read_dir(&directory).map_err(|error| {
            WorkerError::new(
                WorkerErrorCode::Io,
                format!("cannot enumerate cgroup {}: {error}", directory.display()),
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                WorkerError::new(
                    WorkerErrorCode::Io,
                    format!("cannot read cgroup directory entry: {error}"),
                )
            })?;
            if entry
                .file_type()
                .map_err(|error| {
                    WorkerError::new(
                        WorkerErrorCode::Io,
                        format!(
                            "cannot inspect cgroup entry {}: {error}",
                            entry.path().display()
                        ),
                    )
                })?
                .is_dir()
            {
                pending.push(entry.path());
            }
        }
    }
    Ok(processes)
}

pub(super) fn process_is_zombie(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| crate::identity::parse_proc_stat(&stat))
        .is_some_and(|(state, ..)| state == 'Z')
}

/// Descendant cgroups can disappear during enumeration as the kernel removes empty groups.
pub(super) fn cgroup_tree_contains(directory: &Path, pid_text: &str) -> Result<bool, WorkerError> {
    let members = std::fs::read_to_string(directory.join("cgroup.procs")).map_err(|error| {
        WorkerError::new(
            WorkerErrorCode::Io,
            format!(
                "cannot read cgroup members in {}: {error}",
                directory.display()
            ),
        )
    })?;
    if members.lines().any(|member| member.trim() == pid_text) {
        return Ok(true);
    }
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(_) => return Ok(false),
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let is_directory = entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false);
        if is_directory && cgroup_tree_contains(&entry.path(), pid_text)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Check the parked helper's cgroup membership before allowing payload execution.
pub(super) fn prove_cgroup_membership(
    channel: &WorkerChannel,
    cgroup_path: &str,
    unit: &str,
    leader_pid: u32,
) -> Result<u64, WorkerError> {
    use std::os::unix::fs::MetadataExt;

    let directory = cgroup_directory(channel, cgroup_path, unit)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let leader_text = leader_pid.to_string();
    loop {
        if let Ok(metadata) = std::fs::metadata(&directory) {
            if metadata.is_dir() {
                let member = std::fs::read_to_string(directory.join("cgroup.procs"))
                    .ok()
                    .is_some_and(|members| {
                        members.lines().any(|member| member.trim() == leader_text)
                    });
                if member {
                    return Ok(metadata.ino());
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(WorkerError::new(
                WorkerErrorCode::IdentityProof,
                format!(
                    "leader {leader_pid} is not present in unit cgroup {}",
                    directory.display()
                ),
            ));
        }
        std::thread::sleep(REAP_POLL);
    }
}

/// Scan for survivors after teardown; `/proc` correlation does not authorize signaling.
pub fn scan_cgroup_residue(unit: &str) -> Result<Vec<ProcessIdentity>, WorkerError> {
    let entries = std::fs::read_dir("/proc").map_err(|error| {
        WorkerError::new(
            WorkerErrorCode::Io,
            format!("cannot enumerate /proc for worker residue: {error}"),
        )
    })?;
    let mut survivors = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(WorkerError::new(
                    WorkerErrorCode::Io,
                    format!("cannot read /proc entry for worker residue: {error}"),
                ));
            }
        };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let cgroup = match std::fs::read_to_string(entry.path().join("cgroup")) {
            Ok(cgroup) => cgroup,
            // Exited between enumeration and the read (NotFound or ESRCH): not a survivor.
            Err(error) if process_vanished(&error) => continue,
            Err(error) => {
                return Err(WorkerError::new(
                    WorkerErrorCode::Io,
                    format!("cannot read /proc/{pid}/cgroup: {error}"),
                ));
            }
        };
        if cgroup
            .lines()
            .any(|line| line.starts_with("0::") && line.contains(unit))
        {
            if let Some(identity) = read_process_identity(pid) {
                survivors.push(identity);
            }
        }
    }
    survivors.sort_by_key(|identity| (identity.pid, identity.start_time_ticks));
    Ok(survivors)
}

fn process_vanished(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound
        || error.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error())
}

pub fn process_cgroup_line(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()?
        .lines()
        .find(|line| line.starts_with("0::"))
        .map(|line| line["0::".len()..].to_owned())
}

#[cfg(test)]
mod vanished_tests {
    use super::process_vanished;

    /// ESRCH between /proc enumeration and reading means the worker exited, not observation failure.
    #[test]
    fn exited_process_reads_are_vanished_not_errors() {
        let esrch = std::io::Error::from_raw_os_error(rustix::io::Errno::SRCH.raw_os_error());
        assert!(process_vanished(&esrch));
        assert!(process_vanished(&std::io::Error::from(
            std::io::ErrorKind::NotFound
        )));
        assert!(!process_vanished(&std::io::Error::from(
            std::io::ErrorKind::PermissionDenied
        )));
    }
}
