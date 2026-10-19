use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use odin_types::HashHex;

use crate::{ProcessError, ProcessErrorCode, CORRELATION_ENV};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub parent_pid: u32,
    pub start_time_ticks: u64,
    pub process_group: i32,
    pub cgroup_sha256: HashHex,
    pub correlation_token_present: bool,
    pub fixture_root_referenced: bool,
    pub survived_teardown: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocketIdentity {
    pub path_sha256: HashHex,
    pub inode: u64,
    pub owner_pid: Option<u32>,
    pub survived_teardown: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountIdentity {
    pub path_sha256: HashHex,
    pub owner_pid: u32,
    pub survived_teardown: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IdentitySnapshot {
    pub processes: Vec<ProcessIdentity>,
    pub sockets: Vec<SocketIdentity>,
    pub mounts: Vec<MountIdentity>,
}

#[derive(Clone, Debug)]
pub struct ScanCriteria {
    process_groups: BTreeSet<i32>,
    root_pids: BTreeSet<u32>,
    correlation_id: String,
    fixture_root: PathBuf,
}

impl ScanCriteria {
    pub fn new(correlation_id: impl Into<String>, fixture_root: impl Into<PathBuf>) -> Self {
        Self {
            process_groups: BTreeSet::new(),
            root_pids: BTreeSet::new(),
            correlation_id: correlation_id.into(),
            fixture_root: fixture_root.into(),
        }
    }

    pub fn add_process_group(&mut self, process_group: i32) {
        if process_group > 0 {
            self.process_groups.insert(process_group);
        }
    }

    pub fn add_root_pid(&mut self, root_pid: u32) {
        if root_pid > 0 {
            self.root_pids.insert(root_pid);
        }
    }

    pub fn process_groups(&self) -> impl Iterator<Item = i32> + '_ {
        self.process_groups.iter().copied()
    }

    pub fn root_pids(&self) -> impl Iterator<Item = u32> + '_ {
        self.root_pids.iter().copied()
    }

    pub fn fixture_root(&self) -> &Path {
        &self.fixture_root
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SurvivorScanner;

impl SurvivorScanner {
    pub fn scan(&self, criteria: &ScanCriteria) -> Result<IdentitySnapshot, ProcessError> {
        let entries = fs::read_dir("/proc").map_err(|error| {
            ProcessError::new(
                ProcessErrorCode::Identity,
                format!("cannot enumerate /proc: {error}"),
            )
        })?;
        let owner_uid = fs::metadata("/proc/self")
            .map_err(|error| {
                ProcessError::new(
                    ProcessErrorCode::Identity,
                    format!("cannot identify /proc owner: {error}"),
                )
            })?
            .uid();
        let mut processes = BTreeMap::new();

        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            if !entry
                .metadata()
                .is_ok_and(|metadata| metadata.uid() == owner_uid)
            {
                continue;
            }
            let Some(mut identity) = read_process_identity(pid) else {
                continue;
            };
            let proc_root = entry.path();
            identity.correlation_token_present =
                process_has_correlation(&proc_root, &criteria.correlation_id);
            identity.fixture_root_referenced =
                process_references_fixture(&proc_root, criteria.fixture_root());
            processes.insert(pid, identity);
        }

        let selected = selected_process_ids(&processes, criteria);
        let socket_paths = fixture_sockets(criteria.fixture_root());
        let mut found_processes = Vec::with_capacity(selected.len());
        let mut sockets = BTreeMap::<u64, SocketIdentity>::new();
        let mut mounts = Vec::new();
        for pid in selected {
            let Some(mut identity) = processes.remove(&pid) else {
                continue;
            };
            identity.survived_teardown = true;
            let proc_root = PathBuf::from(format!("/proc/{pid}"));
            collect_open_sockets(pid, &proc_root, &socket_paths, &mut sockets);
            collect_mounts(pid, &proc_root, criteria.fixture_root(), &mut mounts);
            found_processes.push(identity);
        }
        found_processes.sort_by_key(|identity| (identity.pid, identity.start_time_ticks));
        mounts.sort_by_key(|identity| (identity.owner_pid, identity.path_sha256.clone()));
        Ok(IdentitySnapshot {
            processes: found_processes,
            sockets: sockets.into_values().collect(),
            mounts,
        })
    }
}

fn selected_process_ids(
    processes: &BTreeMap<u32, ProcessIdentity>,
    criteria: &ScanCriteria,
) -> BTreeSet<u32> {
    let mut pending = criteria.root_pids.iter().copied().collect::<Vec<_>>();
    pending.extend(processes.values().filter_map(|identity| {
        (criteria.process_groups.contains(&identity.process_group)
            || identity.correlation_token_present
            || identity.fixture_root_referenced)
            .then_some(identity.pid)
    }));

    let mut children = BTreeMap::<u32, Vec<u32>>::new();
    for identity in processes.values() {
        children
            .entry(identity.parent_pid)
            .or_default()
            .push(identity.pid);
    }

    let mut expanded = BTreeSet::new();
    let mut selected = BTreeSet::new();
    while let Some(pid) = pending.pop() {
        if !expanded.insert(pid) {
            continue;
        }
        if processes.contains_key(&pid) {
            selected.insert(pid);
        }
        if let Some(descendants) = children.get(&pid) {
            pending.extend(descendants);
        }
    }
    selected
}

pub(crate) fn read_process_identity(pid: u32) -> Option<ProcessIdentity> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (parent_pid, process_group, start_time_ticks) = parse_process_stat(&stat)?;
    let cgroup = fs::read(format!("/proc/{pid}/cgroup")).ok()?;
    Some(ProcessIdentity {
        pid,
        parent_pid,
        start_time_ticks,
        process_group,
        cgroup_sha256: HashHex::sha256(&cgroup),
        correlation_token_present: false,
        fixture_root_referenced: false,
        survived_teardown: false,
    })
}

fn parse_process_stat(stat: &str) -> Option<(u32, i32, u64)> {
    let (_, parent_pid, process_group, _, start_time_ticks) = parse_proc_stat(stat)?;
    Some((parent_pid, process_group, start_time_ticks))
}

/// Split after the final `)` because the command name can contain spaces and parentheses.
pub(crate) fn parse_proc_stat(stat: &str) -> Option<(char, u32, i32, i32, u64)> {
    let command_end = stat.rfind(')')?;
    let mut fields = stat.get(command_end + 2..)?.split_whitespace();
    let state = fields.next()?.chars().next()?;
    let parent_pid = fields.next()?.parse().ok()?;
    let process_group = fields.next()?.parse().ok()?;
    let session = fields.next()?.parse().ok()?;
    let start_time_ticks = fields.nth(15)?.parse().ok()?;
    Some((state, parent_pid, process_group, session, start_time_ticks))
}

fn process_has_correlation(proc_root: &Path, correlation_id: &str) -> bool {
    if correlation_id.is_empty() {
        return false;
    }
    let Ok(environment) = fs::read(proc_root.join("environ")) else {
        return false;
    };
    let expected = format!("{CORRELATION_ENV}={correlation_id}");
    environment
        .split(|byte| *byte == 0)
        .any(|entry| entry == expected.as_bytes())
}

fn process_references_fixture(proc_root: &Path, fixture_root: &Path) -> bool {
    let raw_root = fixture_root.as_os_str().as_encoded_bytes();
    if raw_root.is_empty() {
        return false;
    }
    if fs::read(proc_root.join("cmdline")).is_ok_and(|bytes| contains_bytes(&bytes, raw_root)) {
        return true;
    }
    if fs::read(proc_root.join("environ")).is_ok_and(|bytes| contains_bytes(&bytes, raw_root)) {
        return true;
    }
    let Ok(entries) = fs::read_dir(proc_root.join("fd")) else {
        return false;
    };
    entries.flatten().any(|entry| {
        fs::read_link(entry.path()).is_ok_and(|target| target.starts_with(fixture_root))
    })
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|part| part == needle)
}

fn fixture_sockets(root: &Path) -> BTreeMap<u64, HashHex> {
    let mut found = BTreeMap::new();
    if let Ok(unix_table) = fs::read("/proc/net/unix") {
        for line in unix_table.split(|byte| *byte == b'\n') {
            let fields = line
                .split(|byte| byte.is_ascii_whitespace())
                .filter(|field| !field.is_empty())
                .collect::<Vec<_>>();
            if let (Some(inode), Some(path)) = (fields.get(6), fields.get(7)) {
                if path.starts_with(root.as_os_str().as_encoded_bytes()) {
                    if let Ok(inode) = std::str::from_utf8(inode)
                        .unwrap_or_default()
                        .parse::<u64>()
                    {
                        found.insert(inode, HashHex::sha256(path));
                    }
                }
            }
        }
    }
    let mut pending = vec![root.to_path_buf()];
    let mut visited = 0_usize;
    while let Some(directory) = pending.pop() {
        let Ok(entries) = fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            visited += 1;
            if visited > 4_096 {
                return found;
            }
            let path = entry.path();
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                continue;
            };
            if metadata.file_type().is_dir() {
                pending.push(path);
            } else if metadata.file_type().is_socket() {
                found.insert(
                    metadata.ino(),
                    HashHex::sha256(path.as_os_str().as_encoded_bytes()),
                );
            }
        }
    }
    found
}

fn collect_open_sockets(
    pid: u32,
    proc_root: &Path,
    known: &BTreeMap<u64, HashHex>,
    found: &mut BTreeMap<u64, SocketIdentity>,
) {
    let Ok(entries) = fs::read_dir(proc_root.join("fd")) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(target) = fs::read_link(entry.path()) else {
            continue;
        };
        let Some(text) = target.to_str() else {
            continue;
        };
        let Some(inode) = text
            .strip_prefix("socket:[")
            .and_then(|value| value.strip_suffix(']'))
            .and_then(|value| value.parse::<u64>().ok())
        else {
            continue;
        };
        if let Some(path_sha256) = known.get(&inode) {
            found.entry(inode).or_insert_with(|| SocketIdentity {
                path_sha256: path_sha256.clone(),
                inode,
                owner_pid: Some(pid),
                survived_teardown: true,
            });
        }
    }
}

fn collect_mounts(pid: u32, proc_root: &Path, fixture_root: &Path, found: &mut Vec<MountIdentity>) {
    let Ok(mountinfo) = fs::read(proc_root.join("mountinfo")) else {
        return;
    };
    let fixture = fixture_root.as_os_str().as_encoded_bytes();
    for line in mountinfo.split(|byte| *byte == b'\n') {
        if contains_bytes(line, fixture) {
            found.push(MountIdentity {
                path_sha256: HashHex::sha256(line),
                owner_pid: pid,
                survived_teardown: true,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_stat_includes_parent_pid() {
        let stat = "321 (command with ) paren) S 77 88 89 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 4242";

        assert_eq!(parse_process_stat(stat), Some((77, 88, 4242)));
    }

    #[test]
    fn selection_includes_descendants_of_every_owned_seed() {
        let mut criteria = ScanCriteria::new("correlation", "/fixture");
        criteria.add_root_pid(10);
        criteria.add_process_group(70);

        let mut processes = BTreeMap::new();
        for identity in [
            identity(10, 1, 10),
            identity(11, 10, 71),
            identity(12, 11, 72),
            correlated(identity(20, 1, 20)),
            identity(21, 20, 73),
            fixture_referencing(identity(30, 1, 30)),
            identity(31, 30, 74),
            identity(40, 1, 70),
            identity(41, 40, 75),
            identity(99, 1, 99),
        ] {
            processes.insert(identity.pid, identity);
        }

        assert_eq!(
            selected_process_ids(&processes, &criteria),
            BTreeSet::from([10, 11, 12, 20, 21, 30, 31, 40, 41])
        );
    }

    #[test]
    fn selection_does_not_include_unrelated_process_trees() {
        let mut criteria = ScanCriteria::new("", "");
        criteria.add_root_pid(10);
        criteria.add_root_pid(0);

        let processes = [
            identity(11, 10, 500),
            identity(12, 11, 501),
            identity(90, 1, 500),
            identity(91, 90, 501),
        ]
        .into_iter()
        .map(|identity| (identity.pid, identity))
        .collect();

        assert_eq!(
            selected_process_ids(&processes, &criteria),
            BTreeSet::from([11, 12])
        );
        assert_eq!(criteria.root_pids().collect::<Vec<_>>(), vec![10]);
    }

    fn identity(pid: u32, parent_pid: u32, process_group: i32) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            parent_pid,
            start_time_ticks: u64::from(pid),
            process_group,
            cgroup_sha256: HashHex::sha256(&pid.to_ne_bytes()),
            correlation_token_present: false,
            fixture_root_referenced: false,
            survived_teardown: false,
        }
    }

    fn correlated(mut identity: ProcessIdentity) -> ProcessIdentity {
        identity.correlation_token_present = true;
        identity
    }

    fn fixture_referencing(mut identity: ProcessIdentity) -> ProcessIdentity {
        identity.fixture_root_referenced = true;
        identity
    }
}
