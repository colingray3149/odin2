use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::{ProcessError, ProcessErrorCode, CORRELATION_ENV};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub parent_pid: u32,
    pub start_time_ticks: u64,
    pub process_group: i32,
    pub survived_teardown: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IdentitySnapshot {
    pub processes: Vec<ProcessIdentity>,
}

/// A process the scan read, and whether it carries the correlation token or points at the fixture root.
struct Candidate {
    identity: ProcessIdentity,
    marked: bool,
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
            let Some(identity) = read_process_identity(pid) else {
                continue;
            };
            let proc_root = entry.path();
            let marked = process_has_correlation(&proc_root, &criteria.correlation_id)
                || process_references_fixture(&proc_root, criteria.fixture_root());
            processes.insert(pid, Candidate { identity, marked });
        }

        let mut found = selected_process_ids(&processes, criteria)
            .into_iter()
            .filter_map(|pid| processes.remove(&pid))
            .map(|candidate| ProcessIdentity {
                survived_teardown: true,
                ..candidate.identity
            })
            .collect::<Vec<_>>();
        found.sort_by_key(|identity| (identity.pid, identity.start_time_ticks));
        Ok(IdentitySnapshot { processes: found })
    }
}

fn selected_process_ids(
    processes: &BTreeMap<u32, Candidate>,
    criteria: &ScanCriteria,
) -> BTreeSet<u32> {
    let mut pending = criteria.root_pids.iter().copied().collect::<Vec<_>>();
    pending.extend(processes.values().filter_map(|candidate| {
        (criteria
            .process_groups
            .contains(&candidate.identity.process_group)
            || candidate.marked)
            .then_some(candidate.identity.pid)
    }));

    let mut children = BTreeMap::<u32, Vec<u32>>::new();
    for candidate in processes.values() {
        children
            .entry(candidate.identity.parent_pid)
            .or_default()
            .push(candidate.identity.pid);
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
    Some(ProcessIdentity {
        pid,
        parent_pid,
        start_time_ticks,
        process_group,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scan_by_process_group_reports_the_live_member_even_with_no_fixture_root() {
        use std::os::unix::process::CommandExt;
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .expect("spawn sleep");
        let group = i32::try_from(child.id()).expect("pid fits");
        let mut criteria = ScanCriteria::new("", "");
        criteria.add_process_group(group);
        let snapshot = SurvivorScanner.scan(&criteria);
        child.kill().expect("kill sleep");
        child.wait().expect("reap sleep");
        let found = snapshot.expect("scan").processes;
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].pid, child.id());
        assert_eq!(found[0].process_group, group);
        assert!(found[0].survived_teardown);
    }

    #[test]
    fn selection_includes_descendants_of_every_owned_seed() {
        let mut criteria = ScanCriteria::new("correlation", "/fixture");
        criteria.add_root_pid(10);
        criteria.add_process_group(70);

        let mut processes = BTreeMap::new();
        for candidate in [
            candidate(10, 1, 10, false),
            candidate(11, 10, 71, false),
            candidate(12, 11, 72, false),
            candidate(20, 1, 20, true),
            candidate(21, 20, 73, false),
            candidate(30, 1, 30, true),
            candidate(31, 30, 74, false),
            candidate(40, 1, 70, false),
            candidate(41, 40, 75, false),
            candidate(99, 1, 99, false),
        ] {
            processes.insert(candidate.identity.pid, candidate);
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
            candidate(11, 10, 500, false),
            candidate(12, 11, 501, false),
            candidate(90, 1, 500, false),
            candidate(91, 90, 501, false),
        ]
        .into_iter()
        .map(|candidate| (candidate.identity.pid, candidate))
        .collect();

        assert_eq!(
            selected_process_ids(&processes, &criteria),
            BTreeSet::from([11, 12])
        );
        assert_eq!(criteria.root_pids().collect::<Vec<_>>(), vec![10]);
    }

    fn candidate(pid: u32, parent_pid: u32, process_group: i32, marked: bool) -> Candidate {
        Candidate {
            identity: ProcessIdentity {
                pid,
                parent_pid,
                start_time_ticks: u64::from(pid),
                process_group,
                survived_teardown: false,
            },
            marked,
        }
    }
}
