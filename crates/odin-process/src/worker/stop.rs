//! Check systemd, cgroupfs, and `/proc` independently before reporting a worker stopped.

#[cfg(test)]
use std::process::Child;
use std::process::{ChildStderr, ChildStdout, ExitStatus};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use odin_domain::worker::InvocationId;
use odin_types::WorkerId;
use rustix::process::{pidfd_send_signal, Signal};

use crate::identity::read_process_identity;
use crate::systemd::{ManagerClient, Value, UNIT_INTERFACE};
use crate::ProcessIdentity;

use super::identity::{
    cgroup_directory, cgroup_tree_contains, leader_pidfd, process_is_zombie,
    prove_cgroup_membership, recursive_cgroup_process_count, scan_cgroup_residue,
};
use super::launch::{invocation_from_properties, property_string, WorkerChannel, WorkerIdentity};
use super::{WorkerAuthority, WorkerError, WorkerErrorCode};

/// Allow a requested cooperative shutdown before escalating to signals.
const COOPERATIVE_GRACE: Duration = Duration::from_millis(100);
const TERM_GRACE: Duration = Duration::from_secs(2);
const KILL_WAIT: Duration = Duration::from_secs(10);
const DROP_STOP_GRACE: Duration = Duration::from_millis(500);
const DROP_KILL_WAIT: Duration = Duration::from_millis(1_500);
/// Transient units need time to become active before their identity can be checked.
const UNIT_PROOF_WINDOW: Duration = Duration::from_secs(2);

pub(super) const REAP_POLL: Duration = Duration::from_millis(5);

/// Persisted identity must match before adopting a scope after restart.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryAnchors {
    pub cgroup_path: String,
    pub cgroup_inode: u64,
    pub leader_pid: u32,
    pub leader_start_ticks: u64,
}

/// Record the unit, cgroup, and leader together so recovery can reject reused identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnitIdentityProof {
    pub invocation_id: InvocationId,
    pub cgroup_path: String,
    pub cgroup_inode: u64,
    pub leader_pid: u32,
    pub leader_start_ticks: u64,
}

/// `/proc` survivors supplement the manager query but do not authorize signaling.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WorkerResidue {
    pub unit_active: bool,
    pub cgroup_present: bool,
    pub processes: Vec<ProcessIdentity>,
}

impl WorkerResidue {
    pub fn is_empty(&self) -> bool {
        !self.unit_active && !self.cgroup_present && self.processes.is_empty()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WorkerStopReport {
    pub frozen: bool,
    pub term_sent: bool,
    pub cgroup_kill: bool,
    pub stopped: bool,
    pub residual: Option<WorkerResidue>,
}

/// Independent post-stop observations do not authorize further process control.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WorkerInspection {
    pub unit_identity_verified: bool,
    pub unit_active: bool,
    pub cgroup_present: bool,
    pub cgroup_descendants: u64,
    pub processes: Vec<ProcessIdentity>,
    pub leader: Option<ProcessIdentity>,
    pub leader_reaped: bool,
}

/// Scopes have no Service.MainPID, so recovery checks cgroup membership and `/proc`.
pub(super) struct RecoveredWorker {
    pub(super) unit: String,
    pub(super) invocation_id: InvocationId,
    pub(super) cgroup_path: Option<String>,
}

impl WorkerAuthority {
    fn scope_is_ours(
        &self,
        state: &std::collections::BTreeMap<String, Value>,
    ) -> Result<bool, WorkerError> {
        let unit = &self.identity.unit;
        Ok(property_string(state, "Id", unit)? == *unit
            && invocation_from_properties(state, unit)? == self.identity.invocation_id
            && property_string(state, "ControlGroup", unit)? == self.identity.cgroup_path)
    }

    /// Collected placeholders lose their invocation; retired loaded scopes can lose only their cgroup.
    fn scope_is_retired(
        &self,
        state: &std::collections::BTreeMap<String, Value>,
    ) -> Result<bool, WorkerError> {
        if matches!(state.get("LoadState"), Some(Value::String(load)) if load == "not-found") {
            return Ok(true);
        }
        let inactive = matches!(
            state.get("ActiveState"),
            Some(Value::String(active)) if matches!(active.as_str(), "inactive" | "failed" | "garbage")
        );
        let cleared =
            matches!(state.get("ControlGroup"), Some(Value::String(group)) if group.is_empty());
        Ok(inactive
            && cleared
            && matches!(state.get("Id"), Some(Value::String(id)) if id == &self.identity.unit)
            && invocation_from_properties(state, &self.identity.unit)?
                == self.identity.invocation_id)
    }

    fn same_invocation(
        &self,
        state: &std::collections::BTreeMap<String, Value>,
    ) -> Result<bool, WorkerError> {
        let unit = &self.identity.unit;
        Ok(property_string(state, "Id", unit)? == *unit
            && invocation_from_properties(state, unit)? == self.identity.invocation_id)
    }

    fn stop_already_underway(state: &std::collections::BTreeMap<String, Value>) -> bool {
        let deactivating = matches!(
            state.get("ActiveState"),
            Some(Value::String(active)) if active == "deactivating"
        );
        let cleared = matches!(
            state.get("ControlGroup"),
            Some(Value::String(group)) if group.is_empty()
        );
        deactivating || cleared
    }

    /// A unit already stopping still requires a check that its process tree is gone.
    fn request_cgroup_kill(
        client: &mut ManagerClient,
        unit: &str,
        unit_disappeared: &mut bool,
    ) -> Result<bool, WorkerError> {
        match client.stop_unit(unit, "replace") {
            Ok(_) => Ok(true),
            Err(error) if error.is_no_such_unit() => {
                *unit_disappeared = true;
                Ok(false)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Recovered workers have no inherited output pipes.
    pub fn take_stdout(&mut self) -> Result<ChildStdout, WorkerError> {
        self.held_leader_mut()?
            .stdout
            .take()
            .ok_or_else(|| WorkerError::new(WorkerErrorCode::Io, "worker stdout pipe is missing"))
    }

    /// Recovered workers have no inherited output pipes.
    pub fn take_stderr(&mut self) -> Result<ChildStderr, WorkerError> {
        self.held_leader_mut()?
            .stderr
            .take()
            .ok_or_else(|| WorkerError::new(WorkerErrorCode::Io, "worker stderr pipe is missing"))
    }

    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, WorkerError> {
        let status = self.held_leader_mut()?.try_wait().map_err(reap_error)?;
        if status.is_some() {
            self.exited = true;
        }
        Ok(status)
    }

    pub fn wait(&mut self) -> Result<ExitStatus, WorkerError> {
        let status = self.held_leader_mut()?.wait().map_err(reap_error)?;
        self.exited = true;
        Ok(status)
    }

    /// Test-only child-handle access for the process unit contracts, which
    /// create this authority themselves, so this cannot be a recovered
    /// worker.
    #[cfg(test)]
    pub(crate) fn leader(&mut self) -> &mut Child {
        self.leader
            .as_mut()
            .expect("spawned supervisor authority owns its child")
    }

    #[cfg(test)]
    pub(crate) fn mark_reaped(&mut self) {
        self.exited = true;
    }

    /// If the recovered leader has exited, stopping still proceeds to the cgroup kill.
    pub fn terminate_leader(&mut self) -> bool {
        !self.exited
            && self
                .leader_pidfd
                .as_ref()
                .is_some_and(|pidfd| pidfd_send_signal(pidfd, Signal::TERM).is_ok())
    }

    pub fn kill_leader(&mut self) -> bool {
        !self.exited
            && self
                .leader_pidfd
                .as_ref()
                .is_some_and(|pidfd| pidfd_send_signal(pidfd, Signal::KILL).is_ok())
    }

    /// Check start time so PID reuse or a shared process group cannot identify a different leader.
    pub fn verify_leader(&self, pid: u32) -> Result<(), WorkerError> {
        let identity = read_process_identity(pid).ok_or_else(|| {
            WorkerError::new(
                WorkerErrorCode::IdentityProof,
                format!("pid {pid} has no /proc identity"),
            )
        })?;
        if identity.pid != self.identity.leader_pid
            || identity.start_time_ticks != self.identity.leader_start_ticks
        {
            return Err(WorkerError::new(
                WorkerErrorCode::IdentityProof,
                format!(
                    "pid {pid} is not the proven leader {}:{}",
                    self.identity.leader_pid, self.identity.leader_start_ticks
                ),
            ));
        }
        Ok(())
    }

    /// Reap held children locally; systemd reaps recovered leaders.
    fn poll_exit(&mut self, deadline: Instant) -> bool {
        if self.exited {
            return true;
        }
        if self.leader.is_some() {
            while Instant::now() < deadline {
                match self.try_wait() {
                    Ok(Some(_status)) => return true,
                    Ok(None) => std::thread::sleep(REAP_POLL),
                    Err(_) => return false,
                }
            }
            if matches!(self.try_wait(), Ok(Some(_))) {
                self.exited = true;
            }
            return self.exited;
        }
        while Instant::now() < deadline {
            if !self.recorded_leader_live() {
                self.exited = true;
                return true;
            }
            std::thread::sleep(REAP_POLL);
        }
        if !self.recorded_leader_live() {
            self.exited = true;
        }
        self.exited
    }

    fn recorded_leader_live(&self) -> bool {
        read_process_identity(self.identity.leader_pid).is_some_and(|identity| {
            identity.start_time_ticks == self.identity.leader_start_ticks
                && !process_is_zombie(identity.pid)
        })
    }

    /// Freeze failures must not skip cgroup kill; missing observations cannot count as a clean stop.
    pub fn stop(&mut self) -> Result<WorkerStopReport, WorkerError> {
        self.stop_ladder(None)
    }

    /// Clamp every grace window and reap to the caller's deadline.
    pub fn stop_bounded(&mut self, deadline: Instant) -> Result<WorkerStopReport, WorkerError> {
        self.stop_ladder(Some(deadline))
    }

    /// An elapsed deadline still allows a single nonblocking observation.
    fn stop_window(grace: Duration, deadline: Option<Instant>) -> Instant {
        let end = Instant::now() + grace;
        match deadline {
            Some(deadline) if deadline < end => deadline,
            _ => end,
        }
    }

    fn stop_ladder(&mut self, deadline: Option<Instant>) -> Result<WorkerStopReport, WorkerError> {
        if self.stopped {
            return Ok(WorkerStopReport {
                stopped: true,
                residual: None,
                ..WorkerStopReport::default()
            });
        }

        let cooperatively_exited = self.poll_exit(Self::stop_window(COOPERATIVE_GRACE, deadline));
        let mut frozen = false;
        let mut term_sent = false;
        let mut cgroup_kill = false;
        let mut client = ManagerClient::connect(self.channel.bus())?;
        let mut unit_disappeared = false;
        // A collected unit still requires reaping and independent cgroup and process checks.
        'actuation: {
            let Some(unit_path) = client.get_unit(&self.identity.unit)? else {
                unit_disappeared = true;
                break 'actuation;
            };
            let state = match client.ownership_properties(&unit_path) {
                Ok(state) => state,
                Err(error)
                    if error.is_no_such_unit()
                        || error.name == "org.freedesktop.DBus.Error.UnknownObject" =>
                {
                    unit_disappeared = true;
                    break 'actuation;
                }
                Err(error) => return Err(error.into()),
            };
            if self.scope_is_retired(&state)? {
                unit_disappeared = true;
                break 'actuation;
            }
            let ours = self.scope_is_ours(&state);
            if !ours.as_ref().is_ok_and(|ours| *ours) {
                // Collection between Unit and Scope reads can mix live identity with an empty cgroup.
                let again = match client.ownership_properties(&unit_path) {
                    Ok(state) => state,
                    Err(error)
                        if error.is_no_such_unit()
                            || error.name == "org.freedesktop.DBus.Error.UnknownObject" =>
                    {
                        unit_disappeared = true;
                        break 'actuation;
                    }
                    Err(error) => return Err(error.into()),
                };
                if self.scope_is_retired(&again)? {
                    unit_disappeared = true;
                    break 'actuation;
                }
                ours?;
                if self.same_invocation(&again)? && Self::stop_already_underway(&again) {
                    cgroup_kill = Self::request_cgroup_kill(
                        &mut client,
                        &self.identity.unit,
                        &mut unit_disappeared,
                    )?;
                    break 'actuation;
                }
                return Err(WorkerError::new(
                    WorkerErrorCode::IdentityProof,
                    format!(
                        "scope {} identity changed before stop actuation",
                        self.identity.unit
                    ),
                ));
            }
            let active = property_string(&state, "ActiveState", &self.identity.unit)?;
            if active != "inactive" && active != "failed" && active != "garbage" {
                match client.freeze_unit(&self.identity.unit) {
                    Ok(()) => frozen = true,
                    Err(error) if error.is_no_such_unit() => {
                        unit_disappeared = true;
                        break 'actuation;
                    }
                    // A stopping unit can refuse freezing; skipping the kill would leave descendants alive.
                    Err(error) if error.is_transport() => return Err(error.into()),
                    Err(_) => {}
                }
                if frozen && !cooperatively_exited {
                    term_sent = self.terminate_leader();
                }
                if frozen {
                    // Thaw after signaling so the task can run its TERM handler.
                    match client.thaw_unit(&self.identity.unit) {
                        Ok(()) => {}
                        Err(error) if error.is_no_such_unit() => {
                            unit_disappeared = true;
                            break 'actuation;
                        }
                        Err(error) => return Err(error.into()),
                    }
                    let _ = self.poll_exit(Self::stop_window(TERM_GRACE, deadline));
                }
                cgroup_kill = Self::request_cgroup_kill(
                    &mut client,
                    &self.identity.unit,
                    &mut unit_disappeared,
                )?;
            }
        }
        if unit_disappeared && !cooperatively_exited && self.recorded_leader_live() {
            return Err(WorkerError::new(
                WorkerErrorCode::Stop,
                format!(
                    "scope {} vanished while leader {} was still live",
                    self.identity.unit, self.identity.leader_pid
                ),
            ));
        }
        if !self.exited && !self.poll_exit(Self::stop_window(KILL_WAIT, deadline)) {
            let _ = self.kill_leader();
            if self.leader.is_some() {
                match deadline {
                    None => {
                        self.wait()?;
                    }
                    Some(deadline) => {
                        let _ = self.poll_exit(deadline);
                    }
                }
            } else if !self.poll_exit(Self::stop_window(KILL_WAIT, deadline)) {
                return Err(WorkerError::new(
                    WorkerErrorCode::Reap,
                    format!(
                        "recovered worker leader {} did not exit after cgroup kill",
                        self.identity.leader_pid
                    ),
                ));
            }
        }
        if !self.exited {
            return Err(WorkerError::new(
                WorkerErrorCode::Reap,
                format!(
                    "worker leader {} did not exit after the cgroup kill",
                    self.identity.leader_pid
                ),
            ));
        }
        let residue = self.prove_clean(deadline)?;
        let report = WorkerStopReport {
            frozen,
            term_sent,
            cgroup_kill,
            stopped: residue.is_empty(),
            residual: if residue.is_empty() {
                None
            } else {
                Some(residue)
            },
        };
        if report.stopped {
            self.stopped = true;
        }
        Ok(report)
    }

    /// Check each source independently so a failed query cannot appear as an empty process tree.
    fn prove_clean(&self, deadline: Option<Instant>) -> Result<WorkerResidue, WorkerError> {
        let mut client = ManagerClient::connect(self.channel.bus())?;
        let directory = cgroup_directory(
            &self.channel,
            &self.identity.cgroup_path,
            &self.identity.unit,
        )?;
        let deadline = Self::stop_window(KILL_WAIT, deadline);
        loop {
            let unit_active = match client.get_unit(&self.identity.unit)? {
                None => false,
                Some(unit_path) => {
                    let state = client.ownership_properties(&unit_path)?;
                    let active = property_string(&state, "ActiveState", &self.identity.unit)?;
                    active != "inactive" && active != "failed" && active != "garbage"
                }
            };
            let cgroup_present = match directory.try_exists() {
                Ok(present) => {
                    if present {
                        let _ = recursive_cgroup_process_count(&directory)?;
                    }
                    present
                }
                Err(error) => {
                    return Err(WorkerError::new(
                        WorkerErrorCode::Io,
                        format!(
                            "cannot inspect worker cgroup {}: {error}",
                            directory.display()
                        ),
                    ));
                }
            };
            let processes = scan_cgroup_residue(&self.identity.unit)?;
            let residue = WorkerResidue {
                unit_active,
                cgroup_present,
                processes,
            };
            if residue.is_empty() || Instant::now() >= deadline {
                return Ok(residue);
            }
            std::thread::sleep(REAP_POLL);
        }
    }

    pub fn inspection(&self) -> Result<WorkerInspection, WorkerError> {
        Self::inspect_recorded(
            &self.channel,
            &self.identity.unit,
            &self.identity.invocation_id,
            &RecoveryAnchors {
                cgroup_path: self.identity.cgroup_path.clone(),
                cgroup_inode: self.identity.cgroup_inode,
                leader_pid: self.identity.leader_pid,
                leader_start_ticks: self.identity.leader_start_ticks,
            },
        )
    }

    pub fn unit_absent(channel: &WorkerChannel, unit: &str) -> Result<bool, WorkerError> {
        let mut client = ManagerClient::connect(channel.bus())?;
        Ok(client.get_unit(unit)?.is_none())
    }

    /// Check the running service's cgroup and leader identity before recording it for recovery.
    pub fn prove_unit_identity(
        channel: &WorkerChannel,
        expected_unit: &str,
    ) -> Result<UnitIdentityProof, WorkerError> {
        let deadline = Instant::now() + UNIT_PROOF_WINDOW;
        let mut proved = None;
        while proved.is_none() && Instant::now() < deadline {
            let mut client = ManagerClient::connect(channel.bus())?;
            if let Some(unit_path) = client.get_unit(expected_unit)? {
                let unit_state = client.unit_properties(&unit_path, UNIT_INTERFACE)?;
                let service_state = client.service_properties(&unit_path)?;
                let active = property_string(&unit_state, "ActiveState", expected_unit)?;
                match active.as_str() {
                    "active" => proved = Some((unit_path, unit_state, service_state)),
                    // A starting transient unit may briefly remain activating.
                    "activating" | "reloading" => std::thread::sleep(REAP_POLL),
                    state => {
                        return Err(WorkerError::new(
                            WorkerErrorCode::ScopeRejected,
                            format!(
                                "unit {expected_unit} entered {state} before its identity proof"
                            ),
                        ));
                    }
                }
            } else {
                std::thread::sleep(REAP_POLL);
            }
        }
        let Some((unit_path, unit_state, service_state)) = proved else {
            return Err(WorkerError::new(
                WorkerErrorCode::ScopeRejected,
                format!(
                    "unit {expected_unit} did not become active before the identity proof deadline"
                ),
            ));
        };
        let id = property_string(&unit_state, "Id", expected_unit)?;
        if id != expected_unit {
            return Err(WorkerError::new(
                WorkerErrorCode::IdentityProof,
                format!("unit name {expected_unit} is loaded as {id:?}"),
            ));
        }
        // ControlGroup lives on the concrete Service or Scope interface.
        let mut client = ManagerClient::connect(channel.bus())?;
        let state = client.ownership_properties(&unit_path)?;
        let invocation_id = invocation_from_properties(&state, expected_unit)?;
        let cgroup_path = property_string(&state, "ControlGroup", expected_unit)?;
        let leader_pid = match service_state
            .as_ref()
            .and_then(|state| state.get("MainPID"))
        {
            Some(Value::Uint32(pid)) if *pid > 0 => *pid,
            _ => {
                return Err(WorkerError::new(
                    WorkerErrorCode::IdentityProof,
                    format!(
                        "unit {expected_unit} has no service main process to anchor its identity"
                    ),
                ));
            }
        };
        let cgroup_inode =
            prove_cgroup_membership(channel, &cgroup_path, expected_unit, leader_pid)?;
        let leader = read_process_identity(leader_pid).ok_or_else(|| {
            WorkerError::new(
                WorkerErrorCode::IdentityProof,
                format!(
                    "cannot read /proc identity for unit {expected_unit} main process {leader_pid}"
                ),
            )
        })?;
        Ok(UnitIdentityProof {
            invocation_id,
            cgroup_path,
            cgroup_inode,
            leader_pid,
            leader_start_ticks: leader.start_time_ticks,
        })
    }

    /// Inspect persisted identity without signaling a worker that may already have exited.
    pub fn inspect_recorded(
        channel: &WorkerChannel,
        expected_unit: &str,
        invocation: &InvocationId,
        anchors: &RecoveryAnchors,
    ) -> Result<WorkerInspection, WorkerError> {
        let mut client = ManagerClient::connect(channel.bus())?;
        let (unit_identity_verified, unit_active) = match client
            .get_unit_by_invocation(invocation.as_bytes())?
        {
            Some(unit_path) => {
                let state = client.ownership_properties(&unit_path)?;
                let id = property_string(&state, "Id", expected_unit)?;
                let found = invocation_from_properties(&state, expected_unit)?;
                let cgroup = property_string(&state, "ControlGroup", expected_unit)?;
                let active = property_string(&state, "ActiveState", expected_unit)?;
                let unit_active = active != "inactive" && active != "failed" && active != "garbage";
                // systemd can clear ControlGroup before unloading; check cgroupfs and `/proc` separately.
                let retired_cgroup = !unit_active && cgroup.is_empty();
                if id != expected_unit
                    || found != *invocation
                    || (cgroup != anchors.cgroup_path && !retired_cgroup)
                {
                    return Err(WorkerError::new(
                        WorkerErrorCode::IdentityProof,
                        format!(
                            "manager identity for recovered scope {expected_unit} changed: id={id:?}, invocation={found}, cgroup={cgroup:?}; expected invocation={invocation}, cgroup={:?}",
                            anchors.cgroup_path
                        ),
                    ));
                }
                (true, unit_active)
            }
            None => {
                if let Some(unit_path) = client.get_unit(expected_unit)? {
                    let state = client.ownership_properties(&unit_path)?;
                    let found = invocation_from_properties(&state, expected_unit)?;
                    return Err(WorkerError::new(
                        WorkerErrorCode::IdentityProof,
                        format!("unit name {expected_unit} was reused by InvocationID {found}"),
                    ));
                }
                (true, false)
            }
        };

        use std::os::unix::fs::MetadataExt;
        let directory = cgroup_directory(channel, &anchors.cgroup_path, expected_unit)?;
        let (cgroup_present, cgroup_descendants) = match directory.try_exists() {
            Ok(false) => (false, 0),
            Ok(true) => {
                let metadata = std::fs::metadata(&directory).map_err(|error| {
                    WorkerError::new(
                        WorkerErrorCode::Io,
                        format!("cannot stat cgroup {}: {error}", directory.display()),
                    )
                })?;
                if !metadata.is_dir() || metadata.ino() != anchors.cgroup_inode {
                    return Err(WorkerError::new(
                        WorkerErrorCode::IdentityProof,
                        format!(
                            "cgroup inode for {expected_unit} changed from {} to {}",
                            anchors.cgroup_inode,
                            metadata.ino()
                        ),
                    ));
                }
                (true, recursive_cgroup_process_count(&directory)?)
            }
            Err(error) => {
                return Err(WorkerError::new(
                    WorkerErrorCode::Io,
                    format!("cannot inspect cgroup {}: {error}", directory.display()),
                ));
            }
        };
        let processes = scan_cgroup_residue(expected_unit)?;
        let leader = read_process_identity(anchors.leader_pid)
            .filter(|identity| identity.start_time_ticks == anchors.leader_start_ticks);
        let leader_reaped = leader.is_none();
        Ok(WorkerInspection {
            unit_identity_verified,
            unit_active,
            cgroup_present,
            cgroup_descendants,
            processes,
            leader,
            leader_reaped,
        })
    }

    /// Recovery must check persisted identities before adopting the returned unit.
    pub(super) fn recover_by_invocation(
        channel: &WorkerChannel,
        unit_prefix: &str,
        invocation: &InvocationId,
    ) -> Result<Option<RecoveredWorker>, WorkerError> {
        let mut client = ManagerClient::connect(channel.bus())?;
        let Some(unit_path) = client.get_unit_by_invocation(invocation.as_bytes())? else {
            return Ok(None);
        };
        let state = client.ownership_properties(&unit_path)?;
        let unit = property_string(&state, "Id", "InvocationID recovery")?;
        let admitted_suffix = unit.ends_with(".scope") || unit.ends_with(".service");
        if !unit.starts_with(unit_prefix) || !admitted_suffix {
            // Do not adopt an invocation outside the caller's worker namespace.
            return Ok(None);
        }
        let found = invocation_from_properties(&state, &unit)?;
        if found != *invocation {
            return Err(WorkerError::new(
                WorkerErrorCode::IdentityProof,
                format!("GetUnitByInvocationID returned {unit} with a different InvocationID"),
            ));
        }
        Ok(Some(RecoveredWorker {
            unit,
            invocation_id: found,
            cgroup_path: state
                .get("ControlGroup")
                .and_then(Value::as_str)
                .map(str::to_owned),
        }))
    }

    /// Recheck unit, cgroup, and leader identity before retaining a pidfd or stopping the scope.
    pub fn recover(
        channel: &WorkerChannel,
        worker_id: WorkerId,
        expected_unit: &str,
        invocation: &InvocationId,
        anchors: RecoveryAnchors,
    ) -> Result<Option<Self>, WorkerError> {
        let Some(recovered) = Self::recover_by_invocation(channel, expected_unit, invocation)?
        else {
            return Ok(None);
        };
        if recovered.unit != expected_unit || recovered.invocation_id != *invocation {
            return Err(WorkerError::new(
                WorkerErrorCode::IdentityProof,
                format!(
                    "InvocationID recovery returned {}, expected exact unit {expected_unit}",
                    recovered.unit
                ),
            ));
        }
        let cgroup_path = recovered.cgroup_path.ok_or_else(|| {
            WorkerError::new(
                WorkerErrorCode::IdentityProof,
                format!("recovered scope {expected_unit} has no ControlGroup"),
            )
        })?;
        if cgroup_path != anchors.cgroup_path {
            return Err(WorkerError::new(
                WorkerErrorCode::IdentityProof,
                format!(
                    "recovered scope {expected_unit} cgroup changed from {:?} to {:?}",
                    anchors.cgroup_path, cgroup_path
                ),
            ));
        }
        use std::os::unix::fs::MetadataExt;
        let directory = cgroup_directory(channel, &cgroup_path, expected_unit)?;
        let metadata = std::fs::metadata(&directory).map_err(|error| {
            WorkerError::new(
                WorkerErrorCode::IdentityProof,
                format!(
                    "recovered scope {expected_unit} cgroup {} is unreadable: {error}",
                    directory.display()
                ),
            )
        })?;
        if !metadata.is_dir() || metadata.ino() != anchors.cgroup_inode {
            return Err(WorkerError::new(
                WorkerErrorCode::IdentityProof,
                format!(
                    "recovered scope {expected_unit} cgroup inode changed from {} to {}",
                    anchors.cgroup_inode,
                    metadata.ino()
                ),
            ));
        }

        let recorded_live = read_process_identity(anchors.leader_pid).is_some_and(|identity| {
            identity.start_time_ticks == anchors.leader_start_ticks
                && !process_is_zombie(identity.pid)
        });
        // Scopes have no Service.MainPID, so a live recorded leader must still belong to the cgroup.
        let leader_pidfd = if recorded_live {
            let leader_text = anchors.leader_pid.to_string();
            if !cgroup_tree_contains(&directory, &leader_text)? {
                return Err(WorkerError::new(
                    WorkerErrorCode::IdentityProof,
                    format!(
                        "recovered scope {expected_unit} live leader {} is not a member of cgroup {}",
                        anchors.leader_pid,
                        directory.display()
                    ),
                ));
            }
            Some(leader_pidfd(anchors.leader_pid)?)
        } else {
            None
        };
        Ok(Some(Self {
            channel: channel.clone(),
            identity: WorkerIdentity {
                worker_id,
                unit: expected_unit.to_owned(),
                invocation_id: *invocation,
                cgroup_path,
                cgroup_inode: anchors.cgroup_inode,
                leader_pid: anchors.leader_pid,
                leader_start_ticks: anchors.leader_start_ticks,
            },
            correlation: None,
            stdin_serial: Arc::new(Mutex::new(())),
            leader: None,
            leader_pidfd,
            payload_gate: None,
            payload_released: true,
            recovered: true,
            exited: !recorded_live,
            stopped: false,
            abandoned: false,
            abandonment: None,
        }))
    }
}

impl Drop for WorkerAuthority {
    fn drop(&mut self) {
        if self.stopped
            || self.abandoned
            || self
                .abandonment
                .as_ref()
                .is_some_and(|signal| signal.load(std::sync::atomic::Ordering::Acquire))
        {
            return;
        }
        // Ordinary drop attempts a stop; a process crash leaves recovery to the persisted InvocationID.
        if !self.exited {
            let _ = self.terminate_leader();

            let _ = self.poll_exit(Instant::now() + DROP_STOP_GRACE);
        }
        // A reused unit name with a different invocation is not this worker.
        if let Ok(mut client) = ManagerClient::connect(self.channel.bus()) {
            let ours = client
                .get_unit(&self.identity.unit)
                .ok()
                .flatten()
                .and_then(|unit_path| client.ownership_properties(&unit_path).ok())
                .is_some_and(|state| self.scope_is_ours(&state).unwrap_or(false));
            if ours {
                let _ = client.stop_unit(&self.identity.unit, "replace");
            }
        }
        if !self.exited && !self.poll_exit(Instant::now() + DROP_KILL_WAIT) {
            let _ = self.kill_leader();
            if let Some(leader) = self.leader.as_mut() {
                let _ = leader.wait();
                self.exited = true;
            } else {
                let _ = self.poll_exit(Instant::now() + DROP_KILL_WAIT);
            }
        }
        if !self.exited {
            if let Some(leader) = self.leader.as_mut() {
                let _ = leader.kill();
                let _ = leader.wait();
                self.exited = true;
            }
        }
    }
}

fn reap_error(error: std::io::Error) -> WorkerError {
    WorkerError::new(WorkerErrorCode::Reap, error.to_string())
}
