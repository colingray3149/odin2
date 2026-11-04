//! Declared lane wall and build-slot admission shared by coding operations.

use odin_domain::Scope;

use super::DaemonCodingRoute;

impl DaemonCodingRoute {
    /// The calling lane, its declared `limits.build_slots` floor, and the
    /// effective cap after any typed raise, when the pinned registry
    /// declares one. `None` means the lane has no build-slot budget, so
    /// cargo-slot and the daemon admit without a lane cap.
    pub(crate) fn lane_build_slots(
        &self,
        scope: &Scope,
    ) -> Result<Option<(String, u32, u32)>, String> {
        let Some(lane) = scope.lane.as_ref() else {
            return Ok(None);
        };
        let Some(pin) = &self.registry else {
            return Ok(None);
        };
        let snapshot = pin.current();
        let Some(odin_registry::ObjectConfig::Lane(declared)) = snapshot
            .object(odin_registry::RegistryKind::Lane, lane.as_str())
            .map(|object| &object.config)
        else {
            return Err(format!(
                "lane {lane} has no lane declaration; limits.build_slots cannot be read"
            ));
        };
        let Some(floor) = declared.limits.build_slots.map(|cap| u32::from(cap.get())) else {
            return Ok(None);
        };
        let effective = odin_registry::RaisedLaneBudgets::load(&self.state_root.join("huginn"))?
            .and_then(|raised| {
                raised.effective(
                    lane.as_str(),
                    Some(floor),
                    odin_registry::LaneBudgetKind::BuildSlots,
                )
            })
            .unwrap_or(floor);
        Ok(Some((lane.as_str().to_owned(), floor, effective)))
    }

    /// The lane identity the build environment carries: `ODIN_LANE` alone.
    /// The cap itself never rides in the environment — a shell cannot lift
    /// `limits.build_slots` by exporting a bigger number. Instead the
    /// declared floor is published under the lane admission lock beside the
    /// slot marks, with a link to the raise store `task.steer` writes, and
    /// `tools/cargo-slot` reads both. Empty when the lane declares no cap.
    pub(crate) fn lane_slot_env(&self, scope: &Scope) -> Result<Vec<(String, String)>, String> {
        let Some((lane, floor, _)) = self.lane_build_slots(scope)? else {
            return Ok(Vec::new());
        };
        let budgets = self
            .state_root
            .join("huginn")
            .join(odin_registry::LANE_BUDGET_FILE);
        LaneBuildSlot::publish_floor(&lane, floor, &budgets)?;
        Ok(vec![("ODIN_LANE".to_owned(), lane)])
    }

    /// Holds one of the lane's declared build slots for a cargo run, using
    /// the same marks `tools/cargo-slot` counts. At the exact cap the run
    /// is refused by name and nothing starts. A lane with no declared cap
    /// holds nothing.
    pub(crate) fn hold_lane_build_slot(
        &self,
        scope: &Scope,
    ) -> Result<Option<LaneBuildSlot>, String> {
        self.admit_lane_wall(scope)?;
        let Some((lane, _, effective)) = self.lane_build_slots(scope)? else {
            return Ok(None);
        };
        LaneBuildSlot::acquire(&lane, effective).map(Some)
    }

    /// Refuses a build once a live worker of this lane has filled
    /// `limits.wall_seconds` (the declaration, or a typed raise above it).
    /// A lane that declares no wall admits. The clock is the shared lease
    /// `task` rows publish, not a number a shell can export.
    fn admit_lane_wall(&self, scope: &Scope) -> Result<(), String> {
        let Some(lane) = scope.lane.as_ref() else {
            return Ok(());
        };
        let Some(pin) = &self.registry else {
            return Ok(());
        };
        let snapshot = pin.current();
        let Some(odin_registry::ObjectConfig::Lane(declared)) = snapshot
            .object(odin_registry::RegistryKind::Lane, lane.as_str())
            .map(|object| &object.config)
        else {
            return Err(format!(
                "lane {lane} has no lane declaration; limits.wall_seconds cannot be read"
            ));
        };
        let floor = odin_registry::LaneBudgetKind::WallSeconds.declared(&declared.limits);
        let huginn = self.state_root.join("huginn");
        let raised = odin_registry::RaisedLaneBudgets::load(&huginn)?;
        let cap = raised
            .as_ref()
            .and_then(|raised| {
                raised.effective(
                    lane.as_str(),
                    floor,
                    odin_registry::LaneBudgetKind::WallSeconds,
                )
            })
            .or(floor);
        let started = odin_registry::LaneWallLease::load(&huginn)?
            .and_then(|lease| lease.started(lane.as_str()));
        odin_registry::refuse_wall(cap, started, odin_registry::unix_millis())
            .map_err(|detail| format!("lane {lane} wall budget refused: {detail}"))
    }
}
/// One held lane build slot. Drop releases it, including on cancel.
pub(crate) struct LaneBuildSlot {
    file: std::fs::File,
    path: std::path::PathBuf,
}

impl LaneBuildSlot {
    fn acquire(lane: &str, cap: u32) -> Result<Self, String> {
        Self::acquire_in(std::path::Path::new("/tmp/odin-coord"), lane, cap)
    }

    /// A slot mark is `lane-<lane>.<pid>.<counter>`: digits only after
    /// the lane prefix. The admission lock, the published floor and the
    /// raise-store link share the prefix and are never marks.
    fn is_mark(name: &str, lane: &str) -> bool {
        let Some(rest) = name.strip_prefix(&format!("lane-{lane}.")) else {
            return false;
        };
        let Some((pid, counter)) = rest.split_once('.') else {
            return false;
        };
        !pid.is_empty()
            && !counter.is_empty()
            && pid.bytes().all(|byte| byte.is_ascii_digit())
            && counter.bytes().all(|byte| byte.is_ascii_digit())
    }

    fn acquire_in(directory: &std::path::Path, lane: &str, cap: u32) -> Result<Self, String> {
        use rustix::fs::{flock, FlockOperation};
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT_MARK: AtomicU64 = AtomicU64::new(0);
        std::fs::create_dir_all(directory).map_err(|error| error.to_string())?;
        // This is the same admission lock held by tools/cargo-slot. It
        // serializes counting and marker creation across both callers.
        let admission = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(directory.join(format!("lane-{lane}.lock")))
            .map_err(|error| error.to_string())?;
        flock(&admission, FlockOperation::LockExclusive)
            .map_err(|error| format!("lane {lane} build slot admission: {error}"))?;
        let mut held = 0u32;
        for entry in std::fs::read_dir(directory).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !Self::is_mark(name, lane) {
                continue;
            }
            let file = match std::fs::File::open(entry.path()) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.to_string()),
            };
            match flock(&file, FlockOperation::NonBlockingLockShared) {
                Ok(()) => {
                    let _ = std::fs::remove_file(entry.path());
                }
                Err(error) if error == rustix::io::Errno::WOULDBLOCK => held += 1,
                Err(error) => return Err(format!("lane {lane} build slot: {error}")),
            }
        }
        if held >= cap {
            return Err(format!(
                "lane {lane} already holds {held} build slot(s); limits.build_slots is {cap}"
            ));
        }
        let path = directory.join(format!(
            "lane-{lane}.{}.{}",
            std::process::id(),
            NEXT_MARK.fetch_add(1, Ordering::Relaxed)
        ));
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .map_err(|error| error.to_string())?;
        flock(&file, FlockOperation::NonBlockingLockExclusive)
            .map_err(|error| format!("lane {lane} build slot could not be held: {error}"))?;
        Ok(Self { file, path })
    }

    /// Publishes the declared floor and the raise-store link `tools/cargo-slot`
    /// reads, under the same admission lock as the marks: a counting pass
    /// never sees a half-published budget. The floor is the declaration,
    /// never a raised value, so a raise can only lift what the shell sees.
    fn publish_floor(lane: &str, floor: u32, budgets: &std::path::Path) -> Result<(), String> {
        Self::publish_floor_in(
            std::path::Path::new("/tmp/odin-coord"),
            lane,
            floor,
            budgets,
        )
    }

    fn publish_floor_in(
        directory: &std::path::Path,
        lane: &str,
        floor: u32,
        budgets: &std::path::Path,
    ) -> Result<(), String> {
        use rustix::fs::{flock, FlockOperation};
        std::fs::create_dir_all(directory).map_err(|error| error.to_string())?;
        let admission = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(directory.join(format!("lane-{lane}.lock")))
            .map_err(|error| error.to_string())?;
        flock(&admission, FlockOperation::LockExclusive)
            .map_err(|error| format!("lane {lane} build slot admission: {error}"))?;
        std::fs::write(
            directory.join(format!("lane-{lane}.cap")),
            floor.to_string(),
        )
        .map_err(|error| error.to_string())?;
        let link = directory.join(format!("lane-{lane}.budgets"));
        // The store may not exist yet (no raise ever); the link dangles
        // until the first raise creates its target.
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(budgets, &link).map_err(|error| error.to_string())
    }
}

impl Drop for LaneBuildSlot {
    fn drop(&mut self) {
        use rustix::fs::{flock, FlockOperation};
        let _ = flock(&self.file, FlockOperation::Unlock);
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod lane_build_slot_tests {
    use super::LaneBuildSlot;
    use rustix::fs::{flock, FlockOperation};

    #[test]
    fn admission_lock_is_not_a_slot_and_shell_markers_are_counted() {
        let dir = tempfile::tempdir().unwrap();
        let first = LaneBuildSlot::acquire_in(dir.path(), "lane", 1).unwrap();
        let error = LaneBuildSlot::acquire_in(dir.path(), "lane", 1)
            .err()
            .unwrap();
        assert!(error.contains("limits.build_slots is 1"));
        drop(first);
        // The mark shape tools/cargo-slot holds: pid and counter.
        let marker = dir.path().join("lane-lane.12345.678");
        let shell_slot = std::fs::File::create(&marker).unwrap();
        flock(&shell_slot, FlockOperation::LockExclusive).unwrap();
        let error = LaneBuildSlot::acquire_in(dir.path(), "lane", 1)
            .err()
            .unwrap();
        assert!(error.contains("limits.build_slots is 1"));
        drop(shell_slot);
        let _slot = LaneBuildSlot::acquire_in(dir.path(), "lane", 1).unwrap();
    }

    #[test]
    fn concurrent_slots_in_one_process_have_distinct_markers() {
        let dir = tempfile::tempdir().unwrap();
        let first = LaneBuildSlot::acquire_in(dir.path(), "lane", 2).unwrap();
        let second = LaneBuildSlot::acquire_in(dir.path(), "lane", 2).unwrap();
        assert_ne!(first.path, second.path);
        assert!(LaneBuildSlot::acquire_in(dir.path(), "lane", 2).is_err());
    }
}
