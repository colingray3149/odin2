//! Declared per-lane wall, build-slot, and pod budget, plus the typed
//! raise `task.steer` applies. Enforcement lives at the admission sites;
//! this module only names the keys, the effective cap, and the exact-limit
//! refusal.

#[cfg(test)]
use std::num::NonZeroU16;
use std::num::NonZeroU32;

use serde::{Deserialize, Serialize};

use super::seat::LaneLimitsToml;

/// Registry keys named in every refusal and raise.
pub const WALL_LIMIT_KEY: &str = "limits.wall_seconds";
pub const BUILD_SLOTS_LIMIT_KEY: &str = "limits.build_slots";
pub const PODS_LIMIT_KEY: &str = "limits.pods";

/// One dimension of the declared lane budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LaneBudgetKind {
    WallSeconds,
    BuildSlots,
    Pods,
}

impl LaneBudgetKind {
    pub const fn key(self) -> &'static str {
        match self {
            Self::WallSeconds => WALL_LIMIT_KEY,
            Self::BuildSlots => BUILD_SLOTS_LIMIT_KEY,
            Self::Pods => PODS_LIMIT_KEY,
        }
    }

    pub fn declared(self, limits: &LaneLimitsToml) -> Option<u32> {
        match self {
            Self::WallSeconds => limits.wall_seconds.map(NonZeroU32::get),
            Self::BuildSlots => limits.build_slots.map(|value| u32::from(value.get())),
            Self::Pods => limits.pods.map(|value| u32::from(value.get())),
        }
    }
}

/// A typed `task.steer` raise of one declared lane dimension.
///
/// The caller names the dimension and the new absolute cap. A raise is
/// refused when the lane does not declare that dimension, when the value
/// is below the declared floor, or when it equals the current effective
/// cap (the exact limit).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LaneBudgetRaise {
    pub kind: LaneBudgetKind,
    pub value: u32,
}

/// Why a typed raise was refused. The detail names the limit key and the
/// exact current cap, so the caller can see the boundary it hit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaneBudgetRefusal {
    pub kind: &'static str,
    pub detail: String,
}

impl LaneBudgetRefusal {
    fn not_above(kind: LaneBudgetKind, current: u32, value: u32) -> Self {
        Self {
            kind: "exact_limit",
            detail: format!(
                "{} is {current}; a raise to {value} is not strictly above it",
                kind.key()
            ),
        }
    }

    fn below_floor(kind: LaneBudgetKind, floor: u32, value: u32) -> Self {
        Self {
            kind: "below_declared",
            detail: format!(
                "{} cannot be lowered to {value}; the declared floor is {floor}",
                kind.key()
            ),
        }
    }

    fn undeclared(kind: LaneBudgetKind) -> Self {
        Self {
            kind: "undeclared_limit",
            detail: format!(
                "{} is not declared on this lane; task.steer cannot invent a budget",
                kind.key()
            ),
        }
    }
}

/// Effective caps: the declaration, plus any typed raises above it.
/// A dimension the lane does not declare stays absent and is not enforced.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LaneBudget {
    pub wall_seconds: Option<u32>,
    pub build_slots: Option<u32>,
    pub pods: Option<u32>,
}

impl LaneBudget {
    pub fn declared(limits: &LaneLimitsToml) -> Self {
        Self {
            wall_seconds: LaneBudgetKind::WallSeconds.declared(limits),
            build_slots: LaneBudgetKind::BuildSlots.declared(limits),
            pods: LaneBudgetKind::Pods.declared(limits),
        }
    }

    pub const fn cap(self, kind: LaneBudgetKind) -> Option<u32> {
        match kind {
            LaneBudgetKind::WallSeconds => self.wall_seconds,
            LaneBudgetKind::BuildSlots => self.build_slots,
            LaneBudgetKind::Pods => self.pods,
        }
    }

    /// Applies one typed raise. Equality with the current cap is the
    /// exact-limit refusal; a value under the declared floor is refused
    /// too. An undeclared dimension cannot be raised into existence.
    pub fn raise(
        &mut self,
        declared: &LaneLimitsToml,
        raise: LaneBudgetRaise,
    ) -> Result<u32, LaneBudgetRefusal> {
        let Some(floor) = raise.kind.declared(declared) else {
            return Err(LaneBudgetRefusal::undeclared(raise.kind));
        };
        if raise.value < floor {
            return Err(LaneBudgetRefusal::below_floor(
                raise.kind,
                floor,
                raise.value,
            ));
        }
        let current = self.cap(raise.kind).unwrap_or(floor);
        if raise.value <= current {
            return Err(LaneBudgetRefusal::not_above(
                raise.kind,
                current,
                raise.value,
            ));
        }
        match raise.kind {
            LaneBudgetKind::WallSeconds => self.wall_seconds = Some(raise.value),
            LaneBudgetKind::BuildSlots => self.build_slots = Some(raise.value),
            LaneBudgetKind::Pods => self.pods = Some(raise.value),
        }
        Ok(raise.value)
    }
}

/// Whether `used` already fills `cap`. A missing cap admits. At the exact
/// cap the action is refused and the detail names the key and both numbers.
pub fn at_cap(kind: LaneBudgetKind, cap: Option<u32>, used: u32) -> Result<(), String> {
    let Some(cap) = cap else {
        return Ok(());
    };
    if used >= cap {
        return Err(format!(
            "{used} already fills {key} of {cap}",
            key = kind.key()
        ));
    }
    Ok(())
}

/// Runtime raises live beside the huginn root, not in the registry. A
/// declaration is the floor; this file is the effective cap until a later
/// raise replaces it. A missing file is no raise. An unreadable or
/// malformed file is an error: it is never treated as no raise.
pub const LANE_BUDGET_FILE: &str = "lane-budgets.json";

/// One lane's raised caps. A missing dimension was not raised.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RaisedLaneBudgets {
    #[serde(default)]
    pub lanes: std::collections::BTreeMap<String, LaneBudget>,
}

impl RaisedLaneBudgets {
    /// Shared-lock read. `Ok(None)` only when the file is absent.
    pub fn load(huginn_root: &std::path::Path) -> Result<Option<Self>, String> {
        let path = huginn_root.join(LANE_BUDGET_FILE);
        let _lock = RaiseLock::acquire(huginn_root)?;
        Self::read_locked(&path)
    }

    /// Exclusive read-modify-write of one dimension. Concurrent raises of
    /// other lanes or dimensions are preserved. The replacement is a unique
    /// temp file renamed over the live file.
    pub fn raise(
        huginn_root: &std::path::Path,
        lane: &str,
        kind: LaneBudgetKind,
        value: u32,
    ) -> Result<Self, String> {
        let path = huginn_root.join(LANE_BUDGET_FILE);
        let _lock = RaiseLock::acquire(huginn_root)?;
        let mut budgets = Self::read_locked(&path)?.unwrap_or_default();
        budgets.apply(lane, kind, value);
        budgets.write_locked(&path)?;
        Ok(budgets)
    }

    fn read_locked(path: &std::path::Path) -> Result<Option<Self>, String> {
        match crate::snapshot::read_regular_file(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|error| format!("{} is malformed: {error}", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("{} is unreadable: {error}", path.display())),
        }
    }

    fn write_locked(&self, path: &std::path::Path) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(self).map_err(|error| error.to_string())?;
        crate::snapshot::atomic_write(path, &bytes).map_err(|error| {
            format!(
                "{} {}: {}",
                error.action,
                error.path.display(),
                error.source
            )
        })
    }

    /// The effective cap when the lane declares one. A stored raise can
    /// only lift that floor. An undeclared dimension stays absent: a raise
    /// file cannot invent a budget the registry does not name.
    pub fn effective(
        &self,
        lane: &str,
        declared: Option<u32>,
        kind: LaneBudgetKind,
    ) -> Option<u32> {
        let floor = declared?;
        let raised = self.lanes.get(lane).and_then(|budget| budget.cap(kind));
        Some(match raised {
            Some(raised) => floor.max(raised),
            None => floor,
        })
    }

    fn apply(&mut self, lane: &str, kind: LaneBudgetKind, value: u32) {
        let budget = self.lanes.entry(lane.to_owned()).or_default();
        match kind {
            LaneBudgetKind::WallSeconds => budget.wall_seconds = Some(value),
            LaneBudgetKind::BuildSlots => budget.build_slots = Some(value),
            LaneBudgetKind::Pods => budget.pods = Some(value),
        }
    }

    /// Exclusive check-and-set of one typed raise. The comparison against
    /// the stored cap happens under the raise lock, so two simultaneous
    /// steers cannot both pass a stale floor and the later write cannot
    /// lower the earlier one. A value that is not strictly above the
    /// effective cap is the exact-limit refusal.
    pub fn commit(
        huginn_root: &std::path::Path,
        lane: &str,
        declared: &LaneLimitsToml,
        raise: LaneBudgetRaise,
    ) -> Result<u32, CommitError> {
        let Some(floor) = raise.kind.declared(declared) else {
            return Err(CommitError::Refused(LaneBudgetRefusal::undeclared(
                raise.kind,
            )));
        };
        if raise.value < floor {
            return Err(CommitError::Refused(LaneBudgetRefusal::below_floor(
                raise.kind,
                floor,
                raise.value,
            )));
        }
        let path = huginn_root.join(LANE_BUDGET_FILE);
        let _lock = RaiseLock::acquire(huginn_root).map_err(CommitError::Store)?;
        let mut budgets = Self::read_locked(&path)
            .map_err(CommitError::Store)?
            .unwrap_or_default();
        let current = budgets
            .effective(lane, Some(floor), raise.kind)
            .unwrap_or(floor);
        if raise.value <= current {
            return Err(CommitError::Refused(LaneBudgetRefusal::not_above(
                raise.kind,
                current,
                raise.value,
            )));
        }
        budgets.apply(lane, raise.kind, raise.value);
        budgets.write_locked(&path).map_err(CommitError::Store)?;
        Ok(raise.value)
    }
}

/// Exclusive advisory lock for the whole read-modify-write. Readers take the
/// same lock so they never observe a partial replacement.
struct RaiseLock {
    file: std::fs::File,
}

impl RaiseLock {
    fn acquire(huginn_root: &std::path::Path) -> Result<Self, String> {
        Self::acquire_file(huginn_root, &format!(".{LANE_BUDGET_FILE}.lock"))
    }

    fn acquire_file(huginn_root: &std::path::Path, name: &str) -> Result<Self, String> {
        std::fs::create_dir_all(huginn_root).map_err(|error| error.to_string())?;
        let path = huginn_root.join(name);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        file.lock()
            .map_err(|error| format!("{}: {error}", path.display()))?;
        Ok(Self { file })
    }
}

impl Drop for RaiseLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// Why a locked raise commit failed. A refusal names the limit key; a store
/// error means the file could not be read or replaced and was not treated
/// as "no raise".
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommitError {
    Refused(LaneBudgetRefusal),
    Store(String),
}

impl CommitError {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Refused(refusal) => refusal.kind,
            Self::Store(_) => "lane_budget_unwritable",
        }
    }

    pub fn detail(&self) -> &str {
        match self {
            Self::Refused(refusal) => refusal.detail.as_str(),
            Self::Store(detail) => detail.as_str(),
        }
    }
}

/// Oldest live worker start for each lane, written beside the raise file
/// whenever a delegation row commits. Admission reads this instead of the
/// link ledger so coding, Claude, and kube share one clock.
pub const LANE_WALL_FILE: &str = "lane-wall.json";

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LaneWallLease {
    #[serde(default)]
    pub lanes: std::collections::BTreeMap<String, u64>,
}

impl LaneWallLease {
    pub fn load(huginn_root: &std::path::Path) -> Result<Option<Self>, String> {
        let path = huginn_root.join(LANE_WALL_FILE);
        let _lock = RaiseLock::acquire_file(huginn_root, &format!(".{LANE_WALL_FILE}.lock"))?;
        match crate::snapshot::read_regular_file(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|error| format!("{} is malformed: {error}", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("{} is unreadable: {error}", path.display())),
        }
    }

    pub fn publish(
        huginn_root: &std::path::Path,
        lanes: std::collections::BTreeMap<String, u64>,
    ) -> Result<(), String> {
        let path = huginn_root.join(LANE_WALL_FILE);
        let _lock = RaiseLock::acquire_file(huginn_root, &format!(".{LANE_WALL_FILE}.lock"))?;
        let bytes =
            serde_json::to_vec_pretty(&Self { lanes }).map_err(|error| error.to_string())?;
        crate::snapshot::atomic_write(&path, &bytes).map_err(|error| {
            format!(
                "{} {}: {}",
                error.action,
                error.path.display(),
                error.source
            )
        })
    }

    pub fn started(&self, lane: &str) -> Option<u64> {
        self.lanes.get(lane).copied()
    }
}

/// Refuses when a live worker's elapsed wall already fills `cap`. No live
/// worker, or no declared cap, admits. At the exact cap the detail names
/// `limits.wall_seconds`.
pub fn refuse_wall(cap: Option<u32>, started_ms: Option<u64>, now_ms: u64) -> Result<(), String> {
    let Some(started) = started_ms else {
        return Ok(());
    };
    let elapsed = now_ms.saturating_sub(started) / 1_000;
    let used = u32::try_from(elapsed).unwrap_or(u32::MAX);
    at_cap(LaneBudgetKind::WallSeconds, cap, used)
}

pub fn unix_millis() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
        .unwrap_or(0);
    u64::try_from(now).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(wall: u32, slots: u16, pods: u16) -> LaneLimitsToml {
        LaneLimitsToml {
            wall_seconds: NonZeroU32::new(wall),
            build_slots: NonZeroU16::new(slots),
            pods: NonZeroU16::new(pods),
        }
    }

    #[test]
    fn a_raise_above_the_cap_is_the_new_effective_limit() {
        let declared = limits(600, 1, 2);
        let mut budget = LaneBudget::declared(&declared);
        let applied = budget
            .raise(
                &declared,
                LaneBudgetRaise {
                    kind: LaneBudgetKind::BuildSlots,
                    value: 3,
                },
            )
            .expect("raised");
        assert_eq!(applied, 3);
        assert_eq!(budget.build_slots, Some(3));
        let again = budget
            .raise(
                &declared,
                LaneBudgetRaise {
                    kind: LaneBudgetKind::BuildSlots,
                    value: 3,
                },
            )
            .expect_err("now exact");
        assert_eq!(again.kind, "exact_limit");
    }

    #[test]
    fn admission_refuses_at_the_exact_cap_and_names_it() {
        let error = at_cap(LaneBudgetKind::Pods, Some(2), 2).expect_err("full");
        assert!(error.contains(PODS_LIMIT_KEY));
        assert!(error.contains('2'));
        assert!(at_cap(LaneBudgetKind::Pods, Some(2), 1).is_ok());
        assert!(at_cap(LaneBudgetKind::Pods, None, 9).is_ok());
    }


    #[test]
    fn a_commit_refuses_a_value_that_is_not_strictly_above_the_stored_cap() {
        let root =
            std::env::temp_dir().join(format!("odin-lane-budget-commit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("root");
        let declared = limits(600, 2, 1);
        let first = LaneBudgetRaise {
            kind: LaneBudgetKind::WallSeconds,
            value: 900,
        };
        assert_eq!(
            RaisedLaneBudgets::commit(&root, "gungnir-odin", &declared, first).expect("raise"),
            900
        );
        let same =
            RaisedLaneBudgets::commit(&root, "gungnir-odin", &declared, first).expect_err("exact");
        assert_eq!(same.kind(), "exact_limit");
        assert!(same.detail().contains("900"), "{}", same.detail());
        let lower = LaneBudgetRaise {
            kind: LaneBudgetKind::WallSeconds,
            value: 700,
        };
        assert_eq!(
            RaisedLaneBudgets::commit(&root, "gungnir-odin", &declared, lower)
                .expect_err("not above")
                .kind(),
            "exact_limit"
        );
        let loaded = RaisedLaneBudgets::load(&root).expect("load").expect("file");
        assert_eq!(
            loaded.effective("gungnir-odin", Some(600), LaneBudgetKind::WallSeconds),
            Some(900)
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
