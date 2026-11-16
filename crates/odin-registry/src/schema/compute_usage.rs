//! Metered compute per lane: requested cores, GPUs and priced node time, charged by odind's
//! compute meter into daily buckets beside the huginn root and read by kube admission against
//! the lane's `limits.core_hours`, `limits.gpu_hours` and `limits.compute_usd`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::lane_budget::{LaneBudgetKind, RaiseLock};

pub const COMPUTE_USAGE_FILE: &str = "compute-usage.json";

/// Marks a compute budget refusal so a batch launch can wait instead of failing.
pub const COMPUTE_BUDGET_REFUSED: &str = "compute budget refused";

const SECONDS_PER_DAY: u64 = 86_400;

/// Resource time in one bucket: core-seconds, GPU-seconds and dollars.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComputeCharge {
    #[serde(default)]
    pub core_seconds: f64,
    #[serde(default)]
    pub gpu_seconds: f64,
    #[serde(default)]
    pub usd: f64,
}

impl ComputeCharge {
    pub fn add(&mut self, other: ComputeCharge) {
        self.core_seconds += other.core_seconds;
        self.gpu_seconds += other.gpu_seconds;
        self.usd += other.usd;
    }

    /// The charge in the unit its lane limit counts: hours, or dollars.
    pub fn in_limit_units(&self, kind: LaneBudgetKind) -> f64 {
        match kind {
            LaneBudgetKind::CoreHours => self.core_seconds / 3_600.0,
            LaneBudgetKind::GpuHours => self.gpu_seconds / 3_600.0,
            LaneBudgetKind::ComputeUsd => self.usd,
            _ => 0.0,
        }
    }
}

/// One running pod as the meter sees it.
#[derive(Clone, Debug, PartialEq)]
pub struct MeteredPod {
    pub uid: String,
    /// Its lane and, when different, the lane its budget is charged to.
    pub lanes: Vec<String>,
    pub cores: f64,
    pub gpus: f64,
    /// Its node's `cost.usd_per_hour` × its share of the node's CPUs; 0 on owned nodes.
    pub usd_per_hour: f64,
    pub started_ms: u64,
}

/// A uniformly charged interval, retained at meter cadence for exact rolling windows.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComputeInterval {
    pub start_ms: u64,
    pub end_ms: u64,
    pub charge: ComputeCharge,
    /// Present for a replaceable cumulative source, absent for ordinary intervals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComputeUsage {
    /// lane → unix day → charge.
    #[serde(default)]
    pub lanes: BTreeMap<String, BTreeMap<u64, ComputeCharge>>,
    /// lane → metered intervals. Legacy daily buckets remain readable in `lanes`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub intervals: BTreeMap<String, Vec<ComputeInterval>>,
    /// Non-pod source → unix day → charge, for source-level spend reporting.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub source_charges: BTreeMap<String, BTreeMap<u64, ComputeCharge>>,
    /// Running pod uid → when it was last charged, so a restart resumes without double counting.
    #[serde(default)]
    pub pods: BTreeMap<String, u64>,
    /// Non-pod source ID → last charged timestamp, committed atomically with usage.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sources: BTreeMap<String, u64>,
    /// `lane:key` already told it is over its cap; cleared when back under.
    #[serde(default)]
    pub over_cap: std::collections::BTreeSet<String>,
}

impl ComputeUsage {
    pub fn load(huginn_root: &std::path::Path) -> Result<Self, String> {
        let _lock = lock(huginn_root)?;
        read(&huginn_root.join(COMPUTE_USAGE_FILE))
    }

    /// Exclusive read-modify-write of the store.
    pub fn update<T>(
        huginn_root: &std::path::Path,
        change: impl FnOnce(&mut Self) -> T,
    ) -> Result<T, String> {
        let path = huginn_root.join(COMPUTE_USAGE_FILE);
        let _lock = lock(huginn_root)?;
        let mut usage = read(&path)?;
        let out = change(&mut usage);
        let bytes = serde_json::to_vec(&usage).map_err(|error| error.to_string())?;
        crate::snapshot::atomic_write(&path, &bytes).map_err(|error| {
            format!(
                "{} {}: {}",
                error.action,
                error.path.display(),
                error.source
            )
        })?;
        Ok(out)
    }

    /// Charge a resource interval, splitting it at UTC day boundaries for window accounting.
    pub fn charge_interval(
        &mut self,
        lanes: &[String],
        start_ms: u64,
        end_ms: u64,
        cores: f64,
        gpus: f64,
        usd_per_hour: f64,
    ) {
        if start_ms >= end_ms {
            return;
        }
        let seconds = (end_ms - start_ms) as f64 / 1_000.0;
        let charge = ComputeCharge {
            core_seconds: seconds * cores,
            gpu_seconds: seconds * gpus,
            usd: seconds / 3_600.0 * usd_per_hour,
        };
        for (index, lane) in lanes.iter().enumerate() {
            if !lanes[..index].contains(lane) {
                self.intervals
                    .entry(lane.clone())
                    .or_default()
                    .push(ComputeInterval {
                        start_ms,
                        end_ms,
                        charge,
                        source: None,
                    });
            }
        }
    }

    /// Charge a non-pod source once through `end_ms`, including across retries and restarts.
    pub fn charge_source(
        &mut self,
        source: &str,
        lanes: &[String],
        interval: std::ops::Range<u64>,
        cores: f64,
        gpus: f64,
        usd_per_hour: f64,
    ) {
        let start_ms = interval.start;
        let end_ms = interval.end;
        let since = self
            .sources
            .get(source)
            .copied()
            .unwrap_or(start_ms)
            .max(start_ms);
        self.charge_interval(lanes, since, end_ms, cores, gpus, usd_per_hour);
        let day_ms = SECONDS_PER_DAY * 1_000;
        let mut start = since;
        while start < end_ms {
            let day = start / day_ms;
            let end = end_ms.min(day.saturating_add(1).saturating_mul(day_ms));
            let seconds = (end - start) as f64 / 1_000.0;
            self.source_charges
                .entry(source.to_owned())
                .or_default()
                .entry(day)
                .or_default()
                .add(ComputeCharge {
                    core_seconds: seconds * cores,
                    gpu_seconds: seconds * gpus,
                    usd: seconds / 3_600.0 * usd_per_hour,
                });
            start = end;
        }
        self.sources.insert(source.to_owned(), end_ms.max(since));
    }

    /// Replace one source's cumulative authoritative charge atomically. Aggregate-only
    /// accounting cannot locate suspended time, so all use is conservatively attributed
    /// to the observation instant; later observations replace, rather than add, it.
    /// Do not use `charge_source` for the same source ID.
    pub fn replace_source_total(
        &mut self,
        source: &str,
        lanes: &[String],
        observed_ms: u64,
        total: ComputeCharge,
    ) {
        for intervals in self.intervals.values_mut() {
            intervals.retain(|interval| interval.source.as_deref() != Some(source));
        }
        self.intervals.retain(|_, intervals| !intervals.is_empty());
        let end_ms = observed_ms.max(1);
        for (index, lane) in lanes.iter().enumerate() {
            if !lanes[..index].contains(lane) {
                self.intervals
                    .entry(lane.clone())
                    .or_default()
                    .push(ComputeInterval {
                        start_ms: end_ms - 1,
                        end_ms,
                        charge: total,
                        source: Some(source.to_owned()),
                    });
            }
        }
        let day = observed_ms / 1_000 / SECONDS_PER_DAY;
        self.source_charges
            .insert(source.to_owned(), [(day, total)].into_iter().collect());
        self.sources.insert(source.to_owned(), end_ms);
    }

    /// Charges running pods since their last charge (or start). Unseen pod cursors remain
    /// until completion or expiry, so a delayed terminal observation cannot double charge.
    pub fn charge(&mut self, pods: &[MeteredPod], now_ms: u64) {
        for pod in pods {
            let since = self.pods.get(&pod.uid).copied().unwrap_or(pod.started_ms);
            self.charge_interval(
                &pod.lanes,
                since,
                now_ms,
                pod.cores,
                pod.gpus,
                pod.usd_per_hour,
            );
            self.pods.insert(pod.uid.clone(), now_ms.max(since));
        }
    }

    /// Charge the final interval once, including pods that completed between meter ticks.
    /// Call before `charge`, while the last running cursor is still present.
    pub fn charge_completed(&mut self, pod: &MeteredPod, end_ms: u64) {
        let source = format!("pod:{}", pod.uid);
        if self.sources.contains_key(&source) {
            return;
        }
        let since = self.pods.remove(&pod.uid).unwrap_or(pod.started_ms);
        self.charge_interval(
            &pod.lanes,
            since,
            end_ms,
            pod.cores,
            pod.gpus,
            pod.usd_per_hour,
        );
        self.sources.insert(source, end_ms.max(since));
    }

    /// What `lane` used in the rolling `window_days` ending at `now_ms`.
    pub fn used(&self, lane: &str, window_days: u16, now_ms: u64) -> ComputeCharge {
        let first_ms = now_ms.saturating_sub(u64::from(window_days) * SECONDS_PER_DAY * 1_000);
        let mut total = ComputeCharge::default();
        if let Some(intervals) = self.intervals.get(lane) {
            for interval in intervals {
                let start = interval.start_ms.max(first_ms);
                let end = interval.end_ms.min(now_ms);
                if end > start && interval.end_ms > interval.start_ms {
                    let fraction =
                        (end - start) as f64 / (interval.end_ms - interval.start_ms) as f64;
                    total.add(ComputeCharge {
                        core_seconds: interval.charge.core_seconds * fraction,
                        gpu_seconds: interval.charge.gpu_seconds * fraction,
                        usd: interval.charge.usd * fraction,
                    });
                }
            }
        }
        // Older stores only contain daily totals; retain those until they age out.
        if let Some(days) = self.lanes.get(lane) {
            let first_day = first_ms / 1_000 / SECONDS_PER_DAY;
            let today = now_ms / 1_000 / SECONDS_PER_DAY;
            for (_, charge) in days.range(first_day..=today) {
                total.add(*charge);
            }
        }
        total
    }

    /// Drops buckets older than every lane's window.
    pub fn prune(&mut self, keep_days: u16, now_ms: u64) {
        let today = now_ms / 1_000 / SECONDS_PER_DAY;
        let first = today.saturating_sub(u64::from(keep_days));
        for days in self.lanes.values_mut() {
            days.retain(|day, _| *day >= first);
        }
        self.lanes.retain(|_, days| !days.is_empty());
        let first_ms = now_ms.saturating_sub(u64::from(keep_days) * SECONDS_PER_DAY * 1_000);
        for intervals in self.intervals.values_mut() {
            intervals.retain(|interval| interval.end_ms > first_ms);
        }
        self.intervals.retain(|_, intervals| !intervals.is_empty());
        for days in self.source_charges.values_mut() {
            days.retain(|day, _| *day >= first);
        }
        self.source_charges.retain(|_, days| !days.is_empty());
        self.pods.retain(|_, last| *last >= first_ms);
        self.sources.retain(|_, last| *last >= first_ms);
    }
}

fn lock(huginn_root: &std::path::Path) -> Result<RaiseLock, String> {
    RaiseLock::acquire_file(huginn_root, &format!(".{COMPUTE_USAGE_FILE}.lock"))
}

fn read(path: &std::path::Path) -> Result<ComputeUsage, String> {
    match crate::snapshot::read_regular_file(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|error| format!("{} is malformed: {error}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(ComputeUsage::default()),
        Err(error) => Err(format!("{} is unreadable: {error}", path.display())),
    }
}

/// Refuses when what the lane used in its window, plus what its live runs and this launch
/// may still use, passes the cap. A missing cap admits.
pub fn refuse_compute(
    kind: LaneBudgetKind,
    cap: Option<u32>,
    used: f64,
    projected: f64,
) -> Result<(), String> {
    let Some(cap) = cap else {
        return Ok(());
    };
    if used + projected > f64::from(cap) {
        return Err(format!(
            "{used:.1} used + {projected:.1} projected passes {key} of {cap}",
            key = kind.key()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR_MS: u64 = 3_600_000;

    fn pod(uid: &str, lanes: &[&str]) -> MeteredPod {
        MeteredPod {
            uid: uid.to_owned(),
            lanes: lanes.iter().map(|lane| (*lane).to_owned()).collect(),
            cores: 4.0,
            gpus: 1.0,
            usd_per_hour: 0.5,
            started_ms: 10 * HOUR_MS,
        }
    }

    #[test]
    fn a_running_pod_accrues_core_seconds_to_its_lane_and_budget_lane() {
        let mut usage = ComputeUsage::default();
        let running = [pod("uid-1", &["worker-project", "project-sweeps"])];
        usage.charge(&running, 11 * HOUR_MS);
        usage.charge(&running, 12 * HOUR_MS);
        for lane in ["worker-project", "project-sweeps"] {
            let used = usage.used(lane, 30, 12 * HOUR_MS);
            assert!((used.in_limit_units(LaneBudgetKind::CoreHours) - 8.0).abs() < 1e-9);
            assert!((used.in_limit_units(LaneBudgetKind::GpuHours) - 2.0).abs() < 1e-9);
            assert!((used.in_limit_units(LaneBudgetKind::ComputeUsd) - 1.0).abs() < 1e-9);
        }
        assert_eq!(
            usage.used("elsewhere", 30, 12 * HOUR_MS),
            ComputeCharge::default()
        );
    }

    #[test]
    fn a_paused_pod_accrues_nothing() {
        let mut usage = ComputeUsage::default();
        usage.charge(&[pod("uid-1", &["lane"])], 11 * HOUR_MS);
        let before = usage.used("lane", 30, 11 * HOUR_MS);
        // Paused: its Job is suspended, so no running pod reaches the meter.
        usage.charge(&[], 15 * HOUR_MS);
        assert_eq!(usage.used("lane", 30, 15 * HOUR_MS), before);
        assert!(
            usage.pods.contains_key("uid-1"),
            "retain the cursor for a delayed terminal observation"
        );
    }

    #[test]
    fn interval_is_prorated_at_the_rolling_window_boundary() {
        let mut usage = ComputeUsage::default();
        let day = SECONDS_PER_DAY * 1_000;
        let lanes = vec!["lane".to_owned()];
        usage.charge_interval(&lanes, day - HOUR_MS, day + HOUR_MS, 2.0, 1.0, 1.0);
        assert_eq!(usage.used("lane", 1, day + HOUR_MS).core_seconds, 14_400.0);
        assert_eq!(usage.used("lane", 1, 2 * day).core_seconds, 7_200.0);
        assert_eq!(usage.used("lane", 1, 2 * day + HOUR_MS).usd, 0.0);
    }

    #[test]
    fn source_retries_do_not_double_charge() {
        let mut usage = ComputeUsage::default();
        let lanes = vec!["lane".to_owned()];
        usage.charge_source("offload:run", &lanes, 0..HOUR_MS, 2.0, 0.0, 1.0);
        usage.charge_source("offload:run", &lanes, 0..HOUR_MS, 2.0, 0.0, 1.0);
        usage.charge_source("offload:run", &lanes, 0..2 * HOUR_MS, 2.0, 0.0, 1.0);
        let used = usage.used("lane", 1, 2 * HOUR_MS);
        assert_eq!(used.core_seconds, 4.0 * 3_600.0);
        assert_eq!(used.usd, 2.0);
    }

    #[test]
    fn cumulative_source_replaces_prior_charge_and_lane_attribution() {
        let mut usage = ComputeUsage::default();
        let first = ComputeCharge {
            core_seconds: 100.0,
            gpu_seconds: 20.0,
            usd: 1.0,
        };
        let corrected = ComputeCharge {
            core_seconds: 80.0,
            gpu_seconds: 16.0,
            usd: 0.8,
        };
        usage.replace_source_total("slurm:job", &["old".into()], HOUR_MS, first);
        usage.replace_source_total("slurm:job", &["new".into()], 2 * HOUR_MS, corrected);
        usage.replace_source_total("slurm:job", &["new".into()], 2 * HOUR_MS, corrected);
        assert_eq!(usage.used("old", 1, 2 * HOUR_MS), ComputeCharge::default());
        assert_eq!(usage.used("new", 1, 2 * HOUR_MS), corrected);
        assert_eq!(usage.source_charges["slurm:job"][&0], corrected);
    }

    #[test]
    fn completed_pod_is_charged_once_through_its_finish() {
        let mut usage = ComputeUsage::default();
        let running = pod("uid-1", &["lane"]);
        usage.charge(std::slice::from_ref(&running), 11 * HOUR_MS);
        usage.charge_completed(&running, 12 * HOUR_MS);
        usage.charge(&[], 12 * HOUR_MS);
        usage.charge_completed(&running, 12 * HOUR_MS);
        assert_eq!(
            usage.used("lane", 1, 12 * HOUR_MS).core_seconds,
            8.0 * 3_600.0
        );
    }

    #[test]
    fn a_launch_whose_projection_crosses_core_hours_is_refused_naming_the_key() {
        let refused =
            refuse_compute(LaneBudgetKind::CoreHours, Some(100), 60.0, 50.0).expect_err("over");
        assert!(
            refused.contains(super::super::lane_budget::CORE_HOURS_LIMIT_KEY),
            "{refused}"
        );
        assert!(
            refused.contains("60.0") && refused.contains("50.0"),
            "{refused}"
        );
        assert!(refuse_compute(LaneBudgetKind::CoreHours, Some(100), 60.0, 40.0).is_ok());
        assert!(refuse_compute(LaneBudgetKind::CoreHours, None, 1e9, 1e9).is_ok());
    }

    #[test]
    fn usage_outside_the_window_does_not_count() {
        let mut usage = ComputeUsage::default();
        usage.charge(&[pod("uid-1", &["lane"])], 11 * HOUR_MS);
        let later = 11 * HOUR_MS + 40 * 24 * HOUR_MS;
        assert_eq!(usage.used("lane", 30, later), ComputeCharge::default());
        usage.prune(30, later);
        assert!(usage.lanes.is_empty());
        assert!(usage.intervals.is_empty());
    }
}
