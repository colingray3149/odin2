//! Serializable sample contract and the stateful collector.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::gpu::{GpuProbe, GpuReading};
use crate::read::{self, CpuTimes};

/// One GPU in a node's compute sample.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComputeGpu {
    pub name: String,
    pub utilization_percent: Option<f64>,
    pub memory_used_bytes: Option<u64>,
    pub memory_total_bytes: Option<u64>,
    pub temperature_celsius: Option<f64>,
}

/// One model runtime a node's sample saw. The caller fills these.
///
/// `unit` is the systemd ActiveState. `loaded` and `ready` come from the
/// backend's own endpoint, never from that unit state and never from a
/// socket that would start an idle model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComputeModel {
    pub name: String,
    /// Served model id when the backend listed one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loaded: Option<String>,
    pub runtime: String,
    /// systemd ActiveState, kept separate from readiness.
    #[serde(default)]
    pub unit: String,
    /// Backend health answered ready. Never inferred from `unit`.
    #[serde(default)]
    pub ready: bool,
    /// `ready`, `loaded`, or the unit state when neither was observed.
    pub state: String,
}

/// One pod a node's sample saw. The caller fills these.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComputePod {
    pub name: String,
    pub node: String,
    pub state: String,
}

/// One node's compute sample: the collector's newest reading.
///
/// Nullable gauges are `None` when that source was absent or unreadable.
/// `models` and `pods` stay empty until the caller fills them.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComputeSample {
    pub node: String,
    pub sampled_at: String,
    pub cpu_percent: Option<f64>,
    pub memory_used_bytes: Option<u64>,
    pub memory_total_bytes: Option<u64>,
    pub storage_used_bytes: Option<u64>,
    pub storage_total_bytes: Option<u64>,
    pub temperature_celsius: Option<f64>,
    pub gpus: Vec<ComputeGpu>,
    pub models: Vec<ComputeModel>,
    /// Why the model rows are absent, when this host's declarations could not
    /// be read. `None` with empty `models` is a valid file that declared none.
    pub models_note: Option<String>,
    /// Why pod rows are absent. `None` with empty `pods` means the node has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pods_note: Option<String>,
    pub pods: Vec<ComputePod>,
}

/// Why one sample could not be taken. A missing optional gauge is not an error.
#[derive(Debug)]
pub enum SampleError {
    /// The host root is not a directory the collector can read.
    HostRoot(std::io::Error),
    /// Wall-clock time could not be formatted as the sample timestamp.
    Clock(time::error::Format),
}

impl std::fmt::Display for SampleError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HostRoot(error) => write!(formatter, "host root is unreadable: {error}"),
            Self::Clock(error) => write!(formatter, "sample clock is unformattable: {error}"),
        }
    }
}

impl std::error::Error for SampleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::HostRoot(error) => Some(error),
            Self::Clock(error) => Some(error),
        }
    }
}

/// Proc, sysfs, and device roots, plus the filesystem whose capacity is reported.
///
/// Tests point this at a fixture. Production uses [`HostRoot::system`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostRoot {
    proc: PathBuf,
    sys: PathBuf,
    dev: PathBuf,
    storage: PathBuf,
}

impl HostRoot {
    /// The live Linux host.
    pub fn system() -> Self {
        Self {
            proc: PathBuf::from("/proc"),
            sys: PathBuf::from("/sys"),
            dev: PathBuf::from("/dev"),
            storage: PathBuf::from("/"),
        }
    }

    /// A fixture or chroot: `<root>/proc`, `<root>/sys`, `<root>/dev`, storage at `<root>`.
    pub fn under(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            proc: root.join("proc"),
            sys: root.join("sys"),
            dev: root.join("dev"),
            storage: root,
        }
    }

    pub fn proc(&self) -> &Path {
        &self.proc
    }

    pub fn sys(&self) -> &Path {
        &self.sys
    }

    pub fn dev(&self) -> &Path {
        &self.dev
    }

    pub fn storage(&self) -> &Path {
        &self.storage
    }
}

/// Stateful sampler. CPU percent needs the previous `/proc/stat` counters,
/// so the first sample leaves `cpu_percent` empty.
#[derive(Debug)]
pub struct Collector {
    host: HostRoot,
    probe: GpuProbe,
    nvml_library: Option<std::path::PathBuf>,
    previous_cpu: Option<CpuTimes>,
}

impl Collector {
    /// `probe` is the host's declared GPU probe; only `Cuda` ever opens NVML.
    pub fn new(host: HostRoot, probe: GpuProbe) -> Self {
        Self::with_library(host, probe, None)
    }

    /// `nvml_library` is the Nix-declared driver library. `None` uses the
    /// bare filename, which a NixOS package does not find.
    pub fn with_library(
        host: HostRoot,
        probe: GpuProbe,
        nvml_library: Option<std::path::PathBuf>,
    ) -> Self {
        Self {
            host,
            probe,
            nvml_library,
            previous_cpu: None,
        }
    }

    /// Sample the live host.
    pub fn system(probe: GpuProbe) -> Self {
        Self::new(HostRoot::system(), probe)
    }

    /// Sample the live host, opening NVML at the declared library.
    pub fn system_with_library(probe: GpuProbe, nvml_library: Option<std::path::PathBuf>) -> Self {
        Self::with_library(HostRoot::system(), probe, nvml_library)
    }

    /// Take one sample for `node`.
    ///
    /// CPU, memory, storage, and temperature are read from the host root.
    /// NVIDIA cards go through NVML, and only when the declared probe is
    /// `Cuda` and this root shows the card (`dev/nvidia0`, or a `drm` card
    /// whose vendor is NVIDIA). Every other DRM card is read from sysfs and
    /// never opens NVML. Models and pods are left empty for the caller. A
    /// missing host root is [`SampleError::HostRoot`]; a missing gauge inside
    /// a present root is `None`, not an error.
    pub fn sample(&mut self, node: &str) -> Result<ComputeSample, SampleError> {
        fs::metadata(self.host.proc()).map_err(SampleError::HostRoot)?;
        let cpu = read::cpu_times(self.host.proc());
        let cpu_percent = match (&self.previous_cpu, &cpu) {
            (Some(previous), Some(current)) => read::cpu_percent(previous, current),
            _ => None,
        };
        self.previous_cpu = cpu;

        let (memory_used_bytes, memory_total_bytes) = read::memory(self.host.proc());
        let (storage_used_bytes, storage_total_bytes) = read::storage(self.host.storage());
        let temperature_celsius = read::temperature(self.host.sys());
        let gpus = read::gpus(&self.host, self.probe, self.nvml_library.as_deref())
            .into_iter()
            .map(gpu_row)
            .collect();

        Ok(ComputeSample {
            node: node.to_owned(),
            sampled_at: sampled_at()?,
            cpu_percent,
            memory_used_bytes,
            memory_total_bytes,
            storage_used_bytes,
            storage_total_bytes,
            temperature_celsius,
            gpus,
            models: Vec::new(),
            models_note: None,
            pods_note: None,
            pods: Vec::new(),
        })
    }
}

fn gpu_row(reading: GpuReading) -> ComputeGpu {
    ComputeGpu {
        name: reading.name,
        utilization_percent: reading.utilization_percent,
        memory_used_bytes: reading.memory_used_bytes,
        memory_total_bytes: reading.memory_total_bytes,
        temperature_celsius: reading.temperature_celsius,
    }
}

fn sampled_at() -> Result<String, SampleError> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
    let timestamp = OffsetDateTime::from_unix_timestamp(seconds)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
        + time::Duration::nanoseconds(i64::from(now.subsec_nanos()));
    timestamp.format(&Rfc3339).map_err(SampleError::Clock)
}
