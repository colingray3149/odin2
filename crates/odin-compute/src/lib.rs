//! Tiny host collector for one node's compute sample.
//!
//! [`Collector::sample`] reads CPU, memory, storage, and temperature from a
//! proc/sys root. NVIDIA GPU readings come from NVML, and only on a host
//! whose declared probe is `Cuda` and whose root shows an NVIDIA GPU. Other
//! DRM cards are read from sysfs. Model and pod rows are the caller's: this
//! crate does not talk to a runtime or a cluster.

#![deny(unsafe_code)]
#![deny(dead_code)]
#![deny(unused)]
use std::time::Duration;

/// Gap between two CPU readings inside one finite sample.
pub const CPU_DELTA: Duration = Duration::from_millis(50);
/// How long one finite sample may wait for `/proc/stat` to move.
pub const CPU_WAIT: Duration = Duration::from_millis(750);

mod gpu;
mod nvml;
mod read;
mod sample;

pub use gpu::GpuProbe;
pub use sample::{
    Collector, ComputeGpu, ComputeModel, ComputePod, ComputeSample, HostRoot, SampleError,
};
