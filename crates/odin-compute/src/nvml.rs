//! NVML readings. Called only after a host root shows an NVIDIA GPU.
//!
//! The library path is the one Nix declared (`compute-facts.json`), never a
//! host-name branch and never the bare filename alone: NixOS keeps
//! `libnvidia-ml.so.1` under `/run/opengl-driver/lib`, which a packaged
//! binary does not search. A missing library or a declined query becomes an
//! empty GPU list, never a sample error. Non-NVIDIA cards never reach this
//! module.

use std::path::Path;

use nvml_wrapper::enum_wrappers::device::TemperatureSensor;
use nvml_wrapper::Nvml;

use crate::gpu::GpuReading;

/// Sample every visible NVIDIA GPU. Empty when NVML is missing or declines.
pub(crate) fn sample_gpus(library: Option<&Path>) -> Vec<GpuReading> {
    let Ok(nvml) = open(library) else {
        return Vec::new();
    };
    let Ok(count) = nvml.device_count() else {
        return Vec::new();
    };
    (0..count)
        .filter_map(|index| read_device(&nvml, index))
        .collect()
}

fn open(library: Option<&Path>) -> Result<Nvml, nvml_wrapper::error::NvmlError> {
    let Some(library) = library else {
        return Nvml::init();
    };
    let mut builder = Nvml::builder();
    builder.lib_path(library.as_os_str()).init()
}

fn read_device(nvml: &Nvml, index: u32) -> Option<GpuReading> {
    let device = nvml.device_by_index(index).ok()?;
    let name = device.name().unwrap_or_else(|_| format!("gpu{index}"));
    let utilization_percent = device
        .utilization_rates()
        .ok()
        .map(|rates| f64::from(rates.gpu));
    let memory = device.memory_info().ok();
    let temperature_celsius = device
        .temperature(TemperatureSensor::Gpu)
        .ok()
        .map(f64::from);
    Some(GpuReading {
        name,
        utilization_percent,
        memory_used_bytes: memory.as_ref().map(|info| info.used),
        memory_total_bytes: memory.as_ref().map(|info| info.total),
        temperature_celsius,
    })
}
