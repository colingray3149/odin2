//! Bounded readers for `/proc` and `/sys`. Missing files become `None`.

use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

use crate::gpu::{GpuProbe, GpuReading};
use crate::nvml;
use crate::sample::HostRoot;

const READ_CAP: u64 = 65_536;
const AGGREGATE_CPU: &str = "cpu";
const NVIDIA_PCI_VENDOR: &str = "0x10de";
/// Enough for a workstation's cards and sensors, not an unbounded sysfs walk.
const SCAN_CAP: usize = 64;

/// Cumulative `/proc/stat` counters for the aggregate `cpu` line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CpuTimes {
    pub(crate) idle: u64,
    pub(crate) total: u64,
}

pub(crate) fn cpu_times(proc_root: &Path) -> Option<CpuTimes> {
    parse_cpu_times(&read_capped(&proc_root.join("stat"))?)
}

fn parse_cpu_times(text: &str) -> Option<CpuTimes> {
    let line = text
        .lines()
        .find(|line| cpu_label(line) == Some(AGGREGATE_CPU))?;
    let mut idle = 0_u64;
    let mut total = 0_u64;
    let mut fields = 0_usize;
    // user, nice, system, idle, iowait, irq, softirq, steal. `guest` and
    // `guest_nice` are already inside user and nice; summing them again
    // double-counts virtual machines.
    for (index, field) in line.split_whitespace().skip(1).take(8).enumerate() {
        let value = field.parse::<u64>().ok()?;
        total = total.saturating_add(value);
        if index == 3 || index == 4 {
            idle = idle.saturating_add(value);
        }
        fields += 1;
    }
    (fields >= 4).then_some(CpuTimes { idle, total })
}

fn cpu_label(line: &str) -> Option<&str> {
    line.split_whitespace().next()
}

/// Busy share of the delta, in percent. `None` when the counters went backwards
/// or did not move: a delta of zero is not a measurement.
pub(crate) fn cpu_percent(previous: &CpuTimes, current: &CpuTimes) -> Option<f64> {
    let total = current.total.checked_sub(previous.total)?;
    let idle = current.idle.checked_sub(previous.idle)?;
    if total == 0 || idle > total {
        return None;
    }
    Some((total - idle) as f64 * 100.0 / total as f64)
}

pub(crate) fn memory(proc_root: &Path) -> (Option<u64>, Option<u64>) {
    let Some(text) = read_capped(&proc_root.join("meminfo")) else {
        return (None, None);
    };
    parse_memory(&text)
}

fn parse_memory(text: &str) -> (Option<u64>, Option<u64>) {
    let mut total_kib = None;
    let mut available_kib = None;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else {
            continue;
        };
        let Some(value) = parts.next().and_then(|field| field.parse::<u64>().ok()) else {
            continue;
        };
        match key {
            "MemTotal:" => total_kib = Some(value),
            "MemAvailable:" => available_kib = Some(value),
            _ => {}
        }
    }
    let total = total_kib.map(|kib| kib.saturating_mul(1024));
    let used = match (total_kib, available_kib) {
        (Some(total_kib), Some(available_kib)) => {
            Some(total_kib.saturating_sub(available_kib).saturating_mul(1024))
        }
        _ => None,
    };
    (used, total)
}

/// Used and total bytes of the filesystem containing `path`.
///
/// `f_bavail` is the unprivileged free count, so used is what a normal
/// process can no longer allocate, not the raw block-free count.
pub(crate) fn storage(path: &Path) -> (Option<u64>, Option<u64>) {
    let Ok(file) = File::open(path) else {
        return (None, None);
    };
    let Ok(stats) = rustix::fs::fstatvfs(&file) else {
        return (None, None);
    };
    if stats.f_frsize == 0 || stats.f_blocks == 0 {
        return (None, None);
    }
    let total = stats.f_blocks.saturating_mul(stats.f_frsize);
    let available = stats.f_bavail.saturating_mul(stats.f_frsize);
    (Some(total.saturating_sub(available)), Some(total))
}

/// Every GPU this host root declares.
///
/// NVIDIA cards go through NVML, and only when the declared probe is `Cuda`
/// and the root shows the card. AMD and other DRM cards are read from the
/// card's own sysfs (`gpu_busy_percent`, `mem_info_vram_*`); a non-`Cuda`
/// probe still shows an NVIDIA card this way, with empty gauges. A card with
/// no readable gauge still counts: a declared GPU is not the same as no GPU.
pub(crate) fn gpus(
    host: &HostRoot,
    probe: GpuProbe,
    nvml_library: Option<&Path>,
) -> Vec<GpuReading> {
    let nvml_owns_nvidia = probe.opens_nvml() && nvidia_present(host);
    let mut readings = Vec::new();
    if nvml_owns_nvidia {
        readings.extend(nvml::sample_gpus(nvml_library));
    }
    readings.extend(drm_gpus(host.sys(), nvml_owns_nvidia));
    if readings.is_empty() && nvml_owns_nvidia && nvidia_device_node(host) {
        // The driver is present but NVML declined (a version mismatch, as on
        // pc before its reboot): the host still has the card, with no gauges.
        readings.push(GpuReading {
            name: "nvidia0".to_owned(),
            utilization_percent: None,
            memory_used_bytes: None,
            memory_total_bytes: None,
            temperature_celsius: None,
        });
    }
    readings
}

fn nvidia_present(host: &HostRoot) -> bool {
    nvidia_device_node(host) || drm_vendor_is(host.sys(), NVIDIA_PCI_VENDOR)
}

fn nvidia_device_node(host: &HostRoot) -> bool {
    let node = host.dev().join("nvidia0");
    let Ok(metadata) = fs::symlink_metadata(&node) else {
        return false;
    };
    // A regular stand-in is enough for a fixture. A live node is a character
    // device; anything else (a directory, a dangling declaration) is not.
    metadata.file_type().is_char_device() || metadata.file_type().is_file()
}

fn drm_vendor_is(sys_root: &Path, vendor: &str) -> bool {
    drm_cards(sys_root).any(|card| card_vendor(&card).as_deref() == Some(vendor))
}

/// DRM cards other than ones NVML already owns. Connectors never arrive here.
/// Intel render cards count; a missing gauge stays null rather than dropping
/// the laptop GPU.
fn drm_gpus(sys_root: &Path, skip_nvidia: bool) -> Vec<GpuReading> {
    drm_cards(sys_root)
        .filter(|card| card_is_gpu(card, skip_nvidia))
        .map(|card| drm_reading(&card))
        .collect()
}

fn card_is_gpu(card: &Path, skip_nvidia: bool) -> bool {
    match card_vendor(card).as_deref() {
        Some(NVIDIA_PCI_VENDOR) => !skip_nvidia,
        Some(_) => true,
        None => false,
    }
}

fn drm_cards(sys_root: &Path) -> impl Iterator<Item = std::path::PathBuf> {
    let entries = fs::read_dir(sys_root.join("class/drm"))
        .map(|directory| directory.flatten().take(SCAN_CAP).collect::<Vec<_>>())
        .unwrap_or_default();
    entries.into_iter().filter_map(|entry| {
        let name = entry.file_name();
        let name = name.to_str()?;
        // `card1-DP-1` is a connector, not a card.
        (name.starts_with("card") && !name.contains('-')).then(|| entry.path())
    })
}

fn card_vendor(card: &Path) -> Option<String> {
    read_capped(&card.join("device/vendor")).map(|value| value.trim().to_owned())
}

fn drm_reading(card: &Path) -> GpuReading {
    let device = card.join("device");
    let name = read_capped(&device.join("product_name"))
        .or_else(|| hwmon_chip_name(&device))
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            card.file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "gpu".to_owned());
    GpuReading {
        name,
        utilization_percent: read_capped(&device.join("gpu_busy_percent"))
            .as_deref()
            .and_then(parse_percent),
        memory_used_bytes: read_capped(&device.join("mem_info_vram_used"))
            .as_deref()
            .and_then(parse_u64),
        memory_total_bytes: read_capped(&device.join("mem_info_vram_total"))
            .as_deref()
            .and_then(parse_u64),
        temperature_celsius: card_temperature(&device),
    }
}

/// AMD publishes the die temperature on the card's hwmon, in millidegrees.
fn card_temperature(device: &Path) -> Option<f64> {
    let hwmon = fs::read_dir(device.join("hwmon")).ok()?;
    for entry in hwmon.flatten().take(SCAN_CAP) {
        let hottest = hwmon_temperature(&entry.path());
        if hottest.is_some() {
            return hottest;
        }
    }
    None
}

fn hwmon_chip_name(device: &Path) -> Option<String> {
    let hwmon = fs::read_dir(device.join("hwmon")).ok()?;
    for entry in hwmon.flatten().take(SCAN_CAP) {
        if let Some(name) = read_capped(&entry.path().join("name")) {
            let name = name.trim().to_owned();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}
/// Hottest readable sensor, in Celsius.
///
/// hwmon is preferred: it is where AMD and most board sensors publish. Thermal
/// zones remain the fallback for a host whose hwmon tree is empty or absent.
pub(crate) fn temperature(sys_root: &Path) -> Option<f64> {
    hwmon_tree_temperature(sys_root).or_else(|| thermal_zone_temperature(sys_root))
}

fn hwmon_tree_temperature(sys_root: &Path) -> Option<f64> {
    let chips = fs::read_dir(sys_root.join("class/hwmon")).ok()?;
    let mut hottest: Option<f64> = None;
    for entry in chips.flatten().take(SCAN_CAP) {
        hottest = max_celsius(hottest, hwmon_temperature(&entry.path()));
    }
    hottest
}

fn hwmon_temperature(chip: &Path) -> Option<f64> {
    let entries = fs::read_dir(chip).ok()?;
    let mut hottest: Option<f64> = None;
    for entry in entries.flatten().take(SCAN_CAP) {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        // `temp1_input`, not `temp1_label` or `temp1_max`.
        if !(name.starts_with("temp") && name.ends_with("_input")) {
            continue;
        }
        let Some(text) = read_capped(&entry.path()) else {
            continue;
        };
        hottest = max_celsius(hottest, millidegrees(&text));
    }
    hottest
}

fn thermal_zone_temperature(sys_root: &Path) -> Option<f64> {
    let zones = fs::read_dir(sys_root.join("class/thermal")).ok()?;
    let mut hottest: Option<f64> = None;
    for entry in zones.flatten().take(SCAN_CAP) {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with("thermal_zone") {
            continue;
        }
        let Some(text) = read_capped(&entry.path().join("temp")) else {
            continue;
        };
        hottest = max_celsius(hottest, millidegrees(&text));
    }
    hottest
}

fn millidegrees(text: &str) -> Option<f64> {
    let millidegrees = text.trim().parse::<f64>().ok()?;
    Some(millidegrees / 1000.0)
}

fn max_celsius(current: Option<f64>, next: Option<f64>) -> Option<f64> {
    match (current, next) {
        (Some(current), Some(next)) => Some(current.max(next)),
        (None, next) => next,
        (current, None) => current,
    }
}

fn parse_percent(text: &str) -> Option<f64> {
    let percent = text.trim().parse::<f64>().ok()?;
    (0.0..=100.0).contains(&percent).then_some(percent)
}

fn parse_u64(text: &str) -> Option<u64> {
    text.trim().parse::<u64>().ok()
}

fn read_capped(path: &Path) -> Option<String> {
    let file = File::open(path).ok()?;
    read_file_capped(file).ok()
}

fn read_file_capped(mut file: File) -> io::Result<String> {
    let mut buffer = Vec::new();
    file.by_ref().take(READ_CAP).read_to_end(&mut buffer)?;
    String::from_utf8(buffer).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}
