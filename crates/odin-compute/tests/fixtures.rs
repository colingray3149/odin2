//! Collector behavior against real proc/sys fixture trees.
//!
//! Storage still comes from `fstatvfs` of the fixture directory: a fake
//! proc tree has no filesystem capacity of its own. GPU presence is the
//! fixture's device node or DRM vendor, never this machine's `/dev`; the
//! NVML attempt itself is gated by the declared probe and NVIDIA hardware.

use std::fs;
use std::path::Path;

use odin_compute::{Collector, ComputeModel, ComputePod, GpuProbe, HostRoot};

fn write(path: &Path, body: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("fixture parent is creatable");
    }
    fs::write(path, body).expect("fixture file is writable");
}

fn cpu_host(root: &Path) {
    write(
        &root.join("proc/stat"),
        "cpu  100 0 100 600 200 0 0 0 0 0\ncpu0 50 0 50 300 100 0 0 0 0 0\n",
    );
    write(
        &root.join("proc/meminfo"),
        "MemTotal:        8192 kB\nMemFree:         1024 kB\nMemAvailable:    4096 kB\n",
    );
    write(
        &root.join("sys/class/thermal/thermal_zone0/temp"),
        "42000\n",
    );
    write(
        &root.join("sys/class/thermal/thermal_zone1/temp"),
        "61500\n",
    );
}

#[test]
fn first_sample_has_no_cpu_percent_and_no_gpu_on_a_cpu_host() {
    let fixture = tempfile::tempdir().expect("fixture root");
    cpu_host(fixture.path());
    let mut collector = Collector::new(HostRoot::under(fixture.path()), GpuProbe::None);

    let sample = collector.sample("mini").expect("fixture sample");

    assert_eq!(sample.node, "mini");
    assert!(sample.cpu_percent.is_none(), "no prior counters yet");
    assert_eq!(sample.memory_total_bytes, Some(8192 * 1024));
    assert_eq!(sample.memory_used_bytes, Some((8192 - 4096) * 1024));
    assert!(sample.storage_total_bytes.is_some_and(|total| total > 0));
    assert!(sample.storage_used_bytes.is_some());
    assert_eq!(sample.temperature_celsius, Some(61.5));
    assert!(sample.gpus.is_empty(), "no drm card on a cpu fixture");
    assert!(sample.models.is_empty());
    assert!(sample.pods.is_empty());
    assert!(
        sample.sampled_at.ends_with('Z') && sample.sampled_at.contains('T'),
        "sampledAt is RFC3339 UTC, got {}",
        sample.sampled_at
    );
}

#[test]
fn second_sample_reports_the_cpu_delta() {
    let fixture = tempfile::tempdir().expect("fixture root");
    cpu_host(fixture.path());
    let mut collector = Collector::new(HostRoot::under(fixture.path()), GpuProbe::None);
    let first = collector.sample("mini").expect("baseline");
    assert!(first.cpu_percent.is_none());

    // Previous total 1000, idle 800. Add 100 busy and 100 idle: 50%.
    write(
        &fixture.path().join("proc/stat"),
        "cpu  150 0 150 700 200 0 0 0 0 0\n",
    );
    let second = collector.sample("mini").expect("delta sample");
    let percent = second.cpu_percent.expect("delta is measurable");
    assert!(
        (percent - 50.0).abs() < f64::EPSILON,
        "busy delta / total delta = 50, got {percent}"
    );
}

#[test]
fn missing_gauges_are_null_and_caller_attaches_models_and_pods() {
    let fixture = tempfile::tempdir().expect("fixture root");
    fs::create_dir_all(fixture.path().join("proc")).expect("proc dir");
    fs::create_dir_all(fixture.path().join("sys")).expect("sys dir");
    let mut collector = Collector::new(HostRoot::under(fixture.path()), GpuProbe::None);

    let mut sample = collector
        .sample("laptop")
        .expect("sparse fixture still samples");

    assert!(sample.cpu_percent.is_none());
    assert!(sample.memory_used_bytes.is_none());
    assert!(sample.memory_total_bytes.is_none());
    assert!(sample.temperature_celsius.is_none());
    assert!(sample.gpus.is_empty());
    sample.models = vec![ComputeModel {
        name: "qwen".to_owned(),
        loaded: None,
        runtime: "llama".to_owned(),
        unit: "active".to_owned(),
        ready: false,
        state: "active".to_owned(),
    }];
    sample.pods = vec![ComputePod {
        name: "embed".to_owned(),
        node: "laptop".to_owned(),
        state: "Running".to_owned(),
    }];

    let json = serde_json::to_value(&sample).expect("sample serializes");
    assert_eq!(json["node"], "laptop");
    assert!(json["cpuPercent"].is_null());
    assert!(json["memoryUsedBytes"].is_null());
    assert!(json["temperatureCelsius"].is_null());
    assert!(json["modelsNote"].is_null());
    assert_eq!(json["gpus"], serde_json::json!([]));
    assert_eq!(json["models"][0]["runtime"], "llama");
    assert_eq!(json["pods"][0]["state"], "Running");
    assert!(json.get("sampled_at").is_none(), "wire key is camelCase");
    assert!(json["sampledAt"].is_string());
}

#[test]
fn a_vulkan_probe_shows_an_nvidia_card_from_sysfs_without_nvml() {
    let fixture = tempfile::tempdir().expect("fixture root");
    cpu_host(fixture.path());
    write(
        &fixture.path().join("sys/class/drm/card1/device/vendor"),
        "0x10de\n",
    );
    let mut collector = Collector::new(HostRoot::under(fixture.path()), GpuProbe::Vulkan);

    let sample = collector.sample("mini").expect("fixture samples");

    // No NVIDIA sysfs gauges exist on this fixture, and NVML never ran, so
    // the card shows by its sysfs name with every gauge empty.
    assert_eq!(sample.gpus.len(), 1);
    let gpu = &sample.gpus[0];
    assert_eq!(gpu.name, "card1");
    assert!(gpu.utilization_percent.is_none());
    assert!(gpu.memory_used_bytes.is_none());
    assert!(gpu.memory_total_bytes.is_none());
    assert!(gpu.temperature_celsius.is_none());
}

#[test]
fn a_cuda_host_whose_nvml_declines_still_shows_its_nvidia_card_without_gauges() {
    let fixture = tempfile::tempdir().expect("fixture root");
    cpu_host(fixture.path());
    write(&fixture.path().join("dev/nvidia0"), "");
    write(
        &fixture.path().join("sys/class/drm/card1/device/vendor"),
        "0x10de\n",
    );
    // The driver library is absent, as on pc after a driver update before its reboot.
    let missing_library = fixture.path().join("libnvidia-ml.so.1");
    let mut collector = Collector::with_library(
        HostRoot::under(fixture.path()),
        GpuProbe::Cuda,
        Some(missing_library),
    );

    let sample = collector.sample("pc").expect("gpu fixture samples");

    assert_eq!(sample.gpus.len(), 1);
    let gpu = &sample.gpus[0];
    assert_eq!(gpu.name, "nvidia0");
    assert!(gpu.utilization_percent.is_none());
    assert!(gpu.memory_total_bytes.is_none());
}

#[test]
fn a_missing_host_root_is_an_error_not_a_null_sample() {
    let fixture = tempfile::tempdir().expect("fixture root");
    let missing = fixture.path().join("absent");
    let mut collector = Collector::new(HostRoot::under(&missing), GpuProbe::None);

    let error = collector
        .sample("mini")
        .expect_err("an absent proc root is not a sample");

    let message = error.to_string();
    assert!(message.contains("host root is unreadable"), "got {message}");
}

#[test]
fn hwmon_temperature_wins_over_a_cooler_thermal_zone() {
    let fixture = tempfile::tempdir().expect("fixture root");
    cpu_host(fixture.path());
    write(
        &fixture.path().join("sys/class/hwmon/hwmon0/temp1_input"),
        "47000\n",
    );
    write(
        &fixture.path().join("sys/class/hwmon/hwmon0/temp1_max"),
        "90000\n",
    );
    write(
        &fixture.path().join("sys/class/hwmon/hwmon1/temp2_input"),
        "73000\n",
    );
    write(
        &fixture.path().join("sys/class/hwmon/hwmon1/temp2_label"),
        "edge\n",
    );
    let mut collector = Collector::new(HostRoot::under(fixture.path()), GpuProbe::None);

    let sample = collector.sample("mini").expect("hwmon fixture samples");

    assert_eq!(sample.temperature_celsius, Some(73.0));
}

#[test]
fn an_amd_card_is_read_from_drm_sysfs_without_nvml() {
    let fixture = tempfile::tempdir().expect("fixture root");
    cpu_host(fixture.path());
    let card = fixture.path().join("sys/class/drm/card1/device");
    write(&card.join("vendor"), "0x1002\n");
    write(&card.join("product_name"), "AMD Radeon Graphics\n");
    write(&card.join("gpu_busy_percent"), "37\n");
    write(&card.join("mem_info_vram_used"), "1073741824\n");
    write(&card.join("mem_info_vram_total"), "4294967296\n");
    write(&card.join("hwmon/hwmon3/temp1_input"), "68000\n");
    // A connector beside the card must not become a second GPU.
    write(
        &fixture
            .path()
            .join("sys/class/drm/card1-DP-1/device/vendor"),
        "0x1002\n",
    );
    let mut collector = Collector::new(HostRoot::under(fixture.path()), GpuProbe::Vulkan);

    let sample = collector.sample("mini").expect("amd fixture samples");

    assert_eq!(sample.gpus.len(), 1, "a connector is not a second card");
    let gpu = &sample.gpus[0];
    assert_eq!(gpu.name, "AMD Radeon Graphics");
    assert_eq!(gpu.utilization_percent, Some(37.0));
    assert_eq!(gpu.memory_used_bytes, Some(1_073_741_824));
    assert_eq!(gpu.memory_total_bytes, Some(4_294_967_296));
    assert_eq!(gpu.temperature_celsius, Some(68.0));
}
