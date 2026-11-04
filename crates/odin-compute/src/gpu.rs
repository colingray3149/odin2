//! One GPU reading, whether it came from NVML or from DRM sysfs, and the
//! host's declared GPU probe.

/// The host's declared probe (`odin.node.gpu` → `compute-facts.json`).
///
/// `Cuda` is the only value that opens NVML. `Vulkan` and `None` read DRM
/// sysfs only, so a host can stop NVML attempts without a code change (a
/// broken driver, as on pc until its reboot).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpuProbe {
    None,
    Vulkan,
    Cuda,
}

impl GpuProbe {
    /// Whether this probe may open NVML. The card must also be NVIDIA.
    pub fn opens_nvml(self) -> bool {
        matches!(self, Self::Cuda)
    }
}

impl std::str::FromStr for GpuProbe {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "none" => Ok(Self::None),
            "vulkan" => Ok(Self::Vulkan),
            "cuda" => Ok(Self::Cuda),
            _ => Err(format!(
                "unknown GPU probe {text}; want none, vulkan or cuda"
            )),
        }
    }
}

pub(crate) struct GpuReading {
    pub(crate) name: String,
    pub(crate) utilization_percent: Option<f64>,
    pub(crate) memory_used_bytes: Option<u64>,
    pub(crate) memory_total_bytes: Option<u64>,
    pub(crate) temperature_celsius: Option<f64>,
}
