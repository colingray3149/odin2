//! Authority-wire limits of the live session sidecar.

use odin_domain::extension_policy::SidecarOperationalPolicy;

/// The sidecar's declared operational ceilings, which the sidecar refuses to be launched beyond.
pub fn authority_wire_limits() -> odin_sidecar_protocol::WireLimits {
    let policy = SidecarOperationalPolicy::compiled_default();
    odin_sidecar_protocol::WireLimits::new(
        policy.max_request_bytes as usize,
        policy.max_frame_bytes as usize,
    )
    .expect("the sidecar's declared limits are valid")
}
