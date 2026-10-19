//! Fixed authority-wire limits shared by the live session sidecar.

pub fn authority_wire_limits() -> odin_sidecar_protocol::WireLimits {
    odin_sidecar_protocol::WireLimits::new(16_384, 32_768)
        .expect("fixed eval authority limits are valid")
}
