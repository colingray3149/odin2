//! Device-boundary check against a real Flipper over USB serial.
//!
//!   FLIPPER_PORT=/dev/serial/by-id/usb-Flipper_Devices_Inc._Uvin1cs_flip_Uvin1cs-if00 \
//!     cargo test -p bagd --test flipper_hw -- --ignored --nocapture
//!
//! Requesting the test means a device is expected: an unset or absent `FLIPPER_PORT` fails it.
//! It reads `device_info` only; it never installs firmware and never writes storage.

use bagd::flipper::FlipperCli;

#[test]
#[ignore = "requires physical Flipper; never flashes"]
fn a_real_device_answers_device_info() {
    let path = std::env::var("FLIPPER_PORT")
        .expect("FLIPPER_PORT names the attached Flipper's by-id node");
    let mut cli = FlipperCli::new(path);
    let info = cli
        .command("device_info", std::time::Duration::from_secs(8))
        .expect("device_info");
    assert!(info.contains("Flipper Zero"), "{info}");
}
