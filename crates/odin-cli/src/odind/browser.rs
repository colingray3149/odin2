//! Compose browsers from compiled Node/Playwright payloads and manifest-verified scanner/Xvfb paths.

use std::env;
use std::ffi::OsString;
use std::path::PathBuf;

use odin_browser::config::DisplaySource;
use odin_cli::browser_runtime;
use odin_domain::huginn as live;
use odin_huginn::{BrowserDisplaySource, OdindConfig, RuntimeManifest};

use crate::composition::{
    bound_manifest_identity, open_stop_authority, registered_runtime_binding,
};

const COMPILED_BROWSER_NODE_BIN: Option<&str> = option_env!("ODIN_BROWSER_NODE_BIN");
const COMPILED_BROWSER_PLAYWRIGHT_MODULE: Option<&str> =
    option_env!("ODIN_BROWSER_PLAYWRIGHT_MODULE");

/// Borrowed-display xauthority arrives only through ODIN_BROWSER_EXISTING_XAUTHORITY, not config.
pub(super) fn browser_runtime_config(
    config: &OdindConfig,
    manifest: &RuntimeManifest,
) -> Result<Option<browser_runtime::BrowserRuntimeConfig>, String> {
    let Some(browser) = &config.executables.browser else {
        return Ok(None);
    };
    let display = match browser.display.source {
        BrowserDisplaySource::Xvfb => {
            let xvfb_binary = browser.display.xvfb_binary.clone().ok_or_else(|| {
                "browser display source `xvfb` requires executables.browser.display.xvfb_binary"
                    .to_owned()
            })?;
            // The isolated display must execute the exact manifest Xvfb path.
            bound_manifest_identity(manifest, "xvfb", &xvfb_binary)?;
            DisplaySource::Virtual {
                xvfb_binary,
                display_base: 90,
                screen: "1920x1080x24".to_owned(),
            }
        }
        BrowserDisplaySource::Existing => {
            let display = browser.display.display.clone().ok_or_else(|| {
                "browser display source `existing` requires executables.browser.display.display"
                    .to_owned()
            })?;
            let authority_file = env::var_os("ODIN_BROWSER_EXISTING_XAUTHORITY").map(PathBuf::from);
            DisplaySource::Existing {
                display,
                authority_file,
            }
        }
    };
    let node_binary = COMPILED_BROWSER_NODE_BIN
        .map(PathBuf::from)
        .ok_or_else(|| "odind was built without ODIN_BROWSER_NODE_BIN".to_owned())?;
    let playwright_module_root = COMPILED_BROWSER_PLAYWRIGHT_MODULE
        .map(PathBuf::from)
        .ok_or_else(|| "odind was built without ODIN_BROWSER_PLAYWRIGHT_MODULE".to_owned())?;
    let stream_id = live::StreamId::parse(&browser.stream)
        .map_err(|error| format!("invalid executables.browser.stream value: {error}"))?;
    let worker_binding = registered_runtime_binding(manifest, "browser_node", &node_binary)?;
    let scanner_binary = browser.scanner.clone();
    // The scanner runs as an isolated payload with fixed configured args,
    // so its config path must equal the independently generated manifest
    // scanner identity instead of assuming the two settings match.
    bound_manifest_identity(manifest, "scanner", &scanner_binary)?;
    let stop_authority = open_stop_authority(
        manifest,
        &config.worker_bus,
        &config.paths.state_root.join("browser-authority"),
        "browser",
    )?;
    let limits = &config.capacity;
    Ok(Some(browser_runtime::BrowserRuntimeConfig {
        node_binary,
        playwright_module_root,
        chromium_binary: browser.chromium.clone(),
        display,
        profile_root: browser.profile_root.clone(),
        policy_file: browser.policy.clone(),
        protected_values_file: browser.protected_values.clone(),
        scanner_binary,
        scanner_arguments: browser.scanner_args.iter().map(OsString::from).collect(),
        stream_id,
        projection: odin_huginn::browser::BrowserProjectionConfig {
            command_capacity: limits.streams.frame_queue_depth,
            max_timeline_records: limits.streams.replay_buffer_events,
            max_timeline_bytes: limits.streams.max_stream_frame_bytes,
        },
        max_pending_actions: limits.connections.max_inflight_requests,
        max_stream_frame_bytes: limits.streams.max_stream_frame_bytes,
        takeover_lease: odin_browser::takeover::DEFAULT_TAKEOVER_LEASE_TTL,
        stop_authority,
        worker_binding,
    }))
}
