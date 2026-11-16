//! Microphones: the default one by name, and the list status shows.

use std::time::Instant;

use serde_json::{json, Value};

use super::{AUDIO_ROUTE_POLL_INTERVAL, AUDIO_ROUTE_TIMEOUT};
use crate::devices::AliasKind;
use crate::Failure;

impl crate::Desk {
    /// Sets the default microphone and reads it back.
    pub(super) fn default_input(&self, asked: &str) -> Result<String, Failure> {
        let selector = self.devices.resolve(AliasKind::Audio, asked)?;
        let sources = self.pactl_json(&["--format=json", "list", "sources"])?;
        let name = resolve_input(&sources, &selector)?;
        self.timed(&self.bin.pactl, &["set-default-source", &name])?;
        let deadline = Instant::now() + AUDIO_ROUTE_TIMEOUT;
        loop {
            let now = self.timed(&self.bin.pactl, &["get-default-source"])?;
            if now.trim() == name {
                let mics = microphones(&sources, &name);
                return Ok(json!({"verified": true, "mic": mics.join(" · ")}).to_string());
            }
            if Instant::now() >= deadline {
                return Err(format!("the default microphone stayed {}", now.trim()).into());
            }
            self.await_change(&self.pulse, AUDIO_ROUTE_POLL_INTERVAL)?;
        }
    }
}

/// Real microphones (no sink monitors), the default marked with `*`.
pub(super) fn microphones(sources: &Value, default: &str) -> Vec<String> {
    sources
        .as_array()
        .into_iter()
        .flatten()
        .filter(|source| {
            source["name"]
                .as_str()
                .is_some_and(|name| !name.ends_with(".monitor"))
        })
        .map(|source| {
            let name = source["name"].as_str().unwrap_or("?");
            let label = source["description"].as_str().unwrap_or(name);
            let mark = if name == default { "*" } else { "" };
            format!("{mark}{label}")
        })
        .collect()
}

/// The one microphone whose name is `selector`, or whose description is or
/// contains it.
fn resolve_input(sources: &Value, selector: &str) -> Result<String, String> {
    let wanted = selector.to_lowercase();
    let live: Vec<&Value> = sources
        .as_array()
        .into_iter()
        .flatten()
        .filter(|source| {
            source["name"]
                .as_str()
                .is_some_and(|name| !name.ends_with(".monitor"))
        })
        .collect();
    let description = |source: &Value| source["description"].as_str().unwrap_or("").to_lowercase();
    let exact: Vec<&Value> = live
        .iter()
        .copied()
        .filter(|source| source["name"].as_str() == Some(selector) || description(source) == wanted)
        .collect();
    let found = if exact.is_empty() {
        live.iter()
            .copied()
            .filter(|source| description(source).contains(&wanted))
            .collect()
    } else {
        exact
    };
    match found.as_slice() {
        [one] => Ok(one["name"].as_str().unwrap_or_default().to_owned()),
        _ => Err(format!(
            "{} microphone matches {selector:?}; microphones here: {}",
            if found.is_empty() {
                "no"
            } else {
                "more than one"
            },
            microphones(sources, "").join(" · ")
        )),
    }
}
