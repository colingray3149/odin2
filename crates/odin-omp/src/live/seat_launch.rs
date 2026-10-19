//! The per-seat launch choice: which of a seat's declared launch options —
//! model and harness — its sessions open with. Set from a
//! DM through `seat.model.set`, kept across restarts in
//! `<state_root>/seat-launch.json`, and read by every opener (the
//! conversation vehicle, cross-seat workers). Only a declared option can be
//! chosen; a stored choice the declaration no longer offers is ignored with
//! a log line, and the seat opens on its first declared option.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use odin_domain::huginn::LiveLaunchOption;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SeatLaunchChoice {
    pub provider: String,
    pub model: String,
}

#[derive(Clone, Debug)]
pub struct SeatLaunchStore {
    path: PathBuf,
}

impl SeatLaunchStore {
    pub fn new(state_root: &Path) -> Self {
        Self {
            path: state_root.join("seat-launch.json"),
        }
    }

    fn load(&self) -> Result<BTreeMap<String, SeatLaunchChoice>, String> {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|error| {
                format!("{} is not a seat launch map: {error}", self.path.display())
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(error) => Err(format!("{} is unreadable: {error}", self.path.display())),
        }
    }

    /// Records the seat's choice (atomic replace).
    pub fn set(&self, seat: &str, choice: SeatLaunchChoice) -> Result<(), String> {
        let mut map = self.load()?;
        map.insert(seat.to_owned(), choice);
        let bytes = serde_json::to_vec_pretty(&map).map_err(|error| error.to_string())?;
        let temporary = self.path.with_extension("json.tmp");
        std::fs::write(&temporary, bytes)
            .and_then(|()| std::fs::rename(&temporary, &self.path))
            .map_err(|error| format!("could not write {}: {error}", self.path.display()))
    }

    /// The option the seat opens with: its stored choice when that is still
    /// declared, else the first declared option.
    pub fn select<'a>(
        &self,
        seat: &str,
        options: &'a [LiveLaunchOption],
    ) -> Option<&'a LiveLaunchOption> {
        let choice = match self.load() {
            Ok(map) => map.get(seat).cloned(),
            Err(error) => {
                tracing::error!("odind: seat_launch unreadable seat={seat} reason={error:?}");
                None
            }
        };
        if let Some(choice) = choice {
            if let Some(option) = options.iter().find(|option| {
                option.provider.as_str() == choice.provider && option.model.as_str() == choice.model
            }) {
                return Some(option);
            }
            tracing::warn!(
                "odind: seat_launch stale seat={seat} provider={} model={} reason=\"no longer \
                 declared; the first option opens\"",
                choice.provider,
                choice.model
            );
        }
        options.first()
    }
}
