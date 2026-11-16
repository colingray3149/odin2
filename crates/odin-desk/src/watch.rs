//!
//! The stop: once desktop control has acted for an ask, the owner touching a
//! physical mouse, or pressing the stop keys (a niri bind running `odin desk
//! stop`), stops it until the next ask. One thread polls the mice every 100 ms.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use evdev::raw_stream::RawDevice;
use rustix::event::{poll, PollFd, PollFlags, Timespec};

use crate::Step;

const TICK: Duration = Duration::from_millis(100);

#[derive(Default)]
struct State {
    /// Since when actions are watched (the current ask's first action).
    armed: Option<SystemTime>,
    stopped: Option<String>,
}

#[derive(Clone)]
pub(crate) struct Watch {
    state: Arc<Mutex<State>>,
}

/// The file the stop keys touch.
pub(crate) fn stop_file(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join("odin-desk-stop")
}

impl Watch {
    /// Opens every physical mouse; one that exists but cannot be read is an
    /// error, since moving it could not stop desktop control.
    pub(crate) fn start(runtime_dir: &Path) -> Result<Self, String> {
        let mice = open_mice()?;
        let watch = Self {
            state: Arc::new(Mutex::new(State::default())),
        };
        let thread_watch = watch.clone();
        let stop_file = stop_file(runtime_dir);
        std::thread::Builder::new()
            .name("odin-desk-watch".to_owned())
            .spawn(move || thread_watch.run(mice, &stop_file))
            .map_err(|error| format!("the stop watcher could not start: {error}"))?;
        Ok(watch)
    }

    /// A new ask: any earlier stop is lifted, and watching starts now.
    pub(crate) fn arm(&self) {
        let mut state = self.lock();
        state.armed = Some(SystemTime::now());
        state.stopped = None;
    }

    pub(crate) fn disarm(&self) {
        let mut state = self.lock();
        state.armed = None;
        state.stopped = None;
    }

    pub(crate) fn armed(&self) -> bool {
        self.lock().armed.is_some()
    }

    /// Why desktop control is stopped, if it is.
    pub(crate) fn check(&self) -> Result<(), String> {
        match &self.lock().stopped {
            Some(why) => Err(why.clone()),
            None => Ok(()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn stop(&self, why: impl FnOnce() -> String) {
        let mut state = self.lock();
        if state.armed.is_some() && state.stopped.is_none() {
            state.stopped = Some(why());
        }
    }

    /// Latches a stop when the stop keys have touched their file since `seen`.
    fn poll_stop_file(&self, seen: &mut Option<SystemTime>, stop_file: &Path) {
        let stamp = modified(stop_file);
        if stamp != *seen {
            *seen = stamp;
            self.stop(|| format!("the stop keys were pressed at {}", clock()));
        }
    }

    fn run(&self, mut mice: Vec<(String, RawDevice)>, stop_file: &Path) {
        let mut seen_stop = modified(stop_file);
        loop {
            let ready: Vec<bool> = {
                let mut fds: Vec<PollFd> = mice
                    .iter()
                    .map(|(_, device)| PollFd::new(device, PollFlags::IN))
                    .collect();
                let timeout = Timespec::try_from(TICK).ok();
                if poll(&mut fds, timeout.as_ref()).is_err() {
                    std::thread::sleep(TICK);
                }
                fds.iter()
                    .map(|fd| {
                        fd.revents()
                            .intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR)
                    })
                    .collect()
            };
            let mut gone = Vec::new();
            for (index, (name, device)) in mice.iter_mut().enumerate() {
                if !ready[index] {
                    continue;
                }
                match device.fetch_events() {
                    Ok(mut events) => {
                        if events.next().is_some() {
                            self.stop(|| format!("the mouse ({name}) moved at {}", clock()));
                        }
                    }
                    Err(_) => gone.push(index),
                }
            }
            for index in gone.into_iter().rev() {
                mice.remove(index);
            }
            self.poll_stop_file(&mut seen_stop, stop_file);
        }
    }
}

/// Whether a step types, clicks or acts inside an app, which the owner's
/// mouse or the stop keys must be able to stop.
pub(crate) fn drives_input(step: &Step) -> bool {
    match step {
        Step::Click { .. }
        | Step::Point { .. }
        | Step::Drag { .. }
        | Step::Scroll { .. }
        | Step::Type { .. }
        | Step::Key { .. }
        | Step::Structure { .. } => true,
        Step::Scene { steps, .. } => steps.iter().any(drives_input),
        _ => false,
    }
}

fn modified(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
}

/// Wall time as `HH:MM:SS UTC` for the stop sentence.
fn clock() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!(
        "{:02}:{:02}:{:02} UTC",
        now.hour(),
        now.minute(),
        now.second()
    )
}

/// The physical pointing devices, by udev's classification.
fn open_mice() -> Result<Vec<(String, RawDevice)>, String> {
    let mut mice = Vec::new();
    let entries = std::fs::read_dir("/sys/class/input")
        .map_err(|error| format!("/sys/class/input is unreadable: {error}"))?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with("event") {
            continue;
        }
        let sys = entry.path();
        let physical = std::fs::canonicalize(&sys)
            .is_ok_and(|real| !real.components().any(|part| part.as_os_str() == "virtual"));
        let device_name = std::fs::read_to_string(sys.join("device/name")).unwrap_or_default();
        let device_name = device_name.trim().to_owned();
        if !physical || !is_pointer(&sys) {
            continue;
        }
        let node = Path::new("/dev/input").join(&name);
        let device = RawDevice::open(&node).map_err(|error| {
            format!(
                "the mouse {device_name:?} ({}) cannot be read ({error}), so moving it could \
                 not stop desktop control; this host needs the desktop-control udev rule",
                node.display()
            )
        })?;
        mice.push((device_name, device));
    }
    Ok(mice)
}

/// udev marks mice, touchpads and tablets in its database by device number.
fn is_pointer(sys: &Path) -> bool {
    let Ok(number) = std::fs::read_to_string(sys.join("dev")) else {
        return false;
    };
    let database = format!("/run/udev/data/c{}", number.trim());
    std::fs::read_to_string(database).is_ok_and(|data| {
        data.lines().any(|line| {
            matches!(
                line,
                "E:ID_INPUT_MOUSE=1" | "E:ID_INPUT_TOUCHPAD=1" | "E:ID_INPUT_TABLET=1"
            )
        })
    })
}

#[cfg(test)]
impl Watch {
    /// A watch with no mice and no polling thread.
    pub(crate) fn inert() -> Self {
        Self {
            state: Arc::new(Mutex::new(State::default())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn touching_the_stop_file_stops_an_armed_watch_but_not_an_idle_one() {
        let dir = tempfile::tempdir().unwrap();
        let file = stop_file(dir.path());
        let mut seen = modified(&file);
        let watch = Watch::inert();
        watch.poll_stop_file(&mut seen, &file);
        assert!(watch.check().is_ok(), "no stop file yet");
        std::fs::write(&file, "1").unwrap();
        watch.poll_stop_file(&mut seen, &file);
        assert!(
            watch.check().is_ok(),
            "nothing is armed, so nothing to stop"
        );
        watch.arm();
        std::fs::write(&file, "2").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&file)
            .unwrap()
            .set_modified(SystemTime::now() + Duration::from_secs(5))
            .unwrap();
        watch.poll_stop_file(&mut seen, &file);
        assert!(watch.check().unwrap_err().contains("stop keys"));
    }
}
