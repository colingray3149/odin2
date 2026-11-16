//! The desk's live model: one long-lived event stream per source (niri's
//! event stream, `pactl subscribe`) bumps a change counter, and a reading
//! taken at one count stays good until the next event. Verbs read the model
//! (no helper spawns while nothing changes) and wait on the next event
//! instead of polling. A stream that ends leaves its signal dead, and every
//! read goes to the source again.

use std::io::BufRead;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// How long a window step waits for niri to show it done.
const CONFIRM_WITHIN: Duration = Duration::from_secs(1);

#[derive(Default)]
struct State {
    version: u64,
    alive: bool,
}

/// A change counter fed by one event stream.
#[derive(Clone, Default)]
pub(crate) struct Signal {
    state: Arc<(Mutex<State>, Condvar)>,
}

impl Signal {
    /// Every line `stream` sends is a change; its end leaves the signal dead.
    pub(crate) fn from_lines(name: &'static str, stream: impl BufRead + Send + 'static) -> Self {
        let signal = Self::default();
        signal.lock().alive = true;
        let feed = signal.clone();
        let spawned = std::thread::Builder::new()
            .name(format!("odin-desk-{name}"))
            .spawn(move || {
                for line in stream.lines() {
                    if line.is_err() {
                        break;
                    }
                    feed.lock().version += 1;
                    feed.state.1.notify_all();
                }
                feed.lock().alive = false;
                feed.state.1.notify_all();
                eprintln!("odin-desk: the {name} event stream ended; reading the source directly");
            });
        if spawned.is_err() {
            signal.lock().alive = false;
        }
        signal
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The change count, or `None` when no stream is feeding it.
    pub(crate) fn version(&self) -> Option<u64> {
        let state = self.lock();
        state.alive.then_some(state.version)
    }

    /// Waits until a change past `seen` or `timeout`, whichever is first.
    pub(crate) fn wait_past(&self, seen: u64, timeout: Duration) {
        let state = self.lock();
        let _ = self
            .state
            .1
            .wait_timeout_while(state, timeout, |state| state.alive && state.version <= seen);
    }
}

/// A reading that stays good until its signal's next change.
pub(crate) struct Cached<T> {
    value: Mutex<Option<(u64, T)>>,
}

impl<T> Default for Cached<T> {
    fn default() -> Self {
        Self {
            value: Mutex::new(None),
        }
    }
}

impl<T: Clone> Cached<T> {
    /// Our own change: the next read goes to the source, without waiting
    /// for the stream to report it.
    pub(crate) fn invalidate(&self) {
        *self
            .value
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    /// The reading at the signal's current count, read with `fetch` only
    /// when something changed since the last one (always, without a stream).
    pub(crate) fn get<E>(
        &self,
        signal: &Signal,
        fetch: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        // The count is taken before the read, so a change during it marks
        // the reading stale for the next caller.
        let Some(version) = signal.version() else {
            return fetch();
        };
        let mut value = self
            .value
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((at, reading)) = value.as_ref() {
            if *at == version {
                return Ok(reading.clone());
            }
        }
        let reading = fetch()?;
        *value = Some((version, reading.clone()));
        Ok(reading)
    }
}

impl crate::Desk {
    /// Starts `pactl subscribe` in the desktop session; without it every
    /// audio read runs pactl again.
    pub(crate) fn follow_audio(&mut self) {
        let child = self
            .command(&self.bin.pactl)
            .arg("subscribe")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn();
        match child.map(|mut child| child.stdout.take()) {
            Ok(Some(stdout)) => {
                self.pulse = Signal::from_lines("pactl", std::io::BufReader::new(stdout));
            }
            Ok(None) => eprintln!("odin-desk: pactl subscribe gave no output"),
            Err(error) => eprintln!("odin-desk: pactl subscribe could not start: {error}"),
        }
    }

    /// Waits until a window matching `app` and/or `title` (substrings) is
    /// open, or with `gone` until none is; at most 120 s.
    pub(crate) fn wait_for(
        &self,
        app: &Option<String>,
        title: &Option<String>,
        gone: bool,
        seconds: u32,
    ) -> Result<String, crate::Failure> {
        if app.is_none() && title.is_none() {
            return Err(crate::Failure::Error(
                "waitFor needs an app or a title".to_owned(),
            ));
        }
        let contains = |field: &Option<String>, wanted: &Option<String>| {
            wanted.as_ref().is_none_or(|wanted| {
                field
                    .as_ref()
                    .is_some_and(|field| field.to_lowercase().contains(&wanted.to_lowercase()))
            })
        };
        let started = std::time::Instant::now();
        let until = started + std::time::Duration::from_secs(u64::from(seconds.min(120)));
        loop {
            self.watch.check().map_err(crate::Failure::Stopped)?;
            let desktop = self.niri.desktop()?;
            let found = desktop
                .windows
                .iter()
                .find(|window| contains(&window.app_id, app) && contains(&window.title, title));
            match (found, gone) {
                (Some(window), false) => {
                    return Ok(format!(
                        "{} appeared after {} ms",
                        window.label(),
                        started.elapsed().as_millis()
                    ))
                }
                (None, true) => {
                    return Ok(format!(
                        "it was gone after {} ms",
                        started.elapsed().as_millis()
                    ))
                }
                _ if std::time::Instant::now() >= until => {
                    return Err(crate::Failure::Error(format!(
                        "after {} s {}",
                        seconds.min(120),
                        if gone {
                            "the window is still open"
                        } else {
                            "no such window appeared"
                        }
                    )))
                }
                // The next niri event, or a re-read without the stream.
                _ => self.await_change(self.niri.events(), crate::WINDOW_MATCH_POLL_INTERVAL)?,
            }
        }
    }

    /// The step's line once niri shows it done, or the line marked
    /// unconfirmed when niri has not shown it within a second.
    pub(crate) fn confirm(
        &self,
        line: &str,
        done: impl Fn(&crate::niri::Desktop) -> bool,
    ) -> String {
        if self.niri.settle(CONFIRM_WITHIN, done) {
            line.to_owned()
        } else {
            format!("{line} (asked; niri has not shown it yet)")
        }
    }

    /// Waits up to `longest` for `signal`'s next change, so a verb verifies
    /// against the next event instead of polling; the owner's stop is
    /// checked throughout. Without a stream it simply waits.
    pub(crate) fn await_change(
        &self,
        signal: &Signal,
        longest: Duration,
    ) -> Result<(), crate::Failure> {
        let Some(seen) = signal.version() else {
            return self.wait(longest);
        };
        let deadline = std::time::Instant::now() + longest;
        loop {
            self.watch.check().map_err(crate::Failure::Stopped)?;
            let now = std::time::Instant::now();
            if now >= deadline || signal.version() != Some(seen) {
                return Ok(());
            }
            signal.wait_past(seen, (deadline - now).min(crate::STOP_CHECK_INTERVAL));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn a_reading_is_reused_until_the_stream_reports_a_change() {
        let (reader, mut writer) = std::os::unix::net::UnixStream::pair().unwrap();
        let signal = Signal::from_lines("test", std::io::BufReader::new(reader));
        let cached = Cached::default();
        let reads = std::cell::Cell::new(0);
        let read = || -> Result<u32, ()> {
            reads.set(reads.get() + 1);
            Ok(reads.get())
        };
        assert_eq!(cached.get(&signal, read), Ok(1));
        assert_eq!(cached.get(&signal, read), Ok(1), "nothing changed");
        let seen = signal.version().unwrap();
        writeln!(writer, "Event 'change' on sink #1").unwrap();
        signal.wait_past(seen, Duration::from_secs(5));
        assert_eq!(cached.get(&signal, read), Ok(2), "a change re-reads");
        drop(writer);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while signal.version().is_some() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(signal.version(), None, "an ended stream is dead");
        assert_eq!(cached.get(&signal, read), Ok(3));
        assert_eq!(
            cached.get(&signal, read),
            Ok(4),
            "without a stream every read goes to the source"
        );
    }
}
