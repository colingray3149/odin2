//!
//! `odin desk serve`: Sinmara's hands on the owner's desktop. odind on the
//! authority keeps one ssh channel open to it; each JSON line in is one
//! request (steps, then an optional screenshot) and each line out its reply.
//! It drives a uinput pointer and keyboard, niri's IPC socket and grim, only
//! in an unlocked niri session, and stops for the rest of an ask when the owner
//! touches his mouse or presses the stop keys.
//! Operation-specific timeout and polling durations are named constants beside
//! the desktop, device, media, and accessibility code that uses them.

mod devices;
mod hands;
mod keys;
mod live;
mod niri;
mod shot;
mod structure;
mod watch;

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde::Deserialize;
use serde_json::{json, Value};

pub use devices::DeviceMap;
pub use hands::Button;
use hands::Hands;
use keys::Chord;
use niri::{Desktop, Niri, Rect};
use shot::Shot;
use watch::Watch;

const COMMAND_EXIT_POLL_INTERVAL: Duration = Duration::from_millis(10);
const REPEATED_CLICK_INTERVAL: Duration = Duration::from_millis(30);
const POINTER_MOTION_INTERVAL: Duration = Duration::from_millis(8);
const STOP_CHECK_INTERVAL: Duration = Duration::from_millis(50);
const WINDOW_MATCH_POLL_INTERVAL: Duration = Duration::from_millis(250);
/// How long one audio or media helper may run before it is abandoned.
const HELPER_TIMEOUT: Duration = Duration::from_secs(20);

/// One request: the ask it serves, its steps in order, then what to show.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    /// The owner's message this request answers; a new one lifts an earlier stop.
    pub ask: String,
    #[serde(default)]
    pub steps: Vec<Step>,
    /// Return the outputs, workspaces and windows.
    #[serde(default)]
    pub layout: bool,
    pub shot: Option<ShotOf>,
}

/// A window by its niri id, or by app or title ("discord", "palworld"), or
/// "focused", so a step needs no lookup first.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum WindowRef {
    Id(u64),
    Name(String),
}

#[derive(Debug, Deserialize)]
#[serde(tag = "do", rename_all = "camelCase", deny_unknown_fields)]
pub enum Step {
    Focus {
        window: WindowRef,
    },
    Workspace {
        index: u8,
        output: Option<String>,
    },
    Move {
        window: WindowRef,
        workspace: Option<u8>,
        output: Option<String>,
    },
    Size {
        window: WindowRef,
        width: Option<String>,
        height: Option<String>,
    },
    Fullscreen {
        window: WindowRef,
    },
    Close {
        window: WindowRef,
    },
    /// These windows top to bottom in one column, in this order.
    Column {
        windows: Vec<u64>,
    },
    /// These windows in adjacent columns, left to right in this order.
    Beside {
        windows: Vec<u64>,
        width: Option<String>,
    },
    Launch {
        app: String,
    },
    Structure {
        action: Box<structure::StructureAction>,
        #[serde(default)]
        headless: bool,
    },
    Device {
        action: devices::DeviceAction,
    },
    Display {
        on: bool,
    },
    Headless {
        action: devices::HeadlessAction,
    },
    Scene {
        name: String,
        steps: Vec<Step>,
    },
    Save {
        path: PathBuf,
        expected: String,
        content: String,
        #[serde(default)]
        encoding: SaveEncoding,
    },
    Click {
        x: f64,
        y: f64,
        button: Option<Button>,
        double: Option<bool>,
    },
    Point {
        x: f64,
        y: f64,
    },
    #[serde(rename_all = "camelCase")]
    Drag {
        #[serde(default)]
        path: Vec<Point>,
        x: Option<f64>,
        y: Option<f64>,
        to_x: Option<f64>,
        to_y: Option<f64>,
    },
    Scroll {
        x: f64,
        y: f64,
        down: i32,
        right: Option<i32>,
    },
    Type {
        text: String,
    },
    Key {
        keys: String,
    },
    Wait {
        ms: u32,
    },
    #[serde(rename_all = "camelCase")]
    WaitFor {
        app: Option<String>,
        title: Option<String>,
        gone: Option<bool>,
        seconds: u32,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Point {
    x: f64,
    y: f64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SaveEncoding {
    #[default]
    Utf8,
    Base64,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "of", rename_all = "camelCase", deny_unknown_fields)]
pub enum ShotOf {
    Screen {
        output: Option<String>,
    },
    All {},
    Window {
        window: u64,
    },
    /// A rectangle in the pixels of the last screenshot.
    Zoom {
        x: f64,
        y: f64,
        width: f64,
        height: f64,
    },
}

/// Names the JSON file of executables this host declares for the desk
/// (`desktop-control.nix`); none is looked up on PATH.
const EXECUTABLES: &str = "ODIN_DESK_EXECUTABLES";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Executables {
    grim: PathBuf,
    wtype: PathBuf,
    notify_send: PathBuf,
    loginctl: PathBuf,
    systemctl: PathBuf,
    pactl: PathBuf,
    wl_copy: PathBuf,
    wl_paste: PathBuf,
    weston: PathBuf,
    dbus_daemon: PathBuf,
}

fn executables() -> Result<Executables, String> {
    let path = std::env::var_os(EXECUTABLES).ok_or_else(|| {
        format!("{EXECUTABLES} is unset; desktop-control.nix declares it on the desktop host")
    })?;
    let path = PathBuf::from(path);
    let text = std::fs::read_to_string(&path).map_err(|error| {
        format!(
            "{EXECUTABLES} file {} is unreadable: {error}",
            path.display()
        )
    })?;
    serde_json::from_str(&text).map_err(|error| {
        format!(
            "{EXECUTABLES} file {} does not parse: {error}",
            path.display()
        )
    })
}

#[derive(Debug)]
enum Failure {
    Stopped(String),
    Error(String),
}

impl From<String> for Failure {
    fn from(error: String) -> Self {
        Failure::Error(error)
    }
}

impl From<&str> for Failure {
    fn from(error: &str) -> Self {
        Failure::Error(error.to_owned())
    }
}

impl Failure {
    fn into_text(self) -> String {
        match self {
            Failure::Stopped(text) | Failure::Error(text) => text,
        }
    }
}

struct Desk {
    niri: Niri,
    bin: Executables,
    devices: DeviceMap,
    /// The desktop user's graphical session environment, as his user manager holds it.
    environment: Vec<(String, String)>,
    session: String,
    watch: Watch,
    hands: Option<Hands>,
    ask: Option<String>,
    last_shot: Option<Shot>,
    shots: u64,
    /// The output before the last whole-computer switch, for a swap back.
    previous_output: Option<String>,
    /// `pactl subscribe`, and the audio state read at its change count.
    pulse: live::Signal,
    audio: live::Cached<Value>,
    headless: Option<devices::Headless>,
}

/// Serves requests from `input` until it closes.
pub fn serve(input: impl BufRead, output: impl Write) -> Result<(), String> {
    let bin = executables()?;
    let environment = session_environment(&bin)?;
    let variable = |name: &str| {
        session_var(&environment, name)
            .map(str::to_owned)
            .ok_or_else(|| {
                format!(
                    "the desktop user's session has no {name}: niri is not running on this host"
                )
            })
    };
    let runtime_dir = PathBuf::from(variable("XDG_RUNTIME_DIR")?);
    variable("WAYLAND_DISPLAY")?;
    let mut desk = Desk {
        niri: Niri::new(PathBuf::from(variable("NIRI_SOCKET")?)),
        session: variable("XDG_SESSION_ID")?,
        watch: Watch::start(&runtime_dir)?,
        devices: DeviceMap::from_environment()?,
        bin,
        environment,
        hands: None,
        ask: None,
        last_shot: None,
        shots: 0,
        previous_output: None,
        headless: None,
        pulse: live::Signal::default(),
        audio: live::Cached::default(),
    };
    desk.niri.follow_events();
    desk.follow_audio();
    desk.serve_lines(&private_file(&runtime_dir), input, output)
}

fn session_var<'a>(environment: &'a [(String, String)], name: &str) -> Option<&'a str> {
    environment
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

/// While this file exists the desktop is private (a local-models mode marked
/// private writes it): every request is refused and nothing is looked at.
fn private_file(runtime_dir: &std::path::Path) -> PathBuf {
    runtime_dir.join("odin-desk-private")
}

fn private_refusal(path: &std::path::Path) -> String {
    let mode = std::fs::read_to_string(path).unwrap_or_default();
    format!(
        "this desktop is private ({}): desktop control is off until that mode ends",
        mode.trim()
    )
}

/// `odin desk stop`: what the stop keys run.
pub fn stop() -> Result<(), String> {
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR").ok_or("XDG_RUNTIME_DIR is not set")?;
    let path = watch::stop_file(std::path::Path::new(&runtime_dir));
    std::fs::write(&path, format!("{:?}\n", std::time::SystemTime::now()))
        .map_err(|error| format!("{} could not be written: {error}", path.display()))
}

fn session_environment(bin: &Executables) -> Result<Vec<(String, String)>, String> {
    let output = std::process::Command::new(&bin.systemctl)
        .args(["--user", "show-environment"])
        .output()
        .map_err(|error| format!("systemctl --user could not run: {error}"))?;
    if !output.status.success() {
        return Err(
            "the desktop user's manager is not running: nobody is logged in here".to_owned(),
        );
    }
    let mut environment: Vec<(String, String)> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();
    // Started inside a niri session (not over ssh), it serves that session.
    if let (Some(niri), Some(wayland)) = (
        std::env::var_os("NIRI_SOCKET"),
        std::env::var_os("WAYLAND_DISPLAY"),
    ) {
        for (key, value) in [("NIRI_SOCKET", niri), ("WAYLAND_DISPLAY", wayland)] {
            environment.retain(|(name, _)| name != key);
            environment.push((key.to_owned(), value.to_string_lossy().into_owned()));
        }
    }
    Ok(environment)
}

/// niri IPC only: no shell command or compositor fallback.
fn display_action(on: bool) -> Value {
    if on {
        json!({ "PowerOnMonitors": {} })
    } else {
        json!({ "PowerOffMonitors": {} })
    }
}

impl Desk {
    fn serve_lines(
        &mut self,
        private: &std::path::Path,
        input: impl BufRead,
        mut output: impl Write,
    ) -> Result<(), String> {
        for line in input.lines() {
            let line = line.map_err(|error| format!("reading a request failed: {error}"))?;
            let reply = match serde_json::from_str::<Request>(&line) {
                Ok(_) if private.exists() => {
                    json!({ "ok": false, "error": private_refusal(private) })
                }
                Ok(request) => self.handle(request),
                Err(error) => {
                    json!({ "ok": false, "error": format!("unreadable request: {error}") })
                }
            };
            writeln!(output, "{reply}")
                .and_then(|()| output.flush())
                .map_err(|error| format!("writing a reply failed: {error}"))?;
        }
        Ok(())
    }

    fn session_var(&self, name: &str) -> Option<&str> {
        session_var(&self.environment, name)
    }

    fn command(&self, path: &std::path::Path) -> std::process::Command {
        let mut command = std::process::Command::new(path);
        command.env_clear().envs(self.environment.iter().cloned());
        command
    }

    fn checked(&self, path: &std::path::Path, args: &[&str]) -> Result<String, String> {
        let mut command = self.command(path);
        command.args(args);
        self.exec(path, &mut command, None, None)
            .map_err(Failure::into_text)
    }

    /// A helper that must answer within `HELPER_TIMEOUT`.
    fn timed(&self, path: &std::path::Path, args: &[&str]) -> Result<String, Failure> {
        let mut command = self.command(path);
        command.args(args);
        self.exec(path, &mut command, None, Some(HELPER_TIMEOUT))
    }


    /// Runs a helper to completion. Children are polled rather than awaited:
    /// the physical stop kills one mid-run and prevents later steps; `limit`
    /// bounds a helper that may hang; `input` is fed to its stdin.
    fn exec(
        &self,
        path: &std::path::Path,
        command: &mut std::process::Command,
        input: Option<&[u8]>,
        limit: Option<Duration>,
    ) -> Result<String, Failure> {
        use std::io::Read as _;
        use std::process::Stdio;
        self.watch.check().map_err(Failure::Stopped)?;
        let mut child = command
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("{} could not run: {error}", path.display()))?;
        let mut stdout = child.stdout.take().ok_or("command has no stdout")?;
        let mut stderr = child.stderr.take().ok_or("command has no stderr")?;
        let mut stdin = child.stdin.take();
        std::thread::scope(|scope| {
            // Both pipes drain concurrently so a large output cannot block the
            // child while the stop watch is polling.
            let out = scope.spawn(move || {
                let mut bytes = Vec::new();
                stdout.read_to_end(&mut bytes).map(|_| bytes)
            });
            let err = scope.spawn(move || {
                let mut bytes = Vec::new();
                stderr.read_to_end(&mut bytes).map(|_| bytes)
            });
            let writer = input
                .zip(stdin.take())
                .map(|(input, mut stdin)| scope.spawn(move || stdin.write_all(input)));
            let deadline = limit.map(|limit| Instant::now() + limit);
            let status = loop {
                let abandon = match self.watch.check() {
                    Err(reason) => Some(Failure::Stopped(reason)),
                    Ok(()) if deadline.is_some_and(|at| Instant::now() >= at) => {
                        Some(Failure::Error(format!(
                            "{} timed out; its effect may be partial",
                            path.display()
                        )))
                    }
                    Ok(()) => None,
                };
                if let Some(failure) = abandon {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(failure);
                }
                match child.try_wait() {
                    Ok(Some(status)) => break status,
                    Ok(None) => std::thread::sleep(COMMAND_EXIT_POLL_INTERVAL),
                    Err(error) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(format!("waiting for {}: {error}", path.display()).into());
                    }
                }
            };
            let written = match writer {
                Some(writer) => writer
                    .join()
                    .map_err(|_| "writing command input panicked")?
                    .map_err(|error| format!("writing {} input: {error}", path.display())),
                None => Ok(()),
            };
            let stdout = out
                .join()
                .map_err(|_| "reading command stdout panicked")?
                .map_err(|error| format!("reading command stdout: {error}"))?;
            let stderr = err
                .join()
                .map_err(|_| "reading command stderr panicked")?
                .map_err(|error| format!("reading command stderr: {error}"))?;
            if !status.success() {
                return Err(format!(
                    "{} exited {status}: {}",
                    path.display(),
                    String::from_utf8_lossy(&stderr).trim()
                )
                .into());
            }
            written?;
            String::from_utf8(stdout).map_err(|error| {
                Failure::Error(format!(
                    "{} returned non-UTF-8 output: {error}",
                    path.display()
                ))
            })
        })
    }

    /// Clipboard owners fork; inherited output pipes must not keep this request open.
    fn checked_input(
        &self,
        path: &std::path::Path,
        args: &[&str],
        input: &[u8],
    ) -> Result<String, String> {
        use std::process::Stdio;
        self.watch.check()?;
        let mut child = self
            .command(path)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| format!("{} could not run: {error}", path.display()))?;
        let mut stdin = child.stdin.take().ok_or("command has no stdin")?;
        let status = std::thread::scope(|scope| -> Result<std::process::ExitStatus, String> {
            let writer = scope.spawn(move || stdin.write_all(input));
            let status = loop {
                if let Err(error) = self.watch.check() {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error);
                }
                match child
                    .try_wait()
                    .map_err(|error| format!("waiting for command: {error}"))?
                {
                    Some(status) => break status,
                    None => std::thread::sleep(COMMAND_EXIT_POLL_INTERVAL),
                }
            };
            writer
                .join()
                .map_err(|_| "writing command input panicked")?
                .map_err(|error| format!("writing command input: {error}"))?;
            Ok(status)
        })?;
        if !status.success() {
            return Err(format!(
                "{} exited {status}; diagnostic written to desktop helper stderr",
                path.display()
            ));
        }
        Ok(String::new())
    }

    fn handle(&mut self, request: Request) -> Value {
        let started = Instant::now();
        let mut did = Vec::new();
        let outcome = self.run(&request, &mut did);
        let steps_ms = started.elapsed().as_millis();
        let mut reply = json!({ "ok": outcome.is_ok(), "did": did, "stepsMs": steps_ms });
        match outcome {
            Ok(()) => {}
            Err(Failure::Stopped(why)) => {
                reply["stopped"] = json!(format!("{why}; nothing more runs until the next ask"));
            }
            Err(Failure::Error(error)) => reply["error"] = json!(error),
        }
        // What the screen shows after the steps, even after a failure.
        if reply.get("stopped").is_none() && (request.layout || request.shot.is_some()) {
            let desktop = self.niri.desktop();
            if request.layout {
                match &desktop {
                    Ok(desktop) => reply["layout"] = desktop.summary(),
                    Err(error) => reply["layoutError"] = json!(error),
                }
            }
            if let Some(of) = &request.shot {
                let shot_started = Instant::now();
                match desktop.and_then(|desktop| self.screenshot(&desktop, of)) {
                    Ok(shot) => {
                        reply["shot"] = json!({
                            "jpeg": base64::engine::general_purpose::STANDARD.encode(&shot.jpeg),
                            "width": shot.width,
                            "height": shot.height,
                            "saved": shot.saved,
                            "ms": shot_started.elapsed().as_millis(),
                        });
                        self.last_shot = Some(shot);
                    }
                    Err(error) => reply["shotError"] = json!(error),
                }
            }
        }
        reply
    }

    fn run(&mut self, request: &Request, did: &mut Vec<String>) -> Result<(), Failure> {
        self.unlocked()?;
        if self.ask.as_deref() != Some(request.ask.as_str()) {
            self.ask = Some(request.ask.clone());
            self.watch.disarm();
        }
        if request.steps.is_empty() {
            return Ok(());
        }
        // Only steps that drive input arm the mouse stop; IPC verbs (audio,
        // windows, media, monitors, lights) leave the owner his mouse.
        if !self.watch.armed() && request.steps.iter().any(watch::drives_input) {
            self.watch.arm();
            self.notify();
        }
        for step in &request.steps {
            self.watch.check().map_err(Failure::Stopped)?;
            let line = self.step(step).map_err(|failure| {
                self.watch
                    .check()
                    .err()
                    .map(Failure::Stopped)
                    .unwrap_or(failure)
            })?;
            did.push(line);
        }
        self.watch.check().map_err(Failure::Stopped)
    }

    /// The screen must be unlocked: typing into the lock screen is never hers.
    fn unlocked(&self) -> Result<(), String> {
        let output = std::process::Command::new(&self.bin.loginctl)
            .args(["show-session", &self.session, "-p", "LockedHint", "--value"])
            .output()
            .map_err(|error| format!("loginctl could not run: {error}"))?;
        match String::from_utf8_lossy(&output.stdout).trim() {
            "no" => Ok(()),
            "yes" => Err("the screen is locked; nothing was done".to_owned()),
            other => Err(format!(
                "session {} reports LockedHint {other:?}",
                self.session
            )),
        }
    }

    fn desktop_point(&self, x: f64, y: f64) -> Result<(f64, f64), String> {
        self.last_shot
            .as_ref()
            .ok_or("take a screenshot first: pointer positions are pixels of your last screenshot")?
            .to_desktop(x, y)
    }

    fn hands(&mut self) -> Result<&mut Hands, String> {
        if self.hands.is_none() {
            self.hands = Some(Hands::new()?);
        }
        self.hands
            .as_mut()
            .ok_or_else(|| "the uinput devices are missing".to_owned())
    }

    /// Moves the pointer to a screenshot pixel.
    fn point(&mut self, x: f64, y: f64) -> Result<(), String> {
        let bounds = self.niri.desktop()?.bounds()?;
        self.point_in(bounds, x, y)
    }

    /// `point` against bounds already read, for a drag's many samples.
    fn point_in(&mut self, bounds: Rect, x: f64, y: f64) -> Result<(), String> {
        let (x, y) = self.desktop_point(x, y)?;
        self.hands()?.point(bounds, x, y)
    }

    fn step(&mut self, step: &Step) -> Result<String, Failure> {
        let label = |desk: &Self, id: u64| -> Result<String, String> {
            Ok(desk.niri.desktop()?.window(id)?.label())
        };
        // One niri read resolves a window reference to its id and label.
        let named = |desk: &Self, window: &WindowRef| -> Result<(u64, String), String> {
            let desktop = desk.niri.desktop()?;
            let found = match window {
                WindowRef::Id(id) => desktop.window(*id)?,
                WindowRef::Name(name) => desktop.window_named(name)?,
            };
            Ok((found.id, found.label()))
        };
        Ok(match step {
            Step::Display { on } => {
                self.niri.action(display_action(*on))?;
                format!(
                    "turned {} all monitors on this device",
                    if *on { "on" } else { "off" }
                )
            }
            Step::Focus { window } => {
                let (window, name) = named(self, window)?;
                self.niri
                    .action(json!({ "FocusWindow": { "id": window } }))?;
                self.confirm(&format!("focused {name}"), |desktop| {
                    desktop.window(window).is_ok_and(|shown| shown.is_focused)
                })
            }
            Step::Workspace { index, output } => {
                let output = output
                    .as_deref()
                    .map(|value| self.devices.resolve(devices::AliasKind::Outputs, value))
                    .transpose()?;
                if let Some(output) = &output {
                    self.niri
                        .action(json!({ "FocusMonitor": { "output": output } }))?;
                }
                self.niri
                    .action(json!({ "FocusWorkspace": { "reference": { "Index": index } } }))?;
                match output {
                    Some(output) => format!("showed workspace {index} on {output}"),
                    None => format!("showed workspace {index}"),
                }
            }
            Step::Move {
                window,
                workspace,
                output,
            } => {
                let (window, name) = named(self, window)?;
                if workspace.is_none() && output.is_none() {
                    return Err(Failure::Error(
                        "move needs a workspace or an output".to_owned(),
                    ));
                }
                let output = output
                    .as_deref()
                    .map(|value| self.devices.resolve(devices::AliasKind::Outputs, value))
                    .transpose()?;
                if let Some(output) = &output {
                    self.niri.action(
                        json!({ "MoveWindowToMonitor": { "id": window, "output": output } }),
                    )?;
                }
                if let Some(index) = workspace {
                    self.niri.action(json!({ "MoveWindowToWorkspace": {
                        "window_id": window, "reference": { "Index": index }, "focus": false
                    } }))?;
                }
                let to: Vec<String> = [
                    output.as_ref().map(|output| format!("output {output}")),
                    workspace.map(|index| format!("workspace {index}")),
                ]
                .into_iter()
                .flatten()
                .collect();
                format!("moved {name} to {}", to.join(", "))
            }
            Step::Size {
                window,
                width,
                height,
            } => {
                let (window, name) = named(self, window)?;
                if let Some(width) = width {
                    let change = niri::size_change(width)?;
                    self.niri
                        .action(json!({ "SetWindowWidth": { "id": window, "change": change } }))?;
                }
                if let Some(height) = height {
                    let change = niri::size_change(height)?;
                    self.niri
                        .action(json!({ "SetWindowHeight": { "id": window, "change": change } }))?;
                }
                format!(
                    "sized {name} to width {} height {}",
                    width.as_deref().unwrap_or("unchanged"),
                    height.as_deref().unwrap_or("unchanged")
                )
            }
            Step::Fullscreen { window } => {
                let (window, name) = named(self, window)?;
                self.niri
                    .action(json!({ "FullscreenWindow": { "id": window } }))?;
                format!("toggled fullscreen on {name}")
            }
            Step::Column { windows } => {
                let (first, rest) = windows
                    .split_first()
                    .ok_or("column needs at least one window")?;
                for window in rest {
                    self.place_after(*first, *window)?;
                    self.niri
                        .action(json!({ "ConsumeOrExpelWindowLeft": { "id": window } }))?;
                }
                self.niri
                    .action(json!({ "FocusWindow": { "id": first } }))?;
                let names = windows
                    .iter()
                    .map(|window| label(self, *window))
                    .collect::<Result<Vec<_>, _>>()?;
                format!("stacked {} in one column", names.join(" over "))
            }
            Step::Beside { windows, width } => {
                let change = width.as_deref().map(niri::size_change).transpose()?;
                for (index, window) in windows.iter().enumerate() {
                    if let Some(previous) = index.checked_sub(1).map(|at| windows[at]) {
                        self.place_after(previous, *window)?;
                    } else {
                        self.alone(*window)?;
                    }
                    if let Some(change) = &change {
                        self.niri
                            .action(json!({ "SetColumnWidth": { "change": change } }))?;
                    }
                }
                let first = windows.first().ok_or("beside needs at least one window")?;
                self.niri
                    .action(json!({ "FocusWindow": { "id": first } }))?;
                let names = windows
                    .iter()
                    .map(|window| label(self, *window))
                    .collect::<Result<Vec<_>, _>>()?;
                format!("placed {} side by side", names.join(", "))
            }
            Step::Close { window } => {
                let (window, name) = named(self, window)?;
                self.niri
                    .action(json!({ "CloseWindow": { "id": window } }))?;
                self.confirm(&format!("closed {name}"), |desktop| {
                    desktop.window(window).is_err()
                })
            }
            Step::Launch { app } => {
                let command = self.desktop_entry(app)?;
                self.niri
                    .action(json!({ "Spawn": { "command": command } }))?;
                format!("launched {app} ({})", command.join(" "))
            }
            Step::Structure { action, headless } => {
                let original = if *headless {
                    let overrides = self
                        .headless
                        .as_mut()
                        .ok_or("start the private headless display first")?
                        .environment()?;
                    let environment = devices::private_session(&self.environment, overrides);
                    Some(std::mem::replace(&mut self.environment, environment))
                } else {
                    None
                };
                let result = self.structure(action);
                if let Some(original) = original {
                    self.environment = original;
                }
                result?
            }
            Step::Device { action } => self.device_action(action)?,
            Step::Headless { action } => self.headless_action(action)?,
            Step::Scene { name, steps } => {
                if steps.is_empty() {
                    return Err("a scene needs at least one typed action".to_owned().into());
                }
                let mut completed = Vec::new();
                for step in steps {
                    self.watch.check().map_err(Failure::Stopped)?;
                    match self.step(step) {
                        Ok(line) => completed.push(line),
                        Err(Failure::Stopped(why)) => {
                            return Err(Failure::Stopped(format!(
                                "scene {name:?} completed {}: {why}",
                                completed.join("; ")
                            )))
                        }
                        Err(Failure::Error(why)) => {
                            return Err(Failure::Error(format!(
                                "scene {name:?} completed {}: {why}",
                                completed.join("; ")
                            )))
                        }
                    }
                }
                format!("scene {name:?}: {}", completed.join("; "))
            }
            Step::Save {
                path,
                expected,
                content,
                encoding,
            } => self.edit_save(path, expected, content, encoding)?,
            Step::Click {
                x,
                y,
                button,
                double,
            } => {
                let button = button.unwrap_or(Button::Left);
                self.point(*x, *y)?;
                let presses = if double.unwrap_or(false) { 2 } else { 1 };
                for _ in 0..presses {
                    let hands = self.hands()?;
                    hands.button(button, true)?;
                    hands.button(button, false)?;
                    std::thread::sleep(REPEATED_CLICK_INTERVAL);
                }
                format!(
                    "clicked {button:?} at ({x}, {y}){}",
                    if presses == 2 { " twice" } else { "" }
                )
            }
            Step::Point { x, y } => {
                self.point(*x, *y)?;
                format!("pointed at ({x}, {y})")
            }
            Step::Drag {
                path,
                x,
                y,
                to_x,
                to_y,
            } => {
                let legacy;
                let points = if path.is_empty() {
                    legacy = vec![
                        Point {
                            x: x.ok_or("drag needs path or x/y/toX/toY")?,
                            y: y.ok_or("drag needs y")?,
                        },
                        Point {
                            x: to_x.ok_or("drag needs toX")?,
                            y: to_y.ok_or("drag needs toY")?,
                        },
                    ];
                    &legacy
                } else {
                    if x.is_some() || y.is_some() || to_x.is_some() || to_y.is_some() {
                        return Err("drag uses path or x/y/toX/toY, not both".to_owned().into());
                    }
                    path
                };
                if points.len() < 2 {
                    return Err("drag path needs at least two points".to_owned().into());
                }
                // Resolve every point before holding a button; all segments use the same transform.
                for point in points {
                    self.desktop_point(point.x, point.y)?;
                }
                let bounds = self.niri.desktop()?.bounds()?;
                self.point_in(bounds, points[0].x, points[0].y)?;
                self.hands()?.button(Button::Left, true)?;
                let result = (|| -> Result<(), Failure> {
                    for segment in points.windows(2) {
                        for index in 1..=12 {
                            self.watch.check().map_err(Failure::Stopped)?;
                            let t = f64::from(index) / 12.0;
                            self.point_in(
                                bounds,
                                segment[0].x + (segment[1].x - segment[0].x) * t,
                                segment[0].y + (segment[1].y - segment[0].y) * t,
                            )?;
                            self.wait(POINTER_MOTION_INTERVAL)?;
                        }
                    }
                    Ok(())
                })();
                let release = self.hands()?.button(Button::Left, false);
                result?;
                release?;
                format!("dragged through {} points", points.len())
            }
            Step::Scroll { x, y, down, right } => {
                self.point(*x, *y)?;
                self.hands()?.scroll(*down, right.unwrap_or(0))?;
                format!(
                    "scrolled {down} down, {} right at ({x}, {y})",
                    right.unwrap_or(0)
                )
            }
            Step::Type { text } => {
                if text
                    .chars()
                    .all(|character| keys::char_key(character).is_some())
                {
                    let watch = self.watch.clone();
                    self.hands()?.type_text(text, &|| watch.check())?;
                } else {
                    self.wtype(text)?;
                }
                let shown: String = text.chars().take(200).collect();
                format!("typed {shown:?}")
            }
            Step::Key { keys } => {
                let chord = Chord::parse(keys)?;
                self.hands()?.chord(&chord)?;
                format!("pressed {keys}")
            }
            Step::Wait { ms } => {
                self.wait(Duration::from_millis(u64::from((*ms).min(10_000))))?;
                format!("waited {} ms", (*ms).min(10_000))
            }
            Step::WaitFor {
                app,
                title,
                gone,
                seconds,
            } => self.wait_for(app, title, gone.unwrap_or(false), *seconds)?,
        })
    }

    fn wait(&self, total: Duration) -> Result<(), Failure> {
        let until = Instant::now() + total;
        while Instant::now() < until {
            self.watch.check().map_err(Failure::Stopped)?;
            std::thread::sleep(STOP_CHECK_INTERVAL.min(until - Instant::now()));
        }
        Ok(())
    }

    /// Text beyond the US keys goes through the virtual-keyboard protocol.
    fn wtype(&self, text: &str) -> Result<(), Failure> {
        let mut command = self.command(&self.bin.wtype);
        command.arg("-");
        self.exec(&self.bin.wtype, &mut command, Some(text.as_bytes()), None)
            .map(drop)
    }

    fn screenshot(&mut self, desktop: &Desktop, of: &ShotOf) -> Result<Shot, String> {
        let rect = match of {
            ShotOf::Screen { output: Some(name) } => desktop.output(name)?.rect,
            ShotOf::Screen { output: None } => desktop.focused_output()?.rect,
            ShotOf::All {} => desktop.bounds()?,
            ShotOf::Window { window } => {
                let window = desktop.window(*window)?;
                desktop
                    .window_rect(window)
                    .ok_or_else(|| format!("{} is not on screen; focus it first", window.label()))?
            }
            ShotOf::Zoom {
                x,
                y,
                width,
                height,
            } => {
                let (left, top) = self.desktop_point(*x, *y)?;
                let (right, bottom) = self.desktop_point(x + width, y + height)?;
                Rect {
                    x: left,
                    y: top,
                    w: right - left,
                    h: bottom - top,
                }
            }
        };
        if rect.w < 1.0 || rect.h < 1.0 {
            return Err("the screenshot area is empty".to_owned());
        }
        self.shots += 1;
        shot::capture(
            self.command(&self.bin.grim),
            rect,
            self.shots,
            std::path::Path::new(shot::SAVED),
        )
    }
}

impl Desk {
    /// Gives `window` a column of its own, focused.
    fn alone(&self, window: u64) -> Result<(), String> {
        let desktop = self.niri.desktop()?;
        let tiled = desktop.window(window)?;
        let (column, _) = tiled
            .column()
            .ok_or_else(|| format!("{} is not tiled", tiled.label()))?;
        let shared = desktop
            .windows
            .iter()
            .filter(|other| {
                other.workspace_id == tiled.workspace_id
                    && other.column().is_some_and(|(at, _)| at == column)
            })
            .count();
        self.niri
            .action(json!({ "FocusWindow": { "id": window } }))?;
        if shared > 1 {
            self.niri
                .action(json!({ "ConsumeOrExpelWindowRight": { "id": window } }))?;
        }
        Ok(())
    }

    /// Moves `window` into its own column right after `anchor`'s column,
    /// on `anchor`'s workspace.
    fn place_after(&self, anchor: u64, window: u64) -> Result<(), String> {
        let desktop = self.niri.desktop()?;
        let workspace = desktop.window(anchor)?.workspace_id;
        if desktop.window(window)?.workspace_id != workspace {
            let workspace = workspace.ok_or("the anchor window has no workspace")?;
            self.niri.action(json!({ "MoveWindowToWorkspace": {
                "window_id": window, "reference": { "Id": workspace }, "focus": false
            } }))?;
        }
        self.alone(window)?;
        let desktop = self.niri.desktop()?;
        let at = |id: u64| -> Result<usize, String> {
            let tiled = desktop.window(id)?;
            tiled
                .column()
                .map(|(column, _)| column)
                .ok_or_else(|| format!("{} is not tiled", tiled.label()))
        };
        let (anchor, column) = (at(anchor)?, at(window)?);
        let index = if column > anchor { anchor + 1 } else { anchor };
        self.niri
            .action(json!({ "MoveColumnToIndex": { "index": index } }))
    }

    /// Tells the owner once per ask that his desktop is being driven, and how to stop it.
    fn notify(&self) {
        let child = std::process::Command::new(&self.bin.notify_send)
            .envs(self.environment.iter().cloned())
            .args([
                "--app-name=odin-desk",
                "Desktop control is on",
                "Move the mouse or press Super+Shift+Escape to stop it.",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        if let Ok(mut child) = child {
            std::thread::spawn(move || child.wait());
        }
    }

    /// Installed desktop metadata supplies both friendly names and exact ids.
    fn desktop_entry(&self, app: &str) -> Result<Vec<String>, String> {
        let app = self.devices.resolve(devices::AliasKind::Apps, app)?;
        let app = app.strip_suffix(".desktop").unwrap_or(&app);
        let home = self.session_var("HOME").ok_or("session has no HOME")?;
        let data_home = self
            .session_var("XDG_DATA_HOME")
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{home}/.local/share"));
        let dirs = std::iter::once(data_home).chain(
            self.session_var("XDG_DATA_DIRS")
                .unwrap_or("/usr/local/share:/usr/share")
                .split(':')
                .filter(|dir| !dir.is_empty())
                .map(str::to_owned),
        );
        let mut entries = std::collections::BTreeMap::new();
        for dir in dirs {
            desktop_entries(&PathBuf::from(dir).join("applications"), "", &mut entries)?;
        }
        let mut matches = Vec::new();
        for (id, (path, text)) in &entries {
            if desktop_value(text, "Hidden") == Some("true") {
                continue;
            }
            if id.eq_ignore_ascii_case(app)
                || desktop_value(text, "Name").is_some_and(|name| name.eq_ignore_ascii_case(app))
            {
                matches.push((id, path, text));
            }
        }
        match matches.as_slice() {
            [(_, path, text)] => entry_command(text)
                .ok_or_else(|| format!("{} has no valid Exec line", path.display())),
            [] => Err(format!("no installed app has desktop id or Name {app:?}")),
            many => Err(format!(
                "app {app:?} is ambiguous: {}",
                many.iter()
                    .map(|(id, _, _)| id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        }
    }

    fn edit_save(
        &self,
        path: &std::path::Path,
        expected: &str,
        content: &str,
        encoding: &SaveEncoding,
    ) -> Result<String, String> {
        let expected_binary;
        let content_binary;
        let (expected, content) = match encoding {
            SaveEncoding::Utf8 => (expected.as_bytes(), content.as_bytes()),
            SaveEncoding::Base64 => {
                expected_binary = base64::engine::general_purpose::STANDARD
                    .decode(expected)
                    .map_err(|error| format!("save expected base64: {error}"))?;
                content_binary = base64::engine::general_purpose::STANDARD
                    .decode(content)
                    .map_err(|error| format!("save content base64: {error}"))?;
                (expected_binary.as_slice(), content_binary.as_slice())
            }
        };
        let path = path
            .canonicalize()
            .map_err(|error| format!("save {}: {error}", path.display()))?;
        let actual = std::fs::read(&path)
            .map_err(|error| format!("reading save {}: {error}", path.display()))?;
        if actual != expected {
            return Err(format!(
                "save {} changed; read its current content before editing",
                path.display()
            ));
        }
        let parent = path.parent().ok_or("save has no parent directory")?;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_nanos();
        let temporary = parent.join(format!(".odin-save-{}-{nonce}", std::process::id()));
        let result = (|| -> Result<(), String> {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(|error| format!("creating save replacement: {error}"))?;
            file.set_permissions(
                std::fs::metadata(&path)
                    .map_err(|error| error.to_string())?
                    .permissions(),
            )
            .map_err(|error| format!("preserving save permissions: {error}"))?;
            file.write_all(content)
                .and_then(|()| file.sync_all())
                .map_err(|error| format!("writing save: {error}"))?;
            self.watch.check()?;
            std::fs::rename(&temporary, &path)
                .map_err(|error| format!("replacing save: {error}"))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result?;
        Ok(format!(
            "updated save {} ({} bytes)",
            path.display(),
            content.len()
        ))
    }
}

/// The Exec line of the [Desktop Entry] group, without field codes.
fn entry_command(text: &str) -> Option<Vec<String>> {
    let mut in_entry = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_entry = line == "[Desktop Entry]";
        } else if let Some(exec) = line.strip_prefix("Exec=").filter(|_| in_entry) {
            let words: Vec<String> = shell_words::split(exec)
                .ok()?
                .into_iter()
                .filter(|word| !(word.len() == 2 && word.starts_with('%') && word != "%%"))
                .map(|word| word.replace("%%", "%"))
                .collect();
            return (!words.is_empty()).then_some(words);
        }
    }
    None
}

fn desktop_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let mut in_entry = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            in_entry = line == "[Desktop Entry]";
        } else if in_entry {
            if let Some((name, value)) = line.split_once('=') {
                if name == key {
                    return Some(value);
                }
            }
        }
    }
    None
}

fn desktop_entries(
    directory: &std::path::Path,
    prefix: &str,
    entries: &mut std::collections::BTreeMap<String, (PathBuf, String)>,
) -> Result<(), String> {
    let children = match std::fs::read_dir(directory) {
        Ok(children) => children,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "reading installed apps {}: {error}",
                directory.display()
            ))
        }
    };
    for child in children {
        let child = child.map_err(|error| format!("reading installed app entry: {error}"))?;
        let path = child.path();
        let name = child.file_name().to_string_lossy().into_owned();
        if child
            .file_type()
            .map_err(|error| error.to_string())?
            .is_dir()
        {
            desktop_entries(&path, &format!("{prefix}{name}-"), entries)?;
        } else if let Some(id) = name.strip_suffix(".desktop") {
            let id = format!("{prefix}{id}");
            if let std::collections::btree_map::Entry::Vacant(entry) = entries.entry(id) {
                let text = std::fs::read_to_string(&path)
                    .map_err(|error| format!("reading app {}: {error}", path.display()))?;
                entry.insert((path, text));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod fixture {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    use super::*;

    /// An executable `#!/bin/sh` script named `name` in `dir`.
    pub(crate) fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// A desk on a scratch session: every helper is the script of its name in
    /// `dir` (written by the test that needs it), niri listens at
    /// `dir/niri.sock`, and no mouse is watched.
    pub(crate) fn desk(dir: &Path) -> Desk {
        let helpers = [
            "grim",
            "wtype",
            "notifySend",
            "loginctl",
            "systemctl",
            "pactl",
            "wlCopy",
            "wlPaste",
            "weston",
            "dbusDaemon",
        ];
        let bin = serde_json::from_value(Value::Object(
            helpers
                .into_iter()
                .map(|name| (name.to_owned(), json!(dir.join(name))))
                .collect(),
        ))
        .unwrap();
        let text = |path: PathBuf| path.display().to_string();
        Desk {
            niri: Niri::new(dir.join("niri.sock")),
            bin,
            devices: DeviceMap::default(),
            environment: vec![
                ("PATH".to_owned(), std::env::var("PATH").unwrap_or_default()),
                ("HOME".to_owned(), text(dir.join("home"))),
                ("XDG_RUNTIME_DIR".to_owned(), text(dir.to_path_buf())),
                ("XDG_DATA_DIRS".to_owned(), text(dir.join("share"))),
            ],
            session: "1".to_owned(),
            watch: Watch::inert(),
            hands: None,
            ask: None,
            last_shot: None,
            shots: 0,
            previous_output: None,
            headless: None,
            pulse: crate::live::Signal::default(),
            audio: crate::live::Cached::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::fixture::{desk, script};
    use super::*;

    fn replies(desk: &mut Desk, private: &std::path::Path, requests: &[Value]) -> Vec<Value> {
        let input: String = requests
            .iter()
            .map(|request| format!("{request}\n"))
            .collect();
        let mut output = Vec::new();
        desk.serve_lines(private, Cursor::new(input), &mut output)
            .unwrap();
        String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn a_private_desktop_refuses_every_request_and_a_bad_line_is_an_error_reply() {
        let dir = tempfile::tempdir().unwrap();
        script(dir.path(), "loginctl", "echo no");
        let mut desk = desk(dir.path());
        let private = private_file(dir.path());
        let idle = json!({"ask": "a"});
        let answers = replies(&mut desk, &private, std::slice::from_ref(&idle));
        assert_eq!(answers[0]["ok"], true);
        let input = "not json\n";
        let mut output = Vec::new();
        desk.serve_lines(&private, Cursor::new(input), &mut output)
            .unwrap();
        let bad: Value = serde_json::from_slice(&output).unwrap();
        assert!(bad["error"]
            .as_str()
            .unwrap()
            .contains("unreadable request"));
        std::fs::write(&private, "kreate\n").unwrap();
        let refused = replies(&mut desk, &private, &[idle])[0].clone();
        assert_eq!(refused["ok"], false);
        assert!(refused["error"]
            .as_str()
            .unwrap()
            .contains("private (kreate)"));
    }

    #[test]
    fn a_locked_screen_refuses_the_request() {
        let dir = tempfile::tempdir().unwrap();
        script(dir.path(), "loginctl", "echo yes");
        let mut desk = desk(dir.path());
        let answer = &replies(
            &mut desk,
            &private_file(dir.path()),
            &[json!({"ask": "a", "steps": [{"do": "wait", "ms": 0}]})],
        )[0];
        assert_eq!(answer["ok"], false);
        assert!(answer["error"].as_str().unwrap().contains("locked"));
    }

    #[test]
    fn a_stopped_ask_runs_no_more_steps_until_a_new_ask_lifts_the_stop() {
        let dir = tempfile::tempdir().unwrap();
        script(dir.path(), "loginctl", "echo no");
        script(dir.path(), "notifySend", "true");
        script(dir.path(), "wtype", "cat >/dev/null");
        let mut desk = desk(dir.path());
        let step = |ask: &str| json!({"ask": ask, "steps": [{"do": "wait", "ms": 0}]});
        let typing = json!({"ask": "a", "steps": [{"do": "type", "text": "x"}]});
        let private = private_file(dir.path());
        // A wait alone does not arm the stop; typing does.
        assert_eq!(replies(&mut desk, &private, &[step("a")])[0]["ok"], true);
        assert!(!desk.watch.armed());
        assert_eq!(replies(&mut desk, &private, &[typing])[0]["ok"], true);
        desk.watch.stop(|| "the mouse moved".to_owned());
        let stopped = replies(&mut desk, &private, &[step("a")])[0].clone();
        assert_eq!(stopped["ok"], false);
        assert!(stopped["stopped"].as_str().unwrap().contains("mouse moved"));
        assert_eq!(replies(&mut desk, &private, &[step("b")])[0]["ok"], true);
    }

    #[test]
    fn a_save_replaces_a_file_only_while_it_still_holds_what_was_read() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let desk = desk(dir.path());
        let file = dir.path().join("save.json");
        std::fs::write(&file, "{\"level\":1}").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
        desk.edit_save(&file, "{\"level\":1}", "{\"level\":2}", &SaveEncoding::Utf8)
            .unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "{\"level\":2}");
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o640
        );

        let error = desk
            .edit_save(&file, "{\"level\":1}", "{\"level\":9}", &SaveEncoding::Utf8)
            .unwrap_err();
        assert!(error.contains("changed"), "{error}");
        let error = desk
            .edit_save(&file, "!!", "x", &SaveEncoding::Base64)
            .unwrap_err();
        assert!(error.contains("base64"), "{error}");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "{\"level\":2}");
        let names: Vec<_> = std::fs::read_dir(dir.path()).unwrap().flatten().collect();
        assert_eq!(
            names.len(),
            1,
            "no replacement file is left behind: {names:?}"
        );
    }

    #[test]
    fn launching_an_app_resolves_its_id_or_name_skips_hidden_entries_and_refuses_ties() {
        let dir = tempfile::tempdir().unwrap();
        let entry = |directory: &str, file: &str, text: &str| {
            let folder = dir.path().join(directory).join("applications");
            std::fs::create_dir_all(folder.join(file).parent().unwrap()).unwrap();
            std::fs::write(folder.join(file), text).unwrap();
        };
        entry(
            "share",
            "alpha.desktop",
            "[Desktop Entry]\nName=Alpha\nExec=alpha %U\n",
        );
        entry(
            "share",
            "beta.desktop",
            "[Desktop Entry]\nName=Beta\nHidden=true\nExec=beta\n",
        );
        entry(
            "share",
            "kde/twin-one.desktop",
            "[Desktop Entry]\nName=Twin\nExec=one\n",
        );
        entry(
            "share",
            "twin-two.desktop",
            "[Desktop Entry]\nName=Twin\nExec=two\n",
        );
        let mut desk = desk(dir.path());
        let share = |names: &[&str]| {
            names
                .iter()
                .map(|name| dir.path().join(name).display().to_string())
                .collect::<Vec<_>>()
                .join(":")
        };
        desk.environment.retain(|(key, _)| key != "XDG_DATA_DIRS");
        desk.environment
            .push(("XDG_DATA_DIRS".to_owned(), share(&["share", "later"])));
        entry(
            "later",
            "alpha.desktop",
            "[Desktop Entry]\nName=Alpha\nExec=shadowed\n",
        );
        assert_eq!(desk.desktop_entry("Alpha").unwrap(), ["alpha"]);
        assert_eq!(desk.desktop_entry("alpha.desktop").unwrap(), ["alpha"]);
        assert!(desk
            .desktop_entry("Beta")
            .unwrap_err()
            .contains("no installed app"));
        let tie = desk.desktop_entry("Twin").unwrap_err();
        assert!(
            tie.contains("ambiguous") && tie.contains("kde-twin-one"),
            "{tie}"
        );
    }
}
