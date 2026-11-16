//!
//! niri's IPC socket: one JSON request line and one reply line per
//! connection (the protocol `niri msg` speaks).

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use crate::live::{Cached, Signal};
use serde_json::{json, Value};

/// How long niri has to answer one request.
const NIRI_REPLY_TIMEOUT: Duration = Duration::from_secs(5);
/// Without an event, a settling wait re-reads the desktop this often.
const SETTLE_REREAD: Duration = Duration::from_millis(250);

/// A rectangle in niri's logical desktop coordinates.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Rect {
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
}

impl Rect {
    /// grim's `-g` geometry.
    pub(crate) fn grim(&self) -> String {
        format!(
            "{},{} {}x{}",
            self.x.round(),
            self.y.round(),
            self.w.round(),
            self.h.round()
        )
    }
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct Window {
    pub id: u64,
    pub title: Option<String>,
    pub app_id: Option<String>,
    pub workspace_id: Option<u64>,
    pub is_focused: bool,
    layout: WindowLayout,
}

#[derive(Clone, Debug, Deserialize)]
struct WindowLayout {
    pos_in_scrolling_layout: Option<(usize, usize)>,
    window_size: (i32, i32),
    tile_pos_in_workspace_view: Option<(f64, f64)>,
    window_offset_in_tile: (f64, f64),
}

impl Window {
    /// The 1-based tiled column and the number of the window in it.
    pub(crate) fn column(&self) -> Option<(usize, usize)> {
        self.layout.pos_in_scrolling_layout
    }

    /// "Player (player, window 12)".
    pub(crate) fn label(&self) -> String {
        format!(
            "{} ({}, window {})",
            self.title.as_deref().unwrap_or("untitled"),
            self.app_id.as_deref().unwrap_or("no app id"),
            self.id
        )
    }
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct Workspace {
    pub id: u64,
    pub idx: u8,
    pub name: Option<String>,
    pub output: Option<String>,
    pub is_active: bool,
    pub is_focused: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct Output {
    pub name: String,
    pub rect: Rect,
}

/// Everything on screen at one moment.
#[derive(Clone)]
pub(crate) struct Desktop {
    pub outputs: Vec<Output>,
    pub workspaces: Vec<Workspace>,
    pub windows: Vec<Window>,
}

impl Desktop {
    /// The bounding box of every output: the absolute pointer's range.
    pub(crate) fn bounds(&self) -> Result<Rect, String> {
        let mut outputs = self.outputs.iter().map(|output| output.rect);
        let first = outputs.next().ok_or("niri reports no enabled output")?;
        let (mut left, mut top) = (first.x, first.y);
        let (mut right, mut bottom) = (first.x + first.w, first.y + first.h);
        for rect in outputs {
            left = left.min(rect.x);
            top = top.min(rect.y);
            right = right.max(rect.x + rect.w);
            bottom = bottom.max(rect.y + rect.h);
        }
        Ok(Rect {
            x: left,
            y: top,
            w: right - left,
            h: bottom - top,
        })
    }

    pub(crate) fn output(&self, name: &str) -> Result<&Output, String> {
        self.outputs
            .iter()
            .find(|output| output.name == name)
            .ok_or_else(|| {
                let names: Vec<&str> = self
                    .outputs
                    .iter()
                    .map(|output| output.name.as_str())
                    .collect();
                format!("no output {name:?} (outputs: {})", names.join(", "))
            })
    }

    /// The output holding the focused workspace.
    pub(crate) fn focused_output(&self) -> Result<&Output, String> {
        let name = self
            .workspaces
            .iter()
            .find(|workspace| workspace.is_focused)
            .and_then(|workspace| workspace.output.as_deref())
            .ok_or("niri reports no focused workspace")?;
        self.output(name)
    }

    pub(crate) fn window(&self, id: u64) -> Result<&Window, String> {
        self.windows
            .iter()
            .find(|window| window.id == id)
            .ok_or_else(|| format!("there is no window {id} (it may have closed)"))
    }

    /// The one window `name` means: "focused", an exact app id, or an app id
    /// or title containing it (case ignored). Several matches prefer the
    /// focused one; otherwise the error lists them.
    pub(crate) fn window_named(&self, name: &str) -> Result<&Window, String> {
        let wanted = name.trim().to_lowercase();
        if wanted == "focused" {
            return self
                .windows
                .iter()
                .find(|window| window.is_focused)
                .ok_or_else(|| "no window is focused".to_owned());
        }
        let app = |window: &Window| window.app_id.as_deref().unwrap_or("").to_lowercase();
        let title = |window: &Window| window.title.as_deref().unwrap_or("").to_lowercase();
        let mut found: Vec<&Window> = self
            .windows
            .iter()
            .filter(|window| app(window) == wanted)
            .collect();
        if found.is_empty() {
            found = self
                .windows
                .iter()
                .filter(|window| app(window).contains(&wanted) || title(window).contains(&wanted))
                .collect();
        }
        match found.as_slice() {
            [one] => Ok(one),
            [] => Err(format!(
                "no window matches {name:?}; open: {}",
                self.windows
                    .iter()
                    .map(Window::label)
                    .collect::<Vec<_>>()
                    .join("; ")
            )),
            several => several
                .iter()
                .find(|window| window.is_focused)
                .copied()
                .ok_or_else(|| {
                    format!(
                        "{name:?} matches several windows; name one by id: {}",
                        several
                            .iter()
                            .map(|window| window.label())
                            .collect::<Vec<_>>()
                            .join("; ")
                    )
                }),
        }
    }

    /// Where a window is on the desktop, if it is on screen now.
    pub(crate) fn window_rect(&self, window: &Window) -> Option<Rect> {
        let workspace = self
            .workspaces
            .iter()
            .find(|workspace| Some(workspace.id) == window.workspace_id && workspace.is_active)?;
        let output = self.output(workspace.output.as_deref()?).ok()?;
        let (tile_x, tile_y) = window.layout.tile_pos_in_workspace_view?;
        let (offset_x, offset_y) = window.layout.window_offset_in_tile;
        let (width, height) = window.layout.window_size;
        Some(Rect {
            x: output.rect.x + tile_x + offset_x,
            y: output.rect.y + tile_y + offset_y,
            w: f64::from(width),
            h: f64::from(height),
        })
    }

    /// The model's view: outputs, workspaces with their windows.
    pub(crate) fn summary(&self) -> Value {
        let workspaces: Vec<Value> = self
            .workspaces
            .iter()
            .map(|workspace| {
                let windows: Vec<Value> = self
                    .windows
                    .iter()
                    .filter(|window| window.workspace_id == Some(workspace.id))
                    .map(|window| {
                        json!({
                            "window": window.id,
                            "title": window.title,
                            "app": window.app_id,
                            "focused": window.is_focused,
                            "onScreen": self.window_rect(window).is_some(),
                        })
                    })
                    .collect();
                json!({
                    "workspace": workspace.idx,
                    "name": workspace.name,
                    "output": workspace.output,
                    "shown": workspace.is_active,
                    "focused": workspace.is_focused,
                    "windows": windows,
                })
            })
            .collect();
        let outputs: Vec<Value> = self
            .outputs
            .iter()
            .map(|output| {
                json!({
                    "output": output.name,
                    "size": format!("{}x{}", output.rect.w, output.rect.h),
                    "at": format!("{},{}", output.rect.x, output.rect.y),
                })
            })
            .collect();
        json!({ "outputs": outputs, "workspaces": workspaces })
    }
}

pub(crate) struct Niri {
    socket: PathBuf,
    /// niri's event stream, once followed: the desktop read at one change
    /// count is reused until the next event.
    events: Signal,
    desktop: Cached<Desktop>,
}

impl Niri {
    pub(crate) fn new(socket: PathBuf) -> Self {
        Self {
            socket,
            events: Signal::default(),
            desktop: Cached::default(),
        }
    }

    /// Follows niri's event stream on its own connection; without it every
    /// read asks niri again.
    pub(crate) fn follow_events(&mut self) {
        let stream = UnixStream::connect(&self.socket).and_then(|mut stream| {
            writeln!(stream, "\"EventStream\"")?;
            Ok(stream)
        });
        match stream {
            Ok(stream) => self.events = Signal::from_lines("niri", BufReader::new(stream)),
            Err(error) => eprintln!("odin-desk: niri's event stream is unavailable: {error}"),
        }
    }

    /// niri's change signal (dead without the event stream).
    pub(crate) fn events(&self) -> &Signal {
        &self.events
    }

    /// Waits for `seen` (a desktop) to change into one `done` accepts, up
    /// to `timeout`; whether it did. Without the event stream it re-reads.
    pub(crate) fn settle(&self, timeout: Duration, done: impl Fn(&Desktop) -> bool) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let seen = self.events.version();
            if self.desktop().is_ok_and(|desktop| done(&desktop)) {
                return true;
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return false;
            }
            let left = (deadline - now).min(SETTLE_REREAD);
            match seen {
                Some(seen) => self.events.wait_past(seen, left),
                None => std::thread::sleep(left),
            }
        }
    }

    fn request(&self, request: &Value) -> Result<Value, String> {
        let failed =
            |error: std::io::Error| format!("niri's socket {}: {error}", self.socket.display());
        let mut stream = UnixStream::connect(&self.socket).map_err(failed)?;
        stream
            .set_read_timeout(Some(NIRI_REPLY_TIMEOUT))
            .map_err(failed)?;
        writeln!(stream, "{request}").map_err(failed)?;
        let mut line = String::new();
        BufReader::new(stream)
            .read_line(&mut line)
            .map_err(failed)?;
        let reply: Value = serde_json::from_str(&line)
            .map_err(|error| format!("niri sent an unreadable reply ({error}): {line:?}"))?;
        match (reply.get("Ok"), reply.get("Err")) {
            (Some(ok), _) => Ok(ok.clone()),
            (_, Some(error)) => Err(format!(
                "niri refused {request}: {}",
                error.as_str().unwrap_or("?")
            )),
            _ => Err(format!("niri sent neither Ok nor Err: {line:?}")),
        }
    }

    fn query<T: serde::de::DeserializeOwned>(&self, what: &str) -> Result<T, String> {
        let reply = self.request(&json!(what))?;
        let body = reply
            .get(what)
            .cloned()
            .ok_or_else(|| format!("niri answered {what} with {reply}"))?;
        serde_json::from_value(body)
            .map_err(|error| format!("niri's {what} did not parse: {error}"))
    }

    pub(crate) fn windows(&self) -> Result<Vec<Window>, String> {
        self.query("Windows")
    }

    pub(crate) fn action(&self, action: Value) -> Result<(), String> {
        self.desktop.invalidate();
        self.request(&json!({ "Action": action })).map(drop)
    }

    pub(crate) fn desktop(&self) -> Result<Desktop, String> {
        self.desktop.get(&self.events, || self.read_desktop())
    }

    fn read_desktop(&self) -> Result<Desktop, String> {
        #[derive(Deserialize)]
        struct Logical {
            x: i32,
            y: i32,
            width: u32,
            height: u32,
        }
        #[derive(Deserialize)]
        struct RawOutput {
            name: String,
            logical: Option<Logical>,
        }
        let raw: std::collections::BTreeMap<String, RawOutput> = self.query("Outputs")?;
        let outputs = raw
            .into_values()
            .filter_map(|output| {
                let logical = output.logical?;
                Some(Output {
                    name: output.name,
                    rect: Rect {
                        x: f64::from(logical.x),
                        y: f64::from(logical.y),
                        w: f64::from(logical.width),
                        h: f64::from(logical.height),
                    },
                })
            })
            .collect();
        let mut workspaces: Vec<Workspace> = self.query("Workspaces")?;
        workspaces.sort_by(|a, b| (&a.output, a.idx).cmp(&(&b.output, b.idx)));
        Ok(Desktop {
            outputs,
            workspaces,
            windows: self.windows()?,
        })
    }
}

/// niri's `SizeChange` from "50%", "+10%", "-5%", "1200" or "+100".
pub(crate) fn size_change(text: &str) -> Result<Value, String> {
    let bad = || format!("{text:?} is not a size like 50%, +10%, 1200 or -100");
    let relative = text.starts_with(['+', '-']);
    Ok(match text.strip_suffix('%') {
        Some(percent) => {
            let value: f64 = percent
                .parse()
                .map_err(|error| format!("{}: {error}", bad()))?;
            if relative {
                json!({ "AdjustProportion": value })
            } else {
                json!({ "SetProportion": value })
            }
        }
        None => {
            let value: i32 = text
                .parse()
                .map_err(|error| format!("{}: {error}", bad()))?;
            if relative {
                json!({ "AdjustFixed": value })
            } else {
                json!({ "SetFixed": value })
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake niri answering one request per connection with `reply`; the
    /// requests it received come back through the handle.
    fn fake_niri(
        socket: &std::path::Path,
        replies: Vec<Value>,
    ) -> std::thread::JoinHandle<Vec<Value>> {
        let listener = std::os::unix::net::UnixListener::bind(socket).unwrap();
        std::thread::spawn(move || {
            let mut requests = Vec::new();
            for reply in replies {
                let (mut stream, _) = listener.accept().unwrap();
                let mut line = String::new();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut line)
                    .unwrap();
                requests.push(serde_json::from_str(&line).unwrap());
                writeln!(stream, "{reply}").unwrap();
            }
            requests
        })
    }

    #[test]
    fn the_desktop_is_read_from_niris_three_queries_and_an_action_reaches_its_socket() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("niri.sock");
        let fake = fake_niri(
            &socket,
            vec![
                json!({"Ok": {"Outputs": {"DP-3": {"name": "DP-3",
                    "logical": {"x": 0, "y": 0, "width": 2560, "height": 1440}},
                    "off": {"name": "HDMI-A-2", "logical": null}}}}),
                json!({"Ok": {"Workspaces": [
                    {"id": 1, "idx": 1, "name": null, "output": "DP-3",
                     "is_active": true, "is_focused": true}]}}),
                json!({"Ok": {"Windows": [
                    {"id": 3, "title": "zellij", "app_id": "konsole", "workspace_id": 1,
                     "is_focused": true,
                     "layout": {"pos_in_scrolling_layout": [1, 1], "window_size": [996, 1396],
                                "tile_pos_in_workspace_view": [16.0, 20.0],
                                "window_offset_in_tile": [2.0, 2.0]}}]}}),
                json!({"Ok": "Handled"}),
            ],
        );
        let niri = Niri::new(socket);
        let desktop = niri.desktop().unwrap();
        assert_eq!(
            desktop.outputs.len(),
            1,
            "an output without a logical size is off"
        );
        assert_eq!(
            desktop.window(3).unwrap().app_id.as_deref(),
            Some("konsole")
        );
        niri.action(json!({"FocusWindow": {"id": 3}})).unwrap();
        let requests = fake.join().unwrap();
        assert_eq!(requests[0], json!("Outputs"));
        assert_eq!(requests[3], json!({"Action": {"FocusWindow": {"id": 3}}}));
    }

    #[test]
    fn a_window_is_found_by_app_or_title_and_ambiguity_prefers_the_focused_one() {
        let window = |id: u64, title: &str, app: &str, focused: bool| -> Window {
            serde_json::from_value(json!({"id": id, "title": title, "app_id": app,
                "workspace_id": 1, "is_focused": focused,
                "layout": {"pos_in_scrolling_layout": null, "window_size": [800, 600],
                           "tile_pos_in_workspace_view": null, "window_offset_in_tile": [0.0, 0.0]}}))
            .unwrap()
        };
        let desktop = Desktop {
            outputs: Vec::new(),
            workspaces: Vec::new(),
            windows: vec![
                window(4, "#general | Discord", "vesktop", false),
                window(7, "Palworld", "steam_app_1623730", false),
                window(9, "zellij", "konsole", true),
                window(11, "htop", "konsole", false),
            ],
        };
        let id = |name: &str| desktop.window_named(name).map(|window| window.id);
        assert_eq!(id("Vesktop"), Ok(4), "exact app id, case ignored");
        assert_eq!(id("discord"), Ok(4), "a word of the title");
        assert_eq!(id("palworld"), Ok(7));
        assert_eq!(id("focused"), Ok(9));
        assert_eq!(id("konsole"), Ok(9), "several matches: the focused one");
        let missing = desktop.window_named("firefox").unwrap_err();
        assert!(missing.contains("Palworld"), "{missing}");
    }

    #[test]
    fn a_refusal_from_niri_names_the_request_and_the_reason() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("niri.sock");
        let fake = fake_niri(&socket, vec![json!({"Err": "no such window"})]);
        let error = Niri::new(socket)
            .action(json!({"CloseWindow": {"id": 9}}))
            .unwrap_err();
        fake.join().unwrap();
        assert!(
            error.contains("CloseWindow") && error.contains("no such window"),
            "{error}"
        );
    }
}
