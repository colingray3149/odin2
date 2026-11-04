//!
//! Sinmara's structural desktop controls. All UI discovery and interaction uses
//! AT-SPI, never coordinates, application-specific chat APIs, or synthetic keys.
//! Applications must actually publish an accessibility tree (including an enabled
//! accessibility bridge for Chromium/egui); missing bridges are explicit errors.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zbus::blocking::{connection::Builder, Connection, Proxy};
use zbus::zvariant::OwnedObjectPath;

use crate::{Desk, Failure};

const ACCESSIBLE: &str = "org.a11y.atspi.Accessible";
const ACTION: &str = "org.a11y.atspi.Action";
const TEXT: &str = "org.a11y.atspi.Text";
const EDITABLE: &str = "org.a11y.atspi.EditableText";
const ROOT: &str = "/org/a11y/atspi/accessible/root";
const MAX_NODES: usize = 4096;
const MAX_DEPTH: usize = 64;
const MAX_TEXT: usize = 16384;
const MAX_CLIPBOARD: usize = 1024 * 1024;
/// The text one outline may return in all.
const MAX_OUTLINE_TEXT: usize = 1024 * 1024;
const DEFAULT_NODES: u32 = 1024;
const DEFAULT_DEPTH: u32 = 32;
const DEFAULT_TEXT: u32 = 4096;
const SCAN_TIME: Duration = Duration::from_secs(20);
const ACCESSIBILITY_METHOD_TIMEOUT: Duration = Duration::from_secs(2);
const STRUCTURE_AWAIT_TIMEOUT: Duration = Duration::from_secs(5);
const STRUCTURE_AWAIT_POLL_INTERVAL: Duration = Duration::from_millis(100);

type Object = (String, OwnedObjectPath);

/// All strings match exactly, including case. `path` is a child-index path from
/// the application's accessible root, as returned by outline. `bus` distinguishes
/// instances with identical names. A path is checked against the other fields;
/// it is never treated as authority to act on a differently named replacement.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Selector {
    app: String,
    window: String,
    name: String,
    role: Option<String>,
    path: Option<Vec<u32>>,
    bus: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Limits {
    max_nodes: Option<u32>,
    max_depth: Option<u32>,
    text_chars: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PressSpec {
    target: Selector,
    /// AT-SPI's machine-readable action name, not the localized label. Omission
    /// is accepted only when the object exposes exactly one action.
    action: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(
    tag = "op",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum StructureAction {
    Outline {
        app: Option<String>,
        window: Option<String>,
        limits: Option<Limits>,
    },
    Press {
        target: Selector,
        action: Option<String>,
    },
    Fill {
        target: Selector,
        text: String,
    },
    Paste {
        target: Selector,
        text: Option<String>,
        position: Option<i32>,
    },
    /// Select the conversation's accessible subtree, not an application API.
    ReadChat {
        target: Selector,
        limits: Option<Limits>,
    },
    PostChat {
        editor: Selector,
        text: String,
        send: PressSpec,
    },
    /// `prepare` can expose a chooser's location entry through accessible
    /// buttons. `pathField` must accept an absolute filename. `confirm` submits
    /// that chooser; it does not pretend to verify network upload completion.
    UploadFile {
        file: PathBuf,
        open: PressSpec,
        #[serde(default)]
        prepare: Vec<PressSpec>,
        path_field: Selector,
        confirm: PressSpec,
    },
    /// Read the selected notification center/alert subtree. No private app API.
    Notifications {
        target: Selector,
        limits: Option<Limits>,
    },
    ClipboardRead {},
    ClipboardWrite {
        text: String,
    },
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Node {
    app: String,
    window: String,
    bus: String,
    object_path: String,
    path: Vec<u32>,
    name: String,
    role: String,
    role_id: u32,
    interfaces: Vec<String>,
    child_count: i32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ActionInfo {
    index: i32,
    name: String,
    description: String,
    key_binding: String,
}

#[derive(Clone, Copy)]
struct Budget {
    nodes: usize,
    depth: usize,
    text: usize,
}

struct Tree {
    nodes: Vec<Node>,
    incomplete: Vec<String>,
}

fn error(message: impl Into<String>) -> Failure {
    Failure::Error(message.into())
}

fn dbus(cause: zbus::Error) -> Failure {
    error(format!("AT-SPI D-Bus: {cause}"))
}

fn proxy<'a>(
    bus: &Connection,
    node: &'a Node,
    interface: &'static str,
) -> Result<Proxy<'a>, Failure> {
    Proxy::new(bus, node.bus.as_str(), node.object_path.as_str(), interface).map_err(dbus)
}

fn budget(limits: Option<&Limits>) -> Result<Budget, Failure> {
    let value = Budget {
        nodes: limits.and_then(|v| v.max_nodes).unwrap_or(DEFAULT_NODES) as usize,
        depth: limits.and_then(|v| v.max_depth).unwrap_or(DEFAULT_DEPTH) as usize,
        text: limits.and_then(|v| v.text_chars).unwrap_or(DEFAULT_TEXT) as usize,
    };
    if value.nodes == 0
        || value.nodes > MAX_NODES
        || value.depth == 0
        || value.depth > MAX_DEPTH
        || value.text == 0
        || value.text > MAX_TEXT
    {
        return Err(error(format!("limits require maxNodes 1..={MAX_NODES}, maxDepth 1..={MAX_DEPTH}, textChars 1..={MAX_TEXT}")));
    }
    Ok(value)
}

fn json_string(value: Value) -> Result<String, Failure> {
    serde_json::to_string(&value)
        .map_err(|cause| error(format!("accessibility result JSON: {cause}")))
}

impl Desk {
    pub(super) fn structure(&mut self, action: &StructureAction) -> Result<String, Failure> {
        self.watch.check().map_err(Failure::Stopped)?;
        match action {
            StructureAction::ClipboardRead {} => {
                return json_string(json!({"text": self.structure_clipboard_read()?}));
            }
            StructureAction::ClipboardWrite { text } => {
                self.structure_clipboard_write(text)?;
                return json_string(json!({"clipboardOwned": true, "bytes": text.len()}));
            }
            _ => {}
        }
        let bus = self.structure_bus()?;
        let result = match action {
            StructureAction::Outline {
                app,
                window,
                limits,
            } => {
                let window = window
                    .as_deref()
                    .map(|value| {
                        self.devices
                            .resolve(crate::devices::AliasKind::Chats, value)
                    })
                    .transpose()?;
                if app.as_ref().is_some_and(|v| v.trim().is_empty()) {
                    return Err(error(
                        "outline app must not be empty; omit it to list all applications",
                    ));
                }
                let limits = budget(limits.as_ref())?;
                let roots = self.structure_apps(&bus, app.as_deref(), None)?;
                if roots.is_empty() {
                    return Err(error("no accessible applications match; the app must expose an enabled AT-SPI bridge"));
                }
                let tree = self.structure_tree(&bus, roots, limits)?;
                let nodes: Vec<Node> = tree
                    .nodes
                    .into_iter()
                    .filter(|node| window.as_ref().is_none_or(|value| &node.window == value))
                    .collect();
                if nodes.is_empty() {
                    return Err(error("no accessible nodes match the requested window"));
                }
                self.structure_outline(&bus, nodes, tree.incomplete, limits.text)?
            }
            StructureAction::Press { target, action } => {
                let node = self.structure_select(&bus, target)?;
                self.structure_press(&bus, &node, action.as_deref())?
            }
            StructureAction::Fill { target, text } => {
                let node = self.structure_select(&bus, target)?;
                self.structure_fill(&bus, &node, text)?;
                json!({"filled": node, "characters": text.chars().count()})
            }
            StructureAction::Paste {
                target,
                text,
                position,
            } => {
                let node = self.structure_select(&bus, target)?;
                require_interface(&node, EDITABLE)?;
                require_interface(&node, TEXT)?;
                let text_proxy = proxy(&bus, &node, TEXT)?;
                let count: i32 = text_proxy.get_property("CharacterCount").map_err(dbus)?;
                let position = match position {
                    Some(value) => *value,
                    None => text_proxy
                        .get_property::<i32>("CaretOffset")
                        .map_err(dbus)?,
                };
                if position < 0 || position > count {
                    return Err(error(format!(
                        "paste position {position} outside character range 0..={count}"
                    )));
                }
                if let Some(text) = text {
                    self.structure_clipboard_write(text)?;
                }
                self.watch.check().map_err(Failure::Stopped)?;
                let ok: bool = proxy(&bus, &node, EDITABLE)?
                    .call("PasteText", &(position,))
                    .map_err(dbus)?;
                accepted(ok, "EditableText.PasteText")?;
                json!({"pasted": node, "position": position})
            }
            StructureAction::ReadChat { target, limits }
            | StructureAction::Notifications { target, limits } => {
                let limits = budget(limits.as_ref())?;
                let node = self.structure_select(&bus, target)?;
                let tree = self.structure_tree(&bus, vec![node], limits)?;
                self.structure_outline(&bus, tree.nodes, tree.incomplete, limits.text)?
            }
            StructureAction::PostChat { editor, text, send } => {
                // Resolve both before changing the editor. Each is checked again
                // immediately before its mutation, so a changed tree cannot cause
                // a stale child-index path to invoke a replacement widget.
                self.structure_select(&bus, &send.target)?;
                let node = self.structure_select(&bus, editor)?;
                self.structure_fill(&bus, &node, text)?;
                let send_node = self.structure_select(&bus, &send.target)?;
                let invoked = self.structure_press(&bus, &send_node, send.action.as_deref())?;
                json!({"editorFilled": node, "send": invoked, "deliveryVerified": false})
            }
            StructureAction::UploadFile {
                file,
                open,
                prepare,
                path_field,
                confirm,
            } => {
                if !file.is_absolute() {
                    return Err(error("uploadFile requires an absolute file path"));
                }
                let metadata = std::fs::metadata(file)
                    .map_err(|cause| error(format!("upload file {}: {cause}", file.display())))?;
                if !metadata.is_file() {
                    return Err(error("uploadFile path is not a regular file"));
                }
                let filename = file
                    .to_str()
                    .ok_or_else(|| error("uploadFile path is not UTF-8"))?;
                if prepare.len() > 16 {
                    return Err(error(
                        "uploadFile allows at most 16 chooser preparation actions",
                    ));
                }
                let node = self.structure_select(&bus, &open.target)?;
                self.structure_press(&bus, &node, open.action.as_deref())?;
                for step in prepare {
                    let node = self.structure_await(&bus, &step.target)?;
                    self.structure_press(&bus, &node, step.action.as_deref())?;
                }
                let field = self.structure_await(&bus, path_field)?;
                self.structure_fill(&bus, &field, filename)?;
                let button = self.structure_await(&bus, &confirm.target)?;
                let invoked = self.structure_press(&bus, &button, confirm.action.as_deref())?;
                json!({"file": filename, "chooserSubmitted": invoked, "uploadCompletionVerified": false})
            }
            StructureAction::ClipboardRead {} | StructureAction::ClipboardWrite { .. } => {
                unreachable!()
            }
        };
        self.watch.check().map_err(Failure::Stopped)?;
        json_string(result)
    }

    fn structure_bus(&self) -> Result<Connection, Failure> {
        let address = self
            .session_var("DBUS_SESSION_BUS_ADDRESS")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| error("graphical session has no DBUS_SESSION_BUS_ADDRESS"))?;
        let session = Builder::address(address)
            .map_err(dbus)?
            .method_timeout(ACCESSIBILITY_METHOD_TIMEOUT)
            .build()
            .map_err(dbus)?;
        self.watch.check().map_err(Failure::Stopped)?;
        let accessibility =
            Proxy::new(&session, "org.a11y.Bus", "/org/a11y/bus", "org.a11y.Bus").map_err(dbus)?;
        let address: String = accessibility.call("GetAddress", &()).map_err(dbus)?;
        if address.is_empty() {
            return Err(error(
                "org.a11y.Bus.GetAddress returned an empty accessibility bus address",
            ));
        }
        self.watch.check().map_err(Failure::Stopped)?;
        Builder::address(address.as_str())
            .map_err(dbus)?
            .method_timeout(ACCESSIBILITY_METHOD_TIMEOUT)
            .build()
            .map_err(dbus)
    }

    fn structure_tick(&self, deadline: Instant) -> Result<(), Failure> {
        self.watch.check().map_err(Failure::Stopped)?;
        if Instant::now() >= deadline {
            return Err(error(format!("AT-SPI traversal exceeded its {}-second time bound; narrow the app or use a node path", SCAN_TIME.as_secs())));
        }
        Ok(())
    }

    fn structure_node(
        &self,
        bus: &Connection,
        object: Object,
        app: &str,
        window: &str,
        path: Vec<u32>,
    ) -> Result<Node, Failure> {
        self.watch.check().map_err(Failure::Stopped)?;
        if object.0.is_empty() || object.1.as_str() == "/org/a11y/atspi/null" {
            return Err(error("AT-SPI returned a null accessible object"));
        }
        let mut node = Node {
            app: app.to_owned(),
            window: window.to_owned(),
            bus: object.0,
            object_path: object.1.to_string(),
            path,
            name: String::new(),
            role: String::new(),
            role_id: 0,
            interfaces: Vec::new(),
            child_count: 0,
        };
        let accessible = proxy(bus, &node, ACCESSIBLE)?;
        let name: String = accessible.get_property("Name").map_err(dbus)?;
        let role: String = accessible.call("GetRoleName", &()).map_err(dbus)?;
        let role_id: u32 = accessible.call("GetRole", &()).map_err(dbus)?;
        let interfaces: Vec<String> = accessible.call("GetInterfaces", &()).map_err(dbus)?;
        let child_count: i32 = accessible.get_property("ChildCount").map_err(dbus)?;
        drop(accessible);
        if child_count < 0 {
            return Err(error("AT-SPI returned a negative ChildCount"));
        }
        node.name = name;
        node.role = role;
        node.role_id = role_id;
        node.interfaces = interfaces;
        node.child_count = child_count;
        if node.path.is_empty() {
            node.app.clone_from(&node.name);
        }
        if node.path.len() == 1 || matches!(role_id, 16 | 19 | 23 | 69) {
            node.window.clone_from(&node.name);
        }
        Ok(node)
    }

    fn structure_apps(
        &self,
        bus: &Connection,
        app: Option<&str>,
        bus_name: Option<&str>,
    ) -> Result<Vec<Node>, Failure> {
        let deadline = Instant::now() + SCAN_TIME;
        let registry =
            Proxy::new(bus, "org.a11y.atspi.Registry", ROOT, ACCESSIBLE).map_err(dbus)?;
        let count: i32 = registry.get_property("ChildCount").map_err(dbus)?;
        if !(0..=256).contains(&count) {
            return Err(error(
                "accessibility registry child count outside bound 0..=256",
            ));
        }
        let mut roots = Vec::new();
        for index in 0..count {
            self.structure_tick(deadline)?;
            let object: Object = registry.call("GetChildAtIndex", &(index,)).map_err(dbus)?;
            if bus_name.is_some_and(|value| value != object.0) {
                continue;
            }
            // Query only the name before filtering, so an unrelated app's broken
            // optional interfaces cannot prevent an explicitly scoped selection.
            let accessible =
                Proxy::new(bus, object.0.as_str(), object.1.as_str(), ACCESSIBLE).map_err(dbus)?;
            let name: String = accessible.get_property("Name").map_err(dbus)?;
            drop(accessible);
            if app.is_some_and(|value| value != name) {
                continue;
            }
            roots.push(self.structure_node(bus, object, &name, "", Vec::new())?);
        }
        Ok(roots)
    }

    fn structure_tree(
        &self,
        bus: &Connection,
        roots: Vec<Node>,
        limits: Budget,
    ) -> Result<Tree, Failure> {
        let deadline = Instant::now() + SCAN_TIME;
        let mut queue: VecDeque<(Node, usize)> = roots.into_iter().map(|node| (node, 0)).collect();
        let mut seen = HashSet::new();
        let mut result = Tree {
            nodes: Vec::new(),
            incomplete: Vec::new(),
        };
        while let Some((node, depth)) = queue.pop_front() {
            self.structure_tick(deadline)?;
            if result.nodes.len() >= limits.nodes {
                result
                    .incomplete
                    .push(format!("maxNodes {} reached", limits.nodes));
                break;
            }
            if !seen.insert((node.bus.clone(), node.object_path.clone())) {
                result.incomplete.push(format!(
                    "repeated/cyclic object {} {}",
                    node.bus, node.object_path
                ));
                continue;
            }
            if node.child_count > 0 && depth >= limits.depth {
                result.incomplete.push(format!(
                    "maxDepth {} reached at {} {}",
                    limits.depth, node.bus, node.object_path
                ));
            } else {
                let available = limits
                    .nodes
                    .saturating_sub(result.nodes.len() + queue.len() + 1);
                let count = (node.child_count as usize).min(available);
                if count < node.child_count as usize {
                    result.incomplete.push(format!(
                        "maxNodes {} prevents enumerating all children at {} {}",
                        limits.nodes, node.bus, node.object_path
                    ));
                }
                let accessible = proxy(bus, &node, ACCESSIBLE)?;
                for index in 0..count {
                    self.structure_tick(deadline)?;
                    let object: Object = accessible
                        .call("GetChildAtIndex", &(index as i32,))
                        .map_err(dbus)?;
                    let mut path = node.path.clone();
                    path.push(index as u32);
                    let child = self.structure_node(bus, object, &node.app, &node.window, path)?;
                    queue.push_back((child, depth + 1));
                }
            }
            result.nodes.push(node);
        }
        Ok(result)
    }

    fn structure_select(&self, bus: &Connection, selector: &Selector) -> Result<Node, Failure> {
        self.structure_find(bus, selector)?.ok_or_else(|| error(format!(
            "no accessible node matches app {:?}, window {:?}, name {:?}, role {:?}, path {:?}; outline the current tree",
            selector.app, selector.window, selector.name, selector.role, selector.path)))
    }

    fn structure_find(
        &self,
        bus: &Connection,
        selector: &Selector,
    ) -> Result<Option<Node>, Failure> {
        let window = self
            .devices
            .resolve(crate::devices::AliasKind::Chats, &selector.window)?;
        if selector.app.trim().is_empty() {
            return Err(error("empty accessibility selector: app must be nonempty"));
        }
        if selector
            .role
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(error(
                "selector role must not be empty; omit it if not needed",
            ));
        }
        let roots = self.structure_apps(bus, Some(&selector.app), selector.bus.as_deref())?;
        let candidates = if let Some(path) = &selector.path {
            if path.len() > MAX_DEPTH {
                return Err(error(format!(
                    "selector path exceeds {MAX_DEPTH} child indices"
                )));
            }
            let deadline = Instant::now() + SCAN_TIME;
            let mut candidates = Vec::new();
            for mut node in roots {
                let mut exists = true;
                for index in path {
                    self.structure_tick(deadline)?;
                    if *index >= node.child_count as u32 {
                        exists = false;
                        break;
                    }
                    let object: Object = proxy(bus, &node, ACCESSIBLE)?
                        .call("GetChildAtIndex", &(*index as i32,))
                        .map_err(dbus)?;
                    let mut path = node.path.clone();
                    path.push(*index);
                    node = self.structure_node(bus, object, &node.app, &node.window, path)?;
                }
                if exists {
                    candidates.push(node);
                }
            }
            candidates
        } else {
            let tree = self.structure_tree(
                bus,
                roots,
                Budget {
                    nodes: MAX_NODES,
                    depth: MAX_DEPTH,
                    text: 0,
                },
            )?;
            if !tree.incomplete.is_empty() {
                return Err(error(format!("cannot prove selector uniqueness in an incomplete tree: {}; use an outline path", tree.incomplete.join("; "))));
            }
            tree.nodes
        };
        let mut matching = candidates.into_iter().filter(|node| {
            node.app == selector.app
                && node.window == window
                && node.name == selector.name
                && selector.role.as_ref().is_none_or(|role| &node.role == role)
        });
        let first = matching.next();
        if let Some(second) = matching.next() {
            return Err(error(format!("multiple accessible nodes match; add bus/path/role from outline (including {} {:?})", second.bus, second.path)));
        }
        Ok(first)
    }

    fn structure_await(&self, bus: &Connection, selector: &Selector) -> Result<Node, Failure> {
        let until = Instant::now() + STRUCTURE_AWAIT_TIMEOUT;
        loop {
            self.watch.check().map_err(Failure::Stopped)?;
            if let Some(node) = self.structure_find(bus, selector)? {
                return Ok(node);
            }
            if Instant::now() >= until {
                return Err(error(format!("file chooser control did not appear within {} seconds: app {:?}, window {:?}, name {:?}", STRUCTURE_AWAIT_TIMEOUT.as_secs(), selector.app, selector.window, selector.name)));
            }
            self.wait(STRUCTURE_AWAIT_POLL_INTERVAL)?;
        }
    }

    fn structure_actions(
        &self,
        bus: &Connection,
        node: &Node,
        deadline: Instant,
    ) -> Result<Vec<ActionInfo>, Failure> {
        require_interface(node, ACTION)?;
        let action = proxy(bus, node, ACTION)?;
        let count: i32 = action.get_property("NActions").map_err(dbus)?;
        if !(0..=64).contains(&count) {
            return Err(error("AT-SPI action count outside bound 0..=64"));
        }
        let mut actions = Vec::with_capacity(count as usize);
        for index in 0..count {
            self.structure_tick(deadline)?;
            actions.push(ActionInfo {
                index,
                name: action.call("GetName", &(index,)).map_err(dbus)?,
                description: action.call("GetDescription", &(index,)).map_err(dbus)?,
                key_binding: action.call("GetKeyBinding", &(index,)).map_err(dbus)?,
            });
        }
        Ok(actions)
    }

    fn structure_press(
        &self,
        bus: &Connection,
        node: &Node,
        action_name: Option<&str>,
    ) -> Result<Value, Failure> {
        require_interface(node, ACTION)?;
        let action = proxy(bus, node, ACTION)?;
        let count: i32 = action.get_property("NActions").map_err(dbus)?;
        if !(0..=64).contains(&count) {
            return Err(error("AT-SPI action count outside bound 0..=64"));
        }
        if action_name.is_none() && count != 1 {
            return Err(error(format!(
                "press without an action name requires exactly one action, found {count}"
            )));
        }
        let deadline = Instant::now() + SCAN_TIME;
        let mut chosen = None;
        for index in 0..count {
            self.structure_tick(deadline)?;
            let name: String = action.call("GetName", &(index,)).map_err(dbus)?;
            if action_name.is_none_or(|value| value == name) {
                if chosen.is_some() {
                    return Err(error("multiple actions have the requested name"));
                }
                chosen = Some((index, name));
            }
        }
        let (index, name) = chosen.ok_or_else(|| {
            error("no action has the requested name; choose an exact action name from outline")
        })?;
        self.watch.check().map_err(Failure::Stopped)?;
        let ok: bool = action.call("DoAction", &(index,)).map_err(dbus)?;
        accepted(ok, "Action.DoAction")?;
        Ok(json!({"invoked": node, "action": name, "actionIndex": index}))
    }

    fn structure_fill(&self, bus: &Connection, node: &Node, text: &str) -> Result<(), Failure> {
        require_interface(node, EDITABLE)?;
        if text.len() > MAX_CLIPBOARD {
            return Err(error(format!("fill text exceeds {MAX_CLIPBOARD} bytes")));
        }
        self.watch.check().map_err(Failure::Stopped)?;
        let ok: bool = proxy(bus, node, EDITABLE)?
            .call("SetTextContents", &(text,))
            .map_err(dbus)?;
        accepted(ok, "EditableText.SetTextContents")
    }

    fn structure_outline(
        &self,
        bus: &Connection,
        nodes: Vec<Node>,
        incomplete: Vec<String>,
        text_chars: usize,
    ) -> Result<Value, Failure> {
        let deadline = Instant::now() + SCAN_TIME;
        let mut output = Vec::with_capacity(nodes.len());
        let mut remaining_text = MAX_OUTLINE_TEXT;
        for node in nodes {
            self.structure_tick(deadline)?;
            let accessible = proxy(bus, &node, ACCESSIBLE)?;
            let description: String = accessible.get_property("Description").map_err(dbus)?;
            let attributes: HashMap<String, String> =
                accessible.call("GetAttributes", &()).map_err(dbus)?;
            let states: Vec<u32> = accessible.call("GetState", &()).map_err(dbus)?;
            let mut item = json!({"node": node, "description": description, "attributes": attributes, "stateWords": states});
            if node.interfaces.iter().any(|value| value == ACTION) {
                item["actions"] = json!(self.structure_actions(bus, &node, deadline)?);
            }
            if node.interfaces.iter().any(|value| value == TEXT) {
                let text = proxy(bus, &node, TEXT)?;
                let count: i32 = text.get_property("CharacterCount").map_err(dbus)?;
                if count < 0 {
                    return Err(error("AT-SPI returned a negative CharacterCount"));
                }
                let end = (count as usize).min(text_chars).min(remaining_text);
                let value: String = if end == 0 {
                    String::new()
                } else {
                    text.call("GetText", &(0_i32, end as i32)).map_err(dbus)?
                };
                remaining_text = remaining_text.saturating_sub(value.chars().count());
                item["text"] = json!({"value": value, "start": 0, "end": end, "characterCount": count, "truncated": end < count as usize});
            }
            output.push(item);
        }
        Ok(
            json!({"mechanism": "AT-SPI", "complete": incomplete.is_empty(), "incomplete": incomplete, "nodes": output,
            "selection": "Exact app/window/name, optional role/bus/path; path indices start at the application root. Text truncation is reported per node. Only exposed accessibility content is readable."}),
        )
    }

    fn structure_clipboard_write(&self, text: &str) -> Result<(), Failure> {
        if text.len() > MAX_CLIPBOARD {
            return Err(error(format!(
                "clipboard text exceeds {} bytes",
                MAX_CLIPBOARD
            )));
        }
        self.watch.check().map_err(Failure::Stopped)?;
        // wl-copy forks after obtaining ownership. Its background owner must keep
        // running to serve subsequent EditableText.PasteText requests. Do not use
        // --paste-once: clipboard managers may read before the target application.
        let result = self.checked_input(
            &self.bin.wl_copy,
            &["--type", "text/plain;charset=utf-8"],
            text.as_bytes(),
        );
        self.watch.check().map_err(Failure::Stopped)?;
        result.map(|_| ()).map_err(error)
    }

    fn structure_clipboard_read(&self) -> Result<String, Failure> {
        self.watch.check().map_err(Failure::Stopped)?;
        let result = self.checked(&self.bin.wl_paste, &["--no-newline", "--type", "text"]);
        self.watch.check().map_err(Failure::Stopped)?;
        let text = result.map_err(error)?;
        if text.len() > MAX_CLIPBOARD {
            return Err(error(format!(
                "clipboard text exceeds {} bytes",
                MAX_CLIPBOARD
            )));
        }
        Ok(text)
    }
}

fn require_interface(node: &Node, interface: &str) -> Result<(), Failure> {
    if node.interfaces.iter().any(|value| value == interface) {
        return Ok(());
    }
    Err(error(format!(
        "accessible node {} {} ({:?}) does not expose {interface}",
        node.bus, node.object_path, node.name
    )))
}

fn accepted(ok: bool, method: &str) -> Result<(), Failure> {
    if ok {
        Ok(())
    } else {
        Err(error(format!(
            "AT-SPI {method} returned false; application rejected the operation"
        )))
    }
}
