//!
//! Sinmara's device APIs and isolated, explicitly headless Wayland sessions.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{DirBuilder, File};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value as BusValue};

use crate::Failure;

const BLUEZ: &str = "org.bluez";
const BLUEZ_DEVICE: &str = "org.bluez.Device1";
const UDISKS: &str = "org.freedesktop.UDisks2";
const UDISKS_ROOT: &str = "/org/freedesktop/UDisks2";
const BLOCK: &str = "org.freedesktop.UDisks2.Block";
const FILESYSTEM: &str = "org.freedesktop.UDisks2.Filesystem";
/// How long a Bluetooth connect may take to show its audio output.
const BLUETOOTH_SETTLE: Duration = Duration::from_secs(10);
const BLUETOOTH_POLL: Duration = Duration::from_millis(250);
const HEADLESS_BUS_START_TIMEOUT: Duration = Duration::from_secs(10);
const HEADLESS_COMPOSITOR_START_TIMEOUT: Duration = Duration::from_secs(10);
const HEADLESS_START_POLL_INTERVAL: Duration = Duration::from_millis(50);
/// The private Weston display's socket name, inside its own runtime directory.
const PRIVATE_SOCKET: &str = "wayland-odin";
const MAX_PRIVATE_PIXELS: u32 = 16_384;
/// The private home's XDG variables and the directories they name.
const PRIVATE_HOME_DIRS: [(&str, &str); 4] = [
    ("XDG_CONFIG_HOME", ".config"),
    ("XDG_CACHE_HOME", ".cache"),
    ("XDG_DATA_HOME", ".local/share"),
    ("XDG_STATE_HOME", ".local/state"),
];
/// Desktop-session variables that would let a private app reach the owner's
/// physical session; none of them reaches a private process.
const SCRUBBED: [&str; 16] = [
    "DISPLAY",
    "NIRI_SOCKET",
    "SWAYSOCK",
    "HYPRLAND_INSTANCE_SIGNATURE",
    "XDG_ACTIVATION_TOKEN",
    "DESKTOP_STARTUP_ID",
    "WAYLAND_SOCKET",
    "XAUTHORITY",
    "GDK_DISPLAY",
    "QT_WAYLAND_DISPLAY",
    "DBUS_SESSION_BUS_PID",
    "DBUS_STARTER_ADDRESS",
    "DBUS_STARTER_BUS_TYPE",
    "PULSE_SERVER",
    "PIPEWIRE_REMOTE",
    "AT_SPI_BUS_ADDRESS",
];
type Properties = HashMap<String, OwnedValue>;
type Objects = HashMap<OwnedObjectPath, HashMap<String, Properties>>;

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "camelCase", deny_unknown_fields)]
pub enum DeviceAction {
    Map {},
    BluetoothDevices {},
    BluetoothConnect {
        device: String,
    },
    BluetoothDisconnect {
        device: String,
    },
    Drives {},
    #[serde(rename_all = "camelCase")]
    Mount {
        drive: String,
        read_only: Option<bool>,
    },
    Unmount {
        drive: String,
    },
    SpeakerChannels {
        sink: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    SetSpeakerChannels {
        sink: Option<String>,
        levels: Vec<ChannelLevel>,
    },
    Power {
        action: PowerAction,
    },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelLevel {
    channel: String,
    percent: u16,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PowerAction {
    PowerOff,
    Reboot,
    Suspend,
    Hibernate,
    HybridSleep,
    SuspendThenHibernate,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "camelCase", deny_unknown_fields)]
pub enum HeadlessAction {
    Start { width: u32, height: u32 },
    Status {},
    Stop {},
    Launch { app: String },
}

/// A string is the common case; arrays explicitly expose ambiguous aliases.
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum Targets {
    One(String),
    Many(Vec<String>),
}

impl Targets {
    fn values(&self) -> &[String] {
        match self {
            Self::One(value) => std::slice::from_ref(value),
            Self::Many(values) => values,
        }
    }
}

/// Site-owned names, never guessed hardware identifiers. Omitted groups are empty.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceMap {
    #[serde(default)]
    desktops: BTreeMap<String, Targets>,
    /// Explicit default for this owner conversation, not the daemon's host.
    #[serde(default)]
    conversation_desktop: Option<String>,
    #[serde(default)]
    outputs: BTreeMap<String, Targets>,
    #[serde(default)]
    apps: BTreeMap<String, Targets>,
    #[serde(default)]
    chats: BTreeMap<String, Targets>,
    #[serde(default)]
    bluetooth: BTreeMap<String, Targets>,
    #[serde(default)]
    drives: BTreeMap<String, Targets>,
    #[serde(default)]
    lights: BTreeMap<String, Targets>,
    #[serde(default)]
    audio: BTreeMap<String, Targets>,
    #[serde(default)]
    notes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum AliasKind {
    Outputs,
    Apps,
    Chats,
    Bluetooth,
    Drives,
    Lights,
    Audio,
}

impl DeviceMap {
    pub fn from_environment() -> Result<Self, String> {
        let Some(path) = std::env::var_os("ODIN_DESK_DEVICES") else {
            return Ok(Self::default());
        };
        let path = PathBuf::from(path);
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("ODIN_DESK_DEVICES {}: {error}", path.display()))?;
        serde_json::from_str(&text)
            .map_err(|error| format!("ODIN_DESK_DEVICES {}: {error}", path.display()))
    }

    /// Resolve a fleet desktop without guessing an undeclared host. Exact
    /// names win, then case-folded names, then a unique prefix.
    pub fn desktop_targets(
        &self,
        selector: Option<&str>,
        available: &BTreeSet<String>,
        allow_all: bool,
    ) -> Result<Vec<String>, String> {
        let selector = selector.or(self.conversation_desktop.as_deref()).ok_or(
            "no local conversation desktop is declared in ODIN_DESK_DEVICES; specify device",
        )?;
        if allow_all && selector.eq_ignore_ascii_case("all") {
            return Ok(available.iter().cloned().collect());
        }
        let mut names: BTreeMap<&str, Vec<&str>> = available
            .iter()
            .map(|host| (host.as_str(), vec![host.as_str()]))
            .collect();
        for (name, targets) in &self.desktops {
            if !available.contains(name) {
                names.insert(name, targets.values().iter().map(String::as_str).collect());
            }
        }
        let folded = selector.to_lowercase();
        let candidates = if let Some(targets) = names.get(selector) {
            vec![(selector, targets)]
        } else {
            let exact: Vec<_> = names
                .iter()
                .filter(|(name, _)| name.to_lowercase() == folded)
                .map(|(name, targets)| (*name, targets))
                .collect();
            if exact.is_empty() && !selector.trim().is_empty() {
                names
                    .iter()
                    .filter(|(name, _)| name.to_lowercase().starts_with(&folded))
                    .map(|(name, targets)| (*name, targets))
                    .collect()
            } else {
                exact
            }
        };
        let targets: BTreeSet<_> = candidates
            .iter()
            .flat_map(|(_, targets)| targets.iter().copied())
            .collect();
        if targets.len() != 1 {
            return Err(format!(
                "desktop device {selector:?} is {} (matches: {}; available: {})",
                if targets.is_empty() {
                    "unknown"
                } else {
                    "ambiguous"
                },
                candidates
                    .iter()
                    .map(|(name, _)| *name)
                    .collect::<Vec<_>>()
                    .join(", "),
                names.keys().copied().collect::<Vec<_>>().join(", "),
            ));
        }
        let target = *targets.first().expect("one desktop target");
        if !available.contains(target) {
            return Err(format!("desktop device {selector:?} names {target:?}, which is not an enabled desktop node"));
        }
        Ok(vec![target.to_owned()])
    }

    pub(super) fn resolve(&self, kind: AliasKind, value: &str) -> Result<String, String> {
        if value.trim().is_empty() {
            return Err(format!("empty {kind:?} selector"));
        }
        let aliases = match kind {
            AliasKind::Outputs => &self.outputs,
            AliasKind::Apps => &self.apps,
            AliasKind::Chats => &self.chats,
            AliasKind::Bluetooth => &self.bluetooth,
            AliasKind::Drives => &self.drives,
            AliasKind::Lights => &self.lights,
            AliasKind::Audio => &self.audio,
        };
        let mut matches = aliases
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(value));
        let Some((_, targets)) = matches.next() else {
            return Ok(value.to_owned());
        };
        if matches.next().is_some() {
            return Err(format!(
                "ambiguous {kind:?} alias {value:?}: multiple case-insensitive names"
            ));
        }
        let targets: BTreeSet<&str> = targets.values().iter().map(String::as_str).collect();
        if targets.iter().any(|target| target.trim().is_empty()) {
            return Err(format!("{kind:?} alias {value:?} contains an empty target"));
        }
        if targets.len() != 1 {
            return Err(format!(
                "{kind:?} alias {value:?} requires exactly one target, found {targets:?}"
            ));
        }
        Ok((*targets.iter().next().expect("one target")).to_owned())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BluetoothDevice {
    path: OwnedObjectPath,
    address: String,
    name: Option<String>,
    alias: Option<String>,
    paired: bool,
    connected: bool,
    /// Headphones, a headset or speakers (BlueZ's icon is audio-*).
    audio: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Drive {
    path: OwnedObjectPath,
    device: String,
    uuid: Option<String>,
    label: Option<String>,
    filesystem: Option<String>,
    mount_points: Vec<String>,
    mountable: bool,
}

fn system_bus() -> Result<Connection, String> {
    Connection::system().map_err(|error| format!("system D-Bus: {error}"))
}

fn objects(connection: &Connection, service: &str, path: &str) -> Result<Objects, String> {
    Proxy::new(
        connection,
        service,
        path,
        "org.freedesktop.DBus.ObjectManager",
    )
    .and_then(|proxy| proxy.call("GetManagedObjects", &()))
    .map_err(|error| format!("{service} GetManagedObjects: {error}"))
}

fn property<T>(properties: &mut Properties, name: &str) -> Result<Option<T>, String>
where
    T: TryFrom<OwnedValue>,
    T::Error: std::fmt::Display,
{
    properties
        .remove(name)
        .map(|value| {
            T::try_from(value).map_err(|error| format!("invalid D-Bus property {name}: {error}"))
        })
        .transpose()
}

fn required<T>(properties: &mut Properties, name: &str) -> Result<T, String>
where
    T: TryFrom<OwnedValue>,
    T::Error: std::fmt::Display,
{
    property(properties, name)?.ok_or_else(|| format!("missing D-Bus property {name}"))
}

fn bluetooth_devices(connection: &Connection) -> Result<Vec<BluetoothDevice>, String> {
    let mut devices = Vec::new();
    for (path, mut interfaces) in objects(connection, BLUEZ, "/")? {
        let Some(mut properties) = interfaces.remove(BLUEZ_DEVICE) else {
            continue;
        };
        devices.push(BluetoothDevice {
            path,
            address: required(&mut properties, "Address")?,
            name: property(&mut properties, "Name")?,
            alias: property(&mut properties, "Alias")?,
            paired: required(&mut properties, "Paired")?,
            connected: required(&mut properties, "Connected")?,
            audio: property::<String>(&mut properties, "Icon")?
                .is_some_and(|icon| icon.starts_with("audio")),
        });
    }
    devices.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(devices)
}

fn byte_path(mut bytes: Vec<u8>) -> Result<String, String> {
    if bytes.last() == Some(&0) {
        bytes.pop();
    }
    String::from_utf8(bytes).map_err(|error| format!("device path is not UTF-8: {error}"))
}

fn drives(connection: &Connection) -> Result<Vec<Drive>, String> {
    let mut drives = Vec::new();
    for (path, mut interfaces) in objects(connection, UDISKS, UDISKS_ROOT)? {
        let Some(mut block) = interfaces.remove(BLOCK) else {
            continue;
        };
        let filesystem = interfaces.remove(FILESYSTEM);
        let mountable = filesystem.is_some();
        let mount_points = match filesystem {
            Some(mut properties) => {
                let paths: Vec<Vec<u8>> = required(&mut properties, "MountPoints")?;
                paths
                    .into_iter()
                    .map(byte_path)
                    .collect::<Result<Vec<_>, _>>()?
            }
            None => Vec::new(),
        };
        drives.push(Drive {
            path,
            device: byte_path(required(&mut block, "Device")?)?,
            uuid: property(&mut block, "IdUUID")?,
            label: property(&mut block, "IdLabel")?,
            filesystem: property(&mut block, "IdType")?,
            mount_points,
            mountable,
        });
    }
    drives.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(drives)
}

fn unique<T>(mut matches: Vec<T>, selector: &str, kind: &str) -> Result<T, String> {
    match matches.len() {
        1 => Ok(matches.pop().expect("one match")),
        0 => Err(format!(
            "no {kind} matches {selector:?}; inspect {kind} status"
        )),
        count => Err(format!(
            "ambiguous {kind} selector {selector:?}: {count} matches; use an exact object path"
        )),
    }
}


fn sink_channels(sink: &Value) -> Result<Vec<&str>, String> {
    let map = sink
        .get("channel_map")
        .and_then(Value::as_str)
        .ok_or_else(|| "pactl sink has no string channel_map".to_owned())?;
    let channels: Vec<&str> = map.split(',').map(str::trim).collect();
    if channels.is_empty() || channels.iter().any(|channel| channel.is_empty()) {
        return Err("pactl sink has an empty channel map".to_owned());
    }
    Ok(channels)
}

impl crate::Desk {
    pub(super) fn device_action(&mut self, action: &DeviceAction) -> Result<String, Failure> {
        self.watch.check().map_err(Failure::Stopped)?;
        match action {
            DeviceAction::Map {} => Ok(serde_json::to_string(&DeviceMap::from_environment()?)
                .map_err(|error| format!("serialize device map: {error}"))?),
            DeviceAction::BluetoothDevices {} => {
                let connection = system_bus()?;
                Ok(serde_json::to_string(&bluetooth_devices(&connection)?)
                    .map_err(|error| format!("serialize Bluetooth devices: {error}"))?)
            }
            DeviceAction::BluetoothConnect { device }
            | DeviceAction::BluetoothDisconnect { device } => {
                let selector = self.devices.resolve(AliasKind::Bluetooth, device)?;
                let connection = system_bus()?;
                let device = unique(
                    bluetooth_devices(&connection)?
                        .into_iter()
                        .filter(|device| {
                            device.path.as_str() == selector
                                || device.address.eq_ignore_ascii_case(&selector)
                                || device.name.as_deref() == Some(selector.as_str())
                                || device.alias.as_deref() == Some(selector.as_str())
                        })
                        .collect(),
                    &selector,
                    "Bluetooth device",
                )?;
                let method = if matches!(action, DeviceAction::BluetoothConnect { .. }) {
                    "Connect"
                } else {
                    "Disconnect"
                };
                self.watch.check().map_err(Failure::Stopped)?;
                let proxy = Proxy::new(&connection, BLUEZ, device.path.as_str(), BLUEZ_DEVICE)
                    .map_err(|error| format!("BlueZ {}: {error}", device.path))?;
                proxy
                    .call::<_, _, ()>(method, &())
                    .map_err(|error| format!("BlueZ {method} {}: {error}", device.path))?;
                let want = method == "Connect";
                // Connected, and for headphones or speakers their output too,
                // so an audio switch right after finds it.
                let sink = format!("bluez_output.{}", device.address.replace(':', "_"));
                let deadline = Instant::now() + BLUETOOTH_SETTLE;
                let (connected, output) = loop {
                    let connected: bool = proxy
                        .get_property("Connected")
                        .map_err(|error| format!("BlueZ Connected {}: {error}", device.path))?;
                    let output = want
                        && self
                            .timed(&self.bin.pactl, &["list", "short", "sinks"])
                            .is_ok_and(|sinks| sinks.contains(&sink));
                    if connected == want && (!want || !device.audio || output)
                        || Instant::now() >= deadline
                    {
                        break (connected, output);
                    }
                    self.wait(BLUETOOTH_POLL)?;
                };
                if connected != want {
                    return Err(format!(
                        "{} is still {} after {}s",
                        device.alias.as_deref().unwrap_or(&device.address),
                        if connected {
                            "connected"
                        } else {
                            "disconnected"
                        },
                        BLUETOOTH_SETTLE.as_secs()
                    )
                    .into());
                }
                Ok(json!({"device":device.path.as_str(),"address":device.address,"connected":connected,"audioOutput":output.then_some(sink)}).to_string())
            }
            DeviceAction::Drives {} => {
                let connection = system_bus()?;
                Ok(serde_json::to_string(&drives(&connection)?)
                    .map_err(|error| format!("serialize drives: {error}"))?)
            }
            DeviceAction::Mount { drive, .. } | DeviceAction::Unmount { drive } => {
                let selector = self.devices.resolve(AliasKind::Drives, drive)?;
                let connection = system_bus()?;
                let drive = unique(
                    drives(&connection)?
                        .into_iter()
                        .filter(|drive| {
                            drive.path.as_str() == selector
                                || drive.device == selector
                                || drive.uuid.as_deref() == Some(selector.as_str())
                                || drive.label.as_deref() == Some(selector.as_str())
                        })
                        .collect(),
                    &selector,
                    "drive",
                )?;
                if !drive.mountable {
                    return Err(
                        format!("{} has no UDisks filesystem interface", drive.device).into(),
                    );
                }
                let proxy = Proxy::new(&connection, UDISKS, drive.path.as_str(), FILESYSTEM)
                    .map_err(|error| format!("UDisks {}: {error}", drive.path))?;
                let mut options: HashMap<&str, BusValue<'_>> = HashMap::new();
                options.insert("auth.no_user_interaction", BusValue::from(true));
                self.watch.check().map_err(Failure::Stopped)?;
                if let DeviceAction::Mount { read_only, .. } = action {
                    if let Some(read_only) = read_only {
                        options.insert(
                            "options",
                            BusValue::from(if *read_only { "ro" } else { "rw" }),
                        );
                    }
                    let mount_point: String = proxy
                        .call("Mount", &(options,))
                        .map_err(|error| format!("UDisks Mount {}: {error}", drive.device))?;
                    Ok(json!({"device":drive.device,"mountPoint":mount_point}).to_string())
                } else {
                    proxy
                        .call::<_, _, ()>("Unmount", &(options,))
                        .map_err(|error| format!("UDisks Unmount {}: {error}", drive.device))?;
                    Ok(json!({"device":drive.device,"unmounted":true}).to_string())
                }
            }
            DeviceAction::SpeakerChannels { sink } => {
                Ok(self.speaker_sink(sink.as_deref())?.to_string())
            }
            DeviceAction::SetSpeakerChannels { sink, levels } => {
                if levels.is_empty() {
                    return Err("setSpeakerChannels requires at least one channel level"
                        .to_owned()
                        .into());
                }
                let sink = self.speaker_sink(sink.as_deref())?;
                let channels = sink_channels(&sink)?;
                let volumes = sink
                    .get("volume")
                    .and_then(Value::as_object)
                    .ok_or_else(|| "pactl sink has no volume object".to_owned())?;
                let name = sink
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "pactl sink has no name".to_owned())?;
                let mut requested = BTreeMap::new();
                for level in levels {
                    if level.percent > 150 {
                        return Err(format!(
                            "channel {} volume must be 0..150 percent",
                            level.channel
                        )
                        .into());
                    }
                    if !channels.contains(&level.channel.as_str()) {
                        return Err(format!(
                            "sink {name} has no channel {:?}; available: {channels:?}",
                            level.channel
                        )
                        .into());
                    }
                    if requested
                        .insert(level.channel.as_str(), level.percent)
                        .is_some()
                    {
                        return Err(format!("duplicate channel {:?}", level.channel).into());
                    }
                }
                let mut args = vec!["set-sink-volume".to_owned(), name.to_owned()];
                for channel in channels {
                    args.push(match requested.get(channel) {
                        Some(percent) => format!("{percent}%"),
                        None => volumes
                            .get(channel)
                            .and_then(|volume| volume.get("value"))
                            .and_then(Value::as_u64)
                            .ok_or_else(|| format!("pactl channel {channel} has no raw volume"))?
                            .to_string(),
                    });
                }
                self.watch.check().map_err(Failure::Stopped)?;
                let args: Vec<&str> = args.iter().map(String::as_str).collect();
                self.checked(&self.bin.pactl, &args)?;
                Ok(self.speaker_sink(Some(name))?.to_string())
            }
            DeviceAction::Power { action } => {
                let method = match action {
                    PowerAction::PowerOff => "PowerOff",
                    PowerAction::Reboot => "Reboot",
                    PowerAction::Suspend => "Suspend",
                    PowerAction::Hibernate => "Hibernate",
                    PowerAction::HybridSleep => "HybridSleep",
                    PowerAction::SuspendThenHibernate => "SuspendThenHibernate",
                };
                let connection = system_bus()?;
                let proxy = Proxy::new(
                    &connection,
                    "org.freedesktop.login1",
                    "/org/freedesktop/login1",
                    "org.freedesktop.login1.Manager",
                )
                .map_err(|error| format!("logind: {error}"))?;
                self.watch.check().map_err(Failure::Stopped)?;
                // false means no interactive authorization / new approval prompt.
                proxy
                    .call::<_, _, ()>(method, &(false,))
                    .map_err(|error| format!("logind {method}: {error}"))?;
                Ok(format!("logind accepted {method}"))
            }
        }
    }

    fn speaker_sink(&self, selector: Option<&str>) -> Result<Value, String> {
        let selector = self
            .devices
            .resolve(AliasKind::Audio, selector.unwrap_or("@DEFAULT_SINK@"))?;
        let selector = if selector == "@DEFAULT_SINK@" {
            self.checked(&self.bin.pactl, &["get-default-sink"])?
                .trim()
                .to_owned()
        } else {
            selector
        };
        let output = self.checked(&self.bin.pactl, &["--format=json", "list", "sinks"])?;
        let sinks: Vec<Value> =
            serde_json::from_str(&output).map_err(|error| format!("pactl sink JSON: {error}"))?;
        unique(
            sinks
                .into_iter()
                .filter(|sink| {
                    sink.get("name").and_then(Value::as_str) == Some(selector.as_str())
                        || sink
                            .get("index")
                            .and_then(Value::as_u64)
                            .is_some_and(|index| index.to_string() == selector)
                })
                .collect(),
            &selector,
            "audio sink",
        )
    }

    pub(super) fn headless_action(&mut self, action: &HeadlessAction) -> Result<String, Failure> {
        self.watch.check().map_err(Failure::Stopped)?;
        match action {
            HeadlessAction::Start { width, height } => {
                if self.headless.is_some() {
                    return Err(
                        "a private Weston display already exists; stop it before starting another"
                            .to_owned()
                            .into(),
                    );
                }
                if !(1..=MAX_PRIVATE_PIXELS).contains(width)
                    || !(1..=MAX_PRIVATE_PIXELS).contains(height)
                {
                    return Err(format!(
                        "private display width and height must be 1..{MAX_PRIVATE_PIXELS} pixels"
                    )
                    .into());
                }
                let runtime = self
                    .session_var("XDG_RUNTIME_DIR")
                    .map(PathBuf::from)
                    .ok_or_else(|| "graphical session has no XDG_RUNTIME_DIR".to_owned())?;
                let runtime = private_runtime(&runtime)?;
                let socket = runtime.join(PRIVATE_SOCKET);
                let mut headless = Headless {
                    runtime,
                    socket,
                    width: *width,
                    height: *height,
                    compositor: None,
                    bus: None,
                    apps: Vec::new(),
                };
                for (_, directory) in PRIVATE_HOME_DIRS {
                    std::fs::create_dir_all(headless.home().join(directory)).map_err(|error| {
                        format!("create private app directory {directory}: {error}")
                    })?;
                }
                let bus_stderr = File::create(headless.runtime.join("bus.log"))
                    .map_err(|error| format!("create private bus log: {error}"))?;
                let mut bus_command = self.command(&self.bin.dbus_daemon);
                bus_command.args([
                    "--session".to_owned(),
                    "--nofork".to_owned(),
                    "--nopidfile".to_owned(),
                    format!("--address=unix:path={}", headless.bus_socket().display()),
                ]);
                isolate(&mut bus_command, &headless);
                bus_command
                    .process_group(0)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(bus_stderr);
                headless.bus = Some(
                    bus_command
                        .spawn()
                        .map_err(|error| format!("start private session bus: {error}"))?,
                );
                self.await_private(&mut headless, Private::Bus, HEADLESS_BUS_START_TIMEOUT)?;
                let stderr = File::create(headless.runtime.join("stderr.log"))
                    .map_err(|error| format!("create Weston stderr log: {error}"))?;
                let mut command = self.command(&self.bin.weston);
                command.args([
                    "--backend=headless-backend.so".to_owned(),
                    "--renderer=pixman".to_owned(),
                    format!("--socket={PRIVATE_SOCKET}"),
                    "--no-config".to_owned(),
                    "--idle-time=0".to_owned(),
                    format!("--width={width}"),
                    format!("--height={height}"),
                    format!("--log={}", headless.runtime.join("weston.log").display()),
                ]);
                isolate(&mut command, &headless);
                command
                    .process_group(0)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(stderr);
                headless.compositor = Some(
                    command
                        .spawn()
                        .map_err(|error| format!("start headless Weston: {error}"))?,
                );
                self.await_private(
                    &mut headless,
                    Private::Compositor,
                    HEADLESS_COMPOSITOR_START_TIMEOUT,
                )?;
                let status = headless.status()?;
                self.headless = Some(headless);
                Ok(status)
            }
            HeadlessAction::Status {} => match self.headless.as_mut() {
                Some(headless) => Ok(headless.status()?),
                None => Ok(json!({"running":false}).to_string()),
            },
            HeadlessAction::Stop {} => {
                let mut headless = self
                    .headless
                    .take()
                    .ok_or_else(|| "there is no private Weston display to stop".to_owned())?;
                let socket = headless.socket.display().to_string();
                let result = headless.stop();
                drop(headless);
                result?;
                Ok(json!({"stopped":true,"socket":socket}).to_string())
            }
            HeadlessAction::Launch { app } => {
                let app = self.devices.resolve(AliasKind::Apps, app)?;
                let argv = self.desktop_entry(&app)?;
                let executable = argv
                    .first()
                    .ok_or_else(|| format!("desktop entry {app} has an empty command"))?;
                let mut command = self.command(Path::new(executable));
                let socket = {
                    let headless = self.headless.as_mut().ok_or_else(|| {
                        "start a private Weston display before launching an app".to_owned()
                    })?;
                    headless.ensure_running()?;
                    isolate(&mut command, headless);
                    headless.socket.clone()
                };
                command.args(&argv[1..]);
                command
                    .process_group(0)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                self.watch.check().map_err(Failure::Stopped)?;
                let child = command
                    .spawn()
                    .map_err(|error| format!("launch {app} on private display: {error}"))?;
                let pid = child.id();
                self.headless
                    .as_mut()
                    .expect("private Weston exists")
                    .apps
                    .push(child);
                Ok(json!({"app":app,"pid":pid,"waylandDisplay":socket}).to_string())
            }
        }
    }
}

/// A private bus and profile prevent desktop-entry single-instance activation
/// from forwarding this launch to an app on the owner's physical desktop.
fn isolate(command: &mut std::process::Command, headless: &Headless) {
    command
        .envs(headless.variables())
        .current_dir(headless.home());
    for key in SCRUBBED {
        command.env_remove(key);
    }
}

/// The desktop session's environment as a client of the private display sees
/// it: nothing that reaches the physical session, the private variables over it.
pub(super) fn private_session(
    session: &[(String, String)],
    private: Vec<(String, String)>,
) -> Vec<(String, String)> {
    let mut environment: Vec<(String, String)> = session
        .iter()
        .filter(|(key, _)| {
            !SCRUBBED.contains(&key.as_str()) && !private.iter().any(|(name, _)| name == key)
        })
        .cloned()
        .collect();
    environment.extend(private);
    environment
}

static NEXT_DISPLAY: AtomicU64 = AtomicU64::new(0);

fn private_runtime(parent: &Path) -> Result<PathBuf, String> {
    for _ in 0..32 {
        let sequence = NEXT_DISPLAY.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(
            "odin-desk-weston-{}-{sequence}",
            std::process::id()
        ));
        match DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "create private Weston runtime {}: {error}",
                    path.display()
                ))
            }
        }
    }
    Err("could not reserve a private Weston runtime directory".to_owned())
}

/// Owns only this module's compositor, app process groups, and private directory.
/// Dropping Desk (including error/EOF) cannot leave its private display behind.
pub(super) struct Headless {
    runtime: PathBuf,
    socket: PathBuf,
    width: u32,
    height: u32,
    compositor: Option<Child>,
    bus: Option<Child>,
    apps: Vec<Child>,
}

/// Which private child `await_private` watches.
#[derive(Clone, Copy)]
enum Private {
    Bus,
    Compositor,
}

impl crate::Desk {
    /// Waits for a private child to open its socket, or fails with how it
    /// exited and what it logged.
    fn await_private(
        &self,
        headless: &mut Headless,
        which: Private,
        timeout: Duration,
    ) -> Result<(), Failure> {
        let (name, socket) = match which {
            Private::Bus => ("private session bus", headless.bus_socket()),
            Private::Compositor => ("headless Weston", headless.socket.clone()),
        };
        let deadline = Instant::now() + timeout;
        loop {
            let child = match which {
                Private::Bus => headless.bus.as_mut(),
                Private::Compositor => headless.compositor.as_mut(),
            }
            .expect("a spawned private child");
            let exited = child
                .try_wait()
                .map_err(|error| format!("inspect {name}: {error}"))?;
            if let Some(status) = exited {
                return Err(format!("{name} exited {status}: {}", headless.logs()).into());
            }
            if UnixStream::connect(&socket).is_ok() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "{name} did not open {}: {}",
                    socket.display(),
                    headless.logs()
                )
                .into());
            }
            self.wait(HEADLESS_START_POLL_INTERVAL)?;
        }
    }
}

impl Headless {
    fn home(&self) -> PathBuf {
        self.runtime.join("home")
    }

    fn bus_socket(&self) -> PathBuf {
        self.runtime.join("bus")
    }

    /// Every variable a process on the private display is given: the display,
    /// the private bus and a profile of its own.
    fn variables(&self) -> Vec<(String, String)> {
        let home = self.home();
        let text = |path: &Path| path.display().to_string();
        let mut variables = vec![
            ("WAYLAND_DISPLAY".to_owned(), text(&self.socket)),
            ("XDG_RUNTIME_DIR".to_owned(), text(&self.runtime)),
            (
                "DBUS_SESSION_BUS_ADDRESS".to_owned(),
                format!("unix:path={}", self.bus_socket().display()),
            ),
            ("HOME".to_owned(), text(&home)),
            ("XDG_SESSION_TYPE".to_owned(), "wayland".to_owned()),
            ("XDG_CURRENT_DESKTOP".to_owned(), "Weston".to_owned()),
            ("GDK_BACKEND".to_owned(), "wayland".to_owned()),
            ("QT_QPA_PLATFORM".to_owned(), "wayland".to_owned()),
            ("SDL_VIDEODRIVER".to_owned(), "wayland".to_owned()),
            ("MOZ_ENABLE_WAYLAND".to_owned(), "1".to_owned()),
        ];
        variables.extend(
            PRIVATE_HOME_DIRS
                .into_iter()
                .map(|(name, directory)| (name.to_owned(), text(&home.join(directory)))),
        );
        variables
    }

    /// Overrides for clients that connect directly to the private bus/display.
    pub(super) fn environment(&mut self) -> Result<Vec<(String, String)>, String> {
        self.ensure_running()?;
        Ok(self.variables())
    }

    fn ensure_running(&mut self) -> Result<(), String> {
        let bus = self
            .bus
            .as_mut()
            .ok_or_else(|| "private session bus has been stopped".to_owned())?;
        if let Some(status) = bus
            .try_wait()
            .map_err(|error| format!("inspect private session bus: {error}"))?
        {
            return Err(format!(
                "private session bus exited {status}: {}",
                self.logs()
            ));
        }
        let compositor = self
            .compositor
            .as_mut()
            .ok_or_else(|| "private Weston has been stopped".to_owned())?;
        if let Some(status) = compositor
            .try_wait()
            .map_err(|error| format!("inspect private Weston: {error}"))?
        {
            return Err(format!("private Weston exited {status}: {}", self.logs()));
        }
        Ok(())
    }

    fn status(&mut self) -> Result<String, String> {
        self.ensure_running()?;
        let mut running = Vec::new();
        let mut completed = Vec::new();
        for child in &mut self.apps {
            match child
                .try_wait()
                .map_err(|error| format!("inspect private app: {error}"))?
            {
                None => running.push(child.id()),
                Some(status) => {
                    // A launcher exiting must not leave a detached descendant behind.
                    let _ = rustix::process::kill_process_group(
                        rustix::process::Pid::from_child(child),
                        rustix::process::Signal::KILL,
                    );
                    completed.push(json!({"pid":child.id(),"status":status.to_string()}));
                }
            }
        }
        self.apps.retain(|child| running.contains(&child.id()));
        Ok(json!({
            "running":true,
            "waylandDisplay":self.socket,
            "width":self.width,
            "height":self.height,
            "westonPid":self.compositor.as_ref().map(Child::id),
            "busPid":self.bus.as_ref().map(Child::id),
            "appPids":running,
            "completedApps":completed,
        })
        .to_string())
    }

    fn logs(&self) -> String {
        ["weston.log", "stderr.log", "bus.log"]
            .into_iter()
            .filter_map(|name| std::fs::read_to_string(self.runtime.join(name)).ok())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn stop(&mut self) -> Result<(), String> {
        let mut errors = Vec::new();
        for child in &mut self.apps {
            terminate(child, &mut errors);
        }
        self.apps.clear();
        if let Some(mut compositor) = self.compositor.take() {
            terminate(&mut compositor, &mut errors);
        }
        if let Some(mut bus) = self.bus.take() {
            terminate(&mut bus, &mut errors);
        }
        if let Err(error) = std::fs::remove_dir_all(&self.runtime) {
            if error.kind() != std::io::ErrorKind::NotFound {
                errors.push(format!("remove {}: {error}", self.runtime.display()));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

fn terminate(child: &mut Child, errors: &mut Vec<String>) {
    if let Err(error) = rustix::process::kill_process_group(
        rustix::process::Pid::from_child(child),
        rustix::process::Signal::KILL,
    ) {
        if error != rustix::io::Errno::SRCH {
            errors.push(format!(
                "kill private process group {}: {error}",
                child.id()
            ));
        }
    }
    if let Err(error) = child.wait() {
        errors.push(format!("reap private process {}: {error}", child.id()));
    }
}

impl Drop for Headless {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(test)]
mod fleet_tests {
    use super::*;

    #[test]
    fn desktop_names_resolve_exact_case_fold_and_unique_prefix_without_host_fallback() {
        let map: DeviceMap = serde_json::from_value(json!({
            "desktops": {"workstation": "pc", "Work": "mini", "notebook": "laptop",
                         "shared": ["pc", "mini"], "away": "retired"},
            "conversationDesktop": "pc"
        }))
        .unwrap();
        let nodes = BTreeSet::from(["pc".to_owned(), "mini".to_owned(), "laptop".to_owned()]);
        for (selector, expected) in [
            (None, "pc"),
            (Some("workstation"), "pc"),
            (Some("WORKSTATION"), "pc"),
            (Some("noteb"), "laptop"),
            (Some("mi"), "mini"),
            (Some("Work"), "mini"),
        ] {
            assert_eq!(
                map.desktop_targets(selector, &nodes, false).unwrap(),
                [expected]
            );
        }
        assert!(map
            .desktop_targets(Some("wor"), &nodes, false)
            .unwrap_err()
            .contains("ambiguous"));
        assert!(map
            .desktop_targets(Some("shared"), &nodes, false)
            .unwrap_err()
            .contains("ambiguous"));
        assert!(map
            .desktop_targets(Some("away"), &nodes, false)
            .unwrap_err()
            .contains("not an enabled"));
        let error = map
            .desktop_targets(Some("missing"), &nodes, false)
            .unwrap_err();
        assert!(error.contains("unknown") && error.contains("available:"));
        assert!(DeviceMap::default()
            .desktop_targets(None, &nodes, false)
            .unwrap_err()
            .contains("specify device"));
        assert_eq!(
            map.desktop_targets(Some("all"), &nodes, true).unwrap(),
            ["laptop", "mini", "pc"]
        );
        assert!(map.desktop_targets(Some("all"), &nodes, false).is_err());
    }

    #[test]
    fn an_alias_resolves_one_hop_and_refuses_a_name_that_names_two_things() {
        let map: DeviceMap = serde_json::from_value(json!({
            "bluetooth": {"Buds": "AA:BB", "both": ["AA:BB", "CC:DD"], "blank": " ",
                          "Case": "one", "case": "two"},
            "drives": {"Buds": "drive-uuid"}
        }))
        .unwrap();
        for (kind, value, expected) in [
            (AliasKind::Bluetooth, "Buds", Ok("AA:BB")),
            (AliasKind::Bluetooth, "buds", Ok("AA:BB")),
            (AliasKind::Drives, "Buds", Ok("drive-uuid")),
            (AliasKind::Bluetooth, "AA:BB", Ok("AA:BB")),
            (AliasKind::Bluetooth, "both", Err("exactly one target")),
            (AliasKind::Bluetooth, "blank", Err("empty target")),
            (AliasKind::Bluetooth, "CASE", Err("ambiguous")),
            (AliasKind::Bluetooth, " ", Err("empty")),
        ] {
            match (map.resolve(kind, value), expected) {
                (Ok(got), Ok(want)) => assert_eq!(got, want, "{value}"),
                (Err(got), Err(cause)) => assert!(got.contains(cause), "{value}: {got}"),
                (got, want) => panic!("{value}: {got:?} against {want:?}"),
            }
        }
    }

    #[test]
    fn an_app_on_the_private_display_sees_its_own_bus_and_profile_never_the_physical_session() {
        let headless = Headless {
            runtime: PathBuf::from("/run/private"),
            socket: PathBuf::from("/run/private").join(PRIVATE_SOCKET),
            width: 800,
            height: 600,
            compositor: None,
            bus: None,
            apps: Vec::new(),
        };
        let session: Vec<(String, String)> = [
            ("NIRI_SOCKET", "/run/user/1000/niri.sock"),
            ("DISPLAY", ":0"),
            ("AT_SPI_BUS_ADDRESS", "unix:path=/physical"),
            ("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus"),
            ("HOME", "/home/owner"),
            ("LANG", "C.UTF-8"),
        ]
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .to_vec();
        let private = private_session(&session, headless.variables());
        let var = |name: &str| {
            private
                .iter()
                .filter(|(key, _)| key == name)
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>()
        };
        assert!(var("NIRI_SOCKET").is_empty() && var("DISPLAY").is_empty());
        assert!(var("AT_SPI_BUS_ADDRESS").is_empty());
        assert_eq!(
            var("DBUS_SESSION_BUS_ADDRESS"),
            ["unix:path=/run/private/bus"]
        );
        assert_eq!(var("HOME"), ["/run/private/home"]);
        assert_eq!(var("XDG_STATE_HOME"), ["/run/private/home/.local/state"]);
        assert_eq!(var("WAYLAND_DISPLAY"), ["/run/private/wayland-odin"]);
        assert_eq!(var("LANG"), ["C.UTF-8"], "ordinary variables pass through");
    }

}
