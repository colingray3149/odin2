//! Unit state over the systemd manager's D-Bus API, presented as `systemctl show` text.

use std::collections::BTreeMap;
use std::path::PathBuf;

use super::codec::Value;
use super::endpoint::{BusAddress, BusError};
use super::framing::ManagerClient;
use super::manager::{SERVICE_INTERFACE, UNIT_INTERFACE};

const SYSTEM_BUS: &str = "/run/dbus/system_bus_socket";

/// The systemd manager a unit belongs to. A caller names one scope and never falls back to the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagerScope {
    System,
    User,
}

impl ManagerScope {
    /// This host's bus for the scope: the system bus, or the owner's user bus.
    pub fn bus(self) -> Result<BusAddress, String> {
        match self {
            Self::System => BusAddress::unix_socket(PathBuf::from(SYSTEM_BUS)),
            Self::User => BusAddress::unix_socket(PathBuf::from(format!(
                "/run/user/{}/bus",
                rustix::process::getuid().as_raw()
            ))),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::User => "user",
        }
    }
}

/// One unit's properties as `systemctl show` presents them. `LoadUnit` starts nothing and answers
/// `LoadState=not-found` for an unknown name. Failures name the manager and the unit.
pub fn unit_state(scope: ManagerScope, unit: &str) -> Result<BTreeMap<String, String>, String> {
    let address = scope.bus()?;
    let mut client = ManagerClient::connect(&address).map_err(|error| {
        format!(
            "the {} manager bus {address} is unreadable: {error}",
            scope.label()
        )
    })?;
    read_unit(&mut client, unit).map_err(|error| {
        format!(
            "the {} manager could not read {unit}: {error}",
            scope.label()
        )
    })
}

/// Names of the units the manager lists as failed, as `systemctl list-units --state=failed` does.
pub fn failed_units(scope: ManagerScope) -> Result<Vec<String>, String> {
    let address = scope.bus()?;
    let mut client = ManagerClient::connect(&address).map_err(|error| {
        format!(
            "the {} manager bus {address} is unreadable: {error}",
            scope.label()
        )
    })?;
    client.failed_unit_names().map_err(|error| {
        format!(
            "the {} manager could not list failed units: {error}",
            scope.label()
        )
    })
}

/// `LoadUnit`, then `GetAll` on the `Unit` interface and, for a service, its own interface. A
/// service's interface may be missing on a stub the manager did not load; that is not an error.
pub(crate) fn read_unit(
    client: &mut ManagerClient,
    unit: &str,
) -> Result<BTreeMap<String, String>, BusError> {
    let path = client.load_unit(unit)?;
    let mut properties = render(client.unit_properties(&path, UNIT_INTERFACE)?);
    if unit.ends_with(".service") {
        match client.unit_properties(&path, SERVICE_INTERFACE) {
            Ok(values) => properties.extend(render(values)),
            Err(error) if error.is_unknown_interface() => {}
            Err(error) => return Err(error),
        }
    }
    Ok(properties)
}

/// Strings stay verbatim, booleans are yes/no, numbers are decimal, the 16-byte `InvocationID` is
/// lowercase hex and a `(uo)` job is `0` or `<id> <path>`. A `*Timestamp` is `@<unix seconds>`,
/// empty when unset, as `--timestamp=unix` prints it. Other shapes are left out, not guessed.
fn render(values: BTreeMap<String, Value>) -> BTreeMap<String, String> {
    values
        .into_iter()
        .filter_map(|(key, value)| {
            let text = render_value(&key, &value)?;
            Some((key, text))
        })
        .collect()
}

fn render_value(key: &str, value: &Value) -> Option<String> {
    Some(match value {
        Value::String(text) | Value::ObjectPath(text) => text.clone(),
        Value::Bool(flag) => if *flag { "yes" } else { "no" }.to_owned(),
        Value::Int32(number) => number.to_string(),
        Value::Uint32(number) => number.to_string(),
        Value::Uint64(micros) if key.ends_with("Timestamp") => {
            if *micros == 0 {
                String::new()
            } else {
                format!("@{}", *micros / 1_000_000)
            }
        }
        Value::Uint64(number) => number.to_string(),
        Value::Array(element, bytes) if element == "y" => bytes
            .iter()
            .map(|byte| match byte {
                Value::Byte(byte) => Some(format!("{byte:02x}")),
                _ => None,
            })
            .collect::<Option<String>>()?,
        Value::Struct(fields) => match fields.as_slice() {
            [Value::Uint32(0), ..] => "0".to_owned(),
            [Value::Uint32(id), Value::ObjectPath(path)] => format!("{id} {path}"),
            _ => return None,
        },
        _ => return None,
    })
}
