//! Query systemd unit properties and manage transient worker scopes.

use std::collections::BTreeMap;

use super::codec::Value;
use super::endpoint::{BusError, PROTOCOL_ERROR_NAME};
use super::framing::ManagerClient;
use super::values;

const MANAGER_DESTINATION: &str = "org.freedesktop.systemd1";
const MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
const PROPERTIES_INTERFACE: &str = "org.freedesktop.DBus.Properties";
const NO_UNIT_FOR_INVOCATION: &str = "org.freedesktop.systemd1.NoUnitForInvocationID";
pub(crate) const UNIT_INTERFACE: &str = "org.freedesktop.systemd1.Unit";
const SCOPE_INTERFACE: &str = "org.freedesktop.systemd1.Scope";
const SERVICE_INTERFACE: &str = "org.freedesktop.systemd1.Service";

pub(crate) const KILL_MODE_CONTROL_GROUP: &str = "control-group";

impl ManagerClient {
    /// Mode `fail` prevents replacing an existing unit with the same name.
    pub fn start_transient_unit(
        &mut self,
        name: &str,
        properties: &[(&str, Value)],
    ) -> Result<String, BusError> {
        let mut entries = Vec::with_capacity(properties.len());
        for (key, value) in properties {
            entries.push(Value::Struct(vec![
                Value::String((*key).to_owned()),
                Value::Variant(Box::new(value.clone())),
            ]));
        }
        let reply = self.call(
            MANAGER_DESTINATION,
            MANAGER_PATH,
            MANAGER_INTERFACE,
            "StartTransientUnit",
            "ssa(sv)a(sa(sv))",
            &[
                Value::String(name.to_owned()),
                Value::String("fail".to_owned()),
                Value::Array("(sv)".to_owned(), entries),
                Value::Array("(sa(sv))".to_owned(), Vec::new()),
            ],
        )?;
        match reply.first() {
            Some(Value::ObjectPath(job)) => Ok(job.clone()),
            other => Err(BusError::new(
                PROTOCOL_ERROR_NAME,
                format!("StartTransientUnit returned {other:?}"),
            )),
        }
    }

    pub fn stop_unit(&mut self, name: &str, mode: &str) -> Result<(), BusError> {
        self.call(
            MANAGER_DESTINATION,
            MANAGER_PATH,
            MANAGER_INTERFACE,
            "StopUnit",
            "ss",
            &[
                Value::String(name.to_owned()),
                Value::String(mode.to_owned()),
            ],
        )?;
        Ok(())
    }

    /// Freeze before signaling recovered processes to prevent them escaping during inspection.
    pub fn freeze_unit(&mut self, name: &str) -> Result<(), BusError> {
        self.call(
            MANAGER_DESTINATION,
            MANAGER_PATH,
            MANAGER_INTERFACE,
            "FreezeUnit",
            "s",
            &[Value::String(name.to_owned())],
        )?;
        Ok(())
    }

    /// Thaw before stopping so frozen tasks can handle termination signals.
    pub fn thaw_unit(&mut self, name: &str) -> Result<(), BusError> {
        self.call(
            MANAGER_DESTINATION,
            MANAGER_PATH,
            MANAGER_INTERFACE,
            "ThawUnit",
            "s",
            &[Value::String(name.to_owned())],
        )?;
        Ok(())
    }

    /// Only NoSuchUnit means absence; other query failures remain errors.
    pub fn get_unit(&mut self, name: &str) -> Result<Option<String>, BusError> {
        match self.call(
            MANAGER_DESTINATION,
            MANAGER_PATH,
            MANAGER_INTERFACE,
            "GetUnit",
            "s",
            &[Value::String(name.to_owned())],
        ) {
            Ok(values) => match values.first() {
                Some(Value::ObjectPath(path)) => Ok(Some(path.clone())),
                other => Err(BusError::new(
                    PROTOCOL_ERROR_NAME,
                    format!("GetUnit returned {other:?}"),
                )),
            },
            Err(error) if error.is_no_such_unit() => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Load properties without starting the unit; missing units can return a not-found placeholder.
    pub fn load_unit(&mut self, name: &str) -> Result<String, BusError> {
        match self.call(
            MANAGER_DESTINATION,
            MANAGER_PATH,
            MANAGER_INTERFACE,
            "LoadUnit",
            "s",
            &[Value::String(name.to_owned())],
        ) {
            Ok(values) => match values.first() {
                Some(Value::ObjectPath(path)) => Ok(path.clone()),
                other => Err(BusError::new(
                    PROTOCOL_ERROR_NAME,
                    format!("LoadUnit returned {other:?}"),
                )),
            },
            Err(error) => Err(error),
        }
    }

    pub fn unit_properties(
        &mut self,
        unit_path: &str,
        interface: &str,
    ) -> Result<BTreeMap<String, Value>, BusError> {
        let reply = self.call(
            MANAGER_DESTINATION,
            unit_path,
            PROPERTIES_INTERFACE,
            "GetAll",
            "s",
            &[Value::String(interface.to_owned())],
        )?;
        let mut properties = BTreeMap::new();
        let Some(Value::Array(_, entries)) = reply.first() else {
            return Err(BusError::new(
                PROTOCOL_ERROR_NAME,
                "GetAll returned no property dictionary",
            ));
        };
        for entry in entries {
            let Value::Struct(pair) = entry else {
                return Err(BusError::new(
                    PROTOCOL_ERROR_NAME,
                    "property entry is malformed",
                ));
            };
            if pair.len() != 2 {
                return Err(BusError::new(
                    PROTOCOL_ERROR_NAME,
                    "property entry is malformed",
                ));
            }
            if let (Value::String(key), Value::Variant(value)) = (&pair[0], &pair[1]) {
                properties.insert(key.clone(), (**value).clone());
            } else {
                return Err(BusError::new(
                    PROTOCOL_ERROR_NAME,
                    "property entry is malformed",
                ));
            }
        }
        Ok(properties)
    }

    /// Only explicit missing-unit or missing-invocation replies mean absence.
    pub fn get_unit_by_invocation(
        &mut self,
        invocation: &[u8; 16],
    ) -> Result<Option<String>, BusError> {
        match self.call(
            MANAGER_DESTINATION,
            MANAGER_PATH,
            MANAGER_INTERFACE,
            "GetUnitByInvocationID",
            "ay",
            &[values::invocation_bytes(invocation)],
        ) {
            Ok(values) => match values.first() {
                Some(Value::ObjectPath(path)) => Ok(Some(path.clone())),
                other => Err(BusError::new(
                    PROTOCOL_ERROR_NAME,
                    format!("GetUnitByInvocationID returned {other:?}"),
                )),
            },
            Err(error) if error.is_no_such_unit() || error.name == NO_UNIT_FOR_INVOCATION => {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    /// Only an explicit missing-unit reply means absence.
    pub fn get_unit_by_pid(&mut self, pid: u32) -> Result<Option<String>, BusError> {
        match self.call(
            MANAGER_DESTINATION,
            MANAGER_PATH,
            MANAGER_INTERFACE,
            "GetUnitByPID",
            "u",
            &[Value::Uint32(pid)],
        ) {
            Ok(values) => match values.first() {
                Some(Value::ObjectPath(path)) => Ok(Some(path.clone())),
                other => Err(BusError::new(
                    PROTOCOL_ERROR_NAME,
                    format!("GetUnitByPID returned {other:?}"),
                )),
            },
            Err(error) if error.is_no_such_unit() => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Use `ownership_properties` instead when the caller must also accept service units.
    pub fn scope_properties(
        &mut self,
        unit_path: &str,
    ) -> Result<BTreeMap<String, Value>, BusError> {
        let mut properties = self.unit_properties(unit_path, UNIT_INTERFACE)?;
        match self.unit_properties(unit_path, SCOPE_INTERFACE) {
            Ok(scope) => properties.extend(scope),
            Err(error) if error.is_unknown_interface() => {}
            Err(error) => return Err(error),
        }
        Ok(properties)
    }

    /// ControlGroup lives on Service or Scope, so select the concrete unit interface.
    pub fn ownership_properties(
        &mut self,
        unit_path: &str,
    ) -> Result<BTreeMap<String, Value>, BusError> {
        let mut properties = self.unit_properties(unit_path, UNIT_INTERFACE)?;
        let id = properties
            .get("Id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                BusError::new(
                    PROTOCOL_ERROR_NAME,
                    format!("unit object {unit_path} reports no Id"),
                )
            })?
            .to_owned();
        let interface = if id.ends_with(".service") {
            SERVICE_INTERFACE
        } else if id.ends_with(".scope") {
            SCOPE_INTERFACE
        } else {
            return Err(BusError::new(
                PROTOCOL_ERROR_NAME,
                format!("unit {id} is not a process-hosting service or scope"),
            ));
        };
        let concrete = self.unit_properties(unit_path, interface)?;
        properties.extend(concrete);
        Ok(properties)
    }

    /// Scopes lack the Service interface and return `None`; service MainPID is read here.
    pub fn service_properties(
        &mut self,
        unit_path: &str,
    ) -> Result<Option<BTreeMap<String, Value>>, BusError> {
        match self.unit_properties(unit_path, SERVICE_INTERFACE) {
            Ok(properties) => Ok(Some(properties)),
            Err(error) if error.is_unknown_interface() => Ok(None),
            Err(error) => Err(error),
        }
    }
}

/// Match systemd's lowercase byte escapes, including a leading dot.
pub(crate) fn escape_unit_component(raw: &str) -> String {
    let mut escaped = String::with_capacity(raw.len());
    for (index, byte) in raw.as_bytes().iter().copied().enumerate() {
        if index == 0 && byte == b'.' {
            push_byte_escape(&mut escaped, byte);
            continue;
        }
        match byte {
            b'/' => escaped.push('-'),
            b'-' | b'\\' => push_byte_escape(&mut escaped, byte),
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' => escaped.push(byte as char),
            byte => push_byte_escape(&mut escaped, byte),
        }
    }
    escaped
}

fn push_byte_escape(escaped: &mut String, byte: u8) {
    escaped.push('\\');
    escaped.push('x');
    escaped.push(char::from_digit(u32::from(byte >> 4), 16).expect("nibble fits hex"));
    escaped.push(char::from_digit(u32::from(byte & 0x0F), 16).expect("nibble fits hex"));
}

/// Include a unique worker suffix so concurrent attempts do not collide.
pub(crate) fn compose_scope_unit_name(
    tx_id: &str,
    wp_id: &str,
    attempt: u32,
    suffix: &str,
) -> String {
    format!(
        "{}-{}-attempt-{}-{}.scope",
        escape_unit_component(tx_id),
        escape_unit_component(wp_id),
        attempt,
        escape_unit_component(suffix),
    )
}
