use super::*;
use odin_process::ManagerClient;
use odin_process::Value as DbusValue;

/// The systemd unit health predicate, evaluated on real properties. A unit
/// the manager reports as auto-restarting is a crash loop between restarts;
/// it is never judged healthy, so a service that keeps dying can never ride
/// an `ActiveState=active` sample into a Pass.
pub(in crate::syscheck) fn unit_active(properties: &BTreeMap<String, String>) -> bool {
    properties.get("LoadState").map(String::as_str) == Some("loaded")
        && properties.get("ActiveState").map(String::as_str) == Some("active")
        && properties.get("SubState").map(String::as_str) != Some("auto-restart")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SystemdManager {
    User,
    System,
}

impl SystemdManager {
    fn index(self) -> usize {
        match self {
            SystemdManager::User => 0,
            SystemdManager::System => 1,
        }
    }
}

impl std::fmt::Display for SystemdManager {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            SystemdManager::User => "user",
            SystemdManager::System => "system",
        })
    }
}

/// Which manager scope a [`UnitStateReader`] consults.
///
/// `UserOnly` never falls back: the declared user units SYS-07 audits are
/// unhealthy when only the system manager knows them. `UserThenSystem`
/// consults the system manager whenever the user manager does not report the
/// unit loaded — including when the user manager cannot be consulted at all,
/// so a system-managed unit still resolves; when no manager yields a loaded
/// unit, the user manager's honest answer wins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::syscheck) enum ManagerScope {
    UserOnly,
    UserThenSystem,
}

const SYSTEM_BUS_SOCKET: &str = "/run/dbus/system_bus_socket";

const UNIT_INTERFACE: &str = "org.freedesktop.systemd1.Unit";
const SERVICE_INTERFACE: &str = "org.freedesktop.systemd1.Service";
const SOCKET_INTERFACE: &str = "org.freedesktop.systemd1.Socket";

/// The typed failure for a manager that is refused, denied, or otherwise
/// cannot be consulted. There is no shell fallback: the check reports the
/// unit state as unreadable instead of invoking `systemctl` after the bus
/// said no.
fn unreadable(manager: SystemdManager, unit: &str, error: impl std::fmt::Display) -> CheckFailure {
    CheckFailure::fail(
        "unit-unreadable",
        format!("the {manager} manager could not be consulted for {unit}: {error}"),
    )
}

fn is_loaded(properties: &BTreeMap<String, String>) -> bool {
    properties.get("LoadState").map(String::as_str) == Some("loaded")
}

/// The unit-type interface a unit name implies, read after the shared
/// `Unit` interface for the type-owned properties (`ExecStart`/`MainPID`
/// live on `Service`, `Listen` on `Socket`).
fn unit_type_interface(unit: &str) -> Option<&'static str> {
    if unit.ends_with(".service") {
        Some(SERVICE_INTERFACE)
    } else if unit.ends_with(".socket") {
        Some(SOCKET_INTERFACE)
    } else {
        None
    }
}

/// One systemd unit-state reader over the real D-Bus manager API. One
/// connection per manager, `LoadUnit` + `Properties.GetAll` per unit, and a
/// per-sweep cache: a unit resolved twice inside one check — SYS-09's
/// litellm `ExecStart` (config) and `MainPID` (environ) — costs one read.
/// There is no `systemctl` child and no shell fallback; every manager
/// refusal is the typed `unit-unreadable` failure, never a fabricated
/// property map. The bus transport bounds each call itself, so no check
/// deadline plumbing is needed.
pub(in crate::syscheck) struct UnitStateReader {
    scope: ManagerScope,
    user: BusAddress,
    system: BusAddress,
    clients: [Option<ManagerClient>; 2],
    cache: BTreeMap<String, BTreeMap<String, String>>,
}

impl UnitStateReader {
    /// Uses DBUS_SESSION_BUS_ADDRESS or the user runtime directory's bus socket, plus the system bus.
    pub(in crate::syscheck) fn for_host(scope: ManagerScope) -> Result<Self, CheckFailure> {
        let user = match env::var_os("DBUS_SESSION_BUS_ADDRESS").filter(|v| !v.is_empty()) {
            Some(raw) => BusAddress::parse(&raw.to_string_lossy()).map_err(|error| {
                CheckFailure::fail(
                    "unit-unreadable",
                    format!("the session bus address is not a registered unix endpoint: {error}"),
                )
            })?,
            None => {
                let runtime = runner::host_runtime_dir().map_err(|error| {
                    CheckFailure::fail(
                        "unit-unreadable",
                        format!("host user runtime directory unavailable: {error}"),
                    )
                })?;
                BusAddress::unix_socket(runtime.join("bus"))
                    .map_err(|error| CheckFailure::fail("unit-unreadable", error))?
            }
        };
        let system = BusAddress::unix_socket(PathBuf::from(SYSTEM_BUS_SOCKET))
            .map_err(|error| CheckFailure::fail("unit-unreadable", error))?;
        Ok(Self::at(scope, user, system))
    }

    pub(in crate::syscheck) fn at(
        scope: ManagerScope,
        user: BusAddress,
        system: BusAddress,
    ) -> Self {
        Self {
            scope,
            user,
            system,
            clients: [None, None],
            cache: BTreeMap::new(),
        }
    }

    /// Resolves one unit's state once per sweep and returns the property
    /// map in `systemctl show` presentation. A unit the manager cannot find
    /// is an honest `LoadState=not-found` answer, not an error.
    pub(in crate::syscheck) fn unit(
        &mut self,
        unit: &str,
    ) -> Result<BTreeMap<String, String>, CheckFailure> {
        if let Some(properties) = self.cache.get(unit) {
            return Ok(properties.clone());
        }
        let resolved = self.resolve(unit)?;
        self.cache.insert(unit.to_owned(), resolved.clone());
        Ok(resolved)
    }

    fn resolve(&mut self, unit: &str) -> Result<BTreeMap<String, String>, CheckFailure> {
        match self.scope {
            ManagerScope::UserOnly => self.consult(SystemdManager::User, unit),
            ManagerScope::UserThenSystem => {
                let user = self.consult(SystemdManager::User, unit);
                let user_loaded = matches!(&user, Ok(properties) if is_loaded(properties));
                if user_loaded {
                    return user;
                }
                let system = self.consult(SystemdManager::System, unit)?;
                if is_loaded(&system) {
                    return Ok(system);
                }
                user
            }
        }
    }

    /// One manager's answer for one unit: `LoadUnit` (the `systemctl show`
    /// primitive — a unit the manager cannot find still yields the stub
    /// whose `LoadState=not-found`; nothing is started) followed by
    /// `Properties.GetAll` over the `Unit` interface and the unit type's
    /// own interface. A loaded unit whose manager refuses one of those
    /// reads is unreadable; a not-loaded stub is only guaranteed the `Unit`
    /// interface, so a type-interface refusal there stays an honest answer.
    fn consult(
        &mut self,
        manager: SystemdManager,
        unit: &str,
    ) -> Result<BTreeMap<String, String>, CheckFailure> {
        let client = self.client(manager)?;
        let unit_path = client
            .load_unit(unit)
            .map_err(|error| unreadable(manager, unit, error))?;
        let mut properties = render_properties(
            client
                .unit_properties(&unit_path, UNIT_INTERFACE)
                .map_err(|error| unreadable(manager, unit, error))?,
        );
        if let Some(interface) = unit_type_interface(unit) {
            match client.unit_properties(&unit_path, interface) {
                Ok(values) => properties.extend(render_properties(values)),
                Err(_) if !is_loaded(&properties) => {}
                Err(error) => return Err(unreadable(manager, unit, error)),
            }
        }
        if !properties.contains_key("LoadState") {
            return Err(CheckFailure::fail(
                "unit-unreadable",
                format!("the {manager} manager answered no LoadState for {unit}"),
            ));
        }
        Ok(properties)
    }

    fn client(&mut self, manager: SystemdManager) -> Result<&mut ManagerClient, CheckFailure> {
        let index = manager.index();
        if self.clients[index].is_none() {
            let address = self.address(manager);
            self.clients[index] = Some(ManagerClient::connect(&address).map_err(|error| {
                CheckFailure::fail(
                    "unit-unreadable",
                    format!("the {manager} manager bus {address} is unreadable: {error}"),
                )
            })?);
        }
        Ok(self.clients[index]
            .as_mut()
            .expect("the client is connected"))
    }

    fn address(&self, manager: SystemdManager) -> BusAddress {
        match manager {
            SystemdManager::User => self.user.clone(),
            SystemdManager::System => self.system.clone(),
        }
    }
}

/// Render D-Bus properties in the systemctl show format consumed by check parsers.
/// Strings stay verbatim, booleans use yes/no, and unsigned numbers use decimal.
/// ExecStart uses `{ path=… ; argv[]=… ; ignore_errors=… }`; Listen uses `address (TYPE)`.
/// Unsupported values are omitted rather than guessed.
fn render_properties(values: BTreeMap<String, DbusValue>) -> BTreeMap<String, String> {
    values
        .into_iter()
        .filter_map(|(key, value)| Some((key, render_value(&value)?)))
        .collect()
}

fn render_value(value: &DbusValue) -> Option<String> {
    match value {
        DbusValue::String(text) => Some(text.clone()),
        DbusValue::Bool(flag) => Some(if *flag { "yes" } else { "no" }.to_owned()),
        DbusValue::Uint32(number) => Some(number.to_string()),
        DbusValue::Uint64(number) => Some(number.to_string()),
        DbusValue::Array(signature, entries) if signature == "(sasbttttuii)" => {
            let commands = entries.iter().filter_map(exec_command).collect::<Vec<_>>();
            (!commands.is_empty()).then(|| commands.join(" "))
        }
        DbusValue::Array(signature, entries) if signature == "(ss)" => {
            let listen = entries.iter().filter_map(listen_entry).collect::<Vec<_>>();
            (!listen.is_empty()).then(|| listen.join(" "))
        }
        _ => None,
    }
}

/// One exec command in `systemctl show` text; `argv[]=` joins the full
/// argument vector verbatim, exactly the shape the ExecStart scanners and
/// the socket-proxyd target check parse. The struct is the real
/// `a(sasbttttuii)` element — path, argv, `ignore_errors`, then the
/// start/exit timestamps, uid, exit code, and exit status; the trailing
/// fields are consumed and not printed, because no check reads them.
fn exec_command(value: &DbusValue) -> Option<String> {
    let DbusValue::Struct(fields) = value else {
        return None;
    };
    let [DbusValue::String(path), DbusValue::Array(_, argv), DbusValue::Bool(ignore_errors), DbusValue::Uint64(_), DbusValue::Uint64(_), DbusValue::Uint64(_), DbusValue::Uint64(_), DbusValue::Uint32(_), DbusValue::Int32(_), DbusValue::Int32(_)] =
        fields.as_slice()
    else {
        return None;
    };
    let argv = argv
        .iter()
        .filter_map(|word| match word {
            DbusValue::String(text) => Some(text.clone()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join(" ");
    Some(format!(
        "{{ path={path} ; argv[]={argv} ; ignore_errors={} }}",
        if *ignore_errors { "yes" } else { "no" }
    ))
}

/// Renders an `a(ss)` socket entry (type, address) as `address (TYPE)`
/// for the relay listener check, one entry per `Listen*=` line.
fn listen_entry(value: &DbusValue) -> Option<String> {
    let DbusValue::Struct(fields) = value else {
        return None;
    };
    let [DbusValue::String(kind), DbusValue::String(address)] = fields.as_slice() else {
        return None;
    };
    Some(format!("{address} ({kind})"))
}
