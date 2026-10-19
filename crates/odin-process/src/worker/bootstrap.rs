//! Park the payload until registration completes, then isolate it from the manager socket.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use rustix::mount::{mount_change, MountPropagationFlags};
use rustix::process::setsid;

use super::{WorkerError, WorkerErrorCode};
use crate::AllowlistedEnvironment;

/// Remove bus addresses so the payload cannot connect to the manager through its environment.
pub const BUS_AUTHORITY_ENV_VARS: [&str; 3] = [
    "DBUS_SESSION_BUS_ADDRESS",
    "DBUS_SYSTEM_BUS_ADDRESS",
    "ODIN_WORKER_BUS",
];

pub const BUS_ADDRESS_VAR: &str = "ODIN_WORKER_BUS";
pub const BOOTSTRAP_VAR: &str = "ODIN_WORKER_BOOTSTRAP_BIN";
pub const UNSHARE_VAR: &str = "ODIN_WORKER_UNSHARE_BIN";
pub(crate) const BOOTSTRAP_ACTIVE_VAR: &str = "ODIN_WORKER_BOOTSTRAP_ACTIVE";
pub(super) const BOOTSTRAP_MASK_VAR: &str = "ODIN_WORKER_BOOTSTRAP_MASK";
pub(super) const BOOTSTRAP_GATE_VAR: &str = "ODIN_WORKER_BOOTSTRAP_GATE";
pub(super) const BOOTSTRAP_PAYLOAD_VAR: &str = "ODIN_WORKER_BOOTSTRAP_PAYLOAD";
pub(super) const BOOTSTRAP_ARGC_VAR: &str = "ODIN_WORKER_BOOTSTRAP_ARGC";

/// Strip bus addresses even if a caller included them in the allowlist.
pub fn strip_bus_authority(environment: &AllowlistedEnvironment) -> AllowlistedEnvironment {
    let survivors: Vec<(String, String)> = environment
        .iter()
        .filter_map(|(key, value)| {
            let key = key.to_string_lossy().into_owned();
            let forbidden = BUS_AUTHORITY_ENV_VARS.iter().any(|name| key == *name);
            if forbidden {
                None
            } else {
                Some((key, value.to_string_lossy().into_owned()))
            }
        })
        .collect();
    let mut builder = crate::EnvironmentBuilder::new(survivors.iter().map(|(key, _)| key.as_str()))
        .expect("surviving keys came from an allowlisted environment");
    for (key, value) in &survivors {
        builder = builder
            .set(key, value)
            .expect("surviving entry re-validates");
    }
    builder.build()
}

pub(super) fn bootstrap_arg_var(index: usize) -> String {
    format!("ODIN_WORKER_BOOTSTRAP_ARG_{index}")
}

/// Mask only the socket because hiding its parent would hide unrelated runtime sockets and profiles.
pub(super) fn bus_mask_path(socket: &Path) -> Result<String, WorkerError> {
    match std::fs::metadata(socket) {
        Ok(_) => Ok(socket.to_string_lossy().into_owned()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(WorkerError::new(
            WorkerErrorCode::Spawn,
            format!(
                "the bus socket {} cannot be inspected for masking: {error}",
                socket.display()
            ),
        )),
    }
}

/// Wait for durable registration before executing the payload with private mounts and no capabilities.
pub fn bootstrap_run() -> ! {
    if std::env::var_os(BOOTSTRAP_ACTIVE_VAR).as_deref() != Some(std::ffi::OsStr::new("1")) {
        bootstrap_fail(125, "bootstrap activation is missing");
    }
    let mask = std::env::var_os(BOOTSTRAP_MASK_VAR).unwrap_or_default();
    let gate_path = std::env::var_os(BOOTSTRAP_GATE_VAR).unwrap_or_default();
    if gate_path.is_empty() || !Path::new(&gate_path).is_absolute() {
        bootstrap_fail(125, "payload gate path is missing or relative");
    }
    let payload = std::env::var_os(BOOTSTRAP_PAYLOAD_VAR).unwrap_or_default();
    if payload.is_empty() {
        bootstrap_fail(125, "payload executable is missing");
    }
    let arg_count = std::env::var(BOOTSTRAP_ARGC_VAR)
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or_else(|| bootstrap_fail(125, "payload argc is invalid"));
    let mut args = Vec::with_capacity(arg_count);
    for index in 0..arg_count {
        let name = bootstrap_arg_var(index);
        let argument = std::env::var_os(&name)
            .unwrap_or_else(|| bootstrap_fail(125, "payload argv is incomplete"));
        args.push(argument);
    }

    let mut gate_stream = match UnixStream::connect(&gate_path) {
        Ok(stream) => stream,
        Err(error) => {
            // Preserve errno to distinguish resource exhaustion from socket failures.
            let present = Path::new(&gate_path).exists();
            let detail = format!(
                "cannot connect to private payload gate {gate_path:?}: {error} \
                 (socket present from helper view: {present})"
            );
            bootstrap_fail(125, &detail);
        }
    };
    let mut gate = [0_u8; 1];
    if gate_stream.read_exact(&mut gate).is_err() || gate != [1] {
        bootstrap_fail(125, "gate closed before release");
    }
    drop(gate_stream);
    if mount_change(
        "/",
        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
    )
    .is_err()
    {
        bootstrap_fail(124, "cannot make mount propagation private");
    }
    // Masking the parent directory would hide unrelated sockets and profiles.
    if !mask.is_empty() {
        if rustix::mount::mount_bind("/dev/null", mask.as_os_str()).is_err() {
            bootstrap_fail(124, "cannot bind-mask the worker bus socket");
        }
        if rustix::mount::mount_remount(
            mask.as_os_str(),
            rustix::mount::MountFlags::BIND
                | rustix::mount::MountFlags::RDONLY
                | rustix::mount::MountFlags::NOSUID
                | rustix::mount::MountFlags::NODEV
                | rustix::mount::MountFlags::NOEXEC,
            "",
        )
        .is_err()
        {
            bootstrap_fail(124, "cannot make the worker bus mask read-only");
        }
    }
    // A new session cannot escape the systemd cgroup used for stopping the worker.
    if setsid().is_err() {
        bootstrap_fail(124, "setsid failed");
    }
    // Drop bootstrap capabilities so the payload cannot undo the bus mask.
    if rustix::thread::clear_ambient_capability_set().is_err()
        || rustix::thread::set_capabilities(
            None,
            rustix::thread::CapabilitySets {
                effective: rustix::thread::CapabilitySet::empty(),
                permitted: rustix::thread::CapabilitySet::empty(),
                inheritable: rustix::thread::CapabilitySet::empty(),
            },
        )
        .is_err()
    {
        bootstrap_fail(124, "cannot drop bootstrap namespace capabilities");
    }
    let mut payload_command = Command::new(payload);
    payload_command
        .args(args)
        .env_remove(BOOTSTRAP_ACTIVE_VAR)
        .env_remove(BOOTSTRAP_MASK_VAR)
        .env_remove(BOOTSTRAP_GATE_VAR)
        .env_remove(BOOTSTRAP_PAYLOAD_VAR)
        .env_remove(BOOTSTRAP_ARGC_VAR);
    for index in 0..arg_count {
        payload_command.env_remove(bootstrap_arg_var(index));
    }
    let error = payload_command.exec();
    let _ = writeln!(
        std::io::stderr(),
        "odin-worker-bootstrap: payload exec failed: {error}"
    );
    std::process::exit(126);
}

fn bootstrap_fail(code: i32, detail: &str) -> ! {
    let _ = writeln!(std::io::stderr(), "odin-worker-bootstrap: {detail}");
    std::process::exit(code)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::bus_mask_path;
    use crate::worker::WorkerErrorCode;

    #[test]
    fn an_uninspectable_bus_socket_refuses_instead_of_going_unmasked() {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("bus");
        std::fs::write(&socket, b"").unwrap();
        assert_eq!(bus_mask_path(&socket).unwrap(), socket.to_string_lossy());
        assert_eq!(bus_mask_path(&root.path().join("absent")).unwrap(), "");

        let sealed = root.path().join("sealed");
        std::fs::create_dir(&sealed).unwrap();
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o000)).unwrap();
        let hidden = bus_mask_path(&sealed.join("bus"));
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o700)).unwrap();
        if rustix::process::geteuid().is_root() {
            return;
        }
        assert_eq!(hidden.unwrap_err().code(), WorkerErrorCode::Spawn);
    }
}
