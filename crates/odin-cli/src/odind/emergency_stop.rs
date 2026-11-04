//! Run emergency stop in a separate user unit so it outlives the daemon it stops.

use odin_domain::huginn as live;

pub(crate) fn start(
    device: live::DeviceId,
    request: &live::EmergencyStopRequest,
) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
    start_with("systemd-run", device, request)
}

fn start_with(
    systemd_run: &str,
    device: live::DeviceId,
    request: &live::EmergencyStopRequest,
) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
    let started = std::process::Command::new(systemd_run)
        .args(stop_argv())
        .stdin(std::process::Stdio::null())
        .output();
    match started {
        Ok(output) if output.status.success() => {
            tracing::info!(
                "emergency stop started device={device} command={}",
                request.command_id
            );
            Ok(live::HuginnResponse::Ack)
        }
        Ok(output) => {
            let reason = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            tracing::error!(
                "emergency stop not started device={device} command={} reason=\"{reason}\"",
                request.command_id
            );
            Err(live::HuginnProtocolError::unavailable(
                "emergencyStop",
                format!("systemd-run {}: {reason}", output.status),
            ))
        }
        Err(error) => {
            tracing::error!(
                "emergency stop not started device={device} command={} reason=\"{error}\"",
                request.command_id
            );
            Err(live::HuginnProtocolError::unavailable(
                "emergencyStop",
                format!("systemd-run: {error}"),
            ))
        }
    }
}

/// `ohshit` in a transient unit of the user manager, whose PATH holds it.
fn stop_argv() -> [&'static str; 8] {
    [
        "--user",
        "--collect",
        "--quiet",
        "--unit=odin-emergency-stop",
        "--",
        "/bin/sh",
        "-c",
        "exec ohshit",
    ]
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn systemd_run(dir: &std::path::Path, body: &str) -> String {
        let path = dir.join("systemd-run");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("script");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("mode");
        path.display().to_string()
    }

    fn stop_request() -> live::EmergencyStopRequest {
        live::EmergencyStopRequest {
            command_id: odin_cli::authority_provision::random_command_uuid().expect("command id"),
        }
    }

    fn device() -> live::DeviceId {
        live::DeviceId::new(uuid::Uuid::new_v4()).expect("device id")
    }

    #[test]
    fn the_stop_runs_in_a_user_unit_that_outlives_the_daemon() {
        let dir = tempfile::tempdir().expect("tempdir");
        let argv = dir.path().join("argv");
        let program = systemd_run(
            dir.path(),
            &format!("printf '%s\\n' \"$@\" > {}", argv.display()),
        );

        let response = start_with(&program, device(), &stop_request()).expect("started");

        assert!(matches!(response, live::HuginnResponse::Ack));
        let argv = std::fs::read_to_string(argv).expect("argv recorded");
        let argv: Vec<&str> = argv.lines().collect();
        assert_eq!(argv[0], "--user");
        assert_eq!(argv.last(), Some(&"exec ohshit"));
    }
}
