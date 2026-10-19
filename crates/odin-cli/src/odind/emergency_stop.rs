//! Run emergency stop in a separate user unit so it outlives the daemon it stops.

use odin_domain::huginn as live;

pub(crate) fn start(
    device: live::DeviceId,
    request: &live::EmergencyStopRequest,
) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
    let started = std::process::Command::new("systemd-run")
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
            tracing::error!(
                "emergency stop not started device={device} command={} reason=\"{}\"",
                request.command_id,
                String::from_utf8_lossy(&output.stderr).trim()
            );
            Err(unavailable())
        }
        Err(error) => {
            tracing::error!(
                "emergency stop not started device={device} command={} reason=\"{error}\"",
                request.command_id
            );
            Err(unavailable())
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

fn unavailable() -> live::HuginnProtocolError {
    live::HuginnProtocolError::Unavailable {
        code: "emergencyStop".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn stop_argv_is_the_user_unit_that_execs_ohshit() {
        assert_eq!(
            super::stop_argv(),
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
        );
    }
}
