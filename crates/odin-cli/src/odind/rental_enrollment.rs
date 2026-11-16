//! Owner-approved, per-lease SSH identity enrollment for offload targets.
use std::{path::Path, process::Stdio};

use odin_registry::{
    ObjectConfig, RentalEnrollment, RentalLeaseState, RentalLeases, RentalTargets, Snapshot,
};
use tokio::io::AsyncReadExt;

use crate::provider_transport;

async fn authenticate(
    root: &Path,
    lease_id: &str,
    identity: &RentalEnrollment,
    identity_file: Option<&str>,
    timeout: std::time::Duration,
) -> Result<(), String> {
    let dir = root.join("rental-known-hosts");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let known = dir.join(lease_id);
    odin_cli::authority_provision::write_private_atomic(
        &known,
        format!("odin-rental-{lease_id} {}\n", identity.known_host).as_bytes(),
    )?;
    let mut command = tokio::process::Command::new("ssh");
    if let Some(path) = identity_file {
        command
            .arg("-i")
            .arg(path)
            .args(["-o", "IdentitiesOnly=yes"]);
    }
    let mut child = command
        .args([
            "-F",
            "/dev/null",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
        ])
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", known.display()))
        .arg("-o")
        .arg(format!("HostKeyAlias=odin-rental-{lease_id}"))
        .arg("-p")
        .arg(identity.ssh_port.to_string())
        .arg(format!("{}@{}", identity.ssh_user, identity.ssh_host))
        .arg("printf 'READY\\n'")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| "could not start SSH".to_owned())?;
    let mut stdout = child.stdout.take().ok_or("missing SSH stdout")?;
    tokio::time::timeout(timeout, async {
        let mut marker = [0; 6];
        stdout
            .read_exact(&mut marker)
            .await
            .map_err(|_| "SSH authentication or remote readiness failed".to_owned())?;
        if &marker != b"READY\n" {
            return Err("unexpected SSH readiness response".into());
        }
        let status = child
            .wait()
            .await
            .map_err(|_| "SSH completion failed".to_owned())?;
        if !status.success() {
            return Err("SSH remote operation failed".into());
        }
        Ok(())
    })
    .await
    .map_err(|_| "SSH operation timed out".to_owned())?
}

/// The caller must obtain owner approval for these exact arguments. Provider listing is
/// used only for routing; the SSH pin is supplied independently by the owner.
pub(crate) async fn enroll(
    root: &Path,
    snapshot: &Snapshot,
    lease_id: &str,
    known_host: &str,
    ssh_user: &str,
    ssh_port: u16,
    target_alias: Option<&str>,
) -> Result<(), String> {
    let lock_root = root.to_owned();
    let lock_id = lease_id.to_owned();
    let _guard =
        tokio::task::spawn_blocking(move || RentalLeases::lock_operation(&lock_root, &lock_id))
            .await
            .map_err(|_| "rental operation lock failed".to_owned())??;
    let lease = RentalLeases::list(root)?
        .into_iter()
        .find(|l| l.id == lease_id)
        .ok_or("unknown lease")?;
    if !matches!(
        lease.state,
        RentalLeaseState::PendingIdentity | RentalLeaseState::Enrolling
    ) || odin_registry::unix_millis() >= lease.expires_ms
    {
        return Err("lease is not eligible for enrollment".into());
    }
    let provider = snapshot
        .objects
        .iter()
        .find_map(|o| match &o.config {
            ObjectConfig::ComputeProvider(p)
                if o.id == lease.provider
                    && p.enabled
                    && p.allowed_projects.contains(&lease.project) =>
            {
                Some(p)
            }
            _ => None,
        })
        .ok_or("provider is unavailable or no longer permits this project")?;
    let key = std::env::var(&provider.key).map_err(|_| "provider credential unavailable")?;
    let servers = provider_transport::list(provider, &key).await?;
    let mut matches = servers
        .iter()
        .filter(|s| s.lease_id == lease.id && Some(s.id.as_str()) == lease.server_id.as_deref());
    let server = matches
        .next()
        .ok_or("provider server identity unavailable")?;
    if matches.next().is_some() || servers.iter().filter(|s| s.lease_id == lease.id).count() != 1 {
        return Err("ambiguous provider server identity".into());
    }
    let host = server
        .ip
        .as_deref()
        .ok_or("provider has not assigned an SSH address")?;
    let ip: std::net::Ipv4Addr = host
        .parse()
        .map_err(|_| "provider SSH address is not IPv4")?;
    if server.ssh_port.is_some_and(|port| port != ssh_port)
        || (server.ssh_port.is_none() && ssh_port != 22)
    {
        return Err("SSH port does not match provider endpoint".into());
    }
    let alias = target_alias.ok_or("SSH target alias is required")?;
    let template = snapshot
        .objects
        .iter()
        .find_map(|o| match &o.config {
            ObjectConfig::ComputeTarget(t) if o.id == alias => Some(t.as_ref()),
            _ => None,
        })
        .ok_or("published target alias unavailable")?;
    if template.control_master.is_some() {
        return Err("rental targets cannot use an existing SSH control master".into());
    }
    let identity = RentalEnrollment {
        server_id: server.id.clone(),
        ssh_host: ip.to_string(),
        ssh_port,
        ssh_user: ssh_user.to_owned(),
        known_host: known_host.to_owned(),
    };
    identity.validate()?;
    // A failed probe has no remote effect and leaves the owner free to correct the pin.
    authenticate(
        root,
        lease_id,
        &identity,
        template.identity_file.as_deref(),
        template.command_timeout(),
    )
    .await?;
    // The reaper must know which target to gate even if registration is interrupted.
    let target = format!("rental-{}", lease.id);
    RentalLeases::bind_enrollment(root, lease_id, identity.clone(), &target, alias)?;
    RentalTargets::register(root, &target, alias, &lease.project, template, &identity)?;
    RentalLeases::enrolled(root, lease_id, &target, alias)?;
    Ok(())
}
