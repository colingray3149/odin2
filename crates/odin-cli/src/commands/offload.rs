//! Interactive, host-key-pinned login for a declared offload target.
use crate::RunStatus;
use clap::{Args, Subcommand};
use odin_registry::{ObjectConfig, RegistryKind, SnapshotStore};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;

#[derive(Debug, Args)]
pub(crate) struct OffloadArgs {
    #[command(subcommand)]
    command: OffloadCommand,
}

#[derive(Debug, Subcommand)]
enum OffloadCommand {
    Login {
        target: String,
        /// Odin state directory containing offload state and registry snapshot.
        #[arg(long)]
        state_root: PathBuf,
        /// Published snapshot, if it is not under the state directory.
        #[arg(long)]
        snapshot: Option<PathBuf>,
    },
}

pub(crate) fn offload_command(
    args: OffloadArgs,
    output: &mut impl Write,
) -> Result<RunStatus, String> {
    let OffloadCommand::Login {
        target,
        state_root,
        snapshot,
    } = args.command;
    let snapshot =
        SnapshotStore::new(snapshot.unwrap_or_else(|| state_root.join("registry/snapshot.json")))
            .load_verified()
            .map_err(|error| error.to_string())?;
    let card = snapshot
        .objects
        .iter()
        .find_map(|object| match &object.config {
            ObjectConfig::ComputeTarget(card)
                if object.id == target
                    && card.enabled
                    && card.kind == RegistryKind::ComputeTarget =>
            {
                Some(card)
            }
            _ => None,
        })
        .ok_or_else(|| format!("{target} is not an enabled compute target"))?;
    if card.control_master.is_none() {
        return Err(format!("{target} does not declare a ControlMaster login"));
    }
    let root = state_root.join("offload");
    let dir = root.join("masters");
    std::fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())?;
    let socket = dir.join(&target);
    let proof = dir.join(format!("{target}.proof"));
    if socket.exists() || proof.exists() {
        return Err(format!(
            "managed login already exists at {}; close it before logging in again",
            socket.display()
        ));
    }
    let known_dir = root.join("known_hosts");
    std::fs::create_dir_all(&known_dir).map_err(|error| error.to_string())?;
    let known = known_dir.join(&target);
    let host_alias = format!("odin-offload-{target}");
    let host_pattern = if card.ssh_port() == 22 {
        host_alias
    } else {
        format!("[{host_alias}]:{}", card.ssh_port())
    };
    odin_cli::authority_provision::write_private_atomic(
        &known,
        format!("{host_pattern} {}\n", card.known_host.trim()).as_bytes(),
    )?;
    let mut ssh = std::process::Command::new("ssh");
    ssh.args([
        "-F",
        "none",
        "-M",
        "-fN",
        "-o",
        "ControlMaster=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
    ])
    .arg("-S")
    .arg(&socket)
    .arg("-o")
    .arg(format!("UserKnownHostsFile={}", known.display()))
    .arg("-o")
    .arg(format!("HostKeyAlias={host_pattern}"));
    ssh.arg("-p").arg(card.ssh_port().to_string());
    if let Some(identity) = &card.identity_file {
        ssh.arg("-i")
            .arg(identity)
            .args(["-o", "IdentitiesOnly=yes"]);
    }
    let status = ssh
        .arg(&card.ssh_host)
        .status()
        .map_err(|error| error.to_string())?;
    if !status.success() {
        return Err(format!("ssh login failed: {status}"));
    }
    let metadata = std::fs::metadata(&socket)
        .map_err(|error| format!("managed socket unavailable: {error}"))?;
    let identity = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        card.ssh_host,
        card.ssh_port(),
        card.known_host.trim(),
        card.identity_file.as_deref().unwrap_or(""),
        metadata.dev(),
        metadata.ino(),
        metadata.ctime(),
        metadata.ctime_nsec()
    );
    odin_cli::authority_provision::write_private_atomic(&proof, identity.as_bytes())?;
    writeln!(output, "managed login established for {target}")
        .map_err(|error| error.to_string())?;
    Ok(RunStatus::Success)
}
