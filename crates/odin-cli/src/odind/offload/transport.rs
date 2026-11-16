use std::path::PathBuf;

use odin_kube::JobLaunch;
use odin_registry::{ComputeExecutor, ComputeTargetToml, OffloadRuntime, WorkloadProfileToml};

use super::{quote, unit_name, Offload, Transport};

impl Offload {
    fn known_hosts(&self, id: &str, target: &ComputeTargetToml) -> Result<PathBuf, String> {
        let path = self.dir.join("known_hosts").join(id);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let host_alias = format!("odin-offload-{id}");
        let host_pattern = if target.ssh_port() == 22 {
            host_alias
        } else {
            format!("[{host_alias}]:{}", target.ssh_port())
        };
        let line = format!("{host_pattern} {}\n", target.known_host.trim());
        if std::fs::read_to_string(&path).ok().as_deref() != Some(line.as_str()) {
            odin_cli::authority_provision::write_private_atomic(&path, line.as_bytes())?;
        }
        Ok(path)
    }

    fn managed_master(&self, id: &str, target: &ComputeTargetToml) -> Result<PathBuf, String> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let socket = self.dir.join("masters").join(id);
        let metadata = std::fs::symlink_metadata(&socket).map_err(|_| {
            format!("unavailable: run `odin offload login {id} --state-root <odin-state>`")
        })?;
        if !metadata.file_type().is_socket() {
            return Err(format!(
                "unavailable: managed socket for {id} is not a socket"
            ));
        }
        let proof = std::fs::read_to_string(self.dir.join("masters").join(format!("{id}.proof")))
            .map_err(|_| format!("unavailable: managed login for {id} is unverified"))?;
        let expected = format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            target.ssh_host,
            target.ssh_port(),
            target.known_host.trim(),
            target.identity_file.as_deref().unwrap_or(""),
            metadata.dev(),
            metadata.ino(),
            metadata.ctime(),
            metadata.ctime_nsec()
        );
        if proof != expected {
            return Err(format!(
                "unavailable: managed login for {id} no longer matches its host pin"
            ));
        }
        Ok(socket)
    }

    /// ssh options that pin the target's host key and, when declared, its ControlMaster.
    fn ssh_options(&self, id: &str, target: &ComputeTargetToml) -> Result<Vec<String>, String> {
        let known = self.known_hosts(id, target)?;
        // The daemon's user namespace can map root-owned Nix store configs to nobody.
        // Ignore user config while preserving the target's explicit host pin below.
        let mut options: Vec<String> = odin_omp::live::harness::SSH_OPTIONS
            .iter()
            .map(|option| (*option).to_owned())
            .collect();
        options.extend([
            "-T".to_owned(),
            "-p".to_owned(),
            target.ssh_port().to_string(),
            "-o".to_owned(),
            "StrictHostKeyChecking=yes".to_owned(),
            "-o".to_owned(),
            "GlobalKnownHostsFile=/dev/null".to_owned(),
            "-o".to_owned(),
            format!("UserKnownHostsFile={}", known.display()),
            "-o".to_owned(),
            format!(
                "HostKeyAlias={}",
                if target.ssh_port() == 22 {
                    format!("odin-offload-{id}")
                } else {
                    format!("[odin-offload-{id}]:{}", target.ssh_port())
                }
            ),
            "-o".to_owned(),
            match &target.control_master {
                Some(_) => format!("ControlPath={}", self.managed_master(id, target)?.display()),
                None => "ControlPath=none".to_owned(),
            },
            "-o".to_owned(),
            "ControlMaster=no".to_owned(),
        ]);
        if let Some(identity) = &target.identity_file {
            options.extend([
                "-i".to_owned(),
                identity.clone(),
                "-o".to_owned(),
                "IdentitiesOnly=yes".to_owned(),
            ]);
        }
        Ok(options)
    }

    /// Runs `script` with the target's shell and answers its stdout; a failure names stderr.
    pub(super) async fn remote(
        &self,
        id: &str,
        target: &ComputeTargetToml,
        script: &str,
    ) -> Result<String, String> {
        let mut command = match &self.transport {
            Transport::Ssh { ssh, .. } => {
                let mut command = tokio::process::Command::new(ssh);
                command
                    .args(self.ssh_options(id, target)?)
                    .arg(&target.ssh_host)
                    .arg(script);
                command
            }
            #[cfg(test)]
            Transport::Local { path } => {
                let mut command = tokio::process::Command::new("sh");
                let inherited = std::env::var("PATH").unwrap_or_default();
                command
                    .arg("-c")
                    .arg(script)
                    .env("PATH", format!("{}:{inherited}", path.display()));
                command
            }
        };
        command
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true);
        let bound = target.command_timeout();
        let output = tokio::time::timeout(bound, command.output())
            .await
            .map_err(|_| format!("{id}: the command exceeded {}s", bound.as_secs()))?
            .map_err(|error| format!("{id}: ssh did not start: {error}"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let tail: String = stderr.trim().chars().rev().take(300).collect();
            return Err(format!(
                "{id}: exited {:?}: {}",
                output.status.code(),
                tail.chars().rev().collect::<String>()
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Copies `from` to `to`; exactly one side is `host:`-prefixed in the ssh transport.
    pub(super) async fn copy(
        &self,
        id: &str,
        target: &ComputeTargetToml,
        from: &str,
        to: &str,
        remote_from: bool,
    ) -> Result<(), String> {
        let mut command;
        match &self.transport {
            Transport::Ssh { ssh, rsync } => {
                command = tokio::process::Command::new(rsync);
                let shell = std::iter::once(ssh.display().to_string())
                    .chain(self.ssh_options(id, target)?)
                    .collect::<Vec<_>>()
                    .join(" ");
                let remote = |path: &str| format!("{}:{path}", target.ssh_host);
                let (from, to) = if remote_from {
                    (remote(from), to.to_owned())
                } else {
                    (from.to_owned(), remote(to))
                };
                command.arg("-a").arg("-e").arg(shell).arg(from).arg(to);
            }
            #[cfg(test)]
            Transport::Local { .. } => {
                command = tokio::process::Command::new("sh");
                command
                    .arg("-c")
                    .arg("mkdir -p \"$2\" && cp -a \"$1\". \"$2\"")
                    .arg("copy")
                    .arg(from)
                    .arg(to);
            }
        }
        command
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true);
        let output = tokio::time::timeout(target.copy_timeout(), command.output())
            .await
            .map_err(|_| format!("{id}: the copy exceeded its bound"))?
            .map_err(|error| format!("{id}: rsync did not start: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "{id}: rsync exited {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(())
    }

    /// Why `target` cannot take or read runs right now; `None` when it can.
    pub(super) async fn unavailable(&self, id: &str, target: &ComputeTargetToml) -> Option<String> {
        target.control_master.as_ref()?;
        let socket = match self.managed_master(id, target) {
            Ok(socket) => socket,
            Err(error) => return Some(error),
        };
        let alive = match &self.transport {
            Transport::Ssh { ssh, .. } => tokio::process::Command::new(ssh)
                .args(["-F", "none"])
                .arg("-S")
                .arg(socket)
                .arg("-p")
                .arg(target.ssh_port().to_string())
                .args(["-O", "check", &target.ssh_host])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .await
                .is_ok_and(|status| status.success()),
            #[cfg(test)]
            Transport::Local { .. } => true,
        };
        (!alive).then(|| {
            format!("unavailable: run `odin offload login {id} --state-root <odin-state>`")
        })
    }
}

/// The run's whole life on the target: its command under the declared runtime, every line
/// stamped like a pod log, its exit status written last.
pub(super) fn run_script(
    target: &ComputeTargetToml,
    launch: &JobLaunch,
    profile: &WorkloadProfileToml,
    dir: &str,
    deadline_at: i64,
) -> String {
    let argv = launch
        .command
        .iter()
        .chain(&launch.args)
        .map(|arg| quote(arg))
        .collect::<Vec<_>>()
        .join(" ");
    let image = quote(target.image.as_deref().unwrap_or(&profile.image.reference));
    let podman_control = if profile.control.is_some() {
        "-v \"$ODIN_CONTROL:/var/run/odin/control:ro\""
    } else {
        ""
    };
    let apptainer_control = if profile.control.is_some() {
        ",$ODIN_CONTROL:/var/run/odin/control:ro"
    } else {
        ""
    };
    let command = match target.runtime {
        OffloadRuntime::Host => argv,
        OffloadRuntime::Podman => format!(
            "podman run --rm -v \"$ODIN_STAGE:/stage:ro\" -v \"$ODIN_EXPORT:/export\" {podman_control} \
             -e ODIN_RUN_ID -e ODIN_STAGE=/stage -e ODIN_EXPORT=/export {image} {argv}"
        ),
        OffloadRuntime::Apptainer => format!(
            "apptainer exec --bind \"$ODIN_STAGE:/stage:ro,$ODIN_EXPORT:/export{apptainer_control}\" \
             --env ODIN_STAGE=/stage,ODIN_EXPORT=/export {image} {argv}"
        ),
    };
    format!(
        "#!/usr/bin/env bash\n\
         set -uo pipefail\n\
         cd {dir}\n\
         mkdir -p export\n\
         rm -f exit\n\
         export ODIN_RUN_ID={run} ODIN_STAGE={dir}/in ODIN_EXPORT={dir}/export ODIN_CONTROL={dir}/control\n\
         remaining=$(({deadline_at} - $(date +%s)))\n\
         if (( remaining <= 0 )); then echo 124 > exit; exit 124; fi\n\
         stamp() {{ while IFS= read -r line; do printf '%s %s\\n' \"$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)\" \"$line\"; done; }}\n\
         timeout --signal=TERM --kill-after={grace} \"$remaining\" bash -c {command} 2>&1 | stamp >> log\n\
         echo \"${{PIPESTATUS[0]}}\" > exit.tmp && mv exit.tmp exit\n",
        dir = quote(dir),
        run = quote(launch.labels.run_id.as_str()),
        grace = target.stop_grace_seconds.get(),
        command = quote(&command),
    )
}

pub(super) fn submit_script(
    target: &ComputeTargetToml,
    launch: &JobLaunch,
    name: &str,
    dir: &str,
) -> String {
    // submit refuses a launch without one.
    let deadline = launch.deadline_seconds.unwrap_or_default();
    let script = quote(&format!("{dir}/run.sh"));
    match target.executor {
        ComputeExecutor::Ssh => format!(
            "systemd-run --user --quiet --collect --unit={} -p RuntimeMaxSec={deadline} bash {script} && echo ok",
            quote(&unit_name(name))
        ),
        ComputeExecutor::Slurm => {
            let mut flags = vec![
                "--parsable".to_owned(),
                format!("--job-name={}", quote(&format!("odin-{name}"))),
                format!("--chdir={}", quote(dir)),
                format!("--output={}", quote(&format!("{dir}/slurm.out"))),
                format!("--time={}", deadline.div_ceil(60)),
            ];
            if let Some(resources) = launch.workload.as_ref().and_then(|plan| plan.resources) {
                flags.push(format!("--cpus-per-task={}", resources.cpu));
                flags.push(format!("--mem={}M", resources.memory_bytes.div_ceil(1 << 20)));
            }
            if let Some(partition) = &target.partition {
                flags.push(format!("--partition={}", quote(partition)));
            }
            if let Some(account) = &target.account {
                flags.push(format!("--account={}", quote(account)));
            }
            if launch.gpu_count > 0 {
                flags.push(format!("--gres=gpu:{}", launch.gpu_count));
            }
            format!("sbatch {} {script}", flags.join(" "))
        }
    }
}
