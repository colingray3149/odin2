use super::*;

/// Only the transport has NET_ADMIN. Its marked UDP socket is the sole outer
/// packet path; worker/browser processes cannot set that socket mark.
const TRANSPORT_RUN_AS: i64 = 0;
const TRANSPORT_CONTAINER: &str = "transport";
const TUN_VOLUME: &str = "odin-net-tun";
const TUN_HOST_PATH: &str = "/dev/net/tun";

fn transport_security() -> SecurityContext {
    SecurityContext {
        allow_privilege_escalation: Some(false),
        capabilities: Some(Capabilities {
            drop: Some(vec!["ALL".to_owned()]),
            add: Some(vec!["NET_ADMIN".to_owned()]),
        }),
        run_as_non_root: Some(false),
        run_as_user: Some(TRANSPORT_RUN_AS),
        run_as_group: Some(TRANSPORT_RUN_AS),
        read_only_root_filesystem: Some(true),
        ..Default::default()
    }
}

pub(super) fn tun_volume() -> Volume {
    Volume {
        name: TUN_VOLUME.to_owned(),
        host_path: Some(HostPathVolumeSource {
            path: TUN_HOST_PATH.to_owned(),
            type_: Some("CharDevice".to_owned()),
        }),
        ..Default::default()
    }
}
pub(super) fn transport_sidecar(image: &str, argv: &[String]) -> Container {
    Container {
        name: TRANSPORT_CONTAINER.to_owned(),
        restart_policy: Some("Always".to_owned()),
        image: Some(image.to_owned()),
        command: Some(
            argv.iter()
                .map(|arg| crate::job::shell_argv_channel_encoding(arg))
                .collect(),
        ),
        env: Some(vec![EnvVar {
            name: "POD_IP".to_owned(),
            value: None,
            value_from: Some(EnvVarSource {
                field_ref: Some(k8s_openapi::api::core::v1::ObjectFieldSelector {
                    field_path: "status.podIP".to_owned(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        }]),
        volume_mounts: Some(vec![
            VolumeMount {
                name: TUN_VOLUME.to_owned(),
                mount_path: TUN_HOST_PATH.to_owned(),
                read_only: Some(false),
                ..Default::default()
            },
            VolumeMount {
                name: "odin-vpn-ready".to_owned(),
                mount_path: "/run/odin-vpn".to_owned(),
                read_only: Some(false),
                ..Default::default()
            },
        ]),
        resources: Some(bounded_resources(TRANSPORT_RESERVATION)),
        security_context: Some(transport_security()),
        startup_probe: Some(k8s_openapi::api::core::v1::Probe {
            exec: Some(k8s_openapi::api::core::v1::ExecAction {
                command: Some(vec![
                    "/bin/test".to_owned(),
                    "-f".to_owned(),
                    "/run/odin-vpn/ready".to_owned(),
                ]),
            }),
            period_seconds: Some(1),
            failure_threshold: Some(30),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Only the model gateway uses ordinary host DNS. Site pins use the protected resolver.
pub(super) async fn protected_pins(
    plan: &crate::workload::WorkloadPodPlan,
) -> Result<(Vec<std::net::IpAddr>, u16, Vec<std::net::IpAddr>), KubeError> {
    use std::net::IpAddr;
    let (gateway_port, gateway_host) = match plan.agent.as_ref() {
        Some(agent) => (agent.gateway.port, Some(agent.gateway.host.as_str())),
        None => (0, None),
    };
    let mut gateway = Vec::new();
    if let Some(host) = gateway_host {
        if let Ok(address) = host.parse::<IpAddr>() {
            if !address.is_ipv4() {
                return Err(KubeError::rejected(format!(
                    "protected gateway {host} must be IPv4; IPv6 is not a tunnel exception"
                )));
            }
            gateway.push(address);
        } else {
            let resolved = crate::workload::resolve_hosts(
                &[],
                &[plan.agent.as_ref().expect("agent").gateway.clone()],
            )
            .await?;
            gateway.extend(
                resolved
                    .pinned
                    .iter()
                    .flat_map(|(_, addresses)| addresses)
                    .copied(),
            );
            if gateway.iter().any(|address| !address.is_ipv4()) {
                return Err(KubeError::rejected(
                    "protected gateway resolved an IPv6 address; IPv6 is not a tunnel exception"
                        .to_owned(),
                ));
            }
        }
    }
    let mut allow = Vec::new();
    if !plan.network_open {
        let resolver = plan.vpn.as_ref().and_then(|vpn| vpn.resolver.clone());
        for host in &plan.allow_hosts {
            if let Ok(address) = host.parse::<std::net::IpAddr>() {
                if !address.is_ipv4() {
                    return Err(KubeError::rejected(format!(
                        "protected allow_host {host:?} is not IPv4"
                    )));
                }
                allow.push(address);
                continue;
            }
            let Some(resolver) = resolver.as_deref() else {
                return Err(KubeError::rejected(format!(
                    "protected allow_host {host:?} needs the resolved transport lookup; refusing \
                     host DNS"
                )));
            };
            allow.extend(lookup_protected(resolver, host).await?);
        }
    }
    allow.sort();
    allow.dedup();
    Ok((gateway, gateway_port, allow))
}

const LOOKUP_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

/// One protected hostname through the declared lookup. Output is whitespace-separated IPv4.
async fn lookup_protected(resolver: &str, host: &str) -> Result<Vec<std::net::IpAddr>, KubeError> {
    use std::net::IpAddr;
    let output = tokio::time::timeout(
        LOOKUP_BUDGET,
        tokio::process::Command::new(resolver)
            .arg(host)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| {
        KubeError::unavailable(format!(
            "protected lookup of {host:?} exceeded {}s",
            LOOKUP_BUDGET.as_secs()
        ))
    })?
    .map_err(|error| {
        KubeError::unavailable(format!("protected lookup of {host:?} failed: {error}"))
    })?;
    if !output.status.success() {
        return Err(KubeError::rejected(format!(
            "protected lookup of {host:?} exited {}",
            output.status
        )));
    }
    let text = String::from_utf8(output.stdout).map_err(|_| {
        KubeError::rejected(format!("protected lookup of {host:?} returned non-UTF-8"))
    })?;
    let mut addresses = Vec::new();
    for token in text.split_whitespace() {
        let address = token.parse::<IpAddr>().map_err(|_| {
            KubeError::rejected(format!(
                "protected lookup of {host:?} returned {token:?}, not an IPv4 address"
            ))
        })?;
        if !address.is_ipv4() {
            return Err(KubeError::rejected(format!(
                "protected lookup of {host:?} returned IPv6 {address}"
            )));
        }
        addresses.push(address);
    }
    if addresses.is_empty() {
        return Err(KubeError::rejected(format!(
            "protected lookup of {host:?} returned no IPv4 address"
        )));
    }
    Ok(addresses)
}
