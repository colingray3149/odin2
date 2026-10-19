use super::*;

/// Site addresses use HTTP/TLS/QUIC ports; pinned targets use their declared TCP port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedEgress {
    pub sites: BTreeMap<String, BTreeSet<IpAddr>>,
    /// An agent pod's model gateway; a terminal pod's kernel bridge and git
    /// mirror; none for a script pod.
    pub pinned: Vec<(WorkloadGatewayTarget, BTreeSet<IpAddr>)>,
}

/// Resolve before admission so an unenforceable allowlist prevents launch.
pub async fn resolve_declared_hosts(plan: &WorkloadPodPlan) -> Result<ResolvedEgress, KubeError> {
    let gateway: Vec<WorkloadGatewayTarget> = plan
        .agent
        .iter()
        .map(|agent| agent.gateway.clone())
        .collect();
    resolve_hosts(&plan.allow_hosts, &gateway).await
}

pub async fn resolve_hosts(
    allow_hosts: &[String],
    pinned: &[WorkloadGatewayTarget],
) -> Result<ResolvedEgress, KubeError> {
    let sites =
        futures_util::future::try_join_all(allow_hosts.iter().map(|host| async move {
            Ok::<_, KubeError>((host.clone(), resolve_host(host).await?))
        }))
        .await?
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let targets = futures_util::future::try_join_all(pinned.iter().map(|target| async move {
        Ok::<_, KubeError>((target.clone(), resolve_gateway_host(&target.host).await?))
    }))
    .await?;
    Ok(ResolvedEgress {
        sites,
        pinned: targets,
    })
}

/// Reject the entire result if any gateway address is unsuitable for pod access.
pub(super) async fn resolve_gateway_host(host: &str) -> Result<BTreeSet<IpAddr>, KubeError> {
    let addresses = resolve_host(host).await?;
    for address in &addresses {
        if let Some(class) = odin_registry::schema::node_gateway_address_class(address) {
            return Err(KubeError::rejected(format!(
                "declared gateway host {host:?} resolves to {address} ({class}); no pod on the \
                 node can reach it"
            )));
        }
    }
    Ok(addresses)
}

const RESOLVE_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

async fn resolve_host(host: &str) -> Result<BTreeSet<IpAddr>, KubeError> {
    let addresses = tokio::time::timeout(RESOLVE_BUDGET, tokio::net::lookup_host((host, 443u16)))
        .await
        .map_err(|_| {
            KubeError::unavailable(format!(
                "declared egress host {host:?} did not resolve within {}s",
                RESOLVE_BUDGET.as_secs()
            ))
        })?
        .map_err(|error| resolve_failure(host, error))?
        .map(|entry| entry.ip())
        .collect::<BTreeSet<IpAddr>>();
    if addresses.is_empty() {
        return Err(KubeError::rejected(format!(
            "declared egress host {host:?} resolves to no address; the allowlist cannot be enforced"
        )));
    }
    Ok(addresses)
}

fn resolve_failure(host: &str, error: std::io::Error) -> KubeError {
    if host_missing(&error) {
        KubeError::rejected(format!(
            "declared egress host {host:?} does not resolve: {error}"
        ))
    } else {
        KubeError::unavailable(format!(
            "declared egress host {host:?} lookup failed: {error}"
        ))
    }
}

/// Missing or malformed names are rejected; resolver I/O failures remain retryable.
fn host_missing(error: &std::io::Error) -> bool {
    if matches!(
        error.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidInput
    ) {
        return true;
    }
    let message = error.to_string().to_ascii_lowercase();
    message.contains("name or service not known")
        || message.contains("no such host")
        || message.contains("nodename nor servname")
        || message.contains("no address associated")
}

/// Allow cluster DNS and resolved IPs only. IP pins cannot enforce hostnames
/// when addresses are shared or DNS changes after resolution.
pub fn egress_rules(resolved: &ResolvedEgress) -> Vec<NetworkPolicyEgressRule> {
    let mut rules = vec![NetworkPolicyEgressRule {
        to: Some(vec![NetworkPolicyPeer {
            namespace_selector: Some(LabelSelector {
                match_labels: Some(BTreeMap::from([(
                    "kubernetes.io/metadata.name".to_owned(),
                    "kube-system".to_owned(),
                )])),
                ..Default::default()
            }),
            pod_selector: Some(LabelSelector {
                match_labels: Some(BTreeMap::from([(
                    "k8s-app".to_owned(),
                    "kube-dns".to_owned(),
                )])),
                ..Default::default()
            }),
            ip_block: None,
        }]),
        ports: Some(vec![
            network_policy_port("UDP", 53),
            network_policy_port("TCP", 53),
        ]),
    }];
    for addresses in resolved.sites.values() {
        for address in addresses {
            rules.push(pinned_address_rule(
                *address,
                EGRESS_TCP_PORTS
                    .iter()
                    .map(|port| network_policy_port("TCP", *port))
                    .chain(
                        EGRESS_UDP_PORTS
                            .iter()
                            .map(|port| network_policy_port("UDP", *port)),
                    )
                    .collect(),
            ));
        }
    }
    for (target, addresses) in &resolved.pinned {
        for address in addresses {
            rules.push(pinned_address_rule(
                *address,
                vec![network_policy_port("TCP", i32::from(target.port))],
            ));
        }
    }
    rules
}

fn pinned_address_rule(address: IpAddr, ports: Vec<NetworkPolicyPort>) -> NetworkPolicyEgressRule {
    let suffix = match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    NetworkPolicyEgressRule {
        to: Some(vec![NetworkPolicyPeer {
            namespace_selector: None,
            pod_selector: None,
            ip_block: Some(IPBlock {
                cidr: format!("{address}/{suffix}"),
                except: None,
            }),
        }]),
        ports: Some(ports),
    }
}

pub(super) fn network_policy_port(protocol: &str, port: i32) -> NetworkPolicyPort {
    NetworkPolicyPort {
        port: Some(IntOrString::Int(port)),
        protocol: Some(protocol.to_owned()),
        end_port: None,
    }
}

/// An empty annotation represents an empty host set, not one empty hostname.
pub(super) fn annotated_scope(annotation: &str) -> BTreeSet<&str> {
    annotation
        .split(',')
        .filter(|host| !host.is_empty())
        .collect()
}

pub(super) fn declared_scope(resolved: &ResolvedEgress) -> Vec<String> {
    let mut scope: Vec<String> = resolved.sites.keys().cloned().collect();
    for (target, _) in &resolved.pinned {
        scope.push(format!("{}:{}", target.host, target.port));
    }
    scope
}

/// Restrict egress without changing ingress; retain declared hosts for scope checks.
pub(crate) fn desired_egress_policy(run_id: &RunId, resolved: &ResolvedEgress) -> NetworkPolicy {
    NetworkPolicy {
        metadata: ObjectMeta {
            name: Some(egress_policy_name(run_id)),
            labels: Some(run_claim_labels(run_id)),
            annotations: Some(BTreeMap::from([(
                DECLARED_HOSTS_ANNOTATION.to_owned(),
                declared_scope(resolved).join(","),
            )])),
            ..Default::default()
        },
        spec: Some(NetworkPolicySpec {
            pod_selector: Some(LabelSelector {
                match_labels: Some(run_claim_labels(run_id)),
                ..Default::default()
            }),
            policy_types: Some(vec!["Egress".to_owned()]),
            egress: Some(egress_rules(resolved)),
            ingress: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn resolve_hosts_joins_literals_and_rejects_invalid_fast() {
        let started = Instant::now();
        let resolved = resolve_hosts(&["127.0.0.1".to_owned(), "127.0.0.2".to_owned()], &[])
            .await
            .expect("literals resolve");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "literal resolution took {:?}",
            started.elapsed()
        );
        let loopback: IpAddr = "127.0.0.1".parse().expect("literal");
        let other: IpAddr = "127.0.0.2".parse().expect("literal");
        assert_eq!(
            resolved.sites.get("127.0.0.1"),
            Some(&BTreeSet::from([loopback]))
        );
        assert_eq!(
            resolved.sites.get("127.0.0.2"),
            Some(&BTreeSet::from([other]))
        );

        let started = Instant::now();
        let error = resolve_host("no-such-host.invalid")
            .await
            .expect_err("invalid must not resolve");
        assert!(
            matches!(error, KubeError::Rejected { .. }),
            "an unresolvable name is rejected, not unavailable: {error:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            ".invalid took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_resolver_blip_is_unavailable_and_a_missing_host_is_rejected() {
        let blip = resolve_failure(
            "example.test",
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Temporary failure in name resolution",
            ),
        );
        assert!(matches!(blip, KubeError::Unavailable { .. }), "{blip:?}");
        let missing = resolve_failure(
            "no-such-host.invalid",
            std::io::Error::other("Name or service not known"),
        );
        assert!(matches!(missing, KubeError::Rejected { .. }), "{missing:?}");
    }
}
