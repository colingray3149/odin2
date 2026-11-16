use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};

/// A protected plan carries site names unresolved: the tunnel, not this host, resolves them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedEgress {
    pub endpoint: IpAddr,
    /// Where the authority forwards the endpoint; a local pod's packets reach policy rewritten.
    pub forwarded: Option<IpAddr>,
    pub port: u16,
    pub allow_hosts: Vec<String>,
}

/// Site addresses use HTTP/TLS/QUIC ports; pinned targets use their declared TCP port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedEgress {
    pub sites: BTreeMap<String, BTreeSet<IpAddr>>,
    /// Declared hosts that did not resolve at launch, with the cause: the pod
    /// cannot reach them, and its brief names them.
    pub unresolved: BTreeMap<String, String>,
    pub pinned: Vec<(WorkloadGatewayTarget, BTreeSet<IpAddr>)>,
    /// Public TCP 80/443 for this run, with non-public ranges excluded.
    pub open: bool,
    /// Set only for a protected plan. Cluster egress is then the tunnel and the gateway.
    pub protected: Option<ProtectedEgress>,
    /// A script pod takes no inbound connections from any peer on the pod overlay.
    pub deny_ingress: bool,
}

/// Resolve before admission; an unresolvable gateway prevents launch.
/// A protected plan never asks the host resolver for site pins: those names
/// travel into the tunnel and resolve there, or the launch fails closed.
pub async fn resolve_declared_hosts(plan: &WorkloadPodPlan) -> Result<ResolvedEgress, KubeError> {
    let gateway: Vec<WorkloadGatewayTarget> = plan.gateway_target().cloned().into_iter().collect();
    if plan.transport == odin_registry::WorkloadTransport::VpnRequired {
        let vpn = plan.vpn.as_ref().ok_or_else(|| {
            KubeError::rejected(
                "vpn-required workload has no resolved transport binding; refusing direct \
                 fallback",
            )
        })?;
        vpn.validate().map_err(KubeError::rejected)?;
        // The gateway stays on the ordinary daemon DNS path. Site names do not.
        let mut resolved = resolve_hosts(&[], &gateway).await?;
        resolved.protected = Some(ProtectedEgress {
            endpoint: vpn.endpoint,
            forwarded: vpn.forwarded,
            port: vpn.port,
            allow_hosts: plan.allow_hosts.clone(),
        });
        return Ok(resolved);
    }
    let mut resolved = resolve_hosts(&plan.allow_hosts, &gateway).await?;
    resolved.open = plan.network_open;
    resolved.deny_ingress = plan.agent.is_none();
    Ok(resolved)
}

/// A declared site that does not resolve is left out of the policy rather
/// than failing the launch: one slow or missing host among many must not
/// sink the pod. Pinned targets must resolve.
pub async fn resolve_hosts(
    allow_hosts: &[String],
    pinned: &[WorkloadGatewayTarget],
) -> Result<ResolvedEgress, KubeError> {
    let mut sites = BTreeMap::new();
    let mut unresolved = BTreeMap::new();
    let lookups = allow_hosts
        .iter()
        .map(|host| async move { (host.clone(), resolve_host(host).await) });
    for (host, result) in futures_util::future::join_all(lookups).await {
        match result {
            Ok(addresses) => {
                sites.insert(host, addresses);
            }
            Err(error) => {
                let cause = error.to_string();
                tracing::warn!("egress host skipped host={host} cause=\"{cause}\"");
                unresolved.insert(host, cause);
            }
        }
    }
    let targets = futures_util::future::try_join_all(pinned.iter().map(|target| async move {
        Ok::<_, KubeError>((target.clone(), resolve_gateway_host(&target.host).await?))
    }))
    .await?;
    Ok(ResolvedEgress {
        deny_ingress: false,
        sites,
        unresolved,
        pinned: targets,
        open: false,
        protected: None,
    })
}

/// The addresses no pod on the node can reach, each as `address (class)`.
pub(super) fn inadmissible_gateway_addresses<'a>(
    addresses: impl IntoIterator<Item = &'a IpAddr>,
) -> Vec<String> {
    addresses
        .into_iter()
        .filter_map(|address| {
            odin_registry::schema::node_gateway_address_class(address)
                .map(|class| format!("{address} ({class})"))
        })
        .collect()
}

/// Reject the entire result if any gateway address is unsuitable for pod access.
pub(super) async fn resolve_gateway_host(host: &str) -> Result<BTreeSet<IpAddr>, KubeError> {
    let addresses = resolve_host(host).await?;
    let inadmissible = inadmissible_gateway_addresses(&addresses);
    if !inadmissible.is_empty() {
        return Err(KubeError::rejected(format!(
            "declared gateway host {host:?} resolves to {}; no pod on the node can reach it",
            inadmissible.join(", ")
        )));
    }
    Ok(addresses)
}

async fn resolve_host(host: &str) -> Result<BTreeSet<IpAddr>, KubeError> {
    let addresses =
        tokio::time::timeout(HOST_LOOKUP_BUDGET, tokio::net::lookup_host((host, 443u16)))
            .await
            .map_err(|error| {
                KubeError::unavailable(format!(
                    "declared egress host {host:?} did not resolve within {}s: {error}",
                    HOST_LOOKUP_BUDGET.as_secs()
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
/// A protected plan admits only the tunnel UDP endpoint and the pinned gateway.
pub fn egress_rules(resolved: &ResolvedEgress) -> Vec<NetworkPolicyEgressRule> {
    if let Some(protected) = &resolved.protected {
        let mut rules: Vec<NetworkPolicyEgressRule> = std::iter::once(protected.endpoint)
            .chain(protected.forwarded)
            .map(|address| {
                pinned_address_rule(
                    address,
                    vec![network_policy_port("UDP", i32::from(protected.port))],
                )
            })
            .collect();
        for (target, addresses) in &resolved.pinned {
            for address in addresses {
                rules.push(pinned_address_rule(
                    *address,
                    vec![network_policy_port("TCP", i32::from(target.port))],
                ));
            }
        }
        return rules;
    }
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
    if resolved.open {
        rules.extend(public_web_rules());
    }
    rules
}

/// Non-public ranges a public-only policy must exclude.
const PUBLIC_EXCEPT_V4: &[(IpAddr, u8)] = &[
    (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8),
    (IpAddr::V4(Ipv4Addr::from_octets([10, 0, 0, 0])), 8),
    (IpAddr::V4(Ipv4Addr::from_octets([100, 64, 0, 0])), 10),
    (IpAddr::V4(Ipv4Addr::from_octets([127, 0, 0, 0])), 8),
    (IpAddr::V4(Ipv4Addr::from_octets([169, 254, 0, 0])), 16),
    (IpAddr::V4(Ipv4Addr::from_octets([172, 16, 0, 0])), 12),
    (IpAddr::V4(Ipv4Addr::from_octets([192, 0, 0, 0])), 24),
    (IpAddr::V4(Ipv4Addr::from_octets([192, 0, 2, 0])), 24),
    (IpAddr::V4(Ipv4Addr::from_octets([192, 88, 99, 0])), 24),
    (IpAddr::V4(Ipv4Addr::from_octets([192, 168, 0, 0])), 16),
    (IpAddr::V4(Ipv4Addr::from_octets([198, 18, 0, 0])), 15),
    (IpAddr::V4(Ipv4Addr::from_octets([198, 51, 100, 0])), 24),
    (IpAddr::V4(Ipv4Addr::from_octets([203, 0, 113, 0])), 24),
    (IpAddr::V4(Ipv4Addr::from_octets([224, 0, 0, 0])), 4),
    (IpAddr::V4(Ipv4Addr::from_octets([240, 0, 0, 0])), 4),
];

const PUBLIC_EXCEPT_V6: &[(IpAddr, u8)] = &[
    (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 128),
    (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 96),
    (IpAddr::V6(Ipv6Addr::LOCALHOST), 128),
    (
        IpAddr::V6(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0)),
        96,
    ),
    (
        IpAddr::V6(Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, 0, 0)),
        48,
    ),
    (IpAddr::V6(Ipv6Addr::new(0x100, 0, 0, 0, 0, 0, 0, 0)), 64),
    (IpAddr::V6(Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0)), 32),
    (
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
        32,
    ),
    (IpAddr::V6(Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0)), 16),
    (IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0)), 7),
    (IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)), 10),
    (IpAddr::V6(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0)), 8),
    (
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x20, 0, 0, 0, 0, 0, 0)),
        28,
    ),
];

fn policy_cidr(address: IpAddr, prefix: u8) -> String {
    format!("{address}/{prefix}")
}

fn public_web_rules() -> Vec<NetworkPolicyEgressRule> {
    let web_ports = EGRESS_TCP_PORTS
        .iter()
        .map(|port| network_policy_port("TCP", *port))
        .collect::<Vec<_>>();
    vec![
        NetworkPolicyEgressRule {
            to: Some(vec![NetworkPolicyPeer {
                namespace_selector: None,
                pod_selector: None,
                ip_block: Some(IPBlock {
                    cidr: policy_cidr(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    except: Some(
                        PUBLIC_EXCEPT_V4
                            .iter()
                            .map(|&(address, prefix)| policy_cidr(address, prefix))
                            .collect(),
                    ),
                }),
            }]),
            ports: Some(web_ports.clone()),
        },
        NetworkPolicyEgressRule {
            to: Some(vec![NetworkPolicyPeer {
                namespace_selector: None,
                pod_selector: None,
                ip_block: Some(IPBlock {
                    cidr: policy_cidr(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
                    except: Some(
                        PUBLIC_EXCEPT_V6
                            .iter()
                            .map(|&(address, prefix)| policy_cidr(address, prefix))
                            .collect(),
                    ),
                }),
            }]),
            ports: Some(web_ports),
        },
    ]
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
                cidr: policy_cidr(address, suffix),
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

/// The declared hosts, resolved or not, so a host that resolves only on a
/// later launch keeps the same scope.
pub(super) fn declared_scope(resolved: &ResolvedEgress) -> Vec<String> {
    let mut scope: Vec<String> = resolved
        .sites
        .keys()
        .chain(resolved.unresolved.keys())
        .chain(
            resolved
                .protected
                .iter()
                .flat_map(|protected| protected.allow_hosts.iter()),
        )
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    for (target, _) in &resolved.pinned {
        scope.push(format!("{}:{}", target.host, target.port));
    }
    if let Some(protected) = &resolved.protected {
        scope.push(format!("vpn:{}:{}", protected.endpoint, protected.port));
    }
    scope
}

/// Restrict egress, and deny all ingress for a script pod; retain declared hosts for scope checks.
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
            policy_types: Some(if resolved.deny_ingress {
                vec!["Egress".to_owned(), "Ingress".to_owned()]
            } else {
                vec!["Egress".to_owned()]
            }),
            egress: Some(egress_rules(resolved)),
            // Ingress listed with no rules admits nothing.
            ingress: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_policies_deny_ingress() {
        let run = RunId::new("run-ingress").unwrap();
        let resolved = |deny_ingress| ResolvedEgress {
            deny_ingress,
            sites: BTreeMap::new(),
            unresolved: BTreeMap::new(),
            pinned: Vec::new(),
            open: false,
            protected: None,
        };
        let spec = desired_egress_policy(&run, &resolved(true)).spec.unwrap();
        assert_eq!(
            spec.policy_types.as_deref(),
            Some(&["Egress".to_owned(), "Ingress".to_owned()][..])
        );
        assert!(spec.ingress.is_none(), "no ingress rule admits anything");
        let agent = desired_egress_policy(&run, &resolved(false)).spec.unwrap();
        assert_eq!(
            agent.policy_types.as_deref(),
            Some(&["Egress".to_owned()][..])
        );
    }

    #[test]
    fn protected_egress_has_no_direct_site_or_cluster_dns_path() {
        let tunnel = "192.0.2.10".parse().unwrap();
        let gateway = "192.0.2.11".parse().unwrap();
        let resolved = ResolvedEgress {
            deny_ingress: false,
            sites: BTreeMap::from([(
                "example.com".to_owned(),
                BTreeSet::from(["93.184.215.14".parse().unwrap()]),
            )]),
            unresolved: BTreeMap::new(),
            pinned: vec![(
                WorkloadGatewayTarget {
                    host: "gateway.example".to_owned(),
                    port: 14000,
                },
                BTreeSet::from([gateway]),
            )],
            open: true,
            protected: Some(ProtectedEgress {
                endpoint: tunnel,
                forwarded: Some("192.168.15.1".parse().expect("forwarded")),
                port: 8421,
                allow_hosts: Vec::new(),
            }),
        };
        assert_eq!(
            egress_rules(&resolved),
            [
                pinned_address_rule(tunnel, vec![network_policy_port("UDP", 8421)]),
                // A pod on the authority meets policy after the host forwarded its tunnel there.
                pinned_address_rule(
                    "192.168.15.1".parse().unwrap(),
                    vec![network_policy_port("UDP", 8421)]
                ),
                pinned_address_rule(gateway, vec![network_policy_port("TCP", 14000)]),
            ]
        );
    }

    #[test]
    fn open_egress_is_public_tcp_only_and_keeps_the_gateway_pin() {
        let gateway = IpAddr::V4(Ipv4Addr::from_octets([100, 91, 122, 102]));
        let resolved = ResolvedEgress {
            deny_ingress: false,
            sites: BTreeMap::new(),
            unresolved: BTreeMap::new(),
            pinned: vec![(
                WorkloadGatewayTarget {
                    host: "gateway.example.net".to_owned(),
                    port: 14000,
                },
                BTreeSet::from([gateway]),
            )],
            open: true,
            protected: None,
        };
        let rules = egress_rules(&resolved);
        assert_eq!(rules.len(), 4, "DNS, gateway, IPv4 and IPv6 rules only");
        assert_eq!(
            rules[1],
            pinned_address_rule(gateway, vec![network_policy_port("TCP", 14000)])
        );
        for (rule, (address, exclusions)) in rules[2..].iter().zip([
            (IpAddr::V4(Ipv4Addr::UNSPECIFIED), PUBLIC_EXCEPT_V4),
            (IpAddr::V6(Ipv6Addr::UNSPECIFIED), PUBLIC_EXCEPT_V6),
        ]) {
            let peers = rule.to.as_ref().expect("public peers");
            assert_eq!(peers.len(), 1);
            let block = peers[0].ip_block.as_ref().expect("public CIDR block");
            assert_eq!(block.cidr, policy_cidr(address, 0));
            assert_eq!(
                block.except,
                Some(
                    exclusions
                        .iter()
                        .map(|&(base, prefix)| policy_cidr(base, prefix))
                        .collect()
                )
            );
            assert_eq!(
                rule.ports,
                Some(vec![
                    network_policy_port("TCP", 80),
                    network_policy_port("TCP", 443),
                ]),
                "open egress is TCP only"
            );
        }
    }
}
