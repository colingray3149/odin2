//! Prepared cloud rental operations. Provider identity is never treated as SSH identity.
use odin_domain::Scope;
use odin_hermes::runtime::rental::RentalRoute;
use odin_kernel::PreparedEffect;
use odin_registry::{
    ComputeProviderToml, ObjectConfig, RentalApproval, RentalApprovals, RentalLease,
    RentalLeaseState, RentalLeases, SnapshotHandle,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{future::Future, path::PathBuf, sync::Arc};

const BOOTSTRAP: &str = "#cloud-config\n";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    provider: String,
    offer: String,
    project: String,
    lane: String,
    hours: u32,
    estimated_usd: f64,
    approved_cap_usd: f64,
    #[serde(default)]
    ssh_key_name: Option<String>,
    dry_run: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Destroy {
    lease_id: String,
    dry_run: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enroll {
    lease_id: String,
    known_host: String,
    ssh_user: String,
    #[serde(default = "ssh_port")]
    ssh_port: u16,
    #[serde(default)]
    target_alias: Option<String>,
}
fn ssh_port() -> u16 {
    22
}

pub(crate) struct DaemonRentalRoute {
    pub root: PathBuf,
    pub pin: Arc<SnapshotHandle>,
    pub runtime: tokio::runtime::Handle,
}

fn scope_matches(scope: &Scope, project: &str, lane: &str) -> Result<(), String> {
    if scope.project.as_ref().map(|v| v.as_str()) != Some(project)
        || scope.lane.as_ref().map(|v| v.as_str()) != Some(lane)
    {
        return Err("rental project and lane must match the admitted scope".into());
    }
    Ok(())
}
fn parse<T: serde::de::DeserializeOwned>(arguments: &Value) -> Result<T, String> {
    serde_json::from_value(arguments.clone()).map_err(|e| e.to_string())
}
fn create_error(error: crate::provider_transport::CreateError) -> String {
    match error {
        crate::provider_transport::CreateError::Refused(s)
        | crate::provider_transport::CreateError::Ambiguous(s) => s,
    }
}

impl DaemonRentalRoute {
    fn provider(&self, id: &str) -> Result<ComputeProviderToml, String> {
        self.pin
            .current()
            .objects
            .iter()
            .find_map(|object| match &object.config {
                ObjectConfig::ComputeProvider(provider) if object.id == id => {
                    Some(provider.as_ref().clone())
                }
                _ => None,
            })
            .ok_or_else(|| "unknown compute provider".into())
    }
    fn lease(&self, id: &str, scope: &Scope) -> Result<RentalLease, String> {
        let lease = RentalLeases::list(&self.root)?
            .into_iter()
            .find(|lease| lease.id == id)
            .ok_or("unknown rental lease")?;
        scope_matches(scope, &lease.project, &lease.lane)?;
        Ok(lease)
    }
    fn create_terms(&self, scope: &Scope, request: &Create) -> Result<ComputeProviderToml, String> {
        scope_matches(scope, &request.project, &request.lane)?;
        let provider = self.provider(&request.provider)?;
        let offer = provider
            .offers
            .get(&request.offer)
            .ok_or("unknown provider offer")?;
        if !provider.enabled
            || !provider.allowed_projects.contains(&request.project)
            || request.hours == 0
            || request.hours > provider.max_lease_hours.get()
            || !offer.usd_per_hour.is_finite()
            || offer.usd_per_hour < 0.0
            || offer.usd_per_hour > provider.max_hourly_usd
        {
            return Err("rental exceeds provider policy".into());
        }
        let price = offer.usd_per_hour * f64::from(request.hours);
        if !request.estimated_usd.is_finite()
            || !request.approved_cap_usd.is_finite()
            || request.estimated_usd != price
            || request.estimated_usd > request.approved_cap_usd
        {
            return Err("published rental price differs from approved terms".into());
        }
        crate::provider_transport::create_request(
            &provider,
            offer,
            "dry-run",
            BOOTSTRAP,
            request.ssh_key_name.as_deref(),
        )
        .map_err(create_error)?;
        Ok(provider)
    }
    fn bridge<T>(&self, future: impl Future<Output = T>) -> T {
        match tokio::runtime::Handle::try_current() {
            Ok(current) => tokio::task::block_in_place(|| current.block_on(future)),
            Err(_) => self.runtime.block_on(future),
        }
    }
}

impl RentalRoute for DaemonRentalRoute {
    fn preflight(&self, capability: &str, scope: &Scope, arguments: &Value) -> Result<(), String> {
        match capability {
            "compute.lease.create" => {
                let request: Create = parse(arguments)?;
                scope_matches(scope, &request.project, &request.lane)
            }
            "compute.lease.destroy" => {
                let request: Destroy = parse(arguments)?;
                self.lease(&request.lease_id, scope)?;
                Ok(())
            }
            "compute.lease.enroll" => {
                let request: Enroll = parse(arguments)?;
                self.lease(&request.lease_id, scope)?;
                Ok(())
            }
            "compute.lease.list" => {
                if arguments != &json!({}) {
                    return Err("list accepts no arguments".into());
                }
                if scope.project.is_none() || scope.lane.is_none() {
                    return Err("rental list requires project and lane scope".into());
                }
                Ok(())
            }
            _ => Err("unknown rental capability".into()),
        }
    }
    fn execute(
        &self,
        effect: &PreparedEffect,
        scope: Scope,
        arguments: Value,
    ) -> Result<Value, odin_omp::host_tools::HostToolError> {
        let capability = effect.contract().id.as_str();
        let tool = match capability {
            "compute.lease.create" => "compute_lease_create",
            "compute.lease.destroy" => "compute_lease_destroy",
            "compute.lease.enroll" => "compute_lease_enroll",
            _ => "compute_lease_list",
        };
        let mut effect_started = false;
        let result: Result<Value, String> = (|| match capability {
            "compute.lease.create" => {
                let request: Create = parse(&arguments)?;
                scope_matches(&scope, &request.project, &request.lane)?;
                let operation = effect.operation_id().to_string();
                if !request.dry_run {
                    if let Some(lease) = RentalLeases::by_operation(&self.root, &operation)? {
                        if lease.provider != request.provider
                            || lease.offer != request.offer
                            || lease.project != request.project
                            || lease.lane != request.lane
                            || lease.expires_ms.saturating_sub(lease.started_ms)
                                != u64::from(request.hours) * 3_600_000
                            || lease.usd_per_hour * f64::from(request.hours)
                                != request.estimated_usd
                        {
                            return Err("operation already bound to different rental terms".into());
                        }
                        return Ok(json!({"dry_run": false, "lease": lease}));
                    }
                }
                let provider = self.create_terms(&scope, &request)?;
                let offer = provider.offers.get(&request.offer).ok_or("unknown offer")?;
                let digest = odin_domain::Digest::hash(operation.as_bytes()).hex();
                let id = format!("lease-{}", &digest[..32]);
                let (url, body) = crate::provider_transport::create_request(
                    &provider,
                    offer,
                    &id,
                    BOOTSTRAP,
                    request.ssh_key_name.as_deref(),
                )
                .map_err(create_error)?;
                if request.dry_run {
                    return Ok(
                        json!({"dry_run": true, "method": "POST", "url": url.as_str(), "body": body}),
                    );
                }
                let key = std::env::var(&provider.key)
                    .ok()
                    .filter(|s| !s.is_empty())
                    .ok_or("provider credential unavailable")?;
                let now = odin_registry::unix_millis();
                let usd = offer.usd_per_hour * f64::from(request.hours);
                let lease = RentalLease {
                    id: id.clone(),
                    operation: operation.clone(),
                    approval_id: operation.clone(),
                    provider: request.provider.clone(),
                    provider_snapshot: Some(provider.clone()),
                    offer: request.offer.clone(),
                    project: request.project.clone(),
                    lane: request.lane.clone(),
                    started_ms: now,
                    expires_ms: now
                        .checked_add(u64::from(request.hours) * 3_600_000)
                        .ok_or("lease expiry overflow")?,
                    usd_per_hour: offer.usd_per_hour,
                    state: RentalLeaseState::Creating,
                    server_id: None,
                    target_id: None,
                    target_alias: None,
                    destroyed_ms: None,
                    enrollment: None,
                };
                RentalApprovals::record(
                    &self.root,
                    RentalApproval {
                        id: operation.clone(),
                        project: request.project,
                        provider: request.provider,
                        hours: request.hours,
                        estimated_usd: request.estimated_usd,
                        approved_cap_usd: request.approved_cap_usd,
                    },
                )?;
                effect_started = true;
                if !RentalApprovals::reserve(&self.root, lease, &provider, request.hours, usd, now)?
                {
                    return Ok(
                        json!({"dry_run": false, "lease": RentalLeases::by_operation(&self.root, &operation)?.ok_or("reserved lease missing")?}),
                    );
                }
                let server = match self.bridge(crate::provider_transport::create(
                    &provider,
                    offer,
                    &key,
                    &id,
                    BOOTSTRAP,
                    request.ssh_key_name.as_deref(),
                )) {
                    Ok(server) => server,
                    Err(crate::provider_transport::CreateError::Refused(reason)) => {
                        RentalApprovals::refused_create(
                            &self.root,
                            &id,
                            &operation,
                            odin_registry::unix_millis(),
                        )?;
                        effect_started = false;
                        return Err(reason);
                    }
                    Err(crate::provider_transport::CreateError::Ambiguous(reason)) => {
                        return Err(reason)
                    }
                };
                RentalLeases::activate(&self.root, &id, &server.id)?;
                Ok(
                    json!({"dry_run": false, "lease": RentalLeases::by_operation(&self.root, &operation)?.ok_or("created lease missing")?}),
                )
            }
            "compute.lease.destroy" => {
                let request: Destroy = parse(&arguments)?;
                let lease = self.lease(&request.lease_id, &scope)?;
                if !request.dry_run && lease.state != RentalLeaseState::Destroyed {
                    effect_started = true;
                    RentalLeases::destroying(&self.root, &lease.id)?;
                }
                Ok(
                    json!({"dry_run": request.dry_run, "lease": self.lease(&request.lease_id, &scope)?}),
                )
            }
            "compute.lease.enroll" => {
                let request: Enroll = parse(&arguments)?;
                self.lease(&request.lease_id, &scope)?;
                let snapshot = self.pin.current();
                effect_started = true;
                self.bridge(crate::rental_enrollment::enroll(
                    &self.root,
                    &snapshot,
                    &request.lease_id,
                    &request.known_host,
                    &request.ssh_user,
                    request.ssh_port,
                    request.target_alias.as_deref(),
                ))?;
                Ok(json!({"lease": self.lease(&request.lease_id, &scope)?}))
            }
            "compute.lease.list" => {
                self.preflight(capability, &scope, &arguments)?;
                let leases: Vec<_> = RentalLeases::list(&self.root)?
                    .into_iter()
                    .filter(|lease| scope_matches(&scope, &lease.project, &lease.lane).is_ok())
                    .collect();
                Ok(json!({"leases": leases}))
            }
            _ => Err("unknown rental capability".into()),
        })();
        result.map_err(|detail| {
            if effect_started {
                odin_omp::host_tools::HostToolError::Uncertain { tool, detail }
            } else {
                odin_omp::host_tools::HostToolError::Unavailable {
                    tool,
                    reason: detail,
                }
            }
        })
    }
}
