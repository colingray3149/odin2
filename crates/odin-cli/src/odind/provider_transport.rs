//! Provider API transport for leased machines. The caller persists the lease ID before create;
//! an ambiguous create must be reconciled with `list`, never blindly retried.

use std::collections::HashSet;
use std::time::Duration;

use odin_registry::schema::{ComputeOfferToml, ComputeProviderApi, ComputeProviderToml};
use reqwest::{Client, Method, StatusCode, Url};
use serde_json::{json, Value};

const MARKER: &str = "odin-lease";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Server {
    pub id: String,
    pub lease_id: String,
    pub ip: Option<String>,
    /// Runpod's public mapping for container TCP port 22, when assigned. The IP and
    /// port are not an authenticated identity; a per-lease host pin is still required.
    pub ssh_port: Option<u16>,
    /// Present for Runpod: authenticate this proxy as `ssh_host_key` before bootstrap.
    pub ssh_proxy_user: Option<String>,
    pub ssh_host_key: Option<String>,
}

#[derive(Debug)]
pub(crate) enum CreateError {
    Refused(String),
    Ambiguous(String),
}

fn client(provider: &ComputeProviderToml) -> Result<Client, String> {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(
            provider
                .request_timeout_seconds
                .map_or(30, |value| u64::from(value.get())),
        ))
        .build()
        .map_err(|_| "cannot initialize provider client".to_owned())
}

fn base(provider: &ComputeProviderToml) -> Result<Url, String> {
    let default = match provider.api {
        ComputeProviderApi::Hetzner => "https://api.hetzner.cloud/v1/",
        ComputeProviderApi::Lambda => "https://cloud.lambda.ai/api/v1/",
        ComputeProviderApi::Runpod => "https://rest.runpod.io/v1/",
    };
    let mut url = Url::parse(provider.endpoint.as_deref().unwrap_or(default))
        .map_err(|_| "invalid provider endpoint".to_owned())?;
    // Plain HTTP is permitted only for local fake APIs; never send a key over the network.
    let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if (url.scheme() != "https" && !(url.scheme() == "http" && local))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("invalid provider endpoint".to_owned());
    }
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Ok(url)
}

fn endpoint(provider: &ComputeProviderToml, path: &str) -> Result<Url, String> {
    base(provider)?
        .join(path)
        .map_err(|_| "invalid provider endpoint".to_owned())
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 48 && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
}

fn lease_name(lease_id: &str) -> String {
    format!("{MARKER}-{lease_id}")
}

fn id(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::to_owned)
        .or_else(|| value.as_u64().map(|n| n.to_string()))
        .filter(|id| valid_id(id))
}

fn from_server(api: ComputeProviderApi, value: &Value) -> Option<Server> {
    let lease_id = match api {
        ComputeProviderApi::Hetzner => value.pointer("/labels/odin-lease")?.as_str()?,
        ComputeProviderApi::Lambda => value.get("tags")?.as_array()?.iter().find_map(|tag| {
            (tag.get("key")?.as_str()? == MARKER)
                .then(|| tag.get("value")?.as_str())
                .flatten()
        })?,
        ComputeProviderApi::Runpod => value.get("name")?.as_str()?.strip_prefix("odin-lease-")?,
    };
    if !valid_id(lease_id) {
        return None;
    }
    let ip = match api {
        ComputeProviderApi::Hetzner => value.pointer("/public_net/ipv4/ip"),
        ComputeProviderApi::Lambda => value.get("ip"),
        ComputeProviderApi::Runpod => value.get("publicIp"),
    }
    .and_then(Value::as_str)
    .map(str::to_owned);
    let ssh_port = if matches!(api, ComputeProviderApi::Runpod) {
        value
            .pointer("/portMappings/22")
            .and_then(Value::as_u64)
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port != 0)
    } else {
        None
    };
    Some(Server {
        id: id(value.get("id")?)?,
        lease_id: lease_id.to_owned(),
        ip,
        ssh_port,
        ssh_proxy_user: None,
        ssh_host_key: None,
    })
}
// A missing ownership marker is foreign; a present but malformed one is an
// error, not evidence that the resource can be ignored during reconciliation.
fn listed_server(api: ComputeProviderApi, value: &Value) -> Result<Option<Server>, String> {
    let marked = match api {
        ComputeProviderApi::Hetzner => {
            let labels = value
                .get("labels")
                .and_then(Value::as_object)
                .ok_or_else(|| "invalid provider resource labels".to_owned())?;
            labels.contains_key(MARKER)
        }
        ComputeProviderApi::Lambda => {
            let tags = value.get("tags").filter(|tags| !tags.is_null());
            match tags {
                None => false,
                Some(tags) => tags
                    .as_array()
                    .ok_or_else(|| "invalid provider resource tags".to_owned())?
                    .iter()
                    .any(|tag| tag.get("key").and_then(Value::as_str) == Some(MARKER)),
            }
        }
        ComputeProviderApi::Runpod => value
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| "invalid provider resource name".to_owned())?
            .starts_with("odin-lease-"),
    };
    if !marked {
        return Ok(None);
    }
    from_server(api, value)
        .map(Some)
        .ok_or_else(|| "malformed Odin-owned provider resource".to_owned())
}

fn runpod_proxy(provider: &ComputeProviderToml, server: &mut Server) -> Result<(), String> {
    if !matches!(provider.api, ComputeProviderApi::Runpod) {
        return Ok(());
    }
    let ssh = provider
        .runpod_ssh
        .as_ref()
        .ok_or_else(|| "Runpod SSH enrollment not configured".to_owned())?;
    let key = |text: &str| {
        let mut parts = text.split_whitespace();
        parts
            .next()
            .is_some_and(|kind| kind.starts_with("ssh-") || kind.starts_with("ecdsa-"))
            && parts.next().is_some()
            && parts.next().is_none()
    };
    if ssh.account_id.is_empty()
        || !ssh.account_id.bytes().all(|b| b.is_ascii_alphanumeric())
        || !key(&ssh.public_key)
        || !key(&ssh.known_host)
    {
        return Err("invalid Runpod SSH enrollment".into());
    }
    server.ssh_proxy_user = Some(format!("{}-{}", server.id, ssh.account_id));
    server.ssh_host_key = Some(ssh.known_host.clone());
    Ok(())
}

/// Build the actual provider request without sending it or exposing credentials.
pub(crate) fn create_request(
    provider: &ComputeProviderToml,
    offer: &ComputeOfferToml,
    lease_id: &str,
    cloud_init: &str,
    ssh_key_name: Option<&str>,
) -> Result<(Url, Value), CreateError> {
    if !valid_id(lease_id) || cloud_init.is_empty() {
        return Err(CreateError::Refused(
            "invalid lease ID or empty bootstrap".into(),
        ));
    }
    let (path, body) = match provider.api {
        ComputeProviderApi::Hetzner => {
            let mut body = json!({"name": lease_name(lease_id), "server_type": offer.machine,
                "image": offer.image, "user_data": cloud_init, "labels": {"odin-lease": lease_id}});
            if let Some(region) = &offer.region {
                body["location"] = json!(region);
            }
            ("servers", body)
        }
        ComputeProviderApi::Lambda => {
            let region = offer
                .region
                .as_deref()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| CreateError::Refused("Lambda requires a region".into()))?;
            let ssh_key = ssh_key_name
                .filter(|s| !s.is_empty())
                .ok_or_else(|| CreateError::Refused("Lambda requires an SSH key name".into()))?;
            (
                "instance-operations/launch",
                json!({"name": lease_name(lease_id),
                "region_name": region, "instance_type_name": offer.machine,
                "image": {"id": offer.image}, "ssh_key_names": [ssh_key],
                "user_data": cloud_init, "tags": [{"key": MARKER, "value": lease_id}]}),
            )
        }
        ComputeProviderApi::Runpod => {
            let mut check = Server {
                id: "pending".into(),
                lease_id: lease_id.into(),
                ip: None,
                ssh_port: None,
                ssh_proxy_user: None,
                ssh_host_key: None,
            };
            runpod_proxy(provider, &mut check).map_err(CreateError::Refused)?;
            let ssh = provider
                .runpod_ssh
                .as_ref()
                .expect("validated Runpod enrollment");
            let mut body = json!({"name": lease_name(lease_id), "imageName": offer.image,
                "ports": ["22/tcp"], "supportPublicIp": true,
                "env": {"SSH_PUBLIC_KEY": ssh.public_key}});
            if offer.gpus == 0 {
                body["computeType"] = json!("CPU");
                body["cpuFlavorIds"] = json!([offer.machine]);
                body["vcpuCount"] = json!(offer.cores.get());
            } else {
                body["computeType"] = json!("GPU");
                body["gpuTypeIds"] = json!([offer.machine]);
                body["gpuCount"] = json!(offer.gpus);
            }
            if let Some(region) = &offer.region {
                body["dataCenterIds"] = json!([region]);
            }
            ("pods", body)
        }
    };
    Ok((
        endpoint(provider, path).map_err(CreateError::Refused)?,
        body,
    ))
}

fn create_http_error(status: StatusCode) -> CreateError {
    let message = format!("provider create returned HTTP {status}");
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        CreateError::Refused(message)
    } else {
        CreateError::Ambiguous(format!("{message}; reconcile before refund"))
    }
}

/// Send exactly the request returned by `create_request`; callers must persist intent first.
pub(crate) async fn create(
    provider: &ComputeProviderToml,
    offer: &ComputeOfferToml,
    key: &str,
    lease_id: &str,
    cloud_init: &str,
    ssh_key_name: Option<&str>,
) -> Result<Server, CreateError> {
    let (url, body) = create_request(provider, offer, lease_id, cloud_init, ssh_key_name)?;
    let client = client(provider).map_err(CreateError::Refused)?;
    let response = client
        .post(url)
        .bearer_auth(key)
        .json(&body)
        .send()
        .await
        .map_err(|_| {
            CreateError::Ambiguous("provider create request failed; reconcile before retry".into())
        })?;
    let status = response.status();
    if !status.is_success() {
        return Err(create_http_error(status));
    }
    let body: Value = response.json().await.map_err(|_| {
        CreateError::Ambiguous("invalid create response; reconcile before retry".into())
    })?;
    let server = match provider.api {
        ComputeProviderApi::Hetzner => body
            .get("server")
            .and_then(|v| from_server(provider.api, v)),
        ComputeProviderApi::Lambda => {
            body.pointer("/data/instance_ids/0")
                .and_then(id)
                .map(|id| Server {
                    id,
                    lease_id: lease_id.to_owned(),
                    ip: None,
                    ssh_port: None,
                    ssh_proxy_user: None,
                    ssh_host_key: None,
                })
        }
        ComputeProviderApi::Runpod => from_server(provider.api, &body),
    };
    let mut server = server.filter(|s| s.lease_id == lease_id).ok_or_else(|| {
        CreateError::Ambiguous("incomplete create response; reconcile before retry".into())
    })?;
    runpod_proxy(provider, &mut server).map_err(CreateError::Ambiguous)?;
    Ok(server)
}

/// Lists all and only resources bearing Odin's lease ownership marker.
pub(crate) async fn list(provider: &ComputeProviderToml, key: &str) -> Result<Vec<Server>, String> {
    let client = client(provider)?;
    let path = match provider.api {
        ComputeProviderApi::Hetzner => "servers",
        ComputeProviderApi::Lambda => "instances",
        ComputeProviderApi::Runpod => "pods",
    };
    let mut url = endpoint(provider, path)?;
    let mut result = Vec::new();
    let mut seen = HashSet::new();
    loop {
        let response = client
            .get(url.clone())
            .bearer_auth(key)
            .send()
            .await
            .map_err(|_| "provider list request failed".to_owned())?;
        if !response.status().is_success() {
            return Err(format!("provider list returned HTTP {}", response.status()));
        }
        let body: Value = response
            .json()
            .await
            .map_err(|_| "invalid provider list response".to_owned())?;
        let items = match provider.api {
            ComputeProviderApi::Hetzner => body.get("servers"),
            ComputeProviderApi::Lambda => body.get("data"),
            ComputeProviderApi::Runpod => Some(&body),
        }
        .and_then(Value::as_array)
        .ok_or_else(|| "invalid provider list response".to_owned())?;
        for item in items {
            if let Some(mut server) = listed_server(provider.api, item)? {
                if provider.runpod_ssh.is_some() {
                    runpod_proxy(provider, &mut server)?;
                }
                result.push(server);
            }
        }
        // Lambda's unpaginated endpoint returns every instance; Runpod v1 returns an array.
        if !matches!(provider.api, ComputeProviderApi::Hetzner) {
            break;
        }
        let next = body
            .pointer("/meta/pagination/next_page")
            .ok_or_else(|| "missing provider pagination".to_owned())?;
        if next.is_null() {
            break;
        }
        let page = next
            .as_u64()
            .filter(|n| *n > 0)
            .ok_or_else(|| "invalid provider pagination".to_owned())?;
        if !seen.insert(page) {
            return Err("repeated provider pagination".into());
        }
        url.query_pairs_mut()
            .clear()
            .append_pair("page", &page.to_string());
    }
    Ok(result)
}

/// Checks the individual resource before deletion; a list omission is not proof of absence.
/// Other failures, including timeouts, must be retried by reconciliation.
pub(crate) async fn destroy(
    provider: &ComputeProviderToml,
    key: &str,
    server_id: &str,
) -> Result<(), String> {
    if !valid_id(server_id) {
        return Err("invalid provider server ID".into());
    }
    let client = client(provider)?;
    let detail_path = match provider.api {
        ComputeProviderApi::Hetzner => format!("servers/{server_id}"),
        ComputeProviderApi::Lambda => format!("instances/{server_id}"),
        ComputeProviderApi::Runpod => format!("pods/{server_id}"),
    };
    let response = client
        .get(endpoint(provider, &detail_path)?)
        .bearer_auth(key)
        .send()
        .await
        .map_err(|_| "provider resource lookup failed".to_owned())?;
    if response.status() == StatusCode::NOT_FOUND {
        return Ok(());
    }
    if !response.status().is_success() {
        return Err(format!(
            "provider lookup returned HTTP {}",
            response.status()
        ));
    }
    let detail: Value = response
        .json()
        .await
        .map_err(|_| "invalid provider lookup response".to_owned())?;
    let value = match provider.api {
        ComputeProviderApi::Hetzner => detail.get("server"),
        ComputeProviderApi::Lambda => detail.get("data"),
        ComputeProviderApi::Runpod => Some(&detail),
    }
    .ok_or_else(|| "invalid provider lookup response".to_owned())?;
    let server = listed_server(provider.api, value)?
        .ok_or_else(|| "provider resource is not Odin-owned".to_owned())?;
    if server.id != server_id {
        return Err("provider lookup returned a different resource".into());
    }
    if matches!(provider.api, ComputeProviderApi::Lambda)
        && value.get("status").and_then(Value::as_str) == Some("terminated")
    {
        return Ok(());
    }
    if matches!(provider.api, ComputeProviderApi::Lambda)
        && value.get("status").and_then(Value::as_str) == Some("terminating")
    {
        return Err("provider termination is still pending".into());
    }
    let (method, path, body) = match provider.api {
        ComputeProviderApi::Hetzner => (Method::DELETE, format!("servers/{server_id}"), None),
        ComputeProviderApi::Runpod => (Method::DELETE, format!("pods/{server_id}"), None),
        ComputeProviderApi::Lambda => (
            Method::POST,
            "instance-operations/terminate".into(),
            Some(json!({"instance_ids": [server_id]})),
        ),
    };
    let mut request = client
        .request(method, endpoint(provider, &path)?)
        .bearer_auth(key);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request
        .send()
        .await
        .map_err(|_| "provider destroy request failed; reconcile before retry".to_owned())?;
    let status = response.status();
    if status == StatusCode::NOT_FOUND {
        return Ok(());
    }
    if !status.is_success() {
        return Err(format!("provider destroy returned HTTP {status}"));
    }
    // An accepted operation is not proof that billing has stopped. Re-read the
    // individual resource; if it remains, let the reaper retry reconciliation.
    let response = client
        .get(endpoint(provider, &detail_path)?)
        .bearer_auth(key)
        .send()
        .await
        .map_err(|_| "provider termination confirmation failed".to_owned())?;
    if response.status() == StatusCode::NOT_FOUND {
        return Ok(());
    }
    if !response.status().is_success() {
        return Err(format!(
            "provider termination confirmation returned HTTP {}",
            response.status()
        ));
    }
    let detail: Value = response
        .json()
        .await
        .map_err(|_| "invalid provider confirmation response".to_owned())?;
    if matches!(provider.api, ComputeProviderApi::Lambda) {
        let value = detail
            .get("data")
            .ok_or_else(|| "invalid provider confirmation response".to_owned())?;
        let server = listed_server(provider.api, value)?
            .ok_or_else(|| "provider resource is not Odin-owned".to_owned())?;
        if server.id == server_id
            && value.get("status").and_then(Value::as_str) == Some("terminated")
        {
            return Ok(());
        }
    }
    Err("provider termination is still pending".into())
}

#[cfg(test)]
mod refusal_tests {
    use super::*;

    #[test]
    fn only_authentication_and_authorization_failures_are_definite() {
        for status in [StatusCode::UNAUTHORIZED, StatusCode::FORBIDDEN] {
            assert!(matches!(create_http_error(status), CreateError::Refused(_)));
        }
        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::CONFLICT,
            StatusCode::REQUEST_TIMEOUT,
            StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            assert!(matches!(
                create_http_error(status),
                CreateError::Ambiguous(_)
            ));
        }
    }
}
