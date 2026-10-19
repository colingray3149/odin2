//! Shared parsing keeps daemon TOML and backend JSON configuration consistent; hosts check files.

use std::collections::BTreeMap;
use std::num::{NonZeroU32, NonZeroU64};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::ids::AdapterWireId;
use crate::Digest;
use odin_domain::huginn::OpaqueCredentialHandle;

pub const MIN_REQUEST_TIMEOUT_MS: u64 = 1_000;
pub const MAX_REQUEST_TIMEOUT_MS: u64 = 60_000;
pub const MIN_MAX_RESULTS: u32 = 1;
pub const MAX_MAX_RESULTS: u32 = 20;
pub const MIN_MAX_RESPONSE_BYTES: u64 = 1_024;
pub const MAX_MAX_RESPONSE_BYTES: u64 = 8_388_608;

pub const ADAPTER_BACKEND_CONFIG_SCHEMA: &str = "odin.adapter-backend-config.v1";

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AdapterConfigError {
    #[error("invalid adapter endpoint: {0}")]
    Endpoint(String),
    #[error("invalid adapter credential: {0}")]
    Credential(String),
    #[error("adapter CA bundle path must be absolute")]
    CaBundlePath,
    #[error("adapter bound out of range: {field} {value} not within {low}..={high}")]
    Range {
        field: &'static str,
        value: u64,
        low: u64,
        high: u64,
    },
    #[error("invalid compiled adapter ID: {0}")]
    Key(String),
    #[error("invalid search backend declaration: {0}")]
    Backend(String),
}

fn range(field: &'static str, value: u64, low: u64, high: u64) -> Result<(), AdapterConfigError> {
    if value < low || value > high {
        return Err(AdapterConfigError::Range {
            field,
            value,
            low,
            high,
        });
    }
    Ok(())
}

/// HTTPS or loopback HTTP only; URL normalization makes equality and serialization consistent.
#[derive(Clone, Debug)]
pub struct AdapterEndpoint(url::Url);

impl AdapterEndpoint {
    pub fn parse(value: &str) -> Result<Self, AdapterConfigError> {
        let url = url::Url::parse(value)
            .map_err(|error| AdapterConfigError::Endpoint(error.to_string()))?;
        let loopback = match url.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            _ => false,
        };
        match url.scheme() {
            "https" => {}
            "http" if loopback => {}
            _ => {
                return Err(AdapterConfigError::Endpoint(
                    "scheme must be https, or http to a loopback address".to_owned(),
                ))
            }
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(AdapterConfigError::Endpoint(
                "userinfo is not allowed in adapter endpoints".to_owned(),
            ));
        }
        if url.fragment().is_some() {
            return Err(AdapterConfigError::Endpoint(
                "fragments are not allowed in adapter endpoints".to_owned(),
            ));
        }
        if url.host_str().is_none_or(str::is_empty) {
            return Err(AdapterConfigError::Endpoint(
                "endpoint must name a host".to_owned(),
            ));
        }
        Ok(Self(url))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn is_https(&self) -> bool {
        self.0.scheme() == "https"
    }
}

impl PartialEq for AdapterEndpoint {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_str() == other.0.as_str()
    }
}

impl Eq for AdapterEndpoint {}

impl std::hash::Hash for AdapterEndpoint {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.as_str().hash(state);
    }
}

impl std::fmt::Display for AdapterEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0.as_str())
    }
}

impl Serialize for AdapterEndpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.0.as_str())
    }
}

impl<'de> Deserialize<'de> for AdapterEndpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

/// Only the handle and secret-file path enter configuration, never the credential value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "snake_case",
    try_from = "CredentialRaw"
)]
pub struct AdapterCredential {
    handle: OpaqueCredentialHandle,
    path: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
struct CredentialRaw {
    handle: OpaqueCredentialHandle,
    path: PathBuf,
}

impl TryFrom<CredentialRaw> for AdapterCredential {
    type Error = AdapterConfigError;

    fn try_from(raw: CredentialRaw) -> Result<Self, Self::Error> {
        Self::new(raw.handle, raw.path)
    }
}
impl AdapterCredential {
    pub fn new(handle: OpaqueCredentialHandle, path: PathBuf) -> Result<Self, AdapterConfigError> {
        if !path.is_absolute() {
            return Err(AdapterConfigError::Credential(
                "credential path must be absolute; the backend host owns all further filesystem checks".to_owned(),
            ));
        }
        Ok(Self { handle, path })
    }

    pub fn handle(&self) -> &OpaqueCredentialHandle {
        &self.handle
    }

    pub fn path(&self) -> &std::path::Path {
        self.path.as_path()
    }
}

/// SearXNG needs no credential; Brave requires one.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchBackend {
    Searxng,
    Brave,
}

impl SearchBackend {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Searxng => "searxng",
            Self::Brave => "brave",
        }
    }
}

/// Deserialization checks backend credentials, HTTPS requirements, and single-level fallback.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "snake_case",
    try_from = "DeploymentRaw"
)]
pub struct AdapterDeployment {
    backend: SearchBackend,
    endpoint: AdapterEndpoint,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential: Option<AdapterCredential>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ca_bundle_path: Option<PathBuf>,
    request_timeout_ms: NonZeroU64,
    max_results: NonZeroU32,
    max_response_bytes: NonZeroU64,
    #[serde(skip_serializing_if = "Option::is_none")]
    fallback: Option<Box<AdapterDeployment>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
struct DeploymentRaw {
    backend: SearchBackend,
    endpoint: AdapterEndpoint,
    #[serde(default)]
    credential: Option<AdapterCredential>,
    #[serde(default)]
    ca_bundle_path: Option<PathBuf>,
    request_timeout_ms: NonZeroU64,
    max_results: NonZeroU32,
    max_response_bytes: NonZeroU64,
    #[serde(default)]
    fallback: Option<Box<AdapterDeployment>>,
}

impl TryFrom<DeploymentRaw> for AdapterDeployment {
    type Error = AdapterConfigError;

    fn try_from(raw: DeploymentRaw) -> Result<Self, Self::Error> {
        range(
            "request_timeout_ms",
            raw.request_timeout_ms.get(),
            MIN_REQUEST_TIMEOUT_MS,
            MAX_REQUEST_TIMEOUT_MS,
        )?;
        range(
            "max_results",
            u64::from(raw.max_results.get()),
            u64::from(MIN_MAX_RESULTS),
            u64::from(MAX_MAX_RESULTS),
        )?;
        range(
            "max_response_bytes",
            raw.max_response_bytes.get(),
            MIN_MAX_RESPONSE_BYTES,
            MAX_MAX_RESPONSE_BYTES,
        )?;
        if raw
            .ca_bundle_path
            .as_ref()
            .is_some_and(|path| !path.is_absolute())
        {
            return Err(AdapterConfigError::CaBundlePath);
        }
        match (raw.backend, &raw.credential) {
            (SearchBackend::Brave, None) => {
                return Err(AdapterConfigError::Backend(
                    "brave needs a credential".to_owned(),
                ))
            }
            (SearchBackend::Brave, Some(_)) if !raw.endpoint.is_https() => {
                return Err(AdapterConfigError::Backend(
                    "brave carries a credential, so its endpoint must be https".to_owned(),
                ))
            }
            (SearchBackend::Searxng, Some(_)) => {
                return Err(AdapterConfigError::Backend(
                    "searxng takes no credential".to_owned(),
                ))
            }
            _ => {}
        }
        if raw
            .fallback
            .as_ref()
            .is_some_and(|fallback| fallback.fallback.is_some())
        {
            return Err(AdapterConfigError::Backend(
                "a fallback deployment declares no fallback of its own".to_owned(),
            ));
        }
        Ok(Self {
            backend: raw.backend,
            endpoint: raw.endpoint,
            credential: raw.credential,
            ca_bundle_path: raw.ca_bundle_path,
            request_timeout_ms: raw.request_timeout_ms,
            max_results: raw.max_results,
            max_response_bytes: raw.max_response_bytes,
            fallback: raw.fallback,
        })
    }
}

impl AdapterDeployment {
    pub fn new(
        backend: SearchBackend,
        endpoint: AdapterEndpoint,
        credential: Option<AdapterCredential>,
        request_timeout_ms: NonZeroU64,
        max_results: NonZeroU32,
        max_response_bytes: NonZeroU64,
    ) -> Result<Self, AdapterConfigError> {
        Self::try_from(DeploymentRaw {
            backend,
            endpoint,
            credential,
            ca_bundle_path: None,
            request_timeout_ms,
            max_results,
            max_response_bytes,
            fallback: None,
        })
    }

    /// Add private trust roots without replacing the client's public roots.
    pub fn with_ca_bundle_path(mut self, path: PathBuf) -> Result<Self, AdapterConfigError> {
        if !path.is_absolute() {
            return Err(AdapterConfigError::CaBundlePath);
        }
        self.ca_bundle_path = Some(path);
        Ok(self)
    }

    pub fn with_fallback(self, fallback: Self) -> Result<Self, AdapterConfigError> {
        Self::try_from(DeploymentRaw {
            backend: self.backend,
            endpoint: self.endpoint,
            credential: self.credential,
            ca_bundle_path: self.ca_bundle_path,
            request_timeout_ms: self.request_timeout_ms,
            max_results: self.max_results,
            max_response_bytes: self.max_response_bytes,
            fallback: Some(Box::new(fallback)),
        })
    }

    pub fn backend(&self) -> SearchBackend {
        self.backend
    }

    pub fn fallback(&self) -> Option<&Self> {
        self.fallback.as_deref()
    }

    pub fn endpoint(&self) -> &AdapterEndpoint {
        &self.endpoint
    }

    pub fn credential(&self) -> Option<&AdapterCredential> {
        self.credential.as_ref()
    }

    pub fn ca_bundle_path(&self) -> Option<&std::path::Path> {
        self.ca_bundle_path.as_deref()
    }

    pub fn request_timeout_ms(&self) -> NonZeroU64 {
        self.request_timeout_ms
    }

    pub fn max_results(&self) -> NonZeroU32 {
        self.max_results
    }

    pub fn max_response_bytes(&self) -> NonZeroU64 {
        self.max_response_bytes
    }

    /// Shared canonical hashing keeps backend and host deployment identities consistent.
    pub fn binding_digest(&self) -> Digest {
        let wire = serde_json::to_value(self).expect("deployment facts serialize infallibly");
        let canonical = odin_strict_json::canonicalize(&wire)
            .expect("validated deployment facts canonicalize infallibly");
        Digest::hash(&canonical)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "snake_case",
    try_from = "BackendConfigRaw"
)]
pub struct AdapterBackendConfig {
    adapters: BTreeMap<AdapterWireId, AdapterDeployment>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
struct BackendConfigRaw {
    schema: String,
    adapters: BTreeMap<AdapterWireId, AdapterDeployment>,
}

impl TryFrom<BackendConfigRaw> for AdapterBackendConfig {
    type Error = AdapterConfigError;

    fn try_from(raw: BackendConfigRaw) -> Result<Self, Self::Error> {
        if raw.schema != ADAPTER_BACKEND_CONFIG_SCHEMA {
            return Err(AdapterConfigError::Endpoint(format!(
                "backend config schema must be {ADAPTER_BACKEND_CONFIG_SCHEMA}, found {:?}",
                raw.schema
            )));
        }
        if raw.adapters.is_empty() {
            return Err(AdapterConfigError::Key(
                "backend config must declare at least one adapter".to_owned(),
            ));
        }
        Ok(Self {
            adapters: raw.adapters,
        })
    }
}

impl AdapterBackendConfig {
    pub fn new(
        adapters: BTreeMap<AdapterWireId, AdapterDeployment>,
    ) -> Result<Self, AdapterConfigError> {
        if adapters.is_empty() {
            return Err(AdapterConfigError::Key(
                "backend config must declare at least one adapter".to_owned(),
            ));
        }
        Ok(Self { adapters })
    }

    pub fn adapters(&self) -> &BTreeMap<AdapterWireId, AdapterDeployment> {
        &self.adapters
    }
}

impl Serialize for AdapterBackendConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("AdapterBackendConfig", 2)?;
        state.serialize_field("schema", ADAPTER_BACKEND_CONFIG_SCHEMA)?;
        state.serialize_field("adapters", &self.adapters)?;
        state.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn searxng() -> serde_json::Value {
        json!({
            "backend": "searxng",
            "endpoint": "http://127.0.0.1:8888/search",
            "request_timeout_ms": 5_000,
            "max_results": 10,
            "max_response_bytes": 1_048_576,
        })
    }

    fn brave() -> serde_json::Value {
        json!({
            "backend": "brave",
            "endpoint": "https://api.search.brave.com/res/v1/web/search",
            "credential": { "handle": "cred:brave-search", "path": "/run/secrets/BRAVE_API_KEY" },
            "request_timeout_ms": 15_000,
            "max_results": 10,
            "max_response_bytes": 1_048_576,
        })
    }

    fn parse(value: serde_json::Value) -> Result<AdapterDeployment, serde_json::Error> {
        serde_json::from_value(value)
    }

    #[test]
    fn optional_ca_bundle_is_absolute_and_part_of_the_binding() {
        let public = parse(brave()).unwrap();
        assert!(public.ca_bundle_path().is_none());
        assert!(serde_json::to_value(&public)
            .unwrap()
            .get("ca_bundle_path")
            .is_none());

        let mut configured = brave();
        configured["ca_bundle_path"] = json!("/run/adapter-trust/roots.pem");
        let private = parse(configured.clone()).unwrap();
        assert_eq!(
            private.ca_bundle_path(),
            Some(std::path::Path::new("/run/adapter-trust/roots.pem"))
        );
        assert_eq!(serde_json::to_value(&private).unwrap(), configured);
        assert_ne!(public.binding_digest(), private.binding_digest());
        assert_eq!(
            public
                .with_ca_bundle_path("/run/adapter-trust/roots.pem".into())
                .unwrap(),
            private
        );

        for path in ["", "relative/roots.pem"] {
            let mut invalid = brave();
            invalid["ca_bundle_path"] = json!(path);
            let error = parse(invalid).unwrap_err().to_string();
            assert!(error.contains("adapter CA bundle path must be absolute"));
            assert!(!error.contains("relative/roots.pem"));
            assert!(matches!(
                private.clone().with_ca_bundle_path(path.into()),
                Err(AdapterConfigError::CaBundlePath)
            ));
        }
        for value in [json!(42), json!({}), json!(["/run/roots.pem"])] {
            let mut invalid = brave();
            invalid["ca_bundle_path"] = value;
            assert!(parse(invalid).is_err());
        }
        let config: AdapterBackendConfig = serde_json::from_value(json!({
            "schema": ADAPTER_BACKEND_CONFIG_SCHEMA,
            "adapters": { "web-search": configured },
        }))
        .unwrap();
        assert_eq!(config.adapters().values().next().unwrap(), &private);
    }

    #[test]
    fn fallback_trust_is_independent_and_preserved() {
        let primary = parse(searxng())
            .unwrap()
            .with_ca_bundle_path("/run/primary.pem".into())
            .unwrap();
        let fallback = parse(brave())
            .unwrap()
            .with_ca_bundle_path("/run/fallback.pem".into())
            .unwrap();
        let deployment = primary.with_fallback(fallback).unwrap();
        assert_eq!(
            deployment.ca_bundle_path(),
            Some(std::path::Path::new("/run/primary.pem"))
        );
        assert_eq!(
            deployment.fallback().unwrap().ca_bundle_path(),
            Some(std::path::Path::new("/run/fallback.pem"))
        );
        assert_eq!(
            parse(serde_json::to_value(&deployment).unwrap()).unwrap(),
            deployment
        );
    }

    #[test]
    fn searxng_with_a_brave_fallback_parses_in_declared_order() {
        let mut primary = searxng();
        primary["fallback"] = brave();
        let deployment = parse(primary).unwrap();
        assert_eq!(deployment.backend(), SearchBackend::Searxng);
        assert!(deployment.credential().is_none());
        let fallback = deployment.fallback().unwrap();
        assert_eq!(fallback.backend(), SearchBackend::Brave);
        assert!(fallback.credential().is_some());
    }

    #[test]
    fn plain_http_is_admitted_only_to_loopback() {
        for admitted in ["http://127.0.0.1:8888/search", "http://[::1]:8888/search"] {
            assert!(AdapterEndpoint::parse(admitted).is_ok(), "{admitted}");
        }
        for refused in [
            "http://example.com/search",
            "http://10.77.0.11:8888/search",
            "http://localhost:8888/search",
            "ftp://127.0.0.1/",
        ] {
            assert!(AdapterEndpoint::parse(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn credentials_follow_the_backend() {
        let mut keyless_brave = brave();
        keyless_brave.as_object_mut().unwrap().remove("credential");
        assert!(parse(keyless_brave).is_err());

        let mut keyed_searxng = searxng();
        keyed_searxng["credential"] = brave()["credential"].clone();
        assert!(parse(keyed_searxng).is_err());

        let mut plain_brave = brave();
        plain_brave["endpoint"] = json!("http://127.0.0.1:9/search");
        assert!(parse(plain_brave).is_err());
    }

    #[test]
    fn a_fallback_has_no_fallback_of_its_own() {
        let mut fallback = brave();
        fallback["fallback"] = searxng();
        let mut primary = searxng();
        primary["fallback"] = fallback;
        assert!(parse(primary).is_err());
    }
}
