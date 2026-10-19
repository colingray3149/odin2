//! Provider routes, embedding protocols, and recovery policies.

use std::collections::BTreeSet;

use odin_domain::{knowledge::EmbeddingModelId, Digest, ProviderId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::object::{ObjectConfig, RegistryKind};
use super::seat::{bind_budget_policy, BudgetPolicyToml, ResolvedBudgetPolicy};
use super::validation::{valid_gateway_model_id, valid_id, validate_recovery_policy_fields};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderToml {
    pub schema: String,
    pub kind: RegistryKind,
    pub enabled: bool,
    pub description: String,
    pub adapter: String,
    pub policy: ProviderPolicyToml,
    /// Absent keeps raw embedding input and output; omit it to preserve canonical declaration hashes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<EmbeddingProtocolToml>,
    pub budget: Option<BudgetPolicyToml>,
    pub recovery: RecoveryPolicyToml,
}

/// Fallback order is declared here; endpoints and credential handles come from the gateway projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderPolicyToml {
    pub routes: Vec<ProviderRouteToml>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRouteToml {
    pub gateway_lane_id: String,
    pub gateway_model_id: String,
}

/// Limit embedding prefix truncation to 64k pinned tokens.
pub const MAX_EMBEDDING_PROTOCOL_TRUNCATE_TOKENS: u32 = 65_536;

/// Apply declared framing and normalization before composing the effective embedding model identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddingProtocolToml {
    /// Compose as gateway_model_id:id; reject separators inside the protocol ID.
    pub id: String,
    pub framing: EmbeddingFramingToml,
    /// Truncate before framing; the pinned tokenizer counts one UTF-8 byte per token.
    pub truncate_tokens: u32,
    pub l2_normalize: bool,
}

/// Write only the declared markers, without an added EOS token or trailing newline.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EmbeddingFramingToml {
    /// `<|im_start|>user\n` + input + `<|im_end|>` (the WeMM chat-im framing).
    ImUserV1,
}

pub const GATEWAY_PROJECTION_SCHEMA: &str = "odin.gateway-projection.v1";

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayProjectionRoute {
    pub gateway_lane_id: String,
    pub gateway_model_id: String,
    /// Opaque account selector, never a credential value.
    pub account_handle: String,
    /// Copy endpoint authority only from the verified gateway projection.
    pub endpoint: String,
    /// Credential lookup name, never secret bytes.
    pub credential_handle: String,
    pub role: String,
    pub affinity_key: String,
    pub eligible: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayProjectionManifest {
    pub schema: String,
    pub projection_digest: Digest,
    pub routes: Vec<GatewayProjectionRoute>,
}
impl GatewayProjectionManifest {
    pub fn build(mut routes: Vec<GatewayProjectionRoute>) -> Result<Self, ProviderPolicyError> {
        validate_projection_routes(&routes)?;
        routes.sort();
        let projection_digest = projection_digest(&routes)?;
        Ok(Self {
            schema: GATEWAY_PROJECTION_SCHEMA.to_owned(),
            projection_digest,
            routes,
        })
    }

    pub fn verify(&self) -> Result<(), ProviderPolicyError> {
        if self.schema != GATEWAY_PROJECTION_SCHEMA {
            return Err(ProviderPolicyError::InvalidProjection(format!(
                "schema must be {GATEWAY_PROJECTION_SCHEMA:?}, found {:?}",
                self.schema
            )));
        }
        validate_projection_routes(&self.routes)?;
        let mut canonical = self.routes.clone();
        canonical.sort();
        if canonical != self.routes {
            return Err(ProviderPolicyError::InvalidProjection(
                "routes must be sorted by stable gateway IDs".to_owned(),
            ));
        }
        let computed = projection_digest(&canonical)?;
        if computed != self.projection_digest {
            return Err(ProviderPolicyError::InvalidProjection(format!(
                "projection digest mismatch: declared {}, computed {}",
                self.projection_digest, computed
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedProviderRoute {
    pub gateway_lane_id: String,
    pub gateway_model_id: String,
    pub account_handle: String,
    pub endpoint: String,
    pub credential_handle: String,
    pub role: String,
    pub affinity_key: String,
    pub priority: u32,
    /// Absent preserves raw embedding behavior and is omitted from canonical serialization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<EmbeddingProtocolToml>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedProviderPolicy {
    pub budget: Option<ResolvedBudgetPolicy>,
    /// Declarations restrict recovery parameters; code determines rung order.
    pub recovery: ResolvedRecoveryPolicy,
    pub provider_id: ProviderId,
    pub registry_revision: u64,
    pub policy_digest: Digest,
    pub projection_digest: Digest,
    pub routes: Vec<ResolvedProviderRoute>,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderPolicyError {
    #[error("provider policy is invalid: {0}")]
    Invalid(String),
    #[error("gateway projection is invalid: {0}")]
    InvalidProjection(String),
    #[error("provider {0} is absent or disabled in registry revision {1}")]
    ProviderUnavailable(ProviderId, u64),
    #[error("provider {provider} declares duplicate gateway route {lane}/{model}")]
    DuplicateRoute {
        provider: ProviderId,
        lane: String,
        model: String,
    },
    #[error("provider {provider} references unknown gateway route {lane}/{model}")]
    UnknownRoute {
        provider: ProviderId,
        lane: String,
        model: String,
    },
    #[error("provider {0} has no eligible declared gateway route")]
    NoEligibleRoute(ProviderId),
    #[error(
        "provider {provider} uses native adapter {adapter:?} and declares no gateway routes; \
         policy resolution does not apply"
    )]
    NativeProvider {
        provider: ProviderId,
        adapter: String,
    },
    #[error("provider policy canonicalization failed: {0}")]
    Canonical(String),
}

/// Preserve declared route order while filtering ineligible gateway projection entries.
pub fn resolve_provider_policy(
    snapshot: &crate::snapshot::Snapshot,
    provider_id: &ProviderId,
    projection: &GatewayProjectionManifest,
) -> Result<ResolvedProviderPolicy, ProviderPolicyError> {
    snapshot
        .verify()
        .map_err(|error| ProviderPolicyError::Canonical(error.to_string()))?;
    let provider = snapshot
        .objects
        .iter()
        .find_map(|object| (object.id == provider_id.as_str()).then_some(&object.config))
        .and_then(|config| match config {
            ObjectConfig::Provider(provider) if provider.enabled => Some(provider.as_ref()),
            _ => None,
        })
        .ok_or_else(|| {
            ProviderPolicyError::ProviderUnavailable(provider_id.clone(), snapshot.revision)
        })?;
    if provider.policy.routes.is_empty() && provider.adapter != "litellm-gateway" {
        return Err(ProviderPolicyError::NativeProvider {
            provider: provider_id.clone(),
            adapter: provider.adapter.clone(),
        });
    }
    projection.verify()?;
    // Validate protocol and composed model IDs before any route can be used.
    let protocol = provider
        .protocol
        .as_ref()
        .map(|protocol| resolve_embedding_protocol(provider_id, protocol, &provider.policy.routes))
        .transpose()?;

    let mut declared = BTreeSet::new();
    let mut routes = Vec::new();
    for (index, route) in provider.policy.routes.iter().enumerate() {
        let key = (
            route.gateway_lane_id.as_str(),
            route.gateway_model_id.as_str(),
        );
        if !declared.insert(key) {
            return Err(ProviderPolicyError::DuplicateRoute {
                provider: provider_id.clone(),
                lane: route.gateway_lane_id.clone(),
                model: route.gateway_model_id.clone(),
            });
        }
        let projected = projection
            .routes
            .iter()
            .find(|candidate| {
                candidate.gateway_lane_id == route.gateway_lane_id
                    && candidate.gateway_model_id == route.gateway_model_id
            })
            .ok_or_else(|| ProviderPolicyError::UnknownRoute {
                provider: provider_id.clone(),
                lane: route.gateway_lane_id.clone(),
                model: route.gateway_model_id.clone(),
            })?;
        if !projected.eligible {
            continue;
        }
        routes.push(ResolvedProviderRoute {
            gateway_lane_id: projected.gateway_lane_id.clone(),
            gateway_model_id: projected.gateway_model_id.clone(),
            account_handle: projected.account_handle.clone(),
            endpoint: projected.endpoint.clone(),
            credential_handle: projected.credential_handle.clone(),
            role: projected.role.clone(),
            affinity_key: projected.affinity_key.clone(),
            priority: u32::try_from(index).map_err(|_| {
                ProviderPolicyError::Canonical(
                    "provider route index cannot be represented as u32".to_owned(),
                )
            })?,
            protocol: protocol.clone(),
        });
    }
    let budget = provider
        .budget
        .as_ref()
        .map(|policy| bind_budget_policy(snapshot.revision, provider_id.as_str(), policy))
        .transpose()
        .map_err(ProviderPolicyError::Invalid)?;
    let recovery =
        resolve_recovery_policy(snapshot.revision, std::slice::from_ref(&provider.recovery))
            .map_err(|error| ProviderPolicyError::Invalid(error.to_string()))?;
    if routes.is_empty() {
        return Err(ProviderPolicyError::NoEligibleRoute(provider_id.clone()));
    }

    #[derive(Serialize)]
    struct BoundPolicy<'a> {
        provider_id: &'a ProviderId,
        registry_revision: u64,
        projection_digest: Digest,
        declared: &'a ProviderPolicyToml,
        resolved: &'a [ResolvedProviderRoute],
        budget: &'a Option<ResolvedBudgetPolicy>,
        recovery: &'a ResolvedRecoveryPolicy,
    }
    let canonical = serde_json::to_vec(&BoundPolicy {
        provider_id,
        registry_revision: snapshot.revision,
        projection_digest: projection.projection_digest,
        declared: &provider.policy,
        resolved: &routes,
        budget: &budget,
        recovery: &recovery,
    })
    .map_err(|error| ProviderPolicyError::Canonical(error.to_string()))?;
    Ok(ResolvedProviderPolicy {
        provider_id: provider_id.clone(),
        registry_revision: snapshot.revision,
        policy_digest: Digest::hash(&canonical),
        projection_digest: projection.projection_digest,
        routes,
        budget,
        recovery,
    })
}

fn resolve_embedding_protocol(
    provider_id: &ProviderId,
    protocol: &EmbeddingProtocolToml,
    routes: &[ProviderRouteToml],
) -> Result<EmbeddingProtocolToml, ProviderPolicyError> {
    if !valid_id(&protocol.id) {
        return Err(ProviderPolicyError::Invalid(format!(
            "provider {provider_id} declares embedding protocol id {:?}: it must be a \
             stable registry identifier, since it composes each route's effective \
             embedding model id as `{{gateway_model_id}}:<protocol id>`",
            protocol.id
        )));
    }
    if protocol.truncate_tokens == 0
        || protocol.truncate_tokens > MAX_EMBEDDING_PROTOCOL_TRUNCATE_TOKENS
    {
        return Err(ProviderPolicyError::Invalid(format!(
            "provider {provider_id} declares embedding protocol {:?} with \
             truncate_tokens {}; the bound must be 1..={MAX_EMBEDDING_PROTOCOL_TRUNCATE_TOKENS} \
             pinned tokens",
            protocol.id, protocol.truncate_tokens
        )));
    }
    for route in routes {
        let effective = format!("{}:{}", route.gateway_model_id, protocol.id);
        if let Err(error) = EmbeddingModelId::new(effective.as_str()) {
            return Err(ProviderPolicyError::Invalid(format!(
                "provider {provider_id} route {}/{:?} under embedding protocol {:?} \
                 composes effective embedding model id {effective:?}: {error}",
                route.gateway_lane_id, route.gateway_model_id, protocol.id
            )));
        }
    }
    Ok(protocol.clone())
}

fn validate_projection_routes(
    routes: &[GatewayProjectionRoute],
) -> Result<(), ProviderPolicyError> {
    let mut keys = BTreeSet::new();
    for route in routes {
        if !valid_id(&route.gateway_lane_id) || !valid_gateway_model_id(&route.gateway_model_id) {
            return Err(ProviderPolicyError::InvalidProjection(format!(
                "gateway route {}/{} must use stable IDs",
                route.gateway_lane_id, route.gateway_model_id
            )));
        }
        if route.account_handle.trim().is_empty()
            || route.credential_handle.trim().is_empty()
            || route.role.trim().is_empty()
            || route.affinity_key.trim().is_empty()
        {
            return Err(ProviderPolicyError::InvalidProjection(format!(
                "gateway route {}/{} has an empty opaque binding field",
                route.gateway_lane_id, route.gateway_model_id
            )));
        }
        if !(route.endpoint.starts_with("http://") || route.endpoint.starts_with("https://"))
            || route.endpoint.chars().any(char::is_whitespace)
            || endpoint_carries_credentials(&route.endpoint)
        {
            return Err(ProviderPolicyError::InvalidProjection(format!(
                "gateway route {}/{} has an invalid HTTP(S) endpoint",
                route.gateway_lane_id, route.gateway_model_id
            )));
        }
        if !keys.insert((&route.gateway_lane_id, &route.gateway_model_id)) {
            return Err(ProviderPolicyError::InvalidProjection(format!(
                "duplicate gateway route {}/{}",
                route.gateway_lane_id, route.gateway_model_id
            )));
        }
    }
    Ok(())
}

/// Reject URL credentials without echoing the endpoint, which could expose a secret.
fn endpoint_carries_credentials(endpoint: &str) -> bool {
    endpoint
        .strip_prefix("http://")
        .or_else(|| endpoint.strip_prefix("https://"))
        .map(|authority| {
            authority
                .split(['/', '?', '#'])
                .next()
                .unwrap_or_default()
                .contains('@')
        })
        .unwrap_or(false)
}

fn projection_digest(routes: &[GatewayProjectionRoute]) -> Result<Digest, ProviderPolicyError> {
    #[derive(Serialize)]
    struct ProjectionPayload<'a> {
        schema: &'static str,
        routes: &'a [GatewayProjectionRoute],
    }
    let bytes = serde_json::to_vec(&ProjectionPayload {
        schema: GATEWAY_PROJECTION_SCHEMA,
        routes,
    })
    .map_err(|error| ProviderPolicyError::Canonical(error.to_string()))?;
    Ok(Digest::hash(&bytes))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryRungToml {
    Retry,
    RestartWorker,
    Checkpoint,
    Rehome,
    Escalate,
}

impl RecoveryRungToml {
    pub const COMPILED_ORDER: [Self; 5] = [
        Self::Retry,
        Self::RestartWorker,
        Self::Checkpoint,
        Self::Rehome,
        Self::Escalate,
    ];
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAttemptLimitsToml {
    pub retry: u32,
    pub restart_worker: u32,
    pub checkpoint: u32,
    pub rehome: u32,
    pub escalate: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCooldownsToml {
    pub retry: u64,
    pub restart_worker: u64,
    pub checkpoint: u64,
    pub rehome: u64,
    pub escalate: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicyToml {
    pub max_attempts: RecoveryAttemptLimitsToml,
    pub cooldown_seconds: RecoveryCooldownsToml,
    pub allowed_rungs: BTreeSet<RecoveryRungToml>,
    pub blocked_missing_decision: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedRecoveryPolicy {
    pub registry_revision: u64,
    pub policy_digest: Digest,
    pub policy: RecoveryPolicyToml,
    /// Filter compiled rung order by the allowed set; declarations cannot reorder it.
    pub filtered_rungs: Vec<RecoveryRungToml>,
}
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RecoveryPolicyError {
    #[error("at least one registry recovery policy is required")]
    Empty,
    #[error("invalid recovery policy: {0}")]
    Invalid(String),
    #[error("recovery policy canonicalization failed: {0}")]
    Canonical(String),
}

/// Narrow with minimum attempt limits, maximum cooldowns, and intersected allowed rungs.
pub fn resolve_recovery_policy(
    registry_revision: u64,
    policies: &[RecoveryPolicyToml],
) -> Result<ResolvedRecoveryPolicy, RecoveryPolicyError> {
    let Some(first) = policies.first() else {
        return Err(RecoveryPolicyError::Empty);
    };
    validate_recovery_policy_fields(first).map_err(RecoveryPolicyError::Invalid)?;
    let mut effective = first.clone();
    for policy in &policies[1..] {
        validate_recovery_policy_fields(policy).map_err(RecoveryPolicyError::Invalid)?;
        if policy.blocked_missing_decision != effective.blocked_missing_decision {
            return Err(RecoveryPolicyError::Invalid(
                "narrowed policies must agree on blocked_missing_decision".to_owned(),
            ));
        }
        effective.max_attempts.retry = effective.max_attempts.retry.min(policy.max_attempts.retry);
        effective.max_attempts.restart_worker = effective
            .max_attempts
            .restart_worker
            .min(policy.max_attempts.restart_worker);
        effective.max_attempts.checkpoint = effective
            .max_attempts
            .checkpoint
            .min(policy.max_attempts.checkpoint);
        effective.max_attempts.rehome = effective
            .max_attempts
            .rehome
            .min(policy.max_attempts.rehome);
        effective.max_attempts.escalate = effective
            .max_attempts
            .escalate
            .min(policy.max_attempts.escalate);
        effective.cooldown_seconds.retry = effective
            .cooldown_seconds
            .retry
            .max(policy.cooldown_seconds.retry);
        effective.cooldown_seconds.restart_worker = effective
            .cooldown_seconds
            .restart_worker
            .max(policy.cooldown_seconds.restart_worker);
        effective.cooldown_seconds.checkpoint = effective
            .cooldown_seconds
            .checkpoint
            .max(policy.cooldown_seconds.checkpoint);
        effective.cooldown_seconds.rehome = effective
            .cooldown_seconds
            .rehome
            .max(policy.cooldown_seconds.rehome);
        effective.cooldown_seconds.escalate = effective
            .cooldown_seconds
            .escalate
            .max(policy.cooldown_seconds.escalate);
        effective.allowed_rungs = effective
            .allowed_rungs
            .intersection(&policy.allowed_rungs)
            .copied()
            .collect();
    }
    if !effective
        .allowed_rungs
        .contains(&RecoveryRungToml::Escalate)
    {
        return Err(RecoveryPolicyError::Invalid(
            "effective recovery policy must retain the compiled terminal escalate rung".to_owned(),
        ));
    }
    let filtered_rungs = RecoveryRungToml::COMPILED_ORDER
        .into_iter()
        .filter(|rung| effective.allowed_rungs.contains(rung))
        .collect::<Vec<_>>();
    #[derive(Serialize)]
    struct RecoveryPayload<'a> {
        registry_revision: u64,
        policy: &'a RecoveryPolicyToml,
        filtered_rungs: &'a [RecoveryRungToml],
    }
    let canonical = serde_json::to_vec(&RecoveryPayload {
        registry_revision,
        policy: &effective,
        filtered_rungs: &filtered_rungs,
    })
    .map_err(|error| RecoveryPolicyError::Canonical(error.to_string()))?;
    Ok(ResolvedRecoveryPolicy {
        registry_revision,
        policy_digest: Digest::hash(&canonical),
        policy: effective,
        filtered_rungs,
    })
}

#[cfg(test)]
mod embedding_protocol_tests {
    use super::*;
    use crate::schema::object::parse_object_toml;
    use crate::snapshot::Snapshot;

    /// A full provider declaration; `routes` is the raw `policy.routes`
    /// line and `protocol` the raw `[protocol]` table (appended last, so
    /// it is a fresh top-level table).
    fn provider_toml(routes: &str, protocol: Option<&str>) -> String {
        let mut toml = format!(
            concat!(
                "schema = \"odin.registry.v1\"\n",
                "kind = \"provider\"\n",
                "enabled = true\n",
                "description = \"embedding protocol fixture\"\n",
                "adapter = \"litellm-gateway\"\n",
                "[policy]\n{}\n",
                "[recovery]\n",
                "allowed_rungs = [\"escalate\"]\n",
                "blocked_missing_decision = \"operator decision required\"\n",
                "[recovery.max_attempts]\n",
                "retry = 0\nrestart_worker = 0\ncheckpoint = 0\nrehome = 0\nescalate = 1\n",
                "[recovery.cooldown_seconds]\n",
                "retry = 0\nrestart_worker = 0\ncheckpoint = 0\nrehome = 0\nescalate = 0\n",
            ),
            routes
        );
        if let Some(protocol) = protocol {
            toml.push_str(protocol);
        }
        toml
    }

    const WEMM_ROUTES: &str =
        "routes = [{ gateway_lane_id = \"wemm-embedding\", gateway_model_id = \"wemm-embedding\" }]";
    const WEMM_PROTOCOL: &str = concat!(
        "\n[protocol]\n",
        "id = \"wemm-im-user-v1\"\n",
        "framing = \"im_user_v1\"\n",
        "truncate_tokens = 256\n",
        "l2_normalize = true\n",
    );

    fn projection(model: &str) -> GatewayProjectionManifest {
        GatewayProjectionManifest::build(vec![GatewayProjectionRoute {
            gateway_lane_id: "wemm-embedding".to_owned(),
            gateway_model_id: model.to_owned(),
            account_handle: "account".to_owned(),
            endpoint: "http://127.0.0.1:4000".to_owned(),
            credential_handle: "litellm-master-key".to_owned(),
            role: "embedding".to_owned(),
            affinity_key: "skuld".to_owned(),
            eligible: true,
        }])
        .expect("fixture projection builds")
    }

    fn resolved(
        routes: &str,
        model: &str,
        protocol: Option<&str>,
    ) -> Result<ResolvedProviderRoute, ProviderPolicyError> {
        let object = parse_object_toml(
            RegistryKind::Provider,
            "brain-embedding",
            "registry/providers/brain-embedding/provider.toml",
            &provider_toml(routes, protocol),
        )
        .expect("fixture provider object");
        let snapshot = Snapshot::build(1, vec![object]).expect("fixture snapshot");
        let policy = resolve_provider_policy(
            &snapshot,
            &ProviderId::new("brain-embedding").expect("provider id"),
            &projection(model),
        )?;
        let [route] = policy.routes.as_slice() else {
            panic!("the fixture declares exactly one route");
        };
        Ok(route.clone())
    }

    #[test]
    fn declared_protocol_parses_every_facet() {
        let object = parse_object_toml(
            RegistryKind::Provider,
            "brain-embedding",
            "registry/providers/brain-embedding/provider.toml",
            &provider_toml(WEMM_ROUTES, Some(WEMM_PROTOCOL)),
        )
        .expect("fixture provider object");
        let ObjectConfig::Provider(provider) = &object.config else {
            panic!("the fixture is a provider");
        };
        let protocol = provider.protocol.as_ref().expect("protocol declared");
        assert_eq!(protocol.id, "wemm-im-user-v1");
        assert_eq!(protocol.framing, EmbeddingFramingToml::ImUserV1);
        assert_eq!(protocol.truncate_tokens, 256);
        assert!(protocol.l2_normalize);
    }

    #[test]
    fn undeclared_protocol_stays_absent_and_canonically_stable() {
        let object = parse_object_toml(
            RegistryKind::Provider,
            "brain-embedding",
            "registry/providers/brain-embedding/provider.toml",
            &provider_toml(WEMM_ROUTES, None),
        )
        .expect("fixture provider object");
        let ObjectConfig::Provider(provider) = &object.config else {
            panic!("the fixture is a provider");
        };
        assert!(
            provider.protocol.is_none(),
            "an absent [protocol] table keeps the raw declaration law"
        );
        let canonical = serde_json::to_string(provider.as_ref()).expect("canonical form");
        assert!(
            !canonical.contains("\"protocol\":"),
            "existing declarations must keep byte-identical canonical digests; \
             got {canonical}"
        );
    }

    #[test]
    fn unknown_protocol_fields_and_framings_refuse_at_parse() {
        let unknown_field = "\n[protocol]\nid = \"p\"\nframing = \"im_user_v1\"\ntruncate_tokens = 256\nl2_normalize = true\nextra = true\n";
        assert!(
            parse_object_toml(
                RegistryKind::Provider,
                "brain-embedding",
                "registry/providers/brain-embedding/provider.toml",
                &provider_toml(WEMM_ROUTES, Some(unknown_field)),
            )
            .is_err(),
            "a [protocol] table with unknown fields must refuse at parse"
        );
        let unknown_framing = "\n[protocol]\nid = \"p\"\nframing = \"bogus\"\ntruncate_tokens = 256\nl2_normalize = true\n";
        assert!(
            parse_object_toml(
                RegistryKind::Provider,
                "brain-embedding",
                "registry/providers/brain-embedding/provider.toml",
                &provider_toml(WEMM_ROUTES, Some(unknown_framing)),
            )
            .is_err(),
            "an unknown framing value must refuse at parse"
        );
    }

    #[test]
    fn declared_protocol_resolves_onto_every_route() {
        let route = resolved(WEMM_ROUTES, "wemm-embedding", Some(WEMM_PROTOCOL))
            .expect("the declared protocol resolves");
        let protocol = route.protocol.as_ref().expect("protocol stamped");
        assert_eq!(protocol.id, "wemm-im-user-v1");
        assert_eq!(protocol.truncate_tokens, 256);
        assert!(protocol.l2_normalize);
    }

    #[test]
    fn undeclared_protocol_resolves_raw_routes() {
        let route = resolved(WEMM_ROUTES, "wemm-embedding", None).expect("the raw route resolves");
        assert!(
            route.protocol.is_none(),
            "an undeclared protocol resolves no protocol onto the route"
        );
    }

    #[test]
    fn protocol_identity_must_satisfy_the_identifier_law() {
        let colon_id = "\n[protocol]\nid = \"wemm-im-user:v1\"\nframing = \"im_user_v1\"\ntruncate_tokens = 256\nl2_normalize = true\n";
        let error = resolved(WEMM_ROUTES, "wemm-embedding", Some(colon_id))
            .expect_err("the `:` composition separator can never appear inside the id");
        assert!(
            matches!(error, ProviderPolicyError::Invalid(_)),
            "the identity refusal must be a typed policy error, got {error:?}"
        );
    }

    #[test]
    fn protocol_truncation_bound_is_validated() {
        for bound in ["0", "65537"] {
            let protocol = format!(
                "\n[protocol]\nid = \"p\"\nframing = \"im_user_v1\"\ntruncate_tokens = {bound}\nl2_normalize = true\n"
            );
            let error = resolved(WEMM_ROUTES, "wemm-embedding", Some(&protocol))
                .expect_err("an out-of-range truncation bound must refuse");
            assert!(
                matches!(error, ProviderPolicyError::Invalid(_)),
                "the truncation refusal must be a typed policy error, got {error:?}"
            );
        }
    }

    #[test]
    fn composed_model_id_must_be_a_valid_embedding_model() {
        let routes = "routes = [{ gateway_lane_id = \"wemm-embedding\", gateway_model_id = \"openai/test-embedding\" }]";
        let error = resolved(routes, "openai/test-embedding", Some(WEMM_PROTOCOL))
            .expect_err("a composed id outside the embedding model charset must refuse");
        match error {
            ProviderPolicyError::Invalid(reason) => {
                assert!(
                    reason.contains("composes effective embedding model id"),
                    "the refusal must name the composition, got {reason:?}"
                );
            }
            other => panic!("the composition refusal must be typed, got {other:?}"),
        }
    }
}
