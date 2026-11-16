//! Validate declarations with shared field predicates.

use std::collections::BTreeSet;

use odin_domain::knowledge::{EmbeddingBackend, RetrievalMode};
use odin_domain::EffectClass;

use super::capability::{
    ApprovalCardToml, CapabilityApprovalToml, CapabilityToml, HandlerBindingToml, SliceToml,
    SEAT_ASK_EVIDENCE_EXTRACTOR_ID, SEAT_ASK_INPUT_SCHEMA, SEAT_ASK_OUTPUT_SCHEMA,
};
use super::container::{
    valid_registry_hostname_label, ContainerAlertToml, ContainerMonitoringToml,
    ContainerSurfaceDefinitionToml, ContainerSurfaceToml, ContainerToml, ContainerWatchdogToml,
};
use super::node::{HostToml, NodeGatewayEndpoint, NodeToml};
use super::object::{ObjectConfig, RegistryKind, RegistryObject, REGISTRY_SCHEMA};
use super::provider::{ProviderToml, RecoveryPolicyToml, RecoveryRungToml};
use super::seat::{BudgetPolicyToml, LaneToml, ProjectToml, SeatSandboxNetwork, SeatToml};
use super::workload::{
    paths_nest_or_collide, storage_quantity_bytes, valid_digest_pinned_oci_reference,
    valid_pod_path, valid_screen, WorkloadProfileToml, CHECKPOINT_PERCENT_RANGE,
    CONTROL_MAP_LIMIT_BYTES, FORBIDDEN_DATA_HOST_ROOTS, MAX_ROLLOVERS_LIMIT,
    MAX_WORKLOAD_DEADLINE_SECONDS, MIN_WORKLOAD_DEADLINE_SECONDS, RESERVED_POD_PATHS,
    WORKLOAD_BRIEF_MAX_BYTES,
};
use crate::container_identity::{validate_declared_path, ContainerIdentityError};
use crate::{FindingSeverity, RegistryFinding};

mod compute_rules;
mod container_rules;
mod model_validation;
mod project_rules;
mod seat_rules;
mod workload_rules;
use compute_rules::{validate_compute_provider, validate_compute_target};
use container_rules::validate_container;
use model_validation::validate_model_card;
use project_rules::validate_project;
use seat_rules::validate_seat;
use workload_rules::validate_workload;

/// Launch reservation limits: odin-kube enforces these same constants, so published profiles
/// never promise unsupported resources.
pub mod odin_kube_bounds {
    pub const MAX_CONTAINER_GPU_COUNT: u32 = 8;
    pub const MIN_CONTAINER_DEADLINE_SECONDS: u32 = 30;
    pub const MAX_CONTAINER_DEADLINE_SECONDS: u32 = 3_600;
}

pub fn validate_object(object: &RegistryObject) -> Vec<RegistryFinding> {
    let mut findings = Vec::new();
    if !valid_id(&object.id) {
        findings.push(fail(
            object,
            "registry-object-id",
            "folder name must match [A-Za-z0-9][A-Za-z0-9._-]*",
        ));
    }
    match &object.config {
        ObjectConfig::Seat(value) => validate_seat(object, value, &mut findings),
        ObjectConfig::Project(value) => validate_project(object, value, &mut findings),
        ObjectConfig::Lane(value) => validate_lane(object, value, &mut findings),
        ObjectConfig::Model(value) => validate_model_card(object, value, &mut findings),
        ObjectConfig::Node(value) => validate_node(object, value, &mut findings),
        ObjectConfig::Provider(value) => validate_provider(object, value, &mut findings),
        ObjectConfig::Capability(value) => validate_capability(object, value, &mut findings),
        ObjectConfig::Slice(value) => validate_slice(object, value, &mut findings),
        ObjectConfig::Container(value) => validate_container(object, value, &mut findings),
        ObjectConfig::Host(value) => validate_host(object, value, &mut findings),
        ObjectConfig::Workload(value) => validate_workload(object, value, &mut findings),
        ObjectConfig::ClaudeCode(value) => validate_common(
            object,
            &value.schema,
            value.kind,
            &value.description,
            &mut findings,
        ),
        ObjectConfig::Routine(value) => validate_routine(object, value, &mut findings),
        ObjectConfig::Harness(value) => {
            validate_common(
                object,
                &value.schema,
                value.kind,
                &value.description,
                &mut findings,
            );
            for problem in value.check() {
                findings.push(fail(object, "harness-shape", problem));
            }
        }
        ObjectConfig::Environment(value) => {
            validate_common(
                object,
                &value.schema,
                value.kind,
                &value.description,
                &mut findings,
            );
            for problem in value.check() {
                findings.push(fail(object, "environment-shape", problem));
            }
        }
        ObjectConfig::ContextProfile(value) => {
            validate_common(
                object,
                &value.schema,
                value.kind,
                &value.description,
                &mut findings,
            );
            if let Err(problem) = value.check() {
                findings.push(fail(object, "context-profile-shape", problem));
            }
        }
        ObjectConfig::Toolset(value) => validate_common(
            object,
            &value.schema,
            value.kind,
            &value.description,
            &mut findings,
        ),
        ObjectConfig::Feature(value) => validate_feature(object, value, &mut findings),
        ObjectConfig::ComputeTarget(value) => validate_compute_target(object, value, &mut findings),
        ObjectConfig::ComputeProvider(value) => {
            validate_compute_provider(object, value, &mut findings)
        }
        ObjectConfig::BrainRole(value) => {
            validate_common(
                object,
                &value.schema,
                value.kind,
                &value.description,
                &mut findings,
            );
            if object.id != value.role.as_str() {
                findings.push(fail(
                    object,
                    "brain-role-id",
                    format!("folder name must be the role, {:?}", value.role.as_str()),
                ));
            }
            for problem in value.check() {
                findings.push(fail(object, "brain-role-shape", problem));
            }
        }
    }
    findings
}

fn validate_feature(
    object: &RegistryObject,
    value: &super::feature::FeatureToml,
    findings: &mut Vec<RegistryFinding>,
) {
    validate_common(
        object,
        &value.schema,
        value.kind,
        &value.description,
        findings,
    );
    if value.title.trim().is_empty() {
        findings.push(fail(
            object,
            "feature-title",
            format!("feature {:?}: title must be nonempty", object.id),
        ));
    }
    if value.probes.is_empty() {
        findings.push(fail(
            object,
            "feature-probes",
            format!(
                "feature {:?}: a service row names at least one probe",
                object.id
            ),
        ));
    }
    validate_probes(object, "feature", &value.probes, findings);
}

/// Every probe parses and none repeats; `owner` names the declaration in each message.
fn validate_probes(
    object: &RegistryObject,
    owner: &str,
    probes: &[String],
    findings: &mut Vec<RegistryFinding>,
) {
    let mut seen: Vec<super::feature::Probe> = Vec::new();
    for probe in probes {
        match super::feature::Probe::parse(probe) {
            Ok(parsed) if seen.contains(&parsed) => findings.push(fail(
                object,
                "probe-repeated",
                format!(
                    "{owner} {:?}: probe {probe:?} is declared more than once",
                    object.id
                ),
            )),
            Ok(parsed) => seen.push(parsed),
            Err(problem) => findings.push(fail(
                object,
                "probe-shape",
                format!("{owner} {:?}: {problem}", object.id),
            )),
        }
    }
}

/// A declared card is the card preview of an owner approval, and each placeholder and field is a JSON pointer.
fn validate_approval_card(
    object: &RegistryObject,
    value: &CapabilityToml,
    card: &ApprovalCardToml,
    findings: &mut Vec<RegistryFinding>,
) {
    if value.preview != Some(super::PreviewKindToml::Card)
        || value.approval_policy != CapabilityApprovalToml::Operator
    {
        findings.push(fail(
            object,
            "capability-approval-card",
            "approval_card requires preview = \"card\" and approval_policy = \"operator\"; only an owner approval shows it",
        ));
    }
    if card.title.trim().is_empty() {
        findings.push(fail(
            object,
            "capability-approval-card",
            "approval_card.title is empty",
        ));
    }
    for pointer in card
        .title_pointers()
        .chain(card.fields.iter().map(String::as_str))
    {
        if !pointer.starts_with('/') {
            findings.push(fail(
                object,
                "capability-approval-card",
                format!("approval_card pointer {pointer:?} must start with /"),
            ));
        }
    }
}

/// Each test names `<binary-id> <test-name>` once; an enabled capability with none is flagged untested.
fn validate_capability_evidence(
    object: &RegistryObject,
    value: &CapabilityToml,
    findings: &mut Vec<RegistryFinding>,
) {
    let mut seen = BTreeSet::new();
    for test in &value.tests {
        if test.split_whitespace().count() != 2 || test.trim() != test {
            findings.push(fail(
                object,
                "capability-test-shape",
                format!(
                    "capability {:?}: test {test:?} must be \"<binary-id> <test-name>\" as the gate's JUnit report names it",
                    object.id
                ),
            ));
        } else if !seen.insert(test.as_str()) {
            findings.push(fail(
                object,
                "capability-test-repeated",
                format!(
                    "capability {:?}: test {test:?} is declared more than once",
                    object.id
                ),
            ));
        }
    }
    validate_probes(object, "capability", &value.probes, findings);
    if value.enabled && value.tests.is_empty() {
        findings.push(RegistryFinding::flag(
            "capability-untested",
            &object.relative_config,
            "enabled capability names no test that proves it; Capabilities shows it gray until `tests` does",
        ));
    }
}

pub(super) fn validate_common(
    object: &RegistryObject,
    schema: &str,
    declared_kind: RegistryKind,
    description: &str,
    findings: &mut Vec<RegistryFinding>,
) {
    if schema != REGISTRY_SCHEMA {
        findings.push(fail(
            object,
            "registry-schema-version",
            format!("schema must be {REGISTRY_SCHEMA:?}, found {schema:?}"),
        ));
    }
    if declared_kind != object.kind() {
        findings.push(fail(
            object,
            "registry-kind-mismatch",
            format!(
                "folder kind is {:?}, config declares {:?}",
                object.kind().as_str(),
                declared_kind.as_str()
            ),
        ));
    }
    require_nonempty(object, "description", description, findings);
}

pub(crate) fn valid_brain_scope(source: &str) -> bool {
    source.starts_with("atlas.")
        || source.starts_with(odin_domain::knowledge::ARCHIVE_SOURCE_NAMESPACE)
        || source
            .strip_prefix("memory.")
            .is_some_and(|seat| odin_domain::SeatId::new(seat).is_ok())
        || matches!(
            source,
            "state.registry" | "state.live" | "state.tasks" | "state.repos" | "ops.history"
        )
}

fn validate_lane(object: &RegistryObject, value: &LaneToml, findings: &mut Vec<RegistryFinding>) {
    validate_common(
        object,
        &value.schema,
        value.kind,
        &value.description,
        findings,
    );
    require_nonempty(object, "project", value.project.as_str(), findings);
    require_nonempty(
        object,
        "default_seat",
        value.default_seat.as_str(),
        findings,
    );
    match (value.direction, value.payload_kind) {
        (Some(_), Some(_)) | (None, None) => {}
        _ => findings.push(fail(
            object,
            "lane-transfer-pair",
            "direction and payload_kind must be declared together",
        )),
    }
}

fn validate_node(object: &RegistryObject, value: &NodeToml, findings: &mut Vec<RegistryFinding>) {
    validate_common(
        object,
        &value.schema,
        value.kind,
        &value.description,
        findings,
    );
    require_allowed(
        object,
        "role",
        &value.role,
        &["control", "worker", "gateway"],
        findings,
    );
    if !valid_id(&value.host) {
        findings.push(fail(
            object,
            "node-host-id",
            "host must be a stable registry host ID",
        ));
    }
    for capability in &value.capabilities {
        require_nonempty(object, "capabilities", capability, findings);
    }
    for root in &value.data_roots {
        if !valid_pod_path(root)
            || FORBIDDEN_DATA_HOST_ROOTS
                .iter()
                .any(|forbidden| std::path::Path::new(root).starts_with(forbidden))
        {
            findings.push(fail(
                object,
                "node-data-root",
                format!(
                    "data root {root:?} must be a normalized absolute path outside {}",
                    FORBIDDEN_DATA_HOST_ROOTS.join(", ")
                ),
            ));
        }
    }
    if let Some(gpu) = &value.gpu {
        if gpu.count == 0 || gpu.vram_gib == 0 || !valid_registry_hostname_label(&gpu.model) {
            findings.push(fail(
                object,
                "node-gpu",
                "gpu needs count and vram_gib of at least 1 and a label-safe model slug",
            ));
        }
        if !value.capabilities.contains("cuda") {
            findings.push(fail(
                object,
                "node-gpu",
                "a node declaring gpu must declare the cuda capability",
            ));
        }
    }
    if value.external && (value.authoritative_state || value.role != "worker") {
        findings.push(fail(
            object,
            "node-external",
            "an external node is a worker and never holds authoritative_state",
        ));
    }
    if value
        .cost
        .is_some_and(|cost| !cost.usd_per_hour.is_finite() || cost.usd_per_hour < 0.0)
    {
        findings.push(fail(
            object,
            "node-cost",
            "cost.usd_per_hour must be a finite, non-negative price",
        ));
    }
    if let Some(yielding) = &value.yield_to {
        if yielding.modes.is_empty()
            || yielding.modes.iter().any(|mode| !valid_id(mode))
            || yielding.stale_hours == Some(0)
        {
            findings.push(fail(
                object,
                "node-yield",
                "[yield] modes are one or more mode names, and stale_hours is at least 1",
            ));
        }
    }
    if value.authoritative_state && !value.enabled {
        findings.push(fail(
            object,
            "node-disabled-authority",
            "a disabled node cannot hold authoritative_state",
        ));
    }
    match &value.gateway_endpoint {
        Some(endpoint) => {
            if let Err(error) = NodeGatewayEndpoint::parse(endpoint) {
                findings.push(fail(object, "node-gateway-endpoint", error.to_string()));
            }
        }
        None => {
            // Reject missing gateway endpoints at publication rather than at workload launch.
            if value.enabled && value.allow_workloads {
                findings.push(fail(
                    object,
                    "node-gateway-endpoint",
                    "an enabled node that admits workloads must declare gateway_endpoint (one \
                     absolute http(s) URI: scheme, reachable host, effective TCP port, API base \
                     path)",
                ));
            }
        }
    }
}

fn validate_provider(
    object: &RegistryObject,
    value: &ProviderToml,
    findings: &mut Vec<RegistryFinding>,
) {
    validate_common(
        object,
        &value.schema,
        value.kind,
        &value.description,
        findings,
    );
    require_nonempty(object, "adapter", &value.adapter, findings);
    if value.adapter == "litellm-gateway" {
        if value.protocol.is_some() && value.policy.routes.is_empty() {
            findings.push(fail(
                object,
                "provider-policy-empty",
                "an embedding litellm-gateway provider's policy.routes must name its gateway lane/model pair",
            ));
        }
        if value.protocol.is_none() && !value.policy.routes.is_empty() {
            findings.push(fail(
                object,
                "chat-provider-gateway-routes",
                "a chat litellm-gateway provider serves the pinned gateway projection's chat routes \
                 and must not declare policy.routes",
            ));
        }
    } else if !value.policy.routes.is_empty() {
        findings.push(fail(
            object,
            "native-provider-gateway-routes",
            format!(
                "native provider adapter {:?} must not declare gateway policy.routes",
                value.adapter
            ),
        ));
    }
    let mut routes = BTreeSet::new();
    for route in &value.policy.routes {
        if !valid_id(&route.gateway_lane_id) || !valid_gateway_model_id(&route.gateway_model_id) {
            findings.push(fail(
                object,
                "provider-policy-id",
                format!(
                    "gateway route {}/{} must use stable IDs",
                    route.gateway_lane_id, route.gateway_model_id
                ),
            ));
        }
        if !routes.insert((&route.gateway_lane_id, &route.gateway_model_id)) {
            findings.push(fail(
                object,
                "provider-policy-duplicate",
                format!(
                    "policy.routes repeats {}/{}",
                    route.gateway_lane_id, route.gateway_model_id
                ),
            ));
        }
    }
    if let Some(budget) = &value.budget {
        if let Err(message) = validate_budget_policy_fields(budget) {
            findings.push(fail(object, "provider-budget-policy", message));
        }
    }
    if let Err(message) = validate_recovery_policy_fields(&value.recovery) {
        findings.push(fail(object, "provider-recovery-policy", message));
    }
}

fn validate_capability(
    object: &RegistryObject,
    value: &CapabilityToml,
    findings: &mut Vec<RegistryFinding>,
) {
    validate_common(
        object,
        &value.schema,
        value.kind,
        &value.description,
        findings,
    );
    validate_capability_evidence(object, value, findings);
    if value.version == 0 {
        findings.push(fail(
            object,
            "capability-version-range",
            "version must be in 1..=65535",
        ));
    }
    if value.timeout_seconds.get() > 86_400 {
        findings.push(fail(
            object,
            "capability-timeout-range",
            "timeout_seconds must be in 1..=86400",
        ));
    }
    if value.retry.max_attempts > 10 {
        findings.push(fail(
            object,
            "capability-retry-range",
            "retry.max_attempts must be in 0..=10",
        ));
    }
    if value.approval_decider == super::ApprovalDeciderToml::Declaration
        && value.approval_policy != CapabilityApprovalToml::Operator
    {
        findings.push(fail(
            object,
            "capability-approval-decider",
            "approval_decider = \"declaration\" applies only to approval_policy = \"operator\"",
        ));
    }
    if value.preview == Some(super::PreviewKindToml::Plan) && !value.is_workflow() {
        findings.push(fail(
            object,
            "capability-plan-preview",
            "preview = \"plan\" requires implementation = \"workflow\"; only a workflow writes its own plan",
        ));
    }
    if let Some(card) = &value.approval_card {
        validate_approval_card(object, value, card, findings);
    }
    // Require the generic ask handler and schema tuple for delegation, even on disabled capabilities.
    let seat_ask_primitive = value.is_seat_ask_primitive();
    match (seat_ask_primitive, &value.delegate_to) {
        (true, Some(_)) | (false, None) => {}
        (true, None) => findings.push(fail(
            object,
            "capability-delegation-target",
            "the seat_ask delegation primitive must declare delegate_to",
        )),
        (false, Some(target)) => findings.push(fail(
            object,
            "capability-delegation-reserved",
            format!(
                "delegate_to {:?} is reserved for the seat_ask delegation primitive",
                target.as_str()
            ),
        )),
    }
    if seat_ask_primitive {
        if value.effect_class != EffectClass::R3 {
            findings.push(fail(
                object,
                "capability-delegation-approval",
                "seat_ask requires effect class R3",
            ));
        }
        let generic_extractor = matches!(
            &value.evidence_extractor,
            Some(HandlerBindingToml::Builtin(builtin))
                if builtin.id == SEAT_ASK_EVIDENCE_EXTRACTOR_ID
        );
        if !generic_extractor {
            findings.push(fail(
                object,
                "capability-delegation-tuple",
                "the seat_ask delegation primitive requires the generic odin_hermes_seat_ask_evidence evidence extractor",
            ));
        }
        if value.input_schema.as_deref() != Some(SEAT_ASK_INPUT_SCHEMA)
            || value.output_schema.as_deref() != Some(SEAT_ASK_OUTPUT_SCHEMA)
        {
            findings.push(fail(
                object,
                "capability-delegation-tuple",
                "the seat_ask delegation primitive requires the generic seat.ask input/output schema pair",
            ));
        }
    }
    let reservation = !value.enabled && value.implementation.as_deref() == Some("unimplemented");
    if value.enabled && value.implementation.as_deref() == Some("unimplemented") {
        findings.push(fail(
            object,
            "capability-enabled-unimplemented",
            "enabled capability cannot use implementation = \"unimplemented\"",
        ));
    }
    if value.enabled && !value.is_implemented() {
        findings.push(fail(
            object,
            "capability-enabled-contract",
            "enabled capability requires an implementation, dedicated input/output schemas, handler, seat tags, and evidence extractor",
        ));
    } else if !reservation {
        for (field, field_value) in [
            ("implementation", value.implementation.as_deref()),
            ("input_schema", value.input_schema.as_deref()),
            ("output_schema", value.output_schema.as_deref()),
        ] {
            if field_value.is_none_or(str::is_empty) {
                findings.push(fail(
                    object,
                    "capability-contract",
                    format!("implemented capability contract requires nonempty {field}"),
                ));
            }
        }
        for (field, code, binding) in [
            (
                "handler",
                "capability-handler-binding",
                value.handler.as_ref(),
            ),
            (
                "evidence_extractor",
                "capability-evidence-extractor-binding",
                value.evidence_extractor.as_ref(),
            ),
        ] {
            let Some(binding) = binding else {
                findings.push(fail(
                    object,
                    "capability-contract",
                    format!("implemented capability contract requires a {field} binding"),
                ));
                continue;
            };
            if let Err(message) = binding.validate() {
                findings.push(fail(object, code, message));
            }
        }
        if value.seat_tags.is_empty() {
            findings.push(fail(
                object,
                "capability-seat-tags",
                "implemented capability requires at least one seat tag",
            ));
        }
    }
    if !value.enabled && !reservation {
        findings.push(RegistryFinding::flag(
            "capability-disabled-implemented",
            &object.relative_config,
            "disabled implemented capability is omitted from listings",
        ));
    }
}

fn validate_slice(object: &RegistryObject, value: &SliceToml, findings: &mut Vec<RegistryFinding>) {
    validate_common(
        object,
        &value.schema,
        value.kind,
        &value.description,
        findings,
    );
    if let Some(budget) = &value.budget {
        if let Err(message) = validate_budget_policy_fields(budget) {
            findings.push(fail(object, "slice-budget-policy", message));
        }
    }
    require_allowed(
        object,
        "redirects.out_of_scope",
        &value.redirects.out_of_scope,
        &["NeedsPlan", "NeedsApproval", "WrongSeat"],
        findings,
    );
    for (name, variable) in &value.variables {
        if !valid_id(name) {
            findings.push(fail(
                object,
                "slice-variable-name",
                format!("variables.{name} is not a valid stable ID"),
            ));
        }
        require_nonempty(
            object,
            &format!("variables.{name}.type"),
            &variable.variable_type,
            findings,
        );
        require_nonempty(
            object,
            &format!("variables.{name}.meaning"),
            &variable.meaning,
            findings,
        );
        match (variable.min, variable.max) {
            (Some(minimum), Some(maximum)) if minimum <= maximum => {}
            (None, None) => {}
            _ => findings.push(fail(
                object,
                "slice-variable-range",
                format!("variables.{name} must have both min/max with min <= max, or neither"),
            )),
        }
    }
    if let Some(knowledge) = &value.knowledge {
        if knowledge.required && knowledge.atlas_sources.is_empty() {
            findings.push(fail(
                object,
                "slice-knowledge-sources",
                "required knowledge needs at least one Atlas source",
            ));
        }
        if knowledge.top_k > knowledge.candidate_limit {
            findings.push(fail(
                object,
                "slice-knowledge-range",
                "knowledge.top_k must not exceed knowledge.candidate_limit",
            ));
        }
        if knowledge.min_score_micros > 1_000_000 {
            findings.push(fail(
                object,
                "slice-knowledge-range",
                "knowledge.min_score_micros must be in 0..=1000000",
            ));
        }
        if knowledge.chunk_overlap_tokens >= knowledge.chunk_tokens.get() {
            findings.push(fail(
                object,
                "slice-knowledge-range",
                "knowledge.chunk_overlap_tokens must be less than knowledge.chunk_tokens",
            ));
        }
        if matches!(
            knowledge.retrieval_mode,
            RetrievalMode::Vector | RetrievalMode::Hybrid
        ) && knowledge.embedding_backend == EmbeddingBackend::Disabled
        {
            findings.push(fail(
                object,
                "slice-knowledge-embedding",
                "vector retrieval requires a non-disabled embedding backend",
            ));
        }
    }
    if let Some(context) = &value.context {
        let component_tokens = [
            context.control_tokens,
            context.history_tokens,
            context.core_tokens,
            context.prefetch_tokens,
            context.tool_result_tokens,
            context.tool_schema_tokens,
        ]
        .into_iter()
        .map(|tokens| u64::from(tokens.get()))
        .sum::<u64>();
        if component_tokens > u64::from(context.max_bundle_tokens.get()) {
            findings.push(fail(
                object,
                "slice-context-range",
                "context component token ceilings exceed context.max_bundle_tokens",
            ));
        }
        if context.max_item_tokens > context.max_bundle_tokens {
            findings.push(fail(
                object,
                "slice-context-range",
                "context.max_item_tokens must not exceed context.max_bundle_tokens",
            ));
        }
    }
    if let Some(tools) = &value.tools {
        validate_tool_redirects(
            object,
            "tools.redirects",
            tools.redirects.max_http_hops,
            tools.redirects.allow_https_downgrade,
            findings,
        );
    }
    if let Some(live) = &value.live {
        if live.max_sessions_per_seat.get() > 1_024 {
            findings.push(fail(
                object,
                "slice-live-range",
                "live.max_sessions_per_seat must be in 1..=1024",
            ));
        }
        validate_media_types(
            object,
            "live.allowed_file_media_types",
            &live.allowed_file_media_types,
            findings,
        );
        validate_media_types(
            object,
            "live.allowed_render_media_types",
            &live.allowed_render_media_types,
            findings,
        );
    }
}

fn validate_host(object: &RegistryObject, value: &HostToml, findings: &mut Vec<RegistryFinding>) {
    validate_common(
        object,
        &value.schema,
        value.kind,
        &value.description,
        findings,
    );
    require_nonempty(object, "hardware", &value.hardware, findings);
    require_allowed(
        object,
        "role",
        &value.role,
        &["control", "worker", "gateway"],
        findings,
    );
    if value.enrolled && !value.enabled {
        findings.push(fail(
            object,
            "host-enrollment-state",
            "an enrolled host must be enabled",
        ));
    }
    if value.enrolled {
        require_nonempty(object, "tailscale", &value.tailscale, findings);
    }
}

fn validate_routine(
    object: &RegistryObject,
    value: &super::routine::RoutineToml,
    findings: &mut Vec<RegistryFinding>,
) {
    use super::routine::{
        dm_placeholders, RoutineActionKind, RoutineEvent, RoutineSchedule, ROUTINE_TEXT_MAX_CHARS,
    };
    validate_common(
        object,
        &value.schema,
        value.kind,
        &value.description,
        findings,
    );
    let trigger = &value.trigger;
    match (&trigger.schedule, trigger.event) {
        (Some(schedule), None) => {
            if let Err(reason) = RoutineSchedule::parse(schedule) {
                findings.push(fail(object, "routine-schedule", reason));
            }
            if trigger.profile.is_some()
                || trigger.matches.is_some()
                || trigger.lead_minutes.is_some()
                || trigger.account.is_some()
                || trigger.project.is_some()
            {
                findings.push(fail(
                    object,
                    "routine-trigger",
                    "a schedule takes no profile, match, lead_minutes, account or project",
                ));
            }
        }
        (None, Some(event)) => {
            if let Err(reason) = trigger.check_event(event) {
                findings.push(fail(object, "routine-trigger", reason));
            }
        }
        _ => findings.push(fail(
            object,
            "routine-trigger",
            "a routine declares exactly one of trigger.schedule or trigger.event",
        )),
    }
    if value.action.kind == RoutineActionKind::Dm {
        match dm_placeholders(&value.action.text) {
            Err(reason) => findings.push(fail(object, "routine-text", reason)),
            Ok(used) => {
                let outcome = matches!(
                    trigger.event,
                    Some(RoutineEvent::WorkloadSucceeded | RoutineEvent::WorkloadFailed)
                );
                if let (Some(name), false) = (used.first(), outcome) {
                    findings.push(fail(
                        object,
                        "routine-placeholder",
                        format!(
                            "dm placeholder {{{name}}} fills from a run's outcome: set \
                             trigger.event to workload_succeeded or workload_failed"
                        ),
                    ));
                }
            }
        }
    }
    let words = value.action.text.trim().chars().count();
    if words == 0 || words > ROUTINE_TEXT_MAX_CHARS {
        findings.push(fail(
            object,
            "routine-text",
            format!("action.text must be 1..={ROUTINE_TEXT_MAX_CHARS} characters"),
        ));
    }
}

/// Share atlas-subtree and memory-namespace validation between projects and workloads.
pub fn valid_memory_namespace(namespace: &str) -> bool {
    let subtree = ["atlas.", "memory."]
        .iter()
        .find_map(|prefix| namespace.strip_prefix(prefix));
    !subtree.is_none_or(str::is_empty) && valid_id(namespace)
}

pub(super) fn validate_budget_policy_fields(policy: &BudgetPolicyToml) -> Result<(), String> {
    if !(1..=1_000_000_000_000_000).contains(&policy.usd_micros) {
        return Err("usd_micros must be in 1..=1000000000000000".to_owned());
    }
    if policy.window.duration_seconds.get() > 315_576_000 {
        return Err(
            "window.duration_seconds must be in 1..=315576000 (ten Julian years)".to_owned(),
        );
    }
    Ok(())
}

pub(super) fn validate_recovery_policy_fields(policy: &RecoveryPolicyToml) -> Result<(), String> {
    if policy.blocked_missing_decision.trim().is_empty() {
        return Err("blocked_missing_decision must be nonempty".to_owned());
    }
    if !policy.allowed_rungs.contains(&RecoveryRungToml::Escalate) {
        return Err("allowed_rungs must retain the compiled terminal escalate rung".to_owned());
    }
    let limits = [
        policy.max_attempts.retry,
        policy.max_attempts.restart_worker,
        policy.max_attempts.checkpoint,
        policy.max_attempts.rehome,
        policy.max_attempts.escalate,
    ];
    if limits.iter().any(|limit| *limit > 1_000) {
        return Err("max_attempts values must be in 0..=1000".to_owned());
    }
    if policy.max_attempts.escalate == 0 {
        return Err("max_attempts.escalate must be positive".to_owned());
    }
    let cooldowns = [
        policy.cooldown_seconds.retry,
        policy.cooldown_seconds.restart_worker,
        policy.cooldown_seconds.checkpoint,
        policy.cooldown_seconds.rehome,
        policy.cooldown_seconds.escalate,
    ];
    if cooldowns.iter().any(|seconds| *seconds > 31_557_600) {
        return Err("cooldown_seconds values must not exceed one Julian year".to_owned());
    }
    Ok(())
}

fn validate_tool_redirects(
    object: &RegistryObject,
    field: &str,
    max_http_hops: u8,
    allow_https_downgrade: bool,
    findings: &mut Vec<RegistryFinding>,
) {
    if max_http_hops > 3 {
        findings.push(fail(
            object,
            "tool-redirect-range",
            format!("{field}.max_http_hops must be in 0..=3"),
        ));
    }
    if allow_https_downgrade {
        findings.push(fail(
            object,
            "tool-redirect-downgrade",
            format!("{field}.allow_https_downgrade must be false"),
        ));
    }
}

fn validate_media_types(
    object: &RegistryObject,
    field: &str,
    media_types: &BTreeSet<String>,
    findings: &mut Vec<RegistryFinding>,
) {
    if media_types.is_empty() {
        findings.push(fail(
            object,
            "slice-live-media-types",
            format!("{field} must contain at least one media type"),
        ));
    }
    for media_type in media_types {
        if !valid_media_type(media_type) {
            findings.push(fail(
                object,
                "slice-live-media-type",
                format!("{field} contains invalid media type {media_type:?}"),
            ));
        }
    }
}

pub(crate) fn valid_media_type(value: &str) -> bool {
    value
        .split_once('/')
        .is_some_and(|(kind, subtype)| !kind.is_empty() && !subtype.is_empty())
}

pub(super) fn require_nonempty(
    object: &RegistryObject,
    field: &str,
    value: &str,
    findings: &mut Vec<RegistryFinding>,
) {
    if value.trim().is_empty() {
        findings.push(fail(
            object,
            "registry-required-value",
            format!("{field} must be nonempty"),
        ));
    }
}

fn require_unique_list(
    object: &RegistryObject,
    field: &str,
    values: &[String],
    findings: &mut Vec<RegistryFinding>,
) {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            findings.push(fail(
                object,
                "registry-duplicate-value",
                format!("{field} contains duplicate {value:?}"),
            ));
        }
    }
}

fn require_allowed(
    object: &RegistryObject,
    field: &str,
    value: &str,
    allowed: &[&str],
    findings: &mut Vec<RegistryFinding>,
) {
    if !allowed.contains(&value) {
        findings.push(fail(
            object,
            "registry-enum-value",
            format!("{field} has unsupported value {value:?}"),
        ));
    }
}

pub(super) fn valid_gateway_model_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-' | b'/')
        })
}

/// Share identifier syntax with path and key consumers so accepted character sets cannot diverge.
pub fn valid_id(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && chars.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
}

pub(crate) fn lookup_toml_path<'a>(root: &'a toml::Value, path: &str) -> Option<&'a toml::Value> {
    path.split('.').try_fold(root, |value, component| {
        value.as_table().and_then(|table| table.get(component))
    })
}

pub(super) fn fail(
    object: &RegistryObject,
    code: impl Into<String>,
    message: impl Into<String>,
) -> RegistryFinding {
    RegistryFinding::fail(code, &object.relative_config, message)
}

pub fn has_failures(findings: &[RegistryFinding]) -> bool {
    findings
        .iter()
        .any(|finding| finding.severity == FindingSeverity::Fail)
}

/// How long a pod's session may journal nothing, at the least and at the most.
const SILENCE_SECONDS: std::ops::RangeInclusive<u32> = 60..=86_400;

/// Require progress counter, two-read stall window, and supported recovery rungs together. A
/// stall window alone is the silence a pod's session may keep before it is resumed.
pub fn check_pod_recovery(
    monitoring: &super::workload::WorkloadMonitoringToml,
) -> Result<(), String> {
    let (progress, stall, recovery) = match (
        &monitoring.progress,
        monitoring.stall_seconds,
        &monitoring.recovery,
    ) {
        (None, None, None) => return Ok(()),
        (None, Some(stall), None) if SILENCE_SECONDS.contains(&stall.get()) => return Ok(()),
        (None, Some(_), None) => {
            return Err(format!(
                "monitoring.stall_seconds alone is a pod's allowed silence and must be {}..={}",
                SILENCE_SECONDS.start(),
                SILENCE_SECONDS.end()
            ))
        }
        (Some(progress), Some(stall), Some(recovery)) => (progress, stall, recovery),
        _ => {
            return Err(
                "monitoring.progress and recovery are declared together with \
                 stall_seconds"
                    .to_owned(),
            )
        }
    };
    if progress.is_empty()
        || progress.len() > 64
        || !progress
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        return Err(format!(
            "monitoring.progress {progress:?} is not a status counter name"
        ));
    }
    let cadence = monitoring.cadence_seconds.get();
    if stall.get() < cadence.saturating_mul(2) || stall.get() > 86_400 {
        return Err(format!(
            "monitoring.stall_seconds must be at least two reads ({}s) and at most 86400",
            cadence.saturating_mul(2)
        ));
    }
    if let Some(unsupported) = recovery
        .allowed_rungs
        .iter()
        .find(|rung| !super::workload::POD_RECOVERY_RUNGS.contains(rung))
    {
        return Err(format!(
            "a pod recovers only by restart_worker and escalate, not {unsupported:?}"
        ));
    }
    super::provider::resolve_recovery_policy(0, std::slice::from_ref(recovery))
        .map(|_| ())
        .map_err(|error| format!("monitoring.recovery: {error}"))
}

#[cfg(test)]
mod pod_recovery_tests {
    use super::check_pod_recovery;
    use crate::schema::workload::WorkloadMonitoringToml;
    use crate::schema::{
        RecoveryAttemptLimitsToml, RecoveryCooldownsToml, RecoveryPolicyToml, RecoveryRungToml,
    };

    fn ladder(rungs: &[RecoveryRungToml]) -> RecoveryPolicyToml {
        RecoveryPolicyToml {
            max_attempts: RecoveryAttemptLimitsToml {
                retry: 0,
                restart_worker: 1,
                checkpoint: 0,
                rehome: 0,
                escalate: 1,
            },
            cooldown_seconds: RecoveryCooldownsToml {
                retry: 0,
                restart_worker: 30,
                checkpoint: 0,
                rehome: 0,
                escalate: 0,
            },
            allowed_rungs: rungs.iter().copied().collect(),
            blocked_missing_decision: "the owner decides".to_owned(),
        }
    }

    fn monitoring(
        progress: Option<&str>,
        stall: Option<u32>,
        recovery: Option<RecoveryPolicyToml>,
    ) -> WorkloadMonitoringToml {
        WorkloadMonitoringToml {
            status_tail_lines: None,
            cadence_seconds: std::num::NonZeroU32::new(15).unwrap(),
            reviewer: None,
            watchdogs: Vec::new(),
            progress: progress.map(str::to_owned),
            stall_seconds: stall.and_then(std::num::NonZeroU32::new),
            telemetry_stale_multiplier: None,
            recovery,
        }
    }

    /// Pod recovery requires a counter, at least two reads, supported recovery steps, and terminal escalation.
    #[test]
    fn a_pod_ladder_is_whole_readable_and_walkable() {
        use RecoveryRungToml::*;
        assert!(check_pod_recovery(&monitoring(None, None, None)).is_ok());
        // A stall window alone bounds a pod's silence; a counter or ladder needs the whole set.
        assert!(check_pod_recovery(&monitoring(None, Some(300), None)).is_ok());
        assert!(check_pod_recovery(&monitoring(None, Some(30), None)).is_err());
        assert!(check_pod_recovery(&monitoring(Some("step"), None, None)).is_err());
        let whole = monitoring(
            Some("step"),
            Some(120),
            Some(ladder(&[RestartWorker, Escalate])),
        );
        assert!(check_pod_recovery(&whole).is_ok());
        assert!(check_pod_recovery(&monitoring(Some("step"), Some(120), None)).is_err());
        assert!(check_pod_recovery(&monitoring(
            Some("step"),
            Some(20),
            Some(ladder(&[RestartWorker, Escalate]))
        ))
        .is_err());
        assert!(check_pod_recovery(&monitoring(
            Some("step"),
            Some(120),
            Some(ladder(&[Rehome, Escalate]))
        ))
        .is_err());
        assert!(check_pod_recovery(&monitoring(
            Some("step"),
            Some(120),
            Some(ladder(&[RestartWorker]))
        ))
        .is_err());
        assert!(check_pod_recovery(&monitoring(
            Some("bad name"),
            Some(120),
            Some(ladder(&[RestartWorker, Escalate]))
        ))
        .is_err());
    }
}
