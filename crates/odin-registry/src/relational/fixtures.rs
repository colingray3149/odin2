use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use crate::schema::{CapabilityToml, ObjectConfig, RegistryObject, SeatToml, SliceToml};
use crate::RegistryFinding;
use odin_domain::SeatId;

use super::capabilities::validate_capability_relations;
use super::context::{AdmittedBinding, RelationContext};
use super::validate;

pub(super) fn slice_object(enabled: bool) -> RegistryObject {
    let source = format!(
        r#"
schema = "odin.registry.v1"
kind = "slice"
enabled = {enabled}
description = "fixture"
capabilities = []
variables = {{}}
[redirects]
out_of_scope = "NeedsPlan"
"#
    );
    RegistryObject {
        id: "fixture".to_owned(),
        relative_config: PathBuf::from("registry/slices/fixture/slice.toml"),
        config: ObjectConfig::Slice(Box::new(
            toml::from_str::<SliceToml>(&source).expect("parse slice fixture"),
        )),
    }
}

pub(super) fn bound_capability() -> (RegistryObject, CapabilityToml) {
    let capability: CapabilityToml = toml::from_str(
        r#"
schema = "odin.registry.v1"
kind = "capability"
enabled = true
implementation = "builtin"
version = 3
description = "Bound capability fixture."
handler = { id = "fixture.handle" }
input_schema = "schemas/capability/fixture.tool.input.json"
output_schema = "schemas/capability/fixture.tool.output.json"
effect_class = "R0"
seat_tags = ["builder"]
timeout_seconds = 1
idempotency = "pure"
retry = { max_attempts = 1 }
approval_policy = "none"
evidence_extractor = { executable = "/nix/store/q0000000000000000000000000000000-odin-fixture/bin/odin-fixture-extract", argv = ["--framed"] }
"#,
    )
    .expect("parse bound capability fixture");
    let object = RegistryObject {
        id: "fixture.tool".to_owned(),
        relative_config: PathBuf::from("registry/capabilities/fixture.tool/capability.toml"),
        config: ObjectConfig::Capability(Box::new(capability.clone())),
    };
    (object, capability)
}

pub(super) fn admitted_binding(capability: &CapabilityToml) -> AdmittedBinding {
    AdmittedBinding {
        version: capability.version,
        input_schema: capability.input_schema.clone().expect("input schema"),
        output_schema: capability.output_schema.clone().expect("output schema"),
        handler: capability.handler.clone().expect("handler"),
        evidence_extractor: capability.evidence_extractor.clone().expect("extractor"),
    }
}

pub(super) fn capability_relation_messages(
    capability: &CapabilityToml,
    context: &RelationContext,
) -> Vec<String> {
    capability_relation_messages_for("fixture.tool", capability, context)
}

pub(super) fn capability_relation_messages_for(
    id: &str,
    capability: &CapabilityToml,
    context: &RelationContext,
) -> Vec<String> {
    let object = RegistryObject {
        id: id.to_owned(),
        relative_config: PathBuf::from(format!("registry/capabilities/{id}/capability.toml")),
        config: ObjectConfig::Capability(Box::new(capability.clone())),
    };
    let mut findings = Vec::new();
    let seats: BTreeMap<&str, &SeatToml> = BTreeMap::new();
    validate_capability_relations(
        &object,
        capability,
        context,
        &seats,
        &BTreeSet::from(["builder"]),
        &mut BTreeMap::new(),
        &mut findings,
    );
    findings
        .into_iter()
        .map(|finding| finding.message)
        .collect()
}

pub(super) fn project_object(enabled: bool) -> RegistryObject {
    let source = format!(
        r#"
schema = "odin.registry.v1"
kind = "project"
enabled = {enabled}
description = "fixture"
source_root = ""
default_seat = "fixture"
memory_namespaces = ["atlas.code"]
artifact_policy = "standard"
"#
    );
    RegistryObject {
        id: "fixture".to_owned(),
        relative_config: PathBuf::from("registry/projects/fixture/project.toml"),
        config: ObjectConfig::Project(Box::new(
            toml::from_str(&source).expect("parse project fixture"),
        )),
    }
}

pub(super) fn seat_object(conversation: &str, live: bool) -> RegistryObject {
    seat_object_named("fixture", conversation, live)
}

/// Uses arbitrary seat names to avoid identity-specific validation.
pub(super) fn seat_object_named(id: &str, conversation: &str, live: bool) -> RegistryObject {
    let live_plane = if live {
        r#"
[live]
max_sessions = 4
file_ingress_lane = "file.in"
file_egress_lane = "file.out"
render_ingress_lane = "render.in"
render_egress_lane = "render.out"
"#
    } else {
        ""
    };
    let source = format!(
        r#"
schema = "odin.registry.v1"
kind = "seat"
enabled = true
description = "fixture"
categories = []
tool_refs = []
project_scope = ["fixture"]
approval_defaults = {{ r0 = "auto", r1 = "auto", r2 = "auto", r3 = "approval" }}
brain_scope = []
limits = {{ max_parallel_runs = 4, max_sessions = 4, budget = {{ usd_micros = 1000000, window = {{ duration_seconds = 2592000 }} }} }}
knowledge = {{ atlas_sources = [], required_tags = [], denied_tags = [], top_k = 16 }}
tools = {{ deny = [], redirects = {{ max_http_hops = 0, allow_cross_origin = false, disabled_aliases = [] }} }}
{conversation}
{live_plane}
"#
    );
    RegistryObject {
        id: id.to_owned(),
        relative_config: PathBuf::from(format!("registry/seats/{id}/seat.toml")),
        config: ObjectConfig::Seat(Box::new(
            toml::from_str(&source).expect("parse seat fixture"),
        )),
    }
}

/// A generic ask capability bound to the primitive tuple with an
/// explicit published target. The logical id and the target are both
/// arbitrary: no branch may know either name.
pub(super) fn ask_capability_object(id: &str, delegate_to: &str) -> RegistryObject {
    let source = format!(
        r#"
schema = "odin.registry.v1"
kind = "capability"
enabled = true
implementation = "builtin"
version = 1
description = "fixture"
handler = {{ id = "seat_ask" }}
delegate_to = "{delegate_to}"
input_schema = "schemas/capability/seat.ask.input.json"
output_schema = "schemas/capability/seat.ask.output.json"
effect_class = "R3"
seat_tags = ["*"]
timeout_seconds = 30
idempotency = "required"
retry = {{ max_attempts = 0 }}
approval_policy = "operator"
evidence_extractor = {{ id = "odin_hermes_seat_ask_evidence" }}
"#
    );
    RegistryObject {
        id: id.to_owned(),
        relative_config: PathBuf::from(format!("registry/capabilities/{id}/capability.toml")),
        config: ObjectConfig::Capability(Box::new(
            toml::from_str(&source).expect("parse ask capability fixture"),
        )),
    }
}

pub(super) fn capability_mut(object: &mut RegistryObject) -> &mut CapabilityToml {
    let ObjectConfig::Capability(capability) = &mut object.config else {
        panic!("fixture must be a capability");
    };
    capability
}

/// The four live-plane lanes a fixture seat's `[live]` block binds, so
/// the clean conversation case proves the whole seat validates, not
/// just the conversation slice of it.
pub(super) fn lane_fixtures() -> Vec<RegistryObject> {
    [
        ("file.in", "ingress", "file"),
        ("file.out", "egress", "file"),
        ("render.in", "ingress", "render"),
        ("render.out", "egress", "render"),
    ]
    .into_iter()
    .map(|(name, direction, payload)| {
        let source = format!(
            r#"
schema = "odin.registry.v1"
kind = "lane"
enabled = true
description = "fixture"
project = "fixture"
family = "transfer"
default_seat = "fixture"
queue = "interactive"
requires_independent_review = false
direction = "{direction}"
payload_kind = "{payload}"
"#
        );
        RegistryObject {
            id: name.to_owned(),
            relative_config: PathBuf::from(format!("registry/lanes/{name}/lane.toml")),
            config: ObjectConfig::Lane(Box::new(
                toml::from_str(&source).expect("parse lane fixture"),
            )),
        }
    })
    .collect()
}

pub(super) fn conversation_findings(objects: &[RegistryObject]) -> Vec<RegistryFinding> {
    // The publication pipeline runs both layers over the same object
    // set: strict per-object schema validation, then cross-object
    // relations. Fixture checks exercise exactly that combination.
    let mut findings = Vec::new();
    for object in objects {
        findings.extend(crate::schema::validate_object(object));
    }
    findings.extend(validate(
        objects,
        &RelationContext::new("/nonexistent/odin-relation-fixture"),
    ));
    findings
        .into_iter()
        .filter(|finding| finding.path.to_string_lossy().contains("seat.toml"))
        .collect()
}

pub(super) fn fixture_set(project: RegistryObject, seat: RegistryObject) -> Vec<RegistryObject> {
    let mut objects = lane_fixtures();
    objects.push(ask_capability_object("seat.ask.fixture", "fixture"));
    objects.push(project);
    objects.push(seat);
    objects
}

pub(super) fn seat_mut(object: &mut RegistryObject) -> &mut SeatToml {
    let ObjectConfig::Seat(seat) = &mut object.config else {
        panic!("fixture must be a seat");
    };
    seat
}

pub(super) fn with_delegate_to(object: &mut RegistryObject, target: &str) {
    capability_mut(object).delegate_to = Some(SeatId::new(target).expect("seat id"));
}

/// A fixture odin root whose schema catalog carries exactly the generic
/// ask pair, so dedicated-schema file checks can pass while the
/// delegation relations run.
pub(super) fn ask_schema_root() -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "odin-registry-delegation-fixture-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(root.join("schemas/capability")).unwrap();
    for name in ["seat.ask.input.json", "seat.ask.output.json"] {
        std::fs::write(
            root.join("schemas/capability").join(name),
            r#"{"$schema": "https://json-schema.org/draft/2020-12/schema"}"#,
        )
        .unwrap();
    }
    root
}

/// Uses an arbitrary provider route to avoid provider/model-specific validation.
pub(super) fn provider_object(enabled: bool) -> RegistryObject {
    let source = format!(
        r#"
schema = "odin.registry.v1"
kind = "provider"
enabled = {enabled}
description = "fixture"
adapter = "litellm-gateway"

[policy]
routes = [{{ gateway_lane_id = "fixture.gateway", gateway_model_id = "fixture/model" }}]

[budget]
usd_micros = 1000000

[budget.window]
duration_seconds = 2592000

[recovery]
allowed_rungs = ["escalate"]
blocked_missing_decision = "fixture"

[recovery.max_attempts]
retry = 0
restart_worker = 0
checkpoint = 0
rehome = 0
escalate = 1

[recovery.cooldown_seconds]
retry = 0
restart_worker = 0
checkpoint = 0
rehome = 0
escalate = 0
"#
    );
    RegistryObject {
        id: "fixture-provider".to_owned(),
        relative_config: PathBuf::from("registry/providers/fixture-provider/provider.toml"),
        config: crate::schema::ObjectConfig::Provider(Box::new(
            toml::from_str(&source).expect("parse provider fixture"),
        )),
    }
}

/// Uses arbitrary workload references to avoid identity-specific validation.
pub(super) fn workload_object(
    id: &str,
    seat: &str,
    project: &str,
    gateway_lane: &str,
    enabled: bool,
) -> RegistryObject {
    let source = format!(
        r#"
schema = "odin.registry.v1"
kind = "workload"
enabled = {enabled}
description = "fixture"

[image]
reference = "localhost/odin-fixture@sha256:0000000000000000000000000000000000000000000000000000000000000000"

[runtime]
launcher = "/odin/bin/omp"
browser = "/odin/bin/chromium"
supervisor = "/odin/bin/odind"
playwright = "/odin/lib/playwright-core"

[seat]
seat = "{seat}"
project = "{project}"
gateway_lane = "{gateway_lane}"

[network]
allow_hosts = ["example.com"]

[display]
xvfb = "/odin/bin/Xvfb"
screen = "1280x800x24"
stream = true

[state]
path = "/state"
storage = "2Gi"

[export]
pod_path = "/export"
host_folder = "/srv/odin/fixture"

[brief]
text = "fixture brief"

[memory]
namespace = "atlas.code"

[lifetime]
deadline_seconds = 3600
"#
    );
    RegistryObject {
        id: id.to_owned(),
        relative_config: PathBuf::from(format!("registry/workloads/{id}/profile.toml")),
        config: ObjectConfig::Workload(Box::new(
            toml::from_str(&source).expect("parse workload fixture"),
        )),
    }
}
