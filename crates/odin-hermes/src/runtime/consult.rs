//! `model_consult` — one question to a stronger model.
//!
//! The default ask is the calling seat's `[context] consult` declaration
//! (one of its own `models`, read from the pinned registry at call time),
//! served through the host's model gateway. The optional `model` argument
//! names any consultable frontier model instead: the registry's
//! frontier-tier gateway cards (served through the same gateway path) or
//! an official-client card — Opus 5.5 through Claude Code, an Antigravity
//! model through agy — served by the daemon-bound official consult route,
//! never through seat turn lanes. The model sees no tools. The answer comes
//! back with the deployment that served it, the time it took, its tokens
//! and the cost, so the caller can say whom it asked and Odin's surfaces
//! show what it spent. Gateway requests carry the `seat:<seat>,consult`
//! spend tag; official clients attribute their own spend (Claude Code
//! sessions land in the account's own records, so ccusage shows them).
//! odind logs one `model.consult` line per call.

use std::collections::BTreeMap;
use std::sync::Arc;

use odin_domain::Scope;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode};
use odin_registry::schema::{CHAT_CAPABILITY, FRONTIER_TIER, GATEWAY_ROUTE};
use odin_registry::{ObjectConfig, RegistryKind};
use serde_json::{json, Value};

use super::gateway;
use super::tools::{parse_string, CapabilityTool};
use super::HermesRuntime;

const TOOL: &str = "model_consult";
const SYSTEM: &str = "Another agent is consulting you on a question it judged hard. The answer \
comes back as its result: the result first, then the reasoning that supports it, with the steps \
a reader needs to check it, in under 600 words. Where you are unsure, or the question lacks a \
fact, say so, and name the sources and numbers the answer rests on.";

/// One consultable official-client model, served by a daemon-bound driver:
/// Opus 5.5 through Claude Code, an Antigravity model through agy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfficialConsultModel {
    /// Card id, e.g. `claude/claude-opus-5-5` or `antigravity/gemini-3-pro`.
    pub id: String,
    /// Card route: `claude-code` or `agy`.
    pub route: String,
    /// Model identity the official client is invoked with.
    pub model: String,
    /// Reasoning effort the client is asked at.
    pub effort: String,
    /// The card's strengths line.
    pub strengths: String,
}

/// One official-client consult answer. Tokens and cost are whatever the
/// client reports; spend attribution itself stays with the client's own
/// records (ccusage for Claude Code).
#[derive(Clone, Debug, PartialEq)]
pub struct OfficialConsultOutcome {
    pub answer: String,
    /// The model the client reports having served, when it says.
    pub served_model: Option<String>,
    pub seconds: u64,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cost_usd: Option<f64>,
}

/// The daemon-bound official-client consult drivers. Unbound, `model.consult`
/// keeps its gateway frontier cards and refuses official choices by name.
pub trait OfficialConsultRoute: Send + Sync {
    /// The official-client frontier models this host can consult, with the
    /// card facts the caller chooses by.
    fn models(&self) -> Vec<OfficialConsultModel>;
    /// One question to one official client, with no tools.
    fn consult(
        &self,
        seat: &str,
        model: &OfficialConsultModel,
        question: &str,
        material: Option<&str>,
    ) -> Result<OfficialConsultOutcome, String>;
}

/// One entry of the consultable set: a gateway card (with its LiteLLM
/// lane) or an official-client model.
#[derive(Clone, Debug)]
struct ConsultChoice {
    strengths: String,
    /// The gateway lane a gateway card names; absent on official clients.
    lane: Option<String>,
    /// The official-client model; absent on gateway cards.
    official: Option<OfficialConsultModel>,
}
/// The calling seat's declared consult lane and effort.
fn declared(
    runtime: &HermesRuntime,
    seat: &odin_domain::SeatId,
) -> Result<(String, String), HostToolError> {
    let pin = runtime.registry_pin().ok_or_else(|| {
        HostToolError::unavailable(TOOL, "the published registry is not bound on this host")
    })?;
    let snapshot = pin.current();
    let consult = snapshot
        .objects
        .iter()
        .find_map(|object| match &object.config {
            ObjectConfig::Seat(config)
                if object.kind() == RegistryKind::Seat && object.id == seat.as_str() =>
            {
                Some(
                    config
                        .context
                        .as_ref()
                        .and_then(|context| context.consult.clone()),
                )
            }
            _ => None,
        });
    match consult {
        Some(Some(consult)) => Ok((consult.lane, consult.effort)),
        Some(None) => Err(HostToolError::unavailable(
            TOOL,
            format!("seat {seat} declares no [context] consult lane"),
        )),
        None => Err(HostToolError::unavailable(
            TOOL,
            format!("seat {seat} is not in the published registry"),
        )),
    }
}

fn consult(
    gateway: &str,
    seat: &str,
    lane: &str,
    effort: &str,
    question: &str,
    material: Option<&str>,
) -> Result<Value, HostToolError> {
    let user = match material {
        Some(material) => format!("{question}\n\nMaterial for the question:\n{material}"),
        None => question.to_owned(),
    };
    let reply = gateway::chat(
        gateway,
        &format!("seat:{seat},consult"),
        None,
        &json!({
            "model": lane,
            "reasoning_effort": effort,
            "messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": user},
            ],
        }),
    )
    .map_err(|reason| HostToolError::unavailable(TOOL, reason))?;
    reply.log("model.consult", seat, lane);
    let mut result = reply.facts(lane);
    result["answer"] = json!(reply.text);
    Ok(result)
}

/// The frontier gateway cards the pinned registry declares, keyed by card
/// id. Only `gateway`-routed chat cards with the frontier tier consult.
fn frontier_cards(snapshot: &odin_registry::Snapshot) -> BTreeMap<String, ConsultChoice> {
    snapshot
        .objects
        .iter()
        .filter_map(|object| match &object.config {
            ObjectConfig::Model(card)
                if object.enabled()
                    && card.route == GATEWAY_ROUTE
                    && card.capability == CHAT_CAPABILITY
                    && card.tier.as_deref() == Some(FRONTIER_TIER) =>
            {
                Some(card.as_ref())
            }
            _ => None,
        })
        .filter_map(|card| {
            let lane = card.lane()?.to_owned();
            Some((
                card.id.clone(),
                ConsultChoice {
                    strengths: card.strengths.clone(),
                    lane: Some(lane),
                    official: None,
                },
            ))
        })
        .collect()
}

/// The consultable set: the registry's frontier gateway cards plus the
/// official-client models the bound route serves, keyed by card id.
fn consult_choices(runtime: &HermesRuntime) -> BTreeMap<String, ConsultChoice> {
    let mut choices = runtime
        .registry_pin()
        .map(|pin| frontier_cards(&pin.current()))
        .unwrap_or_default();
    if let Some(route) = runtime.consult_route() {
        for model in route.models() {
            choices.insert(
                model.id.clone(),
                ConsultChoice {
                    strengths: model.strengths.clone(),
                    lane: None,
                    official: Some(model),
                },
            );
        }
    }
    choices
}

/// The `model` property with the consultable ids, over the compiled
/// schema's plain optional string.
fn model_parameters(choices: &BTreeMap<String, ConsultChoice>) -> Value {
    let mut schema: Value = serde_json::from_str(include_str!(
        "../../../../schemas/capability/model.consult.input.json"
    ))
    .expect("compiled model.consult input schema");
    if choices.is_empty() {
        return schema;
    }
    let ids: Vec<&str> = choices.keys().map(String::as_str).collect();
    schema["properties"]["model"] = json!({
        "type": "string",
        "enum": ids,
        "description": "The model to ask: one of the frontier models this host \
            serves. Omit it to ask your seat's declared consult lane.",
    });
    schema
}

fn description(choices: &BTreeMap<String, ConsultChoice>) -> String {
    let mut text = "Ask a stronger model than your own one hard question, with no \
        tools. Use it by default, without being asked, when a question genuinely \
        needs deep reasoning: multi-step engineering, physics or math, a design \
        trade-off across several projects, or the argument of a long paper; answer \
        facts, lookups, short arithmetic and chat yourself. Put the whole question in \
        question and everything it needs (what you read, the numbers, the paper's \
        text) in material: it sees nothing else. Check its answer against your sources \
        before using it, and tell the person you answer in a few words which model \
        weighed in (served_model). It answers with seconds, tokens and cost. Omit \
        model to ask your seat's declared consult lane; name one of these to ask \
        another frontier model, each with its strengths:"
        .to_owned();
    if choices.is_empty() {
        text.push_str(" this host declares no other consultable model.");
        return text;
    }
    for (id, choice) in choices {
        text.push_str("\n- ");
        text.push_str(id);
        text.push_str(": ");
        text.push_str(&choice.strengths);
    }
    text
}

pub(super) fn consult_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    let runtime = Arc::clone(runtime);
    let choices = consult_choices(&runtime);
    let handler_runtime = Arc::clone(&runtime);
    let handler = move |scope: Scope, arguments: Value| {
        let question = parse_string(&arguments, "question", usize::MAX)?;
        let material = match arguments.get("material") {
            None | Some(Value::Null) => None,
            Some(_) => Some(parse_string(&arguments, "material", usize::MAX)?),
        };
        let model = match arguments.get("model") {
            None | Some(Value::Null) => None,
            Some(_) => Some(parse_string(&arguments, "model", usize::MAX)?),
        };
        let seat_id = scope.seat.as_ref().ok_or(HostToolError::Scope {
            tool: TOOL,
            reason: "a bound caller seat is required",
        })?;
        let seat = seat_id.as_str();
        // The registry may have published a card since the catalog was built.
        let current = consult_choices(&handler_runtime);
        let choice = model.as_deref().and_then(|id| current.get(id));
        if let Some(id) = &model {
            if choice.is_none() {
                let known: Vec<&str> = current.keys().map(String::as_str).collect();
                return Err(HostToolError::Arguments {
                    tool: TOOL,
                    detail: format!(
                        "{id} is not one of the consultable models: {}",
                        known.join(", ")
                    ),
                });
            }
        }
        match choice {
            // An official-client card: the daemon-bound driver serves it.
            Some(ConsultChoice {
                official: Some(official),
                ..
            }) => {
                let route = handler_runtime.consult_route().ok_or_else(|| {
                    HostToolError::unavailable(
                        TOOL,
                        "the official consult route is not composed on this host",
                    )
                })?;
                let outcome = route
                    .consult(seat, official, &question, material.as_deref())
                    .map_err(|reason| HostToolError::unavailable(TOOL, reason))?;
                tracing::info!(
                    "odind: model.consult seat={seat} lane={} served={} seconds={} \
                     input_tokens={} output_tokens={} cost_usd={}",
                    official.id,
                    outcome.served_model.as_deref().unwrap_or("unknown"),
                    outcome.seconds,
                    outcome
                        .input_tokens
                        .map_or("unknown".to_owned(), |n| n.to_string()),
                    outcome
                        .output_tokens
                        .map_or("unknown".to_owned(), |n| n.to_string()),
                    outcome
                        .cost_usd
                        .map_or("unknown".to_owned(), |c| format!("{c:.4}")),
                );
                Ok(json!({
                    "answer": outcome.answer,
                    "lane": official.id,
                    "served_model": outcome.served_model,
                    "seconds": outcome.seconds,
                    "input_tokens": outcome.input_tokens,
                    "output_tokens": outcome.output_tokens,
                    "cost_usd": outcome.cost_usd,
                }))
            }
            // The gateway, at the seat's declared effort: a gateway card's own lane, or with no
            // model named the seat's declared lane.
            other => {
                let (declared_lane, effort) = declared(&handler_runtime, seat_id)?;
                let lane = other
                    .and_then(|choice| choice.lane.as_deref())
                    .unwrap_or(&declared_lane);
                let gateway = handler_runtime.model_gateway().ok_or_else(|| {
                    HostToolError::unavailable(TOOL, "odind has no model gateway configured")
                })?;
                consult(
                    &gateway,
                    seat,
                    lane,
                    &effort,
                    &question,
                    material.as_deref(),
                )
            }
        }
    };
    tools.push(Arc::new(CapabilityTool::plain_without_prerequisites(
        RpcHostToolDefinition {
            name: TOOL.into(),
            label: "Consult a stronger model".into(),
            description: description(&choices).into(),
            parameters: model_parameters(&choices),
            hidden: false,
            load_mode: ToolLoadMode::Essential,
        },
        Box::new(handler),
    )));
}

#[cfg(test)]
mod tests {
    use crate::runtime::gateway::{tests::fake as fake_gateway, KEY_ENV};
    use odin_domain::SeatId;
    use odin_registry::schema::parse_object_toml;
    use odin_registry::{Snapshot, SnapshotHandle, SnapshotStore};

    use super::*;

    /// A minimal seat declaring its consult lane, or none (`consult == false`).
    fn seat_toml(id: &str, consult: bool) -> String {
        let consult = if consult {
            "consult = { lane = \"astra\", effort = \"high\" }\n"
        } else {
            ""
        };
        format!(
            r#"schema = "odin.registry.v1"
kind = "seat"
enabled = true
description = "Consult fixture seat {id}."
categories = ["builder"]
tool_refs = ["artifact.read"]
project_scope = ["odin"]
brain_scope = ["atlas.code"]

[limits]
max_parallel_runs = 2
max_sessions = 2

[context]
max_bundle_tokens = 24576
profile = "medium"
{consult}"#
        )
    }

    /// A runtime with the consult fixture seats and a seat that declares none,
    /// published the way `SnapshotStore` verifies them.
    fn runtime(gateway: &str) -> (Arc<HermesRuntime>, tempfile::TempDir) {
        let root = tempfile::tempdir().expect("state");
        let settings = crate::config::HermesSettings::new(
            root.path().join("state"),
            None,
            None,
            Vec::new(),
        )
        .expect("hermes settings");
        let ledgers = crate::runtime::HermesLedgers {
            conversation: odin_ledger::Ledger::open_in_memory().expect("conversation ledger"),
            adapter: Arc::new(parking_lot::Mutex::new(
                odin_ledger::Ledger::open_in_memory().expect("adapter ledger"),
            )),
            purchase: Arc::new(std::sync::Mutex::new(
                odin_ledger::Ledger::open_in_memory().expect("purchase ledger"),
            )),
        };
        let runtime = HermesRuntime::open(
            settings,
            ledgers,
            &std::collections::BTreeMap::new(),
            None,
            8_192,
            std::collections::BTreeMap::new(),
            None,
        )
        .expect("hermes runtime");
        let seats = [
            ("sinmara", seat_toml("sinmara", true)),
            ("kubert", seat_toml("kubert", true)),
            ("gungnir", seat_toml("gungnir", true)),
            ("architect", seat_toml("architect", true)),
            ("helper", seat_toml("helper", false)),
        ]
        .map(|(id, source)| {
            parse_object_toml(
                RegistryKind::Seat,
                id,
                format!("registry/seats/{id}/seat.toml"),
                &source,
            )
            .expect("fixture seat parses")
        });
        let cards = [
            (
                "astra",
                r#"
schema = "odin.registry.v1"
kind = "model"
enabled = true
description = "Frontier card for the astra gateway lane."
id = "gateway/astra"
served = "openai/gpt-6-astra"
tier = "frontier"
strengths = "Hard multi-step math, physics and engineering"
seats = true
"#,
            ),
            (
                "kimi-k31",
                r#"
schema = "odin.registry.v1"
kind = "model"
enabled = true
description = "Frontier card for the kimi-k31 gateway lane."
id = "gateway/kimi-k31"
tier = "frontier"
strengths = "Long, patient research passes over large material"
seats = true
"#,
            ),
        ]
        .map(|(id, source)| {
            parse_object_toml(
                RegistryKind::Model,
                id,
                format!("registry/models/{id}/model.toml"),
                source,
            )
            .expect("fixture card parses")
        });
        let mut objects = seats.to_vec();
        objects.extend(cards);
        let snapshot = Snapshot::build(1, objects).expect("snapshot");
        let mut bytes = serde_json::to_vec_pretty(&snapshot).expect("snapshot json");
        bytes.push(b'\n');
        let revisions = root.path().join("revisions");
        std::fs::create_dir_all(&revisions).expect("revisions");
        std::fs::write(root.path().join("snapshot.json"), &bytes).expect("snapshot");
        std::fs::write(revisions.join(format!("{:020}.snapshot.json", 1)), &bytes)
            .expect("versioned snapshot");
        let receipt = json!({
            "schema": odin_registry::PUBLICATION_RECEIPT_SCHEMA,
            "outcome": "published",
            "revision": 1,
            "previous_revision": null,
            "commit": "commit-1",
            "tree": "tree-1",
            "snapshot_hash": snapshot.hash,
        });
        std::fs::write(
            revisions.join(format!("{:020}.receipt.json", 1)),
            serde_json::to_vec_pretty(&receipt).expect("receipt json"),
        )
        .expect("receipt");
        let pin = SnapshotHandle::open(SnapshotStore::new(root.path().join("snapshot.json")))
            .expect("pinned registry");
        runtime.set_registry_pin(Arc::new(pin));
        runtime.set_model_gateway(gateway.to_owned());
        (runtime, root)
    }

    fn invoke(
        runtime: &Arc<HermesRuntime>,
        seat: &str,
        arguments: Value,
    ) -> Result<Value, HostToolError> {
        let mut tools = Vec::new();
        consult_tools(runtime, &mut tools);
        tools
            .pop()
            .expect("model_consult tool")
            .invoke(odin_omp::host_tools::HostInvocation {
                scope: Scope {
                    seat: Some(SeatId::new(seat).unwrap()),
                    ..Scope::default()
                },
                arguments,
            })
    }

    /// The seat's declared lane and effort reach the gateway; the answer
    /// comes back with the served model, tokens and cost.
    #[test]
    fn the_declared_lane_answers_with_its_model_tokens_and_cost() {
        std::env::set_var(KEY_ENV, "test-key");
        let (url, request) = fake_gateway(
            "200 OK",
            "x-litellm-model-name: openai/gpt-6-astra\r\nx-litellm-response-cost: 0.0315\r\n",
            r#"{"choices":[{"message":{"content":"The beam yields first."}}],"usage":{"prompt_tokens":812,"completion_tokens":2240}}"#,
        );
        let (runtime, _root) = runtime(&url);
        let result = invoke(
            &runtime,
            "sinmara",
            json!({"question": "Which fails first?", "material": "L = 2 m"}),
        )
        .expect("consult");
        assert_eq!(result["answer"], "The beam yields first.");
        assert_eq!(result["lane"], "astra");
        assert_eq!(result["served_model"], "openai/gpt-6-astra");
        assert_eq!(result["input_tokens"], 812);
        assert_eq!(result["output_tokens"], 2240);
        assert_eq!(result["cost_usd"], 0.0315);
        let request = request.recv().expect("request");
        assert!(
            request.starts_with("POST /v1/chat/completions"),
            "{request}"
        );
        assert!(
            request.contains("x-litellm-tags: seat:sinmara,consult"),
            "{request}"
        );
        let body: Value =
            serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).expect("json body");
        assert_eq!(body["model"], "astra");
        assert_eq!(body["reasoning_effort"], "high");
        let user = body["messages"][1]["content"].as_str().unwrap();
        assert!(
            user.starts_with("Which fails first?") && user.ends_with("L = 2 m"),
            "{user}"
        );
    }

    #[test]
    fn a_seat_without_a_consult_declaration_is_refused_by_name() {
        let (runtime, _root) = runtime("http://127.0.0.1:9");
        let error = invoke(&runtime, "helper", json!({"question": "q"})).expect_err("undeclared");
        let message = error.to_string();
        assert!(
            message.contains("seat helper declares no [context] consult lane"),
            "{message}"
        );
    }

    type Asked = (String, String, String, Option<String>);

    struct FakeOfficialRoute {
        asked: std::sync::Mutex<Vec<Asked>>,
    }

    impl OfficialConsultRoute for FakeOfficialRoute {
        fn models(&self) -> Vec<OfficialConsultModel> {
            vec![OfficialConsultModel {
                id: "claude/claude-opus-5-5".to_owned(),
                route: "claude-code".to_owned(),
                model: "claude-opus-5-5".to_owned(),
                effort: "high".to_owned(),
                strengths: "Hard engineering judgment".to_owned(),
            }]
        }

        fn consult(
            &self,
            seat: &str,
            model: &OfficialConsultModel,
            question: &str,
            material: Option<&str>,
        ) -> Result<OfficialConsultOutcome, String> {
            self.asked.lock().expect("asked").push((
                seat.to_owned(),
                model.id.clone(),
                question.to_owned(),
                material.map(str::to_owned),
            ));
            Ok(OfficialConsultOutcome {
                answer: "Opus weighed in.".to_owned(),
                served_model: Some(model.model.clone()),
                seconds: 4,
                input_tokens: Some(120),
                output_tokens: Some(80),
                cost_usd: Some(0.06),
            })
        }
    }

    #[test]
    fn naming_an_official_model_returns_the_drivers_answer() {
        let (runtime, _root) = runtime("http://127.0.0.1:9");
        let route = Arc::new(FakeOfficialRoute {
            asked: std::sync::Mutex::new(Vec::new()),
        });
        runtime.set_consult_route(route.clone());
        let result = invoke(
            &runtime,
            "sinmara",
            json!({"question": "Is the truss overconstrained?", "material": "Node loads: 4 kN", "model": "claude/claude-opus-5-5"}),
        )
        .expect("consult");
        assert_eq!(result["answer"], "Opus weighed in.");
        assert_eq!(result["lane"], "claude/claude-opus-5-5");
        assert_eq!(result["served_model"], "claude-opus-5-5");
        assert_eq!(result["input_tokens"], 120);
        assert_eq!(result["output_tokens"], 80);
        assert_eq!(result["cost_usd"], 0.06);
        let asked = route.asked.lock().expect("asked");
        assert_eq!(
            asked.last().map(|(seat, id, question, material)| {
                (
                    seat.as_str(),
                    id.as_str(),
                    question.as_str(),
                    material.as_deref(),
                )
            }),
            Some((
                "sinmara",
                "claude/claude-opus-5-5",
                "Is the truss overconstrained?",
                Some("Node loads: 4 kN")
            ))
        );
    }
}
