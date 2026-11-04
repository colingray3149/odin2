//! `model_complete` — one prompt, one local model, one shot.
//!
//! The caller names a model on the local list and gives the whole prompt; it is
//! sent as a single user message with the caller's `max_tokens` cap, through
//! the same gateway path that serves the local family's lanes. Meant for
//! rewrites that keep the caller's own wording decisions — a humanizing pass
//! over a draft section — not for questions, which the caller or `model.consult`
//! answer better. The answer comes back with the lane that served it, the time
//! it took, its tokens and the cost. Gateway requests carry the
//! `seat:<seat>,complete` spend tag; odind logs one `model.complete` line per
//! call.

use std::sync::Arc;

use odin_domain::Scope;
use odin_omp::capability_parameters;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode};
use serde_json::{json, Value};

use super::gateway;
use super::models::{local_family, LocalMember};
use super::tools::CapabilityTool;
use super::HermesRuntime;

const TOOL: &str = "model_complete";
/// The largest cap a call may set: a full section's rewrite, never an unbounded run.
const MAX_TOKENS: u64 = 16384;

/// The member a caller's `id` names — the bare id from the local list, its
/// `local/<id>` lane or the family card's `gateway/local/<id>` — refusing ids
/// that are not chat or vision members and members a mode holds.
fn resolve<'a>(id: &str, members: &'a [LocalMember]) -> Result<&'a LocalMember, HostToolError> {
    let id = id
        .strip_prefix("gateway/local/")
        .or_else(|| id.strip_prefix("local/"))
        .unwrap_or(id);
    match members.iter().find(|member| member.id == id) {
        Some(member) => match &member.hold {
            Some(hold) => Err(HostToolError::unavailable(
                TOOL,
                format!("local/{id} cannot take work: {hold}"),
            )),
            None => Ok(member),
        },
        None => {
            let known: Vec<&str> = members.iter().map(|member| member.id.as_str()).collect();
            Err(HostToolError::Arguments {
                tool: TOOL,
                detail: format!(
                    "{id} is not on the local list; its chat and vision models are: {}",
                    known.join(", ")
                ),
            })
        }
    }
}

/// One prompt to one local lane, with the caller's cap.
fn complete(
    gateway: &str,
    seat: &str,
    lane: &str,
    prompt: &str,
    max_tokens: u64,
) -> Result<Value, HostToolError> {
    let reply = gateway::chat(
        gateway,
        &format!("seat:{seat},complete"),
        None,
        &json!({
            "model": lane,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }),
    )
    .map_err(|reason| HostToolError::unavailable(TOOL, reason))?;
    reply.log("model.complete", seat, lane);
    let mut result = reply.facts(lane);
    result["text"] = json!(reply.text);
    Ok(result)
}

pub(super) fn model_complete_tools(
    runtime: &Arc<HermesRuntime>,
    tools: &mut Vec<Arc<dyn HostTool>>,
) {
    let runtime = Arc::clone(runtime);
    let handler = move |scope: Scope, arguments: Value| {
        let id = super::tools::parse_string(&arguments, "id", 200)?;
        let prompt = super::tools::parse_string(&arguments, "prompt", 120_000)?;
        let max_tokens = arguments
            .get("max_tokens")
            .and_then(Value::as_u64)
            .filter(|cap| (1..=MAX_TOKENS).contains(cap))
            .ok_or_else(|| HostToolError::Arguments {
                tool: TOOL,
                detail: format!("max_tokens must be an integer 1..={MAX_TOKENS}"),
            })?;
        let members = local_family().map_err(|reason| HostToolError::unavailable(TOOL, reason))?;
        let member = resolve(&id, &members)?;
        let gateway = runtime.model_gateway().ok_or_else(|| {
            HostToolError::unavailable(TOOL, "odind has no model gateway configured")
        })?;
        let seat = scope.seat.as_ref().map_or("", |seat| seat.as_str());
        complete(&gateway, seat, &member.lane(), &prompt, max_tokens)
    };
    tools.push(Arc::new(CapabilityTool::plain_without_prerequisites(
        RpcHostToolDefinition {
            name: TOOL.into(),
            label: "One-shot local model completion".into(),
            description: "Run one prompt through one local model on the local list, as a single \
                user message with a required max_tokens cap: the whole prompt — instructions \
                and the text to rewrite together — goes in prompt, the model's list id in id. \
                Meant for rewrites that keep your own wording decisions, like a humanizing \
                pass over a draft section; answer questions yourself or consult a stronger \
                model. Returns the text with the lane, seconds, tokens and cost."
                .into(),
            parameters: capability_parameters!("model.complete"),
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
        },
        Box::new(handler),
    )));
}

#[cfg(test)]
mod tests {
    use crate::runtime::gateway::{tests::fake as fake_gateway, KEY_ENV};
    use odin_domain::SeatId;

    use super::*;
    use serde_json::json;

    /// The local list fixture: one temp dir held for the process lifetime, set
    /// once — `set_local_list` keeps only the first path, so a per-test temp
    /// dir would delete the list out from under the other tests in a shared
    /// test process. Two chat models and an embedding.
    fn declare_local_list() -> &'static tempfile::TempDir {
        static LIST: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
        LIST.get_or_init(|| {
            let dir = tempfile::tempdir().expect("dir");
            std::fs::write(
                dir.path().join("local-list.json"),
                r#"{"models":[
                    {"id":"lfm2.5-8b-a1b","kind":"chat","context":131072},
                    {"id":"qwen3.6-35b","kind":"chat","context":131072},
                    {"id":"bge","kind":"embedding","context":null}
                ]}"#,
            )
            .expect("list");
            super::super::models::set_local_list(dir.path().join("local-list.json"));
            dir
        })
    }

    /// A runtime with only a model gateway, the way the handler reads it.
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
        runtime.set_model_gateway(gateway.to_owned());
        (runtime, root)
    }

    fn invoke(
        runtime: &Arc<HermesRuntime>,
        seat: &str,
        arguments: Value,
    ) -> Result<Value, HostToolError> {
        let mut tools = Vec::new();
        model_complete_tools(runtime, &mut tools);
        tools
            .pop()
            .expect("model_complete tool")
            .invoke(odin_omp::host_tools::HostInvocation {
                scope: Scope {
                    seat: Some(SeatId::new(seat).unwrap()),
                    ..Scope::default()
                },
                arguments,
            })
    }

    /// The prompt reaches the lane as one user message with the cap, and the
    /// text comes back with the served model, tokens and cost.
    #[test]
    fn one_prompt_reaches_the_local_lane_with_its_cap() {
        std::env::set_var(KEY_ENV, "test-key");
        let _list = declare_local_list();
        let (url, request) = fake_gateway(
            "200 OK",
            "x-litellm-model-name: local/lfm2.5-8b-a1b\r\nx-litellm-response-cost: 0\r\n",
            r#"{"choices":[{"message":{"content":"The stones stand above the road."}}],"usage":{"prompt_tokens":1200,"completion_tokens":640}}"#,
        );
        let (runtime, _root) = runtime(&url);
        let prompt = "Rewrite this section in the voice of the style card.\n\nThe stones...";
        let result = invoke(
            &runtime,
            "gungnir",
            json!({"id": "lfm2.5-8b-a1b", "prompt": prompt, "max_tokens": 2048}),
        )
        .expect("complete");
        assert_eq!(result["text"], "The stones stand above the road.");
        assert_eq!(result["lane"], "local/lfm2.5-8b-a1b");
        assert_eq!(result["served_model"], "local/lfm2.5-8b-a1b");
        assert_eq!(result["input_tokens"], 1200);
        assert_eq!(result["output_tokens"], 640);
        let request = request.recv().expect("request");
        assert!(
            request.starts_with("POST /v1/chat/completions"),
            "{request}"
        );
        assert!(
            request.contains("x-litellm-tags: seat:gungnir,complete"),
            "{request}"
        );
        let body: Value =
            serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).expect("json body");
        assert_eq!(body["model"], "local/lfm2.5-8b-a1b");
        assert_eq!(body["max_tokens"], 2048);
        assert_eq!(
            body["messages"],
            json!([{"role": "user", "content": prompt}])
        );
    }

    /// An id that is not a chat or vision member is refused with the family.
    #[test]
    fn an_unknown_id_lists_the_family() {
        let _list = declare_local_list();
        let (runtime, _root) = runtime("http://127.0.0.1:9");
        let error = invoke(
            &runtime,
            "gungnir",
            json!({"id": "bge", "prompt": "p", "max_tokens": 64}),
        )
        .expect_err("unknown id");
        let message = error.to_string();
        assert!(
            message.contains("bge is not on the local list"),
            "{message}"
        );
        assert!(message.contains("lfm2.5-8b-a1b, qwen3.6-35b"), "{message}");
    }

    /// A refusing lane names its status and the router's own message.
    #[test]
    fn a_refusing_lane_names_its_status_and_message() {
        std::env::set_var(KEY_ENV, "test-key");
        let _list = declare_local_list();
        let (url, _request) = fake_gateway(
            "500 Internal Server Error",
            "",
            r#"{"error":{"message":"model server crashed"}}"#,
        );
        let (runtime, _root) = runtime(&url);
        let error = invoke(
            &runtime,
            "gungnir",
            json!({"id": "lfm2.5-8b-a1b", "prompt": "p", "max_tokens": 64}),
        )
        .expect_err("refused");
        let message = error.to_string();
        assert!(
            message.contains(
                "the local/lfm2.5-8b-a1b lane refused (500 Internal Server Error): model server crashed"
            ),
            "{message}"
        );
    }

    /// A member a mode holds names why it cannot take work.
    #[test]
    fn a_held_member_refuses_with_its_hold() {
        let members = vec![LocalMember {
            id: "lfm2.5-8b-a1b".to_owned(),
            vision: false,
            context: 131072,
            hold: Some(
                "the local models are off: kreate mode since 2026-11-02T09:00:00Z".to_owned(),
            ),
        }];
        let error = resolve("local/lfm2.5-8b-a1b", &members).expect_err("held");
        let message = error.to_string();
        assert!(
            message.contains("local/lfm2.5-8b-a1b cannot take work: the local models are off"),
            "{message}"
        );
    }
}
