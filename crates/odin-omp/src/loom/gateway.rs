//! Streaming OpenAI chat completions to the model gateway (LiteLLM), the
//! same provider OMP is given: `<gateway>/v1/chat/completions`, the gateway
//! key as bearer, and the session's spend tag in `x-litellm-tags`.

use std::time::Duration;

use serde_json::{json, Map, Value};

use super::journal::Call;

/// The gateway spend-tag header, as the rendered OMP provider sets it.
const SPEND_TAG_HEADER: &str = "x-litellm-tags";

#[derive(Clone, Debug)]
pub struct Gateway {
    pub url: String,
    pub key: String,
}

/// One answered round.
#[derive(Debug, Default)]
pub struct Reply {
    pub text: String,
    pub reasoning: Option<String>,
    pub calls: Vec<Call>,
    /// Message-level opaque provider fields to send back with this message.
    pub opaque: Option<Value>,
    pub prompt_tokens: Option<u64>,
    pub cached_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
}

#[derive(Default)]
struct PartialCall {
    id: String,
    name: String,
    arguments: String,
    opaque: Option<Value>,
}

/// How long a request may take to connect, and to go without a byte.
#[derive(Clone, Copy, Debug)]
pub struct Timeouts {
    pub connect: Duration,
    pub idle: Duration,
}

/// Why a round got no usable reply: the cause, and the HTTP status when the
/// gateway or provider gave one (402, 429, 5xx drive Hermes's lane fallback
/// and account holds exactly as OMP's provider errors do).
#[derive(Clone, Debug)]
pub struct Refusal {
    pub message: String,
    pub status: Option<u16>,
}

impl Refusal {
    fn new(message: String) -> Self {
        Self {
            message,
            status: None,
        }
    }
}

impl Gateway {
    fn endpoint(&self) -> String {
        format!("{}/v1/chat/completions", self.url.trim_end_matches('/'))
    }

    /// Streams one request; `on_text` sees every text delta. Every failure
    /// names the lane and its cause. A stream that ends before both its
    /// finish reason and `[DONE]` is a refusal: nothing partial is kept.
    pub async fn complete(
        &self,
        tag: &str,
        body: &Value,
        timeouts: Timeouts,
        mut on_text: impl FnMut(&str),
    ) -> Result<Reply, Refusal> {
        let lane = body["model"].as_str().unwrap_or("the gateway").to_owned();
        let stalled = || {
            Refusal::new(format!(
                "lane {lane}: the stream stalled for {} seconds (stream_idle_seconds)",
                timeouts.idle.as_secs()
            ))
        };
        let client = reqwest::Client::builder()
            .connect_timeout(timeouts.connect)
            .build()
            .map_err(|error| Refusal::new(format!("gateway client: {error}")))?;
        let send = client
            .post(self.endpoint())
            .bearer_auth(&self.key)
            .header(SPEND_TAG_HEADER, tag)
            .json(body)
            .send();
        let mut response = tokio::time::timeout(timeouts.idle, send)
            .await
            .map_err(|_| stalled())?
            .map_err(|error| {
                Refusal::new(format!("lane {lane}: the gateway request failed: {error}"))
            })?;
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(Refusal {
                message: format!(
                    "lane {lane}: the gateway answered {status}: {}",
                    text.chars().take(600).collect::<String>()
                ),
                status: Some(status.as_u16()),
            });
        }
        let mut reply = Reply::default();
        let mut calls: Vec<PartialCall> = Vec::new();
        let mut buffer = Vec::new();
        let (mut done, mut finished) = (false, false);
        while !done {
            let Some(chunk) = tokio::time::timeout(timeouts.idle, response.chunk())
                .await
                .map_err(|_| stalled())?
                .map_err(|error| Refusal::new(format!("lane {lane}: the stream broke: {error}")))?
            else {
                break;
            };
            buffer.extend_from_slice(&chunk);
            while let Some(end) = buffer.iter().position(|byte| *byte == b'\n') {
                let line: Vec<u8> = buffer.drain(..=end).collect();
                let line = String::from_utf8_lossy(&line);
                let Some(data) = line.trim().strip_prefix("data:") else {
                    continue;
                };
                let data = data.trim();
                if data == "[DONE]" {
                    done = true;
                    break;
                }
                let event: Value = serde_json::from_str(data).map_err(|error| {
                    Refusal::new(format!("lane {lane}: unreadable stream event: {error}"))
                })?;
                if let Some(error) = event.get("error").filter(|error| !error.is_null()) {
                    return Err(Refusal {
                        message: format!(
                            "lane {lane}: the provider refused: {}",
                            error["message"]
                                .as_str()
                                .map_or_else(|| error.to_string(), str::to_owned)
                        ),
                        status: error["code"]
                            .as_u64()
                            .or_else(|| error["code"].as_str().and_then(|code| code.parse().ok()))
                            .and_then(|code| u16::try_from(code).ok()),
                    });
                }
                finished |= absorb(&event, &mut reply, &mut calls, &mut on_text);
            }
        }
        if !(done && finished) {
            return Err(Refusal::new(format!(
                "lane {lane}: the stream ended before the reply finished (finish reason \
                 {}, [DONE] {}); nothing of it was kept",
                if finished { "seen" } else { "missing" },
                if done { "seen" } else { "missing" },
            )));
        }
        reply.calls = calls
            .into_iter()
            .map(|call| Call {
                id: call.id,
                name: call.name,
                arguments: if call.arguments.trim().is_empty() {
                    "{}".to_owned()
                } else {
                    call.arguments
                },
                opaque: call.opaque,
            })
            .collect();
        Ok(reply)
    }
}

fn merge(slot: &mut Option<Value>, fields: &Value) {
    let (Some(slot), Value::Object(fields)) = (
        slot.get_or_insert_with(|| json!({})).as_object_mut(),
        fields,
    ) else {
        return;
    };
    for (key, value) in fields {
        match (slot.get_mut(key), value) {
            (Some(Value::Array(existing)), Value::Array(more)) => existing.extend(more.clone()),
            _ => {
                slot.insert(key.clone(), value.clone());
            }
        }
    }
}

/// Folds one stream event into the reply; true when it carries the finish reason.
fn absorb(
    event: &Value,
    reply: &mut Reply,
    calls: &mut Vec<PartialCall>,
    on_text: &mut impl FnMut(&str),
) -> bool {
    if let Some(usage) = event.get("usage").filter(|usage| usage.is_object()) {
        reply.prompt_tokens = usage["prompt_tokens"].as_u64().or(reply.prompt_tokens);
        reply.output_tokens = usage["completion_tokens"].as_u64().or(reply.output_tokens);
        reply.cached_tokens = usage["prompt_tokens_details"]["cached_tokens"]
            .as_u64()
            .or(reply.cached_tokens);
    }
    let Some(choice) = event["choices"].get(0) else {
        return false;
    };
    let finished = choice["finish_reason"].is_string();
    let delta = &choice["delta"];
    if let Some(text) = delta["content"].as_str().filter(|text| !text.is_empty()) {
        reply.text.push_str(text);
        on_text(text);
    }
    if let Some(text) = delta["reasoning_content"]
        .as_str()
        .filter(|text| !text.is_empty())
    {
        reply
            .reasoning
            .get_or_insert_with(String::new)
            .push_str(text);
    }
    for key in ["provider_specific_fields", "thinking_blocks"] {
        if let Some(fields) = delta.get(key).filter(|fields| !fields.is_null()) {
            let wrapped = json!({ key: fields });
            merge(&mut reply.opaque, &wrapped);
        }
    }
    for delta in delta["tool_calls"].as_array().into_iter().flatten() {
        let index = delta["index"].as_u64().unwrap_or(calls.len() as u64) as usize;
        while calls.len() <= index {
            calls.push(PartialCall::default());
        }
        let call = &mut calls[index];
        if let Some(id) = delta["id"].as_str().filter(|id| !id.is_empty()) {
            call.id = id.to_owned();
        }
        // Some providers repeat the whole name on later chunks.
        if let Some(name) = delta["function"]["name"].as_str() {
            if name != call.name {
                call.name.push_str(name);
            }
        }
        if let Some(arguments) = delta["function"]["arguments"].as_str() {
            call.arguments.push_str(arguments);
        }
        if let Some(fields) = delta
            .get("provider_specific_fields")
            .filter(|f| f.is_object())
        {
            merge(&mut call.opaque, fields);
        }
    }
    finished
}

/// The request body: no `cache_control` ever (it would buy paid explicit
/// caches); the cache key names the session's context epoch.
pub fn body(
    lane: &str,
    messages: Vec<Value>,
    tools: &[Value],
    cache_key: &str,
    effort: Option<&str>,
) -> Value {
    let mut body = Map::new();
    body.insert("model".into(), json!(lane));
    body.insert("messages".into(), Value::Array(messages));
    if !tools.is_empty() {
        body.insert("tools".into(), Value::Array(tools.to_vec()));
    }
    body.insert("stream".into(), json!(true));
    body.insert("stream_options".into(), json!({"include_usage": true}));
    body.insert("prompt_cache_key".into(), json!(cache_key));
    if let Some(effort) = effort {
        body.insert("reasoning_effort".into(), json!(effort));
    }
    Value::Object(body)
}
