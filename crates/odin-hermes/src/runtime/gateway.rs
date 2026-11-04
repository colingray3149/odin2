//! The daemon's own calls to the model gateway (LiteLLM): its key, one
//! tagged chat completion, and the served model and cost the reply carries.

use std::time::{Duration, Instant};

use serde_json::{json, Value};

/// The env var holding the model gateway bearer, for every gateway call.
pub(crate) const KEY_ENV: &str = "LITELLM_MASTER_KEY";

/// The gateway key odind holds; an empty value counts as unset.
pub(super) fn key() -> Result<String, String> {
    std::env::var(KEY_ENV)
        .ok()
        .filter(|key| !key.is_empty())
        .ok_or_else(|| format!("{KEY_ENV} is not set for odind on this host"))
}

/// The chat-completions endpoint of a gateway base URL (or of the endpoint itself).
fn chat_url(gateway: &str) -> String {
    let base = gateway.trim_end_matches('/');
    if base.ends_with("/v1/chat/completions") {
        base.to_owned()
    } else {
        format!("{base}/v1/chat/completions")
    }
}

/// One answered completion and what the gateway reported about serving it.
pub(super) struct Reply {
    pub text: String,
    pub served: Option<String>,
    pub cost: Option<f64>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub seconds: u64,
}

impl Reply {
    /// The facts every model call reports beside its text.
    pub fn facts(&self, lane: &str) -> Value {
        json!({
            "lane": lane,
            "served_model": self.served,
            "seconds": self.seconds,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cost_usd": self.cost,
        })
    }

    /// The one journal line for a call (`what` is the capability, e.g. `model.consult`).
    pub fn log(&self, what: &str, seat: &str, lane: &str) {
        let unknown = |value: Option<String>| value.unwrap_or_else(|| "unknown".to_owned());
        tracing::info!(
            "odind: {what} seat={seat} lane={lane} served={} seconds={} input_tokens={} output_tokens={} cost_usd={}",
            self.served.as_deref().unwrap_or("unknown"),
            self.seconds,
            unknown(self.input_tokens.map(|n| n.to_string())),
            unknown(self.output_tokens.map(|n| n.to_string())),
            unknown(self.cost.map(|cost| format!("{cost:.4}"))),
        );
    }
}

/// Posts `request` (its `model` names the lane) to the gateway under `tag`
/// for spend attribution. Every failure names the lane and its cause.
pub(super) fn chat(
    gateway: &str,
    tag: &str,
    timeout: Option<Duration>,
    request: &Value,
) -> Result<Reply, String> {
    let key = key()?;
    let lane = request["model"].as_str().unwrap_or("the gateway");
    let client =
        crate::http_pool::default_redirect().map_err(|error| format!("gateway client: {error}"))?;
    let started = Instant::now();
    let mut post = client
        .post(chat_url(gateway))
        .bearer_auth(key)
        .header(odin_omp::SPEND_TAG_HEADER, tag)
        .json(request);
    if let Some(timeout) = timeout {
        post = post.timeout(timeout);
    }
    let response = post
        .send()
        .map_err(|error| format!("the {lane} lane did not answer: {error}"))?;
    let status = response.status();
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    let served = header("x-litellm-model-name");
    let cost = header("x-litellm-response-cost").and_then(|cost| cost.parse::<f64>().ok());
    let body: Value = response
        .json()
        .map_err(|error| format!("the {lane} lane answered {status} without JSON: {error}"))?;
    if !status.is_success() {
        let detail = body
            .pointer("/error/message")
            .and_then(Value::as_str)
            .map_or_else(|| body.to_string(), str::to_owned);
        return Err(format!("the {lane} lane refused ({status}): {detail}"));
    }
    let text = body
        .pointer("/choices/0/message/content")
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .ok_or_else(|| format!("the {lane} lane returned no answer: {body}"))?
        .to_owned();
    Ok(Reply {
        text,
        served,
        cost,
        input_tokens: body.pointer("/usage/prompt_tokens").and_then(Value::as_u64),
        output_tokens: body
            .pointer("/usage/completion_tokens")
            .and_then(Value::as_u64),
        seconds: started.elapsed().as_secs(),
    })
}

#[cfg(test)]
pub(super) mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    /// A one-request gateway that hands back the raw request it received.
    pub fn fake(status: &str, headers: &str, body: &str) -> (String, mpsc::Receiver<String>) {
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("addr");
        let (sent, received) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 8192];
            loop {
                let read = stream.read(&mut buffer).expect("read");
                request.extend_from_slice(&buffer[..read]);
                let text = String::from_utf8_lossy(&request);
                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let length = head
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .map(str::to_owned)
                        })
                        .and_then(|length| length.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if body.len() >= length {
                        break;
                    }
                }
            }
            sent.send(String::from_utf8_lossy(&request).into_owned())
                .unwrap();
            stream.write_all(response.as_bytes()).expect("write");
        });
        (format!("http://{address}"), received)
    }
}
