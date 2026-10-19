//! Discord's REST rate limits as its responses report them: a route whose
//! bucket is spent waits for its reset, a 429 is waited out and retried
//! once, and a global 429 pauses every route of the one bot token.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use reqwest::header::HeaderMap;
use reqwest::{RequestBuilder, Response, StatusCode};
use serde_json::Value;
use tokio::time::Instant;

use super::DiscordSendError;

/// A 429 that names no wait still waits this long, never a hot retry.
const MIN_RETRY: Duration = Duration::from_secs(1);
/// The longest wait honoured before a send; a longer one is reported.
const MAX_WAIT: Duration = Duration::from_secs(60);

#[derive(Default)]
pub(super) struct RateGate {
    state: Mutex<GateState>,
}

#[derive(Default)]
struct GateState {
    routes: HashMap<String, Instant>,
    global: Option<Instant>,
}

impl RateGate {
    /// Sends the request `build` makes on `route` under the route's limit,
    /// retrying exactly once after a 429. The response is returned as
    /// Discord sent it (a second 429 included) for the caller to settle.
    pub(super) async fn send(
        &self,
        route: &str,
        build: impl Fn() -> RequestBuilder,
    ) -> Result<Response, DiscordSendError> {
        let response = self.send_once(route, &build).await?;
        if response.status() != StatusCode::TOO_MANY_REQUESTS {
            return Ok(response);
        }
        let header_global = response
            .headers()
            .get("x-ratelimit-global")
            .is_some_and(|value| value.as_bytes() == b"true");
        let header_retry = seconds_header(response.headers(), "retry-after");
        let body: Value = response.json().await.unwrap_or(Value::Null);
        let retry = body
            .get("retry_after")
            .and_then(Value::as_f64)
            .or(header_retry)
            .map(seconds)
            .unwrap_or_default()
            .max(MIN_RETRY);
        let global = header_global || body.get("global").and_then(Value::as_bool) == Some(true);
        tracing::warn!(
            route = %route,
            retry_after_ms = retry.as_millis() as u64,
            global,
            "odind: discord rate-limited route=\"{route}\" retry_after_ms={} global={global}",
            retry.as_millis()
        );
        if retry > MAX_WAIT {
            return Err(DiscordSendError::RateLimited {
                retry_after_ms: u64::try_from(retry.as_millis()).unwrap_or(u64::MAX),
            });
        }
        self.block(route, Instant::now() + retry, global);
        self.send_once(route, &build).await
    }

    async fn send_once(
        &self,
        route: &str,
        build: &impl Fn() -> RequestBuilder,
    ) -> Result<Response, DiscordSendError> {
        if let Some(until) = self.blocked_until(route) {
            tokio::time::sleep_until(until.min(Instant::now() + MAX_WAIT)).await;
        }
        let response = build().send().await.map_err(|error| {
            if error.is_connect() {
                DiscordSendError::Unreachable
            } else {
                DiscordSendError::ServiceUnavailable
            }
        })?;
        let headers = response.headers();
        if headers
            .get("x-ratelimit-remaining")
            .is_some_and(|value| value.as_bytes() == b"0")
        {
            if let Some(reset) = seconds_header(headers, "x-ratelimit-reset-after") {
                self.block(route, Instant::now() + seconds(reset), false);
            }
        }
        Ok(response)
    }

    fn blocked_until(&self, route: &str) -> Option<Instant> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let now = Instant::now();
        [state.routes.get(route).copied(), state.global]
            .into_iter()
            .flatten()
            .filter(|until| *until > now)
            .max()
    }

    fn block(&self, route: &str, until: Instant, global: bool) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let now = Instant::now();
        state.routes.retain(|_, until| *until > now);
        if global {
            state.global = Some(until);
        } else {
            state.routes.insert(route.to_owned(), until);
        }
    }
}

fn seconds_header(headers: &HeaderMap, name: &str) -> Option<f64> {
    headers.get(name)?.to_str().ok()?.trim().parse().ok()
}

fn seconds(value: f64) -> Duration {
    Duration::try_from_secs_f64(value).unwrap_or_default()
}
