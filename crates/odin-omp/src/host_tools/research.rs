//! The research VPN exit. A page fetch that a site refuses, or that times out, through the
//! research VPN is tried again from the next region: the root helper behind `exit_socket` moves
//! the exit and names the regions it has not tried. A site that fails in every region tried is
//! recorded under `<state>/refused/<host>`; a site the owner allowed (`<state>/direct/<host>`) is
//! fetched once on mini's own network instead.

use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use odin_adapter_core::transport::{
    AdapterErrorCode, AdapterTransportFault, JsonRpcOutcome, JsonRpcRequest, RpcMethod,
};
use odin_kernel::HandlerBinding;
use serde_json::{json, Value};

/// The carrier's flag, and the variable its nested carriers inherit, that run a command on
/// mini's own network instead of the research namespace.
pub const DIRECT_FLAG: &str = "--direct";
pub const DIRECT_ENV: &str = "ODIN_RESEARCH_DIRECT";

/// The most of one helper reply that is read.
const REPLY_BYTES: u64 = 64 * 1024;

/// Where one attempt leaves: the research exit, or mini's own network for an allowed site.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Way {
    Exit,
    Direct,
}

/// What one attempt came to.
pub enum Attempt<T> {
    /// It ended: served, or failed for a reason another region cannot change.
    Done(T),
    /// The site refused or timed out; the cause is the last thing it said.
    Refused(String),
}

impl<T> Attempt<T> {
    /// The attempt as a single try: a refusal is its cause.
    pub fn once(self) -> Result<T, String> {
        match self {
            Self::Done(done) => Ok(done),
            Self::Refused(cause) => Err(cause),
        }
    }
}

/// The helper's answer to a `next` request: the region it moved to, if one was left, and every
/// region this fetch has now used.
struct Moved {
    region: Option<String>,
    tried: Vec<String>,
}

pub struct ResearchExit {
    exit_socket: PathBuf,
    state: PathBuf,
}

impl ResearchExit {
    pub fn new(exit_socket: PathBuf, state: PathBuf) -> Self {
        Self { exit_socket, state }
    }

    /// Runs `attempt(way, time left)` for the page at `url`. While it is refused, the exit moves
    /// to the next region and it runs again, each region at most once and only while the call
    /// has as long left as its slowest attempt took. Success and every other failure return as
    /// they are. `Err` is the message for a site no region served, or for an exit that could not
    /// move. An allowed site runs once, directly.
    pub fn fetch<T>(
        &self,
        url: &str,
        timeout: Duration,
        mut attempt: impl FnMut(Way, Duration) -> Attempt<T>,
    ) -> Result<T, String> {
        let host = url::Url::parse(url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned));
        let Some(host) = host else {
            return attempt(Way::Exit, timeout).once();
        };
        if self.state.join("direct").join(&host).is_file() {
            return attempt(Way::Direct, timeout).once();
        }
        let deadline = Instant::now() + timeout;
        let mut tried: Vec<String> = Vec::new();
        let mut slowest = Duration::ZERO;
        loop {
            let started = Instant::now();
            let cause = match attempt(Way::Exit, deadline.saturating_duration_since(started)) {
                Attempt::Done(done) => return Ok(done),
                Attempt::Refused(cause) => cause,
            };
            slowest = slowest.max(started.elapsed());
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() || left < slowest {
                return Err(if tried.is_empty() {
                    stuck(&host, &cause, "no time was left in the call")
                } else {
                    self.exhausted(&host, &tried, &cause)
                });
            }
            match self.next(&tried, left) {
                Ok(Moved {
                    region: Some(_),
                    tried: now,
                }) => tried = now,
                Ok(Moved { tried: now, .. }) => return Err(self.exhausted(&host, &now, &cause)),
                Err(reason) => return Err(stuck(&host, &cause, &reason)),
            }
        }
    }

    /// An operation that fetches a page (`input.url`) through the named adapter, retried like
    /// [`Self::fetch`]. A refusal is the adapter's typed error marked `data.refused`. Probes and
    /// operations with no URL pass through once. `call` makes one framed call with a binding.
    pub fn adapter_call(
        &self,
        binding: &HandlerBinding,
        timeout: Duration,
        request: &JsonRpcRequest,
        call: impl Fn(
            &HandlerBinding,
            Duration,
            &JsonRpcRequest,
        ) -> Result<JsonRpcOutcome, AdapterTransportFault>,
    ) -> Result<JsonRpcOutcome, AdapterTransportFault> {
        let url = match (&request.method, request.params["input"]["url"].as_str()) {
            (RpcMethod::Operation(_), Some(url)) => url,
            _ => return call(binding, timeout, request),
        };
        let fetched = self.fetch(url, timeout, |way, left| {
            let outcome = match (way, binding) {
                (Way::Direct, HandlerBinding::Exec { executable, argv }) => {
                    let mut direct = vec![DIRECT_FLAG.to_owned()];
                    direct.extend(argv.iter().cloned());
                    let binding = HandlerBinding::Exec {
                        executable: executable.clone(),
                        argv: direct,
                    };
                    call(&binding, left, request)
                }
                _ => call(binding, left, request),
            };
            match outcome {
                Ok(JsonRpcOutcome::Error {
                    message,
                    data: Some(data),
                    ..
                }) if data.get("refused") == Some(&Value::Bool(true)) => Attempt::Refused(message),
                other => Attempt::Done(other),
            }
        });
        match fetched {
            Ok(outcome) => outcome,
            Err(message) => Ok(JsonRpcOutcome::Error {
                id: request.id.clone(),
                code: AdapterErrorCode::InternalError,
                message,
                data: None,
            }),
        }
    }

    /// Records the regions that all failed, so a direct route can be asked about, and says so.
    fn exhausted(&self, host: &str, tried: &[String], cause: &str) -> String {
        let record = self.state.join("refused").join(host);
        let written = record
            .parent()
            .map_or(Ok(()), std::fs::create_dir_all)
            .and_then(|()| std::fs::write(&record, format!("{}\n", tried.join(" "))));
        let mut said = format!(
            "{host} refused or timed out through every research VPN region tried ({}); last: {cause}; \
             web.direct can ask the owner to route {host} directly",
            tried.join(", ")
        );
        if let Err(error) = written {
            said.push_str(&format!(
                "; it could not be recorded at {} for a direct route: {error}",
                record.display()
            ));
        }
        said
    }

    /// Asks the helper to move the exit to a region this fetch has not tried.
    fn next(&self, tried: &[String], within: Duration) -> Result<Moved, String> {
        let reply = self.ask(&json!({"action": "next", "tried": tried}), within)?;
        let tried = reply["tried"]
            .as_array()
            .map(|regions| {
                regions
                    .iter()
                    .filter_map(|region| region.as_str().map(str::to_owned))
                    .collect()
            })
            .ok_or("the research exit helper named no tried regions")?;
        Ok(Moved {
            region: reply["region"].as_str().map(str::to_owned),
            tried,
        })
    }

    /// One request and reply over the owner-only socket. `Err` is the helper's own cause, or why
    /// it could not be asked.
    fn ask(&self, request: &Value, within: Duration) -> Result<Value, String> {
        let socket = self.exit_socket.display();
        let unreachable = |what: &str, error: std::io::Error| {
            format!("the research exit helper at {socket} {what}: {error}")
        };
        let mut stream = UnixStream::connect(&self.exit_socket)
            .map_err(|error| unreachable("is unreachable", error))?;
        stream
            .set_read_timeout(Some(within))
            .and_then(|()| stream.set_write_timeout(Some(within)))
            .and_then(|()| stream.write_all(request.to_string().as_bytes()))
            .and_then(|()| stream.shutdown(Shutdown::Write))
            .map_err(|error| unreachable("did not take the request", error))?;
        let mut reply = String::new();
        stream
            .take(REPLY_BYTES)
            .read_to_string(&mut reply)
            .map_err(|error| unreachable("did not answer in time", error))?;
        let reply: Value = serde_json::from_str(&reply)
            .map_err(|error| format!("the research exit helper's reply is not JSON: {error}"))?;
        if reply["ok"] == Value::Bool(true) {
            return Ok(reply);
        }
        Err(reply["cause"]
            .as_str()
            .unwrap_or("the helper gave no cause")
            .to_owned())
    }
}

/// A refusal the exit could not answer by moving.
fn stuck(host: &str, cause: &str, reason: &str) -> String {
    format!(
        "{host} refused or timed out through the research VPN ({cause}); \
         the research exit could not move to another region: {reason}"
    )
}

#[cfg(test)]
#[path = "research_tests.rs"]
pub(crate) mod tests;
