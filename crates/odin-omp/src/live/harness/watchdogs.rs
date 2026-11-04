//! An environment's declared watchdogs, evaluated in code over a session's
//! decoded frames: a hit raises an incident (Huginn card, phone, a Sinmara
//! wake).

use std::sync::Arc;
use std::time::{Duration, Instant};

use odin_registry::EnvironmentWatchdogToml;
use serde_json::Value;

use super::HarnessRoute;

/// Where a watchdog hit goes (the daemon's incident desk).
pub trait HarnessIncidentSink: Send + Sync {
    fn raise(&self, environment: &str, watchdog: &str, summary: &str, detail: &str);
}

/// A match watchdog fires at most once per this window.
const COOLDOWN: Duration = Duration::from_secs(60);
/// An incident quotes this many characters of the matching text, starting at most
/// [`EXCERPT_LEAD_CHARS`] before the needle.
const EXCERPT_CHARS: usize = 400;
const EXCERPT_LEAD_CHARS: usize = 200;

/// One watchdog's running state.
struct Dog {
    declared: EnvironmentWatchdogToml,
    last_fired: Option<Instant>,
}

/// The first decoded string inside `value` that contains `needle`, so a
/// match watchdog searches the frame's own text fields instead of
/// re-serializing the whole frame (a tool result can be hundreds of KB).
fn needle_text<'a>(value: &'a Value, needle: &str) -> Option<&'a str> {
    match value {
        Value::String(text) => text.contains(needle).then_some(text.as_str()),
        Value::Array(items) => items.iter().find_map(|item| needle_text(item, needle)),
        Value::Object(fields) => fields.values().find_map(|field| needle_text(field, needle)),
        _ => None,
    }
}

/// The match watchdogs one decoded frame fires, as (name, needle, an excerpt of the matching
/// string around the needle): none for a backlog line, and each dog at most once a minute.
fn matched(dogs: &mut [Dog], frame: &Value, live: bool) -> Vec<(String, String, String)> {
    if !live {
        return Vec::new();
    }
    let mut fired = Vec::new();
    for dog in dogs.iter_mut() {
        let Some(needle) = &dog.declared.matches else {
            continue;
        };
        let cooled = dog.last_fired.is_none_or(|at| at.elapsed() > COOLDOWN);
        if cooled {
            if let Some(text) = needle_text(frame, needle.as_str()) {
                dog.last_fired = Some(Instant::now());
                let at = text.find(needle.as_str()).unwrap_or(0);
                let start = text[..at]
                    .char_indices()
                    .rev()
                    .nth(EXCERPT_LEAD_CHARS - 1)
                    .map_or(0, |(i, _)| i);
                let excerpt: String = text[start..].chars().take(EXCERPT_CHARS).collect();
                fired.push((dog.declared.name.clone(), needle.clone(), excerpt));
            }
        }
    }
    fired
}

pub(super) struct Watchdogs {
    dogs: Vec<Dog>,
    open_tool: Option<(String, Instant)>,
}

impl Watchdogs {
    pub(super) fn new(route: &HarnessRoute) -> Self {
        Self {
            dogs: route
                .environment
                .watchdogs
                .iter()
                .cloned()
                .map(|declared| Dog {
                    declared,
                    last_fired: None,
                })
                .collect(),
            open_tool: None,
        }
    }

    pub(super) fn reset_transcript(&mut self) {
        self.open_tool = None;
    }

    pub(super) fn frame(
        &mut self,
        frame: &Value,
        live: bool,
        sink: &Option<Arc<dyn HarnessIncidentSink>>,
        route: &HarnessRoute,
        transcript: Option<&str>,
    ) {
        if !live || self.dogs.is_empty() {
            return;
        }
        match frame.get("type").and_then(Value::as_str) {
            Some("tool_execution_start") => {
                let name = frame
                    .get("toolName")
                    .and_then(Value::as_str)
                    .unwrap_or("tool");
                self.open_tool = Some((name.to_owned(), Instant::now()));
            }
            Some("tool_execution_end") => self.open_tool = None,
            _ => {}
        }
        for (name, needle, excerpt) in matched(&mut self.dogs, frame, true) {
            fire(
                sink,
                route,
                transcript,
                &name,
                &format!("the agent's output contained {needle:?}: {excerpt}"),
            );
        }
    }

    pub(super) fn tick(
        &mut self,
        sink: &Option<Arc<dyn HarnessIncidentSink>>,
        route: &HarnessRoute,
        transcript: Option<&str>,
    ) {
        let Some((tool, since)) = &self.open_tool else {
            return;
        };
        for dog in &mut self.dogs {
            let Some(seconds) = dog.declared.silent_seconds else {
                continue;
            };
            if since.elapsed() >= Duration::from_secs(u64::from(seconds))
                && dog.last_fired.is_none_or(|at| at < *since)
            {
                dog.last_fired = Some(Instant::now());
                fire(
                    sink,
                    route,
                    transcript,
                    &dog.declared.name,
                    &format!(
                    "the agent's tool call {tool} has made no progress for over the declared window"
                ),
                );
            }
        }
    }
}

fn fire(
    sink: &Option<Arc<dyn HarnessIncidentSink>>,
    route: &HarnessRoute,
    transcript: Option<&str>,
    watchdog: &str,
    detail: &str,
) {
    tracing::info!(
        "odind: watchdog environment={} watchdog={watchdog} fired transcript={}",
        route.environment_id,
        transcript.unwrap_or_default()
    );
    match sink {
        Some(sink) => sink.raise(
            &route.environment_id,
            watchdog,
            &format!(
                "Watchdog {watchdog} fired on the session {} ({}) transcript={}",
                route.environment_id,
                route.environment.host.as_deref().unwrap_or("?"),
                transcript.unwrap_or_default()
            ),
            detail,
        ),
        None => tracing::error!("odind: watchdog has no incident sink; logged only"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn force_push_dog() -> Dog {
        Dog {
            declared: EnvironmentWatchdogToml {
                name: "force-push".to_owned(),
                matches: Some("push --force".to_owned()),
                silent_seconds: None,
            },
            last_fired: None,
        }
    }

    struct Sink(std::sync::mpsc::Sender<(String, String, String)>);

    impl HarnessIncidentSink for Sink {
        fn raise(&self, environment: &str, watchdog: &str, summary: &str, _: &str) {
            self.0
                .send((
                    environment.to_owned(),
                    watchdog.to_owned(),
                    summary.to_owned(),
                ))
                .unwrap();
        }
    }

    fn route_with(dogs: &[EnvironmentWatchdogToml]) -> HarnessRoute {
        let mut route = HarnessRoute {
            harness_id: "fixture-process".to_owned(),
            harness: super::super::tests::process_fixture(),
            environment_id: "pod-authority".to_owned(),
            environment: toml::from_str(include_str!(
                "../../../../../registry/environments/fleet-authority/environment.toml"
            ))
            .unwrap(),
            account: None,
        };
        route.environment.watchdogs = dogs.to_vec();
        route
    }

    #[test]
    fn a_watchdog_uses_its_declared_trigger_and_exact_transcript() {
        let route = route_with(&[force_push_dog().declared]);
        let (tx, rx) = std::sync::mpsc::channel();
        let sink: Option<Arc<dyn HarnessIncidentSink>> = Some(Arc::new(Sink(tx)));
        let mut watchdogs = Watchdogs::new(&route);
        let frame = json!({"type":"message_end", "message":{"role":"assistant", "content":[{"type":"text", "text":"push --force"}]}});
        watchdogs.frame(&frame, false, &sink, &route, Some("/old.jsonl"));
        assert!(rx.try_recv().is_err(), "history never raises an incident");
        watchdogs.reset_transcript();
        watchdogs.frame(&frame, true, &sink, &route, Some("/owned/new.jsonl"));
        let (environment, dog, receipt) = rx.try_recv().unwrap();
        assert_eq!(environment, "pod-authority");
        assert_eq!(dog, "force-push");
        assert!(receipt.ends_with("transcript=/owned/new.jsonl"));
        assert!(!receipt.contains("/old.jsonl"));
        watchdogs.frame(&frame, true, &sink, &route, Some("/owned/new.jsonl"));
        assert!(
            rx.try_recv().is_err(),
            "declared evaluator cooldown is shared"
        );
    }

    /// A tool call that stays open past the declared window raises one incident for that call.
    #[test]
    fn a_tool_call_silent_past_its_window_raises_one_incident() {
        let route = route_with(&[EnvironmentWatchdogToml {
            name: "stalled-tool".to_owned(),
            matches: None,
            silent_seconds: Some(30),
        }]);
        let (tx, rx) = std::sync::mpsc::channel();
        let sink: Option<Arc<dyn HarnessIncidentSink>> = Some(Arc::new(Sink(tx)));
        let mut watchdogs = Watchdogs::new(&route);
        let start = json!({"type": "tool_execution_start", "toolName": "claude-code.bash"});
        watchdogs.frame(&start, true, &sink, &route, None);
        watchdogs.tick(&sink, &route, None);
        assert!(rx.try_recv().is_err(), "inside the window");

        let (_, since) = watchdogs.open_tool.as_mut().expect("the call is open");
        *since = Instant::now() - Duration::from_secs(31);
        watchdogs.tick(&sink, &route, None);
        let (_, dog, _) = rx.try_recv().expect("past the window");
        assert_eq!(dog, "stalled-tool");
        watchdogs.tick(&sink, &route, None);
        assert!(rx.try_recv().is_err(), "once per call");

        let end = json!({"type": "tool_execution_end", "toolName": "claude-code.bash"});
        watchdogs.frame(&end, true, &sink, &route, None);
        assert!(watchdogs.open_tool.is_none());
    }

    #[test]
    fn only_live_lines_fire_a_match_watchdog() {
        let mut dogs = vec![force_push_dog()];
        let frame: serde_json::Value =
            serde_json::from_str(r#"{"command":"git push --force origin main"}"#)
                .expect("fixture frame");
        assert!(matched(&mut dogs, &frame, false).is_empty());
        assert_eq!(
            matched(&mut dogs, &frame, true),
            vec![(
                "force-push".to_owned(),
                "push --force".to_owned(),
                "git push --force origin main".to_owned()
            )]
        );
        assert!(
            matched(&mut dogs, &frame, true).is_empty(),
            "cools for a minute"
        );
    }
}
