//! One request, rendered fresh every time in a fixed order:
//! [tools + system] → [summary: durable rows + notes] → [recent window] →
//! [current turn: tail (brain, message), then its own calls and results].
//! Nothing volatile precedes the window, and a call is never separated from
//! its result.

use std::collections::BTreeMap;

use odin_domain::Digest;
use serde_json::{json, Map, Value};

use super::journal::{Call, Entry};
use crate::live::rollover::{RolloverChildState, RolloverPendingApproval, RolloverPlanRecord};

/// The text a call that never got its result is answered with in history.
const INTERRUPTED: &str =
    "no result was recorded: the turn was interrupted before this call finished";

/// Bytes to tokens: the provider's own ratio once a request reported its
/// prompt tokens, bytes / 4 before that.
#[derive(Clone, Copy, Debug, Default)]
pub struct Estimator {
    pub tokens: u64,
    pub bytes: u64,
}

impl Estimator {
    pub fn tokens(&self, bytes: usize) -> u64 {
        let bytes = bytes as u64;
        match (self.tokens, self.bytes) {
            (0, _) | (_, 0) => bytes.div_ceil(4),
            (tokens, total) => (bytes * tokens).div_ceil(total),
        }
    }
}

/// One past exchange of the main window: an owner turn with its rounds,
/// or a side turn's posted reply.
#[derive(Clone, Debug)]
pub struct Exchange {
    pub turn: u64,
    pub messages: Vec<Value>,
    pub bytes: usize,
}

/// Messages of one turn's entries, each call followed by its own result.
pub fn turn_messages(entries: &[&Entry], digests: bool, reasoning: bool) -> Vec<Value> {
    let mut messages = Vec::new();
    let result_of = |id: &str| {
        entries.iter().find_map(|entry| match entry {
            Entry::Result {
                call_id,
                text,
                digest,
                ..
            } if call_id == id => Some(match (digests, digest) {
                (true, Some(digest)) => digest.clone(),
                _ => text.clone(),
            }),
            _ => None,
        })
    };
    for entry in entries {
        match entry {
            Entry::User { text, .. } => messages.push(json!({"role": "user", "content": text})),
            Entry::Posted { text, .. } => {
                messages.push(json!({"role": "assistant", "content": text}))
            }
            Entry::Assistant {
                text,
                reasoning: thought,
                calls,
                opaque,
                ..
            } => {
                messages.push(assistant_message(
                    text,
                    thought.as_deref().filter(|_| reasoning),
                    calls,
                    opaque.as_ref(),
                ));
                for call in calls {
                    let content = result_of(&call.id).unwrap_or_else(|| INTERRUPTED.to_owned());
                    messages.push(tool_message(&call.id, &content));
                }
            }
            _ => {}
        }
    }
    messages
}

pub fn assistant_message(
    text: &str,
    reasoning: Option<&str>,
    calls: &[Call],
    opaque: Option<&Value>,
) -> Value {
    let mut message = Map::new();
    if let Some(Value::Object(fields)) = opaque {
        message.extend(fields.clone());
    }
    message.insert("role".into(), json!("assistant"));
    message.insert(
        "content".into(),
        if text.is_empty() && !calls.is_empty() {
            Value::Null
        } else {
            json!(text)
        },
    );
    if let Some(reasoning) = reasoning {
        message.insert("reasoning_content".into(), json!(reasoning));
    }
    if !calls.is_empty() {
        let calls = calls
            .iter()
            .map(|call| {
                let mut wire = json!({
                    "id": call.id,
                    "type": "function",
                    "function": {"name": call.name, "arguments": call.arguments},
                });
                if let Some(opaque) = &call.opaque {
                    wire["provider_specific_fields"] = opaque.clone();
                }
                wire
            })
            .collect();
        message.insert("tool_calls".into(), Value::Array(calls));
    }
    Value::Object(message)
}

pub fn tool_message(call_id: &str, content: &str) -> Value {
    json!({"role": "tool", "tool_call_id": call_id, "content": content})
}

/// The main window's exchanges after `after`: owner turns (all but `current`)
/// and posted side replies, oldest first, settled results shown as digests.
pub fn window(
    entries: &[Entry],
    after: u64,
    current: Option<u64>,
    reasoning: bool,
) -> Vec<Exchange> {
    let dropped = dropped(entries);
    let mut turns: BTreeMap<u64, Vec<&Entry>> = BTreeMap::new();
    for entry in entries {
        let Some(turn) = entry.turn() else { continue };
        // A side turn's posted reply is not `side`: it joins the main window.
        if turn > after && Some(turn) != current && !entry.side() && !dropped.contains(&turn) {
            turns.entry(turn).or_default().push(entry);
        }
    }
    turns
        .into_iter()
        .map(|(turn, entries)| {
            let messages = turn_messages(&entries, true, reasoning);
            let bytes = messages
                .iter()
                .map(|message| message.to_string().len())
                .sum();
            Exchange {
                turn,
                messages,
                bytes,
            }
        })
        .collect()
}

/// Turns refused over the budget: they leave no trace in later requests.
fn dropped(entries: &[Entry]) -> std::collections::BTreeSet<u64> {
    entries
        .iter()
        .filter_map(|entry| match entry {
            Entry::Settled {
                turn,
                dropped: true,
                ..
            } => Some(*turn),
            _ => None,
        })
        .collect()
}

/// How many of the oldest exchanges a fold takes so that summary plus the
/// rest is at most `target` tokens. Exchanges are whole owner turns, so a
/// fold never splits a call from its result.
pub fn fold_count(
    exchanges: &[Exchange],
    summary_bytes: usize,
    estimate: Estimator,
    target: u64,
) -> usize {
    let mut rest: usize = exchanges.iter().map(|exchange| exchange.bytes).sum();
    let mut count = 0;
    while count < exchanges.len() && estimate.tokens(summary_bytes + rest) > target {
        rest -= exchanges[count].bytes;
        count += 1;
    }
    count
}

/// The durable rows the summary always carries, read from the ledger and
/// the journal every request: never left to the model.
#[derive(Clone, Debug, Default)]
pub struct Durable {
    pub unanswered: Option<String>,
    pub plan: Option<RolloverPlanRecord>,
    pub approvals: Vec<RolloverPendingApproval>,
    pub children: Vec<RolloverChildState>,
    /// Newest last.
    pub failures: Vec<String>,
}

/// The most recent owner request that did not get its answer (excluding `current`).
pub fn unanswered(entries: &[Entry], current: Option<u64>) -> Option<String> {
    let dropped = dropped(entries);
    let turn = entries.iter().rev().find_map(|entry| match entry {
        Entry::User {
            turn, side: false, ..
        } if Some(*turn) != current && !dropped.contains(turn) => Some(*turn),
        _ => None,
    })?;
    let answered = entries.iter().any(|entry| {
        matches!(entry, Entry::Settled { turn: at, failure: None, reply: Some(_), .. } if *at == turn)
    });
    // The turn's first words are the request; later ones steered it.
    let request = entries.iter().find_map(|entry| match entry {
        Entry::User { turn: at, text, .. } if *at == turn => Some(text.clone()),
        _ => None,
    })?;
    (!answered).then_some(request)
}

/// Failed calls and turns, newest last.
pub fn failures(entries: &[Entry]) -> Vec<String> {
    entries
        .iter()
        .filter_map(|entry| match entry {
            Entry::Result {
                turn,
                tool,
                text,
                is_error: true,
                ..
            } => Some(format!(
                "turn {turn}: {tool} failed: {}",
                text.lines().next().unwrap_or_default()
            )),
            Entry::Settled {
                turn,
                failure: Some(failure),
                ..
            } => Some(format!("turn {turn} stopped: {failure}")),
            _ => None,
        })
        .collect()
}

/// The summary: the durable section re-rendered every time, then the
/// model-written notes. Failures are dropped oldest first to keep the
/// durable section within `max_bytes`; the rest always rides.
pub fn summary(durable: &Durable, notes: &str, max_bytes: usize) -> String {
    let mut fixed = String::new();
    if let Some(request) = &durable.unanswered {
        // Bounded so a long request can never crowd out every later turn.
        let mut cut = request.len().min(max_bytes / 2);
        while !request.is_char_boundary(cut) {
            cut -= 1;
        }
        let more = if cut < request.len() { " …" } else { "" };
        fixed.push_str(&format!(
            "Unanswered request from the owner:\n{}{more}\n\n",
            &request[..cut]
        ));
    }
    if let Some(plan) = &durable.plan {
        fixed.push_str(&format!(
            "Task plan (revision {}, {}): {}\n",
            plan.revision,
            if plan.accepted {
                "accepted"
            } else {
                "not accepted"
            },
            plan.objective
        ));
        for todo in &plan.todos {
            fixed.push_str(&format!(
                "- [{}] {}\n",
                todo["status"].as_str().unwrap_or("?"),
                todo["title"].as_str().unwrap_or_default()
            ));
        }
        fixed.push('\n');
    }
    if !durable.approvals.is_empty() {
        fixed.push_str("Approvals waiting on the owner:\n");
        for approval in &durable.approvals {
            fixed.push_str(&format!(
                "- {} for {}\n",
                approval.approval_id, approval.capability_id
            ));
        }
        fixed.push('\n');
    }
    if !durable.children.is_empty() {
        fixed.push_str("Delegated sessions:\n");
        for child in &durable.children {
            fixed.push_str(&format!(
                "- {} {} ({}/{}) in {}\n",
                child.child_session, child.phase, child.provider, child.model, child.project
            ));
        }
        fixed.push('\n');
    }
    let mut room = max_bytes.saturating_sub(fixed.len());
    let mut kept = Vec::new();
    for failure in durable.failures.iter().rev() {
        if failure.len() + 3 > room {
            break;
        }
        room -= failure.len() + 3;
        kept.push(failure.as_str());
    }
    if !kept.is_empty() {
        fixed.push_str("Recent failures:\n");
        for failure in kept.into_iter().rev() {
            fixed.push_str(&format!("- {failure}\n"));
        }
        fixed.push('\n');
    }
    if !notes.trim().is_empty() {
        fixed.push_str("Notes on earlier work:\n");
        fixed.push_str(notes.trim());
        fixed.push('\n');
    }
    fixed.trim_end().to_owned()
}

/// A long tool result as later requests see it: tool, an arguments gist,
/// size, its first and last lines, its error lines, and the artifact
/// holding all of it. Bounded by `budget` bytes; no model call.
pub fn digest(tool: &str, arguments: &str, text: &str, artifact: &str, budget: usize) -> String {
    let gist: String = arguments.chars().take(budget / 8).collect();
    let mut out = format!(
        "[{tool} {gist}: {} bytes; artifact {artifact} holds all of it (page it with files \
         {{op: \"artifact\", artifactId, offset, limit}})]\n",
        text.len()
    );
    let quarter = budget / 4;
    let lines: Vec<&str> = text.lines().collect();
    let mut head = Vec::new();
    let mut used = 0;
    for line in &lines {
        if used + line.len() > quarter {
            break;
        }
        used += line.len() + 1;
        head.push(*line);
    }
    let mut tail = Vec::new();
    used = 0;
    for line in lines.iter().skip(head.len()).rev() {
        if used + line.len() > quarter {
            break;
        }
        used += line.len() + 1;
        tail.push(*line);
    }
    tail.reverse();
    out.push_str(&head.join("\n"));
    if head.len() + tail.len() < lines.len() {
        out.push_str("\n…\n");
    } else if !tail.is_empty() {
        out.push('\n');
    }
    out.push_str(&tail.join("\n"));
    let errors: Vec<&str> = lines[head.len()..lines.len() - tail.len()]
        .iter()
        .filter(|line| {
            let lower = line.to_lowercase();
            lower.contains("error") || lower.contains("exit") || lower.contains("failed")
        })
        .copied()
        .collect();
    for line in errors {
        if out.len() + line.len() + 1 > budget {
            break;
        }
        out.push('\n');
        out.push_str(line);
    }
    out
}

/// The hash of the cached prefix: tools then system.
pub fn prefix_hash(tools: &[Value], system: &str) -> Digest {
    let mut bytes = serde_json::to_vec(tools).unwrap_or_default();
    bytes.extend_from_slice(system.as_bytes());
    Digest::hash(&bytes)
}

/// The messages of one request in the fixed order. `summary` is empty when
/// there is nothing to carry; `nudge` is a last one-line hint, after every result.
pub fn messages(
    system: &str,
    summary: &str,
    window: &[Exchange],
    current: &[Value],
    nudge: Option<&str>,
) -> Vec<Value> {
    let mut messages = vec![json!({"role": "system", "content": system})];
    if !summary.is_empty() {
        messages.push(json!({"role": "system", "content": summary}));
    }
    messages.extend(
        window
            .iter()
            .flat_map(|exchange| exchange.messages.iter().cloned()),
    );
    messages.extend(current.iter().cloned());
    if let Some(nudge) = nudge {
        messages.push(json!({"role": "user", "content": nudge}));
    }
    messages
}
