//! Whole-message decisions and declaration-driven human presentation.

use serde_json::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerDecision {
    AllowOnce,
    Deny,
}

/// How the owner answered a question that waits on him.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnerAnswer {
    /// A yes, with whatever he said after it ("yes, remind me about it later").
    Yes(Option<String>),
    /// A no, with whatever he said after it ("no, drop the pod and move on").
    No(Option<String>),
    /// Opens with a yes but adds a condition or names something else: it approves nothing.
    Hedged,
}

const YES: &[&str] = &["yes", "yeah", "yep", "yup", "y", "approve", "approved"];
/// Words that open ordinary sentences too ("ok so check my calendar"), so only a very
/// short tail after them is still an answer.
const MILD_YES: &[&str] = &["ok", "okay", "sure", "allow"];
/// A leading no declines; "stop the deploy" or "cancel the booking" are new requests, so the
/// rest of the calling-off words decline only as a whole message.
const NO: &[&str] = &["no", "nope", "nah", "n"];
const WHOLE_NO: &[&str] = &[
    "stop",
    "cancel",
    "deny",
    "reject",
    "don't",
    "dont",
    "do not",
    "not now",
    "never mind",
    "nevermind",
    "forget it",
    "forget that",
    "cancel that",
    "cancel it",
    "don't do it",
    "dont do it",
    "don't do that",
    "dont do that",
];
/// A yes that carries one of these is a condition, not an approval ("yes to the laptop"
/// names something too).
const HEDGES: &[&str] = &[
    "but", "only", "if", "unless", "except", "instead", "however", "wait", "hold", "not",
];
/// "no worries" and "no problem" are pleasantries, not a decline.
const PLEASANTRIES: &[&str] = &["worries", "worry", "problem"];
/// Past this many words after a yes it is a message that opens with one.
const YES_TAIL_WORDS: usize = 6;
const MILD_YES_TAIL_WORDS: usize = 2;

/// What follows the first word past its punctuation: "no, drop the pod" gives "drop the pod".
fn after_first_word(content: &str) -> Option<String> {
    let trimmed = content.trim();
    let end = trimmed.find(|c: char| !(c.is_alphanumeric() || c == '\''))?;
    let rest = trimmed[end..]
        .trim_start_matches(|c: char| !c.is_alphanumeric())
        .trim();
    (!rest.is_empty()).then(|| rest.to_owned())
}

/// Reads a reply as an answer to an open question: a leading yes or no word decides,
/// unless the yes is hedged. Anything else is ordinary chat.
pub fn parse_owner_answer(content: &str) -> Option<OwnerAnswer> {
    let text = content.trim().to_lowercase().replace('\u{2019}', "'");
    let words: Vec<&str> = text
        .split(|c: char| !(c.is_alphanumeric() || c == '\''))
        .filter(|word| !word.is_empty())
        .collect();
    let (first, rest) = words.split_first()?;
    let (limit, tail) = match *first {
        word if YES.contains(&word) => (YES_TAIL_WORDS, rest),
        "go" if rest.first() == Some(&"ahead") => (YES_TAIL_WORDS, &rest[1..]),
        "do" if rest.first() == Some(&"it") => (YES_TAIL_WORDS, &rest[1..]),
        // "go" opens requests too ("go check the pod"), so only alone is it a yes.
        "go" if rest.is_empty() => (YES_TAIL_WORDS, rest),
        word if MILD_YES.contains(&word) => (MILD_YES_TAIL_WORDS, rest),
        _ => {
            return if NO.contains(first)
                && !rest.first().is_some_and(|word| PLEASANTRIES.contains(word))
            {
                Some(OwnerAnswer::No(after_first_word(content)))
            } else if WHOLE_NO.contains(&words.join(" ").as_str()) {
                Some(OwnerAnswer::No(None))
            } else {
                None
            };
        }
    };
    // A long tail is a message that happens to open with a yes: ordinary chat.
    if tail.len() > limit {
        return None;
    }
    let conditional = tail.iter().any(|word| HEDGES.contains(word))
        || tail.first() == Some(&"to")
        || text.trim_end().ends_with('?');
    Some(if conditional {
        OwnerAnswer::Hedged
    } else {
        OwnerAnswer::Yes(after_first_word(content))
    })
}

/// A call's result as short plain text for the owner and the seat.
pub fn receipt_text(receipt: &Value) -> String {
    let text = receipt
        .as_str()
        .map_or_else(|| receipt.to_string(), str::to_owned);
    bounded_text(&text, 1_500)
}

pub fn first_sentence(description: &str) -> &str {
    let description = description.trim();
    description
        .split_once(". ")
        .map_or(description, |(sentence, _)| sentence)
}

/// Bound presentation at UTF-8 character boundaries, preferring whole words.
fn bounded_text(text: &str, limit: usize) -> String {
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let Some((boundary, _)) = collapsed.char_indices().nth(limit) else {
        return collapsed;
    };
    let prefix = &collapsed[..boundary];
    let end = prefix
        .rfind(' ')
        .filter(|end| *end > 0)
        .unwrap_or(prefix.len());
    format!("{}…", &prefix[..end])
}

pub fn declared_action_phrase(description: &str) -> String {
    bounded_text(
        first_sentence(description).trim_end_matches(['.', '!', '?']),
        160,
    )
}

/// Wording comes from the admitted declaration; the caller rejects missing descriptions.
/// Detail is already selected by the caller; keep it complete for checkpointed
/// chunk delivery rather than silently changing the question's consent scope.
pub fn approval_question(declared_description: &str, detail: Option<&str>) -> String {
    let action = declared_action_phrase(declared_description);
    let mut chars = action.chars();
    let action = match chars.next() {
        Some(first) => format!("{}{}", first.to_lowercase(), chars.as_str()),
        None => String::new(),
    };
    match detail.filter(|text| !text.trim().is_empty()) {
        Some(detail) => format!("May I {action}: {detail}?"),
        None => format!("May I {action}?"),
    }
}

pub fn approval_label(declared_description: &str) -> String {
    bounded_text(
        first_sentence(declared_description).trim_end_matches('.'),
        80,
    )
}

/// Only explicitly human-oriented argument fields contribute prose; identifiers do not.
pub fn detail_from_request_json(request_json: &str) -> Option<String> {
    let parsed: Value = serde_json::from_str(request_json).ok()?;
    let arguments = parsed.get("arguments").unwrap_or(&parsed);
    // A message names what it says and who receives it.
    if let Some(subject) = arguments.get("subject").and_then(Value::as_str) {
        let recipients: Vec<&str> = arguments
            .get("to")
            .and_then(Value::as_array)
            .map(|to| to.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let detail = if recipients.is_empty() {
            format!("\u{201c}{subject}\u{201d}")
        } else {
            format!("\u{201c}{subject}\u{201d} to {}", recipients.join(", "))
        };
        return Some(bounded_text(&detail, 240));
    }
    // Approval must identify both the branch and destination project.
    if let (Some(branch), Some(project)) = (
        arguments.get("branch").and_then(Value::as_str),
        arguments.get("project").and_then(Value::as_str),
    ) {
        return Some(bounded_text(&format!("{branch} into {project}"), 240));
    }
    // Calendar approval must identify the event, time, and account.
    if let (Some(kind), Some(account)) = (
        arguments.get("type").and_then(Value::as_str),
        arguments.get("account").and_then(Value::as_str),
    ) {
        let instant = |value: &Value| {
            value
                .as_str()
                .map(|text| text.chars().take(16).collect::<String>().replace('T', " "))
        };
        let event = |item: &Value| -> Option<String> {
            Some(format!(
                "\u{201c}{}\u{201d} at {}",
                item.get("title")?.as_str()?,
                instant(item.get("start")?)?
            ))
        };
        let change = match kind {
            "create" => event(arguments).map(|event| format!("add {event}")),
            "batchCreate" => arguments
                .get("drafts")
                .and_then(Value::as_array)
                .and_then(|drafts| {
                    let first = event(drafts.first()?)?;
                    Some(match drafts.len() {
                        1 => format!("add {first}"),
                        count => format!(
                            "add {count} events, the first {first}, the last at {}",
                            drafts.last().and_then(|last| instant(last.get("start")?))?
                        ),
                    })
                }),
            "move" => arguments
                .get("start")
                .and_then(instant)
                .map(|start| format!("move an event to {start}")),
            "cancel" => Some("cancel an event".to_owned()),
            _ => None,
        };
        if let Some(change) = change {
            return Some(bounded_text(
                &format!("{change} on the {account} calendar"),
                240,
            ));
        }
    }
    [
        "task",
        "goal",
        "question",
        "prompt",
        "request",
        "instruction",
        "objective",
        "title",
        "summary",
        "message",
        "notes",
        "reason",
        "content",
    ]
    .into_iter()
    .filter_map(|key| arguments.get(key).and_then(Value::as_str))
    .find(|text| !text.trim().is_empty())
    .map(|text| bounded_text(text, 240))
}

/// The provider's refusal in plain words: what kind of failure it is, never
/// the provider's raw error body.
pub fn provider_refusal(message: &str) -> &'static str {
    let lower = message.to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|needle| lower.contains(needle));
    if has(&[
        "429",
        "quota",
        "rate limit",
        "rate_limit",
        "usage limit",
        "insufficient_quota",
        "too many requests",
    ]) {
        "its provider says it is over its usage limit"
    } else if has(&[
        "401",
        "403",
        "unauthorized",
        "forbidden",
        "api key",
        "api_key",
        "authentication",
        "invalid key",
        "permission",
    ]) {
        "its provider rejected the key it uses"
    } else if has(&[
        "timeout",
        "timed out",
        "overloaded",
        "503",
        "502",
        "504",
        "unavailable",
        "connection",
    ]) {
        "its provider is not reachable or overloaded right now"
    } else {
        "its provider refused the request"
    }
}

/// The one line the owner gets when a quiet lane's turn is sent again on the next declared lane.
pub fn lane_moved_line(from: &str, to: &str, seconds: u64) -> String {
    format!("{from} went quiet for {seconds}s, so I moved to {to} and sent that again.")
}

/// A timeout leaves the effect outcome unknown; never encourage blind replay.
pub fn natural_intent_failure(failure: &crate::runtime::IntentFailure) -> String {
    use crate::runtime::IntentFailure;
    match failure {
        IntentFailure::AnswerTimeout => "I couldn't confirm the result in time; I need to check what happened before trying again.",
        IntentFailure::VehicleLost | IntentFailure::VehicleRecoveryFailed { .. } => "My workspace stopped responding; I need to recover it and check the last action before continuing.",
        IntentFailure::ConversationBusy => "I'm still working on the previous request; please give me a moment.",
        IntentFailure::TurnRefused { .. } => "Something on my side failed before I could start on that, so nothing was done; please send it again in a minute.",
        IntentFailure::ContextExhausted => "That request is too large for my model's context window even in a fresh conversation; please split it into smaller pieces.",
        IntentFailure::ModelUnavailable { reason } => return format!(
            "My model couldn't answer — {}. Nothing was done; try again later, or tell me to use a different model.",
            provider_refusal(reason)
        ),
        IntentFailure::LaneStalled { from, to: Some(to), seconds } => return format!(
            "{from} went quiet for {seconds}s, so I moved to {to}; that request didn't finish, \
             please send it again."
        ),
        IntentFailure::LaneStalled { from, to: None, seconds } => return format!(
            "{from} went quiet for {seconds}s and my seat declares no other model to move to; \
             please send that again in a minute."
        ),
        IntentFailure::SilentTurn => "I worked on that but ended up with no answer to give you; please ask me again.",
        IntentFailure::HistoryUnavailable { .. } => "I couldn't read our conversation history; I need to restore that connection before continuing.",
        IntentFailure::ReplyStateUnavailable => "I couldn't durably record the state of that request; I need to restore that before continuing, and I won't send it twice.",
        IntentFailure::ConversationClosed => "This conversation has been closed; it needs a new conversation before work can continue.",
        IntentFailure::SuccessorStartBackoff { .. } => "My workspace keeps failing to start, so nothing was done; Odin raised an incident and keeps retrying on a slower schedule.",
        IntentFailure::SuccessorStartExhausted { .. } => "My workspace failed to start too many times in a row, so nothing was done; Odin raised an incident and stopped retrying until the fault is fixed.",
        IntentFailure::Other(_) => "I couldn't finish that request; I need to check its state before trying again.",
    }.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_detail_preserves_bound_whitespace() {
        assert_eq!(
            approval_question("Change it.", Some("value  ")),
            "May I change it: value  ?"
        );
    }

    #[test]
    fn a_leading_yes_or_no_answers_and_a_conditional_yes_approves_nothing() {
        for text in [
            "yes",
            "Go ahead!",
            "yes, go ahead and send it",
            "  APPROVED.  ",
            "ok do it",
            "yes, please",
            "yes, go ahead",
            "go",
            "yes go",
            "okay go",
            "do it",
        ] {
            assert!(
                matches!(parse_owner_answer(text), Some(OwnerAnswer::Yes(_))),
                "{text}"
            );
        }
        assert_eq!(
            parse_owner_answer("yes, remind me about it later"),
            Some(OwnerAnswer::Yes(Some(
                "remind me about it later".to_owned()
            )))
        );
        assert_eq!(parse_owner_answer("no"), Some(OwnerAnswer::No(None)));
        assert_eq!(
            parse_owner_answer("no \u{2014} drop the pod, move on"),
            Some(OwnerAnswer::No(Some("drop the pod, move on".to_owned())))
        );
        assert_eq!(
            parse_owner_answer("never mind."),
            Some(OwnerAnswer::No(None))
        );
        for text in [
            "yes, but only under $100",
            "yes?",
            "yes to the laptop sleeve",
        ] {
            assert_eq!(
                parse_owner_answer(text),
                Some(OwnerAnswer::Hedged),
                "{text}"
            );
        }
        for text in [
            "no worries",
            "what time is it",
            "",
            "maybe later",
            "stop the deploy",
            "cancel my dinner booking",
            "ok so check my calendar for tomorrow",
            "go check the pod",
            "yes and while you are at it please look at my calendar for next week too",
        ] {
            assert_eq!(parse_owner_answer(text), None, "{text}");
        }
    }

    #[test]
    fn an_unknown_failure_detail_never_reaches_the_owner_text() {
        let secret = "token:private-state";
        let failure = crate::runtime::IntentFailure::Other(secret.to_owned());
        assert!(!natural_intent_failure(&failure).contains(secret));
    }
}
