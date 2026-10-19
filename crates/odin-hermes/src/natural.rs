//! Whole-message decisions and declaration-driven human presentation.

use serde_json::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerDecision {
    AllowOnce,
    Deny,
}

/// Interpret only an entire affirmative or negative reply; never an instruction prefix.
pub fn parse_whole_message_decision(content: &str) -> Option<OwnerDecision> {
    let normalized = content
        .trim()
        .trim_end_matches(['.', '!'])
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
        .replace('’', "'");
    match normalized.as_str() {
        "yes" | "yeah" | "yep" | "yup" | "sure" | "go ahead" | "do it" | "approve" | "approved"
        | "allow" | "ok" | "okay" | "y" | "yes please" | "yes go ahead" | "go for it" => {
            Some(OwnerDecision::AllowOnce)
        }
        "no" | "nope" | "nah" | "don't" | "dont" | "do not" | "stop" | "cancel" | "not now"
        | "reject" | "deny" | "n" | "cancel that" | "cancel it" | "never mind" | "nevermind"
        | "forget it" | "forget that" | "no thanks" | "no thank you" | "don't do it"
        | "dont do it" | "don't do that" | "dont do that" => Some(OwnerDecision::Deny),
        _ => None,
    }
}

/// A denial that carries an instruction ("no — drop the pod, move on"):
/// a denial word closed by explicit punctuation, then the owner's words,
/// returned for the declined turn to act on. Only a DENIAL decides this
/// way — declining is never consequential — while "yes, but …" and
/// "no worries" (no punctuation) stay undecided.
pub fn parse_leading_denial(content: &str) -> Option<String> {
    let trimmed = content.trim();
    let split = trimmed.find([',', '.', '!', ';', ':', '—', '–', '-'])?;
    let (head, rest) = trimmed.split_at(split);
    if parse_whole_message_decision(head) != Some(OwnerDecision::Deny) {
        return None;
    }
    let rest = rest
        .trim_start_matches(|c: char| {
            c.is_ascii_punctuation() || c.is_whitespace() || matches!(c, '—' | '–')
        })
        .trim();
    (!rest.is_empty()).then(|| rest.to_owned())
}

/// The words of a message, lowercased; an amount is one token ("$1,500"
/// and "1500" are both "1500", and "$500" never matches it).
fn tokens(content: &str) -> Vec<String> {
    let text = content.to_lowercase().replace('’', "'");
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        let digit_glue = matches!(c, ',' | '.')
            && current
                .chars()
                .last()
                .is_some_and(|last| last.is_ascii_digit())
            && chars.peek().is_some_and(char::is_ascii_digit);
        if digit_glue {
            if c == '.' {
                current.push(c);
            }
        } else if c.is_alphanumeric() || c == '\'' {
            current.push(c);
        } else if !current.is_empty() {
            tokens.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// A decision that names its question: a leading yes/no word, then the
/// words that say which one ("no to the calendar one", "yes, send the
/// email"). Every word but filler is returned, short ones included, so a
/// condition or another object ("yes to the laptop, but only if under $100")
/// stays in the designation; "no worries" names nothing.
pub fn parse_named_decision(content: &str) -> Option<(OwnerDecision, Vec<String>)> {
    const FILLER: &[&str] = &[
        "to",
        "the",
        "a",
        "an",
        "that",
        "this",
        "them",
        "those",
        "these",
        "one",
        "ones",
        "please",
        "question",
        "worries",
        "thanks",
        "okay",
        "sure",
        "both",
        "each",
        "all",
        "everything",
    ];
    let mut words = tokens(content).into_iter();
    let decision = parse_whole_message_decision(&words.next()?)?;
    let terms: Vec<String> = words
        .filter(|word| !FILLER.contains(&word.as_str()))
        .collect();
    (!terms.is_empty()).then_some((decision, terms))
}

/// How a named decision's words meet one question's text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Designation {
    Untouched,
    /// Some words name it, others say something it does not.
    Partial,
    /// Every word names it: the whole message designates this question.
    Whole,
}

pub fn designation(terms: &[String], question: &str) -> Designation {
    let words = tokens(question);
    // Whole tokens only: "laptops" is not "laptop", "500" is not "$1,500".
    let names = |term: &str| words.iter().any(|word| word == term);
    match terms.iter().filter(|term| names(term)).count() {
        0 => Designation::Untouched,
        named if named == terms.len() => Designation::Whole,
        _ => Designation::Partial,
    }
}

/// Whether a reply states a count, an amount, an ordinal, a date or a
/// time, in digits, words or a currency sign. Read from the whole message
/// before filler is dropped. "one" is a count unless it is a pronoun: a
/// pronoun takes its determiner ("the calendar one", "that one"), is not
/// cut off from it by punctuation ("the laptop, one", "the laptop; one"),
/// and is followed only
/// by a prepositional or politeness tag ("the one with the sleeve", "the
/// red one, please"). A noun after it makes it a count again ("the one
/// laptop", "this one laptop"); ambiguous forms ask again.
pub fn states_a_quantity(content: &str) -> bool {
    const WORDS: &[&str] = &[
        "zero",
        "two",
        "three",
        "four",
        "five",
        "six",
        "seven",
        "eight",
        "nine",
        "ten",
        "eleven",
        "twelve",
        "thirteen",
        "fourteen",
        "fifteen",
        "sixteen",
        "seventeen",
        "eighteen",
        "nineteen",
        "twenty",
        "thirty",
        "forty",
        "fifty",
        "sixty",
        "seventy",
        "eighty",
        "ninety",
        "hundred",
        "thousand",
        "million",
        "billion",
        "trillion",
        "dozen",
        "half",
        "couple",
        "pair",
        "quarter",
        "few",
        "several",
        "once",
        "twice",
        "first",
        "second",
        "third",
        "fourth",
        "fifth",
        "sixth",
        "seventh",
        "eighth",
        "ninth",
        "tenth",
        "eleventh",
        "twelfth",
        "thirteenth",
        "fourteenth",
        "fifteenth",
        "sixteenth",
        "seventeenth",
        "eighteenth",
        "nineteenth",
        "twentieth",
        "thirtieth",
        "fortieth",
        "fiftieth",
        "sixtieth",
        "seventieth",
        "eightieth",
        "ninetieth",
        "hundredth",
        "thousandth",
        "millionth",
        "billionth",
        "trillionth",
        "dollar",
        "buck",
        "cent",
        "penny",
        "pennies",
        "usd",
        "euro",
        "eur",
        "pound",
        "gbp",
        "yen",
        "today",
        "tonight",
        "tomorrow",
        "yesterday",
        "monday",
        "tuesday",
        "wednesday",
        "thursday",
        "friday",
        "saturday",
        "sunday",
        "january",
        "february",
        "march",
        "april",
        "may",
        "june",
        "july",
        "august",
        "september",
        "october",
        "november",
        "december",
        "noon",
        "midnight",
        "morning",
        "afternoon",
        "evening",
        "night",
        "week",
        "weekend",
        "fortnight",
        "month",
        "year",
        "hour",
        "minute",
        "am",
        "pm",
        "o'clock",
        "daily",
        "weekly",
        "monthly",
        "yearly",
    ];
    const DETERMINERS: &[&str] = &[
        "the", "that", "this", "which", "each", "every", "any", "other", "another",
    ];
    const PHRASE_BREAKS: &[&str] = &[
        "and", "or", "but", "with", "without", "for", "of", "to", "from", "in", "on", "at", "by",
    ];
    if content
        .chars()
        .any(|c| c.is_ascii_digit() || matches!(c, '$' | '€' | '£' | '¥' | '₹' | '%'))
    {
        return true;
    }
    const PHRASE_TAILS: &[&str] = &[
        "with", "without", "of", "for", "from", "in", "on", "at", "by", "to", "near", "that",
        "which", "who", "please", "thanks", "thank", "you",
    ];
    // Words with the punctuation that precedes them: any separator cuts
    // "one" off from the noun phrase whose determiner would make it a
    // pronoun; whitespace does not.
    let text = content.to_lowercase().replace('’', "'");
    let mut words: Vec<(&str, bool)> = Vec::new();
    let (mut start, mut cut) = (None, false);
    for (i, c) in text.char_indices() {
        if c.is_alphanumeric() || c == '\'' {
            start.get_or_insert(i);
        } else {
            if let Some(s) = start.take() {
                words.push((&text[s..i], cut));
                cut = false;
            }
            cut |= !c.is_whitespace();
        }
    }
    if let Some(s) = start {
        words.push((&text[s..], cut));
    }
    words.iter().enumerate().any(|(index, (word, cut_before))| {
        if matches!(*word, "one" | "ones") {
            let determiner_before = words[..index]
                .iter()
                .rev()
                .take_while(|&&(before, cut)| !cut && !PHRASE_BREAKS.contains(&before))
                .any(|(before, _)| DETERMINERS.contains(before));
            let tail_is_tag = words[index + 1..]
                .first()
                .is_none_or(|(after, _)| PHRASE_TAILS.contains(after));
            return !(determiner_before && tail_is_tag && !cut_before);
        }
        let singular = word
            .strip_suffix('s')
            .filter(|stem| stem.len() > 2)
            .unwrap_or(word);
        WORDS.contains(word) || WORDS.contains(&singular)
    })
}
/// A denial that covers every open question ("no to both", "no, cancel all
/// of them") — only when that is the whole message: "no to all except the
/// laptop" names an exception and decides nothing. Only a denial can:
/// declining is never consequential.
pub fn denies_every_question(content: &str) -> bool {
    const BLANKET: &[&str] = &["both", "all", "everything", "each"];
    const FILLER: &[&str] = &[
        "to",
        "of",
        "them",
        "the",
        "these",
        "those",
        "questions",
        "please",
        "cancel",
        "one",
    ];
    let words = tokens(content);
    let Some((first, rest)) = words.split_first() else {
        return false;
    };
    parse_whole_message_decision(first) == Some(OwnerDecision::Deny)
        && rest.iter().any(|word| BLANKET.contains(&word.as_str()))
        && rest
            .iter()
            .all(|word| BLANKET.contains(&word.as_str()) || FILLER.contains(&word.as_str()))
}

/// Ambiguous decision-like text may trigger clarification, but never authorization.
pub fn opens_decisionish(content: &str) -> bool {
    let Some(first) = content.split_whitespace().next() else {
        return false;
    };
    let first = first.trim_end_matches(|c: char| c.is_ascii_punctuation());
    parse_whole_message_decision(first).is_some()
}

/// "yes to the laptop", "no to the calendar one": a decision that says
/// which question it answers.
pub fn is_framed_decision(content: &str) -> bool {
    let normalized = content.to_lowercase().replace('’', "'");
    let mut words = normalized
        .split(|c: char| !(c.is_alphanumeric() || c == '\''))
        .filter(|word| !word.is_empty());
    words
        .next()
        .and_then(parse_whole_message_decision)
        .is_some()
        && words.next() == Some("to")
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
    match detail.map(str::trim).filter(|text| !text.is_empty()) {
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
        IntentFailure::SilentTurn => "I worked on that but ended up with no answer to give you; please ask me again.",
        IntentFailure::HistoryUnavailable => "I couldn't read our conversation history; I need to restore that connection before continuing.",
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
    fn calling_a_request_off_in_plain_words_declines_it() {
        for phrase in [
            "cancel that",
            "Never mind.",
            "forget it",
            "no thanks",
            "don't do that",
        ] {
            assert_eq!(
                parse_whole_message_decision(phrase),
                Some(OwnerDecision::Deny),
                "{phrase}"
            );
        }
        for phrase in ["yes please", "go for it"] {
            assert_eq!(
                parse_whole_message_decision(phrase),
                Some(OwnerDecision::AllowOnce),
                "{phrase}"
            );
        }
        for phrase in ["no worries", "yes, but tomorrow", "sounds good maybe"] {
            assert_eq!(parse_whole_message_decision(phrase), None, "{phrase}");
        }
    }

    #[test]
    fn only_unambiguous_whole_messages_decide() {
        for text in ["yes", "Go ahead!", "y", "  APPROVED.  "] {
            assert_eq!(
                parse_whole_message_decision(text),
                Some(OwnerDecision::AllowOnce)
            );
        }
        for text in ["no", "Not now!", "don’t"] {
            assert_eq!(
                parse_whole_message_decision(text),
                Some(OwnerDecision::Deny)
            );
        }
        for text in [
            "sure?",
            "yes?",
            "no worries",
            "yes, but not the purchase",
            "cancel that and start over",
            "",
        ] {
            assert_eq!(parse_whole_message_decision(text), None, "{text}");
        }
    }

    #[test]
    fn a_punctuated_denial_decides_and_keeps_the_instruction() {
        assert_eq!(
            parse_leading_denial("no — drop the hinge pod, move on to everything else"),
            Some("drop the hinge pod, move on to everything else".to_owned())
        );
        assert_eq!(
            parse_leading_denial("Nope, just email me the summary"),
            Some("just email me the summary".to_owned())
        );
        for text in [
            "no worries",
            "no worries, take your time",
            "yes, but only 10 likes",
            "no",
            "no.",
            "not sure — what does it cost?",
            "cancel that and start over",
        ] {
            assert_eq!(parse_leading_denial(text), None, "{text}");
        }
    }

    #[test]
    fn unicode_presentation_is_bounded_without_splitting_characters() {
        let text = "界".repeat(400);
        let description = format!("{text}. Internal details.");
        let label = approval_label(&description);
        assert_eq!(label, format!("{}…", "界".repeat(80)));
        let request =
            serde_json::json!({"arguments": {"task": text, "session_id": "opaque-session"}});
        let detail = detail_from_request_json(&request.to_string()).expect("human task");
        assert_eq!(detail, format!("{}…", "界".repeat(240)));
        assert!(
            detail_from_request_json(r#"{"arguments":{"session_id":"opaque-session"}}"#).is_none()
        );
    }

    #[test]
    fn failure_details_never_become_human_authority_or_replay_advice() {
        let secret = "token:private-state";
        let failure = crate::runtime::IntentFailure::Other(secret.to_owned());
        assert!(!natural_intent_failure(&failure).contains(secret));
    }
}

#[cfg(test)]
mod designation_tests {
    use super::{denies_every_question, designation, parse_named_decision, Designation};

    fn designates(reply: &str, question: &str) -> Designation {
        let (_, terms) = parse_named_decision(reply).expect("named");
        designation(&terms, question)
    }

    #[test]
    fn an_amount_is_one_token_and_a_different_one_leaves_it_open() {
        let question = "Buy this item a laptop under $1,500";
        assert_eq!(
            designates("yes to the laptop under $500", question),
            Designation::Partial
        );
        assert_eq!(
            designates("yes to the laptop under $1,500", question),
            Designation::Whole
        );
        assert_eq!(
            designates("yes to the laptop under 1500", question),
            Designation::Whole
        );
    }

    #[test]
    fn a_quantity_in_words_or_signs_is_a_quantity() {
        use super::states_a_quantity;
        assert!(states_a_quantity("yes to the laptop under five dollars"));
        assert!(states_a_quantity("yes to one laptop"));
        assert!(states_a_quantity("yes to one laptop, please"));
        assert!(states_a_quantity("yes to laptop one, thanks"));
        assert!(states_a_quantity("yes to one"));
        assert!(states_a_quantity("yes to the one laptop"));
        assert!(states_a_quantity("yes to this one laptop"));
        assert!(states_a_quantity("yes to the laptop, one"));
        assert!(states_a_quantity("yes to the laptop; one"));
        assert!(states_a_quantity("yes to the laptop: one"));
        assert!(states_a_quantity("yes to the laptop — one"));
        assert!(states_a_quantity("yes to the laptop under $500"));
        assert!(states_a_quantity("yes to the laptop for twenty-five bucks"));
        assert!(states_a_quantity("yes to the trip on Friday"));
        assert!(states_a_quantity("yes to the second laptop"));
        assert!(states_a_quantity("yes to the laptop and one charger"));
        assert!(states_a_quantity("yes to a few laptops"));
        assert!(states_a_quantity("yes, several of them"));
        assert!(states_a_quantity("yes to running it once"));
        assert!(states_a_quantity("yes to the thirteenth"));
        assert!(states_a_quantity("yes until the thirtieth"));
        assert!(states_a_quantity("yes to a trillion rows"));
        assert!(states_a_quantity("yes to the thousandth row"));
        assert!(!states_a_quantity("yes to the laptop"));
        assert!(!states_a_quantity("yes to the one"));
        assert!(!states_a_quantity("yes to the calendar one"));
        assert!(!states_a_quantity("yes to that one"));
        assert!(!states_a_quantity("yes to the one with the sleeve"));
        assert!(!states_a_quantity("yes to the red one, please"));
        assert!(!states_a_quantity("yes to the big one, thank you"));
    }

    /// "no to all except the laptop" names an exception: it declines nothing.
    #[test]
    fn a_blanket_denial_with_an_exception_is_no_blanket() {
        assert!(denies_every_question("no to both"));
        assert!(denies_every_question("no, cancel all of them"));
        assert!(!denies_every_question("no to all except the laptop"));
        assert!(!denies_every_question("no to both, but keep the laptop"));
    }
}
