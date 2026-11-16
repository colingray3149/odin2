//! The generic approval card: what the owner approves, printed as the exact values the call binds.
//!
//! A capability declares `preview = "card"` and its host registers an [`ApprovalCardSource`]
//! ([`HermesRuntime::set_approval_card`]). When the kernel asks the owner, the source turns the
//! journaled call (the same arguments the approval's digest binds) into one object and its rows:
//! the key, the value it has now, the value it gets. A source that cannot build the card leaves the
//! question with the exact arguments and the cause, as every preview does.

use std::sync::Arc;

use odin_registry::schema::ApprovalCardToml;
use serde_json::Value;

use super::HermesRuntime;

/// One bound value of the change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CardChange {
    /// The key takes `new`; `old` is its value now (`None`: not set).
    Set { old: Option<String>, new: String },
    /// `item` joins the list at the key.
    Add(String),
    /// `item` leaves the list at the key.
    Remove(String),
    /// The call binds `value` at the key (a declared card's row).
    Value(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CardRow {
    pub key: String,
    pub change: CardChange,
}

/// What one approval changes: the object (e.g. `seat scribe`) and every bound value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalCard {
    pub object: String,
    pub rows: Vec<CardRow>,
    /// One plain line after the rows (when it takes effect, what it costs); optional.
    pub note: Option<String>,
}

impl ApprovalCard {
    /// The card as the question's detail: the object, then one line per bound value.
    pub fn render(&self) -> String {
        let mut text = format!("{}\n", self.object);
        for row in &self.rows {
            let line = match &row.change {
                CardChange::Set { old, new } => format!(
                    "{}: {} → {new}",
                    row.key,
                    old.as_deref().unwrap_or("(not set)")
                ),
                CardChange::Add(item) => format!("{}: add {item}", row.key),
                CardChange::Remove(item) => format!("{}: remove {item}", row.key),
                CardChange::Value(value) => format!("{}: {value}", row.key),
            };
            text.push_str(&format!("• {line}\n"));
        }
        if let Some(note) = &self.note {
            text.push_str(note);
            text.push('\n');
        }
        text.pop();
        text
    }
}

/// Builds the card of one capability's call from its exact arguments (`approvalId` removed).
pub trait ApprovalCardSource: Send + Sync {
    fn card(&self, arguments: &Value) -> Result<ApprovalCard, String>;
}
/// `odin.plan_accept`: the session and the plan it accepts, from the bound arguments alone.
pub(super) struct PlanAcceptCard;

impl ApprovalCardSource for PlanAcceptCard {
    fn card(&self, arguments: &Value) -> Result<ApprovalCard, String> {
        let field = |name: &str| {
            arguments
                .get(name)
                .filter(|value| !value.is_null())
                .map(|value| {
                    value
                        .as_str()
                        .map_or_else(|| value.to_string(), str::to_owned)
                })
                .ok_or_else(|| format!("the call names no {name}"))
        };
        Ok(ApprovalCard {
            object: format!("Accept the plan of session {}", field("session")?),
            rows: vec![
                CardRow {
                    key: "objective".to_owned(),
                    change: CardChange::Set {
                        old: Some("not accepted".to_owned()),
                        new: field("objective")?,
                    },
                },
                CardRow {
                    key: "revision".to_owned(),
                    change: CardChange::Set {
                        old: None,
                        new: field("revision")?,
                    },
                },
            ],
            note: Some(
                "Its side effects then run under its own grants until the plan changes.".to_owned(),
            ),
        })
    }
}

/// What a declared card prints for a pointer the call does not bind.
pub const ABSENT: &str = "(absent)";

/// The card a capability declares (`approval_card` in its `capability.toml`), rendered from the bound
/// arguments alone: the title with each `{/pointer}` replaced, then one `field: value` row per pointer.
pub struct DeclaredCard(pub ApprovalCardToml);

impl DeclaredCard {
    /// A string as itself, any other value as compact JSON.
    fn value(arguments: &Value, pointer: &str) -> String {
        let Some(value) = arguments.pointer(pointer) else {
            return ABSENT.to_owned();
        };
        value
            .as_str()
            .map_or_else(|| value.to_string(), str::to_owned)
    }

    fn title(&self, arguments: &Value) -> String {
        let mut title = String::new();
        let mut rest = self.0.title.as_str();
        while let Some(open) = rest.find('{') {
            let Some(close) = rest[open..].find('}').map(|close| open + close) else {
                break;
            };
            title.push_str(&rest[..open]);
            title.push_str(&Self::value(arguments, &rest[open + 1..close]));
            rest = &rest[close + 1..];
        }
        title.push_str(rest);
        title
    }
}

impl ApprovalCardSource for DeclaredCard {
    fn card(&self, arguments: &Value) -> Result<ApprovalCard, String> {
        Ok(ApprovalCard {
            object: self.title(arguments),
            rows: self
                .0
                .fields
                .iter()
                .map(|pointer| CardRow {
                    key: pointer.trim_start_matches('/').to_owned(),
                    change: CardChange::Value(Self::value(arguments, pointer)),
                })
                .collect(),
            note: None,
        })
    }
}

impl HermesRuntime {
    /// Registers the card source of `capability` (one per capability; a later one replaces it).
    pub fn set_approval_card(&self, capability: &str, source: Arc<dyn ApprovalCardSource>) {
        if let Ok(mut sources) = self.approval_cards.lock() {
            sources.insert(capability.to_owned(), source);
        }
    }

    pub(super) fn approval_card(
        &self,
        capability: &str,
        arguments: &Value,
    ) -> Result<String, String> {
        let source = self
            .approval_cards
            .lock()
            .ok()
            .and_then(|sources| sources.get(capability).cloned())
            .ok_or_else(|| format!("{capability} has no approval card on this host"))?;
        let mut arguments = arguments.clone();
        if let Some(object) = arguments.as_object_mut() {
            object.remove("approvalId");
        }
        source.card(&arguments).map(|card| card.render())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn campaign() -> DeclaredCard {
        DeclaredCard(ApprovalCardToml {
            title: "Run campaign {/campaign} on {/nodes/0}".to_owned(),
            fields: ["/box", "/rung", "/cases", "/core_hours", "/nodes"]
                .map(str::to_owned)
                .to_vec(),
        })
    }

    #[test]
    fn an_approval_card_names_exactly_the_declared_fields_and_a_missing_pointer_renders_absent() {
        let card = campaign()
            .card(&json!({
                "campaign": "rde-sweep-3",
                "box": {"phi": [0.8, 1.2]},
                "rung": "coarse",
                "nodes": ["mini", "pc"],
                "undeclared": "never shown",
            }))
            .expect("card");
        let keys: Vec<&str> = card.rows.iter().map(|row| row.key.as_str()).collect();
        assert_eq!(keys, ["box", "rung", "cases", "core_hours", "nodes"]);
        let rendered = card.render();
        assert_eq!(
            rendered,
            format!(
                "Run campaign rde-sweep-3 on mini\n\
                 • box: {{\"phi\":[0.8,1.2]}}\n\
                 • rung: coarse\n\
                 • cases: {ABSENT}\n\
                 • core_hours: {ABSENT}\n\
                 • nodes: [\"mini\",\"pc\"]"
            )
        );
        assert!(!rendered.contains("never shown"));
    }

    #[test]
    fn a_card_title_takes_each_bound_pointer_and_keeps_other_text() {
        let card = DeclaredCard(ApprovalCardToml {
            title: "Spend {/hours} h on {/provider} ({/missing}) {not a pointer".to_owned(),
            fields: Vec::new(),
        });
        let rendered = card
            .card(&json!({"hours": 4, "provider": "vast"}))
            .expect("card")
            .render();
        assert_eq!(
            rendered,
            format!("Spend 4 h on vast ({ABSENT}) {{not a pointer")
        );
    }

    #[test]
    fn a_long_card_value_is_preserved_in_title_and_row() {
        let long = format!("{}  ", "é".repeat(240));
        let card = DeclaredCard(ApprovalCardToml {
            title: "Value {/long}".to_owned(),
            fields: vec!["/long".to_owned()],
        })
        .card(&json!({"long": long}))
        .expect("card");
        assert_eq!(card.render(), format!("Value {long}\n• long: {long}"));
    }

    #[test]
    fn a_card_prints_every_bound_value() {
        let card = ApprovalCard {
            object: "Seat scribe (registry/seats/scribe/seat.toml)".to_owned(),
            rows: vec![
                CardRow {
                    key: "read_project_scope".to_owned(),
                    change: CardChange::Add("project-alpha".to_owned()),
                },
                CardRow {
                    key: "context.profile".to_owned(),
                    change: CardChange::Set {
                        old: Some("\"medium\"".to_owned()),
                        new: "\"high\"".to_owned(),
                    },
                },
                CardRow {
                    key: "limits.pods".to_owned(),
                    change: CardChange::Set {
                        old: None,
                        new: "2".to_owned(),
                    },
                },
            ],
            note: Some("Takes effect after odind's next idle reload.".to_owned()),
        };
        assert_eq!(
            card.render(),
            "Seat scribe (registry/seats/scribe/seat.toml)\n\
             • read_project_scope: add project-alpha\n\
             • context.profile: \"medium\" → \"high\"\n\
             • limits.pods: (not set) → 2\n\
             Takes effect after odind's next idle reload."
        );
    }
}
